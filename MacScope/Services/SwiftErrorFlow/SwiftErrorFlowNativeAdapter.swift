import Foundation

/// App-owned, read-only extraction. It never opens a path, hashes bytes, edits the
/// image, consults a display name, or grants source-reconstruction authority.
enum SwiftErrorFlowNativeAdapter {
    static func request(binary: LoadedBinary) throws -> SwiftErrorFlowRequest {
        guard binary.artifactIntegrityState == .verified,
              !binary.isDyldSharedCacheProjection,
              let identity = binary.artifactIdentity,
              let layout = binary.preferredSegmentLayout,
              binary.cpuType == identity.rawCPUType,
              binary.cpuSubtype == identity.rawCPUSubtype,
              binary.cpuType == 0x0100000c, binary.cpuSubtype == 0,
              binary.sliceOffset <= UInt64(binary.bytes.count),
              identity.selectedSliceByteCount == (binary.sliceSize ?? UInt64(binary.bytes.count) - binary.sliceOffset),
              identity.selectedSliceByteCount <= UInt64(binary.bytes.count) - binary.sliceOffset,
              identity.selectedSliceByteCount <= 128 * 1024 * 1024 else {
            throw SwiftErrorFlowAdapterError("unverified_slice")
        }
        let lower = Int(binary.sliceOffset)
        let slice = binary.bytes.subdata(in: lower..<(lower + Int(identity.selectedSliceByteCount)))
        let parsed = try SwiftErrorFlowMachOReader.parse(slice)
        let parsedLayout = try MachOPreferredSegmentLayout(records: parsed.segments.map {
            .init(name: $0.name, preferredVMStart: $0.address, preferredVMSize: $0.size,
                  sliceRelativeFileOffset: $0.fileOffset, fileSize: $0.fileSize,
                  initialProtections: $0.protections)
        }, selectedSliceByteCount: identity.selectedSliceByteCount)
        guard parsedLayout == layout,
              binary.functionStartsParseOutcome == .terminated,
              binary.functionStarts == parsed.allFunctionStarts,
              binary.diagnosticTruncations.isEmpty,
              binary.codeDataRanges.isEmpty,
              binary.relocations.isEmpty else {
            throw SwiftErrorFlowAdapterError("loader_raw_metadata_disagreement")
        }
        let matches = binary.sections.filter {
            $0.name == "__TEXT,__text" && $0.address == parsed.text.address
                && $0.size == parsed.text.size && $0.fileOffset == parsed.text.fileOffset
                && $0.isExecutable && !$0.isZeroFill && ($0.fileSize == nil || $0.fileSize == $0.size)
        }
        guard matches.count == 1 else { throw SwiftErrorFlowAdapterError("unverified_code_mapping") }
        return .init(slice: .init(artifactSHA256: identity.selectedSliceSHA256,
                                 sliceOffset: binary.sliceOffset,
                                 sliceByteCount: identity.selectedSliceByteCount,
                                 cpuType: UInt32(bitPattern: binary.cpuType), cpuSubtype: 0,
                                 littleEndian: true),
                     code: .init(baseAddress: parsed.text.address,
                                 sliceRelativeFileOffset: parsed.text.fileOffset,
                                 sectionOrdinal: parsed.text.ordinal,
                                 hasEmbeddedData: false, hasRelocations: false, words: parsed.words),
                     functions: parsed.functions, symbols: parsed.symbols)
    }
}

struct SwiftErrorFlowAdapterError: Error, LocalizedError, Equatable {
    let code: String
    init(_ code: String) { self.code = code }
    var errorDescription: String? { "Swift error-flow evidence unavailable: \(code). No source or runtime claim is made." }
}

/// This bounded reader consumes the complete original commands and nlist flags.
/// Best-effort projected symbol/relocation arrays are never negative evidence.
enum SwiftErrorFlowMachOReader {
    struct Segment {
        let name: String
        let address: UInt64
        let size: UInt64
        let fileOffset: UInt64
        let fileSize: UInt64
        let protections: Int32
    }
    struct Section {
        let address: UInt64
        let size: UInt64
        let fileOffset: UInt64
        let ordinal: UInt8
    }
    struct Parsed {
        let segments: [Segment]
        let text: Section
        let words: [UInt32]
        let allFunctionStarts: [UInt64]
        let functions: [SwiftErrorFlowFunction]
        let symbols: [SwiftErrorFlowSymbol]
    }

    static func parse(_ data: Data) throws -> Parsed {
        guard data.count >= 32, data.count <= 128 * 1024 * 1024 else { throw failure("slice_size_limit") }
        let r = Reader(bytes: Array(data))
        guard try r.u32(0) == 0xfeedfacf, try r.u32(4) == 0x0100000c, try r.u32(8) == 0,
              [UInt32(2), 6, 8].contains(try r.u32(12)) else { throw failure("unsupported_macho_architecture_or_filetype") }
        let count = Int(try r.u32(16)), size = Int(try r.u32(20))
        guard count > 0, count <= 1024, size <= 1024 * 1024 else { throw failure("load_command_limit") }
        try r.bounds(32, size)
        let commandEnd = 32 + size
        var cursor = 32, ordinal = 0
        var segments: [Segment] = [], texts: [Section] = []
        var startsPayload: Range<Int>?, symbolCommand: Int?
        var sectionExtents: [(vm: Range<UInt64>, file: Range<UInt64>)] = []
        for _ in 0..<count {
            guard cursor <= commandEnd - 8 else { throw failure("truncated_load_command") }
            let command = try r.u32(cursor), length = Int(try r.u32(cursor + 4))
            guard length >= 8, length % 8 == 0, length <= commandEnd - cursor else { throw failure("invalid_load_command_extent") }
            switch command {
            case 0x19: // LC_SEGMENT_64
                guard length >= 72 else { throw failure("truncated_segment") }
                let name = try r.fixedName(cursor + 8)
                let vm = try r.u64(cursor + 24), vmSize = try r.u64(cursor + 32)
                let file = try r.u64(cursor + 40), fileSize = try r.u64(cursor + 48)
                let protection = Int32(bitPattern: try r.u32(cursor + 60))
                let sectionCount = Int(try r.u32(cursor + 64))
                guard sectionCount <= 255 - ordinal, length == 72 + sectionCount * 80,
                      vmSize <= UInt64.max - vm, fileSize <= UInt64(data.count),
                      file <= UInt64(data.count) - fileSize else { throw failure("invalid_segment_mapping") }
                segments.append(.init(name: name, address: vm, size: vmSize,
                                      fileOffset: file, fileSize: fileSize, protections: protection))
                for index in 0..<sectionCount {
                    let p = cursor + 72 + index * 80
                    ordinal += 1
                    let sectionName = try r.fixedName(p), segmentName = try r.fixedName(p + 16)
                    let address = try r.u64(p + 32), bytes = try r.u64(p + 40)
                    let offset = UInt64(try r.u32(p + 48)), relocations = try r.u32(p + 60)
                    let flags = try r.u32(p + 64), kind = flags & 0xff
                    guard segmentName == name, bytes <= UInt64.max - address,
                          address >= vm, address - vm <= vmSize, bytes <= vmSize - (address - vm) else {
                        throw failure("invalid_section_mapping")
                    }
                    if kind != 1 && kind != 0x0c && kind != 0x12 && bytes > 0 {
                        guard offset >= file, offset - file <= fileSize,
                              bytes <= fileSize - (offset - file),
                              address - vm == offset - file else { throw failure("nonlinear_section_mapping") }
                        let extent = (vm: address..<(address + bytes), file: offset..<(offset + bytes))
                        guard sectionExtents.allSatisfy({ !$0.vm.overlaps(extent.vm) && !$0.file.overlaps(extent.file) }) else {
                            throw failure("overlapping_sections")
                        }
                        sectionExtents.append(extent)
                    }
                    // Global refusal avoids mistaking an unprojected relocation table for absence.
                    guard relocations == 0 else { throw failure("relocations_not_supported") }
                    if name == "__TEXT" && sectionName == "__text" {
                        guard kind == 0, flags & 0x80000400 != 0,
                              protection & 4 != 0, protection & 2 == 0,
                              bytes > 0, bytes % 4 == 0, address % 4 == 0, offset % 4 == 0,
                              bytes / 4 <= 65_536, offset >= UInt64(commandEnd) else {
                            throw failure("unsupported_text_mapping")
                        }
                        texts.append(.init(address: address, size: bytes, fileOffset: offset, ordinal: UInt8(ordinal)))
                    }
                }
            case 0x26: // LC_FUNCTION_STARTS
                guard length == 16, startsPayload == nil else { throw failure("ambiguous_function_starts") }
                let offset = Int(try r.u32(cursor + 8)), bytes = Int(try r.u32(cursor + 12))
                guard bytes > 0, bytes <= 64 * 1024, offset >= commandEnd else { throw failure("function_starts_limit") }
                try r.bounds(offset, bytes)
                startsPayload = offset..<(offset + bytes)
            case 2: // LC_SYMTAB
                guard length == 24, symbolCommand == nil else { throw failure("ambiguous_symbol_table") }
                symbolCommand = cursor
            case 0x29: // LC_DATA_IN_CODE: empty command only; no ignored unknown entry kinds.
                guard length == 16, try r.u32(cursor + 12) == 0 else { throw failure("embedded_data_not_supported") }
            case 0x21, 0x2c: // LC_ENCRYPTION_INFO(_64)
                guard length == (command == 0x2c ? 24 : 20), try r.u32(cursor + 16) == 0 else {
                    throw failure("encrypted_or_incomplete_image")
                }
            case 0x0b: // LC_DYSYMTAB external/local relocations
                guard length == 80, try r.u32(cursor + 68) == 0, try r.u32(cursor + 76) == 0 else {
                    throw failure("dynamic_relocations_not_supported")
                }
            case 0x22, 0x80000022: // Classic rebase/bind streams: no precise text-mutation proof here.
                guard length == 48 else { throw failure("incomplete_dyld_info") }
                for field in [12, 20, 28, 36] where try r.u32(cursor + field) != 0 {
                    throw failure("dynamic_mutation_metadata_not_supported")
                }
            case 0x80000034: // LC_DYLD_CHAINED_FIXUPS
                guard length == 16, try r.u32(cursor + 12) == 0 else { throw failure("chained_fixups_not_supported") }
            default: break
            }
            cursor += length
        }
        guard cursor == commandEnd, texts.count == 1, let text = texts.first,
              let payload = startsPayload, let symbolCommand,
              segments.filter({ $0.name == "__TEXT" }).count == 1,
              let base = segments.first(where: { $0.name == "__TEXT" })?.address else {
            throw failure("missing_or_ambiguous_required_metadata")
        }
        let textFile = Int(text.fileOffset)..<(Int(text.fileOffset) + Int(text.size))
        let textVM = text.address..<(text.address + text.size)
        let textRaw = text.fileOffset..<(text.fileOffset + text.size)
        let overlappingMappings = segments.filter {
            ($0.address..<($0.address + $0.size)).overlaps(textVM)
                || ($0.fileOffset..<($0.fileOffset + $0.fileSize)).overlaps(textRaw)
        }
        guard overlappingMappings.count == 1,
              let owner = overlappingMappings.first, owner.name == "__TEXT",
              owner.protections & 4 != 0, owner.protections & 2 == 0 else {
            throw failure("ambiguous_text_mapping")
        }
        guard !payload.overlaps(textFile) else { throw failure("metadata_overlaps_code") }
        let allStarts = try functionStarts(r, payload: payload, base: base)
        let end = text.address + text.size
        let starts = allStarts.filter { $0 >= text.address && $0 < end }
        guard starts.count >= 2, starts.count <= 4097, starts.allSatisfy({ $0 % 4 == 0 }) else {
            throw failure("no_bounded_function_intervals")
        }
        // A following declared start bounds each admitted interval. The last start
        // is deliberately absent: neither __text end nor a RET is a function end.
        let functions = zip(starts, starts.dropFirst()).map {
            SwiftErrorFlowFunction(start: $0.0, endExclusive: $0.1, boundarySource: "lc_function_starts")
        }
        let symbols = try symbols(r, command: symbolCommand, commandEnd: commandEnd,
                                  forbidden: [textFile, payload], sectionCount: ordinal)
        let words = try stride(from: textFile.lowerBound, to: textFile.upperBound, by: 4).map { try r.u32($0) }
        return .init(segments: segments, text: text, words: words, allFunctionStarts: allStarts,
                     functions: functions, symbols: symbols)
    }

    private static func functionStarts(_ r: Reader, payload: Range<Int>, base: UInt64) throws -> [UInt64] {
        var p = payload.lowerBound, address = base, values: [UInt64] = []
        while p < payload.upperBound {
            var value: UInt64 = 0, shift = 0, terminated = false
            for _ in 0..<10 {
                guard p < payload.upperBound else { throw failure("unterminated_function_starts") }
                let byte = r.bytes[p]; p += 1
                let low = UInt64(byte & 0x7f)
                guard shift < 64, low <= UInt64.max >> shift else { throw failure("function_start_overflow") }
                value |= low << shift
                if byte & 0x80 == 0 { terminated = true; break }
                shift += 7
            }
            guard terminated else { throw failure("unterminated_function_start_delta") }
            if value == 0 {
                guard r.bytes[p..<payload.upperBound].allSatisfy({ $0 == 0 }), !values.isEmpty else {
                    throw failure("invalid_function_start_termination")
                }
                return values
            }
            guard values.count < 4097, value <= UInt64.max - address else { throw failure("function_start_limit") }
            address += value
            values.append(address)
        }
        throw failure("unterminated_function_starts")
    }

    private static func symbols(_ r: Reader, command: Int, commandEnd: Int,
                                forbidden: [Range<Int>], sectionCount: Int) throws -> [SwiftErrorFlowSymbol] {
        let offset = Int(try r.u32(command + 8)), count = Int(try r.u32(command + 12))
        let strings = Int(try r.u32(command + 16)), size = Int(try r.u32(command + 20))
        guard count > 0, count <= 8192, size > 0, size <= 4 * 1024 * 1024,
              offset >= commandEnd, strings >= commandEnd else { throw failure("symbol_table_limit") }
        try r.bounds(offset, count * 16); try r.bounds(strings, size)
        let tableRange = offset..<(offset + count * 16), stringRange = strings..<(strings + size)
        guard !tableRange.overlaps(stringRange),
              forbidden.allSatisfy({ !$0.overlaps(tableRange) && !$0.overlaps(stringRange) }) else {
            throw failure("overlapping_symbol_metadata")
        }
        var result: [SwiftErrorFlowSymbol] = []
        for index in 0..<count {
            let p = offset + index * 16, stringIndex = Int(try r.u32(p))
            let type = r.bytes[p + 4], section = r.bytes[p + 5]
            guard stringIndex < size, Int(section) <= sectionCount else { throw failure("invalid_nlist") }
            let nameStart = strings + stringIndex
            let limit = min(strings + size, nameStart + 1025)
            guard let nul = r.bytes[nameStart..<limit].firstIndex(of: 0),
                  let name = String(bytes: r.bytes[nameStart..<nul], encoding: .utf8) else {
                throw failure("unterminated_or_invalid_symbol_name")
            }
            // Keep all aliases, including undefined/weak/debug flags. The core owns
            // recognition and refusal; no user label or demangled winner is chosen.
            result.append(.init(address: try r.u64(p + 8), name: name, nType: type,
                                nDesc: UInt16(r.bytes[p + 6]) | (UInt16(r.bytes[p + 7]) << 8),
                                sectionOrdinal: section))
        }
        return result
    }

    private static func failure(_ code: String) -> SwiftErrorFlowAdapterError { .init(code) }

    private struct Reader {
        let bytes: [UInt8]
        func bounds(_ offset: Int, _ count: Int) throws {
            guard offset >= 0, count >= 0, offset <= bytes.count, count <= bytes.count - offset else {
                throw SwiftErrorFlowAdapterError("truncated_raw_structure")
            }
        }
        func u32(_ offset: Int) throws -> UInt32 {
            try bounds(offset, 4)
            return (0..<4).reduce(0) { $0 | (UInt32(bytes[offset + $1]) << ($1 * 8)) }
        }
        func u64(_ offset: Int) throws -> UInt64 {
            try bounds(offset, 8)
            return (0..<8).reduce(0) { $0 | (UInt64(bytes[offset + $1]) << ($1 * 8)) }
        }
        func fixedName(_ offset: Int) throws -> String {
            try bounds(offset, 16)
            let field = bytes[offset..<(offset + 16)]
            let end = field.firstIndex(of: 0) ?? offset + 16
            guard let value = String(bytes: bytes[offset..<end], encoding: .utf8) else {
                throw SwiftErrorFlowAdapterError("invalid_segment_or_section_name")
            }
            return value
        }
    }
}
