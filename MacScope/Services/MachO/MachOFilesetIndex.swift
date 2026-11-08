import Foundation

/// Data-only facts. Neither this index nor an entry identity grants image loading authority.
struct MachOFilesetIndex: Codable, Sendable {
    struct Identity: Codable, Hashable, Sendable {
        let parent: MachOSliceArtifactIdentity
        let commandOffset: UInt64
        let fileOffset: UInt64
        let virtualAddress: UInt64
        let entryID: String
    }
    struct Header: Codable, Sendable {
        let cpuType: Int32
        let cpuSubtype: Int32
        let fileType: UInt32
        let flags: UInt32
        let loadCommandCount: UInt32
        let loadCommandsSize: UInt32
    }
    struct Segment: Codable, Sendable {
        let name: String
        let fileOffset: UInt64
        let fileSize: UInt64
        let virtualAddress: UInt64
        let virtualSize: UInt64
    }
    struct Entry: Codable, Sendable {
        let identity: Identity
        let commandSize: UInt32
        let header: Header
        /// Nil means no independently available LC_UUID, not an invented identity.
        let childUUID: UUID?
        let segments: [Segment]
        /// Cross-entry overlaps are retained as a warning, never a global address map.
        let sharesOrOverlapsAnotherEntry: Bool
    }
    let parent: MachOSliceArtifactIdentity
    let entries: [Entry]
}

enum MachOFilesetIndexError: Error, Equatable {
    case unsupported(String, offset: UInt64)
    case malformed(String, offset: UInt64)
    case limit(String)
    case identityMismatch
}

struct MachOFilesetIndexLimits: Sendable {
    var maximumContainerBytes = 512 * 1_024 * 1_024
    var maximumCommandBytes = 4 * 1_024 * 1_024
    var maximumCommands = 4_096
    var maximumEntries = 1_024
    var maximumEntryIDBytes = 1_024
    var maximumChildCommandBytes = 16 * 1_024 * 1_024
    var maximumSegments = 4_096
    var maximumSections = 65_536
    var maximumMappingComparisons = 262_144
    var maximumOutputBytes = 4 * 1_024 * 1_024

    fileprivate func validate() throws {
        let hard = Self()
        for (value, ceiling) in [
            (maximumContainerBytes, hard.maximumContainerBytes),
            (maximumCommandBytes, hard.maximumCommandBytes),
            (maximumCommands, hard.maximumCommands), (maximumEntries, hard.maximumEntries),
            (maximumEntryIDBytes, hard.maximumEntryIDBytes),
            (maximumChildCommandBytes, hard.maximumChildCommandBytes),
            (maximumSegments, hard.maximumSegments), (maximumSections, hard.maximumSections),
            (maximumMappingComparisons, hard.maximumMappingComparisons),
            (maximumOutputBytes, hard.maximumOutputBytes)
        ] { guard value > 0, value <= ceiling else { throw MachOFilesetIndexError.limit("configuration") } }
    }
}

/// Parses only a retained thin little-endian arm64 fileset. Never slices a child:
/// segment and section file offsets remain relative to the admitted whole container.
struct MachOFilesetIndexParser {
    /// Trust precondition: the caller supplies the already retained immutable container
    /// and its already admitted identity. Byte count, CPU and independently present UUID
    /// consistency checks below do not establish that the supplied digest names these bytes.
    /// This API neither computes a digest nor performs source admission or loading.
    func index(_ bytes: Data, admittedParent: MachOSliceArtifactIdentity,
               limits: MachOFilesetIndexLimits = .init()) throws -> MachOFilesetIndex {
        try limits.validate()
        guard bytes.count <= limits.maximumContainerBytes else { throw MachOFilesetIndexError.limit("container bytes") }
        guard UInt64(bytes.count) == admittedParent.selectedSliceByteCount else { throw MachOFilesetIndexError.identityMismatch }
        var reader = Reader(bytes: bytes, limits: limits)
        let outer = try reader.image(at: 0, isOuter: true)
        guard outer.header.cpuType == admittedParent.rawCPUType,
              outer.header.cpuSubtype == admittedParent.rawCPUSubtype else { throw MachOFilesetIndexError.identityMismatch }
        if let actual = outer.uuid, let expected = admittedParent.uuid, actual != expected {
            throw MachOFilesetIndexError.identityMismatch
        }
        var ids = Set<String>(), offsets = Set<UInt64>()
        var children: [(RawEntry, Image)] = []
        for entry in outer.entries {
            guard ids.insert(entry.name).inserted, offsets.insert(entry.fileOffset).inserted else {
                throw MachOFilesetIndexError.malformed("duplicate entry ID or header offset", offset: entry.commandOffset)
            }
            guard entry.fileOffset >= outer.headerEnd, entry.fileOffset % 8 == 0 else {
                throw MachOFilesetIndexError.malformed("child header coordinate", offset: entry.commandOffset)
            }
            let child = try reader.image(at: entry.fileOffset, isOuter: false)
            // One local file-backed mapping must explain the entire header/command span
            // and the LC_FILESET_ENTRY vmaddr. No next-entry extent inference is used.
            let covering = child.segments.filter {
                entry.fileOffset >= $0.fileOffset && child.headerEnd <= $0.fileOffset + $0.fileSize
            }
            guard covering.count == 1, let segment = covering.first,
                  entry.fileOffset - segment.fileOffset <= segment.virtualSize,
                  child.headerEnd - entry.fileOffset <= segment.virtualSize - (entry.fileOffset - segment.fileOffset),
                  segment.virtualAddress + (entry.fileOffset - segment.fileOffset) == entry.vmaddr else {
                throw MachOFilesetIndexError.unsupported("unproved absolute child header mapping", offset: entry.fileOffset)
            }
            children.append((entry, child))
        }
        var overlap = Set<Int>()
        for i in children.indices {
            for j in children.indices where j < i {
                let a = children[i], b = children[j]
                guard !(a.0.fileOffset < b.1.headerEnd && b.0.fileOffset < a.1.headerEnd) else {
                    throw MachOFilesetIndexError.malformed("overlapping child header envelopes", offset: a.0.fileOffset)
                }
                for left in a.1.segments { for right in b.1.segments {
                    try reader.chargeComparison()
                    if Reader.intersects(left.fileOffset, left.fileSize, right.fileOffset, right.fileSize)
                        || Reader.intersects(left.virtualAddress, left.virtualSize, right.virtualAddress, right.virtualSize) {
                        overlap.insert(i); overlap.insert(j)
                    }
                } }
            }
        }
        let entries = children.enumerated().map { index, pair in
            MachOFilesetIndex.Entry(identity: .init(parent: admittedParent,
                commandOffset: pair.0.commandOffset, fileOffset: pair.0.fileOffset,
                virtualAddress: pair.0.vmaddr, entryID: pair.0.name),
                commandSize: pair.0.commandSize, header: pair.1.header,
                childUUID: pair.1.uuid, segments: pair.1.segments,
                sharesOrOverlapsAnotherEntry: overlap.contains(index))
        }
        let result = MachOFilesetIndex(parent: admittedParent, entries: entries)
        // Construction is separately bounded; this cap includes all encoded wrappers,
        // repeated parent identity and escaped strings. Encoding is not a content hash.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard try encoder.encode(result).count <= limits.maximumOutputBytes else {
            throw MachOFilesetIndexError.limit("encoded index bytes")
        }
        return result
    }

    private struct RawEntry {
        let commandOffset: UInt64
        let commandSize: UInt32
        let vmaddr: UInt64
        let fileOffset: UInt64
        let name: String
    }
    private struct Image {
        let header: MachOFilesetIndex.Header
        let headerEnd: UInt64
        let uuid: UUID?
        let segments: [MachOFilesetIndex.Segment]
        let entries: [RawEntry]
    }
    private struct Reader {
        let bytes: Data
        let limits: MachOFilesetIndexLimits
        var childWork = 0
        var segmentCount = 0
        var sectionCount = 0
        var comparisons = 0
        var primitive: LittleEndianReader { LittleEndianReader(bytes) }

        func span(_ at: UInt64, _ count: UInt64) throws -> Range<Int> {
            guard let range = primitive.range(at, count) else {
                throw MachOFilesetIndexError.malformed("file extent", offset: at)
            }
            return range
        }
        func u32(_ at: UInt64) throws -> UInt32 { try primitive.u32(span(at, 4).lowerBound) }
        func u64(_ at: UInt64) throws -> UInt64 { try primitive.u64(span(at, 8).lowerBound) }
        func add(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
            let (sum, overflow) = a.addingReportingOverflow(b)
            guard !overflow else { throw MachOFilesetIndexError.malformed("address overflow", offset: a) }
            return sum
        }
        static func intersects(_ a: UInt64, _ sizeA: UInt64, _ b: UInt64, _ sizeB: UInt64) -> Bool {
            sizeA > 0 && sizeB > 0 && a < b + sizeB && b < a + sizeA
        }
        mutating func chargeComparison() throws {
            guard comparisons < limits.maximumMappingComparisons else { throw MachOFilesetIndexError.limit("mapping comparisons") }
            comparisons += 1
        }
        func string(at: UInt64, available: UInt64, maximum: Int, requireTerminator: Bool) throws -> String {
            let count = min(available, UInt64(maximum + 1))
            let range = try span(at, count)
            var raw: [UInt8] = []
            var terminated = false
            for offset in range {
                let byte = bytes[bytes.startIndex + offset]
                if byte == 0 { terminated = true; break }
                raw.append(byte)
            }
            guard (!requireTerminator || terminated), raw.count <= maximum,
                  let text = String(bytes: raw, encoding: .utf8),
                  !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                throw MachOFilesetIndexError.malformed("bounded UTF-8 string", offset: at)
            }
            return text
        }

        mutating func image(at base: UInt64, isOuter: Bool) throws -> Image {
            _ = try span(base, 32)
            guard try u32(base) == MachOConstants.machMagic64 else {
                throw MachOFilesetIndexError.unsupported("not uncompressed thin little-endian Mach-O64", offset: base)
            }
            let cpu = Int32(bitPattern: try u32(base + 4))
            let subtype = Int32(bitPattern: try u32(base + 8))
            let variant = MachOSliceArchitectureVariant.classify(rawCPUType: cpu, rawCPUSubtype: subtype)
            guard variant == .arm64 || variant == .arm64e else {
                throw MachOFilesetIndexError.unsupported("architecture", offset: base)
            }
            let type = try u32(base + 12)
            if isOuter {
                guard type == MachOConstants.fileTypeFileset else { throw MachOFilesetIndexError.unsupported("not MH_FILESET", offset: base) }
            } else {
                guard type != MachOConstants.fileTypeFileset else { throw MachOFilesetIndexError.unsupported("nested fileset", offset: base) }
                guard [MachOConstants.fileTypeExecute, MachOConstants.fileTypeDylib, MachOConstants.fileTypeBundle].contains(type) else {
                    throw MachOFilesetIndexError.unsupported("child file type", offset: base)
                }
            }
            let ncmds = try u32(base + 16), commandBytes = try u32(base + 20)
            guard UInt64(ncmds) <= UInt64(limits.maximumCommands), UInt64(commandBytes) <= UInt64(limits.maximumCommandBytes) else { throw MachOFilesetIndexError.limit("load commands") }
            guard try u32(base + 28) == 0, commandBytes % 8 == 0, UInt64(ncmds) * 8 <= UInt64(commandBytes) else {
                throw MachOFilesetIndexError.malformed("header command envelope", offset: base)
            }
            let commandStart = try add(base, 32), end = try add(commandStart, UInt64(commandBytes))
            _ = try span(commandStart, UInt64(commandBytes))
            if !isOuter {
                guard Int(commandBytes) + 32 <= limits.maximumChildCommandBytes - childWork else { throw MachOFilesetIndexError.limit("aggregate child header work") }
                childWork += Int(commandBytes) + 32
            }
            var cursor = commandStart
            var uuid: UUID?
            var segments: [MachOFilesetIndex.Segment] = []
            var entries: [RawEntry] = []
            for _ in 0..<ncmds {
                guard cursor <= end, end - cursor >= 8 else { throw MachOFilesetIndexError.malformed("truncated command header", offset: cursor) }
                let command = try u32(cursor), size = try u32(cursor + 4)
                guard size >= 8, size % 8 == 0, UInt64(size) <= end - cursor else { throw MachOFilesetIndexError.malformed("command size", offset: cursor) }
                switch command {
                case MachOConstants.loadCommandFilesetEntry:
                    guard isOuter else { throw MachOFilesetIndexError.unsupported("nested entry command", offset: cursor) }
                    guard entries.count < limits.maximumEntries else { throw MachOFilesetIndexError.limit("entries") }
                    guard size >= 40, try u32(cursor + 28) == 0 else { throw MachOFilesetIndexError.malformed("fileset command", offset: cursor) }
                    let stringOffset = try u32(cursor + 24)
                    guard stringOffset >= 32, stringOffset < size else { throw MachOFilesetIndexError.malformed("entry lc_str", offset: cursor) }
                    let name = try string(at: cursor + UInt64(stringOffset), available: UInt64(size - stringOffset), maximum: limits.maximumEntryIDBytes, requireTerminator: true)
                    guard !name.isEmpty else { throw MachOFilesetIndexError.malformed("empty entry ID", offset: cursor) }
                    entries.append(.init(commandOffset: cursor, commandSize: size,
                        vmaddr: try u64(cursor + 8), fileOffset: try u64(cursor + 16), name: name))
                case MachOConstants.loadCommandUUID:
                    guard size == 24, uuid == nil else { throw MachOFilesetIndexError.malformed("UUID command multiplicity or size", offset: cursor) }
                    let raw = try span(cursor + 8, 16).map { bytes[bytes.startIndex + $0] }
                    uuid = UUID(uuid: (raw[0],raw[1],raw[2],raw[3],raw[4],raw[5],raw[6],raw[7],raw[8],raw[9],raw[10],raw[11],raw[12],raw[13],raw[14],raw[15]))
                case MachOConstants.loadCommandSegment64:
                    guard size >= 72, segmentCount < limits.maximumSegments else { throw MachOFilesetIndexError.limit("segments or segment header") }
                    segmentCount += 1
                    let nsects = try u32(cursor + 64), flags = try u32(cursor + 68)
                    guard UInt64(size) == 72 + UInt64(nsects) * 80 else {
                        throw MachOFilesetIndexError.malformed("segment section envelope", offset: cursor)
                    }
                    guard UInt64(nsects) <= UInt64(limits.maximumSections - sectionCount) else {
                        throw MachOFilesetIndexError.limit("sections")
                    }
                    sectionCount += Int(nsects)
                    guard flags & MachOConstants.segmentFlagProtectedVersion1 == 0 else { throw MachOFilesetIndexError.unsupported("protected segment", offset: cursor) }
                    let segment = MachOFilesetIndex.Segment(name: try string(at: cursor + 8, available: 16, maximum: 16, requireTerminator: false),
                        fileOffset: try u64(cursor + 40), fileSize: try u64(cursor + 48), virtualAddress: try u64(cursor + 24), virtualSize: try u64(cursor + 32))
                    _ = try add(segment.virtualAddress, segment.virtualSize)
                    _ = try span(segment.fileOffset, segment.fileSize)
                    guard segment.fileSize <= segment.virtualSize else { throw MachOFilesetIndexError.unsupported("nonmapped file segment", offset: cursor) }
                    for prior in segments {
                        try chargeComparison()
                        if Self.intersects(prior.fileOffset, prior.fileSize, segment.fileOffset, segment.fileSize)
                            || Self.intersects(prior.virtualAddress, prior.virtualSize, segment.virtualAddress, segment.virtualSize) {
                            throw MachOFilesetIndexError.unsupported("ambiguous mappings within one image", offset: cursor)
                        }
                    }
                    for i in 0..<nsects { try section(at: cursor + 72 + UInt64(i) * 80, segment: segment) }
                    segments.append(segment)
                case MachOConstants.loadCommandEncryptionInfo, MachOConstants.loadCommandEncryptionInfo64:
                    guard size == 24 else { throw MachOFilesetIndexError.malformed("encryption command", offset: cursor) }
                    _ = try span(UInt64(u32(cursor + 8)), UInt64(u32(cursor + 12)))
                    guard try u32(cursor + 16) == 0 else { throw MachOFilesetIndexError.unsupported("encrypted bytes", offset: cursor) }
                default: break // Envelope only; no facts or offset interpretation from other commands.
                }
                cursor += UInt64(size)
            }
            guard cursor == end else { throw MachOFilesetIndexError.malformed("sizeofcmds mismatch", offset: base) }
            return Image(header: .init(cpuType: cpu, cpuSubtype: subtype, fileType: type,
                flags: try u32(base + 24), loadCommandCount: ncmds, loadCommandsSize: commandBytes),
                headerEnd: end, uuid: uuid, segments: segments, entries: entries)
        }

        func section(at: UInt64, segment: MachOFilesetIndex.Segment) throws {
            let address = try u64(at + 32), size = try u64(at + 40)
            let end = try add(address, size)
            guard address >= segment.virtualAddress, end <= segment.virtualAddress + segment.virtualSize else {
                throw MachOFilesetIndexError.malformed("section VM extent", offset: at)
            }
            guard try u32(at + 52) <= 63 else {
                throw MachOFilesetIndexError.malformed("section alignment exponent", offset: at)
            }
            let kind = try u32(at + 64) & MachOConstants.sectionTypeMask
            if ![MachOConstants.sectionTypeZeroFill, MachOConstants.sectionTypeGBZeroFill, MachOConstants.sectionTypeThreadLocalZeroFill].contains(kind) {
                let fileOffset = UInt64(try u32(at + 48))
                _ = try span(fileOffset, size)
                guard fileOffset >= segment.fileOffset, try add(fileOffset, size) <= segment.fileOffset + segment.fileSize else {
                    throw MachOFilesetIndexError.malformed("section file extent", offset: at)
                }
            }
            let relocOffset = UInt64(try u32(at + 56)), relocCount = UInt64(try u32(at + 60))
            _ = try span(relocOffset, relocCount * 8)
        }
    }
}
