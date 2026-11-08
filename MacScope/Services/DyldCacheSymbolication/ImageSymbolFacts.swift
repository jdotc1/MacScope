import Foundation

/// Segment, section and function-start facts for one cache image, read from its own mach header
/// and `LC_FUNCTION_STARTS` through the admitted snapshot. All addresses are cache unslid VM.
struct ImageSymbolFacts: Sendable {
    struct Section: Sendable {
        var name: String
        var address: UInt64
        var size: UInt64
        var flags: UInt32

        var end: UInt64 { address &+ size }
        /// S_SYMBOL_STUBS (type 0x8, covers `__stubs` and `__auth_stubs`) or `__stub_helper`.
        /// The helper has a regular section type, so it is recognised by name (UNCONFIRMED on a real image).
        var isStub: Bool { flags & 0xff == 0x8 || name == "__stub_helper" }
        /// S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS.
        var isInstructions: Bool { flags & 0x8000_0400 != 0 }
    }

    struct Segment: Sendable {
        var name: String
        var address: UInt64
        var size: UInt64
        var initialProtection: UInt32
        var sections: [Section]

        var end: UInt64 { address &+ size }
        var isExecutable: Bool { initialProtection & 4 != 0 }
    }

    enum StartsStatus: Sendable, Equatable {
        case terminated
        case failure(FunctionBoundsFailure)
    }

    var segments: [Segment]
    /// Strictly increasing absolute function-start addresses.
    var functionStarts: [UInt64]
    var startsStatus: StartsStatus

    var retainedBytes: Int { functionStarts.count * 8 + segments.count * 256 }

    func segment(containing address: UInt64) -> Segment? {
        segments.first { $0.address <= address && address < $0.end }
    }

    /// Greatest start `<= address`, with its successor if the list has one.
    func start(atOrBelow address: UInt64) -> (index: Int, start: UInt64)? {
        var low = 0, high = functionStarts.count
        while low < high {
            let mid = (low + high) / 2
            if functionStarts[mid] <= address { low = mid + 1 } else { high = mid }
        }
        return low == 0 ? nil : (low - 1, functionStarts[low - 1])
    }

    private enum Command {
        static let segment64: UInt32 = 0x19
        static let functionStarts: UInt32 = 0x26
    }

    static func load(
        catalogIndex: Int, in snapshot: HostCacheSnapshot, limits: DyldCacheSymbolicationLimits
    ) throws -> ImageSymbolFacts {
        let image = snapshot.catalog[catalogIndex]
        func bad(_ detail: String) -> CacheUnavailableError {
            CacheUnavailableError(.unsupportedFormat, "\(String(decoding: image.path, as: UTF8.self)): \(detail)")
        }
        let commands = try loadCommands(of: image, in: snapshot, limits: limits.descriptorLimits)
        let reader = LittleEndianReader(commands.bytes)
        var segments: [Segment] = []
        var linkedit: (vmaddr: UInt64, fileoff: UInt64, filesize: UInt64)?
        var startsRange: (offset: UInt64, size: UInt64)?
        var textAddress: UInt64?
        var cursor = 0
        for _ in 0..<commands.count {
            guard let command = try? reader.u32(cursor), let size = try? reader.u32(cursor + 4),
                  size >= 8, Int(size) <= commands.bytes.count - cursor else { throw bad("malformed load command") }
            switch command {
            case Command.segment64:
                guard size >= 72, let vmaddr = try? reader.u64(cursor + 24), let vmsize = try? reader.u64(cursor + 32),
                      let fileoff = try? reader.u64(cursor + 40), let filesize = try? reader.u64(cursor + 48),
                      let initprot = try? reader.u32(cursor + 60), let sectionCount = try? reader.u32(cursor + 64),
                      !vmaddr.addingReportingOverflow(vmsize).overflow else { throw bad("LC_SEGMENT_64 is truncated or overflows") }
                let name = cString(reader, cursor + 8)
                guard sectionCount <= 4_096, Int(size) == 72 + Int(sectionCount) * 80 else {
                    throw bad("LC_SEGMENT_64 section count does not match its size")
                }
                var sections: [Section] = []
                for index in 0..<Int(sectionCount) {
                    let base = cursor + 72 + index * 80
                    guard let address = try? reader.u64(base + 32), let sectionSize = try? reader.u64(base + 40),
                          let flags = try? reader.u32(base + 64),
                          !address.addingReportingOverflow(sectionSize).overflow else { throw bad("section overflows") }
                    sections.append(Section(name: cString(reader, base), address: address, size: sectionSize, flags: flags))
                }
                guard segments.count < 256 else { throw bad("segment count over the bound") }
                segments.append(Segment(name: name, address: vmaddr, size: vmsize, initialProtection: initprot, sections: sections))
                if name == "__LINKEDIT" { linkedit = (vmaddr, fileoff, filesize) }
                if name == "__TEXT" { textAddress = vmaddr }
            case Command.functionStarts:
                guard startsRange == nil else { throw bad("more than one LC_FUNCTION_STARTS") }
                guard size >= 16, let offset = try? reader.u32(cursor + 8), let length = try? reader.u32(cursor + 12) else {
                    throw bad("LC_FUNCTION_STARTS is truncated")
                }
                startsRange = (UInt64(offset), UInt64(length))
            default:
                break
            }
            cursor += Int(size)
        }

        guard let range = startsRange else {
            return ImageSymbolFacts(segments: segments, functionStarts: [], startsStatus: .failure(.absentCommand))
        }
        guard range.size > 0 else {
            return ImageSymbolFacts(segments: segments, functionStarts: [], startsStatus: .failure(.emptyPayload))
        }
        guard let linkedit, range.offset >= linkedit.fileoff, range.offset - linkedit.fileoff <= linkedit.filesize,
              range.size <= linkedit.filesize - (range.offset - linkedit.fileoff) else {
            throw bad("function starts lie outside __LINKEDIT")
        }
        let (address, overflow) = linkedit.vmaddr.addingReportingOverflow(range.offset - linkedit.fileoff)
        guard !overflow, let payload = snapshot.bytes(at: address, length: range.size) else {
            throw bad("function starts are not inside one admitted mapping")
        }
        var current = textAddress ?? image.loadAddress
        var starts: [UInt64] = []
        let data = LittleEndianReader(payload)
        var position = 0
        var status = StartsStatus.failure(.unterminated)
        parsing: while position < payload.count {
            var delta: UInt64 = 0
            var shift: UInt64 = 0
            while true {
                guard position < payload.count, let byte = data.byte(position) else { break parsing }
                position += 1
                let bits = UInt64(byte & 0x7f)
                if shift >= 64 || (shift == 63 && bits > 1) { throw bad("function start ULEB overflows") }
                delta |= bits << shift
                if byte & 0x80 == 0 { break }
                shift += 7
            }
            if delta == 0 { status = .terminated; break }
            let (next, wrapped) = current.addingReportingOverflow(delta)
            guard !wrapped else { throw bad("function start address overflows") }
            if starts.count >= limits.maximumFunctionStarts {
                status = .failure(.truncatedByCap)
                break
            }
            starts.append(next)
            current = next
        }
        return ImageSymbolFacts(segments: segments, functionStarts: starts, startsStatus: status)
    }

    static func cString(_ reader: LittleEndianReader, _ offset: Int) -> String {
        var bytes: [UInt8] = []
        for index in 0..<16 {
            guard let byte = reader.byte(offset + index), byte != 0 else { break }
            bytes.append(byte)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Mach-O 64 header and load-command bytes of a catalog image.
    static func loadCommands(
        of image: HostCacheSnapshot.CatalogImage, in snapshot: HostCacheSnapshot, limits: DyldCacheImportResolutionLimits
    ) throws -> (bytes: Data, count: Int) {
        func mismatch(_ detail: String) -> CacheUnavailableError {
            CacheUnavailableError(.identityMismatch, "\(String(decoding: image.path, as: UTF8.self)): \(detail)")
        }
        guard let headerBytes = snapshot.bytes(at: image.loadAddress, length: 32) else {
            throw mismatch("mach header is not inside an admitted mapping")
        }
        let header = LittleEndianReader(headerBytes)
        guard (try? header.u32(0)) == 0xfeed_facf else { throw mismatch("mach header magic is not 0xfeedfacf") }
        guard let count = try? header.u32(16), let size = try? header.u32(20),
              count <= UInt32(limits.maximumLoadCommands), size <= UInt32(limits.maximumLoadCommandBytes) else {
            throw CacheUnavailableError(.unsupportedFormat, "load command count or size over the bound")
        }
        let (start, overflow) = image.loadAddress.addingReportingOverflow(32)
        guard !overflow, let bytes = snapshot.bytes(at: start, length: UInt64(size)) else {
            throw mismatch("load commands are not inside an admitted mapping")
        }
        return (bytes, Int(count))
    }
}
