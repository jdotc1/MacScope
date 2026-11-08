import Foundation

/// The facts about one cache image that both import resolution (DC1) and crash-frame
/// symbolication (DC2) need, read from its mach header and load commands only:
/// identity (`LC_UUID`, `LC_ID_DYLIB`), the ordered dependency table, and the export tries.
/// Built through `HostCacheSnapshot`, so every byte read is bound to an admitted cache file.
struct ImageDescriptor: Sendable {
    enum DependencyKind: String, Sendable {
        case required, weak, reexport, upward
    }

    struct Dependency: Sendable, Equatable {
        var installName: [UInt8]
        var kind: DependencyKind
    }

    let catalogIndex: Int
    let path: [UInt8]
    let loadAddress: UInt64
    let uuid: [UInt8]
    /// Dependency table in load-command order. A reexport terminal's ordinal is a 1-based index
    /// into THIS table (the exporting image's own), not the importer's.
    let dependencies: [Dependency]
    /// Export tries as views over the mapped linkedit: LC_DYLD_INFO(_ONLY) then LC_DYLD_EXPORTS_TRIE.
    let exportTries: [Data]

    var reexportedDependencyOrdinals: [Int] {
        dependencies.indices.filter { dependencies[$0].kind == .reexport }.map { $0 + 1 }
    }

    private enum Command {
        static let segment64: UInt32 = 0x19
        static let idDylib: UInt32 = 0xd
        static let loadDylib: UInt32 = 0xc
        static let loadWeakDylib: UInt32 = 0x8000_0018
        static let reexportDylib: UInt32 = 0x8000_001f
        static let loadUpwardDylib: UInt32 = 0x8000_0023
        static let uuid: UInt32 = 0x1b
        static let dyldInfo: UInt32 = 0x22
        static let dyldInfoOnly: UInt32 = 0x8000_0022
        static let exportsTrie: UInt32 = 0x8000_0033
    }

    /// Loads and proves one catalog image. Throws `identityMismatch` when the bytes at the catalog
    /// address are not the image the catalog names, and `unsupportedFormat` when a bound is hit.
    static func load(
        catalogIndex: Int,
        in snapshot: HostCacheSnapshot,
        limits: DyldCacheImportResolutionLimits
    ) throws -> ImageDescriptor {
        let image = snapshot.catalog[catalogIndex]
        func mismatch(_ detail: String) -> CacheUnavailableError {
            CacheUnavailableError(.identityMismatch, "\(String(decoding: image.path, as: UTF8.self)): \(detail)")
        }
        func unsupported(_ detail: String) -> CacheUnavailableError {
            CacheUnavailableError(.unsupportedFormat, "\(String(decoding: image.path, as: UTF8.self)): \(detail)")
        }
        guard let headerBytes = snapshot.bytes(at: image.loadAddress, length: 32) else {
            throw mismatch("mach header is not inside an admitted mapping")
        }
        let header = LittleEndianReader(headerBytes)
        guard (try? header.u32(0)) == 0xfeed_facf else { throw mismatch("mach header magic is not 0xfeedfacf") }
        guard let commandCount = try? header.u32(16), let commandBytes = try? header.u32(20) else {
            throw mismatch("mach header is truncated")
        }
        guard commandCount <= UInt32(limits.maximumLoadCommands),
              commandBytes <= UInt32(limits.maximumLoadCommandBytes) else {
            throw unsupported("load command count or size over the bound")
        }
        let (commandsStart, startOverflow) = image.loadAddress.addingReportingOverflow(32)
        guard !startOverflow, let commands = snapshot.bytes(at: commandsStart, length: UInt64(commandBytes)) else {
            throw mismatch("load commands are not inside an admitted mapping")
        }
        let reader = LittleEndianReader(commands)

        var idName: [UInt8]?
        var uuid: [UInt8]?
        var dependencies: [Dependency] = []
        var linkedit: (vmaddr: UInt64, fileoff: UInt64, filesize: UInt64)?
        var trieRanges: [(offset: UInt64, size: UInt64)] = []
        var cursor = 0
        for _ in 0..<Int(commandCount) {
            guard let command = try? reader.u32(cursor), let size = try? reader.u32(cursor + 4),
                  size >= 8, Int(size) <= Int(commandBytes) - cursor else {
                throw unsupported("malformed load command")
            }
            let end = cursor + Int(size)
            func name(at field: Int) throws -> [UInt8] {
                guard let nameOffset = try? reader.u32(field), nameOffset >= 12, Int(nameOffset) < Int(size) else {
                    throw unsupported("dylib command name offset is out of range")
                }
                var bytes: [UInt8] = []
                var position = cursor + Int(nameOffset)
                while position < end {
                    guard let byte = reader.byte(position) else { break }
                    if byte == 0 { return bytes }
                    bytes.append(byte)
                    position += 1
                }
                throw unsupported("dylib command name is unterminated")
            }
            switch command {
            case Command.idDylib:
                guard idName == nil else { throw mismatch("more than one LC_ID_DYLIB") }
                idName = try name(at: cursor + 8)
            case Command.uuid:
                guard uuid == nil, size >= 24 else { throw mismatch("LC_UUID is duplicated or truncated") }
                uuid = (0..<16).map { reader.byte(cursor + 8 + $0) ?? 0 }
            case Command.loadDylib, Command.loadWeakDylib, Command.reexportDylib, Command.loadUpwardDylib:
                let kind: DependencyKind = command == Command.loadDylib ? .required
                    : command == Command.loadWeakDylib ? .weak
                    : command == Command.reexportDylib ? .reexport : .upward
                guard dependencies.count < limits.maximumDependencies else {
                    throw unsupported("dependency count over the bound")
                }
                dependencies.append(Dependency(installName: try name(at: cursor + 8), kind: kind))
            case Command.segment64:
                guard size >= 72 else { throw unsupported("LC_SEGMENT_64 is truncated") }
                let segmentName = (0..<16).compactMap { reader.byte(cursor + 8 + $0) }.prefix { $0 != 0 }
                if Array(segmentName) == Array("__LINKEDIT".utf8) {
                    guard let vmaddr = try? reader.u64(cursor + 24), let fileoff = try? reader.u64(cursor + 40),
                          let filesize = try? reader.u64(cursor + 48) else { throw unsupported("__LINKEDIT truncated") }
                    linkedit = (vmaddr, fileoff, filesize)
                }
            case Command.dyldInfo, Command.dyldInfoOnly:
                guard size >= 48, let offset = try? reader.u32(cursor + 40), let length = try? reader.u32(cursor + 44) else {
                    throw unsupported("LC_DYLD_INFO is truncated")
                }
                if length > 0 { trieRanges.append((UInt64(offset), UInt64(length))) }
            case Command.exportsTrie:
                guard size >= 16, let offset = try? reader.u32(cursor + 8), let length = try? reader.u32(cursor + 12) else {
                    throw unsupported("LC_DYLD_EXPORTS_TRIE is truncated")
                }
                if length > 0 { trieRanges.append((UInt64(offset), UInt64(length))) }
            default:
                break
            }
            cursor = end
        }

        guard let idName, idName == image.path else {
            throw mismatch("LC_ID_DYLIB does not equal the catalog path")
        }
        guard let uuid else { throw mismatch("no LC_UUID") }

        var tries: [Data] = []
        for range in trieRanges {
            guard let linkedit,
                  range.offset >= linkedit.fileoff,
                  range.offset - linkedit.fileoff <= linkedit.filesize,
                  range.size <= linkedit.filesize - (range.offset - linkedit.fileoff) else {
                throw unsupported("export trie lies outside __LINKEDIT")
            }
            let (address, overflow) = linkedit.vmaddr.addingReportingOverflow(range.offset - linkedit.fileoff)
            guard !overflow, let trie = snapshot.bytes(at: address, length: range.size) else {
                throw unsupported("export trie is not inside one admitted mapping")
            }
            tries.append(trie)
        }
        return ImageDescriptor(
            catalogIndex: catalogIndex, path: image.path, loadAddress: image.loadAddress, uuid: uuid,
            dependencies: dependencies, exportTries: tries)
    }
}

/// Bounded most-recently-used cache of descriptors. Single-threaded by construction (one per
/// resolution session); evicts the least recently used entry at capacity.
struct ImageDescriptorCache {
    private var storage: [Int: ImageDescriptor] = [:]
    private var order: [Int] = []
    let capacity: Int

    init(capacity: Int) { self.capacity = max(1, capacity) }

    var count: Int { storage.count }

    mutating func descriptor(
        for catalogIndex: Int,
        in snapshot: HostCacheSnapshot,
        limits: DyldCacheImportResolutionLimits,
        loaded: inout Int
    ) throws -> ImageDescriptor {
        if let hit = storage[catalogIndex] {
            if let position = order.firstIndex(of: catalogIndex) {
                order.remove(at: position)
                order.append(catalogIndex)
            }
            return hit
        }
        let descriptor = try ImageDescriptor.load(catalogIndex: catalogIndex, in: snapshot, limits: limits)
        loaded += 1
        if storage.count >= capacity, let oldest = order.first {
            order.removeFirst()
            storage[oldest] = nil
        }
        storage[catalogIndex] = descriptor
        order.append(catalogIndex)
        return descriptor
    }
}
