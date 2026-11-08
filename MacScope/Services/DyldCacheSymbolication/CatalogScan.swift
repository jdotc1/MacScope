import Foundation

/// One pass over every catalog image's mach header: LC_UUID and segment extents, plus the main
/// header's `imagesText` UUIDs when that array exists. Built once per cache UUID and memoized.
/// This is what proves "exactly one catalog image carries this UUID" without trusting a path.
struct CatalogScan: Sendable {
    struct Extent: Sendable {
        var start: UInt64
        var end: UInt64
        var catalogIndex: Int
    }

    var uuidToCatalogIndices: [[UInt8]: [Int]] = [:]
    var uuidByCatalogIndex: [Int: [UInt8]] = [:]
    var extents: [Extent] = []
    /// `dyld_cache_image_text_info` UUID by load address; nil when the header has no such array.
    /// An address with conflicting records maps to an empty array.
    var textInfoUUIDs: [UInt64: [UInt8]]?
    var unreadableImages = 0

    var retainedBytes: Int { uuidToCatalogIndices.count * 64 + uuidByCatalogIndex.count * 40 + extents.count * 24 + (textInfoUUIDs?.count ?? 0) * 40 }

    struct Cancelled: Error {}

    static func build(
        snapshot: HostCacheSnapshot, limits: DyldCacheSymbolicationLimits, isCancelled: () -> Bool
    ) throws -> CatalogScan {
        var scan = CatalogScan()
        scan.textInfoUUIDs = readTextInfo(snapshot)
        for (index, image) in snapshot.catalog.enumerated() {
            if index % 256 == 0, isCancelled() { throw Cancelled() }
            guard let facts = scanOne(image, in: snapshot, limits: limits.descriptorLimits) else {
                scan.unreadableImages += 1
                continue
            }
            scan.uuidToCatalogIndices[facts.uuid, default: []].append(index)
            scan.uuidByCatalogIndex[index] = facts.uuid
            for extent in facts.extents { scan.extents.append(Extent(start: extent.0, end: extent.1, catalogIndex: index)) }
        }
        return scan
    }

    private static func scanOne(
        _ image: HostCacheSnapshot.CatalogImage, in snapshot: HostCacheSnapshot, limits: DyldCacheImportResolutionLimits
    ) -> (uuid: [UInt8], extents: [(UInt64, UInt64)])? {
        guard let commands = try? ImageSymbolFacts.loadCommands(of: image, in: snapshot, limits: limits) else { return nil }
        let reader = LittleEndianReader(commands.bytes)
        var uuid: [UInt8]?
        var extents: [(UInt64, UInt64)] = []
        var cursor = 0
        for _ in 0..<commands.count {
            guard let command = try? reader.u32(cursor), let size = try? reader.u32(cursor + 4),
                  size >= 8, Int(size) <= commands.bytes.count - cursor else { return nil }
            if command == 0x1b {
                guard uuid == nil, size >= 24 else { return nil }
                uuid = (0..<16).map { reader.byte(cursor + 8 + $0) ?? 0 }
            } else if command == 0x19 {
                guard size >= 72, let vmaddr = try? reader.u64(cursor + 24), let vmsize = try? reader.u64(cursor + 32) else { return nil }
                let (end, overflow) = vmaddr.addingReportingOverflow(vmsize)
                guard !overflow else { return nil }
                if vmsize > 0 { extents.append((vmaddr, end)) }
            }
            cursor += Int(size)
        }
        guard let uuid else { return nil }
        return (uuid, extents)
    }

    /// `imagesText` at header 0x88 (file offset) / 0x90 (count); records are 32 bytes
    /// (uuid@0, loadAddress@16).
    private static func readTextInfo(_ snapshot: HostCacheSnapshot) -> [UInt64: [UInt8]]? {
        let data = snapshot.files[0].data
        let reader = LittleEndianReader(data)
        guard let offset = try? reader.u64(0x88), let count = try? reader.u64(0x90),
              count > 0, count <= UInt64(DyldSharedCacheParser.maximumArrayCount),
              reader.range(offset, count * 32) != nil else { return nil }
        var result: [UInt64: [UInt8]] = [:]
        for index in 0..<Int(count) {
            let base = Int(offset) + index * 32
            guard let address = try? reader.u64(base + 16) else { return nil }
            let uuid = (0..<16).map { reader.byte(base + $0) ?? 0 }
            result[address] = result[address] == nil ? uuid : []
        }
        return result
    }
}
