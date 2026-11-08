import Foundation

/// Everything one proven cache image contributes to naming: identity, segment and section facts,
/// function starts, and its export enumeration (or the typed reason there is none).
struct ImageSymbolIndex: Sendable {
    var catalogIndex: Int
    var path: [UInt8]
    var uuid: [UInt8]
    var loadAddress: UInt64
    var facts: ImageSymbolFacts
    var exports: ExportEnumeration

    var retainedBytes: Int {
        let exportBytes: Int
        if case .entries(let names) = exports { exportBytes = names.retainedBytes } else { exportBytes = 0 }
        return facts.retainedBytes + exportBytes + path.count + 128
    }
}

/// Bounded LRU memo shared across symbolicators. Keyed by (cache UUID, image UUID), so a changed
/// cache can never serve an index built against another one. Failures are not memoized.
final class SymbolicationMemo: @unchecked Sendable {
    struct Key: Hashable {
        var cacheUUID: [UInt8]
        var imageUUID: [UInt8]
    }

    private let lock = NSLock()
    private let maximumImages: Int
    private let maximumBytes: Int
    private var storage: [Key: ImageSymbolIndex] = [:]
    private var order: [Key] = []
    private var scans: [[UInt8]: CatalogScan] = [:]
    private(set) var imageBuildCount = 0
    private var localStatuses: [[UInt8]: LocalSymbolsUnavailableReason] = [:]
    private(set) var scanBuildCount = 0
    private(set) var localSymbolsBuildCount = 0

    init(limits: DyldCacheSymbolicationLimits = .production) {
        maximumImages = max(1, limits.maximumMemoImages)
        maximumBytes = limits.maximumMemoBytes
    }

    var imageCount: Int { lock.withLock { storage.count } }
    var retainedBytes: Int { lock.withLock { storage.values.reduce(0) { $0 + $1.retainedBytes } } }

    func contains(cacheUUID: [UInt8], imageUUID: [UInt8]) -> Bool {
        lock.withLock { storage[Key(cacheUUID: cacheUUID, imageUUID: imageUUID)] != nil }
    }

    func index(for key: Key, build: () throws -> ImageSymbolIndex) rethrows -> ImageSymbolIndex {
        try lock.withLock {
            if let hit = storage[key] {
                order.removeAll { $0 == key }
                order.append(key)
                return hit
            }
            let built = try build()
            imageBuildCount += 1
            guard built.retainedBytes <= maximumBytes else { return built }
            storage[key] = built
            order.append(key)
            evict()
            return built
        }
    }

    func scan(cacheUUID: [UInt8], build: () throws -> CatalogScan) rethrows -> CatalogScan {
        try lock.withLock {
            if let hit = scans[cacheUUID] { return hit }
            let built = try build()
            scanBuildCount += 1
            // One scan per cache UUID; keep only the most recent few.
            if scans.count >= 2, let drop = scans.keys.first { scans[drop] = nil }
            scans[cacheUUID] = built
            return built
        }
    }

    /// DC2-3: the local-symbols availability of one cache, computed once per cache UUID.
    func localSymbolsStatus(
        cacheUUID: [UInt8], build: () -> LocalSymbolsUnavailableReason
    ) -> LocalSymbolsUnavailableReason {
        lock.withLock {
            if let hit = localStatuses[cacheUUID] { return hit }
            let built = build()
            localSymbolsBuildCount += 1
            if localStatuses.count >= 2, let drop = localStatuses.keys.first { localStatuses[drop] = nil }
            localStatuses[cacheUUID] = built
            return built
        }
    }

    private func evict() {
        var total = storage.values.reduce(0) { $0 + $1.retainedBytes }
        while order.count > 1, storage.count > maximumImages || total > maximumBytes {
            let oldest = order.removeFirst()
            if let removed = storage.removeValue(forKey: oldest) { total -= removed.retainedBytes }
        }
    }
}
