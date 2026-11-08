/// Immutable owner-key adjacency over raw analysis xref ordinals.
///
/// Keys are K(a) = names.owner(a)?.start ?? a. Queries must pass the queued
/// key verbatim: applying K again can change a shadowed function-start key.
/// All kinds and duplicate rows are retained; traversal performs filtering.
struct CallOwnerAdjacencyIndex: Sendable {
    /// Smallest raw xref count for which an owner index is built or read (the one
    /// named home of the former literal 100_000).
    static let minimumIndexedXRefs = 100_000
    /// Read eligibility ceiling (16,777,216). Optional background warmup admits fewer
    /// rows on purpose; see CallOwnerPreparation.maximumWarmupXRefs.
    static let maximumIndexedXRefs = XRefEndpointIndex.maximumIndexedXRefs
    private static let checkpointInterval = 256

    private let outgoingKeys: [UInt64]
    private let outgoingOrdinals: [UInt32]
    private let incomingKeys: [UInt64]
    private let incomingOrdinals: [UInt32]

    var count: Int { outgoingKeys.count }

    /// Returns nil above the admission cap, before any UInt32 conversion.
    /// The caller alone publishes the completed result; a thrown checkpoint
    /// leaves no partial index. No raw XRef array is retained or copied here.
    static func build(
        xrefs: [XRef], names: GraphNameIndex,
        checkpoint: () throws -> Void
    ) throws -> Self? {
        try checkpoint()
        guard xrefs.count <= maximumIndexedXRefs else { return nil }

        var outgoingKeys: [UInt64] = []
        var outgoingOrdinals: [UInt32] = []
        var incomingKeys: [UInt64] = []
        var incomingOrdinals: [UInt32] = []
        outgoingKeys.reserveCapacity(xrefs.count)
        outgoingOrdinals.reserveCapacity(xrefs.count)
        incomingKeys.reserveCapacity(xrefs.count)
        incomingOrdinals.reserveCapacity(xrefs.count)
        try checkpoint()
        for i in xrefs.indices {
            if i.isMultiple(of: checkpointInterval) { try checkpoint() }
            outgoingKeys.append(names.owner(xrefs[i].from)?.start ?? xrefs[i].from)
            outgoingOrdinals.append(UInt32(i))
            incomingKeys.append(names.owner(xrefs[i].to)?.start ?? xrefs[i].to)
            incomingOrdinals.append(UInt32(i))
        }
        try checkpoint()
        try stableRadix(keys: &outgoingKeys, ordinals: &outgoingOrdinals,
                        checkpoint: checkpoint)
        try checkpoint()
        try stableRadix(keys: &incomingKeys, ordinals: &incomingOrdinals,
                        checkpoint: checkpoint)
        try checkpoint()
        return Self(outgoingKeys: outgoingKeys, outgoingOrdinals: outgoingOrdinals,
                    incomingKeys: incomingKeys, incomingOrdinals: incomingOrdinals)
    }

    /// Exact key equality, not a function-range search and not re-normalization.
    /// Two binary searches plus ordinal streaming cost O(log n + k).
    func range(for key: UInt64, incoming: Bool) -> Range<Int> {
        let keys = incoming ? incomingKeys : outgoingKeys
        var low = 0
        var high = keys.count
        while low < high {
            let middle = low + (high - low) / 2
            if keys[middle] < key { low = middle + 1 } else { high = middle }
        }
        let lower = low
        high = keys.count
        while low < high {
            let middle = low + (high - low) / 2
            if keys[middle] <= key { low = middle + 1 } else { high = middle }
        }
        return lower..<low
    }

    /// Offset is absolute within the chosen direction's sorted array. Traversal
    /// adds its bucket-relative scan to range.lowerBound before calling this.
    /// Use the same immutable index and direction that produced the range.
    func ordinal(at offset: Int, incoming: Bool) -> UInt32? {
        guard offset >= 0, offset < count else { return nil }
        return incoming ? incomingOrdinals[offset] : outgoingOrdinals[offset]
    }

    /// Eight stable byte passes preserve ascending raw ordinals for equal keys.
    /// Scratch is initialized cooperatively, not by one n-element bulk fill.
    /// Only one directional pair has scratch at a time: 24n retained bytes,
    /// 36n peak index payload, excluding allocator overhead and other indexes.
    private static func stableRadix(
        keys: inout [UInt64], ordinals: inout [UInt32],
        checkpoint: () throws -> Void
    ) throws {
        try checkpoint()
        var scratchKeys: [UInt64] = []
        var scratchOrdinals: [UInt32] = []
        scratchKeys.reserveCapacity(keys.count)
        scratchOrdinals.reserveCapacity(ordinals.count)
        try checkpoint()
        for i in keys.indices {
            if i.isMultiple(of: checkpointInterval) { try checkpoint() }
            scratchKeys.append(0)
            scratchOrdinals.append(0)
        }
        try checkpoint()
        for shift in stride(from: 0, to: 64, by: 8) {
            try checkpoint()
            var counts = [Int](repeating: 0, count: 256)
            for i in keys.indices {
                if i.isMultiple(of: checkpointInterval) { try checkpoint() }
                counts[Int((keys[i] >> shift) & 255)] += 1
            }
            try checkpoint()
            var position = 0
            for bucket in counts.indices {
                let count = counts[bucket]
                counts[bucket] = position
                position += count
            }
            try checkpoint()
            for i in keys.indices {
                if i.isMultiple(of: checkpointInterval) { try checkpoint() }
                let bucket = Int((keys[i] >> shift) & 255)
                let destination = counts[bucket]
                scratchKeys[destination] = keys[i]
                scratchOrdinals[destination] = ordinals[i]
                counts[bucket] += 1
            }
            try checkpoint()
            swap(&keys, &scratchKeys)
            swap(&ordinals, &scratchOrdinals)
            try checkpoint()
        }
        try checkpoint()
    }
}
