import Foundation

/// Shares the existing optional coordinator and its unchanged defaults.
/// Admission is retained payload accounting, not a process peak-memory ceiling.
enum CallOwnerPreparation {
    static func update(enabled: Bool, coordinator: XRefIndexPreparation,
                       snapshot: WorkspaceSnapshot, previous: WorkspaceSnapshot?) {
        guard enabled else { return }
        if let previous,
           previous.manualXRefEndpointMemo === snapshot.manualXRefEndpointMemo,
           previous.binaries.map(\.slot) == snapshot.binaries.map(\.slot),
           previous.analysisBySlot.count == snapshot.analysisBySlot.count,
           previous.analysisBySlot.allSatisfy({ slot, analysis in
               guard let next = snapshot.analysisBySlot[slot] else { return false }
               return next.xrefEndpointMemo === analysis.xrefEndpointMemo
                   && next.callOwnerAdjacencyMemo === analysis.callOwnerAdjacencyMemo
           }) { return }
        coordinator.update(requests(snapshot: snapshot))
    }

    /// The coordinator's unchanged default budget, in UInt32 ordinal units.
    static let defaultOrdinalBudget = 33_554_432
    /// Units reserved per admitted owner image: owner payload 24n bytes = 6n units plus the
    /// companion endpoint payload 8n bytes = 2n units.
    static let reservedUnitsPerRow = 8
    /// Optional background warmup admits a lone image only up to budget / 8 = 4,194,304 rows.
    /// This is deliberately smaller than the read eligibility ceiling (16,777,216,
    /// CallOwnerAdjacencyIndex.maximumIndexedXRefs): the shared 128 MiB retained-ordinal budget
    /// cannot hold an owner index plus endpoint index for larger images without raising the
    /// coordinator default, which is out of scope. Larger images stay eligible for reads when a
    /// direct prepare has built them, and otherwise take the linear path with auto-continue.
    static let maximumWarmupXRefs = defaultOrdinalBudget / reservedUnitsPerRow

    /// Plans owner-index jobs first, then reuses WorkspaceSnapshot.xrefIndexPreparationRequests
    /// for every endpoint and manual-xref index with the budget that remains. Admission order:
    /// owner indexes first, then manual-xref indexes, then per-image endpoint indexes in the
    /// reused planner's own order. Manual-xref indexes are therefore admitted after (not before)
    /// the owner reservations; before this change they were admitted first.
    static func requests(snapshot: WorkspaceSnapshot,
                         maximumOrdinalCount: Int = defaultOrdinalBudget) -> [XRefIndexPreparation.Request] {
        var remaining = max(0, maximumOrdinalCount)
        var result: [XRefIndexPreparation.Request] = []
        var ownerIDs = Set<ObjectIdentifier>()
        var analyses: [ImageAnalysis] = []
        for binary in snapshot.binaries {
            if let analysis = snapshot.analysis(in: binary.slot) { analyses.append(analysis) }
        }
        if snapshot.binaries.isEmpty, let primary = snapshot.analysis(in: snapshot.primarySlot) {
            analyses.append(primary)
        }

        // Reserve 8n units per admitted owner image. The 2n endpoint share is handed back to the
        // reused planner below, which charges it only for endpoint indexes it actually admits.
        var endpointShare = 0
        for analysis in analyses {
            let n = analysis.xrefs.count
            let owner = ObjectIdentifier(analysis.callOwnerAdjacencyMemo)
            guard n >= CallOwnerAdjacencyIndex.minimumIndexedXRefs,
                  n <= CallOwnerAdjacencyIndex.maximumIndexedXRefs,
                  n <= maximumWarmupXRefs,
                  n <= remaining / reservedUnitsPerRow,
                  ownerIDs.insert(owner).inserted else { continue }
            remaining -= n * reservedUnitsPerRow
            endpointShare += n * 2
            let input = CallOwnerPreparationInput(analysis)
            result.append(.init(owner: owner, ordinalCount: n * 6, build: {
                _ = try input.memo.prepare(input: input, checkpoint: { try Task.checkCancellation() })
            }))
        }
        result += snapshot.xrefIndexPreparationRequests(
            maximumOrdinalCount: remaining + endpointShare,
            minimumCount: XRefEndpointIndex.maximumInlineIndexedXRefs + 1)
        return result
    }
}
