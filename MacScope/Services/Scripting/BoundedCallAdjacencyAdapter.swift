import Foundation

/// One request-local adapter. Retained cursor state stores only backend + UUID,
/// never the prepared arrays. Selection is done after begin and its abandon defer.
struct BoundedCallAdjacencyAdapter: Sendable {
    let backend: CallReadBackend
    private let prepared: CallOwnerPrepared?

    static func select(analysis: ImageAnalysis,
                       retainedBackend: CallReadBackend?) throws -> Self {
        // A linear cursor never peeks, switches, builds, or needs the warm memo.
        if retainedBackend == .linear { return Self(backend: .linear, prepared: nil) }
        let memo = analysis.callOwnerAdjacencyMemo
        let warm: CallOwnerPrepared?
        if retainedBackend == nil {
            // First page: one non-blocking attempt; contention means cold, so linear.
            warm = memo.peek()
        } else {
            // Retained indexed cursor: a transient try-lock failure is not a stale cursor.
            // Retry briefly; only if contention persists report a retryable (non-stale) busy
            // refusal. The cursor is not consumed on refusal, so the client may retry.
            switch memo.peekRetryingContention() {
            case .value(let prepared): warm = prepared
            case .contended: throw busy()
            }
        }
        let available = callReadBackend(rawCount: analysis.xrefs.count, prepared: warm)
        if let retainedBackend {
            guard retainedBackend == available else { throw stale() }
            return Self(backend: retainedBackend, prepared: warm)
        }
        switch available {
        case .linear: return Self(backend: .linear, prepared: nil)
        case .indexed: return Self(backend: available, prepared: warm)
        }
    }

    private static func busy() -> ScriptingError {
        .invalidArgument("cursorBusy: owner adjacency is momentarily busy; retry the same cursor")
    }

    private static func stale() -> ScriptingError {
        .invalidArgument("staleCursor: issuing owner adjacency is unavailable; restart without a cursor")
    }

    /// Accumulates a complete adjacency before the existing sort/BFS emission.
    /// state.scan is a raw offset for linear, a bucket-relative offset for indexed.
    func scan(state: inout BoundedCallState, currentAddress: UInt64,
              xrefs: [XRef], names: GraphNameIndex, visits: inout Int,
              quantum: Int, checkpoint: () throws -> Void) throws -> Bool {
        let range: Range<Int>
        let ownerNames: GraphNameIndex
        switch backend {
        case .linear:
            range = 0..<xrefs.count
            ownerNames = names
        case .indexed(let id):
            guard let prepared, prepared.id == id,
                  prepared.adjacency.count == xrefs.count else { throw Self.stale() }
            range = prepared.adjacency.range(for: currentAddress, incoming: state.request.incoming)
            ownerNames = prepared.names
        }
        guard state.backend == backend, state.scan >= 0, state.scan <= range.count else {
            throw Self.stale()
        }
        while state.scan < range.count, visits < quantum {
            if visits.isMultiple(of: WorkspaceScriptingAPI.checkpointInterval) { try checkpoint() }
            let ordinal: Int
            switch backend {
            case .linear:
                ordinal = state.scan
            case .indexed:
                guard let raw = prepared?.adjacency.ordinal(
                    at: range.lowerBound + state.scan, incoming: state.request.incoming) else {
                    throw Self.stale()
                }
                ordinal = Int(raw)
            }
            guard ordinal < xrefs.count else { throw Self.stale() }
            let ref = xrefs[ordinal]
            state.scan += 1
            visits += 1
            guard ref.kind == XRefKind.call else { continue }
            let caller = ownerNames.owner(ref.from)?.start ?? ref.from
            let callee = ownerNames.owner(ref.to)?.start ?? ref.to
            guard (state.request.incoming ? callee : caller) == currentAddress else { continue }
            let edge = BoundedCallEdge(from: ref.from, to: ref.to, caller: caller, callee: callee)
            guard !state.pendingKeys.contains(edge) else { continue }
            guard state.pending.count < WorkspaceScriptingAPI.boundedCallMaximumEdges else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "bounded call adjacency cap",
                    budget: .init(unit: .rows,
                                  limit: Int64(WorkspaceScriptingAPI.boundedCallMaximumEdges)),
                    narrowing: ["depth", "maxDepth", "imageSlot", "limit"]))
            }
            state.pendingKeys.insert(edge)
            state.pending.append(edge)
        }
        return state.scan == range.count
    }
}
