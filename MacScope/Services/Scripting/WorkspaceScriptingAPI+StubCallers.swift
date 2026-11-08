import Foundation

extension WorkspaceScriptingAPI {
    nonisolated static func stubCallerRows(
        arguments: ScriptValue, snapshot: WorkspaceSnapshot, view: WorkspaceSnapshot,
        filter: ImageSlot?, scope: SnapshotListReadScope, checkpoint: () throws -> Void
    ) throws -> ScriptValue? {
        try checkpoint()
        let functions = view.functions
        let candidate: UInt64
        if let name = arguments["function"]?.stringValue {
            for (index, function) in functions.enumerated() {
                guard scope != .attached || index < maximumSnapshotSelectionWork else { return nil }
                if index % checkpointInterval == 0 { try checkpoint() }
                if function.name == name ||
                    view.displayName(at: function.startAddress, default: function.name) == name {
                    return nil
                }
            }
            // Keep only the lowest sixteen distinct addresses. That suffices to distinguish
            // none, one and ambiguity without allocating a symbol-sized candidate set.
            var addresses: [UInt64] = []
            for (index, symbol) in view.symbols.enumerated() {
                if index % checkpointInterval == 0 { try checkpoint() }
                guard symbol.name == name, let address = symbol.address,
                      !addresses.contains(address) else { continue }
                if addresses.count < 16 {
                    addresses.append(address)
                    addresses.sort()
                } else if address < addresses[15] {
                    addresses[15] = address
                    addresses.sort()
                }
            }
            guard let first = addresses.first else { return nil }
            guard addresses.count == 1 else {
                throw ScriptingError.ambiguousFunctionSelector(name: name, addresses: addresses)
            }
            candidate = first
        } else if let address = arguments["address"]?.addressValue {
            candidate = address
        } else {
            return nil
        }

        for (index, function) in functions.enumerated() {
            guard scope != .attached || index < maximumSnapshotSelectionWork else { return nil }
            if index % checkpointInterval == 0 { try checkpoint() }
            if stubCallerContains(function, candidate) { return nil }
        }

        let references: [XRef]
        do {
            references = try snapshot.boundedEffectiveXRefs(.to(candidate), in: filter, limit: nil,
                maximumRows: maximumSnapshotRows, maximumWork: maximumSnapshotSelectionWork,
                checkpoint: checkpoint)
        } catch let failure as WorkspaceSnapshot.XRefQueryFailure {
            throw stubCallerBudgetRefusal(failure)
        }
        var seen = Set<[UInt64]>()
        var sites: [XRef] = []
        for (index, reference) in references.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            guard reference.to == candidate, reference.kind == XRefKind.call,
                  seen.insert([reference.from, reference.to]).inserted else { continue }
            sites.append(reference)
        }
        guard !sites.isEmpty else { return nil }

        if scope == .attached && functions.count > maximumSnapshotSelectionWork {
            throw stubCallerBudgetRefusal(.workBudget)
        }
        let slot = filter ?? view.primarySlot
        return .array(try namedGraphRows(sites, includeKind: false, snapshot: view, slot: slot,
                                         checkpoint: checkpoint))
    }

    private nonisolated static func stubCallerContains(_ function: FunctionSummary, _ address: UInt64) -> Bool {
        function.endAddress > function.startAddress
            ? address >= function.startAddress && address < function.endAddress
            : address == function.startAddress
    }

    /// One restack point for item 879's structured budget carrier.
    private nonisolated static func stubCallerBudgetRefusal(
        _ failure: WorkspaceSnapshot.XRefQueryFailure
    ) -> ScriptingError {
        switch failure {
        case .workBudget: .invalidArgument("callers exceeds the snapshot work budget")
        case .resultBudget: .invalidArgument("callers exceeds the snapshot result budget")
        }
    }
}
