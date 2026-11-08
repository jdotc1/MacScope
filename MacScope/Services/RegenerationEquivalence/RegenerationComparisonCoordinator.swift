import Foundation

enum RegenerationComparisonCoordinator {
    /// Both sides must already exist in the same captured workspace. This path does not
    /// open either binary or mint a digest; pairing uses captured raw symbols only.
    static func compareCaptured(snapshot: WorkspaceSnapshot, originalSlot: ImageSlot, rebuiltSlot: ImageSlot,
                                manifest: RegenerationManifest?, dependencies: DependencyInventory?,
                                manifestInputBytes: Int = 0,
                                budget: RegenerationWorkBudget) throws -> [String: Data] {
        _ = try remainingInputBytes(snapshot: snapshot, originalSlot: originalSlot, rebuiltSlot: rebuiltSlot,
            manifestInputBytes: manifestInputBytes, manifestRecords: manifest?.functions.count ?? 0,
            includeManifestBindings: manifest != nil, budget: budget)
        let original = try EquivalenceSnapshotAdapter.prepare(snapshot: snapshot, slot: originalSlot, budget: budget,
            includePairingFacts: true, includeManifestBindings: manifest != nil)
        if let manifest {
            try ManifestStateBinding.validate(manifest, budget: budget)
            guard manifest.image == original.identity else { throw EquivalenceInputError.manifestIdentityMismatch }
        }
        let rebuilt = try EquivalenceSnapshotAdapter.prepare(snapshot: snapshot, slot: rebuiltSlot, budget: budget, includePairingFacts: true)
        let report = try RegenerationEquivalenceService.compare(original: original.image, rebuilt: rebuilt.image,
            originalIdentity: original.identity, rebuiltIdentity: .init(captured: rebuilt.identity),
            manifest: manifest, dependencies: dependencies, originalFunctions: original.functions,
            rebuiltFunctions: rebuilt.functions, manifestBindings: original.manifestBindings, budget: budget)
        try budget.checkpoint()
        return try EquivalenceReportFiles.make(report, budget: budget)
    }

    /// Used before manifest reading/decoding, then with its observed byte/record counts.
    static func remainingInputBytes(snapshot: WorkspaceSnapshot, originalSlot: ImageSlot, rebuiltSlot: ImageSlot,
                                    manifestInputBytes: Int = 0, manifestRecords: Int = 0,
                                    includeManifestBindings: Bool = false, budget: RegenerationWorkBudget) throws -> Int {
        try budget.checkpoint()
        guard originalSlot != rebuiltSlot,
              let originalAnalysis = snapshot.analysis(in: originalSlot),
              let rebuiltAnalysis = snapshot.analysis(in: rebuiltSlot) else {
            throw EquivalenceCaptureError.missingOrMismatchedIdentity
        }
        let originalBytes = originalAnalysis.imageBytes.count, rebuiltBytes = rebuiltAnalysis.imageBytes.count
        guard originalBytes <= budget.maximumInputBytes,
              rebuiltBytes <= budget.maximumInputBytes - originalBytes else {
            throw RegenerationWorkBudgetError.inputLimitExceeded
        }
        try FunctionPairingProjection.validateCounts(
            functions: originalAnalysis.functions.count + rebuiltAnalysis.functions.count,
            symbols: originalAnalysis.symbols.count + rebuiltAnalysis.symbols.count, budget: budget)
        var remainingRecords = budget.maximumRecords
        for count in [manifestRecords, includeManifestBindings ? originalAnalysis.functions.count : 0] {
            guard count >= 0 else { throw RegenerationWorkBudgetError.invalidLimit }
            guard count <= remainingRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            remainingRecords -= count
        }
        var remainingBytes = budget.maximumInputBytes - originalBytes - rebuiltBytes
        guard manifestInputBytes >= 0, manifestInputBytes <= remainingBytes else { throw RegenerationWorkBudgetError.inputLimitExceeded }
        remainingBytes -= manifestInputBytes
        var remainingNameBytes = min(1_024 * 1_024, remainingBytes)
        for analysis in [originalAnalysis, rebuiltAnalysis] {
            for count in [analysis.functions.count, analysis.symbols.count, analysis.objcClasses.count,
                          analysis.objcCategories.count, analysis.objcProtocols.count,
                          analysis.swiftTypes.count, analysis.swiftConformances.count] {
                try budget.checkpoint()
                guard count <= remainingRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
                remainingRecords -= count
            }
            for symbol in analysis.symbols {
                try budget.checkpoint()
                let count = symbol.rawLinkageName?.utf8.count ?? 0
                guard count <= 1_024, count <= remainingNameBytes else { throw RegenerationWorkBudgetError.inputLimitExceeded }
                remainingNameBytes -= count
                remainingBytes -= count
            }
        }
        try budget.checkpoint()
        return remainingBytes
    }
}
