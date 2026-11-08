import Foundation

enum DependencySnapshotError: Error { case missingOrMismatchedIdentity, invalidMapping }

enum DependencySnapshotCoordinator {
    /// Uses the already captured snapshot; no executable bytes or provenance are rehashed.
    static func make(snapshot: WorkspaceSnapshot, slot: ImageSlot, app: URL,
                     table: KnownDependencyTable, budget: RegenerationWorkBudget) throws -> DependencyInventory {
        try budget.checkpoint()
        guard table.schemaVersion == 1, table.dependencies.count <= 64,
              table.dependencies.allSatisfy({ $0.modules.count <= 64 && $0.bundleIDs.count <= 64
                  && ($0.modules + $0.bundleIDs).allSatisfy { !$0.isEmpty && $0.utf8.count <= 512 }
                  && [$0.name, $0.sourceURL, $0.packageURL, $0.license, $0.licenseURL, $0.bundleSourceURL ?? ""].allSatisfy { $0.utf8.count <= 4096 } }) else {
            throw DependencySnapshotError.invalidMapping
        }
        guard let binary = snapshot.binary(in: slot), let analysis = snapshot.analysis(in: slot),
              let artifact = binary.artifactIdentity, binary.artifactIntegrityState == .verified,
              artifact.architectureVariant == .arm64, let fingerprint = analysis.analysisInputFingerprint,
              fingerprint.binaryID == binary.id, fingerprint.imageSlot == slot,
              fingerprint.binaryPath == binary.path, fingerprint.binaryName == binary.name,
              fingerprint.selectedSliceIndex == binary.selectedSliceIndex, fingerprint.artifactIdentity == artifact,
              fingerprint.imageBytesSHA256 == artifact.selectedSliceSHA256,
              fingerprint.imageByteCount == artifact.selectedSliceByteCount,
              UInt64(analysis.imageBytes.count) == artifact.selectedSliceByteCount,
              binary.metadata.platformName == nil || binary.metadata.platformName == "macOS" else {
            throw DependencySnapshotError.missingOrMismatchedIdentity
        }
        guard analysis.imageBytes.count <= budget.maximumInputBytes,
              analysis.swiftTypes.count <= budget.maximumRecords,
              (analysis.machOMetadata?.dependentDylibs.count ?? 0) <= budget.maximumRecords else {
            throw RegenerationWorkBudgetError.inputLimitExceeded
        }
        // The current bundle has no capture-bound identity receipt. Do not read it.
        var loads: [DependencyLoad] = []
        for load in analysis.machOMetadata?.dependentDylibs ?? [] {
            try budget.checkpoint()
            loads.append(DependencyLoad(path: load.path, kind: load.kind, currentVersion: load.currentVersion, compatibilityVersion: load.compatibilityVersion))
        }
        var modules = Set<String>()
        var diagnostics = ["Embedded framework inventory unassessed: current bundle is not bound to captured image identity"]
        if analysis.machOMetadata == nil { diagnostics.append("Mach-O load metadata is unavailable") }
        for type in analysis.swiftTypes {
            try budget.checkpoint()
            guard let name = type.qualifiedName, let first = name.split(separator: ".").first,
                  !first.hasPrefix("<"), name.contains(".") else { continue }
            modules.insert(String(first))
        }
        diagnostics.append("Swift module hints may be incomplete")
        let identity = RegenerationImageIdentity(imageSlot: slot.rawValue, selectedSliceIndex: binary.selectedSliceIndex,
            architecture: "arm64", selectedSliceSHA256: artifact.selectedSliceSHA256, analysisFingerprintSHA256: fingerprint.overallSHA256)
        try budget.checkpoint()
        let result = try ModuleAwareInventory.buildBounded(image: identity, loads: loads, frameworks: [],
                                                modules: modules.sorted(), table: table, diagnostics: diagnostics, budget: budget)
        try budget.checkpoint()
        guard result.dependencies.count <= budget.maximumRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
        return result
    }
}
