import Foundation

/// Prepares captured-image dependency facts for the existing transactional project export.
/// The caller owns the export deadline, mapping table and publication.
struct RegenerationDependencyInventory: Sendable {
    let files: [String: Data]
    let dependencyCount: Int
    let path: String
    let coverage: String
    let liveBundleObservations: String
    let diagnostics: [String]

    static func prepare(snapshot: WorkspaceSnapshot, slot: ImageSlot, app: URL,
                        table: KnownDependencyTable, budget: RegenerationWorkBudget) throws -> Self {
        try budget.checkpoint()
        let report = try DependencySnapshotCoordinator.make(snapshot: snapshot, slot: slot, app: app,
                                                              table: table, budget: budget)
        let files = try DependencyInventoryFiles.make(report, budget: budget)
        return Self(files: files, dependencyCount: report.dependencies.count, path: "DEPENDENCIES.json",
                    coverage: "capturedSnapshotOnly", liveBundleObservations: "unassessed",
                    diagnostics: report.diagnostics)
    }
}
