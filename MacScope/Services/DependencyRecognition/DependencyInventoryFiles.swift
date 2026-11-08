import Foundation

enum DependencyInventoryOutputError: Error { case exceedsLimit }

enum DependencyInventoryFiles {
    /// Returns a bounded complete file set; caller owns transactional publication.
    static func make(_ report: DependencyInventory, budget: RegenerationWorkBudget) throws -> [String: Data] {
        try budget.checkpoint()
        guard report.dependencies.count <= budget.maximumRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
        var remaining = budget.maximumOutputBytes
        var items = 0
        func charge(_ value: String) throws {
            try budget.checkpoint()
            items += 1
            guard items <= budget.maximumRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            let (expanded, overflow) = value.utf8.count.multipliedReportingOverflow(by: 12)
            let (cost, overflow2) = expanded.addingReportingOverflow(512)
            guard !overflow, !overflow2, cost <= remaining else { throw DependencyInventoryOutputError.exceedsLimit }
            remaining -= cost
        }
        try charge(report.image.selectedSliceSHA256); try charge(report.image.analysisFingerprintSHA256)
        for item in report.dependencies {
            for value in [item.id, item.name, item.kind, item.confidence, item.emitAs,
                          item.version ?? "", item.versionRange ?? "", item.bundleIdentifier ?? "",
                          item.bundleBuildVersion ?? "", item.dylibCurrentVersion ?? "",
                          item.dylibCompatibilityVersion ?? "", item.packageURL ?? "", item.requirement ?? ""] { try charge(value) }
            for evidence in item.evidence { try charge(evidence.signal); try charge(evidence.detail); try charge(evidence.location) }
            for function in item.functions { try charge(function) }
        }
        for diagnostic in report.diagnostics { try charge(diagnostic) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        let data = try encoder.encode(report) + Data([10])
        try budget.checkpoint()
        guard data.count <= budget.maximumOutputBytes else { throw DependencyInventoryOutputError.exceedsLimit }
        return ["DEPENDENCIES.json": data]
    }
}
