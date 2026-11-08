import Foundation

enum ModuleAwareInventory {
    /// Bound work incrementally so cancellation and record limits apply during construction.
    static func buildBounded(image: RegenerationImageIdentity, loads: [DependencyLoad],
                             frameworks: [DependencyFramework], modules: [String],
                             table: KnownDependencyTable, diagnostics: [String],
                             budget: RegenerationWorkBudget) throws -> DependencyInventory {
        var remaining = budget.maximumRecords
        for count in [loads.count, frameworks.count, modules.count] {
            guard count <= remaining else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            remaining -= count
        }
        var dependencies: [InventoryDependency] = []
        var seen = Set<String>()
        func append(_ report: DependencyInventory) throws {
            for dependency in report.dependencies {
                try budget.checkpoint()
                if seen.insert(dependency.id).inserted {
                    guard dependencies.count < budget.maximumRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
                    dependencies.append(dependency)
                }
            }
        }
        for load in loads {
            try budget.checkpoint()
            try append(build(image: image, loads: [load], frameworks: [], modules: [], table: table, diagnostics: []))
        }
        for framework in frameworks {
            try budget.checkpoint()
            try append(build(image: image, loads: [], frameworks: [framework], modules: [], table: table, diagnostics: []))
        }
        for module in modules {
            try budget.checkpoint()
            try append(build(image: image, loads: [], frameworks: [], modules: [module], table: table, diagnostics: []))
        }
        try budget.checkpoint()
        dependencies.sort { $0.id < $1.id }
        try budget.checkpoint()
        return .init(schemaVersion: 1, image: image, dependencies: dependencies, diagnostics: diagnostics.sorted())
    }

    static func build(image: RegenerationImageIdentity, loads: [DependencyLoad], frameworks: [DependencyFramework],
                      modules: [String], table: KnownDependencyTable, diagnostics: [String]) -> DependencyInventory {
        let base = DependencyInventoryBuilder.build(image: image, loads: loads, frameworks: frameworks, diagnostics: diagnostics)
        let enriched = base.dependencies.map { dependency -> InventoryDependency in
            guard let bundleID = dependency.bundleIdentifier else { return dependency }
            let matches = table.dependencies.filter { $0.bundleIDs.contains(bundleID) }
            guard matches.count == 1, let match = matches.first else { return dependency }
            let mapping = InventoryEvidence(signal: "bundleInfoPlist",
                detail: "Declared bundle identifier \(bundleID); mapping source: \(match.bundleSourceURL ?? match.sourceURL)",
                location: dependency.evidence.first?.location ?? "selected application bundle")
            return InventoryDependency(id: dependency.id, name: match.name, kind: dependency.kind,
                version: dependency.version, versionRange: dependency.versionRange,
                evidence: dependency.evidence + [mapping], confidence: dependency.confidence,
                functions: dependency.functions, emitAs: dependency.emitAs, packageURL: dependency.packageURL,
                requirement: dependency.requirement, bundleIdentifier: dependency.bundleIdentifier,
                bundleBuildVersion: dependency.bundleBuildVersion, dylibCurrentVersion: dependency.dylibCurrentVersion,
                dylibCompatibilityVersion: dependency.dylibCompatibilityVersion)
        }
        let hints = KnownDependencyLookup.matches(modules: modules, table: table).map { hint in
            let id = ["swiftModuleName", hint.module, hint.name].map { "\($0.utf8.count):\($0)" }.joined()
            return InventoryDependency(id: id, name: hint.name, kind: "swiftPackage", version: nil, versionRange: nil,
                evidence: [.init(signal: "swiftModuleName", detail: hint.module + "; mapping source: " + hint.sourceURL,
                                 location: "selected image: Swift metadata")],
                confidence: hint.confidence, functions: [], emitAs: "none", packageURL: nil, requirement: nil,
                bundleIdentifier: nil, bundleBuildVersion: nil, dylibCurrentVersion: nil, dylibCompatibilityVersion: nil)
        }
        return .init(schemaVersion: base.schemaVersion, image: base.image,
                     dependencies: (enriched + hints).sorted { $0.id < $1.id }, diagnostics: base.diagnostics)
    }
}
