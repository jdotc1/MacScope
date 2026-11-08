import Foundation

struct KnownDependency: Codable, Equatable, Sendable {
    let name: String
    let modules: [String]
    let bundleIDs: [String]
    let sourceURL: String
    let packageURL: String
    let license: String
    let licenseURL: String
    var bundleSourceURL: String? = nil
}

struct KnownDependencyTable: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let dependencies: [KnownDependency]
}

struct KnownDependencyHint: Codable, Equatable, Sendable {
    let name: String
    let module: String
    let confidence: String
    let sourceURL: String
}

enum KnownDependencyLookup {
    /// A module is evidence of a possible package, not proof of version, ownership or replacement.
    static func matches(modules: [String], table: KnownDependencyTable) -> [KnownDependencyHint] {
        guard table.schemaVersion == 1 else { return [] }
        var result: [KnownDependencyHint] = []
        for module in Set(modules).sorted() {
            let candidates = table.dependencies.filter { $0.modules.contains(module) }
            let confidence = candidates.count == 1 ? "probable" : "candidate"
            for item in candidates.sorted(by: { ($0.name, $0.sourceURL) < ($1.name, $1.sourceURL) }) {
                result.append(.init(name: item.name, module: module, confidence: confidence, sourceURL: item.sourceURL))
            }
        }
        return result
    }
}
