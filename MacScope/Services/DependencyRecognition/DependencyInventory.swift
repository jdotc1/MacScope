import Foundation

struct InventoryEvidence: Codable, Equatable, Sendable {
    let signal: String
    let detail: String
    let location: String
}

struct InventoryDependency: Codable, Equatable, Sendable {
    let id: String
    let name: String
    let kind: String
    let version: String?
    let versionRange: String?
    let evidence: [InventoryEvidence]
    let confidence: String
    let functions: [String]
    let emitAs: String
    let packageURL: String?
    let requirement: String?
    let bundleIdentifier: String?
    let bundleBuildVersion: String?
    let dylibCurrentVersion: String?
    let dylibCompatibilityVersion: String?

    enum CodingKeys: String, CodingKey {
        case id, name, kind, version, versionRange, evidence, confidence, functions, emitAs, packageURL, requirement
        case bundleIdentifier, bundleBuildVersion, dylibCurrentVersion, dylibCompatibilityVersion
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id); try c.encode(name, forKey: .name); try c.encode(kind, forKey: .kind)
        try c.encode(version, forKey: .version); try c.encode(versionRange, forKey: .versionRange)
        try c.encode(evidence, forKey: .evidence); try c.encode(confidence, forKey: .confidence)
        try c.encode(functions, forKey: .functions); try c.encode(emitAs, forKey: .emitAs)
        try c.encode(packageURL, forKey: .packageURL); try c.encode(requirement, forKey: .requirement)
        try c.encode(bundleIdentifier, forKey: .bundleIdentifier); try c.encode(bundleBuildVersion, forKey: .bundleBuildVersion)
        try c.encode(dylibCurrentVersion, forKey: .dylibCurrentVersion); try c.encode(dylibCompatibilityVersion, forKey: .dylibCompatibilityVersion)
    }
}

struct DependencyInventory: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let image: RegenerationImageIdentity
    let dependencies: [InventoryDependency]
    let diagnostics: [String]
}

enum DependencyInventoryBuilder {
    static func build(image: RegenerationImageIdentity, loads: [DependencyLoad], frameworks: [DependencyFramework],
                      diagnostics: [String]) -> DependencyInventory {
        let records = DependencyRecognitionService.recognize(loads: loads, frameworks: frameworks)
        var seen = Set<String>()
        let dependencies = records.compactMap { record -> InventoryDependency? in
            let pieces = [record.signal, record.path, record.loadKind ?? "", record.identifier ?? "",
                          record.currentVersion ?? "", record.compatibilityVersion ?? "", record.releaseVersion ?? "", record.buildVersion ?? ""]
            let id = pieces.map { "\($0.utf8.count):\($0)" }.joined()
            guard seen.insert(id).inserted else { return nil }
            let detail = record.loadKind.map { "load kind: " + $0 } ?? (record.identifier ?? "framework")
            return .init(id: id, name: URL(fileURLWithPath: record.path).lastPathComponent,
                         kind: record.kind, version: record.releaseVersion, versionRange: nil,
                         evidence: [.init(signal: record.signal, detail: detail, location: record.path)],
                         confidence: record.confidence, functions: [], emitAs: "none", packageURL: nil,
                         requirement: nil, bundleIdentifier: record.identifier, bundleBuildVersion: record.buildVersion,
                         dylibCurrentVersion: record.currentVersion, dylibCompatibilityVersion: record.compatibilityVersion)
        }
        return .init(schemaVersion: 1, image: image, dependencies: dependencies, diagnostics: diagnostics.sorted())
    }
}
