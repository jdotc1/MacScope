import Foundation

struct DependencyLoad: Codable, Equatable, Sendable {
    let path: String
    let kind: String
    let currentVersion: String
    let compatibilityVersion: String
}

/// Framework paths have already been bounded and verified by the bundle fact reader.
struct DependencyFramework: Codable, Equatable, Sendable {
    let path: String
    let identifier: String
    let releaseVersion: String?
    let buildVersion: String?
}

struct DependencyRecord: Codable, Equatable, Sendable {
    let kind: String
    let confidence: String
    let path: String
    let identifier: String?
    let releaseVersion: String?
    let buildVersion: String?
    let loadKind: String?
    let currentVersion: String?
    let compatibilityVersion: String?
    let signal: String
}

enum DependencyRecognitionService {
    /// Each observation is kept separate until image and install-name resolution justify merging.
    static func recognize(loads: [DependencyLoad], frameworks: [DependencyFramework]) -> [DependencyRecord] {
        var records = loads.map { load in
            let components = load.path.split(separator: "/", omittingEmptySubsequences: false)
            let safePath = components.dropFirst().allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
            let system = safePath && (load.path.hasPrefix("/usr/lib/") || load.path.hasPrefix("/System/Library/"))
            return DependencyRecord(kind: system ? "systemFramework" : "unknownThirdParty",
                                    confidence: system ? "confirmed" : "candidate", path: load.path,
                                    identifier: nil, releaseVersion: nil, buildVersion: nil,
                                    loadKind: load.kind, currentVersion: load.currentVersion,
                                    compatibilityVersion: load.compatibilityVersion, signal: "loadCommand")
        }
        records += frameworks.map { framework in
            DependencyRecord(kind: "embeddedFramework", confidence: "confirmed", path: framework.path,
                             identifier: framework.identifier, releaseVersion: framework.releaseVersion,
                             buildVersion: framework.buildVersion, loadKind: nil, currentVersion: nil,
                             compatibilityVersion: nil, signal: "bundleInfoPlist")
        }
        return records.sorted { a, b in
            let left = [a.path, a.signal, a.loadKind ?? "", a.currentVersion ?? "", a.compatibilityVersion ?? "", a.identifier ?? "", a.releaseVersion ?? "", a.buildVersion ?? ""]
            let right = [b.path, b.signal, b.loadKind ?? "", b.currentVersion ?? "", b.compatibilityVersion ?? "", b.identifier ?? "", b.releaseVersion ?? "", b.buildVersion ?? ""]
            return left.lexicographicallyPrecedes(right)
        }
    }
}
