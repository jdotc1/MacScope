import Foundation

enum ResourceRoundTripStatus: String, Codable, Sendable { case copied, converted, partial, refused }
enum ResourceEquivalenceOutcome: String, Codable, Sendable { case notRun, passed, failed, unavailable }

struct ResourceEquivalence: Codable, Equatable, Sendable {
    var outcome: ResourceEquivalenceOutcome
    var tool: String?
    var receiptPath: String?
}

struct ResourceRoundTripRecord: Codable, Equatable, Sendable {
    var compiledPaths: [String]
    var sourcePath: String?
    var converter: String
    var status: ResourceRoundTripStatus
    var equivalence: ResourceEquivalence
    var diagnostics: [String]

    /// Source selection is an evidence decision, independent of whether draft source exists.
    var selectsSource: Bool {
        status == .converted && equivalence.outcome == .passed && sourcePath != nil
            && equivalence.receiptPath != nil
    }
}

struct ResourceRoundTripCandidate: Sendable {
    var record: ResourceRoundTripRecord
    /// Keys are relative to Resources/Source. Draft output remains editable but unselected.
    var sourceFiles: [String: Data]
    var conversionComplete: Bool = false
}

/// Converters render candidates. Only a compile-back oracle may promote them to converted.
protocol ResourceRoundTripConverting {
    func convert(path: String, files: [String: Data]) throws -> ResourceRoundTripCandidate
}

enum ResourceRoundTripComposition {
    static func buildPaths(_ resources: [ResourceRoundTripRecord]) throws -> [String] {
        var seen = Set<String>(), paths = Set<String>()
        for item in resources {
            guard !item.compiledPaths.isEmpty else { throw RegenerationError.invalidInput("resource has no original") }
            for path in item.compiledPaths {
                guard RegenerationEncoding.relativePath(path), seen.insert(path.lowercased()).inserted else {
                    throw RegenerationError.invalidInput("duplicate or invalid resource path")
                }
            }
            if let source = item.sourcePath, !RegenerationEncoding.relativePath(source) {
                throw RegenerationError.invalidInput("invalid resource source path")
            }
            if item.status == .converted && !item.selectsSource {
                throw RegenerationError.invalidInput("converted resource lacks successful equivalence evidence")
            }
            if item.selectsSource, let source = item.sourcePath {
                guard paths.insert("Resources/Source/" + source).inserted else {
                    throw RegenerationError.invalidInput("duplicate resource source output")
                }
            } else {
                paths.formUnion(item.compiledPaths.map { "Resources/Compiled/" + $0 })
            }
        }
        for path in seen {
            let components = path.split(separator: "/")
            for count in 1..<components.count where seen.contains(components.prefix(count).joined(separator: "/")) {
                throw RegenerationError.invalidInput("resource root overlaps an original member")
            }
        }
        let foldedBuildPaths = Set(paths.map { $0.lowercased() })
        guard foldedBuildPaths.count == paths.count else { throw RegenerationError.invalidInput("case-colliding resource outputs") }
        for path in foldedBuildPaths {
            let components = path.split(separator: "/")
            for count in 1..<components.count where foldedBuildPaths.contains(components.prefix(count).joined(separator: "/")) {
                throw RegenerationError.invalidInput("overlapping resource build outputs")
            }
        }
        return paths.sorted()
    }
}
