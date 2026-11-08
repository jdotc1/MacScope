import CoreData
import Foundation

struct CoreDataRoundTripOracle {
    let runner: RegenerationToolRunner

    func verify(_ candidate: ResourceRoundTripCandidate, originalRoot: URL,
                workDirectory: URL, receiptPath: String) throws -> ResourceRoundTripVerification {
        guard candidate.conversionComplete, let source = candidate.record.sourcePath,
              candidate.record.compiledPaths.count == 1,
              RegenerationEncoding.relativePath(receiptPath), receiptPath.hasPrefix("Support/Receipts/") else {
            throw RegenerationError.invalidInput("Core Data candidate is incomplete")
        }
        try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: false)
        let sourceRoot = workDirectory.appendingPathComponent("Source")
        try RegenerationFileSystem.publish(files: candidate.sourceFiles, to: sourceRoot) { _ in }
        let compiledRoot = workDirectory.appendingPathComponent("Compiled")
        try FileManager.default.createDirectory(at: compiledRoot, withIntermediateDirectories: false)
        let originalPath = candidate.record.compiledPaths[0]
        let output = compiledRoot.appendingPathComponent((originalPath as NSString).lastPathComponent)
        let result = try runner.run(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["momc", "--macosx-deployment-target", "11.0", sourceRoot.appendingPathComponent(source).path, output.path],
            workingDirectory: workDirectory)
        var value = candidate, outcome = ResourceEquivalenceOutcome.failed
        var detail = "Model compiler failed; original model retained."
        if result.exitStatus == 0, result.stopReason == nil, result.cleanupComplete {
            if try Self.signature(originalRoot.appendingPathComponent(originalPath)) == Self.signature(output) {
                outcome = .passed
                detail = "Entity hashes, schema, configurations, fetch requests and version identifiers match."
            } else { detail = "Compiled model signature differs from original; original model retained." }
        }
        value.record.equivalence = .init(outcome: outcome, tool: "momc", receiptPath: receiptPath)
        value.record.status = outcome == .passed ? .converted : .partial
        value.record.diagnostics = value.record.diagnostics.filter { $0 != "Compile-back equivalence has not been checked." } + [detail]
        let receipt = Receipt(schemaVersion: 1, converter: candidate.record.converter,
            normalizer: "core-data-public-schema-v1", tool: "momc", outcome: outcome,
            originalPath: originalPath, sourcePath: source, exitStatus: result.exitStatus,
            cleanupComplete: result.cleanupComplete, diagnostic: detail)
        return .init(candidate: value, receipts: [receiptPath: try RegenerationEncoding.json(receipt)])
    }

    static func signature(_ url: URL) throws -> Data {
        if url.pathExtension == "mom" {
            guard let model = NSManagedObjectModel(contentsOf: url) else { throw RegenerationError.invalidInput("compiled model cannot be loaded") }
            return try CoreDataModelSignature.encode(model)
        }
        guard url.pathExtension == "momd" else { throw RegenerationError.invalidInput("unrecognized compiled model container") }
        let versions = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isSymbolicLinkKey, .isRegularFileKey])
            .filter { $0.pathExtension == "mom" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        guard !versions.isEmpty, versions.count <= 128 else { throw RegenerationError.invalidInput("invalid model version count") }
        var signatures: [String: String] = [:]
        for version in versions {
            let values = try version.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true else { throw RegenerationError.invalidPath("compiled model version is not an ordinary file") }
            signatures[version.lastPathComponent] = try signature(version).base64EncodedString()
        }
        let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: url.appendingPathComponent("VersionInfo.plist")), format: nil) as? [String: Any]
        guard let current = info?["NSManagedObjectModel_CurrentVersionName"] as? String else {
            throw RegenerationError.invalidInput("compiled model lacks a current version binding")
        }
        return try RegenerationEncoding.json(VersionSignature(versions: signatures, currentVersion: current))
    }

    private struct VersionSignature: Codable { let versions: [String: String]; let currentVersion: String }
    private struct Receipt: Codable {
        let schemaVersion: Int
        let converter: String
        let normalizer: String
        let tool: String
        let outcome: ResourceEquivalenceOutcome
        let originalPath: String
        let sourcePath: String
        let exitStatus: Int32
        let cleanupComplete: Bool
        let diagnostic: String
    }
}
