import Foundation

struct ResourceRoundTripVerification: Sendable {
    let candidate: ResourceRoundTripCandidate
    /// Receipt files are project-relative; tool logs remain in the external work directory.
    let receipts: [String: Data]
}

struct LocalizationRoundTripOracle {
    let runner: RegenerationToolRunner

    func verify(_ candidate: ResourceRoundTripCandidate, originals: [String: Data],
                workDirectory: URL, receiptPath: String) throws -> ResourceRoundTripVerification {
        guard candidate.conversionComplete, let source = candidate.record.sourcePath,
              candidate.sourceFiles[source] != nil,
              RegenerationEncoding.relativePath(receiptPath), receiptPath.hasPrefix("Support/Receipts/") else {
            throw RegenerationError.invalidInput("localization candidate is incomplete or receipt path is invalid")
        }
        try FileManager.default.createDirectory(at: workDirectory, withIntermediateDirectories: false)
        let input = workDirectory.appendingPathComponent("Source", isDirectory: true)
        try RegenerationFileSystem.publish(files: candidate.sourceFiles, to: input) { _ in }
        let output = workDirectory.appendingPathComponent("Compiled", isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
        let result = try runner.run(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["xcstringstool", "compile", input.appendingPathComponent(source).path,
                        "--output-directory", output.path, "--serialization-format", "binary"], workingDirectory: workDirectory)
        var value = candidate
        var outcome = ResourceEquivalenceOutcome.failed
        var detail = "Compiler failed; original resources retained."
        if result.exitStatus == 0, result.stopReason == nil, result.cleanupComplete {
            let captured = try candidate.record.compiledPaths.reduce(into: [String: Data]()) { values, path in
                guard let data = originals[path] else { throw RegenerationError.invalidInput("missing original localization") }
                values[path] = data
            }
            let compiled = try Self.inventory(output)
            if try Self.normalized(captured) == Self.normalized(compiled) {
                outcome = .passed; detail = "Per-locale table key/value/plural maps match after compilation."
            } else { detail = "Compiled locale maps differ from original; original resources retained." }
        }
        value.record.equivalence = .init(outcome: outcome, tool: "xcstringstool", receiptPath: receiptPath)
        value.record.status = outcome == .passed ? .converted : .partial
        value.record.diagnostics = value.record.diagnostics.filter { $0 != "Compile-back equivalence has not been checked." } + [detail]
        let receipt = Receipt(schemaVersion: 1, converter: candidate.record.converter,
            normalizer: "locale-table-plist-v1", tool: "xcstringstool", outcome: outcome,
            originalPaths: candidate.record.compiledPaths.sorted(), sourcePath: source,
            exitStatus: result.exitStatus, cleanupComplete: result.cleanupComplete, diagnostic: detail)
        return .init(candidate: value, receipts: [receiptPath: try RegenerationEncoding.json(receipt)])
    }

    private struct Receipt: Codable {
        let schemaVersion: Int
        let converter: String
        let normalizer: String
        let tool: String
        let outcome: ResourceEquivalenceOutcome
        let originalPaths: [String]
        let sourcePath: String
        let exitStatus: Int32
        let cleanupComplete: Bool
        let diagnostic: String
    }

    private static func normalized(_ files: [String: Data]) throws -> Data {
        var tables: [String: Any] = [:]
        for path in files.keys.sorted() {
            let components = path.split(separator: "/").map(String.init)
            guard let localeIndex = components.lastIndex(where: { $0.hasSuffix(".lproj") }),
                  localeIndex + 1 == components.count - 1,
                  let data = files[path], data.count <= 8_388_608,
                  let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  JSONSerialization.isValidJSONObject(plist) else {
                throw RegenerationError.invalidInput("localization output cannot be normalized")
            }
            // Compilation output does not include the original table's containing directory.
            let key = components[localeIndex] + "/" + components.last!
            guard tables[key] == nil else { throw RegenerationError.invalidInput("duplicate compiled localization table") }
            tables[key] = plist
        }
        return try JSONSerialization.data(withJSONObject: tables, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func inventory(_ root: URL) throws -> [String: Data] {
        guard let enumerator = FileManager.default.enumerator(at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey], options: []) else {
            throw RegenerationError.invalidPath("compiled localization output is unavailable")
        }
        var result: [String: Data] = [:], count = 0
        for case let file as URL in enumerator {
            count += 1
            guard count <= 1_000 else { throw RegenerationError.invalidInput("compiled localization output exceeds inventory limit") }
            let metadata = try file.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey])
            guard metadata.isSymbolicLink != true else { throw RegenerationError.invalidPath("compiled output contains a symlink") }
            if metadata.isDirectory == true { continue }
            guard metadata.isRegularFile == true, let size = metadata.fileSize, size <= 8_388_608,
                  ["strings", "stringsdict"].contains(file.pathExtension) else {
                throw RegenerationError.invalidInput("unexpected compiled localization output")
            }
            let relative = String(file.path.dropFirst(root.path.count + 1))
            guard RegenerationEncoding.relativePath(relative) else { throw RegenerationError.invalidPath("compiled output escaped its root") }
            result[relative] = try Data(contentsOf: file)
        }
        return result
    }
}
