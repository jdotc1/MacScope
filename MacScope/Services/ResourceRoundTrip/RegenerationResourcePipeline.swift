import Foundation

/// First usable composition: localization and Core Data use native compile-back evidence;
/// unsupported families remain explicit compiled fallbacks. Optional readers do not gate export.
struct RegenerationResourcePipeline {
    func prepare(originals: [String: Data], sourceLanguage: String, workDirectory: URL,
                 deadline: TimeInterval, runner: RegenerationToolRunner) throws -> ResourceRoundTripPreparation {
        let preliminary = try ResourceRoundTripService().prepare(files: originals, sourceLanguage: sourceLanguage)
        let originalRoot = workDirectory.appendingPathComponent("OriginalResources")
        try RegenerationFileSystem.publish(files: originals, to: originalRoot) { _ in }
        var files = preliminary.files, records: [ResourceRoundTripRecord] = []
        var candidates: [ResourceRoundTripCandidate] = [], claimed = Set<String>()
        for (index, initial) in preliminary.records.enumerated() {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RegenerationError.toolFailed("export deadline before resource conversion") }
            var candidate = preliminary.candidates.first { $0.record.compiledPaths == initial.compiledPaths }
            var record = initial
            let first = initial.compiledPaths[0]
            if candidate == nil, ["mom", "momd"].contains((first as NSString).pathExtension.lowercased()) {
                do { candidate = try CoreDataRoundTripConverter().convert(path: first, originalRoot: originalRoot) }
                catch { record.diagnostics.append("Core Data conversion refused: " + error.localizedDescription) }
            }
            if var value = candidate {
                if value.conversionComplete {
                    var allocated = runner
                    allocated.timeout = min(30, max(0.001, deadline - ProcessInfo.processInfo.systemUptime))
                    let directory = workDirectory.appendingPathComponent(String(format: "Conversion-%05d", index))
                    let receipt = String(format: "Support/Receipts/resource-%05d.json", index)
                    do {
                        let verification: ResourceRoundTripVerification
                        if value.record.converter == "localization-v1" {
                            verification = try LocalizationRoundTripOracle(runner: allocated).verify(value, originals: originals,
                                workDirectory: directory, receiptPath: receipt)
                        } else {
                            verification = try CoreDataRoundTripOracle(runner: allocated).verify(value, originalRoot: originalRoot,
                                workDirectory: directory, receiptPath: receipt)
                        }
                        value = verification.candidate
                        for (path, data) in verification.receipts { files[path] = data }
                    } catch {
                        value.record.status = .partial
                        value.record.diagnostics.append("Compile-back comparison unavailable; original retained: " + error.localizedDescription)
                    }
                }
                if value.record.selectsSource && !Self.supportedBuildLocation(value.record.compiledPaths) {
                    value.record.status = .partial
                    value.record.diagnostics.append("Converted source has a nonstandard bundle subdirectory; original build location retained.")
                }
                for (path, data) in value.sourceFiles {
                    guard RegenerationEncoding.relativePath(path), claimed.insert(path.lowercased()).inserted else {
                        throw RegenerationError.invalidInput("resource source collision")
                    }
                    files["Resources/Source/" + path] = data
                }
                record = value.record; candidates.append(value)
            }
            records.append(record)
        }
        _ = try ResourceRoundTripComposition.buildPaths(records)
        return .init(files: files, records: records, candidates: candidates)
    }

    private static func supportedBuildLocation(_ paths: [String]) -> Bool {
        paths.allSatisfy { path in
            let parts = path.split(separator: "/")
            return parts.count == 1 || (parts.count == 2 && parts[0].hasSuffix(".lproj"))
        }
    }
}
