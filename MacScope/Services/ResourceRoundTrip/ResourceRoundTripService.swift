import Foundation

struct ResourceRoundTripPreparation: Sendable {
    let files: [String: Data]
    let records: [ResourceRoundTripRecord]
    let candidates: [ResourceRoundTripCandidate]
}

/// Prepares editable candidates and retains every original. No process or target code is run here.
/// Compile-back promotion is deliberately a later operation, after tool allocation.
struct ResourceRoundTripService {
    func prepare(files originals: [String: Data], sourceLanguage: String) throws -> ResourceRoundTripPreparation {
        guard originals.count <= 20_000,
              originals.keys.allSatisfy(RegenerationEncoding.relativePath),
              Set(originals.keys.map { $0.lowercased() }).count == originals.count else {
            throw RegenerationError.invalidInput("invalid or colliding resource inventory")
        }
        var total = 0
        for bytes in originals.values {
            let next = total.addingReportingOverflow(bytes.count)
            guard !next.overflow, next.partialValue <= 536_870_912 else {
                throw RegenerationError.invalidInput("resource inventory exceeds 512 MiB")
            }
            total = next.partialValue
        }
        var files: [String: Data] = [:], records: [ResourceRoundTripRecord] = []
        var candidates: [ResourceRoundTripCandidate] = [], consumed = Set<String>()
        for path in originals.keys.sorted() {
            guard !consumed.contains(path), let original = originals[path] else { continue }
            if let package = Self.opaquePackageRoot(path) {
                consumed.formUnion(originals.keys.filter { $0 == package || $0.hasPrefix(package + "/") })
                let kind = (package as NSString).pathExtension.lowercased()
                records.append(Self.fallback(package, converter: kind + "-package", status: .refused,
                    reason: "Original package retained as one resource; editable conversion is pending."))
                continue
            }
            let extensionName = (path as NSString).pathExtension.lowercased()
            if ["strings", "stringsdict"].contains(extensionName), path.contains(".lproj/") {
                do {
                    let candidate = try LocalizationRoundTripConverter(sourceLanguage: sourceLanguage)
                        .convert(path: path, files: originals)
                    for (source, data) in candidate.sourceFiles {
                        guard RegenerationEncoding.relativePath(source), files["Resources/Source/" + source] == nil else {
                            throw RegenerationError.invalidInput("resource converter output collision")
                        }
                        files["Resources/Source/" + source] = data
                    }
                    consumed.formUnion(candidate.record.compiledPaths)
                    records.append(candidate.record); candidates.append(candidate)
                } catch {
                    consumed.insert(path)
                    records.append(Self.fallback(path, converter: "localization-v1", status: .refused,
                        reason: "Localization conversion refused: \(error.localizedDescription)"))
                }
            } else {
                consumed.insert(path)
                let family: String?
                if extensionName == "car" { family = "asset-catalog" }
                else if extensionName == "nib" || path.contains(".nib/") { family = "nib" }
                else if extensionName == "mom" || path.contains(".momd/") { family = "core-data" }
                else { family = nil }
                records.append(Self.fallback(path, converter: family ?? "verbatim-copy",
                    status: family == nil ? .copied : .refused,
                    reason: family.map { "\($0) source conversion is not implemented in this checkpoint." }
                        ?? "Original resource retained."))
            }
            files["Resources/Compiled/" + path] = original
        }
        // Group conversion consumes several locale files at once; all originals remain preserved.
        for (path, bytes) in originals { files["Resources/Compiled/" + path] = bytes }
        _ = try ResourceRoundTripComposition.buildPaths(records)
        return .init(files: files, records: records, candidates: candidates)
    }

    private static func opaquePackageRoot(_ path: String) -> String? {
        let packages: Set<String> = ["momd", "nib", "storyboardc", "bundle", "framework", "mlmodelc", "rtfd", "scnassets"]
        let components = path.split(separator: "/").map(String.init)
        for (index, part) in components.enumerated() where packages.contains((part as NSString).pathExtension.lowercased()) {
            return components.prefix(index + 1).joined(separator: "/")
        }
        return nil
    }

    private static func fallback(_ path: String, converter: String,
                                 status: ResourceRoundTripStatus, reason: String) -> ResourceRoundTripRecord {
        .init(compiledPaths: [path], sourcePath: nil, converter: converter, status: status,
              equivalence: .init(outcome: .notRun, tool: nil, receiptPath: nil), diagnostics: [reason])
    }
}
