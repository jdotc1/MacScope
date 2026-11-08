import Foundation

/// Explicit user-authored return evidence; identity checks are not source verification.
enum OwnReturnAuthority {
    struct Source: Codable, Equatable { var url: String; var version: String; var sha256: String }
    struct Image: Codable, Equatable { var uuid: String; var installName: String; var architecture: String }
    struct Candidate: Codable, Equatable {
        var definition: String
        var translationUnit: String
        var precision: String
        var symbol: String
        var returnType: String
        var expandedReturnType: String
        var returnDependsOnPrecision: Bool
        var evidence: String
    }
    struct Row: Codable, Equatable {
        var start_hex: String
        var name: String
        var source_file_line: String
        var declared_return_as_written: String
        var precision_variant: String
        var identity_method: String
        var identity_evidence: String
        var verdict: String
        var confidence_note: String
        var return_type_for_override: String
        var value_class: String
        // Missing optional fields decode as nil for the retained BOUND records.
        // RETURN_INVARIANT proves only a return type, never which candidate is this start.
        var identity_class: String? = nil
        var candidate_definitions: [Candidate]? = nil
        var candidate_set_complete: Bool? = nil
    }
    struct Envelope: Codable, Equatable {
        var schemaVersion: Int
        var source: Source
        var evidenceCensusHead: String
        var image: Image
        var slot: String
        var functions: [Row]
    }
    /// Supplied only by a caller with an independent reviewed trust root.
    /// Product entry points never construct this from the evidence file.
    struct Expectation {
        var source: Source
        var evidenceCensusHead: String
        var image: Image
        var slot: String
        var records: [Row]
    }
    struct DisplacedImported: Codable {
        var start_hex: String
        // Encode the FULL presence-preserving signature, not just its return type.
        // Includes returnType, parameterList, variadicState, noReturnState and legacy quarantine.
        var signature: FunctionSignatureOverride
    }
    struct Report: Codable {
        var schemaVersion = 1
        var source: Source
        var evidenceCensusHead: String
        var image: Image
        var slot: String
        var appliedStarts: [String]
        var displacedImported: [DisplacedImported]
        var appliedStartsByAuthorityClass: [String: [String]] = [:]
    }
    struct Result { var snapshot: WorkspaceSnapshot; var report: Report? }
    struct Rejection: Error, CustomStringConvertible {
        let description: String
        init(_ reason: String) { description = "own-return authority rejected: " + reason }
    }

    static let flagKey = "MacScopeOwnReturnAuthority"
    static let flagEnvironmentKey = "MACSCOPE_OWN_RETURN_AUTHORITY"
    static let pathEnvironmentKey = "MACSCOPE_OWN_RETURN_AUTHORITY_PATH"
    static let maximumBytes = 8 * 1024 * 1024
    static let maximumRows = 10_000

    static func enabled(environment: [String: String], defaults: UserDefaults) -> Bool {
        if defaults === UserDefaults.standard,
           MacIRConfiguration.installedTestBaseline != nil { return false }
        return MacIRConfiguration.enabled(environmentValue: environment[flagEnvironmentKey],
                                           preference: defaults.bool(forKey: flagKey))
    }

    /// The only product file-loading entry. Off never consults the path or loader.
    static func load(into snapshot: WorkspaceSnapshot,
                     environment: [String: String] = ProcessInfo.processInfo.environment,
                     defaults: UserDefaults = .standard,
                     readFile: (URL) throws -> Data = OwnReturnAuthority.readBounded) throws -> Result {
        guard enabled(environment: environment, defaults: defaults) else {
            return Result(snapshot: snapshot, report: nil)
        }
        guard let path = environment[pathEnvironmentKey],
              !path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Rejection("empty authority path")
        }
        let url = URL(fileURLWithPath: path).standardizedFileURL
        return try applyingUserEvidence(data: readFile(url), to: snapshot, file: url.path)
    }

    /// Bounded input read, not a digest or source-provenance check.
    static func readBounded(_ url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var data = Data()
        while data.count <= maximumBytes {
            let remaining = maximumBytes + 1 - data.count
            guard let chunk = try handle.read(upToCount: min(64 * 1024, remaining)),
                  !chunk.isEmpty else { break }
            data.append(chunk)
        }
        guard data.count <= maximumBytes else { throw Rejection("authority file too large") }
        return data
    }

    /// Explicit opt-in pure API. The caller, not the file, supplies its source name.
    static func applyingUserEvidence(data: Data, to snapshot: WorkspaceSnapshot,
                                     file: String) throws -> Result {
        guard !file.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Rejection("empty authority path")
        }
        guard data.count <= maximumBytes else { throw Rejection("authority file too large") }
        return try applying(data: data, to: snapshot, expected: nil, authorityFile: file)
    }

    /// A single validation pipeline retains the legacy interleaved guard order.
    /// A non-nil expectation is supplied by the C2 wrapper, never by product load.
    static func applying(data: Data, to snapshot: WorkspaceSnapshot,
                         expected: Expectation?, authorityFile: String? = nil) throws -> Result {
        let envelope = try JSONDecoder().decode(Envelope.self, from: data)
        guard envelope.schemaVersion == 1 else { throw Rejection("schemaVersion") }
        guard (expected?.slot ?? "primary") == "primary", envelope.slot == "primary",
              snapshot.primarySlot == .primary else { throw Rejection("slot") }
        if let expected {
            guard envelope.source == expected.source,
                  envelope.evidenceCensusHead == expected.evidenceCensusHead,
                  envelope.image == expected.image else {
                throw Rejection("reviewed source/image identity")
            }
        }
        let image = expected?.image ?? envelope.image
        guard snapshot.binaries.filter({ $0.slot == .primary }).count == 1,
              let binary = snapshot.binary(in: .primary),
              let uuid = binary.metadata.uuid, UUID(uuidString: uuid) != nil,
              UUID(uuidString: uuid) == UUID(uuidString: image.uuid),
              binary.architecture == image.architecture,
              let analysis = snapshot.analysis(in: .primary) else {
            throw Rejection("loaded image UUID/architecture/slot")
        }
        // Product installName/source/head are labels, not verified trust roots.
        var catalog: [UInt64: Row] = [:]
        if let expected {
            for row in expected.records {
                let start = try canonicalStart(row.start_hex)
                guard validAuthorityClass(row), !row.return_type_for_override.isEmpty,
                      catalog.updateValue(row, forKey: start) == nil else {
                    throw Rejection("invalid compiled expected catalog")
                }
            }
            guard !catalog.isEmpty, envelope.functions.count == catalog.count else {
                throw Rejection("complete reviewed cohort required")
            }
        } else {
            guard !envelope.functions.isEmpty else { throw Rejection("empty authority cohort") }
            guard envelope.functions.count <= maximumRows else { throw Rejection("too many authority rows") }
        }
        var seen = Set<UInt64>()
        var plan: [(ImageAddress, FunctionSignatureOverride)] = []
        var displaced: [DisplacedImported] = []
        for row in envelope.functions {
            let start = try canonicalStart(row.start_hex)
            guard seen.insert(start).inserted else { throw Rejection("duplicate start " + row.start_hex) }
            guard validAuthorityClass(row),
                  !row.return_type_for_override.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  expected == nil || catalog[start] == row else {
                throw Rejection("noncohort or source/type/evidence mismatch " + row.start_hex)
            }
            if expected == nil {
                let fields = [row.name, row.source_file_line, row.declared_return_as_written,
                              row.precision_variant, row.identity_method, row.identity_evidence,
                              row.confidence_note, row.value_class]
                guard fields.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) else {
                    throw Rejection("malformed authority evidence " + row.start_hex)
                }
            }
            let functions = analysis.functions.filter { $0.startAddress == start }
            guard functions.count == 1,
                  linkageName(functions[0].name) == linkageName(row.name) else {
                throw Rejection("not an exact loaded function start/name " + row.start_hex)
            }
            let key = ImageAddress(slot: .primary, address: start)
            let signature = FunctionSignatureOverride(returnType: row.return_type_for_override)
            if let authored = snapshot.addressOverrides[key]?.signature, authored != signature {
                throw Rejection("conflicting authored signature " + row.start_hex)
            }
            if let imported = snapshot.importedPrototypes[key] {
                displaced.append(.init(start_hex: row.start_hex, signature: imported))
            }
            plan.append((key, signature))
        }
        if expected != nil {
            guard seen == Set(catalog.keys) else { throw Rejection("incomplete cohort") }
        }
        // Commit only after all validation; no inout/store mutation is exposed.
        var result = snapshot
        var overrides = snapshot.addressOverrides
        for (key, signature) in plan {
            var override = overrides[key] ?? AddressOverride()
            let previouslyAuthored = override.signature != nil
            override.signature = signature
            if !previouslyAuthored, let authorityFile {
                override.ownReturnAuthorityFile = authorityFile
            }
            overrides[key] = override
        }
        result.addressOverrides = overrides
        return Result(snapshot: result, report: Report(source: envelope.source,
            evidenceCensusHead: envelope.evidenceCensusHead, image: envelope.image, slot: envelope.slot,
            appliedStarts: envelope.functions.map { $0.start_hex }.sorted(), displacedImported: displaced,
            appliedStartsByAuthorityClass: Dictionary(grouping: envelope.functions,
                by: { $0.identity_class ?? "BOUND" }).mapValues { $0.map { $0.start_hex }.sorted() }))
    }
    private static func expandedInvariantReturn(_ type: String) -> String? {
        switch type {
        case "void": return "void"
        case "int", "boolean": return "int"
        case "JDIMENSION", "unsigned int": return "unsigned int"
        default: return nil
        }
    }
    private static func validAuthorityClass(_ row: Row) -> Bool {
        let classification = row.identity_class ?? "BOUND"
        guard row.verdict == classification else { return false }
        switch classification {
        case "BOUND":
            // Legacy exact-definition rows keep their existing eleven fields and evidence.
            return row.candidate_definitions == nil && row.candidate_set_complete == nil
        case "RETURN_INVARIANT":
            guard row.candidate_set_complete == true,
                  let candidates = row.candidate_definitions, !candidates.isEmpty,
                  let expanded = expandedInvariantReturn(row.return_type_for_override),
                  row.value_class == (expanded == "void" ? "void" : "integer") else { return false }
            var instances = Set<String>()
            for candidate in candidates {
                guard !candidate.definition.isEmpty, !candidate.translationUnit.isEmpty,
                      !candidate.precision.isEmpty, !candidate.evidence.isEmpty,
                      candidate.symbol == linkageName(row.name),
                      !candidate.returnDependsOnPrecision,
                      expandedInvariantReturn(candidate.returnType) == expanded,
                      candidate.expandedReturnType == expanded else { return false }
                // A unit/definition/precision/symbol identifies one source candidate instance.
                let instance = [candidate.translationUnit, candidate.definition,
                                candidate.precision, candidate.symbol].joined(separator: "\n")
                guard instances.insert(instance).inserted else { return false }
            }
            return true
        default:
            return false
        }
        // With a reviewed expectation, row equality separately enforces manifest completeness.
    }
    private static func canonicalStart(_ text: String) throws -> UInt64 {
        guard text.hasPrefix("0x"), let value = UInt64(text.dropFirst(2), radix: 16),
              text == "0x" + String(value, radix: 16) else { throw Rejection("noncanonical start " + text) }
        return value
    }
    private static func linkageName(_ text: String) -> String {
        text.hasPrefix("_") ? String(text.dropFirst()) : text
    }
}
