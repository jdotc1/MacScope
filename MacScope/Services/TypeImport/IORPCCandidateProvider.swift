import Foundation

/// Observations only. Construction does not read a source file, admit an SDK,
/// associate a class, resolve dispatch, decode an archive or calculate a digest.
/// The supplied admitted archive is the sole declaration/identity authority.
/// Presence means a retained observation list, never a complete SDK catalog.
struct IORPCCandidateProvider: Sendable {
    enum Refusal: Error, Equatable { case invalid(String) }
    enum Presence: String, Codable, Sendable { case absent, present }
    enum Status: String, Codable, Sendable {
        case unadmittedCandidate = "unadmitted-candidate"
        case ambiguousNumericAlias = "ambiguous-numeric-alias"
    }
    struct Candidate: Codable, Sendable {
        let identity: ImportedTypeIdentity
        let name: String
        let id: UInt64
        let origin: SDKTypeArchive.Origin
        let status: Status
    }
    struct Projection: Codable, Sendable {
        let archiveSHA256: String
        let configurationID: String
        let targetTriple: String
        let sdkIdentity: String
        let presence: Presence
        let sdkRelease: String?
        let sdkBuild: String?
        let architecture: String?
        let authority: String
        let candidates: [Candidate]
    }
    static let maximumSectionBytes = 4 * 1024 * 1024
    static let maximumProjectionBytes = 8 * 1024 * 1024
    private static let admission = "requires Lane A exact-build/source admission; no message dispatch or class association inferred"
    let projection: Projection
    private let retainedProjection: Data
    func encodedProjection() -> Data { retainedProjection }

    enum LookupRefusal: Error, Equatable {
        case invalidBudget
        case matchCountExceeded
        case byteBudgetExceeded
    }
    struct LookupBudget: Sendable {
        let maximumMatches: Int
        let maximumEncodedBytes: Int
        init(maximumMatches: Int = 10_000, maximumEncodedBytes: Int = IORPCCandidateProvider.maximumProjectionBytes) {
            self.maximumMatches = maximumMatches
            self.maximumEncodedBytes = maximumEncodedBytes
        }
    }
    enum LookupOutcome: String, Codable, Sendable {
        case sectionAbsent, sectionEmpty, noObservedMatch, observedMatches
    }
    /// Data only, including after decoding; never an archive/provider initializer.
    struct LookupProjection: Codable, Sendable {
        let requestedID: UInt64
        let outcome: LookupOutcome
        let context: Projection
    }
    struct LookupResult: Sendable {
        let projection: LookupProjection
        let encoded: Data
    }

    /// Exact retained observations only; no dispatch, signature, ABI, registration,
    /// entitlement, source authenticity or execution authority follows from a match.
    /// Zero slots succeeds only without matches. Conservative preflight can refuse
    /// an encoding that might fit; refusal never yields a partial result.
    func lookup(id: UInt64, budget: LookupBudget = .init()) throws -> LookupResult {
        guard (0...10_000).contains(budget.maximumMatches),
              budget.maximumEncodedBytes > 0,
              budget.maximumEncodedBytes <= Self.maximumProjectionBytes else {
            throw LookupRefusal.invalidBudget
        }
        // No result array or encoded DTO is allocated until the entire scan passes.
        // 2048 covers fixed context/result keys, punctuation, outcome and UInt64 ID;
        // 512 per row covers keys, punctuation and maximum-width numeric fields.
        var bound = 0
        func chargeBytes(_ amount: Int) throws {
            let (next, overflow) = bound.addingReportingOverflow(amount)
            guard !overflow, next <= budget.maximumEncodedBytes else { throw LookupRefusal.byteBudgetExceeded }
            bound = next
        }
        func chargeText(_ text: String) throws {
            let (escaped, overflow) = text.utf8.count.multipliedReportingOverflow(by: 6)
            guard !overflow else { throw LookupRefusal.byteBudgetExceeded }
            try chargeBytes(escaped)
        }
        try chargeBytes(2048)
        try chargeText(projection.archiveSHA256)
        try chargeText(projection.configurationID)
        try chargeText(projection.targetTriple)
        try chargeText(projection.sdkIdentity)
        try chargeText(projection.authority)
        if let text = projection.sdkRelease { try chargeText(text) }
        if let text = projection.sdkBuild { try chargeText(text) }
        if let text = projection.architecture { try chargeText(text) }
        var count = 0
        for row in projection.candidates where row.id == id {
            guard count < budget.maximumMatches else { throw LookupRefusal.matchCountExceeded }
            count += 1 // bounded by validated maximumMatches
            try chargeBytes(512)
            try chargeText(row.identity.archiveSHA256)
            try chargeText(row.identity.declarationID)
            try chargeText(row.name)
            try chargeText(row.origin.header)
            try chargeText(row.status.rawValue)
        }
        var matches: [Candidate] = []
        matches.reserveCapacity(count)
        for row in projection.candidates where row.id == id { matches.append(row) }
        matches.sort { left, right in
            // String equality is canonically equivalent in Swift: compare byte
            // views for both equality and order, never String == or locale APIs.
            for (a, b) in [(left.identity.declarationID, right.identity.declarationID),
                           (left.name, right.name), (left.origin.header, right.origin.header)] {
                if !a.utf8.elementsEqual(b.utf8) { return a.utf8.lexicographicallyPrecedes(b.utf8) }
            }
            if left.origin.line != right.origin.line { return left.origin.line < right.origin.line }
            return left.origin.column < right.origin.column
        }
        let outcome: LookupOutcome
        if projection.presence == .absent { outcome = .sectionAbsent }
        else if projection.candidates.isEmpty { outcome = .sectionEmpty }
        else if matches.isEmpty { outcome = .noObservedMatch }
        else { outcome = .observedMatches }
        let context = Projection(archiveSHA256: projection.archiveSHA256,
                                 configurationID: projection.configurationID,
                                 targetTriple: projection.targetTriple, sdkIdentity: projection.sdkIdentity,
                                 presence: projection.presence, sdkRelease: projection.sdkRelease,
                                 sdkBuild: projection.sdkBuild, architecture: projection.architecture,
                                 authority: projection.authority, candidates: matches)
        let result = LookupProjection(requestedID: id, outcome: outcome, context: context)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(result)
        guard encoded.count <= budget.maximumEncodedBytes else { throw LookupRefusal.byteBudgetExceeded }
        return LookupResult(projection: result, encoded: encoded)
    }

    init(archive: SDKTypeArchive) throws {
        let bytes = archive.encoded() // Retained bytes; no second admission/hash.
        guard bytes.count <= SDKTypeArchive.maxBytes else { throw Refusal.invalid("archive byte limit") }
        var reader = CandidateJSON(bytes)
        let root = try reader.object(0..<bytes.count, maximumMembers: 128)
        guard let provenanceRange = root["provenance"] else { throw Refusal.invalid("missing provenance") }
        let provenance = try reader.object(provenanceRange, maximumMembers: 128)
        let document = archive.document
        let p = document.provenance
        var candidates: [Candidate] = []
        var labels: [String: String] = [:]
        let presence: Presence
        if let sectionRange = provenance["iorpcConstantCandidates"] {
            presence = .present
            guard sectionRange.count <= Self.maximumSectionBytes else { throw Refusal.invalid("candidate byte limit") }
            let section = try reader.object(sectionRange, maximumMembers: 5)
            try Self.keys(section, ["sdkRelease", "sdkBuild", "architecture", "constants", "admission"])
            guard try reader.string(section["admission"]!) == Self.admission else { throw Refusal.invalid("unsupported admission label") }
            for key in ["sdkRelease", "sdkBuild", "architecture"] {
                guard let original = provenance[key] else { throw Refusal.invalid("missing selection provenance") }
                let value = try reader.string(section[key]!, maximum: 256)
                guard !value.isEmpty, value == (try reader.string(original, maximum: 256)) else {
                    throw Refusal.invalid("contradictory selection provenance")
                }
                labels[key] = value
            }
            guard ["arm64", "arm64e"].contains(labels["architecture"]!),
                  p.targetTriple.hasPrefix(labels["architecture"]! + "-apple-") else {
                throw Refusal.invalid("architecture mismatch")
            }
            // The emitter records path|release|build. These labels are checked,
            // not promoted to independently authenticated SDK authority.
            guard p.sdkIdentity.hasSuffix("|" + labels["sdkRelease"]! + "|" + labels["sdkBuild"]!) else {
                throw Refusal.invalid("SDK label mismatch")
            }
            let rows = try reader.array(section["constants"]!, maximumElements: 10_000)
            struct Row { let enumID: String; let name: String; let id: UInt64; let origin: SDKTypeArchive.Origin; let status: String }
            var observations: [Row] = []
            var selected = Set<String>()
            var names: [String: Set<String>] = [:]
            var counts: [UInt64: Int] = [:]
            for range in rows {
                let row = try reader.object(range, maximumMembers: 5)
                try Self.keys(row, ["enumTypeID", "name", "id", "origin", "status"])
                let enumID = try reader.string(row["enumTypeID"]!, maximum: 1024)
                let name = try reader.string(row["name"]!, maximum: 16_384)
                guard !enumID.isEmpty, !name.isEmpty, names[enumID, default: []].insert(name).inserted else {
                    throw Refusal.invalid("duplicate or empty candidate")
                }
                selected.insert(enumID)
                guard selected.count <= 128 else { throw Refusal.invalid("selection count") }
                let id = try reader.unsigned(row["id"]!)
                let origin = try reader.object(row["origin"]!, maximumMembers: 3)
                try Self.keys(origin, ["header", "line", "column"])
                let header = try reader.string(origin["header"]!, maximum: 16_384)
                guard let line = UInt32(exactly: try reader.unsigned(origin["line"]!)),
                      let column = UInt32(exactly: try reader.unsigned(origin["column"]!)) else { throw Refusal.invalid("origin range") }
                observations.append(Row(enumID: enumID, name: name, id: id,
                                        origin: .init(header: header, line: line, column: column),
                                        status: try reader.string(row["status"]!, maximum: 64)))
                counts[id, default: 0] += 1
            }
            guard document.types.count <= SDKTypeArchive.maxNodes else { throw Refusal.invalid("type work limit") }
            // Index selected enums only; never allocate a second whole type DB.
            var nodes: [String: SDKTypeArchive.Node] = [:]
            for node in document.types where selected.contains(node.id) {
                guard node.kind == .enumeration, node.origin != nil,
                      nodes.updateValue(node, forKey: node.id) == nil else { throw Refusal.invalid("enum identity") }
            }
            guard nodes.count == selected.count else { throw Refusal.invalid("missing enum") }
            var values: [String: [String: UInt64]] = [:]
            var total = 0
            for (identity, node) in nodes {
                total += node.enumValues.count
                guard total <= 10_000, node.enumValues.count == names[identity]?.count else {
                    throw Refusal.invalid("incomplete enum selection")
                }
                for item in node.enumValues {
                    guard let value = UInt64(item.value), String(value) == item.value else { throw Refusal.invalid("non-UInt64 enum") }
                    values[identity, default: [:]][item.name] = value
                }
            }
            for row in observations {
                guard values[row.enumID]?[row.name] == row.id, nodes[row.enumID]?.origin == row.origin else {
                    throw Refusal.invalid("candidate does not match admitted declaration")
                }
                let status: Status = counts[row.id]! > 1 ? .ambiguousNumericAlias : .unadmittedCandidate
                guard row.status == status.rawValue else { throw Refusal.invalid("forged status") }
                candidates.append(.init(identity: .init(archiveSHA256: archive.contentSHA256, declarationID: row.enumID),
                                        name: row.name, id: row.id, origin: row.origin, status: status))
            }
        } else { presence = .absent }
        let result = Projection(archiveSHA256: archive.contentSHA256, configurationID: document.configurationID,
                                targetTriple: p.targetTriple, sdkIdentity: p.sdkIdentity, presence: presence,
                                sdkRelease: labels["sdkRelease"], sdkBuild: labels["sdkBuild"], architecture: labels["architecture"],
                                authority: Self.admission, candidates: candidates)
        // Worst-case JSON escaping is six bytes per UTF-8 byte. Charge every
        // emitted text plus fixed keys/numbers/wrappers BEFORE JSONEncoder work.
        var bound = 2048
        func charge(_ text: String) throws {
            let count = text.utf8.count
            guard count <= (Self.maximumProjectionBytes - bound) / 6 else { throw Refusal.invalid("projection byte limit") }
            bound += count * 6
        }
        for text in [result.archiveSHA256, result.configurationID, result.targetTriple, result.sdkIdentity,
                     result.authority, result.sdkRelease ?? "", result.sdkBuild ?? "", result.architecture ?? ""] { try charge(text) }
        for row in candidates {
            guard bound <= Self.maximumProjectionBytes - 512 else { throw Refusal.invalid("projection byte limit") }
            bound += 512
            for text in [row.identity.archiveSHA256, row.identity.declarationID, row.name, row.origin.header, row.status.rawValue] { try charge(text) }
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(result)
        guard encoded.count <= Self.maximumProjectionBytes else { throw Refusal.invalid("projection byte limit") }
        projection = result
        retainedProjection = encoded
    }
    private static func keys(_ object: [String: Range<Int>], _ expected: Set<String>) throws {
        guard Set(object.keys) == expected else { throw Refusal.invalid("unsupported candidate keys") }
    }
}

/// Private range scanner: no whole-archive object graph. Every object rejects
/// decoded duplicate keys, including escaped spellings. The original admitted
/// archive supplies JSON syntax validity; this scanner additionally bounds work
/// and identifies the optional section without NSNumber/Double conversion.
private struct CandidateJSON {
    let data: Data
    var work = 0
    init(_ data: Data) { self.data = data }
    private func byte(_ offset: Int) -> UInt8 { data[data.startIndex + offset] }
    private mutating func tick() throws {
        work += 1
        guard work <= 8_000_000 else { throw IORPCCandidateProvider.Refusal.invalid("JSON work limit") }
    }
    private func whitespace(_ index: inout Int, _ end: Int) {
        while index < end, [UInt8(32), 9, 10, 13].contains(self.byte(index)) { index += 1 }
    }
    private mutating func token(_ index: inout Int, _ end: Int) throws -> Range<Int> {
        let start = index
        guard index < end, self.byte(index) == 34 else { throw IORPCCandidateProvider.Refusal.invalid("JSON string") }
        index += 1
        var escaped = false
        while index < end {
            let byte = self.byte(index); index += 1
            guard index - start <= 98_306 else { throw IORPCCandidateProvider.Refusal.invalid("JSON string limit") }
            if escaped { escaped = false }
            else if byte == 92 { escaped = true }
            else if byte == 34 { return start..<index }
        }
        throw IORPCCandidateProvider.Refusal.invalid("unterminated JSON string")
    }
    mutating func string(_ range: Range<Int>, maximum: Int = 16_384) throws -> String {
        guard range.count <= maximum * 6 + 2 else { throw IORPCCandidateProvider.Refusal.invalid("encoded text limit") }
        let value = try JSONDecoder().decode(String.self, from: data.subdata(in: (data.startIndex + range.lowerBound)..<(data.startIndex + range.upperBound)))
        guard value.utf8.count <= maximum, !value.contains("\0") else { throw IORPCCandidateProvider.Refusal.invalid("text limit") }
        return value
    }
    mutating func unsigned(_ range: Range<Int>) throws -> UInt64 {
        guard !range.isEmpty, range.count <= 20 else { throw IORPCCandidateProvider.Refusal.invalid("integer range") }
        var value: UInt64 = 0
        for index in range {
            let byte = self.byte(index)
            guard (48...57).contains(byte) else { throw IORPCCandidateProvider.Refusal.invalid("integer spelling") }
            let (product, multiplyOverflow) = value.multipliedReportingOverflow(by: 10)
            let (sum, addOverflow) = product.addingReportingOverflow(UInt64(byte - 48))
            guard !multiplyOverflow, !addOverflow else { throw IORPCCandidateProvider.Refusal.invalid("integer overflow") }
            value = sum
        }
        guard range.count == 1 || self.byte(range.lowerBound) != 48 else { throw IORPCCandidateProvider.Refusal.invalid("integer spelling") }
        return value
    }
    private mutating func value(_ index: inout Int, _ end: Int, depth: Int) throws -> Range<Int> {
        try tick(); whitespace(&index, end)
        guard depth <= 32, index < end else { throw IORPCCandidateProvider.Refusal.invalid("JSON depth/end") }
        let start = index
        switch self.byte(index) {
        case 34: return try token(&index, end)
        case 123:
            index += 1; whitespace(&index, end)
            var keys = Set<String>()
            if index < end, self.byte(index) != 125 {
                while true {
                    guard keys.count < 128 else { throw IORPCCandidateProvider.Refusal.invalid("object key limit") }
                    let keyRange = try token(&index, end)
                    let key = try string(keyRange, maximum: 1024)
                    guard keys.insert(key).inserted else { throw IORPCCandidateProvider.Refusal.invalid("duplicate JSON key") }
                    whitespace(&index, end)
                    guard index < end, self.byte(index) == 58 else { throw IORPCCandidateProvider.Refusal.invalid("JSON colon") }
                    index += 1; _ = try value(&index, end, depth: depth + 1); whitespace(&index, end)
                    if index < end, self.byte(index) == 44 { index += 1; whitespace(&index, end); continue }
                    break
                }
            }
            guard index < end, self.byte(index) == 125 else { throw IORPCCandidateProvider.Refusal.invalid("JSON object end") }
            index += 1
        case 91:
            index += 1; whitespace(&index, end)
            var count = 0
            if index < end, self.byte(index) != 93 {
                while true {
                    count += 1
                    guard count <= 1_000_000 else { throw IORPCCandidateProvider.Refusal.invalid("array work limit") }
                    _ = try value(&index, end, depth: depth + 1); whitespace(&index, end)
                    if index < end, self.byte(index) == 44 { index += 1; continue }
                    break
                }
            }
            guard index < end, self.byte(index) == 93 else { throw IORPCCandidateProvider.Refusal.invalid("JSON array end") }
            index += 1
        default:
            while index < end, ![UInt8(32), 9, 10, 13, 44, 93, 125].contains(self.byte(index)) { index += 1 }
            guard index > start else { throw IORPCCandidateProvider.Refusal.invalid("JSON token") }
        }
        return start..<index
    }
    mutating func object(_ range: Range<Int>, maximumMembers: Int) throws -> [String: Range<Int>] {
        var index = range.lowerBound; whitespace(&index, range.upperBound)
        guard index < range.upperBound, self.byte(index) == 123 else { throw IORPCCandidateProvider.Refusal.invalid("expected object") }
        index += 1; whitespace(&index, range.upperBound)
        var result: [String: Range<Int>] = [:]
        if index < range.upperBound, self.byte(index) != 125 {
            while true {
                guard result.count < maximumMembers else { throw IORPCCandidateProvider.Refusal.invalid("object count") }
                let keyRange = try token(&index, range.upperBound)
                let key = try string(keyRange, maximum: 1024)
                whitespace(&index, range.upperBound)
                guard index < range.upperBound, self.byte(index) == 58 else { throw IORPCCandidateProvider.Refusal.invalid("JSON colon") }
                index += 1
                let member = try value(&index, range.upperBound, depth: 1)
                guard result.updateValue(member, forKey: key) == nil else { throw IORPCCandidateProvider.Refusal.invalid("duplicate JSON key") }
                whitespace(&index, range.upperBound)
                if index < range.upperBound, self.byte(index) == 44 { index += 1; whitespace(&index, range.upperBound); continue }
                break
            }
        }
        guard index < range.upperBound, self.byte(index) == 125 else { throw IORPCCandidateProvider.Refusal.invalid("object end") }
        index += 1; whitespace(&index, range.upperBound)
        guard index == range.upperBound else { throw IORPCCandidateProvider.Refusal.invalid("object trailing bytes") }
        return result
    }
    mutating func array(_ range: Range<Int>, maximumElements: Int) throws -> [Range<Int>] {
        var index = range.lowerBound
        guard index < range.upperBound, self.byte(index) == 91 else { throw IORPCCandidateProvider.Refusal.invalid("expected array") }
        index += 1; whitespace(&index, range.upperBound)
        var result: [Range<Int>] = []
        if index < range.upperBound, self.byte(index) != 93 {
            while true {
                guard result.count < maximumElements else { throw IORPCCandidateProvider.Refusal.invalid("candidate count") }
                result.append(try value(&index, range.upperBound, depth: 1)); whitespace(&index, range.upperBound)
                if index < range.upperBound, self.byte(index) == 44 { index += 1; continue }
                break
            }
        }
        guard index < range.upperBound, self.byte(index) == 93, index + 1 == range.upperBound else { throw IORPCCandidateProvider.Refusal.invalid("array end") }
        return result
    }
}
