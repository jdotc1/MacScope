import Foundation

struct VersionCompareAIRSCoverage: Equatable, Sendable {
    let total: Int
    let agreement: Int
    let inconsistency: Int
    let unresolved: Int

    init(total: Int, agreement: Int, inconsistency: Int, unresolved: Int) {
        self.total = total
        self.agreement = agreement
        self.inconsistency = inconsistency
        self.unresolved = unresolved
    }

    init(_ report: UnwindAuditReport) {
        self.init(total: report.findings.count,
                  agreement: report.findings.filter { $0.verdict == "agreement" }.count,
                  inconsistency: report.findings.filter { $0.verdict == "inconsistency" }.count,
                  unresolved: report.findings.filter { $0.verdict == "unresolved" }.count)
    }

    var description: String {
        guard total > 0 else { return "0 findings; coverage unavailable (zero denominator)." }
        return "\(total) findings: \(unresolved) unresolved, \(inconsistency) inconsistency, \(agreement) agreement."
    }
}

/// A read-only projection. The original bytes and source lineage remain in S2's record.
/// An imported single finding is deliberately never converted into a native report.
struct VersionCompareAIRSEvidenceEntry: Identifiable, Equatable, Sendable {
    let record: AIRSEvidenceRecord
    let report: UnwindAuditReport?
    let importedVerdict: String?
    let importedSummary: String?
    var id: UUID { record.id }
    var coverage: VersionCompareAIRSCoverage? { report.map(VersionCompareAIRSCoverage.init) }
    var title: String {
        let source = report == nil ? "Imported finding" : "Native audit"
        return "\(source) · \(record.createdAt.formatted()) · \(record.id.uuidString)"
    }
    var orderedFindings: [UnwindAuditFinding] {
        (report?.findings ?? []).sorted {
            let left = Self.order($0.verdict), right = Self.order($1.verdict)
            if left != right { return left < right }
            if $0.function.address != $1.function.address { return $0.function.address < $1.function.address }
            return $0.function.id < $1.function.id
        }
    }
    private static func order(_ verdict: String) -> Int {
        switch verdict { case "unresolved": 0; case "inconsistency": 1; default: 2 }
    }
}

struct VersionCompareAIRSEvidenceInventory: Equatable, Sendable {
    let entries: [VersionCompareAIRSEvidenceEntry]
    static let empty = Self(entries: [])
    var nativeEntries: [VersionCompareAIRSEvidenceEntry] { entries.filter { $0.report != nil } }

    /// Binding is supplied from the current store snapshot; it is never saved into evidence.
    func orderedEntries(isResolved: (AIRSEvidenceRecord) -> Bool) -> [VersionCompareAIRSEvidenceEntry] {
        entries.map { (entry: $0, resolved: isResolved($0.record)) }.sorted {
            if $0.resolved != $1.resolved { return !$0.resolved }
            return $0.entry.id.uuidString < $1.entry.id.uuidString
        }.map(\.entry)
    }

    /// Validate every record before publishing any projection, including imports which are not
    /// comparison candidates. Reuse the original validating decoder/parser, not a new schema.
    static func build(_ envelope: AIRSEvidenceEnvelope, workspaceID: UUID) throws -> Self {
        try envelope.validate(workspaceID: workspaceID)
        let entries = try envelope.records.map { record -> VersionCompareAIRSEvidenceEntry in
            switch record.source {
            case .nativeUnwind:
                let report = try JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload)
                return .init(record: record, report: report, importedVerdict: nil, importedSummary: nil)
            case .importedHandoff:
                let handoff = try AIRSHandoffImport.parse(record.rawPayload)
                return .init(record: record, report: nil, importedVerdict: handoff.verdict,
                    importedSummary: "\(handoff.name) · \(handoff.verdict) · \(handoff.coverage) · \(handoff.scope) · \(handoff.model)")
            }
        }
        return .init(entries: entries.sorted { $0.id.uuidString < $1.id.uuidString })
    }
}
