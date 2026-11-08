import Foundation

enum UnwindAuditChangeKind: String, Hashable, Codable, Sendable {
    case unchanged
    case changed
    case ambiguous
    case incompatible
}

struct UnwindAuditMatchedChange: Hashable, Codable, Sendable {
    let match: FunctionVersionMatch
    let change: UnwindAuditChangeKind
    let beforeVerdict: String
    let afterVerdict: String
    let beforeScope: String
    let afterScope: String
    let notes: [String]
}

struct UnwindAuditComparison: Hashable, Codable, Sendable {
    let schemaVersion: Int
    let baselineIdentity: MachOSliceArtifactIdentity
    let currentIdentity: MachOSliceArtifactIdentity
    let sameSlice: Bool
    let modelCompatible: Bool
    let configurationChanged: Bool
    /// The matcher's complete result preserves evidence, ambiguity and unmatched functions.
    let matching: FunctionVersionMatchResult
    /// Audit changes are independent of the matcher's code-difference classification.
    let changes: [UnwindAuditMatchedChange]
    let limitations: [String]
}

enum UnwindAuditComparisonError: Error, Equatable, Sendable {
    case invalidAccounting(String)
}

enum UnwindAuditComparator {
    static func compare(
        baseline: UnwindAuditReport,
        current: UnwindAuditReport,
        pins: [FunctionVersionManualPin] = []
    ) throws -> UnwindAuditComparison {
        try baseline.validate()
        try current.validate()
        let sameArchitecture = baseline.identity.rawCPUType == current.identity.rawCPUType
            && baseline.identity.rawCPUSubtype == current.identity.rawCPUSubtype
        let sameSlice = sameArchitecture
            && baseline.identity.selectedSliceSHA256 == current.identity.selectedSliceSHA256
            && baseline.identity.selectedSliceByteCount == current.identity.selectedSliceByteCount
        let matching = try FunctionVersionMatcher(
            old: baseline.findings.map(\.function),
            new: current.findings.map(\.function),
            usingVerifiedSameSliceOffsets: sameSlice
        ).match(pins: pins)
        try validateAccounting(matching, baseline: baseline, current: current)
        let oldByID = Dictionary(uniqueKeysWithValues: baseline.findings.map { ($0.function.id, $0) })
        let newByID = Dictionary(uniqueKeysWithValues: current.findings.map { ($0.function.id, $0) })
        let compatible = sameArchitecture
            && baseline.analysisModelVersion == current.analysisModelVersion
        let configurationChanged = baseline.configuration != current.configuration
        let observationsComparable = compatible && !configurationChanged
        let changes = try matching.matches.map { match -> UnwindAuditMatchedChange in
            guard let before = oldByID[match.oldID], let after = newByID[match.newID] else {
                throw UnwindAuditComparisonError.invalidAccounting("match endpoint absent")
            }
            let change: UnwindAuditChangeKind = observationsComparable
                ? (Signature(before) == Signature(after) ? .unchanged : .changed)
                : .incompatible
            let notes = observationsComparable ? [] : [
                "Analysis model, architecture or configuration differs. Analyze both inputs with one model and configuration before interpreting an audit change."
            ]
            return UnwindAuditMatchedChange(
                match: match, change: change,
                beforeVerdict: before.verdict, afterVerdict: after.verdict,
                beforeScope: before.scope, afterScope: after.scope, notes: notes
            )
        }
        var limitations = [
            "Equal addresses across builds are not function identity evidence.",
            "Automatic matches are review candidates; their original basis and confidence are retained.",
            "Unmatched additions and removals are not automatically regressions or fixes.",
            "An agreement retains the checked scope and limitations of its source report."
        ]
        if sameSlice {
            limitations.append("Same-slice automatic matches use canonical image-local starts only; manual pins retain precedence. Saved identities are declarations, not fresh authentication of source bytes.")
            for match in matching.matches where match.basis == .manual && match.oldAddress != match.newAddress {
                limitations.append("Same-slice manual pin overrides offset authority: \(match.oldID) -> \(match.newID). This is user selection, not independently established identity.")
            }
        }
        if configurationChanged {
            limitations.append("Analysis configuration differs; budget-related scope changes require review.")
        }
        return UnwindAuditComparison(
            schemaVersion: 1,
            baselineIdentity: baseline.identity,
            currentIdentity: current.identity,
            sameSlice: sameSlice,
            modelCompatible: compatible,
            configurationChanged: configurationChanged,
            matching: matching,
            changes: changes,
            limitations: limitations
        )
    }

    /// Every source finding belongs to exactly one matched, unmatched or unresolved bucket.
    /// This is ID accounting, not proof that an imported report covers all binary functions.
    static func validateAccounting(
        _ matching: FunctionVersionMatchResult,
        baseline: UnwindAuditReport, current: UnwindAuditReport
    ) throws {
        try baseline.validate()
        try current.validate()
        let oldIDs = matching.matches.map(\.oldID) + matching.removedIDs
            + matching.unresolved.flatMap(\.oldIDs)
        let newIDs = matching.matches.map(\.newID) + matching.addedIDs
            + matching.unresolved.flatMap(\.newIDs)
        guard oldIDs.count == Set(oldIDs).count, newIDs.count == Set(newIDs).count,
              Set(oldIDs) == Set(baseline.findings.map { $0.function.id }),
              Set(newIDs) == Set(current.findings.map { $0.function.id }) else {
            throw UnwindAuditComparisonError.invalidAccounting("source IDs are not an exact disjoint partition")
        }
        let oldByID = Dictionary(uniqueKeysWithValues: baseline.findings.map { ($0.function.id, $0) })
        let newByID = Dictionary(uniqueKeysWithValues: current.findings.map { ($0.function.id, $0) })
        for match in matching.matches {
            guard oldByID[match.oldID]?.function.address == match.oldAddress,
                  newByID[match.newID]?.function.address == match.newAddress else {
                throw UnwindAuditComparisonError.invalidAccounting("match address disagrees with source")
            }
        }
        for group in matching.unresolved {
            guard !group.oldIDs.isEmpty || !group.newIDs.isEmpty else {
                throw UnwindAuditComparisonError.invalidAccounting("empty unresolved group")
            }
        }
        let manualMatches = Set(matching.matches.filter { $0.basis == .manual }.map {
            FunctionVersionManualPin(oldID: $0.oldID, newID: $0.newID)
        })
        guard Set(matching.manualPins) == manualMatches,
              matching.manualPins.count == Set(matching.manualPins).count else {
            throw UnwindAuditComparisonError.invalidAccounting("manual pin provenance disagrees")
        }
    }

    private struct EvidenceSignature: Equatable {
        let code: String
        let expected: String?
        let observed: String?
        let relativeAddress: UInt64?
    }

    private struct Signature: Equatable {
        let verdict: String
        let coverage: String
        let mode: String
        let scope: String
        let encoding: UInt32?
        let reasonCodes: [String]
        let relativeCheckedPCs: [UInt64]
        let evidence: [EvidenceSignature]

        init(_ finding: UnwindAuditFinding) {
            verdict = finding.verdict
            coverage = finding.coverage
            mode = finding.mode
            scope = finding.scope
            encoding = finding.encoding
            reasonCodes = finding.reasonCodes.sorted()
            relativeCheckedPCs = finding.checkedPCs.map { $0 - finding.function.address }
            evidence = finding.evidence.map {
                EvidenceSignature(
                    code: $0.code, expected: $0.expected, observed: $0.observed,
                    relativeAddress: $0.address.map { $0 - finding.function.address }
                )
            }
        }
    }
}
