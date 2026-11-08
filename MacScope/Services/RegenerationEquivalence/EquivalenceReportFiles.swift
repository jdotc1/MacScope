import Foundation

enum EquivalenceReportOutputError: Error { case invalidLimit, exceedsLimit }

enum EquivalenceReportFiles {
    /// The caller publishes this complete relative file set through the RG1 transactional writer.
    static func make(_ report: EquivalenceServiceReport, budget: RegenerationWorkBudget) throws -> [String: Data] {
        let maximumBytes = budget.maximumOutputBytes
        try budget.checkpoint()
        var remaining = maximumBytes
        var observations = 0
        func charge(_ value: String) throws {
            try budget.checkpoint()
            observations += 1
            guard observations <= budget.maximumRecords else { throw EquivalenceReportOutputError.exceedsLimit }
            let (expanded, overflow) = value.utf8.count.multipliedReportingOverflow(by: 12)
            let (cost, overflow2) = expanded.addingReportingOverflow(512)
            guard !overflow, !overflow2, cost <= remaining else { throw EquivalenceReportOutputError.exceedsLimit }
            remaining -= cost
        }
        func chargeRecord(_ record: StructuralRecord) throws { try charge(record.key); if let v = record.value { try charge(v) } }
        try charge(report.originalIdentity.selectedSliceSHA256); try charge(report.rebuiltIdentity.selectedSliceSHA256)
        for d in report.structure.dimensions {
            try charge(d.name); try charge(d.status)
            for r in d.unassessedOriginal + d.unassessedRebuilt { try chargeRecord(r) }
            if let c = d.comparison {
                for r in c.matched + c.missing + c.extra { try chargeRecord(r) }
                for r in c.differing { try charge(r.key); try charge(r.original); try charge(r.rebuilt) }
                for r in c.unassessed {
                    try charge(r.key); try charge(r.reason)
                    for item in r.original + r.rebuilt { try chargeRecord(item) }
                }
            }
        }
        for state in report.functionStates {
            for value in [state.originalFunctionUUID, state.originalFunctionID ?? "", state.state,
                          state.declaredAddress, state.declaredEndAddressExclusive, state.bindingStatus,
                          state.rebuiltFunctionID ?? "", state.pairingStatus, state.authority, state.dependencyId ?? ""] { try charge(value) }
        }
        for limit in report.limitations { try charge(limit) }
        for _ in report.originalFunctionSizes { try charge("") }
        for _ in report.rebuiltFunctionSizes ?? [] { try charge("") }
        if let pairing = report.functionPairing {
            for value in pairing.assessedEvidence + pairing.unassessedEvidence { try charge(value) }
            for match in pairing.matches { try charge(match.oldID); try charge(match.newID) }
            for id in pairing.removedIDs + pairing.addedIDs { try charge(id) }
            for group in pairing.unresolved { for id in group.oldIDs + group.newIDs { try charge(id) } }
            for _ in pairing.originalSizes + pairing.rebuiltSizes { try charge("") }
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        let json = try encoder.encode(report) + Data([10])
        func safe(_ value: String) -> String { StructuralMarkdown.escape(value) }
        var md = StructuralReportBuilder.markdown(report.structure)
        md += "\n## Function pairing\n\n"
        md += "This is evidence of pairing, not proof of behavioral equivalence.\n\n"
        md += "Original functions: \(report.originalFunctionSizes.count); rebuilt functions: \(report.rebuiltFunctionSizes.map { String($0.count) } ?? "unassessed"); pairing: \(safe(report.functionPairingStatus)).\n\n"
        if let pairing = report.functionPairing {
            for value in pairing.assessedEvidence { md += "- Assessed: \(safe(value))\n" }
            for value in pairing.unassessedEvidence { md += "- Unassessed: \(safe(value))\n" }
            for match in pairing.matches {
                let differences = match.differences.isEmpty ? "none among assessed size facts; code change unassessed" : match.differences.map(\.rawValue).joined(separator: ", ")
                md += "- \(safe(match.oldID)) → \(safe(match.newID)); basis \(match.basis.rawValue); confidence \(match.confidence.rawValue); differences \(differences).\n"
            }
            for id in pairing.removedIDs { md += "- Unpaired original: \(safe(id)).\n" }
            for id in pairing.addedIDs { md += "- Unpaired rebuilt: \(safe(id)).\n" }
            for group in pairing.unresolved {
                md += "- Unresolved original [\(group.oldIDs.map(safe).joined(separator: ", "))]; rebuilt [\(group.newIDs.map(safe).joined(separator: ", "))]; basis \(group.bases.map(\.rawValue).joined(separator: ", ")).\n"
            }
        }
        if !report.functionStates.isEmpty {
            md += "\n## Original manifest declarations\n\n"
            md += "States below are caller declarations. Even compiles or accepted is not verified compilation or acceptance evidence, and no rebuilt state is inferred. External states and dependency IDs are declarations only; no function ownership or exclusion is applied.\n\n"
            for state in report.functionStates {
                let binding = state.originalFunctionID.map { " [analysis " + safe($0) + "]" } ?? " [unbound]"
                let rebuilt = state.rebuiltFunctionID.map { safe($0) } ?? "unassessed or unpaired"
                md += "- \(safe(state.originalFunctionUUID))\(binding): declared state \(safe(state.state)); extent \(safe(state.declaredAddress)) to \(safe(state.declaredEndAddressExclusive)); binding \(safe(state.bindingStatus)); rebuilt association \(rebuilt) (\(safe(state.pairingStatus))); authority \(safe(state.authority)); declared dependency \(state.dependencyId.map { safe($0) } ?? "unspecified"); exclusion applied: \(state.exclusionApplied == false ? "no" : "unassessed").\n"
            }
        }
        md += "\n## Limitations\n\n"
        for limit in report.limitations { md += "- \(safe(limit))\n" }
        try budget.checkpoint()
        let markdown = Data(md.utf8)
        guard json.count <= maximumBytes, markdown.count <= maximumBytes - json.count else {
            throw EquivalenceReportOutputError.exceedsLimit
        }
        return ["Equivalence/STRUCTURE-REPORT.json": json,
                "Equivalence/STRUCTURE-REPORT.md": markdown]
    }
}
