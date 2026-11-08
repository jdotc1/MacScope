import SwiftUI

/// Saved evidence is report-only: no annotation transfer, navigation or analysis execution.
@MainActor
struct VersionCompareAIRSEvidenceView: View {
    @ObservedObject var store: WorkspaceStore
    @State private var model = VersionCompareAIRSEvidenceViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Saved AIRS evidence").font(.headline)
                Text("Compare two retained native audits. Imported single findings appear in the inventory with their original scope. Counts describe saved findings, not all functions in an image.")
                selectors
                if case .failed(let message) = model.phase {
                    Text("Evidence could not be compared: \(message)").foregroundStyle(.red)
                }
                if let error = model.pinError { Text("Pair could not be pinned: \(error)").foregroundStyle(.red) }
                if let comparison = model.comparison {
                    comparisonContent(comparison)
                }
                Divider()
                Text("Coverage inventory · \(store.airsEvidence.records.count) retained records").font(.headline)
                if model.inventory.entries.isEmpty, model.phase == .idle {
                    Text("No retained AIRS evidence. Run a native audit or retain an imported finding first.")
                }
                ForEach(displayedEntries) { entry in
                    VersionCompareAIRSEvidenceRecordView(entry: entry,
                        binding: store.airsEvidenceBinding(entry.record))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
        }
        .textSelection(.enabled)
        .onAppear { bind() }
        .onChange(of: store.airsEvidence) { _, _ in bind() }
        .onChange(of: store.workspaceID) { _, _ in bind() }
        .onChange(of: store.documentInstallationID) { _, _ in bind() }
        .onDisappear { model.cancel() }
    }

    private func bind() {
        model.bind(store.airsEvidence, workspaceID: store.workspaceID, installationID: store.documentInstallationID)
    }

    private var displayedEntries: [VersionCompareAIRSEvidenceEntry] {
        model.inventory.orderedEntries { store.airsEvidenceBinding($0).isResolved }
    }

    private var selectors: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Baseline", selection: Binding(get: { model.baselineID }, set: { model.selectBaseline($0) })) {
                Text("Select native audit").tag(Optional<UUID>.none)
                ForEach(model.inventory.nativeEntries) { entry in Text(entry.title).tag(Optional(entry.id)) }
            }
            Picker("Current", selection: Binding(get: { model.currentID }, set: { model.selectCurrent($0) })) {
                Text("Select native audit").tag(Optional<UUID>.none)
                ForEach(model.inventory.nativeEntries) { entry in Text(entry.title).tag(Optional(entry.id)) }
            }
            HStack {
                Button("Compare saved audits") { model.run() }
                    .disabled(!model.canCompare || model.phase == .running)
                if model.phase == .running {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { model.cancel() }
                }
            }
            Text("Recompare clears manual pins. The same record cannot occupy both sides.")
                .foregroundStyle(.secondary)
        }
    }

    private func comparisonContent(_ comparison: UnwindAuditComparison) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(comparison.modelCompatible && !comparison.configurationChanged ? "Saved audit comparison" : "Incompatible reports")
                .font(.headline)
            if !comparison.modelCompatible || comparison.configurationChanged {
                Text("Analysis model, raw CPU type/subtype or configuration differs. No change, regression or fix is inferred. The original observations and both coverage denominators remain below.")
            }
            if comparison.configurationChanged {
                Text("Analysis limits differ. Matched observations are incompatible until both audits use the same configuration.")
            }
            if let coverage = model.baseline?.coverage { Text("Baseline: \(coverage.description)") }
            if let coverage = model.current?.coverage { Text("Current: \(coverage.description)") }
            Text("\(comparison.matching.matches.count) matched pairs · \(comparison.matching.unresolved.count) unresolved groups · \(comparison.matching.removedIDs.count) baseline-only · \(comparison.matching.addedIDs.count) current-only")

            // Ambiguities precede accepted pairs. Pin candidates retain the existing resolver rules.
            ForEach(comparison.matching.unresolved, id: \.oldIDs) { group in
                VersionCompareAIRSPinView(oldIDs: group.oldIDs, newIDs: group.newIDs,
                    bases: group.bases.map(\.rawValue).joined(separator: ", "),
                    pin: { model.pin(oldID: $0, newID: $1) })
            }
            if !comparison.matching.removedIDs.isEmpty || !comparison.matching.addedIDs.isEmpty {
                VersionCompareAIRSPinView(oldIDs: comparison.matching.removedIDs,
                    newIDs: comparison.matching.addedIDs, bases: "Unmatched functions",
                    pin: { model.pin(oldID: $0, newID: $1) })
            }
            ForEach(model.orderedChanges, id: \.match.oldID) { change in
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(change.match.oldID) ↔ \(change.match.newID): \(change.change.rawValue)")
                        .fontWeight(.semibold)
                    Text("\(change.beforeVerdict) / \(change.beforeScope) → \(change.afterVerdict) / \(change.afterScope)")
                    Text("Match: \(change.match.basis.rawValue) · confidence \(String(describing: change.match.confidence))")
                    Text("Code differences: \(change.match.differences.map(\.rawValue).joined(separator: ", "))")
                    ForEach(change.notes, id: \.self) { Text($0) }
                }
            }
            ForEach(comparison.limitations, id: \.self) { Text($0).foregroundStyle(.secondary) }
        }
    }
}

private struct VersionCompareAIRSPinView: View {
    let oldIDs: [String]
    let newIDs: [String]
    let bases: String
    let pin: (String, String) -> Void
    @State private var oldID: String?
    @State private var newID: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Unresolved matching · \(bases)").fontWeight(.semibold)
            Text("Baseline: \(oldIDs.joined(separator: ", "))")
            Text("Current: \(newIDs.joined(separator: ", "))")
            HStack {
                Picker("Baseline function", selection: $oldID) {
                    Text("Select").tag(Optional<String>.none)
                    ForEach(oldIDs, id: \.self) { Text($0).tag(Optional($0)) }
                }
                Picker("Current function", selection: $newID) {
                    Text("Select").tag(Optional<String>.none)
                    ForEach(newIDs, id: \.self) { Text($0).tag(Optional($0)) }
                }
                Button("Pin pair") {
                    if let oldID, let newID { pin(oldID, newID) }
                }
                .disabled(!oldIDs.contains(oldID ?? "") || !newIDs.contains(newID ?? ""))
            }
        }
    }
}

private struct VersionCompareAIRSEvidenceRecordView: View {
    let entry: VersionCompareAIRSEvidenceEntry
    let binding: AIRSEvidenceBinding

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 8) {
                Text("Record \(entry.id.uuidString) · workspace \(entry.record.workspaceID.uuidString)")
                Text("Source image \(entry.record.sourceImageID?.uuidString ?? "unavailable") · request \(entry.record.nativeRequestID?.uuidString ?? "unavailable")")
                if let report = entry.report {
                    Text("Mach-O UUID \(report.identity.uuid?.uuidString ?? "unavailable") · architecture \(report.identity.architectureVariant.rawValue)")
                    Text("Slice \(report.identity.selectedSliceSHA256) · \(report.identity.selectedSliceByteCount) bytes")
                    Text("CPU \(report.identity.rawCPUType) / \(report.identity.rawCPUSubtype) · model \(report.analysisModelVersion)")
                    Text("Limits: \(report.configuration.maxInstructions) instructions, \(report.configuration.maxSteps) steps, \(report.configuration.maxPaths) paths, \(report.configuration.maxObservations) observations, \(report.configuration.maxEvidence) evidence items")
                    ForEach(entry.orderedFindings, id: \.function.id) { finding in
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(finding.function.id) · 0x\(String(finding.function.address, radix: 16)): \(finding.verdict) · \(finding.coverage) · \(finding.mode) · \(finding.scope)")
                            Text("Reasons: \(finding.reasonCodes.joined(separator: ", "))")
                            Text("Checked PCs: \(finding.checkedPCs.map { "0x" + String($0, radix: 16) }.joined(separator: ", "))")
                            Text(finding.evidence.map { evidence in
                                let address = evidence.address.map { " @ 0x" + String($0, radix: 16) } ?? ""
                                return "\(evidence.code)\(address): \(evidence.message)\nExpected: \(evidence.expected ?? "unavailable") · observed: \(evidence.observed ?? "unavailable")"
                            }.joined(separator: "\n"))
                            Text(finding.limitations.joined(separator: "\n"))
                        }
                    }
                } else {
                    Text("Imported single finding; excluded from native report pairing and native report denominators.")
                    Text(entry.importedSummary ?? "")
                    Text(String(data: entry.record.rawPayload, encoding: .utf8) ?? "Source text unavailable")
                }
            }
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.title)
                Text(binding.unresolvedReason.map { "UNRESOLVED binding: " + $0 } ?? "Source image binding resolved")
                Text(entry.coverage?.description ?? "One imported observation; native-report coverage unavailable.")
            }
        }
    }
}
