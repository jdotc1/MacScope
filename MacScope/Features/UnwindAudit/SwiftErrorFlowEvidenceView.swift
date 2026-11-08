import Foundation
import SwiftUI
import LumenTokens
import LumenUI

/// Additive evidence review. The existing audit, saved evidence, and commands
/// are untouched. There is no automatic analysis, persistence or mutation.
struct SwiftErrorFlowEvidenceView: View {
    @ObservedObject var store: WorkspaceStore
    @StateObject private var coordinator = SwiftErrorFlowCoordinator()
    private var key: SwiftErrorFlowSourceKey? { store.swiftErrorFlowKey(in: store.focusedImageSlot) }
    private var isCurrent: Bool { key != nil && key == coordinator.state.key }

    var body: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s4) {
            HStack {
                Text("Swift Error-Flow Evidence").font(.headline)
                Spacer()
                if isCurrent && coordinator.state.phase == .running {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { coordinator.cancel() }
                } else {
                    Button("Analyze Swift Error Flow") {
                        store.startSwiftErrorFlow(in: store.focusedImageSlot, coordinator: coordinator)
                    }.disabled(key == nil)
                }
            }
            Text("Bounded raw arm64 evidence: direct call followed by an admitted x21 test. This is separate from unwind metadata and does not reconstruct Swift source or prove runtime reachability.")
                .font(.caption).foregroundStyle(.secondary)
            if isCurrent { status }
            else {
                Text(key == nil
                     ? "A verified retained arm64 ALL slice is required. arm64e and incomplete inputs are not admitted."
                     : "Analyze this captured image explicitly. No result from another image or generation is shown.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Read-only and session-local. No document mutation, accepted-evidence record, Python runtime, external tool, or background analysis is created. Cancel retires publication; bounded work may finish before stopping.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .onChange(of: key, initial: true) { _, value in coordinator.activate(value) }
        .onDisappear { coordinator.cancel() }
    }

    @ViewBuilder
    private var status: some View {
        switch coordinator.state.phase {
        case .idle: Text("Ready for explicit analysis.").foregroundStyle(.secondary)
        case .running: Text("Analyzing retained slice bytes…").foregroundStyle(.secondary)
        case .cancelled: Text("Analysis cancelled. Run again to produce a result.").foregroundStyle(.secondary)
        case .failed(let message): Text(message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
        case .completed:
            if let report = coordinator.state.report {
                Text("\(report.status.rawValue) · \(report.edges.count) structural edges · \(report.declarations.count) admitted declarations · \(report.model)")
                    .font(.caption).textSelection(.enabled)
                Text("Slice SHA-256: \(report.slice.artifactSHA256) · \(report.slice.sliceByteCount) bytes")
                    .font(.caption).textSelection(.enabled)
                if report.edges.isEmpty {
                    Text("No edge was established by this bounded model. This is not evidence that the image has no throwing code.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(Array(report.edges.prefix(100).enumerated()), id: \.offset) { _, edge in
                    DisclosureGroup {
                        Text("Raw symbol: \(edge.symbol)").font(.caption).textSelection(.enabled)
                        Text("Call \(hex(edge.callAddress)) → callee \(hex(edge.calleeAddress))\nTest \(hex(edge.testAddress)) (\(edge.testKind))\nZero/error-clear edge \(hex(edge.successAddress)) · nonzero/error edge \(hex(edge.errorAddress))\nCaller-relative offsets: call \(hex(edge.callOffset)), test \(hex(edge.testOffset)), clear \(hex(edge.successOffset)), error \(hex(edge.errorOffset))")
                            .font(.caption).textSelection(.enabled)
                        if let comparison = edge.comparisonAddress {
                            Text("Comparison \(hex(comparison))").font(.caption).textSelection(.enabled)
                        }
                        Text("Raw instruction words: " + edge.evidenceWords.map { String(format: "%08x", $0) }.joined(separator: " "))
                            .font(.caption).textSelection(.enabled)
                        Button("Show Source Location") {
                            _ = store.navigateFromSwiftErrorFlow(edge, coordinator: coordinator)
                        }.disabled(!isCurrent)
                        Text("Source location means the retained binary instruction, not recovered source code.")
                            .font(.caption).foregroundStyle(.secondary)
                    } label: {
                        Text("\(hex(edge.callAddress)) · \(edge.testKind) · structural evidence only").font(.caption)
                    }
                }
                if report.edges.count > 100 {
                    Text("Showing the first 100 of \(report.edges.count) edges; the complete bounded report remains in this session.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !report.abstentions.isEmpty {
                    DisclosureGroup("Abstentions (\(report.abstentions.count))") {
                        Text(report.abstentions.prefix(100).map {
                            $0.code + ($0.address.map { " @ " + hex($0) } ?? "")
                        }.joined(separator: "\n")).font(.caption).textSelection(.enabled)
                        if report.abstentions.count > 100 {
                            Text("Only the first 100 abstentions are shown.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func hex(_ value: UInt64) -> String { "0x" + String(value, radix: 16) }
}
