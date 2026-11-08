import SwiftUI
import NEWFEATURESCore

/// Find Call Path sheet. All behaviour lives in `NEWFEATURESCallPathPresentation`, which the
/// window owns; this view only binds fields, forwards actions and renders the model's state.
struct NEWFEATURESCallPathSheet: View {
    @Bindable var model: NEWFEATURESCallPathPresentation
    @ObservedObject var store: WorkspaceStore
    @ObservedObject var documentSession: WorkspaceDocumentSession
    @Environment(\.dismiss) private var dismiss

    private func refresh() {
        model.refresh(NEWFEATURESCallPathViewContext.read(store: store, session: documentSession))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Find Call Path").font(.headline)
            Text("Searches verified direct calls between two function addresses in the focused image.")
                .font(.caption).foregroundStyle(.secondary)

            HStack {
                TextField("Source address (hex)", text: $model.sourceText)
                    .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
                Button("Use Selection") { model.useSelection(asDestination: false) }
                    .disabled(model.isBusy)
            }
            HStack {
                TextField("Destination address (hex)", text: $model.destinationText)
                    .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
                Button("Use Selection") { model.useSelection(asDestination: true) }
                    .disabled(model.isBusy)
            }

            HStack(spacing: 20) {
                Stepper("Maximum depth: \(model.maximumDepth)", value: $model.maximumDepth, in: 1...16)
                Stepper("Maximum functions: \(model.maximumFunctions)", value: $model.maximumFunctions, in: 2...500)
            }
            .disabled(model.isBusy)

            HStack {
                Button("Find") { model.start() }
                    .disabled(model.isBusy)
                    .keyboardShortcut(.defaultAction)
                Button("Cancel") { model.cancel() }
                    .disabled(!model.isBusy)
                if model.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }

            if let message = Self.message(for: model.phase) {
                Text(message).font(.callout).foregroundStyle(.secondary)
            }

            if let summary = model.summary {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Status: \(Self.statusText(summary.status))")
                    Text("Visited functions: \(summary.visitedFunctions), edges: \(summary.visitedEdges)")
                    Text("Unresolved call observations: \(summary.unresolvedObservations)")
                    Text("Examined unverified edges: \(summary.examinedUnverifiedEdges)")
                }
                .font(.caption)
            }

            if !model.rows.isEmpty {
                List(model.rows) { row in
                    Button {
                        model.select(row)
                    } label: {
                        Text("0x" + String(row.address, radix: 16))
                            .font(.system(.body, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                    .disabled(model.isBusy)
                }
                .frame(minHeight: 120)
            }
        }
        .padding(16)
        .frame(minWidth: 480, minHeight: 360)
        .onAppear { refresh() }
        .onChange(of: store.selectedImageAddress) { refresh() }
        .onChange(of: store.focusedImageSlot) { refresh() }
        .onDisappear { model.disappear() }
    }

    private static func message(for phase: NEWFEATURESCallPathPresentation.Phase) -> String? {
        switch phase {
        case .idle: return nil
        case .searching: return "Searching..."
        case .cancelling: return "Cancelling..."
        case .finished: return nil
        case .refused(let notice): return message(for: notice)
        }
    }

    private static func statusText(_ status: NEWFEATURESPathStatus) -> String {
        switch status {
        case .found: return "Path found"
        case .notFoundInObservedGraph: return "No path in the observed graph"
        case .functionLimit: return "Stopped at the function limit"
        case .depthLimit: return "Stopped at the depth limit"
        case .edgeVisitLimit: return "Stopped at the edge visit limit"
        case .cancelled: return "Cancelled"
        case .timedOut: return "Timed out"
        }
    }

    private static func message(for notice: NEWFEATURESCallPathPresentation.Notice) -> String {
        switch notice {
        case .invalidAddress: return "Enter source and destination as hexadecimal addresses."
        case .unavailable: return "Call path search is not available for this document right now."
        case .analysisRequired: return "The focused image has not finished analysis."
        case .identityUnavailable: return "The focused image has no verified identity yet."
        case .unsupportedArchitecture: return "Call path search does not support this architecture."
        case .ambiguousFunction: return "An address did not resolve to exactly one function."
        case .inputLimit: return "The depth or function limit is outside the allowed range."
        case .outputLimit: return "The result was too large to present."
        case .cancelled: return "The search was cancelled."
        case .timedOut: return "The search ran out of time."
        case .selectionChanged: return "The selection changed, so the search was stopped."
        case .sourceChanged: return "The focused image changed, so the result was discarded."
        case .hidden: return "The search was stopped when the sheet closed."
        }
    }
}
