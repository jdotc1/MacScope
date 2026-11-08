import SwiftUI
import LumenTokens
import LumenUI

/// An immutable report with session-local thread selection; no crash data enters the workspace.
struct CrashReportView: View {
    let report: CrashReport
    let context: CrashReportImageContext?
    let imageName: String?
    let onNavigate: (UInt64) -> Bool
    var rendersOffscreen = false
    var imageContexts: [CrashReportImageContext]? = nil
    var onNavigateImage: ((Int, UInt64) -> Bool)? = nil
    var naming: CrashFrameNamingModel? = nil
    @State private var selectedThreadID: Int?
    @State private var navigationMessage: String?

    private var selectedThread: CrashReportThread? {
        report.threads.first { $0.id == selectedThreadID }
            ?? report.threads.first { $0.triggered }
            ?? report.threads.first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s5) {
            VStack(alignment: .leading, spacing: Lumen.Space.s2) {
                HStack {
                    Text(report.processName).font(.title2.weight(.semibold))
                    Spacer()
                    LumenBadge("Read only", systemImage: "doc.text")
                }
                Text(report.exceptionSummary).font(.body).textSelection(.enabled)
                Text(imageContexts.map { "\($0.count) loaded images · UUID-matched frames open pseudocode" } ?? imageName.map { "Open image: \($0) · UUID-matched frames can navigate" }
                     ?? "Open this report from an image workspace to resolve its frames.")
                    .font(AppTypography.metadata).foregroundStyle(.secondary)
            }
            if let naming { CrashFrameNamingNote(model: naming) }
            Divider()
            if rendersOffscreen {
                threadButtons
            } else {
                ScrollView(.horizontal) { threadButtons }
            }
            if let thread = selectedThread {
                CrashReportRegistersView(thread: thread, rendersOffscreen: rendersOffscreen)
                HStack {
                    Text(thread.name ?? "Thread \(thread.id)").font(.body.weight(.semibold))
                    if thread.triggered { Text("Crashed").foregroundStyle(Color.lumen(.statusDanger)) }
                    Spacer()
                    Text("\(thread.frames.count) frames").foregroundStyle(.secondary)
                }
                if rendersOffscreen {
                    VStack(alignment: .leading, spacing: Lumen.Space.s3) {
                        frameRows(thread)
                    }
                    Spacer(minLength: 0)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: Lumen.Space.s3) {
                            frameRows(thread)
                        }
                    }
                }
            } else {
                Text("No thread frames were recorded.").foregroundStyle(.secondary)
                Spacer()
            }
            if let navigationMessage {
                Text(navigationMessage).font(.caption).foregroundStyle(Color.lumen(.statusWarning))
            }
        }
        .padding(Lumen.Space.s6)
        .workbenchPaneBackground(.debugger)
        .frame(minWidth: AppLayout.crashReportMinimumWidth, minHeight: AppLayout.crashReportMinimumHeight)
    }

    private var threadButtons: some View {
        HStack(spacing: Lumen.Space.s3) {
            ForEach(report.threads) { thread in
                Button {
                    selectedThreadID = thread.id
                    navigationMessage = nil
                } label: {
                    HStack(spacing: Lumen.Space.s2) {
                        if thread.triggered { Image(systemName: "exclamationmark.circle.fill") }
                        Text("Thread \(thread.id)")
                    }
                    .padding(.horizontal, Lumen.Space.s4)
                    .padding(.vertical, Lumen.Space.s3)
                    .background(thread.id == selectedThread?.id ? Color.lumen(.bgSelected) : Color.clear,
                                in: RoundedRectangle(cornerRadius: Lumen.Radius.sm))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func frameRows(_ thread: CrashReportThread) -> some View {
        ForEach(thread.frames) { frame in
            CrashReportFrameRow(frame: frame, threadID: thread.id, report: report, context: context, imageContexts: imageContexts, naming: naming) { index, address in
                let accepted = index.flatMap { onNavigateImage?($0, address) } ?? onNavigate(address)
                navigationMessage = accepted ? nil : "No instruction or containing function is available, or the loaded image changed. Load and analyze the matching binary, then reopen the report."
            }
        }
    }
}

private struct CrashReportFrameRow: View {
    let frame: CrashReportFrame
    let threadID: Int
    let report: CrashReport
    let context: CrashReportImageContext?
    let imageContexts: [CrashReportImageContext]?
    let naming: CrashFrameNamingModel?
    let onNavigate: (Int?, UInt64) -> Void

    var body: some View {
        let match = imageContexts.map { report.match(frame, contexts: $0) }
        let resolved = match?.resolved ?? report.resolve(frame, against: context)
        let image = frame.imageIndex.flatMap { report.images.indices.contains($0) ? report.images[$0].name : nil }
        Button {
            if let address = resolved.address { onNavigate(match?.contextIndex, address) }
        } label: {
            HStack(alignment: .top, spacing: Lumen.Space.s4) {
                Text("\(frame.id)").monospacedDigit().foregroundStyle(.secondary).frame(width: AppLayout.crashReportFrameNumberWidth, alignment: .trailing)
                VStack(alignment: .leading, spacing: Lumen.Space.s2) {
                    Text(resolved.symbol ?? frame.reportedSymbol ?? "Unresolved frame")
                        .font(.system(.body, design: .monospaced))
                    HStack(spacing: Lumen.Space.s3) {
                        Text(image ?? "Unknown image")
                        if let offset = frame.imageOffset { Text("+ \(offset.hexAddress)").monospaced() }
                        if resolved.symbol == nil, frame.reportedSymbol != nil { Text("Reported symbol") }
                    }
                    .font(AppTypography.metadata).foregroundStyle(.secondary)
                    if let runtime = report.runtimeAddress(of: frame) {
                        Text("Crash address: \(runtime.hexAddress)").font(AppTypography.metadata).monospaced().foregroundStyle(.secondary)
                    }
                    if let index = frame.imageIndex, report.images.indices.contains(index), let uuid = report.images[index].uuid {
                        Text("UUID: \(uuid)").font(AppTypography.metadata).textSelection(.enabled).foregroundStyle(.secondary)
                    }
                    if let naming {
                        CrashFrameNameLine(model: naming, key: .init(threadID: threadID, frameID: frame.id),
                                           reportedSymbol: frame.reportedSymbol)
                    }
                    if let diagnostic = resolved.diagnostic {
                        Text(diagnostic).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: Lumen.Space.s3)
                if let address = resolved.address {
                    Text(address.hexAddress).monospaced().foregroundStyle(Color.accentColor)
                    Image(systemName: "arrow.up.right")
                }
            }
            .padding(Lumen.Space.s4)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.lumen(.bgInset), in: RoundedRectangle(cornerRadius: Lumen.Radius.sm))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(resolved.address == nil)
    }
}

private struct CrashFrameNamingNote: View {
    @ObservedObject var model: CrashFrameNamingModel
    var body: some View {
        if let note = model.note {
            Text(note).font(AppTypography.metadata).foregroundStyle(.secondary)
        }
    }
}

private struct CrashFrameNameLine: View {
    @ObservedObject var model: CrashFrameNamingModel
    let key: CrashFrameNamingModel.Key
    let reportedSymbol: String?
    var body: some View {
        if let outcome = model.outcomes[key],
           let display = CrashFrameNameDisplay.make(outcome: outcome, reportedSymbol: reportedSymbol) {
            Text(display.text).font(AppTypography.metadata).foregroundStyle(.secondary).textSelection(.enabled)
        }
    }
}

private struct CrashReportRegistersView: View {
    let thread: CrashReportThread
    let rendersOffscreen: Bool
    @State private var isExpanded = true

    var body: some View {
        DisclosureGroup("Registers at termination · \(thread.registerFlavor ?? "state not reported")", isExpanded: $isExpanded) {
            if thread.registers.isEmpty {
                Text("This thread has no recorded register values.").foregroundStyle(.secondary)
            } else {
                Text("Thread \(thread.id) state at termination; older frames do not have separate register snapshots.")
                    .font(AppTypography.metadata).foregroundStyle(.secondary)
                if rendersOffscreen {
                    VStack(alignment: .leading) {
                        ForEach(thread.registers) { register in
                            Text("\(register.name)  \(register.value.hexAddress)").monospaced()
                        }
                    }
                } else {
                    ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), alignment: .leading)], alignment: .leading) {
                        ForEach(thread.registers) { register in
                            Text("\(register.name)  \(register.value.hexAddress)").monospaced().textSelection(.enabled)
                        }
                    }
                    }.frame(maxHeight: 150)
                }
            }
        }
    }
}
