import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// AppKit owns only the auxiliary window lifecycle; the report surface is SwiftUI.
@MainActor
final class CrashReportWindowPresenter: NSObject, NSWindowDelegate {
    static let shared = CrashReportWindowPresenter()
    private var windows: [ObjectIdentifier: NSWindow] = [:]
    private var namingModels: [ObjectIdentifier: CrashFrameNamingModel] = [:]

    func presentPanel(store: WorkspaceStore?) {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "ips") ?? .json]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a macOS crash report (.ips). The report is opened read only."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        open(url, store: store)
    }

    func open(_ url: URL, store: WorkspaceStore?) {
        let candidates = store.map { store in
            store.snapshot.binaries.compactMap { binary in
                Self.context(in: store, slot: binary.slot).map { (binary, $0) }
            }
        } ?? []
        let contexts = candidates.map { $0.1 }
        Task { [weak self, weak store] in
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let report = try await Task.detached(priority: .userInitiated) {
                    let file = try FileHandle(forReadingFrom: url)
                    defer { try? file.close() }
                    let data = try file.read(upToCount: 16 * 1024 * 1024 + 1) ?? Data()
                    return try CrashReport.parse(data)
                }.value
                guard let self else { return }
                let navigate: (Int, UInt64) -> Bool = { [weak store] index, address in
                    guard let store, candidates.indices.contains(index) else { return false }
                    return Self.navigate(address, binary: candidates[index].0, in: store)
                }
                let naming = CrashFrameNamingModel()
                let content = CrashReportView(report: report, context: nil,
                    imageName: nil, onNavigate: { _ in false }, imageContexts: contexts,
                    onNavigateImage: navigate, naming: naming)
                if let frame = report.threads.first(where: { $0.triggered })?.frames.first {
                    let match = report.match(frame, contexts: contexts)
                    if let index = match.contextIndex, let address = match.resolved.address {
                        _ = navigate(index, address)
                    }
                }
                let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 620),
                                      styleMask: [.titled, .closable, .miniaturizable, .resizable],
                                      backing: .buffered, defer: false)
                window.title = "\(url.lastPathComponent) — Crash Report"
                window.isReleasedWhenClosed = false
                window.contentView = NSHostingView(rootView: content.dsPaletteRoot())
                window.delegate = self
                self.windows[ObjectIdentifier(window)] = window
                self.namingModels[ObjectIdentifier(window)] = naming
                naming.start(report: report)
                window.center()
                window.makeKeyAndOrderFront(nil)
            } catch {
                let alert = NSAlert()
                alert.messageText = "Couldn’t Open Crash Report"
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        windows.removeValue(forKey: ObjectIdentifier(window))
        namingModels.removeValue(forKey: ObjectIdentifier(window))?.cancel()
    }

    /// Rechecks the captured owner before focusing another image or changing selection.
    static func navigate(_ address: UInt64, binary: BinaryImage, in store: WorkspaceStore) -> Bool {
        guard let current = store.snapshot.binary(in: binary.slot),
              current.id == binary.id, current.artifactIdentity == binary.artifactIdentity,
              current.metadata.uuid == binary.metadata.uuid,
              let analysis = store.snapshot.analysis(in: binary.slot),
              analysis.instructions.contains(where: { $0.address == address }),
              analysis.functions.filter({ $0.startAddress <= address && address < $0.endAddress }).count == 1,
              store.snapshot.containsLoadedAddress(address, in: binary.slot)
        else { return false }
        store.focusImage(binary.slot)
        store.editorMode = .pseudocode
        return store.selectAddress(ImageAddress(slot: binary.slot, address: address))
    }

    static func context(in store: WorkspaceStore, slot: ImageSlot? = nil) -> CrashReportImageContext? {
        guard let binary = store.snapshot.binary(in: slot ?? store.focusedImageSlot),
              let uuid = binary.metadata.uuid,
              let layout = binary.preferredSegmentLayout,
              let analysis = store.snapshot.analysis(in: binary.slot) else { return nil }
        // The Mach-O header's file-backed mapping is the preferred image base. PAGEZERO
        // is not a mapping and cannot supply a slide or a navigable range.
        let bases = layout.records.filter { $0.sliceRelativeFileOffset == 0 && $0.fileSize > 0 && $0.initialProtections != 0 }
        guard bases.count == 1, let base = bases.first?.preferredVMStart else { return nil }
        let ranges = layout.records.compactMap { record -> Range<UInt64>? in
            let (end, overflow) = record.preferredVMStart.addingReportingOverflow(record.preferredVMSize)
            guard record.initialProtections != 0, !overflow, end > record.preferredVMStart else { return nil }
            return record.preferredVMStart..<end
        }
        let functions = analysis.functions.map {
            CrashReportSymbol(name: $0.name, address: $0.startAddress, endAddress: $0.endAddress)
        }
        let symbols = analysis.symbols.compactMap { symbol -> CrashReportSymbol? in
            guard let address = symbol.address else { return nil }
            return CrashReportSymbol(name: symbol.name, address: address, endAddress: nil)
        }
        return CrashReportImageContext(uuid: uuid, preferredBase: base, mappedRanges: ranges, symbols: functions + symbols)
    }
}
