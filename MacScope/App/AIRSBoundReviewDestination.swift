import AppKit
import Foundation
import UniformTypeIdentifiers

/// One admitted, session-local destination. Equality includes the full captured
/// container witness so a changed focused image cannot reuse a confirmation.
struct AIRSBoundReviewDestination: Equatable {
    let imageID: UUID
    let slot: ImageSlot
    let identity: MachOSliceArtifactIdentity
    let witness: MachOContainerAdmissionWitness
    let preferredBase: UInt64
    let address: UInt64

    init(binary: BinaryImage, identity: MachOSliceArtifactIdentity,
         witness: MachOContainerAdmissionWitness, preferredBase: UInt64, address: UInt64) {
        imageID = binary.id
        slot = binary.slot
        self.identity = identity
        self.witness = witness
        self.preferredBase = preferredBase
        self.address = address
    }

    var wire: Phase2ProductionJSONValue {
        .object([
            "image_id": .string(imageID.uuidString.lowercased()),
            "uuid": identity.uuid.map { .string($0.uuidString.lowercased()) } ?? .null,
            "architecture": .string(identity.architectureVariant.rawValue),
            "cpu_subtype": .number(String(UInt32(bitPattern: identity.rawCPUSubtype))),
            "container_sha256": .string(witness.containerSHA256),
            "slice_sha256": .string(identity.selectedSliceSHA256),
            "slice_offset": .number(String(witness.sliceOffset)),
            "slice_size": .number(String(witness.sliceSize)),
            "preferred_base": .string("0x" + String(preferredBase, radix: 16))
        ])
    }
}

@MainActor
struct AIRSBoundReviewTerminalSession {
    enum Action { case navigate, cancel }

    let request: AIRSBoundReviewImport
    let destination: AIRSBoundReviewDestination

    init(request: AIRSBoundReviewImport, focusedBinary: BinaryImage) throws {
        self.request = request
        destination = try request.destination(binary: focusedBinary)
    }

    /// This is the terminal core. The caller presents source evidence and a
    /// confirmation choice; no menu, callback, or GUI claim is made here.
    func finish(_ action: Action, store: WorkspaceStore) throws -> AIRSBoundReviewReceipt {
        guard let focused = store.focusedBinary,
              focused.id == destination.imageID,
              (try? request.destination(binary: focused)) == destination else {
            return try AIRSBoundReviewReceipt.rejected(
                .staleDestination, request: request,
                diagnostic: "The focused destination changed after confirmation.")
        }
        switch action {
        case .cancel:
            return try AIRSBoundReviewReceipt.cancelled(request: request, destination: destination)
        case .navigate:
            guard store.selectAddress(ImageAddress(slot: destination.slot, address: destination.address)),
                  let selected = store.selectedImageAddress,
                  let selectedImage = store.focusedBinary,
                  selectedImage.id == destination.imageID,
                  selected.slot == destination.slot,
                  selected.address == destination.address else {
                return try AIRSBoundReviewReceipt.navigationFailed(
                    request: request, destination: destination)
            }
            return try AIRSBoundReviewReceipt.navigated(
                request: request, destination: destination,
                selectedImageID: selectedImage.id, selectedAddress: selected.address)
        }
    }
}

@MainActor
enum AIRSBoundReviewTerminalAdmission {
    case ready(AIRSBoundReviewTerminalSession)
    case finished(AIRSBoundReviewReceipt)

    static func read(fileURL: URL, focusedBinary: BinaryImage?) throws -> Self {
        try admit({ try AIRSBoundReviewImport.read(from: fileURL) }, focusedBinary: focusedBinary)
    }

    static func parse(_ bytes: Data, focusedBinary: BinaryImage?) throws -> Self {
        try admit({ try AIRSBoundReviewImport.parse(bytes) }, focusedBinary: focusedBinary)
    }

    private static func admit(_ readRequest: () throws -> AIRSBoundReviewImport,
                              focusedBinary: BinaryImage?) throws -> Self {
        let request: AIRSBoundReviewImport
        do { request = try readRequest() }
        catch let failure as AIRSBoundReviewImport.Failure {
            return .finished(try AIRSBoundReviewReceipt.rejected(
                failure, diagnostic: failure.errorDescription ?? "Bound review admission failed."))
        }
        guard let focusedBinary else {
            return .finished(try AIRSBoundReviewReceipt.rejected(
                .identityUnavailable, request: request,
                diagnostic: "No focused image has verified container authority."))
        }
        do { return .ready(try AIRSBoundReviewTerminalSession(
            request: request, focusedBinary: focusedBinary)) }
        catch let failure as AIRSBoundReviewImport.Failure {
            return .finished(try AIRSBoundReviewReceipt.rejected(
                failure, request: request,
                diagnostic: failure.errorDescription ?? "Destination admission failed."))
        }
    }
}


/// A modal may pump the run loop while this store installs a different document.
/// Image equality alone is insufficient: a fork can preserve the same image ID.
@MainActor
struct AIRSBoundReviewDocumentGeneration {
    private let storeID: ObjectIdentifier
    private let workspaceID: UUID
    private let installationID: UUID

    init(store: WorkspaceStore) {
        storeID = ObjectIdentifier(store)
        workspaceID = store.workspaceID
        installationID = store.documentInstallationID
    }

    func matches(_ store: WorkspaceStore) -> Bool {
        ObjectIdentifier(store) == storeID
            && store.workspaceID == workspaceID
            && store.documentInstallationID == installationID
    }
}

/// One presentation produces one terminal receipt. Saving/retrying that receipt
/// is separate from finishing the navigation attempt and can never replay it.
@MainActor
final class AIRSBoundReviewPresentationAttempt {
    let session: AIRSBoundReviewTerminalSession
    private let generation: AIRSBoundReviewDocumentGeneration
    private var terminalReceipt: AIRSBoundReviewReceipt?

    init(session: AIRSBoundReviewTerminalSession, generation: AIRSBoundReviewDocumentGeneration) {
        self.session = session
        self.generation = generation
    }

    func finish(_ action: AIRSBoundReviewTerminalSession.Action,
                store: WorkspaceStore) throws -> AIRSBoundReviewReceipt {
        if let terminalReceipt { return terminalReceipt }
        let receipt: AIRSBoundReviewReceipt
        if generation.matches(store) {
            receipt = try session.finish(action, store: store)
        } else {
            receipt = try AIRSBoundReviewReceipt.rejected(
                .staleDestination, request: session.request,
                diagnostic: "The requesting workspace or document installation changed during presentation.")
        }
        terminalReceipt = receipt
        return receipt
    }
}

/// Explicit local UI over the existing bound receiver. No LaunchServices route,
/// background import, binary loading, manual-v1 fallback, or semantic promotion.
@MainActor
enum AIRSBoundReviewPresenter {
    private static var isPresenting = false

    static func presentPanel(store: WorkspaceStore?) {
        guard !isPresenting, let store else { return }
        isPresenting = true
        defer { isPresenting = false }
        // Capture before the file picker, not after the confirmation.
        let generation = AIRSBoundReviewDocumentGeneration(store: store)
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose an AIRS bound-review archive. Open and focus its image in MacScope separately. This command never loads an image from the archive."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        // Only consumer-owned paths are used for write protection. Neither a
        // report display name nor any embedded string becomes a filesystem URL.
        let focusedAtAdmission = store.focusedBinary
        var protectedInputs = [url]
        if let path = focusedAtAdmission?.path, path.hasPrefix("/") {
            protectedInputs.append(URL(fileURLWithPath: path))
        }
        do {
            let admission = try AIRSBoundReviewTerminalAdmission.read(
                fileURL: url, focusedBinary: focusedAtAdmission)
            let receipt: AIRSBoundReviewReceipt
            switch admission {
            case .finished(let terminal):
                receipt = terminal
            case .ready(let session):
                let attempt = AIRSBoundReviewPresentationAttempt(
                    session: session, generation: generation)
                // A replaced document must not receive a stale confirmation.
                let action: AIRSBoundReviewTerminalSession.Action = generation.matches(store)
                    ? confirm(session, imageName: focusedAtAdmission?.name ?? "Loaded image")
                    : .cancel
                receipt = try attempt.finish(action, store: store)
            }
            presentReceipt(receipt, protecting: protectedInputs)
        } catch {
            showFailure(title: "Couldn’t Complete AIRS Bound Review",
                message: error.localizedDescription
                    + "\nNo saved acknowledgment is claimed. A navigation outcome and receipt storage are separate.")
        }
    }

    private static func confirm(_ session: AIRSBoundReviewTerminalSession,
                                imageName: String) -> AIRSBoundReviewTerminalSession.Action {
        let request = session.request
        let finding = request.sourceReportedFinding
        let alert = NSAlert()
        alert.messageText = "Review AIRS Evidence Before Navigation"
        alert.informativeText =
            "Source \(finding.sourceName) \(finding.sourceVersion) · model \(finding.model)\n"
            + "\(finding.verdict) · \(finding.coverage) · \(finding.scope)\n"
            + (request.configurationRecorded
                ? "Configuration: recorded in the exact source report.\n"
                : "Configuration: NOT RECORDED; default limits must not be inferred.\n")
            + "Container and selected-slice identity are verified for the focused image. "
            + "Recovery semantics remain source-reported, not consumer-verified. "
            + "Navigate changes only MacScope's selection."
        let details =
            "Loaded image: \(imageName)\n"
            + "Finding: \(finding.name)\n"
            + "Finding ID: \(request.findingID)\n"
            + "Request ID: \(request.requestID.uuidString.lowercased())\n"
            + "Request SHA-256: \(request.requestSHA256)\n"
            + "Source report SHA-256: \(request.sourceDescriptor.sha256)\n"
            + "Source report bytes: \(request.sourceDescriptor.byteCount)\n"
            + "Selected finding only; the complete original source report remains in the chosen archive.\n"
            + "Container SHA-256: \(session.destination.witness.containerSHA256)\n"
            + "Selected slice SHA-256: \(session.destination.identity.selectedSliceSHA256)\n"
            + "Preferred VM range: 0x\(String(finding.start, radix: 16))–0x\(String(finding.end, radix: 16))\n\n"
            + "Validated request, including the full selected evidence, configuration, checked PCs, and limitations:\n\n"
            + (String(data: request.requestBytes, encoding: .utf8) ?? "Request text unavailable.")
        alert.accessoryView = textView(details)
        alert.addButton(withTitle: "Navigate")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn ? .navigate : .cancel
    }

    private static func presentReceipt(_ receipt: AIRSBoundReviewReceipt, protecting inputs: [URL]) {
        let wire = (try? JSONSerialization.jsonObject(with: receipt.bytes)) as? [String: Any]
        let outcome = wire?["outcome"] as? String ?? "unavailable"
        let code = wire?["code"] as? String ?? "unavailable"
        let diagnostic = wire?["diagnostic"] as? String ?? "Terminal details are shown below."
        let alert = NSAlert()
        alert.messageText = "AIRS Bound Review Terminal Result"
        alert.informativeText = "Result: \(outcome) · \(code)\n\(diagnostic)\n\n"
            + "The result below records this local attempt; it is not proof of recovery correctness. "
            + "No acknowledgment has been saved yet. Save is optional and will not repeat navigation."
        alert.accessoryView = textView(String(data: receipt.bytes, encoding: .utf8) ?? "Receipt text unavailable.")
        alert.addButton(withTitle: "Save Acknowledgment…")
        alert.addButton(withTitle: "Done")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        saveReceipt(receipt, protecting: inputs)
    }

    private static func saveReceipt(_ receipt: AIRSBoundReviewReceipt, protecting inputs: [URL]) {
        while true {
            let panel = NSSavePanel()
            panel.title = "Save AIRS Acknowledgment"
            panel.message = "Choose a new file. Existing files and source inputs are never overwritten, even if the system offers Replace."
            panel.allowedContentTypes = [.json]
            panel.canCreateDirectories = true
            panel.nameFieldStringValue = "airs-ack-\(receipt.id.uuidString.lowercased()).json"
            guard panel.runModal() == .OK, let url = panel.url else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                // Existing core publishes exclusively; a native Replace answer
                // does not weaken its O_EXCL/hard-link no-overwrite policy.
                try receipt.export(to: url, protecting: inputs)
                let saved = NSAlert()
                saved.messageText = "AIRS Acknowledgment Saved"
                saved.informativeText = "Saved to \(url.path).\nThis is a local terminal record, not a semantic attestation."
                saved.addButton(withTitle: "OK")
                saved.runModal()
                return
            } catch {
                let failed = NSAlert()
                failed.messageText = "Acknowledgment Was Not Saved"
                failed.informativeText = error.localizedDescription
                    + "\nThe terminal result is unchanged. Choose another name to retry the same receipt."
                failed.addButton(withTitle: "Choose Another Name…")
                failed.addButton(withTitle: "Done")
                guard failed.runModal() == .alertFirstButtonReturn else { return }
            }
        }
    }

    private static func textView(_ text: String) -> NSScrollView {
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 620, height: 320))
        let view = NSTextView(frame: scroll.bounds)
        view.isEditable = false
        view.isSelectable = true
        view.isAutomaticLinkDetectionEnabled = false
        view.isHorizontallyResizable = false
        view.isVerticallyResizable = true
        view.autoresizingMask = [.width]
        view.textContainer?.widthTracksTextView = true
        view.string = text
        scroll.hasVerticalScroller = true
        scroll.documentView = view
        return scroll
    }

    private static func showFailure(title: String, message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
