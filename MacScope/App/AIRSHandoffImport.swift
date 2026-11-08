import AppKit
import CoreFoundation
import Darwin
import Foundation

/// A selected AIRS finding is untrusted, static evidence. It never supplies a
/// command, file path, runtime slide, or authority to analyze another image.
struct AIRSHandoffImport {
    struct Evidence {
        let code: String
        let message: String
        let address: UInt64?
        let expected: String?
        let observed: String?
    }

    enum Failure: LocalizedError {
        case invalidDocument
        case unsupportedContract
        case missingVerifiedImage
        case imageMismatch
        case rangeMismatch
        case navigationFailed

        var errorDescription: String? {
            switch self {
            case .invalidDocument: "The AIRS handoff is malformed or exceeds the 1 MiB limit."
            case .unsupportedContract: "This AIRS handoff contract is not supported."
            case .missingVerifiedImage: "Select an analyzed Mach-O image with verified slice identity first."
            case .imageMismatch: "The focused image has a different architecture, slice digest, size, subtype, or UUID."
            case .rangeMismatch: "The handoff range does not map to file-backed executable bytes in this image."
            case .navigationFailed: "The selected image and address did not read back as requested."
            }
        }
    }

    struct NavigationRecord {
        let binaryID: UUID
        let address: UInt64
        let handoff: AIRSHandoffImport
    }

    let rawPayload: Data
    let displayName: String
    let containerSHA256: String
    let sliceOffset: UInt64
    let mode: String
    let reasonCodes: [String]
    let sourceName: String
    let sourceVersion: String
    let requirements: [String]
    let name: String
    let findingID: String
    let architecture: String
    let cpuSubtype: UInt32
    let sliceSHA256: String
    let sliceSize: UInt64
    let uuid: UUID?
    let preferredBase: UInt64
    let start: UInt64
    let end: UInt64
    let relativeStart: UInt64
    let relativeEnd: UInt64
    let verdict: String
    let coverage: String
    let scope: String
    let model: String
    let checkedPCs: [UInt64]
    let evidence: [Evidence]
    let limitations: [String]

    static func parse(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= 1_048_576,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.invalidDocument
        }
        guard integer(root["schema_version"]) == 1,
              root["report_kind"] as? String == "airs.macscope_handoff",
              root["integration_status"] as? String == "proposed_export_contract" else {
            throw Failure.unsupportedContract
        }
        guard let image = root["image"] as? [String: Any],
              let selection = root["selection"] as? [String: Any],
              let finding = root["finding"] as? [String: Any],
              let source = root["source_analysis"] as? [String: Any],
              let vm = selection["vm_range"] as? [String: Any],
              let relative = selection["image_relative_range"] as? [String: Any],
              selection["address_space"] as? String == "preferred_vm",
              let findingID = selection["finding_id"] as? String,
              findingID.range(of: "^airsf-[0-9a-f]{64}$", options: .regularExpression) != nil,
              let name = selection["function_name"] as? String, name.utf8.count <= 65_536,
              let architecture = image["architecture"] as? String,
              ["arm64", "arm64e"].contains(architecture),
              let subtype = integer(image["cpu_subtype"]), subtype <= UInt32.max,
              let displayName = image["display_name"] as? String, displayName.utf8.count <= 65_536,
              let containerDigest = image["container_sha256"] as? String,
              containerDigest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let sliceOffset = integer(image["slice_offset"]),
              let digest = image["slice_sha256"] as? String,
              digest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let size = integer(image["slice_size"]), size > 0,
              let base = hex(image["preferred_base"]),
              let start = hex(vm["start"]), let end = hex(vm["end"]),
              let relativeStart = hex(relative["start"]),
              let relativeEnd = hex(relative["end"]),
              start < end, relativeStart < relativeEnd,
              let verdict = finding["verdict"] as? String,
              ["agreement", "inconsistency", "unresolved"].contains(verdict),
              let coverage = finding["coverage"] as? String,
              ["compact", "dwarf_reference", "dwarf_evaluated", "none", "unavailable"].contains(coverage),
              let mode = finding["mode"] as? String,
              ["frame", "frameless", "dwarf", "pauth_frame", "none", "unknown"].contains(mode),
              let scope = finding["scope"] as? String,
              ["synchronous_call_sites", "modeled_leaf_body", "metadata_only"].contains(scope),
              let reasons = finding["reason_codes"] as? [String], reasons.count <= 4_096,
              reasons.allSatisfy({ $0.utf8.count <= 4_096 }),
              let sourceName = source["name"] as? String, sourceName.utf8.count <= 256,
              let sourceVersion = source["version"] as? String, sourceVersion.utf8.count <= 256,
              let model = source["analysis_model_version"] as? String, model.utf8.count <= 256,
              let requirements = root["requirements"] as? [String], requirements.count <= 256,
              requirements.allSatisfy({ $0.utf8.count <= 4_096 }),
              let pcs = finding["checked_pcs"] as? [String], pcs.count <= 4_096,
              let rawEvidence = finding["evidence"] as? [[String: Any]], rawEvidence.count <= 4_096,
              let limitations = finding["limitations"] as? [String], limitations.count <= 256,
              limitations.allSatisfy({ $0.utf8.count <= 4_096 }) else {
            throw Failure.invalidDocument
        }
        let parsedPCs = pcs.compactMap { hex($0) }
        guard parsedPCs.count == pcs.count,
              parsedPCs.allSatisfy({ start <= $0 && $0 < end }) else {
            throw Failure.invalidDocument
        }
        var parsedEvidence: [Evidence] = []
        for entry in rawEvidence {
            guard let code = entry["code"] as? String, code.utf8.count <= 256,
                  let message = entry["message"] as? String, message.utf8.count <= 4_096,
                  (entry["address"] == nil ||
                   entry["address"].flatMap(hex).map({ start <= $0 && $0 < end }) == true),
                  entry["expected"].map({ $0 is String }) ?? true,
                  entry["observed"].map({ $0 is String }) ?? true else {
                throw Failure.invalidDocument
            }
            parsedEvidence.append(Evidence(code: code, message: message,
                                           address: entry["address"].flatMap(hex),
                                           expected: entry["expected"] as? String,
                                           observed: entry["observed"] as? String))
        }
        let rawUUID = image["uuid"] as? String
        guard image.keys.contains("uuid"),
              image["uuid"] is NSNull || rawUUID != nil,
              rawUUID.map({ UUID(uuidString: $0) != nil }) ?? true else {
            throw Failure.invalidDocument
        }
        return Self(rawPayload: data, displayName: displayName, containerSHA256: containerDigest,
                    sliceOffset: sliceOffset, mode: mode, reasonCodes: reasons,
                    sourceName: sourceName, sourceVersion: sourceVersion,
                    requirements: requirements, name: name, findingID: findingID, architecture: architecture,
                    cpuSubtype: UInt32(subtype), sliceSHA256: digest, sliceSize: size,
                    uuid: rawUUID.flatMap(UUID.init(uuidString:)), preferredBase: base,
                    start: start, end: end, relativeStart: relativeStart,
                    relativeEnd: relativeEnd, verdict: verdict, coverage: coverage,
                    scope: scope, model: model, checkedPCs: parsedPCs,
                    evidence: parsedEvidence, limitations: limitations)
    }

    /// Check the opened descriptor, so a replaced path cannot bypass the file gate.
    static func read(from url: URL) throws -> Self {
        guard url.isFileURL else { throw Failure.invalidDocument }
        let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure.invalidDocument }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? file.close() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_size > 0, metadata.st_size <= 1_048_576 else {
            throw Failure.invalidDocument
        }
        return try parse(file.read(upToCount: 1_048_577) ?? Data())
    }

    func navigationRecord(binary: BinaryImage) throws -> NavigationRecord {
        NavigationRecord(binaryID: binary.id,
                         address: try destinationAddress(binary: binary), handoff: self)
    }

    func destinationAddress(binary: BinaryImage) throws -> UInt64 {
        guard binary.artifactIntegrityState == .verified,
              let identity = binary.artifactIdentity,
              let layout = binary.preferredSegmentLayout else {
            throw Failure.missingVerifiedImage
        }
        guard identity.architectureVariant.rawValue == architecture,
              UInt32(bitPattern: identity.rawCPUSubtype) == cpuSubtype,
              identity.selectedSliceSHA256 == sliceSHA256,
              identity.selectedSliceByteCount == sliceSize,
              uuid == nil || identity.uuid == uuid else {
            throw Failure.imageMismatch
        }
        guard let text = layout.records.first(where: { $0.name == "__TEXT" }),
              text.preferredVMStart == preferredBase,
              start >= preferredBase,
              relativeStart == start - preferredBase,
              relativeEnd == end - preferredBase,
              layout.records.contains(where: { segment in
                  let vmEnd = segment.preferredVMStart.addingReportingOverflow(segment.preferredVMSize)
                  let fileEnd = segment.preferredVMStart.addingReportingOverflow(segment.fileSize)
                  return segment.initialProtections & 4 != 0 && !vmEnd.overflow && !fileEnd.overflow
                      && segment.preferredVMStart <= start && end <= min(vmEnd.partialValue, fileEnd.partialValue)
              }) else {
            throw Failure.rangeMismatch
        }
        return start
    }

    private static func hex(_ value: Any?) -> UInt64? {
        guard let text = value as? String,
              text.range(of: "^0x[0-9a-f]{1,16}$", options: .regularExpression) != nil else { return nil }
        return UInt64(text.dropFirst(2), radix: 16)
    }

    private static func integer(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              let parsed = UInt64(number.stringValue),
              NSNumber(value: parsed) == number else { return nil }
        return parsed
    }
}

@MainActor
enum AIRSHandoffPresenter {
    // Retain the qualified source evidence for the most recent imported navigation.
    private(set) static var lastNavigationRecord: AIRSHandoffImport.NavigationRecord?

    static func presentPanel(store: WorkspaceStore?) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Choose a selected-finding AIRS handoff JSON. MacScope will verify the focused image before navigation."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let handoff = try AIRSHandoffImport.read(from: url)
            guard let store else {
                throw AIRSHandoffImport.Failure.missingVerifiedImage
            }
            let importedWorkspaceID = store.workspaceID
            let importedDocumentID = store.documentInstallationID
            let binary = store.focusedBinary
            let canNavigate = binary.flatMap { try? handoff.destinationAddress(binary: $0) } != nil
            let alert = NSAlert()
            alert.messageText = "AIRS finding: \(handoff.name)"
            alert.informativeText = "\(handoff.verdict) · \(handoff.coverage) · \(handoff.scope)\n"
                + "Model \(handoff.model) · preferred VM 0x\(String(handoff.start, radix: 16))–0x\(String(handoff.end, radix: 16))\n"
                + (canNavigate ? "" : "UNRESOLVED image binding. Evidence can be retained; navigation is unavailable.\n")
                + "Imported evidence is source-reported; image binding is checked separately from recovery semantics."
            let details = NSTextView(frame: NSRect(x: 0, y: 0, width: 560, height: 260))
            details.isEditable = false
            details.isSelectable = true
            details.string = handoff.evidence.map { item in
                "\(item.code)\(item.address.map { " @ 0x" + String($0, radix: 16) } ?? " (address not supplied)")\n\(item.message)"
                    + (item.expected.map { "\nExpected: \($0)" } ?? "")
                    + (item.observed.map { "\nObserved: \($0)" } ?? "")
            }.joined(separator: "\n\n")
                + "\n\nChecked PCs: " + handoff.checkedPCs.map { "0x" + String($0, radix: 16) }.joined(separator: ", ")
                + "\n\nLimitations:\n" + handoff.limitations.joined(separator: "\n")
            let scroll = NSScrollView(frame: details.frame)
            scroll.hasVerticalScroller = true
            scroll.documentView = details
            alert.accessoryView = scroll
            alert.addButton(withTitle: canNavigate ? "Retain and Navigate" : "Retain Evidence")
            alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            guard store.workspaceID == importedWorkspaceID,
                  store.documentInstallationID == importedDocumentID else {
                throw AIRSHandoffImport.Failure.imageMismatch
            }
            _ = try store.retainAIRSHandoff(handoff)
            guard canNavigate, let binary else { return }
            // Recheck after the modal presentation in case the workspace changed.
            guard store.focusedBinary?.id == binary.id,
                  let current = store.focusedBinary,
                  let record = try? handoff.navigationRecord(binary: current) else {
                throw AIRSHandoffImport.Failure.imageMismatch
            }
            guard store.selectAddress(ImageAddress(slot: current.slot, address: record.address)),
                  selectionReadback(store: store, imageID: record.binaryID, address: record.address) else {
                throw AIRSHandoffImport.Failure.navigationFailed
            }
            lastNavigationRecord = record
        } catch {
            let alert = NSAlert()
            alert.messageText = "Couldn’t Import AIRS Handoff"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }

    /// Read the workspace's committed, image-qualified selection after navigation.
    /// A true selectAddress return or the requested NavigationRecord alone is not readback.
    static func selectionReadback(store: WorkspaceStore, imageID: UUID, address: UInt64) -> Bool {
        guard let focused = store.focusedBinary, focused.id == imageID,
              let selected = store.selectedImageAddress else { return false }
        return selected.slot == focused.slot && selected.address == address
    }
}
