import CryptoKit
import Foundation
import XCTest
@testable import MacScope

final class AIRSBoundReviewImportTests: XCTestCase {
    private var imageDigest: String { sha(Data(repeating: 0, count: 256)) }
    private let findingID = "airsf-" + String(repeating: "b", count: 64)
    private let requestID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
    private let reportID = UUID(uuidString: "11111111-2222-4333-8444-666666666666")!
    private let requestAttachmentID = UUID(uuidString: "11111111-2222-4333-8444-777777777777")!

    private func sha(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func json(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private func report() -> [String: Any] {
        ["report_kind": "airs.audit", "schema_version": 1,
         "generator": ["name": "AIRS", "version": "0.2.0", "analysis_model_version": "synthetic-static-model"],
         "image": ["display_name": "owned", "architecture": "arm64", "file_type": "execute",
                   "uuid": NSNull(), "cpu_subtype": 0, "container_sha256": imageDigest,
                   "slice_sha256": imageDigest, "slice_offset": 0, "slice_size": 256,
                   "preferred_base": "0x1000"],
         "findings": [["id": findingID,
                       "function": ["name": "_owned", "boundary_source": "lc_function_starts",
                                    "address": "0x1010", "end_address": "0x1020",
                                    "image_offset": "0x10", "size": 16],
                       "verdict": "unresolved", "coverage": "none", "mode": "unknown",
                       "scope": "metadata_only", "instruction_count": 0,
                       "checked_pcs": [], "reason_codes": [], "evidence": [], "limitations": []]],
         "metadata_ranges": [], "issues": [], "limitations": [],
         "summary": ["function_count": 1, "agreement_count": 0,
                     "inconsistency_count": 0, "unresolved_count": 1,
                     "metadata_entry_count": 0, "checked_pc_count": 0]]
    }

    private func projection(from source: [String: Any]) -> [String: Any] {
        let image = source["image"] as! [String: Any]
        let finding = (source["findings"] as! [[String: Any]])[0]
        let function = finding["function"] as! [String: Any]
        return ["schema_version": 1, "report_kind": "airs.macscope_handoff",
                "integration_status": "proposed_export_contract",
                "image": ["display_name": image["display_name"]!, "uuid": image["uuid"]!,
                          "architecture": image["architecture"]!, "cpu_subtype": image["cpu_subtype"]!,
                          "container_sha256": image["container_sha256"]!, "slice_sha256": image["slice_sha256"]!,
                          "slice_offset": image["slice_offset"]!, "slice_size": image["slice_size"]!,
                          "preferred_base": image["preferred_base"]!],
                "selection": ["finding_id": findingID, "function_name": function["name"]!,
                              "address_space": "preferred_vm",
                              "vm_range": ["start": function["address"]!, "end": function["end_address"]!],
                              "image_relative_range": ["start": function["image_offset"]!, "end": "0x20"]],
                "finding": ["verdict": finding["verdict"]!, "coverage": finding["coverage"]!,
                            "mode": finding["mode"]!, "scope": finding["scope"]!,
                            "reason_codes": finding["reason_codes"]!, "checked_pcs": finding["checked_pcs"]!,
                            "evidence": finding["evidence"]!, "limitations": finding["limitations"]!],
                "source_analysis": source["generator"]!,
                "requirements": [
                    "Verify architecture and selected-slice SHA-256 before applying an address to an open image.",
                    "Use UUID as additional image identity when present; a matching filename is insufficient.",
                    "Addresses are preferred unslid VM addresses; apply a verified runtime slide only in a runtime-aware adapter.",
                    "This export defines a proposed adapter contract. It does not assume an existing MacScope GUI deep link or import command."]]
    }

    private func archive(sourceChange: ((inout [String: Any]) -> Void)? = nil,
                         requestChange: ((inout [String: Any]) -> Void)? = nil,
                         corruptReportAttachment: Bool = false) throws -> Data {
        var source = report()
        sourceChange?(&source)
        let sourceBytes = try json(source)
        let sourceSHA = sha(sourceBytes)
        let sourceDescriptor: [String: Any] = ["attachment_id": reportID.uuidString.lowercased(),
                                               "sha256": sourceSHA, "byte_count": sourceBytes.count]
        let configuration: [String: Any]
        if let value = source["analysis_config"] {
            configuration = ["state": "recorded", "value": value]
        } else { configuration = ["state": "not_recorded"] }
        var request: [String: Any] = ["report_kind": "airs.macscope_bound_request", "schema_version": 1,
                                      "request_id": requestID.uuidString.lowercased(),
                                      "profile": "exact_artifact_source_report_navigation_v1",
                                      "source_report": sourceDescriptor, "finding_id": findingID,
                                      "configuration": configuration, "projection": projection(from: source)]
        requestChange?(&request)
        let requestBytes = try json(request)
        let attachedSource = corruptReportAttachment ? sourceBytes + Data(" ".utf8) : sourceBytes
        let items: [[String: Any]] = [
            ["id": requestAttachmentID.uuidString.lowercased(), "kind": "airs.macscope_bound_request",
             "schemaVersion": 1, "mediaType": "application/json", "sha256": sha(requestBytes),
             "byteCount": requestBytes.count, "chunks": [requestBytes.base64EncodedString()]],
            ["id": reportID.uuidString.lowercased(), "kind": "airs.audit",
             "schemaVersion": 1, "mediaType": "application/json", "sha256": sourceSHA,
             "byteCount": sourceBytes.count, "chunks": [attachedSource.base64EncodedString()]]]
        return try json(["kind": "airs.review", "schemaVersion": 1,
                         "attachments": items, "components": []])
    }

    private func syntheticImage() throws -> BinaryImage {
        let bytes = Data(repeating: 0, count: 256)
        let identity = try MachOSliceArtifactIdentity(
            uuid: nil, rawCPUType: MachOConstants.cpuTypeARM64, rawCPUSubtype: 0,
            selectedSliceSHA256: imageDigest, selectedSliceByteCount: 256)
        let layout = try MachOPreferredSegmentLayout(records: [
            .init(name: "__TEXT", preferredVMStart: 0x1000, preferredVMSize: 0x100,
                  sliceRelativeFileOffset: 0, fileSize: 0x100, initialProtections: 5)
        ], selectedSliceByteCount: 256)
        let witness = try XCTUnwrap(MachOContainerAdmissionWitness(
            containerBytes: bytes, sliceOffset: 0, sliceSize: nil,
            selectedSliceIdentity: identity))
        return BinaryImage(id: UUID(), name: "synthetic", path: "/synthetic",
                           kind: "Mach-O", architecture: "arm64", artifactIdentity: identity,
                           preferredSegmentLayout: layout, artifactIntegrityState: .verified,
                           containerAdmissionWitness: witness)
    }

    func testOriginalReportBytesAndAbsentConfigurationBindToSelectedFinding() throws {
        let bytes = try archive()
        XCTAssertThrowsError(try AIRSHandoffImport.parse(bytes))
        let result = try AIRSBoundReviewImport.parse(bytes)
        XCTAssertEqual(result.requestID, requestID)
        XCTAssertEqual(result.findingID, findingID)
        XCTAssertFalse(result.configurationRecorded)
        XCTAssertEqual(result.sourceDescriptor.sha256, sha(result.sourceBytes))
        XCTAssertEqual(result.requestSHA256, sha(result.requestBytes))
        XCTAssertEqual(result.findingStart, 0x1010)
    }

    func testChangedOriginalBytesRejectOldAttachmentIdentity() throws {
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(corruptReportAttachment: true))) {
            XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .attachmentIdentityMismatch)
        }
    }

    func testDuplicateKeysAndInvalidUTF8DeclineBeforeSourceAdmission() {
        let duplicate = Data(#"{"kind":"airs.review","kind":"airs.review","schemaVersion":1,"attachments":[],"components":[]}"#.utf8)
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(duplicate)) {
            XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .malformedTransport)
        }
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(Data([0x7b, 0xff, 0x7d]))) {
            XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .malformedTransport)
        }
    }

    func testBooleanRequestVersionCannotSubstituteForIntegerOne() throws {
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(requestChange: {
            $0["schema_version"] = true
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .unsupportedContract) }
    }

    func testConfigurationAndProjectionAreBoundToSource() throws {
        let recorded = try AIRSBoundReviewImport.parse(archive(sourceChange: {
            $0["analysis_config"] = ["limits": ["max_steps": 12]]
        }))
        XCTAssertTrue(recorded.configurationRecorded)
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(sourceChange: {
            $0["analysis_config"] = ["limits": ["max_steps": 12]]
        }, requestChange: {
            $0["configuration"] = ["state": "not_recorded"]
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .configurationMismatch) }
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(requestChange: {
            var projection = $0["projection"] as! [String: Any]
            var generator = projection["source_analysis"] as! [String: Any]
            generator["analysis_model_version"] = "different-model"
            projection["source_analysis"] = generator
            $0["projection"] = projection
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .projectionMismatch) }
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(requestChange: {
            var projection = $0["projection"] as! [String: Any]
            var finding = projection["finding"] as! [String: Any]
            finding["evidence"] = [["code": "invented", "message": "not in the source"]]
            projection["finding"] = finding
            $0["projection"] = projection
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .projectionMismatch) }
    }

    func testDuplicateFindingAndUnsupportedConfigurationDecline() throws {
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(sourceChange: {
            var findings = $0["findings"] as! [[String: Any]]
            findings.append(findings[0])
            $0["findings"] = findings
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .findingNotUnique) }
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(sourceChange: {
            $0["analysis_config"] = ["limits": ["max_steps": true]]
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .unsupportedConfiguration) }
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(sourceChange: {
            $0["analysis_config"] = ["limits": ["max_steps": 1.5]]
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .unsupportedConfiguration) }
        XCTAssertThrowsError(try AIRSBoundReviewImport.parse(archive(sourceChange: {
            var generator = $0["generator"] as! [String: Any]
            generator["unsupported_numeric_extension"] = 1.5
            $0["generator"] = generator
        }))) { XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .profileLimit) }
    }

    func testSourceBoundAndEarlyRejectionReceiptsKeepDifferentCorrelation() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let bound = try AIRSBoundReviewReceipt.rejected(.identityUnavailable, request: request,
                                                        diagnostic: "Whole-container authority is unavailable.")
        let boundWire = try XCTUnwrap(JSONSerialization.jsonObject(with: bound.bytes) as? [String: Any])
        XCTAssertEqual(boundWire["report_kind"] as? String, "airs.macscope_bound_acknowledgment")
        XCTAssertEqual(boundWire["outcome"] as? String, "rejected")
        XCTAssertEqual(boundWire["code"] as? String, "identity_unavailable")
        XCTAssertEqual(boundWire["admission"] as? String, "source_bound")
        XCTAssertTrue(boundWire["destination"] is NSNull)
        XCTAssertTrue(boundWire["navigation"] is NSNull)
        let correlation = try XCTUnwrap(boundWire["request"] as? [String: Any])
        XCTAssertEqual(correlation["sha256"] as? String, request.requestSHA256)
        XCTAssertEqual(correlation["byte_count"] as? Int, request.requestBytes.count)
        let early = try AIRSBoundReviewReceipt.rejected(.invalidSourceReport,
                                                        diagnostic: "Source report validation failed.")
        let earlyWire = try XCTUnwrap(JSONSerialization.jsonObject(with: early.bytes) as? [String: Any])
        XCTAssertEqual(earlyWire["admission"] as? String, "not_validated")
        XCTAssertTrue(earlyWire["request"] is NSNull)
        XCTAssertTrue(earlyWire["source_report"] is NSNull)
        XCTAssertTrue(earlyWire["finding_id"] is NSNull)
        XCTAssertNotEqual(bound.id, early.id)
    }

    func testTerminalAttemptsNeverPromoteAbsentContainerAuthority() throws {
        let bytes = try archive()
        let first = try AIRSBoundReviewTerminalAttempt.withoutContainerAuthority(bytes: bytes)
        let admitted = try XCTUnwrap(first.admittedRequest)
        let secondReceipt = try AIRSBoundReviewReceipt.rejected(.identityUnavailable, request: admitted,
                                                                 diagnostic: "A new explicit attempt has no container authority.")
        XCTAssertNotEqual(first.receipt.id, secondReceipt.id)
        let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: first.receipt.bytes) as? [String: Any])
        XCTAssertEqual(wire["outcome"] as? String, "rejected")
        XCTAssertEqual(wire["code"] as? String, "identity_unavailable")
        XCTAssertEqual(wire["admission"] as? String, "source_bound")
        XCTAssertTrue(wire["destination"] is NSNull)
        XCTAssertTrue(wire["navigation"] is NSNull)

        let missing = TestWorkRoot.scratch
            .appendingPathComponent("C4-missing-\(UUID().uuidString).airsreview")
        let unreadable = try AIRSBoundReviewTerminalAttempt.withoutContainerAuthority(fileURL: missing)
        XCTAssertNil(unreadable.admittedRequest)
        let errorWire = try XCTUnwrap(JSONSerialization.jsonObject(with: unreadable.receipt.bytes) as? [String: Any])
        XCTAssertEqual(errorWire["outcome"] as? String, "error")
        XCTAssertEqual(errorWire["code"] as? String, "read_failed")
        XCTAssertEqual(errorWire["admission"] as? String, "not_validated")
        XCTAssertTrue(errorWire["request"] is NSNull)
    }

    func testExplicitReceiptExportIsExclusiveAndProtectsInputs() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let receipt = try AIRSBoundReviewReceipt.rejected(.identityUnavailable, request: request,
                                                          diagnostic: "Container identity unavailable.")
        let directory = TestWorkRoot.scratch
            .appendingPathComponent("C4-receipt-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let output = directory.appendingPathComponent("attempt.json")
        let sourceInput = directory.appendingPathComponent("original.airsreview")
        XCTAssertThrowsError(try receipt.export(to: output, protecting: [])) {
            XCTAssertEqual($0 as? AIRSBoundReviewReceipt.ExportFailure, .invalidDestination)
        }
        XCTAssertThrowsError(try receipt.export(to: output, protecting: [directory])) {
            XCTAssertEqual($0 as? AIRSBoundReviewReceipt.ExportFailure, .invalidDestination)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        try receipt.export(to: output, protecting: [sourceInput])
        XCTAssertEqual(try Data(contentsOf: output), receipt.bytes)
        XCTAssertThrowsError(try receipt.export(to: output, protecting: [sourceInput])) {
            XCTAssertEqual($0 as? AIRSBoundReviewReceipt.ExportFailure, .exists)
        }
        XCTAssertEqual(try Data(contentsOf: output), receipt.bytes)
    }

    @MainActor
    func testSelectionReadbackRequiresExactImageAndPreferredAddress() {
        let image = BinaryImage(id: UUID(), name: "synthetic", path: "/synthetic",
                                kind: "Mach-O", architecture: "arm64")
        var analysis = ImageAnalysis()
        analysis.sections = [SectionSummary(id: UUID(), name: "__TEXT,__text",
                                            address: 0x1010, size: 0x20,
                                            fileOffset: 0, isExecutable: true)]
        let snapshot = WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis])
        let store = WorkspaceStore(workspaceName: "AIRS readback", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        XCTAssertFalse(AIRSHandoffPresenter.selectionReadback(store: store, imageID: image.id, address: 0x1010))
        XCTAssertTrue(store.selectAddress(ImageAddress(slot: .primary, address: 0x1010)))
        XCTAssertTrue(AIRSHandoffPresenter.selectionReadback(store: store, imageID: image.id, address: 0x1010))
        XCTAssertFalse(AIRSHandoffPresenter.selectionReadback(store: store, imageID: image.id, address: 0x1014))
        XCTAssertFalse(AIRSHandoffPresenter.selectionReadback(store: store, imageID: UUID(), address: 0x1010))
    }

    func testBoundDestinationRequiresCapturedContainerAndExactOffset() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        var image = try syntheticImage()
        XCTAssertEqual(try request.destination(binary: image).address, 0x1010)
        image.containerAdmissionWitness = nil
        XCTAssertThrowsError(try request.destination(binary: image)) {
            XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .identityUnavailable)
        }
        let slice = Data(repeating: 0, count: 256)
        let otherContainer = Data([1]) + slice
        let identity = try XCTUnwrap(image.artifactIdentity)
        image.containerAdmissionWitness = try XCTUnwrap(MachOContainerAdmissionWitness(
            containerBytes: otherContainer, sliceOffset: 1, sliceSize: 256,
            selectedSliceIdentity: identity))
        XCTAssertThrowsError(try request.destination(binary: image)) {
            XCTAssertEqual($0 as? AIRSBoundReviewImport.Failure, .imageIdentityMismatch)
        }
    }

    @MainActor
    func testTerminalOutcomesAndEmitSyntheticDecoderFixture() throws {
        let requestArchive = try archive()
        let request = try AIRSBoundReviewImport.parse(requestArchive)
        let image = try syntheticImage()
        switch try AIRSBoundReviewTerminalAdmission.parse(requestArchive, focusedBinary: image) {
        case .ready(let admitted): XCTAssertEqual(admitted.destination.imageID, image.id)
        case .finished: XCTFail("Fresh captured container should admit the synthetic destination.")
        }
        switch try AIRSBoundReviewTerminalAdmission.parse(Data([0xff]), focusedBinary: image) {
        case .ready: XCTFail("Malformed transport cannot admit a destination.")
        case .finished(let early):
            let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: early.bytes) as? [String: Any])
            XCTAssertEqual(wire["admission"] as? String, "not_validated")
        }
        var analysis = ImageAnalysis()
        analysis.sections = [SectionSummary(id: UUID(), name: "__TEXT,__text",
                                            address: 0x1010, size: 0x20,
                                            fileOffset: 0x10, isExecutable: true)]
        let store = WorkspaceStore(workspaceName: "AIRS bound synthetic",
                                   snapshot: WorkspaceSnapshot(binaries: [image],
                                                               analysisBySlot: [.primary: analysis]),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let session = try AIRSBoundReviewTerminalSession(request: request, focusedBinary: image)
        let cancelled = try session.finish(.cancel, store: store)
        let navigated = try session.finish(.navigate, store: store)
        let rejected = try AIRSBoundReviewReceipt.rejected(.identityUnavailable, request: request,
                                                           diagnostic: "Synthetic rejection.")
        let failed = try AIRSBoundReviewReceipt.navigationFailed(request: request,
                                                                 destination: session.destination)
        for (receipt, outcome, code, admission) in [
            (cancelled, "cancelled", "user_cancelled", "destination_verified"),
            (navigated, "navigated", "navigation_completed", "destination_verified"),
            (rejected, "rejected", "identity_unavailable", "source_bound"),
            (failed, "error", "navigation_failed", "destination_verified")
        ] {
            let wire = try XCTUnwrap(JSONSerialization.jsonObject(with: receipt.bytes) as? [String: Any])
            XCTAssertEqual(wire["outcome"] as? String, outcome)
            XCTAssertEqual(wire["code"] as? String, code)
            XCTAssertEqual(wire["admission"] as? String, admission)
        }
        let staleImage = BinaryImage(id: UUID(), name: "changed", path: "/changed",
                                     kind: "Mach-O", architecture: "arm64")
        let staleStore = WorkspaceStore(workspaceName: "AIRS changed",
                                        snapshot: WorkspaceSnapshot(binaries: [staleImage], analysisBySlot: [:]),
                                        engine: AnalysisEngine(), autosaveScheduler: nil)
        let stale = try session.finish(.navigate, store: staleStore)
        let staleWire = try XCTUnwrap(JSONSerialization.jsonObject(with: stale.bytes) as? [String: Any])
        XCTAssertEqual(staleWire["code"] as? String, "stale_destination")
        XCTAssertTrue(staleWire["destination"] is NSNull)

        if let path = ProcessInfo.processInfo.environment["MACSCOPE_C4_COMPAT_DIR"] {
            let dir = URL(fileURLWithPath: path, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let fixtures: [(String, Data, String, Bool)] = [
                ("navigated.json", navigated.bytes, "navigated", true),
                ("cancelled.json", cancelled.bytes, "cancelled", true),
                ("rejected.json", rejected.bytes, "rejected", true),
                ("error.json", failed.bytes, "error", true)
            ]
            try requestArchive.write(to: dir.appendingPathComponent("request.json"), options: .atomic)
            for (name, bytes, _, _) in fixtures {
                try bytes.write(to: dir.appendingPathComponent(name), options: .atomic)
            }
            let manifest: [String: Any] = [
                "archive": "request.json",
                "receipts": fixtures.map { entry in
                    ["file": entry.0, "expectedOutcome": entry.2,
                     "expectedMatches": entry.3, "shouldDecode": true] as [String: Any]
                }
            ]
            try json(manifest).write(to: dir.appendingPathComponent("manifest.json"), options: .atomic)
        }
    }
}


extension AIRSBoundReviewImportTests {
    @MainActor
    private func presentationStore(image: BinaryImage, loadedRange: Bool = true) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        if loadedRange {
            analysis.sections = [SectionSummary(id: UUID(), name: "__TEXT,__text",
                address: 0x1010, size: 0x20, fileOffset: 0x10, isExecutable: true)]
        }
        return WorkspaceStore(workspaceName: "Bound review presentation",
            snapshot: WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func receiptWire(_ receipt: AIRSBoundReviewReceipt) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: receipt.bytes) as? [String: Any])
    }

    /// Break caught: omitting the generation guard permits an old modal to navigate
    /// content preserved by forkWorkspaceIdentity into a newly installed document.
    @MainActor
    func testPresentationRejectsWorkspaceForkEvenWhenImageBytesAndIDAreUnchanged() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let image = try syntheticImage()
        let store = presentationStore(image: image)
        let generation = AIRSBoundReviewDocumentGeneration(store: store)
        let attempt = AIRSBoundReviewPresentationAttempt(
            session: try AIRSBoundReviewTerminalSession(request: request, focusedBinary: image),
            generation: generation)
        _ = store.forkWorkspaceIdentity()
        XCTAssertEqual(store.focusedBinary?.id, image.id)
        let receipt = try attempt.finish(.navigate, store: store)
        let wire = try receiptWire(receipt)
        XCTAssertEqual(wire["code"] as? String, "stale_destination")
        XCTAssertEqual(wire["admission"] as? String, "source_bound")
        XCTAssertTrue(wire["destination"] is NSNull)
        XCTAssertTrue(wire["navigation"] is NSNull)
        XCTAssertNil(store.selectedImageAddress)
    }

    /// Break caught: a late second button invocation must not replay navigation
    /// or manufacture a second terminal outcome for one presentation attempt.
    @MainActor
    func testCancelledPresentationIsTerminalAndCannotReplayNavigation() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let image = try syntheticImage()
        let store = presentationStore(image: image)
        let attempt = AIRSBoundReviewPresentationAttempt(
            session: try AIRSBoundReviewTerminalSession(request: request, focusedBinary: image),
            generation: AIRSBoundReviewDocumentGeneration(store: store))
        let cancelled = try attempt.finish(.cancel, store: store)
        let repeated = try attempt.finish(.navigate, store: store)
        XCTAssertEqual(try receiptWire(cancelled)["outcome"] as? String, "cancelled")
        XCTAssertEqual(repeated.id, cancelled.id)
        XCTAssertEqual(repeated.bytes, cancelled.bytes)
        XCTAssertNil(store.selectedImageAddress)
    }

    /// Break caught: reporting success without exact live selection readback,
    /// or finishing one attempt twice and moving the user's later selection.
    @MainActor
    func testPresentationNavigatesLoadedImageOnceAndPreservesLaterSelection() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let image = try syntheticImage()
        let store = presentationStore(image: image)
        let attempt = AIRSBoundReviewPresentationAttempt(
            session: try AIRSBoundReviewTerminalSession(request: request, focusedBinary: image),
            generation: AIRSBoundReviewDocumentGeneration(store: store))
        let receipt = try attempt.finish(.navigate, store: store)
        let wire = try receiptWire(receipt)
        XCTAssertEqual(wire["outcome"] as? String, "navigated")
        XCTAssertEqual(wire["semantics"] as? String, "source_reported_not_consumer_verified")
        let navigation = try XCTUnwrap(wire["navigation"] as? [String: Any])
        XCTAssertEqual(navigation["selected_start"] as? String, "0x1010")
        XCTAssertEqual(navigation["selected_image_id"] as? String, image.id.uuidString.lowercased())
        XCTAssertEqual(store.selectedImageAddress, ImageAddress(slot: .primary, address: 0x1010))
        XCTAssertTrue(store.selectAddress(ImageAddress(slot: .primary, address: 0x1014)))
        XCTAssertEqual(try attempt.finish(.navigate, store: store).bytes, receipt.bytes)
        XCTAssertEqual(store.selectedImageAddress, ImageAddress(slot: .primary, address: 0x1014))
    }

    /// Break caught: substituting admitted preferred-VM mapping for an actual
    /// loaded-address selection and its committed readback.
    @MainActor
    func testPresentationDoesNotClaimNavigationForUnloadedAddress() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let image = try syntheticImage()
        let store = presentationStore(image: image, loadedRange: false)
        let attempt = AIRSBoundReviewPresentationAttempt(
            session: try AIRSBoundReviewTerminalSession(request: request, focusedBinary: image),
            generation: AIRSBoundReviewDocumentGeneration(store: store))
        let wire = try receiptWire(attempt.finish(.navigate, store: store))
        XCTAssertEqual(wire["outcome"] as? String, "error")
        XCTAssertEqual(wire["code"] as? String, "navigation_failed")
        XCTAssertTrue(wire["navigation"] is NSNull)
        XCTAssertNil(store.selectedImageAddress)
    }

    /// Break caught: issuing cancelled/destination_verified after the destination
    /// or document generation was invalidated during the confirmation.
    @MainActor
    func testStaleConfirmationCancelRemainsSourceBoundRejection() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let image = try syntheticImage()
        let store = presentationStore(image: image)
        let attempt = AIRSBoundReviewPresentationAttempt(
            session: try AIRSBoundReviewTerminalSession(request: request, focusedBinary: image),
            generation: AIRSBoundReviewDocumentGeneration(store: store))
        _ = store.forkWorkspaceIdentity()
        let wire = try receiptWire(attempt.finish(.cancel, store: store))
        XCTAssertEqual(wire["outcome"] as? String, "rejected")
        XCTAssertEqual(wire["code"] as? String, "stale_destination")
        XCTAssertTrue(wire["destination"] is NSNull)
    }

    /// Break caught: exporting an acknowledgment over either trusted input, or
    /// changing its terminal ID/bytes while retrying a destination collision.
    func testReceiptRetryProtectsArchiveAndImageAndKeepsTerminalBytes() throws {
        let request = try AIRSBoundReviewImport.parse(archive())
        let receipt = try AIRSBoundReviewReceipt.rejected(.identityUnavailable, request: request,
            diagnostic: "Synthetic input-protection and retry test.")
        let directory = TestWorkRoot.scratch.appendingPathComponent("bound-ui-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let archiveURL = directory.appendingPathComponent("source.airsreview")
        let imageURL = directory.appendingPathComponent("loaded-image")
        let existingURL = directory.appendingPathComponent("prior.json")
        let outputURL = directory.appendingPathComponent("fresh.json")
        let imageBytes = Data([0x01, 0x02, 0x03])
        let priorBytes = Data("previous receipt".utf8)
        let sourceBytes = try archive()
        try sourceBytes.write(to: archiveURL)
        try imageBytes.write(to: imageURL)
        try priorBytes.write(to: existingURL)
        let inputs = [archiveURL, imageURL]
        for input in inputs {
            XCTAssertThrowsError(try receipt.export(to: input, protecting: inputs)) {
                XCTAssertEqual($0 as? AIRSBoundReviewReceipt.ExportFailure, .invalidDestination)
            }
        }
        XCTAssertThrowsError(try receipt.export(to: existingURL, protecting: inputs)) {
            XCTAssertEqual($0 as? AIRSBoundReviewReceipt.ExportFailure, .exists)
        }
        try receipt.export(to: outputURL, protecting: inputs)
        XCTAssertEqual(try Data(contentsOf: archiveURL), sourceBytes)
        XCTAssertEqual(try Data(contentsOf: imageURL), imageBytes)
        XCTAssertEqual(try Data(contentsOf: existingURL), priorBytes)
        XCTAssertEqual(try Data(contentsOf: outputURL), receipt.bytes)
    }
}
