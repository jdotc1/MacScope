import Foundation
import XCTest
@testable import MacScope

private actor AIRSEvidenceSuspendedAudit {
    private var result: CheckedContinuation<UnwindAuditReport, any Error>?
    private var started: CheckedContinuation<Void, Never>?

    func run() async throws -> UnwindAuditReport {
        try await withCheckedThrowingContinuation { continuation in
            result = continuation
            started?.resume()
            started = nil
        }
    }

    func waitUntilStarted() async {
        if result != nil { return }
        await withCheckedContinuation { started = $0 }
    }

    func finish(_ report: UnwindAuditReport) {
        result?.resume(returning: report)
        result = nil
    }
}

@MainActor
final class AIRSEvidencePersistenceTests: XCTestCase {
    private let digest = String(repeating: "a", count: 64)

    private func identity() throws -> MachOSliceArtifactIdentity {
        try .init(uuid: nil, rawCPUType: MachOConstants.cpuTypeARM64, rawCPUSubtype: 0,
                  selectedSliceSHA256: digest, selectedSliceByteCount: 256)
    }

    private func handoff() throws -> AIRSHandoffImport {
        let object: [String: Any] = [
            "schema_version": 1, "report_kind": "airs.macscope_handoff",
            "integration_status": "proposed_export_contract",
            "image": ["display_name": "authored", "architecture": "arm64", "cpu_subtype": 0,
                      "container_sha256": digest, "slice_sha256": digest, "slice_offset": 0,
                      "slice_size": 256, "uuid": NSNull(), "preferred_base": "0x1000"],
            "selection": ["finding_id": "airsf-" + digest, "function_name": "_authored",
                          "address_space": "preferred_vm", "vm_range": ["start": "0x1010", "end": "0x1020"],
                          "image_relative_range": ["start": "0x10", "end": "0x20"]],
            "finding": ["verdict": "unresolved", "coverage": "none", "mode": "unknown",
                        "reason_codes": ["unsupported"], "scope": "metadata_only",
                        "checked_pcs": ["0x1010"], "evidence": [], "limitations": ["Authored fixture"]],
            "source_analysis": ["name": "AIRS", "version": "fixture", "analysis_model_version": "fixture-v1"],
            "requirements": ["Verify identity"], "extra_source_field": "preserve exactly"
        ]
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        return try .parse(Data(" \n".utf8) + bytes + Data("\n ".utf8))
    }

    private func store() -> WorkspaceStore {
        let binary = BinaryImage(id: UUID(), name: "raw", path: "/not-opened/raw", kind: "raw fixture", architecture: "arm64")
        var analysis = ImageAnalysis()
        analysis.imageBytes = Data(repeating: 0, count: 256)
        analysis.hexBytes = analysis.imageBytes
        return WorkspaceStore(workspaceName: "AIRS persistence fixture",
            snapshot: .init(binaries: [binary], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func packageURL() throws -> URL {
        let root = TestWorkRoot.scratch.appendingPathComponent("AIRS-S2-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root.appendingPathComponent("Evidence.mscope")
    }

    /// Same retained authored fixture/admission seam as WorkspaceUnwindAuditTests;
    /// no new fixture bytes or digest are produced by this test.
    func testWorkspaceAcceptedPublicationAutomaticallyRetainsOnceAcrossSaveReopenAndInvalidation() async throws {
        let bytes = MachOFixture.makeExecutableWithFunctionStarts().bytes
        let parsed = try MachOParser().parse(bytes)
        let admission = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: parsed.header.cpuType,
            rawCPUSubtype: parsed.header.cpuSubtype, selectedSliceSHA256: digest,
            selectedSliceByteCount: UInt64(bytes.count))
        let layout = try MachOPreferredSegmentLayout(records: parsed.segments.map {
            .init(name: $0.name, preferredVMStart: $0.vmAddress, preferredVMSize: $0.vmSize,
                  sliceRelativeFileOffset: $0.fileOffset, fileSize: $0.fileSize,
                  initialProtections: $0.initialProtection)
        }, selectedSliceByteCount: UInt64(bytes.count))
        let binary = BinaryImage(id: UUID(), name: "retained authored input", path: "/not-opened/authored",
            kind: "Mach-O", architecture: "arm64", artifactIdentity: admission,
            preferredSegmentLayout: layout, artifactIntegrityState: .verified)
        var analysis = ImageAnalysis()
        analysis.imageBytes = bytes
        analysis.hexBytes = bytes
        analysis.sections = parsed.sections.map {
            .init(id: UUID(), name: $0.qualifiedName, address: $0.address, size: $0.size,
                  fileOffset: UInt64($0.fileOffset), isExecutable: $0.isExecutableInstructions, isZeroFill: $0.isZeroFill)
        }
        let source = WorkspaceStore(workspaceName: "Native publication fixture",
            snapshot: .init(binaries: [binary], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        let task = try XCTUnwrap(source.startUnwindAudit(in: .primary))
        let request = try XCTUnwrap(source.unwindAuditCoordinator.state.request)
        await task.value
        XCTAssertEqual(source.unwindAuditCoordinator.state.phase, .completed)
        let report = try XCTUnwrap(source.unwindAuditCoordinator.state.report)
        XCTAssertEqual(source.airsEvidence.records.count, 1)
        let record = try XCTUnwrap(source.airsEvidence.records.first)
        XCTAssertEqual(record.nativeRequestID, request.id)
        XCTAssertEqual(record.sourceImageID, request.key.imageID)
        XCTAssertEqual(try JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload), report)
        XCTAssertTrue(source.hasUnsavedChanges)
        source.snapshot.binaries[0].name = "New live generation"
        XCTAssertNil(source.unwindAuditCoordinator.state.report)
        XCTAssertEqual(source.airsEvidence.records, [record])
        let url = try packageURL()
        _ = try source.writeDocumentPackageThrowing(to: url)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        XCTAssertEqual(reopened.airsEvidence.records, [record])
        // Package restoration reconstructs byte authority independently; the authored
        // admission digest is never rewritten to manufacture a resolved binding.
        XCTAssertFalse(reopened.airsEvidenceBinding(record).isResolved)
    }

    private func coordinatorInput() throws -> (LoadedBinary, UnwindAuditResultKey) {
        let admission = try identity()
        let key = UnwindAuditResultKey(imageID: UUID(), slot: .primary, generation: UUID(),
            identity: admission, modelID: UnwindAuditResultKey.currentModelID, configuration: .init())
        let binary = LoadedBinary(name: "authored", path: "", isBundle: false, cpuType: 0x0100000c,
            cpuSubtype: 0, fileTypeName: "Mach-O", architectureDisplayName: "arm64", metadata: .empty,
            artifactIdentity: admission, artifactIntegrityState: .verified, bytes: Data(repeating: 0, count: 256),
            sliceOffset: 0, sections: [], executableTextSection: nil, entryPointAddress: nil,
            symbols: [], imports: [], indirectSymbols: [], exports: [], stringLiterals: [],
            functionStarts: [], objcSelectors: [:])
        return (binary, key)
    }

    func testAcceptedCallbackRejectsCancelledAndSupersededLatePublications() async throws {
        for cancel in [true, false] {
            let (binary, key) = try coordinatorInput()
            let suspended = AIRSEvidenceSuspendedAudit()
            let coordinator = UnwindAuditCoordinator(runner: { _, _ in try await suspended.run() })
            var callbacks = 0
            coordinator.onAcceptedPublication = { _, _ in callbacks += 1 }
            let task = try XCTUnwrap(coordinator.start(binary: binary, key: key))
            await suspended.waitUntilStarted()
            if cancel { coordinator.cancel() } else { coordinator.activate(nil) }
            await suspended.finish(.init(identity: key.identity, findings: []))
            await task.value
            XCTAssertEqual(callbacks, 0)
            XCTAssertNil(coordinator.state.report)
            XCTAssertEqual(coordinator.state.discardedPublicationCount, 1)
        }
    }

    func testAcceptedCallbackRejectsReportThatFailsRequestedIdentityFence() async throws {
        let (binary, key) = try coordinatorInput()
        let different = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
            rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "b", count: 64), selectedSliceByteCount: 256)
        let coordinator = UnwindAuditCoordinator(runner: { _, _ in .init(identity: different, findings: []) })
        var callbacks = 0
        coordinator.onAcceptedPublication = { _, _ in callbacks += 1 }
        let task = try XCTUnwrap(coordinator.start(binary: binary, key: key))
        await task.value
        XCTAssertEqual(callbacks, 0)
        XCTAssertNil(coordinator.state.report)
        guard case .failed = coordinator.state.phase else { return XCTFail("Identity mismatch must fail publication") }
    }

    func testImportedExactBytesSurviveSynchronousPackageSaveReopen() throws {
        let source = store()
        let imported = try handoff()
        let generation = source.mutationGeneration
        let id = try source.retainAIRSHandoff(imported)
        XCTAssertGreaterThan(source.mutationGeneration, generation)
        XCTAssertTrue(source.hasUnsavedChanges)
        let url = try packageURL()
        _ = try source.writeDocumentPackageThrowing(to: url)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        let record = try XCTUnwrap(reopened.airsEvidence.records.first)
        XCTAssertEqual(record.id, id)
        XCTAssertEqual(record.workspaceID, source.workspaceID)
        XCTAssertEqual(record.rawPayload, imported.rawPayload)
        XCTAssertEqual(try AIRSHandoffImport.parse(record.rawPayload).findingID, imported.findingID)
        XCTAssertFalse(reopened.airsEvidenceBinding(record).isResolved)
        XCTAssertFalse(reopened.navigateToAIRSEvidence(record))
        XCTAssertFalse(reopened.hasUnsavedChanges)
    }

    func testForkRebindsRetainedEvidenceSoSaveReopenKeepsExactBytes() throws {
        let source = store()
        let imported = try handoff()
        let id = try source.retainAIRSHandoff(imported)
        let fork = source.forkWorkspaceIdentity()
        XCTAssertNotEqual(fork.workspaceID, fork.sourceWorkspaceID)
        let url = try packageURL()
        _ = try source.writeDocumentPackageThrowing(to: url)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        let record = try XCTUnwrap(reopened.airsEvidence.records.first)
        XCTAssertEqual(reopened.airsEvidence.records.count, 1)
        XCTAssertEqual(record.id, id)
        XCTAssertEqual(record.workspaceID, fork.workspaceID)
        XCTAssertEqual(record.rawPayload, imported.rawPayload)
    }

    func testAsyncCaptureWritesSameEnvelopeAndRetainsLaterMutation() throws {
        let source = store()
        _ = try source.retainAIRSHandoff(handoff())
        let captured = try source.makePackagePayload()
        let capturedRecords = source.airsEvidence.records
        _ = try source.retainAIRSHandoff(handoff())
        let manifest = try MacScopeDocumentPackage.validatedManifest(manifestData: captured.manifestData)
        XCTAssertEqual(manifest.airsEvidence?.records, capturedRecords)
        let url = try packageURL()
        _ = try MacScopeDocumentPackage.writePackage(manifest,
            attachmentsByBinaryID: captured.attachmentsByBinaryID, to: url,
            instructionSidecarData: captured.instructionSidecarData)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        XCTAssertEqual(reopened.airsEvidence.records, capturedRecords)
        source.acceptPublishedWrite(capturedGeneration: captured.capturedMutationGeneration, adopting: nil)
        XCTAssertTrue(source.hasUnsavedChanges)
        XCTAssertEqual(source.airsEvidence.records.count, 2)
    }

    func testNativeRecordPreservesOriginalRequestIdentityModelAndConfiguration() throws {
        let source = store()
        let identity = try identity()
        var limits = UnwindAuditLimits()
        limits.maxPaths = 3
        let request = UnwindAuditRequest(id: UUID(), key: .init(imageID: source.snapshot.binaries[0].id,
            slot: .primary, generation: UUID(), identity: identity,
            modelID: UnwindAuditResultKey.currentModelID, configuration: limits))
        let report = UnwindAuditReport(identity: identity, configuration: limits, findings: [])
        source.retainNativeAIRSEvidence(report, request: request)
        source.retainNativeAIRSEvidence(report, request: request)
        XCTAssertEqual(source.airsEvidence.records.count, 1)
        let record = try XCTUnwrap(source.airsEvidence.records.first)
        XCTAssertEqual(record.nativeRequestID, request.id)
        XCTAssertEqual(record.sourceImageID, request.key.imageID)
        XCTAssertEqual(try JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload), report)
        let url = try packageURL()
        _ = try source.writeDocumentPackageThrowing(to: url)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        XCTAssertEqual(reopened.airsEvidence.records, [record])
        XCTAssertFalse(reopened.airsEvidenceBinding(record).isResolved)
    }

    func testMissingMismatchAndAmbiguousBindingsNeverNavigateOrDiscardEvidence() throws {
        let source = store()
        let imported = try handoff()
        _ = try source.retainAIRSHandoff(imported)
        let record = try XCTUnwrap(source.airsEvidence.records.first)
        let selection = source.selectedImageAddress
        XCTAssertFalse(source.navigateToAIRSEvidence(record))
        XCTAssertEqual(source.selectedImageAddress, selection)
        var binary = source.snapshot.binaries[0]
        binary.artifactIdentity = try identity()
        binary.artifactIntegrityState = .verified
        binary.preferredSegmentLayout = try .init(records: [
            .init(name: "__TEXT", preferredVMStart: 0x1000, preferredVMSize: 256,
                  sliceRelativeFileOffset: 0, fileSize: 256, initialProtections: 5)
        ], selectedSliceByteCount: 256)
        source.snapshot.binaries = [binary]
        XCTAssertEqual(source.airsEvidenceBinding(record).binary?.id, binary.id)
        let duplicate = BinaryImage(id: UUID(), name: binary.name, path: binary.path,
            kind: binary.kind, architecture: binary.architecture, artifactIdentity: binary.artifactIdentity,
            preferredSegmentLayout: binary.preferredSegmentLayout, artifactIntegrityState: .verified,
            slot: .init(rawValue: 1))
        source.snapshot.binaries = [binary, duplicate]
        XCTAssertFalse(source.airsEvidenceBinding(record).isResolved)
        binary.artifactIntegrityState = .unavailable
        source.snapshot.binaries = [binary]
        XCTAssertFalse(source.navigateToAIRSEvidence(record))
        source.snapshot.binaries = []
        XCTAssertFalse(source.airsEvidenceBinding(record).isResolved)
        XCTAssertEqual(source.airsEvidence.records, [record])
    }

    /// Synthetic admission fixtures exercise slot ownership only; no real-slice provenance is claimed.
    func testRetainedImportedNavigationFocusesSiblingAndUnmappedAttemptIsNoOp() throws {
        let source = store()
        let primary = source.snapshot.binaries[0]
        let sibling = ImageSlot(rawValue: 1)
        let layout = try MachOPreferredSegmentLayout(records: [
            .init(name: "__TEXT", preferredVMStart: 0x1000, preferredVMSize: 256,
                  sliceRelativeFileOffset: 0, fileSize: 256, initialProtections: 5)
        ], selectedSliceByteCount: 256)
        let binary = BinaryImage(id: UUID(), name: "authored sibling", path: "/not-opened/sibling",
            kind: "raw fixture", architecture: "arm64", artifactIdentity: try identity(),
            preferredSegmentLayout: layout, artifactIntegrityState: .verified, slot: sibling)
        source.snapshot.binaries = [primary, binary]
        var analysis = ImageAnalysis()
        analysis.imageBytes = source.snapshot.analysisBySlot[.primary]?.imageBytes ?? Data()
        analysis.hexBytes = analysis.imageBytes
        analysis.instructions = [.init(address: 0x1010, bytes: "1f 20 03 d5", mnemonic: "nop",
                                       operands: "", hasBreakpoint: false, comment: nil)]
        source.snapshot.analysisBySlot[sibling] = analysis
        _ = try source.retainAIRSHandoff(handoff())
        let record = try XCTUnwrap(source.airsEvidence.records.first)
        XCTAssertEqual(source.focusedImageSlot, .primary)
        XCTAssertEqual(record.sourceImageID, binary.id)
        XCTAssertTrue(source.navigateToAIRSEvidence(record))
        XCTAssertEqual(source.focusedBinary?.id, binary.id)
        XCTAssertEqual(source.selectedImageAddress, ImageAddress(slot: sibling, address: 0x1010))
        source.focusImage(.primary)
        source.snapshot.analysisBySlot[sibling]?.instructions = []
        let selection = source.selectedImageAddress
        XCTAssertFalse(source.navigateToAIRSEvidence(record))
        XCTAssertEqual(source.focusedImageSlot, .primary)
        XCTAssertEqual(source.selectedImageAddress, selection)
        XCTAssertEqual(source.airsEvidence.records, [record])
    }

    func testZeroImagePackageRetainsUnresolvedEvidenceAndKeepsViewContentAvailable() throws {
        let source = WorkspaceStore(workspaceName: "No images",
            snapshot: .init(binaries: [], analysisBySlot: [:]), engine: AnalysisEngine(), autosaveScheduler: nil)
        XCTAssertFalse(MachOMetadataSheet(store: source).hasRenderableContent)
        _ = try source.retainAIRSHandoff(handoff())
        let url = try packageURL()
        _ = try source.writeDocumentPackageThrowing(to: url)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        let record = try XCTUnwrap(reopened.airsEvidence.records.first)
        XCTAssertTrue(reopened.snapshot.binaries.isEmpty)
        XCTAssertEqual(record.rawPayload, try handoff().rawPayload)
        XCTAssertFalse(reopened.airsEvidenceBinding(record).isResolved)
        XCTAssertFalse(reopened.navigateToAIRSEvidence(record))
        // This is the predicate consumed by the actual view branch. Rendered native
        // visibility remains a separate acceptance observation owned by Plan.
        XCTAssertTrue(MachOMetadataSheet(store: reopened).hasRenderableContent)
    }

    func testLegacyAbsentEnvelopeLoadsEmptyAndReplacesPriorDocumentEvidence() throws {
        let legacy = store()
        let url = try packageURL()
        let saved = try legacy.writeDocumentPackageThrowing(to: url)
        XCTAssertNil(saved.manifest.airsEvidence)
        let target = store()
        _ = try target.retainAIRSHandoff(handoff())
        _ = try target.openDocumentPackageThrowing(at: url)
        XCTAssertTrue(target.airsEvidence.records.isEmpty)
        XCTAssertEqual(target.workspaceID, legacy.workspaceID)
    }

    func testMalformedUnknownAndWrongWorkspaceEnvelopesRejectBeforeRestoreMutation() throws {
        let source = store()
        _ = try source.retainAIRSHandoff(handoff())
        let url = try packageURL()
        _ = try source.writeDocumentPackageThrowing(to: url)
        let manifestURL = MacScopeDocumentPackage.manifestURL(in: url)
        let original = try Data(contentsOf: manifestURL)
        let target = store()
        _ = try target.retainAIRSHandoff(handoff())
        let workspace = target.workspaceID
        let retained = target.airsEvidence
        let generation = target.mutationGeneration
        for mutation in 0..<4 {
            var root = try XCTUnwrap(JSONSerialization.jsonObject(with: original) as? [String: Any])
            var envelope = try XCTUnwrap(root["airsEvidence"] as? [String: Any])
            var records = try XCTUnwrap(envelope["records"] as? [[String: Any]])
            switch mutation {
            case 0:
                envelope["schemaVersion"] = 99
                records = [[:]]
            case 1: records[0]["rawPayload"] = Data("{}".utf8).base64EncodedString()
            case 2: records[0]["workspaceID"] = UUID().uuidString
            default:
                envelope["schemaVersion"] = 99
                records[0]["source"] = "futureSource"
            }
            envelope["records"] = records
            root["airsEvidence"] = envelope
            try JSONSerialization.data(withJSONObject: root, options: .sortedKeys).write(to: manifestURL)
            XCTAssertThrowsError(try target.openDocumentPackageThrowing(at: url)) { error in
                if mutation == 0 || mutation == 3 {
                    XCTAssertEqual(error as? AIRSEvidenceError, .unsupportedSchema(99))
                }
            }
            XCTAssertEqual(target.workspaceID, workspace)
            XCTAssertEqual(target.airsEvidence, retained)
            XCTAssertEqual(target.mutationGeneration, generation)
        }
    }

    func testEnvelopeCountAggregateImportBoundsAndDuplicateIDsAreTransactional() throws {
        let workspace = UUID()
        let raw = try handoff().rawPayload
        func record(_ payload: Data = Data(), id: UUID = UUID(), owner: UUID? = nil) -> AIRSEvidenceRecord {
            .init(id: id, workspaceID: owner ?? workspace, source: .importedHandoff,
                  sourceImageID: nil, nativeRequestID: nil, createdAt: Date(timeIntervalSince1970: 1),
                  rawPayload: payload.isEmpty ? raw : payload)
        }
        var envelope = AIRSEvidenceEnvelope(records: [record()])
        let prior = envelope
        XCTAssertThrowsError(try envelope.append(record(id: try XCTUnwrap(prior.records.first).id), workspaceID: workspace))
        XCTAssertEqual(envelope, prior)
        let oversized = Data(repeating: 32, count: 1_048_577 - raw.count) + raw
        XCTAssertEqual(oversized.count, 1_048_577)
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: oversized))
        XCTAssertThrowsError(try envelope.append(record(oversized), workspaceID: workspace)) {
            XCTAssertEqual($0 as? AIRSEvidenceError, .bounds)
        }
        XCTAssertEqual(envelope, prior)
        XCTAssertThrowsError(try AIRSEvidenceEnvelope(schemaVersion: 2).validate(workspaceID: workspace)) {
            XCTAssertEqual($0 as? AIRSEvidenceError, .unsupportedSchema(2))
        }
        XCTAssertThrowsError(try AIRSEvidenceEnvelope(records: (0...256).map { _ in record() }).validate(workspaceID: workspace))
        let padded = Data(repeating: 32, count: 1_048_576 - raw.count) + raw
        var aggregate = AIRSEvidenceEnvelope(records: (0..<24).map { _ in record(padded) })
        let full = aggregate
        XCTAssertThrowsError(try aggregate.append(record(padded), workspaceID: workspace)) {
            XCTAssertEqual($0 as? AIRSEvidenceError, .bounds)
        }
        XCTAssertEqual(aggregate, full)
    }

    func testNativeRetentionResultLinksNewRecordAndReusesExactExistingPayload() throws {
        let source = store()
        let report = UnwindAuditReport(identity: try identity(), findings: [])
        let request = UnwindAuditRequest(id: UUID(), key: .init(imageID: source.snapshot.binaries[0].id,
            slot: .primary, generation: UUID(), identity: report.identity,
            modelID: report.analysisModelVersion, configuration: report.configuration))
        let before = source.mutationGeneration
        let inserted = try source.retainNativeAIRSEvidence(report, request: request).get()
        XCTAssertEqual(source.airsEvidence.records, [inserted])
        XCTAssertEqual(inserted.workspaceID, source.workspaceID)
        XCTAssertEqual(inserted.nativeRequestID, request.id)
        XCTAssertEqual(inserted.sourceImageID, request.key.imageID)
        XCTAssertGreaterThan(source.mutationGeneration, before)
        XCTAssertTrue(source.hasUnsavedChanges)
        // Equivalent JSON formatting must not cause replacement or re-encoding of source bytes.
        let object = try JSONSerialization.jsonObject(with: inserted.rawPayload)
        let formatted = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        XCTAssertNotEqual(formatted, inserted.rawPayload)
        let existing = AIRSEvidenceRecord(id: inserted.id, workspaceID: inserted.workspaceID,
            source: inserted.source, sourceImageID: inserted.sourceImageID,
            nativeRequestID: inserted.nativeRequestID, createdAt: inserted.createdAt, rawPayload: formatted)
        source.airsEvidence = .init(records: [existing])
        let generation = source.mutationGeneration
        let duplicate = try source.retainNativeAIRSEvidence(report, request: request).get()
        XCTAssertEqual(duplicate, existing)
        XCTAssertEqual(duplicate.rawPayload, formatted)
        XCTAssertEqual(duplicate.createdAt, inserted.createdAt)
        XCTAssertEqual(source.airsEvidence.records, [existing])
        XCTAssertEqual(source.mutationGeneration, generation)
        XCTAssertNil(source.airsEvidenceRetentionError)
    }

    func testNativeRetentionResultRejectsConflictingReportImageAndWorkspace() throws {
        for conflict in 0..<3 {
            let source = store()
            let report = UnwindAuditReport(identity: try identity(), findings: [])
            let request = UnwindAuditRequest(id: UUID(), key: .init(imageID: source.snapshot.binaries[0].id,
                slot: .primary, generation: UUID(), identity: report.identity,
                modelID: report.analysisModelVersion, configuration: report.configuration))
            let existing = try source.retainNativeAIRSEvidence(report, request: request).get()
            var incoming = report
            var imageID = request.key.imageID
            if conflict == 0 { incoming.analysisModelVersion = "different-valid-model" }
            if conflict == 1 { imageID = UUID() }
            if conflict == 2 {
                source.airsEvidence = .init(records: [.init(id: existing.id, workspaceID: UUID(),
                    source: existing.source, sourceImageID: existing.sourceImageID,
                    nativeRequestID: existing.nativeRequestID, createdAt: existing.createdAt,
                    rawPayload: existing.rawPayload)])
            }
            let conflictingRequest = UnwindAuditRequest(id: request.id, key: .init(imageID: imageID,
                slot: request.key.slot, generation: request.key.generation, identity: incoming.identity,
                modelID: incoming.analysisModelVersion, configuration: incoming.configuration))
            let prior = source.airsEvidence
            let generation = source.mutationGeneration
            let result = source.retainNativeAIRSEvidence(incoming, request: conflictingRequest)
            XCTAssertThrowsError(try result.get()) {
                XCTAssertEqual($0 as? AIRSEvidenceError, .invalidRecord)
            }
            XCTAssertEqual(source.airsEvidence, prior)
            XCTAssertEqual(source.mutationGeneration, generation)
            XCTAssertEqual(source.airsEvidenceRetentionError, AIRSEvidenceError.invalidRecord.localizedDescription)
        }
    }

    func testNativeRetentionResultValidatesIncomingBeforeDuplicateLookup() throws {
        let source = store()
        let report = UnwindAuditReport(identity: try identity(), findings: [])
        let request = UnwindAuditRequest(id: UUID(), key: .init(imageID: source.snapshot.binaries[0].id,
            slot: .primary, generation: UUID(), identity: report.identity,
            modelID: report.analysisModelVersion, configuration: report.configuration))
        let existing = try source.retainNativeAIRSEvidence(report, request: request).get()
        let generation = source.mutationGeneration
        var invalid = report
        invalid.schemaVersion = 99
        XCTAssertThrowsError(try source.retainNativeAIRSEvidence(invalid, request: request).get()) {
            XCTAssertEqual($0 as? UnwindAuditReportError, .unsupportedSchema(99))
        }
        XCTAssertEqual(source.airsEvidence.records, [existing])
        XCTAssertEqual(source.mutationGeneration, generation)
        XCTAssertNotNil(source.airsEvidenceRetentionError)
        var mismatched = report
        mismatched.configuration.maxPaths += 1
        XCTAssertThrowsError(try source.retainNativeAIRSEvidence(mismatched, request: request).get()) {
            XCTAssertEqual($0 as? AIRSEvidenceError, .invalidRecord)
        }
        XCTAssertEqual(source.airsEvidence.records, [existing])
        XCTAssertEqual(source.mutationGeneration, generation)
        XCTAssertEqual(source.airsEvidenceRetentionError, AIRSEvidenceError.invalidRecord.localizedDescription)
    }

    func testNativeRetentionResultReportsBoundsWithoutMutatingFullEnvelope() throws {
        let source = store()
        let report = UnwindAuditReport(identity: try identity(), findings: [])
        let request = UnwindAuditRequest(id: UUID(), key: .init(imageID: source.snapshot.binaries[0].id,
            slot: .primary, generation: UUID(), identity: report.identity,
            modelID: report.analysisModelVersion, configuration: report.configuration))
        let raw = try JSONEncoder().encode(report)
        let records = (0..<256).map { _ in AIRSEvidenceRecord(id: UUID(), workspaceID: source.workspaceID,
            source: .nativeUnwind, sourceImageID: request.key.imageID, nativeRequestID: UUID(),
            createdAt: Date(timeIntervalSince1970: 1), rawPayload: raw) }
        source.airsEvidence = .init(records: records)
        let generation = source.mutationGeneration
        let result = source.retainNativeAIRSEvidence(report, request: request)
        XCTAssertThrowsError(try result.get()) {
            XCTAssertEqual($0 as? AIRSEvidenceError, .bounds)
        }
        XCTAssertEqual(source.airsEvidence.records, records)
        XCTAssertEqual(source.mutationGeneration, generation)
        XCTAssertEqual(source.airsEvidenceRetentionError, AIRSEvidenceError.bounds.localizedDescription)
    }

    func testStoreOverflowPreservesRecordsGenerationAndSurfacesActionableError() throws {
        let source = store()
        let imported = try handoff()
        let records = (0..<256).map { _ in AIRSEvidenceRecord(id: UUID(), workspaceID: source.workspaceID,
            source: .importedHandoff, sourceImageID: nil, nativeRequestID: nil,
            createdAt: Date(), rawPayload: imported.rawPayload) }
        source.airsEvidence = .init(records: records)
        let generation = source.mutationGeneration
        XCTAssertThrowsError(try source.retainAIRSHandoff(imported))
        XCTAssertEqual(source.airsEvidence.records, records)
        XCTAssertEqual(source.mutationGeneration, generation)
        XCTAssertTrue(source.airsEvidenceRetentionError?.contains("Existing evidence is unchanged") == true)
    }
}
