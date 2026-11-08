import Foundation
import XCTest
@testable import MacScope

@MainActor
final class REAWorkspacePersistenceTests: XCTestCase {
    private func traceFixture(mnemonic: String = "nop", executable: Bool = true, zeroFill: Bool = false,
                              fileSize: UInt64? = nil) throws -> (WorkspaceStore, REAResultEvidence, Phase2ReadImageIdentity, REAUITraceDestination, ImageAnalysis) {
        let binary = BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O", architecture: "arm64", selectedSliceIndex: 0)
        var image = ImageAnalysis()
        image.imageBytes = Data([0, 1, 2, 3])
        image.instructions = [InstructionRow(address: 0x1000, bytes: "00", mnemonic: mnemonic, operands: "", hasBreakpoint: false, comment: nil)]
        image.sections = [SectionSummary(id: UUID(), name: "text", address: 0x1000, size: 4, fileOffset: 0, isExecutable: executable, isZeroFill: zeroFill, fileSize: fileSize)]
        let store = WorkspaceStore(workspaceName: "Trace fixture", snapshot: .init(binaries: [binary], analysisBySlot: [.primary: image]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let imageIdentity = try XCTUnwrap(store.phase2ReadCurrentState(for: .primary).image)
        let hash = REACaptureCommitment.digest(image.imageBytes), snapshotID = UUID(), requestID = UUID()
        let authority = try XCTUnwrap(store.reaAuthority(imageSHA256: hash, snapshotID: snapshotID))
        let method: [String: Any] = ["class_name": "Controller", "selector": "perform:", "method_type": "instance", "implementation_address": "0x1000", "decode": ["status": "decoded"]]
        let input: [String: Any] = ["targetSHA256": hash, "snapshotID": snapshotID.uuidString,
            "metadata": ["targetSHA256": hash, "snapshotID": snapshotID.uuidString,
                         "value": ["objc_dispatch_implementations": [method], "coverage": []]]]
        let nodes: [[String: Any]] = [["id": "source", "kind": "view"],
            ["id": "action", "kind": "action", "attributes": ["selector": "perform:"]],
            ["id": "selector", "kind": "objc_selector", "name": "perform:"],
            ["id": "owner", "kind": "view_controller", "attributes": ["class_name": "Controller"]],
            ["id": "function", "kind": "function", "location": ["address": "0x1000"], "attributes": ["class_name": "Controller", "selector": "perform:", "method_type": "instance"]]]
        let edges: [[String: Any]] = [["from": "source", "to": "action", "relation": "target_action", "resolution": "observed"],
            ["from": "action", "to": "selector", "relation": "target_action", "resolution": "observed"],
            ["from": "action", "to": "owner", "relation": "target_action", "resolution": "observed"],
            ["from": "selector", "to": "function", "relation": "objc_dispatch", "resolution": "resolved"]]
        let result: [String: Any] = ["snapshotID": snapshotID.uuidString, "analysis": ["target_sha256": hash,
            "graph": ["nodes": nodes, "edges": edges, "truncated": false]], "dispatchCandidates": [method]]
        let request = try JSONSerialization.data(withJSONObject: ["schemaVersion": 1, "requestID": requestID.uuidString, "operation": "uiResources", "input": input])
        let response = try JSONSerialization.data(withJSONObject: ["schemaVersion": 1, "requestID": requestID.uuidString, "operation": "uiResources", "implementationIdentity": authority.implementationIdentity, "ok": true, "result": result])
        let evidence = try REAResultEvidence(requestID: requestID, operation: "uiResources", authority: authority, requestJSON: request, responseJSON: response)
        let destination = try XCTUnwrap(REAUITraceProjection.destinations(requestJSON: request, responseJSON: response)["action"])
        return (store, evidence, imageIdentity, destination, image)
    }

    func testTraceRequiresCurrentAcceptedImageAndExecutableFileMapping() throws {
        let (store, evidence, imageIdentity, destination, image) = try traceFixture()
        XCTAssertFalse(store.navigateToREAHandler(destination, evidence: evidence, image: imageIdentity))
        try store.publishREAResult(evidence)
        XCTAssertTrue(store.navigateToREAHandler(destination, evidence: evidence, image: imageIdentity))
        XCTAssertEqual(store.selectedImageAddress, ImageAddress(slot: .primary, address: 0x1000))
        var changed = image
        changed.sections[0].isZeroFill = true
        store.snapshot.replaceAnalysis(changed, in: .primary)
        XCTAssertFalse(store.navigateToREAHandler(destination, evidence: evidence, image: imageIdentity))
    }

    func testTraceRejectsCurrentUnmappedAndNonExecutableCandidates() throws {
        for (executable, zeroFill, fileSize) in [(false, false, nil), (true, true, nil), (true, false, UInt64(0))] as [(Bool, Bool, UInt64?)] {
            let (store, evidence, identity, destination, _) = try traceFixture(executable: executable, zeroFill: zeroFill, fileSize: fileSize)
            try store.publishREAResult(evidence)
            let before = store.selectedImageAddress
            XCTAssertFalse(store.navigateToREAHandler(destination, evidence: evidence, image: identity))
            XCTAssertEqual(store.selectedImageAddress, before)
        }
    }

    func testTraceRejectsCurrentDecoderPlaceholders() throws {
        for mnemonic in ["unknown", ".byte", "unavailable"] {
            let (store, evidence, identity, destination, _) = try traceFixture(mnemonic: mnemonic)
            try store.publishREAResult(evidence)
            let before = store.selectedImageAddress
            XCTAssertFalse(store.navigateToREAHandler(destination, evidence: evidence, image: identity))
            XCTAssertEqual(store.selectedImageAddress, before)
        }
    }
    private func makeStore() -> WorkspaceStore {
        let binary = BinaryImage(id: UUID(), name: "captured", path: "/captured", kind: "Mach-O", architecture: "arm64")
        var analysis = ImageAnalysis()
        analysis.imageBytes = Data([1, 2, 3, 4])
        return WorkspaceStore(workspaceName: "REA fixture",
            snapshot: WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }
    private func candidate(_ store: WorkspaceStore) throws -> REAResultEvidence {
        let digest = REACaptureCommitment.digest(try XCTUnwrap(store.focusedAnalysis?.imageBytes))
        let authority = try XCTUnwrap(store.reaAuthority(imageSHA256: digest, snapshotID: UUID()))
        let id = UUID()
        let request = try JSONSerialization.data(withJSONObject: ["schemaVersion": 1,
            "requestID": id.uuidString, "operation": "nativeApplication", "input": [:]])
        let response = try JSONSerialization.data(withJSONObject: ["schemaVersion": 1,
            "requestID": id.uuidString, "operation": "nativeApplication", "ok": true,
            "implementationIdentity": authority.implementationIdentity, "result": ["fixture": true]])
        return try REAResultEvidence(requestID: id, operation: "nativeApplication", authority: authority,
            requestJSON: request, responseJSON: response)
    }
    func testPublicationDoesNotInvalidateItsOwnSourceAndChangedBytesRejectLateResult() throws {
        let store = makeStore(), evidence = try candidate(store)
        try store.publishREAResult(evidence)
        let active = try XCTUnwrap(store.reaAuthority(imageSHA256: evidence.authority.imageSHA256,
                                                     snapshotID: evidence.authority.snapshotID))
        XCTAssertTrue(store.reaResultEvidence.isCurrent(evidence, activeAuthority: active))
        XCTAssertTrue(store.hasUnsavedChanges)
        var changed = try XCTUnwrap(store.snapshot.analysisBySlot[.primary])
        changed.imageBytes = Data([9, 9, 9])
        store.snapshot.analysisBySlot[.primary] = changed
        XCTAssertThrowsError(try store.publishREAResult(evidence))
        XCTAssertEqual(store.reaResultEvidence.records, [evidence])
    }
    func testManifestRetainsExactREAHistoryAndLegacyManifestOmitsIt() throws {
        let store = makeStore(), evidence = try candidate(store)
        try store.publishREAResult(evidence)
        var manifest = WorkspacePackageManifest(documentID: UUID(), workspaceUUID: store.workspaceID,
            workspaceName: "REA", createdAt: Date(timeIntervalSince1970: 0), modifiedAt: Date(timeIntervalSince1970: 0),
            binaries: [], session: nil)
        let legacy = try JSONEncoder().encode(manifest)
        XCTAssertNil((try JSONSerialization.jsonObject(with: legacy) as? [String: Any])?["reaEvidence"])
        manifest.reaEvidence = try JSONEncoder().encode(store.reaResultEvidence)
        let reopened = try JSONDecoder().decode(WorkspacePackageManifest.self, from: JSONEncoder().encode(manifest))
        let history = try JSONDecoder().decode(REAResultEvidenceStore.self, from: XCTUnwrap(reopened.reaEvidence))
        XCTAssertEqual(history.records, [evidence])
        XCTAssertEqual(history.records.first?.responseJSON, evidence.responseJSON)
    }

    func testWorkspacePublicationContinuesAfter128ResultsAndPackageRetainsNewest() throws {
        let store = makeStore()
        var published: [REAResultEvidence] = []
        for _ in 0...REAResultEvidenceStore.maximumRecords {
            let evidence = try candidate(store)
            try store.publishREAResult(evidence)
            published.append(evidence)
        }
        XCTAssertEqual(store.reaResultEvidence.records, Array(published.dropFirst()))
        XCTAssertTrue(store.hasUnsavedChanges)
        let saved = try JSONEncoder().encode(store.reaResultEvidence)
        XCTAssertLessThanOrEqual(saved.count, REAResultEvidenceStore.maximumEncodedBytes)
        XCTAssertEqual(try JSONDecoder().decode(REAResultEvidenceStore.self, from: saved), store.reaResultEvidence)
    }
}
