import Foundation
import XCTest
@testable import MacScope

// VA7a-1: the MCP `verified-commit` command (headless journal owner). Cases follow DESIGN.md
// section 5, items 1-8 and 10 (item 9, the session owner, is VA7a-2). The helpers below are copies of
// the private ones in VerifiedAnnotationHeadlessCommitTests; they are copied, not lifted, so that file
// is untouched.
#if DEBUG
@MainActor
final class MCPVerifiedCommitTests: XCTestCase {
    private struct Headless {
        let fixture: VCFixture.Store
        let package: URL
        let journal: URL
        let store: WorkspaceStore
        let key: ImageAddress
        let api: WorkspaceScriptingAPI
    }

    private func headless(attach: Bool = true, types: [String] = []) throws -> Headless {
        let fixture = try VCFixture.makeStore(self)
        for name in types { VCFixture.addType(fixture.store, name) }
        let package = fixture.root.appendingPathComponent("Base.mscope")
        _ = try fixture.store.writeDocumentPackageThrowing(to: package)
        let store = try WorkspaceStore.restoredPackage(from: package)
        let journal = fixture.root.appendingPathComponent("edits.journal")
        if attach { try store.attachEditJournal(at: journal) }
        let key = ImageAddress(slot: store.snapshot.primarySlot, address: fixture.base)
        return Headless(fixture: fixture, package: package, journal: journal, store: store, key: key,
                        api: WorkspaceScriptingAPI(store: store))
    }

    private func freshAttach(_ h: Headless) throws -> (store: WorkspaceStore, report: EditJournalReport, key: ImageAddress) {
        let store = try WorkspaceStore.restoredPackage(from: h.package)
        let report = try store.attachEditJournal(at: h.journal)
        return (store, report, ImageAddress(slot: store.snapshot.primarySlot, address: h.fixture.base))
    }

    private func journalRecordCount(_ h: Headless) throws -> Int {
        try EditJournalReader.read(Data(contentsOf: h.journal)).records.count
    }

    private func args(_ address: UInt64, field: String = "name", value: String = "mcp-name",
                      operationId: UUID? = nil, rationale: String? = nil,
                      basedOn: UUID? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = ["address": .hex(address), "field": .string(field), "value": .string(value)]
        if let operationId { fields["operationId"] = .string(operationId.uuidString) }
        if let rationale { fields["rationale"] = .string(rationale) }
        if let basedOn { fields["basedOnGeneration"] = .string(basedOn.uuidString) }
        return .object(fields)
    }

    private func call(_ h: Headless, _ arguments: ScriptValue) throws -> ScriptValue {
        try h.api.execute("verified-commit", arguments: arguments)
    }

    // MARK: 1. Builder

    func testBuilderDigestsMatchProjectorForNameAndComment() throws {
        let fixture = try VCFixture.makeStore(self)
        let store = fixture.store
        for (fieldClass, value) in [(VerifiedFieldClass.name, "built-name"), (VerifiedFieldClass.comment, "built comment")] {
            let projector = VerifiedCommitProjector()
            let request = try VerifiedCommitRequestBuilder.build(
                store: store, key: fixture.key, fieldClass: fieldClass, value: value, projector: projector)
            var expected = store.snapshot.addressOverrides
            var target = expected[fixture.key] ?? AddressOverride()
            fieldClass.set(value, in: &target)
            expected[fixture.key] = target
            XCTAssertEqual(request.receipt.before.digest, VerifiedCommitProjector.digest(store.snapshot.addressOverrides))
            XCTAssertEqual(request.receipt.after?.digest, VerifiedCommitProjector.digest(expected))
            XCTAssertEqual(request.receipt.after?.revision, 1)
            XCTAssertEqual(request.fieldClass, fieldClass)
            XCTAssertEqual(request.requested, value)
            XCTAssertEqual(request.target, fixture.key)
            XCTAssertEqual(request.receipt.request.edits.first?.kind, fieldClass.editKind)
            XCTAssertEqual(projector.calls, 2, "before and candidate stamps both come from the injected projector")
        }
    }

    func testBuilderRejectsNonFunctionEntryAndMintsOrHonoursOperationID() throws {
        let fixture = try VCFixture.makeStore(self)
        XCTAssertThrowsError(try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.other, fieldClass: .name, value: "x",
            projector: VerifiedCommitProjector())) { error in
            XCTAssertEqual(error as? VerifiedCommitRequestBuilder.Failure, .notFunctionEntry)
        }
        let a = try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.key, fieldClass: .name, value: "x", projector: VerifiedCommitProjector())
        let b = try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.key, fieldClass: .name, value: "x", projector: VerifiedCommitProjector())
        XCTAssertNotEqual(a.operationID, b.operationID, "a fresh id per call")
        let id = UUID()
        let c = try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.key, fieldClass: .name, value: "x", operationID: id,
            projector: VerifiedCommitProjector())
        let d = try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.key, fieldClass: .name, value: "x", operationID: id,
            projector: VerifiedCommitProjector())
        XCTAssertEqual(c.operationID, id)
        XCTAssertEqual(c.receipt.requestDigest, d.receipt.requestDigest, "a caller id makes the digest reproducible")
        // Typed classes build without the name/comment entry guard; their stagers judge the target.
        VCFixture.addType(fixture.store)
        let typed = try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.other, fieldClass: .addressType, value: "Header",
            projector: NativeAnnotationProjector())
        XCTAssertEqual(typed.fieldClass, .addressType)
        XCTAssertEqual(typed.requested, "Header")
        XCTAssertEqual(typed.target, fixture.other)
        XCTAssertEqual(typed.receipt.request.edits.first?.kind, .addressType)
        let text = try VerifiedFieldCodec.canonicalSignature(VCFixture.signature([("t1", "p", "int")], returnType: "int"))
        let signed = try VerifiedCommitRequestBuilder.build(
            store: fixture.store, key: fixture.key, fieldClass: .functionSignature, value: text,
            projector: NativeAnnotationProjector())
        XCTAssertEqual(signed.fieldClass, .functionSignature)
        XCTAssertEqual(signed.requested, text)
        XCTAssertEqual(signed.receipt.request.edits.first?.kind, .functionPrototype)
        // The independent refusal: a type at a function entry is refused by the headless stager.
        let h = try headless(types: ["Header"])
        let before = VCFixture.dump(h.store)
        let request = try VerifiedCommitRequestBuilder.build(
            store: h.store, key: h.key, fieldClass: .addressType, value: "Header", projector: NativeAnnotationProjector())
        let outcome = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertEqual(outcome.refusalCode, .candidateRejected, outcome.description)
        XCTAssertTrue(outcome.description.contains("functionEntryTarget"), outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertEqual(try journalRecordCount(h), 0)
    }

    // MARK: 2. Headless happy path

    func testHeadlessCommitReplyIsHonestAndReReadsObserved() throws {
        let h = try headless()
        let id = UUID()
        let reply = try call(h, args(h.fixture.base, operationId: id))
        XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
        XCTAssertEqual(reply["outcome"], .string("committed"))
        XCTAssertEqual(reply["command"], .string("verified-commit"))
        XCTAssertEqual(reply["operationID"], .string(id.uuidString))
        XCTAssertEqual(reply["requested"], .string("mcp-name"))
        XCTAssertEqual(reply["observed"], .string("mcp-name"))
        XCTAssertEqual(reply["matched"], .bool(true))
        XCTAssertEqual(reply["verificationTier"], .string("journal+live-projection"))
        XCTAssertEqual(reply["durability"], .string("journal"))
        XCTAssertEqual(reply["evidenceQuality"], .string("synthetic-link"))
        XCTAssertEqual(reply["process"], .string("same"))
        XCTAssertEqual(reply["publication"]?["scope"], .string("journal-line"))
        XCTAssertEqual(reply["publication"]?["pendingEditsPersisted"], .bool(false))
        XCTAssertEqual(reply["publication"]?["documentClean"], .bool(false))
        XCTAssertNotNil(reply["generation"]?.stringValue.flatMap(UUID.init(uuidString:)))
        let record = try XCTUnwrap(h.store.verifiedAnnotationAudit.records.first)
        XCTAssertEqual(reply["receiptRequestDigest"], .string(record.body.requestDigest))
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "mcp-name")
        XCTAssertTrue(h.store.hasUnsavedChanges, "journal-durable, not package-saved")
        XCTAssertEqual(try journalRecordCount(h), 1, "ONE combined journal line")
        let operation = try XCTUnwrap(reply["expectationOperation"])
        XCTAssertEqual(operation["operationID"], .string(id.uuidString))
        XCTAssertEqual(operation["field"], .string("name"))
        XCTAssertEqual(operation["requested"], .string("mcp-name"))
        XCTAssertEqual(operation["requestDigest"], .string(record.body.requestDigest))
        XCTAssertEqual(operation["decision"], .string("accepted"))

        let comment = try call(h, args(h.fixture.base, field: "comment", value: "mcp comment"))
        XCTAssertEqual(comment["outcome"], .string("committed"), "\(comment)")
        XCTAssertEqual(comment["observed"], .string("mcp comment"))
        XCTAssertEqual(try journalRecordCount(h), 2)
    }

    // VA8 (Q7): every reply carries the writer identity a driver needs to build a checkpoint expectation.
    func testReplyCarriesWriterIdentity() throws {
        let h = try headless()
        let reply = try call(h, args(h.fixture.base))
        XCTAssertEqual(reply["writer"]?["processID"], .int(Int64(ProcessInfo.processInfo.processIdentifier)))
        XCTAssertEqual(reply["writer"]?["workspaceID"], .string(h.store.workspaceID.uuidString))
        XCTAssertEqual(reply["writer"]?["documentID"], .string(h.store.documentID.uuidString))
        XCTAssertEqual(reply["writer"]?["installationID"], .string(h.store.documentInstallationID.uuidString))
        let refused = try call(h, args(h.fixture.base + 4))
        XCTAssertEqual(refused["writer"]?["processID"], reply["writer"]?["processID"], "refusals carry it too")
    }

    func testNonFunctionEntryAddressIsTypedRefusalAndWritesNothing() throws {
        let h = try headless()
        let before = VCFixture.dump(h.store)
        let reply = try call(h, args(h.fixture.base + 4))
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["error"], .string("notFunctionEntry"), "\(reply)")
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertEqual(try journalRecordCount(h), 0)
    }

    // MARK: 3. No journal

    func testHeadlessWithoutJournalRefuses() throws {
        let h = try headless(attach: false)
        let before = VCFixture.dump(h.store)
        let reply = try call(h, args(h.fixture.base))
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["outcome"], .string("refused"))
        XCTAssertEqual(reply["error"], .string("headlessJournalRequired"), "\(reply)")
        XCTAssertEqual(VCFixture.dump(h.store), before)
    }

    // MARK: 4. Bound session

    func testBoundSessionIsRefusedAsSessionOwnerNotBuilt() async throws {
        let session = try await VCSession(test: self)
        defer { session.session.close() }
        let before = VCFixture.dump(session.store)
        let api = WorkspaceScriptingAPI(store: session.store)
        let reply = try api.execute("verified-commit", arguments: args(session.fixture.base))
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["error"], .string("sessionOwnerNotBuilt"), "\(reply)")
        XCTAssertEqual(VCFixture.dump(session.store), before)
    }

    // MARK: 5. Indeterminate / latch

    func testInstallFailureIsTypedIndeterminateWithLatchAndRestartReconciles() throws {
        let h = try headless()
        struct Injected: Error {}
        h.store.verifiedHeadlessBeforeInstallHookForTesting = { throw Injected() }
        let id = UUID()
        let reply = try call(h, args(h.fixture.base, operationId: id))
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["outcome"], .string("indeterminate"), "\(reply)")
        XCTAssertEqual(reply["error"], .string("committedLiveNotInstalled"))
        XCTAssertEqual(reply["latched"], .bool(true))
        XCTAssertEqual(reply["latch"]?["operationID"], .string(id.uuidString))
        XCTAssertEqual(reply["latch"]?["isHeadless"], .bool(true))
        XCTAssertEqual(reply["retrySafe"], .bool(false))
        XCTAssertNotNil(reply["recovery"]?.stringValue)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.customName, "live untouched")
        XCTAssertEqual(try journalRecordCount(h), 1, "the full line is durable")

        h.store.verifiedHeadlessBeforeInstallHookForTesting = nil
        let next = try call(h, args(h.fixture.base, value: "after-latch"))
        XCTAssertEqual(next["error"], .string("recoveryRequired"), "\(next)")
        XCTAssertEqual(next["latch"]?["operationID"], .string(id.uuidString))

        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[fresh.key]?.customName, "mcp-name")
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [id])
        XCTAssertNil(fresh.store.verifiedCommitLatch)
    }

    func testHarnessFaultArgumentArmsTheHookOnlyWhenEnabledAndClearsIt() throws {
        let h = try headless()
        var fields: [String: ScriptValue] = ["address": .hex(h.fixture.base), "field": .string("name"),
                                              "value": .string("harness"), "harnessFault": .string("failBeforeInstall")]
        XCTAssertThrowsError(try WorkspaceScriptingAPI.verifiedCommitReply(
            .object(fields), store: h.store, harnessToolsEnabled: false))
        XCTAssertEqual(try journalRecordCount(h), 0, "a refused harness argument writes nothing")
        let reply = try WorkspaceScriptingAPI.verifiedCommitReply(.object(fields), store: h.store, harnessToolsEnabled: true)
        XCTAssertEqual(reply["outcome"], .string("indeterminate"), "\(reply)")
        XCTAssertEqual(reply["error"], .string("committedLiveNotInstalled"))
        XCTAssertNil(h.store.verifiedHeadlessBeforeInstallHookForTesting, "the hook is disarmed after the call")
        fields["harnessFault"] = .string("bogus")
        XCTAssertThrowsError(try WorkspaceScriptingAPI.verifiedCommitReply(
            .object(fields), store: h.store, harnessToolsEnabled: true))
    }

    // MARK: 6. Exact retry and conflict

    func testExactRetryIsExistingAndConflictsAreTyped() throws {
        let h = try headless()
        let id = UUID()
        let first = try call(h, args(h.fixture.base, operationId: id))
        XCTAssertEqual(first["outcome"], .string("committed"), "\(first)")
        let bytes = try Data(contentsOf: h.journal)

        let retry = try call(h, args(h.fixture.base, operationId: id))
        XCTAssertEqual(retry["ok"], .bool(true), "\(retry)")
        XCTAssertEqual(retry["outcome"], .string("existing"))
        XCTAssertEqual(retry["receiptRequestDigest"], first["receiptRequestDigest"])
        XCTAssertEqual(retry["observed"], .string("mcp-name"))
        XCTAssertEqual(try Data(contentsOf: h.journal), bytes, "exact retry writes nothing")

        for changed in [args(h.fixture.base, value: "other", operationId: id),
                        args(h.fixture.base, field: "comment", value: "mcp-name", operationId: id),
                        args(h.fixture.base, operationId: id, rationale: "different rationale")] {
            let conflict = try call(h, changed)
            XCTAssertEqual(conflict["error"], .string("idempotencyConflict"), "\(conflict)")
            XCTAssertEqual(try Data(contentsOf: h.journal), bytes)
        }

        // Without a caller id a retry is a new commit with a new operation id.
        let minted = try call(h, args(h.fixture.base, value: "again"))
        XCTAssertEqual(minted["outcome"], .string("committed"), "\(minted)")
        XCTAssertNotEqual(minted["operationID"], .string(id.uuidString))
    }

    func testExactRetrySurvivesRestartReplay() throws {
        let h = try headless()
        let id = UUID()
        XCTAssertEqual(try call(h, args(h.fixture.base, operationId: id))["outcome"], .string("committed"))
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        let reply = try WorkspaceScriptingAPI(store: fresh.store).execute(
            "verified-commit", arguments: args(h.fixture.base, operationId: id))
        XCTAssertEqual(reply["outcome"], .string("existing"), "\(reply)")
    }

    // MARK: 7. Generation guard

    func testStaleBasedOnGenerationIsRefusedBeforeAnyEffect() throws {
        let h = try headless()
        let before = VCFixture.dump(h.store)
        XCTAssertThrowsError(try call(h, args(h.fixture.base, basedOn: UUID()))) { error in
            guard case ScriptingError.staleEvidence = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertEqual(try journalRecordCount(h), 0)
        let current = h.store.snapshot.analysisGenerationID
        let ok = try call(h, args(h.fixture.base, basedOn: current))
        XCTAssertEqual(ok["outcome"], .string("committed"), "\(ok)")
    }

    // MARK: 8. Save after headless commit

    func testSaveWorkspacePersistsReceiptAndRotatesJournal() throws {
        let h = try headless()
        let id = UUID()
        XCTAssertEqual(try call(h, args(h.fixture.base, operationId: id))["outcome"], .string("committed"))
        _ = try h.api.execute("save-workspace", arguments: .object([:]))
        let reopened = try MacScopeDocumentPackage.openPackage(from: h.package)
        XCTAssertEqual(reopened.manifest.verifiedAnnotationAudit?.records.map(\.operationID), [id])
        XCTAssertEqual(reopened.snapshot.addressOverrides[h.key]?.customName, "mcp-name")
        XCTAssertEqual(try journalRecordCount(h), 0, "rotation retired the record that carried the receipt")
        h.store.detachEditJournal()?.close()
    }

    // MARK: Argument validation

    func testArgumentValidationIsExactAndBounded() throws {
        let h = try headless()
        func refused(_ fields: [String: ScriptValue], _ field: String, line: UInt = #line) {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.verifiedCommitReply(.object(fields), store: h.store), line: line) { error in
                guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("\(error)", line: line) }
                XCTAssertEqual(refusal.field, field, line: line)
            }
        }
        let good: [String: ScriptValue] = ["address": .hex(h.fixture.base), "field": .string("name"), "value": .string("v")]
        refused(good.merging(["field": .string("type")]) { $1 }, "field")
        refused(good.merging(["value": .string(" padded ")]) { $1 }, "value")
        refused(good.merging(["value": .string("")]) { $1 }, "value")
        refused(good.merging(["value": .string("two\nlines")]) { $1 }, "value")
        refused(good.merging(["value": .string(String(repeating: "n", count: 1_025))]) { $1 }, "value")
        refused(good.merging(["field": .string("comment"), "value": .string(String(repeating: "c", count: 2_049))]) { $1 }, "value")
        refused(good.merging(["operationId": .string("not-a-uuid")]) { $1 }, "operationId")
        refused(good.merging(["extra": .bool(true)]) { $1 }, "extra")
        refused(["field": .string("name"), "value": .string("v")], "address")
        XCTAssertEqual(try journalRecordCount(h), 0)
    }

    // MARK: 10. Catalog

    func testCatalogExposesMutatingToolWithRequiredArgumentsAndNotInAttach() throws {
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "verified-commit" })
        XCTAssertTrue(info.mutates)
        XCTAssertTrue(info.arguments.contains("basedOnGeneration"))
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        XCTAssertEqual(schema["required"], .array([.string("address"), .string("field"), .string("value")]))
        XCTAssertEqual(schema["additionalProperties"], .bool(false))
        XCTAssertNotNil(schema["properties"]?["operationId"])
        // Debug build: the harness argument is listed; the release argument list has no such name
        // (verifiedCommitArguments appends it under #if DEBUG only).
        XCTAssertTrue(info.arguments.contains("harnessFault"))
        XCTAssertFalse(MCPAttachExecutor.attachCommands.contains("verified-commit"),
                       "the attached/session owner is VA7a-2")
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: "verified-commit", arguments: .object([
            "address": .hex(0x1000), "field": .string("bogus"), "value": .string("v")]))) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.field, "field")
        }
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validateDiagnosed(command: "verified-commit", arguments: .object([
            "address": .hex(0x1000), "field": .string("comment"), "value": .string("v")])))
    }
}
#endif
