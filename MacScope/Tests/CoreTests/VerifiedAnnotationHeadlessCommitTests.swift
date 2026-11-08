import Foundation
import XCTest
@testable import MacScope

// VA3b headless-mode tests (DESIGN.md section 9, items 14 and 15). Headless means no document
// session: the R2 edit journal is the commit point and ONE fsync'd line carries both the
// annotation override and its audit record.
#if DEBUG
@MainActor
final class VerifiedAnnotationHeadlessCommitTests: XCTestCase {
    private struct Injected: Error {}

    private struct Headless {
        let fixture: VCFixture.Store
        let package: URL
        let journal: URL
        let store: WorkspaceStore
        let key: ImageAddress
    }

    /// A store restored from a saved package (so a restart restores the SAME workspace and
    /// document identity), with the R2 journal attached unless asked not to.
    private func headless(attach: Bool = true, types: [String] = []) throws -> Headless {
        let fixture = try VCFixture.makeStore(self)
        for name in types { VCFixture.addType(fixture.store, name) }
        let package = fixture.root.appendingPathComponent("Base.mscope")
        _ = try fixture.store.writeDocumentPackageThrowing(to: package)
        let store = try WorkspaceStore.restoredPackage(from: package)
        let journal = fixture.root.appendingPathComponent("edits.journal")
        if attach { try store.attachEditJournal(at: journal) }
        return Headless(fixture: fixture, package: package, journal: journal, store: store,
                        key: ImageAddress(slot: store.snapshot.primarySlot, address: fixture.base))
    }

    /// The restart path: the same saved package restored again, then the same journal attached.
    private func freshAttach(_ h: Headless) throws -> (store: WorkspaceStore, report: EditJournalReport, key: ImageAddress) {
        let store = try WorkspaceStore.restoredPackage(from: h.package)
        let report = try store.attachEditJournal(at: h.journal)
        return (store, report, ImageAddress(slot: store.snapshot.primarySlot, address: h.fixture.base))
    }

    /// A store of a DIFFERENT workspace over the same bytes (owner-mismatch replay).
    private func foreignAttach(_ journal: URL) throws -> (store: WorkspaceStore, report: EditJournalReport, key: ImageAddress) {
        let other = try VCFixture.makeStore(self)
        let report = try other.store.attachEditJournal(at: journal)
        return (other.store, report, other.key)
    }

    private func contents(_ journal: URL) throws -> EditJournalContents {
        try EditJournalReader.read(Data(contentsOf: journal))
    }

    /// SPEC row VA3: override and receipt agree, or the backend refuses further mutation.
    private func assertAgreeOrLatched(_ h: Headless, file: StaticString = #filePath, line: UInt = #line) throws {
        let store = h.store
        if store.verifiedCommitLatch != nil {
            let next = try VCFixture.request(store, key: h.key, name: "after-latch", id: UUID())
            XCTAssertEqual(store.commitVerifiedAnnotationHeadless(next).refusalCode, .recoveryRequired, file: file, line: line)
            return
        }
        let named = store.snapshot.addressOverrides[h.key]?.customName != nil
        XCTAssertEqual(named, !store.verifiedAnnotationAudit.records.isEmpty, file: file, line: line)
    }

    private func enc(_ records: [EditJournalRecord]) throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return try e.encode(records)
    }

    // MARK: Basics

    func testHeadlessCommitInstallsEditAndReceiptAndStaysDirty() throws {
        let h = try headless()
        let request = try VCFixture.request(h.store, key: h.key)
        let outcome = h.store.commitVerifiedAnnotationHeadless(request)
        guard case .committed(let snapshot, let info) = outcome else { return XCTFail(outcome.description) }
        XCTAssertTrue(info.annotationInstalled)
        XCTAssertEqual(snapshot.version, h.store.verifiedCommitVersionToken())
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "verified-name")
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertTrue(h.store.hasUnsavedChanges, "headless commit is journal-durable, not package-saved")
        let records = try contents(h.journal).records
        XCTAssertEqual(records.count, 1, "ONE combined line, never a separate override and audit line")
        guard case .verifiedAnnotation(_, _, _, let changes, let value, let audit) = records[0] else {
            return XCTFail("expected the combined record kind")
        }
        XCTAssertTrue(changes)
        XCTAssertEqual(value?.customName, "verified-name")
        XCTAssertEqual(audit.operationID, request.operationID)
        try assertAgreeOrLatched(h)
    }

    func testHeadlessWithoutJournalRefuses() throws {
        let h = try headless(attach: false)
        let before = VCFixture.dump(h.store)
        let outcome = h.store.commitVerifiedAnnotationHeadless(try VCFixture.request(h.store, key: h.key))
        XCTAssertEqual(outcome.refusalCode, .headlessJournalRequired, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
    }

    func testHeadlessCommitThenFreshAttachReplaysOverrideAndAuditAtomically() throws {
        let h = try headless()
        let request = try VCFixture.request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        h.store.detachEditJournal()?.close()

        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.report.replayed, 1)
        XCTAssertTrue(fresh.report.unattachedAuditRecords.isEmpty)
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[fresh.key]?.customName, "verified-name")
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.first?.digest,
                       h.store.verifiedAnnotationAudit.records.first?.digest)
        XCTAssertTrue(fresh.store.hasUnsavedChanges, "replayed audit must keep the document dirty so it is saved")
    }

    func testReplayIsIdempotentWhenAuditAlreadyPresent() throws {
        let h = try headless()
        let request = try VCFixture.request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        fresh.store.detachEditJournal()?.close()
        // Same live store, same journal: the override is already applied and the audit present.
        let again = try fresh.store.attachEditJournal(at: h.journal)
        XCTAssertTrue(again.alreadyApplied)
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertTrue(again.unattachedAuditRecords.isEmpty)
    }

    func testJournalExactRetryAndConflictingReuse() throws {
        let h = try headless()
        let id = UUID()
        let request = try VCFixture.request(h.store, key: h.key, id: id)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        let bytes = try Data(contentsOf: h.journal)
        let sequence = h.store.editJournal?.appendedSequence
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isExisting)
        XCTAssertEqual(try Data(contentsOf: h.journal), bytes, "exact retry writes nothing")
        XCTAssertEqual(h.store.editJournal?.appendedSequence, sequence)
        let changed = try VCFixture.request(h.store, key: h.key, name: "other", id: id, rationale: "changed reuse")
        XCTAssertEqual(h.store.commitVerifiedAnnotationHeadless(changed).refusalCode, .idempotencyConflict)
        XCTAssertEqual(try Data(contentsOf: h.journal), bytes)
    }

    func testBoundSessionRefusesHeadlessPath() async throws {
        let session = try await VCSession(test: self)
        defer { session.session.close() }
        let outcome = session.store.commitVerifiedAnnotationHeadless(try session.request())
        XCTAssertEqual(outcome.refusalCode, .notHeadless, outcome.description)
    }

    func testRejectedReceiptHeadlessIsAuditOnlyRecord() throws {
        let h = try headless()
        let overrides = h.store.snapshot.addressOverrides
        let request = try VCFixture.request(h.store, key: h.key, accepted: false)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        XCTAssertEqual(h.store.snapshot.addressOverrides, overrides)
        guard case .verifiedAnnotation(_, let slot, _, let changes, let value, _) = try contents(h.journal).records[0] else {
            return XCTFail("expected combined record")
        }
        XCTAssertEqual(slot, -1)
        XCTAssertFalse(changes)
        XCTAssertNil(value)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertEqual(fresh.store.snapshot.addressOverrides, overrides)
    }

    // MARK: H1-H4

    func testH1AppendFailsBeforeBytes() throws {
        let h = try headless()
        let overrides = h.store.snapshot.addressOverrides
        h.store.editJournal?.appendHook = { _ in throw Injected() }
        let request = try VCFixture.request(h.store, key: h.key)
        let outcome = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertEqual(outcome.indeterminateCode, .journalAppendUncertain, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        XCTAssertEqual(h.store.snapshot.addressOverrides, overrides, "live untouched")
        XCTAssertTrue(h.store.verifiedAnnotationAudit.records.isEmpty)
        try assertAgreeOrLatched(h)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.report.replayed, 0)
        XCTAssertTrue(fresh.store.verifiedAnnotationAudit.records.isEmpty, "no line was written: unchanged")
    }

    func testH2AfterWriteBeforeFsync() throws {
        let h = try headless()
        let overrides = h.store.snapshot.addressOverrides
        h.store.editJournal?.beforeAppendSyncForTesting = { _ in throw Injected() }
        let request = try VCFixture.request(h.store, key: h.key)
        let outcome = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertEqual(outcome.indeterminateCode, .journalAppendUncertain, outcome.description)
        XCTAssertEqual(h.store.snapshot.addressOverrides, overrides, "live untouched")
        try assertAgreeOrLatched(h)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        // The line may or may not have reached the file; it is never half applied.
        let named = fresh.store.snapshot.addressOverrides[fresh.key]?.customName == "verified-name"
        XCTAssertEqual(named, fresh.store.verifiedAnnotationAudit.records.map(\.operationID) == [request.operationID])
    }

    func testH3AfterFsyncBeforeLiveInstall() throws {
        let h = try headless()
        let overrides = h.store.snapshot.addressOverrides
        h.store.verifiedHeadlessBeforeInstallHookForTesting = { throw Injected() }
        let request = try VCFixture.request(h.store, key: h.key)
        let outcome = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveNotInstalled, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        XCTAssertEqual(h.store.snapshot.addressOverrides, overrides, "live untouched")
        XCTAssertEqual(try contents(h.journal).records.count, 1, "the full line is durable")
        try assertAgreeOrLatched(h)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[fresh.key]?.customName, "verified-name")
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
    }

    func testH4TornTailDropsBothHalves() throws {
        let h = try headless()
        let request = try VCFixture.request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        h.store.detachEditJournal()?.close()
        var bytes = try Data(contentsOf: h.journal)
        let completeLines = bytes.indices.filter { bytes[$0] == 10 }
        let lastLineStart = completeLines[completeLines.count - 2] + 1
        bytes = bytes.prefix(lastLineStart + 40)  // mid-record, no trailing newline
        try bytes.write(to: h.journal)
        let fresh = try freshAttach(h)
        XCTAssertNotNil(fresh.report.tornTail)
        XCTAssertEqual(fresh.report.replayed, 0)
        XCTAssertNil(fresh.store.snapshot.addressOverrides[fresh.key]?.customName)
        XCTAssertTrue(fresh.store.verifiedAnnotationAudit.records.isEmpty, "never one half")
    }

    // MARK: Journal codec and replay

    func testOldReaderRefusesNewRecordKind() throws {
        let h = try headless()
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(try VCFixture.request(h.store, key: h.key)).isCommitted)
        h.store.detachEditJournal()?.close()
        let bytes = try Data(contentsOf: h.journal)
        // The header version is unchanged, so a pre-VA3b reader reaches the record kind and must
        // fail closed on a kind it does not know.
        let text = try XCTUnwrap(String(data: bytes, encoding: .utf8))
        XCTAssertTrue(text.contains("\"verifiedAnnotation\""))
        let unknown = Data(text.replacingOccurrences(of: "\"verifiedAnnotation\"", with: "\"someFutureKind\"").utf8)
        XCTAssertThrowsError(try EditJournalReader.read(unknown))
        let fresh = try VCFixture.makeStore(self)
        let copy = fresh.root.appendingPathComponent("unknown.journal")
        try unknown.write(to: copy)
        XCTAssertThrowsError(try fresh.store.attachEditJournal(at: copy))
        XCTAssertTrue(fresh.store.snapshot.addressOverrides[fresh.key]?.customName == nil)
        XCTAssertTrue(fresh.store.verifiedAnnotationAudit.records.isEmpty)
    }

    func testOwnerMismatchReplayPerQ4() throws {
        let h = try headless()
        let request = try VCFixture.request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        h.store.detachEditJournal()?.close()
        // The fresh store is a different workspace/document: the override replays as an ordinary
        // edit, the foreign-owner audit record is reported and never attached.
        let fresh = try foreignAttach(h.journal)
        XCTAssertNotEqual(fresh.store.workspaceID, h.store.workspaceID)
        XCTAssertEqual(fresh.report.unattachedAuditRecords, [request.operationID])
        XCTAssertTrue(fresh.store.verifiedAnnotationAudit.records.isEmpty, "foreign-owner audit is never attached")
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[fresh.key]?.customName, "verified-name")
    }

    func testVerifiedRecordCodecRoundTripAndReaderGuard() throws {
        let h = try headless()
        let request = try VCFixture.request(h.store, key: h.key)
        let audit = try VerifiedAnnotationAuditRecord(receipt: request.receipt, nativeEvidenceLinks: request.nativeEvidenceLinks)
        let slot = h.key.slot.rawValue
        let record = EditJournalRecord.verifiedAnnotation(
            seq: 1, slot: slot, address: h.key.address, changesOverride: true,
            value: AddressOverride(customName: "verified-name"), audit: audit)
        let line = try EditJournalCodec.line(record)
        let header = try Data(contentsOf: h.journal).prefix { $0 != 10 } + Data([10])
        XCTAssertEqual(try enc(EditJournalReader.read(header + line).records), try enc([record]))

        let auditOnly = EditJournalRecord.verifiedAnnotation(
            seq: 1, slot: -1, address: 0, changesOverride: false, value: nil, audit: audit)
        XCTAssertEqual(try enc(EditJournalReader.read(header + EditJournalCodec.line(auditOnly)).records), try enc([auditOnly]))

        // An override-changing record may not hide behind the audit-only slot.
        let disguised = EditJournalRecord.verifiedAnnotation(
            seq: 1, slot: -1, address: h.key.address, changesOverride: true,
            value: AddressOverride(customName: "x"), audit: audit)
        XCTAssertThrowsError(try EditJournalReader.read(header + EditJournalCodec.line(disguised)))
    }

    // MARK: Item 15

    func testSaveWorkspaceAfterHeadlessCommitPersistsReceiptAndRotates() throws {
        let fixture = try VCFixture.makeStore(self)
        let package = fixture.root.appendingPathComponent("P.mscope")
        _ = try fixture.store.writeDocumentPackageThrowing(to: package)
        let p1 = try WorkspaceStore.restoredPackage(from: package)
        let journal = fixture.root.appendingPathComponent("p.journal")
        try p1.attachEditJournal(at: journal)
        let key = ImageAddress(slot: p1.snapshot.primarySlot, address: fixture.base)
        let request = try VCFixture.request(p1, key: key)
        XCTAssertTrue(p1.commitVerifiedAnnotationHeadless(request).isCommitted)
        _ = try WorkspaceScriptingAPI(store: p1).execute("save-workspace", arguments: .object([:]))

        let reopened = try MacScopeDocumentPackage.openPackage(from: package)
        XCTAssertEqual(reopened.manifest.verifiedAnnotationAudit?.records.map(\.operationID), [request.operationID])
        XCTAssertEqual(reopened.snapshot.addressOverrides[key]?.customName, "verified-name")
        // Rotation retired the record that carried the receipt; the package now holds it.
        let retired = try EditJournalReader.read(Data(contentsOf: URL(fileURLWithPath: journal.path + ".retired.1")))
        XCTAssertEqual(retired.records.count, 1)
        XCTAssertEqual(try contents(journal).records.count, 0)
        p1.detachEditJournal()?.close()

        let p2 = try WorkspaceStore.restoredPackage(from: package)
        XCTAssertEqual(p2.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertEqual(p2.snapshot.addressOverrides[key]?.customName, "verified-name")
        try p2.attachEditJournal(at: journal)
        XCTAssertEqual(p2.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID], "no duplicate receipt")
    }

    // MARK: VA-SCOPE S4: type-at-address class

    private func typedKey(_ h: Headless) -> ImageAddress { h.fixture.other }

    private func typedCommit(_ h: Headless, type: String?, id: UUID = UUID()) throws -> VerifiedAnnotationCommitOutcome {
        h.store.commitVerifiedAnnotationHeadless(
            try VCFixture.typedRequest(h.store, key: typedKey(h), type: type, id: id))
    }

    /// (b) A typed commit writes ONE unchanged-shape line; replay on a fresh attach applies the override and
    /// the audit record, and the line passes `fieldClassMatches`.
    func testTypedHeadlessCommitJournalsOneLineAndReplays() throws {
        let h = try headless(types: ["Header"])
        let outcome = try typedCommit(h, type: "Header")
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertEqual(h.store.snapshot.addressOverrides[typedKey(h)]?.appliedTypeName, "Header")
        XCTAssertNotNil(h.store.snapshot.appliedType(at: typedKey(h)))
        let records = try contents(h.journal).records
        XCTAssertEqual(records.count, 1)
        guard case .verifiedAnnotation(_, _, let address, let changes, let value, let audit) = records[0] else {
            return XCTFail("expected the combined record kind")
        }
        XCTAssertEqual(address, typedKey(h).address)
        XCTAssertTrue(changes)
        XCTAssertEqual(value?.appliedTypeName, "Header")
        XCTAssertEqual(audit.body.fieldClass, .addressType)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.report.replayed, 1)
        let freshKey = ImageAddress(slot: fresh.store.snapshot.primarySlot, address: typedKey(h).address)
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[freshKey]?.appliedTypeName, "Header")
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.first?.digest, audit.digest)
    }

    /// (b) A tampered typed line that ALSO changes a protected member is refused by replay through
    /// `fieldClassMatches`, with the typed `corrupt` error, before anything is mutated.
    func testTamperedTypedLineThatChangesProtectedMemberIsRefusedOnReplay() throws {
        let h = try headless(types: ["Header"])
        XCTAssertTrue(try typedCommit(h, type: "Header").isCommitted)
        h.store.detachEditJournal()?.close()
        let original = try Data(contentsOf: h.journal)
        guard case .verifiedAnnotation(let seq, let slot, let address, let changes, var value, let audit) =
                try XCTUnwrap(try contents(h.journal).records.first) else { return XCTFail("record kind") }
        value?.customName = "smuggled-name"  // a member the addressType class does not own
        let tampered = EditJournalRecord.verifiedAnnotation(
            seq: seq, slot: slot, address: address, changesOverride: changes, value: value, audit: audit)
        let header = original.prefix { $0 != 10 } + Data([10])
        let bad = header + (try EditJournalCodec.line(tampered))
        XCTAssertNoThrow(try EditJournalReader.read(bad), "the line is well formed; only the class check refuses it")
        try bad.write(to: h.journal)

        let store = try WorkspaceStore.restoredPackage(from: h.package)
        let before = VCFixture.dump(store)
        XCTAssertThrowsError(try store.attachEditJournal(at: h.journal)) { error in
            XCTAssertEqual(error as? EditJournalError, .corrupt(line: Int(seq) + 1))
        }
        XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: store.snapshot.primarySlot, address: address)])
        XCTAssertTrue(store.verifiedAnnotationAudit.records.isEmpty)
        XCTAssertEqual(VCFixture.dump(store), before)
    }

    /// (c) Erase-to-empty: the line is well formed (`changesOverride` true, `value` nil) and replays to no override.
    func testEraseToEmptyJournalLineIsWellFormedAndReplays() throws {
        let h = try headless(types: ["Header"])
        XCTAssertTrue(try typedCommit(h, type: "Header").isCommitted)
        XCTAssertTrue(try typedCommit(h, type: nil).isCommitted)
        XCTAssertNil(h.store.snapshot.addressOverrides[typedKey(h)], "the emptied override is pruned")
        let records = try contents(h.journal).records
        XCTAssertEqual(records.count, 2)
        guard case .verifiedAnnotation(_, _, _, let changes, let value, let audit) = records[1] else {
            return XCTFail("record kind")
        }
        XCTAssertTrue(changes)
        XCTAssertNil(value)
        XCTAssertEqual(audit.body.fieldClass, .addressType)
        let text = try XCTUnwrap(String(data: Data(contentsOf: h.journal), encoding: .utf8))
        XCTAssertEqual(text.split(separator: "\n").count, 3, "header plus two complete lines")
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.report.replayed, 2)
        XCTAssertNil(fresh.store.snapshot.addressOverrides[ImageAddress(slot: fresh.store.snapshot.primarySlot,
                                                                       address: typedKey(h).address)])
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.count, 2)
    }

    /// (d) Typed headless commit: existing-outcome idempotence and the append-failure path stay typed.
    func testTypedHeadlessExactRetryIsExistingAndConflictRefused() throws {
        let h = try headless(types: ["Header"])
        let id = UUID()
        // The exact retry is the SAME request (stamps and digest included), as in the name-class test.
        let request = try VCFixture.typedRequest(h.store, key: typedKey(h), type: "Header", id: id)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        let retry = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertTrue(retry.isExisting, retry.description)
        XCTAssertEqual(try contents(h.journal).records.count, 1, "an existing outcome appends nothing")
        let conflict = try typedCommit(h, type: nil, id: id)
        XCTAssertEqual(conflict.refusalCode, .idempotencyConflict, conflict.description)
    }

    func testTypedHeadlessIndeterminateAfterFsyncThenReplayReconciles() throws {
        let h = try headless(types: ["Header"])
        struct Injected: Error {}
        // H3: the line is durable but the live install fails; the backend latches indeterminate.
        let request = try VCFixture.typedRequest(h.store, key: typedKey(h), type: "Header")
        h.store.verifiedHeadlessBeforeInstallHookForTesting = { throw Injected() }
        let outcome = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveNotInstalled, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        XCTAssertEqual(try contents(h.journal).records.count, 1)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        let freshTyped = ImageAddress(slot: fresh.key.slot, address: typedKey(h).address)
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[freshTyped]?.appliedTypeName, "Header")
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
    }

    /// (a) Name and comment lines keep the v1 shape: no `fieldClass`, v1 domain, no typed encoding, and the
    /// journal line carries the same keys as before. (Goldens are frozen by construction; see VERDICT.)
    func testNameAndCommentJournalLinesKeepV1Shape() throws {
        let h = try headless()
        let name = try VCFixture.request(h.store, key: h.key, name: "n1", id: UUID())
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(name).isCommitted)
        let comment = try VCFixture.request(h.store, key: h.key, name: "c1", id: UUID(), field: .comment)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(comment).isCommitted)
        let text = try XCTUnwrap(String(data: Data(contentsOf: h.journal), encoding: .utf8))
        XCTAssertFalse(text.contains("fieldClass"))
        XCTAssertFalse(text.contains("record.v2"))
        for record in h.store.verifiedAnnotationAudit.records {
            XCTAssertNil(record.body.fieldClass)
            XCTAssertEqual(record.body.domain, VerifiedAnnotationAuditRecord.domain)
            XCTAssertFalse(record.usesTypedEditEncoding)
        }
        let lines = try contents(h.journal).records
        XCTAssertEqual(lines.count, 2)
        guard case .verifiedAnnotation(_, _, _, _, let first, _) = lines[0],
              case .verifiedAnnotation(_, _, _, _, let second, _) = lines[1] else { return XCTFail("kinds") }
        XCTAssertEqual(first?.customName, "n1")
        XCTAssertEqual(second?.customComment, "c1")
        XCTAssertNil(second?.appliedTypeName)
    }

    /// SPEC T8: "Journal v2 line on an old reader fails with `corrupt`".
    /// No true old binary can be run from here (EditJournal.swift is read-only and the old decoder is gone),
    /// so this reproduces the pre-S2 record decode on the audit payload of a real v2 journal line, exactly as
    /// S2 did for the package, and relies on EditJournal.swift:249-250, which maps ANY record decode failure
    /// to `corrupt(line:)`. The current reader is also shown to accept the same line.
    func testT8V2JournalLineOnOldReaderFailsAsCorrupt() throws {
        let h = try headless(types: ["Header"])
        XCTAssertTrue(try typedCommit(h, type: "Header").isCommitted)
        h.store.detachEditJournal()?.close()
        XCTAssertNoThrow(try contents(h.journal))
        guard case .verifiedAnnotation(let seq, _, _, _, _, let audit) = try XCTUnwrap(try contents(h.journal).records.first) else {
            return XCTFail("record kind")
        }
        XCTAssertEqual(audit.body.domain, VerifiedAnnotationAuditRecord.domainV2)
        // Old record decode: v1 Body shape, canonical re-encode equality, v1-only domain.
        struct LegacyV1Body: Codable {
            let domain: String
            let operationID: UUID
            let requestDigest: String
            let decision: VerifiedAnnotationDecision
            let before: VerifiedAnnotationProjectionIdentity
            let after: VerifiedAnnotationProjectionIdentity?
            let mechanical: VerifiedAnnotationMechanicalResult
            let persistence: VerifiedAnnotationPersistenceStatus
            let failure: String?
            let recovery: String?
            let recordedAtMilliseconds: Int64
            let nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink]
            let checkpointReferences: [VerifiedAnnotationCheckpointReference]
        }
        func oldReaderDecodes(_ bytes: Data) -> Bool {
            guard let decoded = try? VerifiedAnnotationAuditCodec.decode(LegacyV1Body.self, from: bytes),
                  let again = try? VerifiedAnnotationAuditCodec.encode(decoded), again == bytes,
                  decoded.domain == VerifiedAnnotationAuditRecord.domain else { return false }
            return true
        }
        XCTAssertFalse(oldReaderDecodes(audit.canonicalBytes), "an old reader cannot decode a v2 audit record")
        // The same decode accepts a v1 name record, so the simulation is not vacuous.
        let v1Request = try VCFixture.request(h.store, key: h.key)
        let v1 = try VerifiedAnnotationAuditRecord(
            receipt: v1Request.receipt, nativeEvidenceLinks: v1Request.nativeEvidenceLinks)
        XCTAssertTrue(oldReaderDecodes(v1.canonicalBytes))
        // The old reader's catch (EditJournal.swift:250) reports the record's line.
        let expected = EditJournalError.corrupt(line: Int(seq) + 1)
        XCTAssertEqual(expected.errorDescription, "journal-corrupt: line 2")
    }

    /// 256 UTF-8 byte bound for type names in the audit mapping (R4); functionName limits unchanged.
    func testTypeNameBoundIs256Utf8BytesInTheAuditMapping() throws {
        let h = try headless()
        let ok = try VCFixture.typedRequest(h.store, key: typedKey(h), type: String(repeating: "T", count: 256))
        XCTAssertNoThrow(try VerifiedAnnotationAuditRecord(receipt: ok.receipt, nativeEvidenceLinks: ok.nativeEvidenceLinks))
        let long = try VCFixture.typedRequest(h.store, key: typedKey(h), type: String(repeating: "T", count: 257))
        XCTAssertThrowsError(try VerifiedAnnotationAuditRecord(receipt: long.receipt, nativeEvidenceLinks: long.nativeEvidenceLinks))
    }

    // MARK: VA-SCOPE S6b: function signature class

    private func signature(_ rows: [(String, String, String)] = [("t1", "buf", "char *"), ("t2", "len", "size_t")],
                           returnType: String? = "ssize_t") -> FunctionSignatureOverride {
        VCFixture.signature(rows.map { (token: $0.0, name: $0.1, type: $0.2) }, returnType: returnType)
    }

    private func signatureCommit(_ h: Headless, _ value: FunctionSignatureOverride?, id: UUID = UUID(),
                                 production: Bool = false) throws -> VerifiedAnnotationCommitOutcome {
        h.store.commitVerifiedAnnotationHeadless(
            try VCFixture.signatureRequest(h.store, key: h.key, signature: value, id: id, production: production))
    }

    /// A signature commit writes ONE unchanged-shape line; replay on a fresh attach applies the override (tokens
    /// included) and the audit record, and the line passes `fieldClassMatches`. The session-only authority never
    /// reaches the journal (`ownReturnAuthorityFile` is absent from `AddressOverride`'s CodingKeys).
    func testSignatureHeadlessCommitJournalsOneLineAndReplays() throws {
        let h = try headless()
        var override = h.store.snapshot.addressOverrides[h.key] ?? AddressOverride()
        override.ownReturnAuthorityFile = "session-authority"  // session-only; no signature yet, so it persists
        h.store.snapshot.addressOverrides[h.key] = override
        let requested = signature()
        let outcome = try signatureCommit(h, requested)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(try XCTUnwrap(h.store.snapshot.addressOverrides[h.key]?.signature)),
                       try VerifiedFieldCodec.canonicalSignature(requested))
        let records = try contents(h.journal).records
        XCTAssertEqual(records.count, 1)
        guard case .verifiedAnnotation(_, _, let address, let changes, let value, let audit) = records[0] else {
            return XCTFail("expected the combined record kind")
        }
        XCTAssertEqual(address, h.key.address)
        XCTAssertTrue(changes)
        XCTAssertEqual(audit.body.fieldClass, .functionSignature)
        XCTAssertEqual(audit.body.domain, VerifiedAnnotationAuditRecord.domainV2)
        let text = try XCTUnwrap(String(data: Data(contentsOf: h.journal), encoding: .utf8))
        XCTAssertFalse(text.contains("ownReturnAuthorityFile"), "the session authority can never be journaled")
        XCTAssertFalse(text.contains("session-authority"))
        let journaled = try XCTUnwrap(value?.signature)
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(journaled), try VerifiedFieldCodec.canonicalSignature(requested))
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.report.replayed, 1)
        XCTAssertEqual(fresh.store.snapshot.addressOverrides[fresh.key]?.signature, journaled)
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.first?.digest, audit.digest)
    }

    /// Point 6: a tampered signature line that ALSO changes `customName` is refused as `corrupt` on replay,
    /// before anything is mutated.
    func testTamperedSignatureLineThatAlsoChangesCustomNameIsRefusedOnReplay() throws {
        let h = try headless()
        XCTAssertTrue(try signatureCommit(h, signature()).isCommitted)
        h.store.detachEditJournal()?.close()
        let original = try Data(contentsOf: h.journal)
        guard case .verifiedAnnotation(let seq, let slot, let address, let changes, var value, let audit) =
                try XCTUnwrap(try contents(h.journal).records.first) else { return XCTFail("record kind") }
        value?.customName = "smuggled-name"
        let tampered = EditJournalRecord.verifiedAnnotation(
            seq: seq, slot: slot, address: address, changesOverride: changes, value: value, audit: audit)
        let header = original.prefix { $0 != 10 } + Data([10])
        let bad = header + (try EditJournalCodec.line(tampered))
        XCTAssertNoThrow(try EditJournalReader.read(bad), "the line is well formed; only the class check refuses it")
        try bad.write(to: h.journal)

        let store = try WorkspaceStore.restoredPackage(from: h.package)
        let before = VCFixture.dump(store)
        XCTAssertThrowsError(try store.attachEditJournal(at: h.journal)) { error in
            XCTAssertEqual(error as? EditJournalError, .corrupt(line: Int(seq) + 1))
        }
        XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: store.snapshot.primarySlot, address: address)])
        XCTAssertTrue(store.verifiedAnnotationAudit.records.isEmpty)
        XCTAssertEqual(VCFixture.dump(store), before)
    }

    /// (d) Signature headless commit: existing-outcome idempotence, conflict, and the indeterminate-then-replay path.
    func testSignatureHeadlessExactRetryConflictAndReplayReconciles() throws {
        let h = try headless()
        let id = UUID()
        let request = try VCFixture.signatureRequest(h.store, key: h.key, signature: signature(), id: id)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(request).isCommitted)
        let retry = h.store.commitVerifiedAnnotationHeadless(request)
        XCTAssertTrue(retry.isExisting, retry.description)
        XCTAssertEqual(try contents(h.journal).records.count, 1, "an existing outcome appends nothing")
        let conflict = try signatureCommit(h, nil, id: id)
        XCTAssertEqual(conflict.refusalCode, .idempotencyConflict, conflict.description)

        let g = try headless()
        let second = try VCFixture.signatureRequest(g.store, key: g.key, signature: signature())
        g.store.verifiedHeadlessBeforeInstallHookForTesting = { throw Injected() }
        let outcome = g.store.commitVerifiedAnnotationHeadless(second)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveNotInstalled, outcome.description)
        XCTAssertNotNil(g.store.verifiedCommitLatch)
        g.store.detachEditJournal()?.close()
        let fresh = try freshAttach(g)
        XCTAssertEqual(try VerifiedFieldCodec.canonicalSignature(try XCTUnwrap(fresh.store.snapshot.addressOverrides[fresh.key]?.signature)),
                       try VerifiedFieldCodec.canonicalSignature(signature()))
        XCTAssertEqual(fresh.store.verifiedAnnotationAudit.records.map(\.operationID), [second.operationID])
    }

    /// Clearing a signature headless is a well-formed erase-to-nothing line that replays.
    func testSignatureHeadlessClearReplays() throws {
        let h = try headless()
        XCTAssertTrue(try signatureCommit(h, signature()).isCommitted)
        XCTAssertTrue(try signatureCommit(h, nil).isCommitted)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key], "the emptied override is pruned")
        guard case .verifiedAnnotation(_, _, _, let changes, let value, let audit) = try contents(h.journal).records[1] else {
            return XCTFail("record kind")
        }
        XCTAssertTrue(changes)
        XCTAssertNil(value)
        XCTAssertEqual(audit.body.fieldClass, .functionSignature)
        h.store.detachEditJournal()?.close()
        let fresh = try freshAttach(h)
        XCTAssertEqual(fresh.report.replayed, 2)
        XCTAssertNil(fresh.store.snapshot.addressOverrides[fresh.key])
    }

    /// Audit mapping (S6b): `functionPrototype` maps to a v2 record with `fieldClass = functionSignature`, bounded by
    /// the codec's 16,384 bytes; name/comment/addressType bounds and classes are unchanged; a rejected receipt stays v1.
    func testSignatureAuditMappingBoundAndFieldClass() throws {
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .functionPrototype), 16_384)
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .functionPrototype),
                       VerifiedFieldCodec.maximumSignatureBytes)
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .functionName), 256)
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .functionComment), 2048)
        XCTAssertEqual(try VerifiedAnnotationAuditRecord.auditValueLimit(for: .addressType), 256)
        let h = try headless()
        // A large but legal signature: 64 rows (the codec's row limit) of long names and types.
        let rows = (0..<64).map { ("r\($0)", String(repeating: "n", count: 120), String(repeating: "t", count: 60)) }
        let large = signature(rows)
        let text = try VerifiedFieldCodec.canonicalSignature(large)
        XCTAssertGreaterThan(text.utf8.count, 2048)
        XCTAssertLessThanOrEqual(text.utf8.count, 16_384)
        let accepted = try VCFixture.signatureRequest(h.store, key: h.key, signature: large)
        let record = try VerifiedAnnotationAuditRecord(receipt: accepted.receipt, nativeEvidenceLinks: accepted.nativeEvidenceLinks)
        XCTAssertEqual(record.body.fieldClass, .functionSignature)
        XCTAssertEqual(VerifiedAnnotationAuditRecord.recordedFieldClass(for: accepted.receipt), .functionSignature)
        let rejected = try VCFixture.signatureRequest(h.store, key: h.key, signature: signature(), accepted: false)
        XCTAssertNil(VerifiedAnnotationAuditRecord.recordedFieldClass(for: rejected.receipt), "a rejected receipt stays v1")
        let rejectedRecord = try VerifiedAnnotationAuditRecord(
            receipt: rejected.receipt, nativeEvidenceLinks: rejected.nativeEvidenceLinks)
        XCTAssertNil(rejectedRecord.body.fieldClass)
        XCTAssertEqual(rejectedRecord.body.domain, VerifiedAnnotationAuditRecord.domain)
    }

    /// (a) One name commit and one comment commit still produce the exact v1 record bytes: re-encoding the record's
    /// fields through an independent copy of the pre-S6b v1 Body shape reproduces the canonical bytes, there is no
    /// `fieldClass`, and the journal lines carry none either. (The diff does not touch the name/comment mapping.)
    func testNameAndCommentRecordBytesStayV1AfterSignatureWiring() throws {
        struct V1Body: Codable {
            let domain: String
            let operationID: UUID
            let requestDigest: String
            let decision: VerifiedAnnotationDecision
            let before: VerifiedAnnotationProjectionIdentity
            let after: VerifiedAnnotationProjectionIdentity?
            let mechanical: VerifiedAnnotationMechanicalResult
            let persistence: VerifiedAnnotationPersistenceStatus
            let failure: String?
            let recovery: String?
            let recordedAtMilliseconds: Int64
            let nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink]
            let checkpointReferences: [VerifiedAnnotationCheckpointReference]
        }
        let h = try headless()
        let name = try VCFixture.request(h.store, key: h.key, name: "n1", id: UUID())
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(name).isCommitted)
        let comment = try VCFixture.request(h.store, key: h.key, name: "c1", id: UUID(), field: .comment)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(comment).isCommitted)
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.count, 2)
        for record in h.store.verifiedAnnotationAudit.records {
            let decoded = try VerifiedAnnotationAuditCodec.decode(V1Body.self, from: record.canonicalBytes)
            XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(decoded), record.canonicalBytes)
            XCTAssertEqual(decoded.domain, VerifiedAnnotationAuditRecord.domain)
            XCTAssertNil(record.body.fieldClass)
        }
        let text = try XCTUnwrap(String(data: Data(contentsOf: h.journal), encoding: .utf8))
        XCTAssertFalse(text.contains("fieldClass"))
        XCTAssertNil(VerifiedAnnotationAuditRecord.recordedFieldClass(for: name.receipt))
        XCTAssertNil(VerifiedAnnotationAuditRecord.recordedFieldClass(for: comment.receipt))
    }
}
#endif
