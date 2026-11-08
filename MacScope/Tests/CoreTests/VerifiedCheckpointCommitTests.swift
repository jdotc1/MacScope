import Foundation
import XCTest
@testable import MacScope

// VA4 slices B, C and E: the fresh-reader checkpoint against receipts written by the real VA3b
// commit paths (session publication and the headless journal), using the production
// NativeAnnotationProjector. The reader is a SECOND store that restores the saved package in this
// process (Option A): it proves the saved bytes suffice. It is not process isolation, so
// `passed` is asserted false here and the literal child-process acceptance stays NOT RUN.
//
// The publisher replaces the package directory, so every read re-canonicalizes the location.
#if DEBUG
@MainActor
final class VerifiedCheckpointCommitTests: XCTestCase {
    private let projector = NativeAnnotationProjector()

    // MARK: Fixtures

    /// Mirrors VCFixture.request, but stamps with the production projector's digest.
    private func request(_ store: WorkspaceStore, key: ImageAddress, name: String? = "verified-name",
                         accepted: Bool = true, id: UUID = UUID(),
                         rationale: String = "VA4 checkpoint test",
                         expecting: String? = nil) throws -> VerifiedAnnotationCommitRequest {
        let accepts = NativeAnnotationProjector.acceptedOrdinal(store.verifiedAnnotationAudit)
        func stamp(_ overrides: [ImageAddress: AddressOverride], _ revision: UInt64) -> VAProjectionStamp {
            VAProjectionStamp(workspaceID: store.workspaceID, documentID: store.documentID,
                              installationID: store.documentInstallationID, revision: revision,
                              digest: NativeAnnotationProjector.digest(overrides))
        }
        let before = stamp(store.snapshot.addressOverrides, accepts)
        var candidate = store.snapshot.addressOverrides
        if accepted {
            var target = candidate[key] ?? AddressOverride()
            VerifiedAnnotationField.name.set(name, in: &target)
            candidate[key] = target.isEmpty ? nil : target
        }
        let after = accepted ? stamp(candidate, accepts + 1) : nil
        let evidenceID = UUID()
        let mutation = VAMutationRequest(
            id: id, base: before,
            edits: [VAEditIntent(target: VATargetReference(componentID: UUID(), function: VAAddress64(key.address)),
                                 kind: .functionName, value: name, evidenceIDs: [evidenceID])],
            rationale: rationale)
        let receipt = try VAVerificationReceipt(
            request: mutation, decision: accepted ? .accepted : .rejected, before: before, after: after,
            mechanical: accepted ? .candidateReadbackVerified : .notVerified,
            persistence: accepted ? .pendingFreshProcessCheckpoint : .notApplicable,
            failure: accepted ? nil : "candidate mismatch", recordedAt: Date(timeIntervalSince1970: 1234.5))
        let projection = VAWorkspaceProjection(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, revision: accepts, components: [])
        return VerifiedAnnotationCommitRequest(
            state: VAVerificationState(projection: projection, receipts: [receipt]), receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))],
            target: accepted ? key : nil, field: accepted ? .name : nil, requested: accepted ? name : nil,
            expectingVersion: expecting ?? store.verifiedCommitVersionToken(), projector: projector)
    }

    private func operation(_ request: VerifiedAnnotationCommitRequest, key: ImageAddress,
                           baseline: String? = nil) -> VerifiedCheckpointExpectation.Operation {
        let before = request.receipt.before.revision
        return .init(operationID: request.operationID, requestDigest: request.receipt.requestDigest,
                     decision: request.isAccepted ? .accepted : .rejected, slot: key.slot.rawValue,
                     address: key.address, field: "name", requested: request.requested ?? "verified-name",
                     baseline: baseline, imageSHA256: nil, beforeRevision: before,
                     afterRevision: request.isAccepted ? before + 1 : nil)
    }

    private func expectation(_ store: WorkspaceStore, _ operations: [VerifiedCheckpointExpectation.Operation],
                             writerInstallations: [UUID]) -> VerifiedCheckpointExpectation {
        .init(schemaVersion: 1, workspaceID: store.workspaceID, documentID: store.documentID,
              writerInstallationIDs: writerInstallations,
              writerProcessID: ProcessInfo.processInfo.processIdentifier, operations: operations)
    }

    /// A second store restored from the saved package, with a fresh document installation.
    private func reader(_ location: WorkspaceDocumentLocation) throws -> WorkspaceStore {
        let fresh = try WorkspaceDocumentLocation.canonicalized(from: location.canonicalURL)
        let store = try WorkspaceStore.restoredPackage(from: fresh.canonicalURL)
        store.recents = VCQuietRecents()
        return store
    }

    private func commitOK(_ h: VCSession, _ request: VerifiedAnnotationCommitRequest,
                          file: StaticString = #filePath, line: UInt = #line) async throws {
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(outcome.isCommitted, outcome.description, file: file, line: line)
    }

    // MARK: Slice B: projector

    func testProjectorCoversOnlyNameAndCommentInStableOrder() {
        let slot = ImageSlot.primary
        var a = AddressOverride(); a.customName = "alpha"
        var b = AddressOverride(); b.customComment = "beta"
        var c = AddressOverride(); c.tag = "ignored"
        let first: [ImageAddress: AddressOverride] = [.init(slot: slot, address: 8): b, .init(slot: slot, address: 4): a]
        let second: [ImageAddress: AddressOverride] = [.init(slot: slot, address: 4): a, .init(slot: slot, address: 8): b]
        XCTAssertEqual(NativeAnnotationProjector.digest(first), NativeAnnotationProjector.digest(second))
        // A field the gate does not compare leaves the stamp unchanged.
        var withTag = first
        withTag[.init(slot: slot, address: 12)] = c
        XCTAssertEqual(NativeAnnotationProjector.digest(withTag), NativeAnnotationProjector.digest(first))
        var renamed = first
        renamed[.init(slot: slot, address: 4)]?.customName = "changed"
        XCTAssertNotEqual(NativeAnnotationProjector.digest(renamed), NativeAnnotationProjector.digest(first))
        XCTAssertEqual(NativeAnnotationProjector.digest([:]).count, 64)
    }

    func testProjectorEchoesTheServiceRevisionAndOrdinalCountsAcceptedOnly() throws {
        let stamp = try projector.stamp(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
                                        snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [:]), revision: 7)
        XCTAssertEqual(stamp.revision, 7)
        XCTAssertEqual(NativeAnnotationProjector.acceptedOrdinal(nil), 0)
        XCTAssertEqual(NativeAnnotationProjector.acceptedOrdinal(.empty), 0)
    }

    // MARK: P1, P2, P3, P4, P6, P7: session mode

    func testP1CommitSaveThenFreshStoreConfirms() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try request(h.store, key: h.key)
        let outcome = await h.session.commitVerifiedAnnotation(req)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        let writerInstallation = h.store.documentInstallationID
        let second = try reader(h.location)
        XCTAssertNotEqual(second.documentInstallationID, writerInstallation)
        let report = second.verifiedCheckpoint(expectation(h.store, [operation(req, key: h.key)],
                                                          writerInstallations: [writerInstallation]))
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertFalse(report.processIsolated, "same process: never the literal acceptance")
        XCTAssertFalse(report.passed)
        // Slice B: the production projector reproduces the archived stamp digest after a reopen.
        XCTAssertTrue(report.notes.contains("stamp digest reproduced at last accepted record"), "\(report.notes)")
    }

    /// VA-SCOPE S5 (a): a name expectation for a real commit is still written as schema 1 with no typed keys,
    /// survives the request-file round trip, and is judged by a fresh store exactly as before.
    func testS5NameCommitExpectationStaysSchema1AndRoundTripsThroughTheRequestFile() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try request(h.store, key: h.key)
        try await commitOK(h, req)
        let writerInstallation = h.store.documentInstallationID
        let written = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [writerInstallation])
        let bytes = try written.encoded()
        let text = String(decoding: bytes, as: UTF8.self)
        XCTAssertTrue(text.contains("\"schemaVersion\":1"), text)
        XCTAssertFalse(text.contains("fieldClass") || text.contains("requestedDigest"), text)
        let decoded = try VerifiedCheckpointExpectation.decode(bytes)
        XCTAssertEqual(decoded, written)
        let report = try reader(h.location).verifiedCheckpoint(decoded)
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        // The simulated old reader reads the same bytes: v1 stays readable by a schema-1-only validate.
        XCTAssertNoThrow(try VerifiedCheckpointExpectation.decode(bytes, supportedSchemaVersions: 1...1))
    }

    func testP2RejectedCommitIsRecordedAndLeavesNoAnnotation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try request(h.store, key: h.key, accepted: false)
        let outcome = await h.session.commitVerifiedAnnotation(req)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(expectation(h.store, [operation(req, key: h.key)],
                                                          writerInstallations: [h.store.documentInstallationID]))
        XCTAssertEqual(report.operations.map(\.outcome), [.rejectedRecorded])
    }

    func testP3TwoCommitsKeepTheAcceptedChain() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let first = try request(h.store, key: h.key, name: "first-name")
        try await commitOK(h, first)
        let secondRequest = try request(h.store, key: h.fixture.other, name: "second-name")
        try await commitOK(h, secondRequest)
        let second = try reader(h.location)
        var expected = [operation(first, key: h.key)]
        expected.append(operation(secondRequest, key: h.fixture.other))
        let report = second.verifiedCheckpoint(expectation(h.store, expected, writerInstallations: [h.store.documentInstallationID]))
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed, .confirmed])
        XCTAssertEqual(first.receipt.before.revision, 0)
        XCTAssertEqual(secondRequest.receipt.before.revision, 1, "VA3b revision is the accepted ordinal")
    }

    func testP4LaterManualEditSavedOverTheReceiptIsAMismatchNotAConfirmation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try request(h.store, key: h.key)
        try await commitOK(h, req)
        h.store.setCustomName(h.key.address, in: h.key.slot, name: "manual-later")
        let saved = await h.session.save()
        guard case .saved = saved else { return XCTFail("\(saved)") }
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(expectation(h.store, [operation(req, key: h.key)],
                                                          writerInstallations: [h.store.documentInstallationID]))
        XCTAssertEqual(report.operations.first?.outcome.code, "mismatch")
        XCTAssertFalse(report.allOperationsPass)
        // Clearing the name instead leaves a receipt with no effect.
        h.store.setCustomName(h.key.address, in: h.key.slot, name: nil)
        guard case .saved = await h.session.save() else { return XCTFail("second save") }
        let cleared = try reader(h.location).verifiedCheckpoint(expectation(h.store, [operation(req, key: h.key)],
            writerInstallations: [h.store.documentInstallationID]))
        XCTAssertEqual(cleared.operations.map(\.outcome), [.receiptWithoutEffect])
    }

    func testP6RefusedCommitLeavesThePackageWithoutTheOperation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        h.publisher.failStage = true
        let req = try request(h.store, key: h.key)
        let outcome = await h.session.commitVerifiedAnnotation(req)
        XCTAssertEqual(outcome.refusalCode, .stageFailed, outcome.description)
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(expectation(h.store, [operation(req, key: h.key)],
                                                          writerInstallations: [h.store.documentInstallationID]))
        XCTAssertEqual(report.packageOutcome, .auditUnattached, "no receipt was ever written")
        XCTAssertFalse(report.allOperationsPass)
    }

    func testP7ReaderStoreCannotBeTheWritersInstallation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try request(h.store, key: h.key)
        try await commitOK(h, req)
        // The writer's own live store shares its installation with the archived records.
        let live = h.store.verifiedCheckpoint(expectation(h.store, [operation(req, key: h.key)],
                                                         writerInstallations: [h.store.documentInstallationID]))
        XCTAssertEqual(live.packageOutcome, .installationNotFresh)
        XCTAssertFalse(live.passed)
    }

    // MARK: VA-SCOPE E2E: real S4 typed commit -> real S5/S5b checkpoint (address type)

    private func typedOperation(_ request: VerifiedAnnotationCommitRequest, key: ImageAddress, type: String,
                                baseline: String? = nil, erase: Bool = false) -> VerifiedCheckpointExpectation.Operation {
        let before = request.receipt.before.revision
        return VerifiedCheckpointExpectation.Operation.addressType(
            operationID: request.operationID, requestDigest: request.receipt.requestDigest,
            decision: request.isAccepted ? .accepted : .rejected, slot: key.slot.rawValue,
            address: key.address, requested: erase ? "" : type, baseline: baseline,
            beforeRevision: before, afterRevision: request.isAccepted ? before + 1 : nil, erase: erase)
    }

    private func typedExpectation(_ store: WorkspaceStore, _ operations: [VerifiedCheckpointExpectation.Operation],
                                  writerInstallations: [UUID]) -> VerifiedCheckpointExpectation {
        .init(schemaVersion: 2, workspaceID: store.workspaceID, documentID: store.documentID,
              writerInstallationIDs: writerInstallations,
              writerProcessID: ProcessInfo.processInfo.processIdentifier, operations: operations)
    }

    /// Writes the expectation through `encoded()` and reads it back through `decode` (the request-file round trip).
    private func roundTripped(_ written: VerifiedCheckpointExpectation) throws -> VerifiedCheckpointExpectation {
        let decoded = try VerifiedCheckpointExpectation.decode(try written.encoded())
        XCTAssertEqual(decoded, written)
        return decoded
    }

    /// E1: accepted addressType commit, saved, fresh store: confirmed; the expectation is schema 2 with the class
    /// and the requested digest.
    func testE1AcceptedTypeCommitIsConfirmedAndTheExpectationRoundTripsAsSchema2() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        let req = try h.typedRequest(type: "Header")
        try await commitOK(h, req)
        let writerInstallation = h.store.documentInstallationID
        let written = typedExpectation(h.store, [typedOperation(req, key: h.typedKey, type: "Header")],
                                       writerInstallations: [writerInstallation])
        let text = String(decoding: try written.encoded(), as: UTF8.self)
        XCTAssertTrue(text.contains("\"schemaVersion\":2"), text)
        XCTAssertTrue(text.contains("\"fieldClass\":\"addressType\""), text)
        XCTAssertTrue(text.contains("\"requestedDigest\":\""), text)
        XCTAssertFalse(text.contains("\"erase\""), text)
        let decoded = try roundTripped(written)
        let second = try reader(h.location)
        XCTAssertNotEqual(second.documentInstallationID, writerInstallation)
        let report = second.verifiedCheckpoint(decoded)
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertEqual(second.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
    }

    /// E2: a real rejected typed commit is recorded as a v1 record with no class; the checkpoint reports
    /// rejectedRecorded and no annotation is installed (regression for the S5b class guard).
    func testE2RejectedTypeCommitIsRecordedWithoutAClassAndLeavesNoAnnotation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        let req = try VCFixture.typedRequest(h.store, key: h.typedKey, type: "Header", accepted: false)
        try await commitOK(h, req)
        let record = try XCTUnwrap(h.store.verifiedAnnotationAudit.records.first)
        XCTAssertNil(record.body.fieldClass, "a rejected receipt is a v1 record with no class")
        let written = typedExpectation(h.store, [typedOperation(req, key: h.typedKey, type: "Header")],
                                       writerInstallations: [h.store.documentInstallationID])
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(try roundTripped(written))
        XCTAssertEqual(report.operations.map(\.outcome), [.rejectedRecorded], "\(report.operations)")
        XCTAssertNil(second.snapshot.addressOverrides[h.typedKey]?.appliedTypeName)
    }

    /// E3: a later manual type edit saved over the receipt is a value mismatch, not a confirmation.
    func testE3LaterManualTypeEditSavedOverTheReceiptIsAMismatchNotAConfirmation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        VCFixture.addType(h.store, "Other")
        let req = try h.typedRequest(type: "Header")
        try await commitOK(h, req)
        let wanted = try roundTripped(typedExpectation(
            h.store, [typedOperation(req, key: h.typedKey, type: "Header")],
            writerInstallations: [h.store.documentInstallationID]))
        h.store.setAppliedType(h.typedKey.address, in: h.typedKey.slot, name: "Other")
        let saved = await h.session.save()
        guard case .saved = saved else { return XCTFail("\(saved)") }
        let report = try reader(h.location).verifiedCheckpoint(wanted)
        guard case .mismatch(let field, _, let observed)? = report.operations.first?.outcome else {
            return XCTFail("\(report.operations)")
        }
        XCTAssertEqual(field, "value")
        XCTAssertTrue(observed.contains("Other"), observed)
        XCTAssertFalse(report.allOperationsPass)
        // Clearing the type instead leaves a receipt with no effect.
        h.store.setAppliedType(h.typedKey.address, in: h.typedKey.slot, name: nil)
        let savedAgain = await h.session.save()
        guard case .saved = savedAgain else { return XCTFail("second save: \(savedAgain)") }
        let cleared = try reader(h.location).verifiedCheckpoint(wanted)
        XCTAssertEqual(cleared.operations.map(\.outcome), [.receiptWithoutEffect], "\(cleared.operations)")
    }

    /// E5: a typed erase of an applied type: expectation with erase true and the old name as baseline is
    /// confirmed, and the override no longer has a type.
    func testE5TypedEraseIsConfirmedAndTheOverrideHasNoType() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        try await commitOK(h, try h.typedRequest(type: "Header"))
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
        let erase = try h.typedRequest(type: nil)
        try await commitOK(h, erase)
        let written = typedExpectation(
            h.store, [typedOperation(erase, key: h.typedKey, type: "", baseline: "Header", erase: true)],
            writerInstallations: [h.store.documentInstallationID])
        let text = String(decoding: try written.encoded(), as: UTF8.self)
        XCTAssertTrue(text.contains("\"erase\":true"), text)
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(try roundTripped(written))
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        XCTAssertNil(second.snapshot.addressOverrides[h.typedKey]?.appliedTypeName)
    }

    /// E6: the type definition is removed (then two same-named definitions exist) after the commit and saved:
    /// mismatch on typeDefinition, never a confirmation.
    func testE6TypeDefinitionRemovedOrDuplicatedAfterTheCommitIsATypeDefinitionMismatch() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let header = VCFixture.addType(h.store, "Header")
        let req = try h.typedRequest(type: "Header")
        try await commitOK(h, req)
        let wanted = try roundTripped(typedExpectation(
            h.store, [typedOperation(req, key: h.typedKey, type: "Header")],
            writerInstallations: [h.store.documentInstallationID]))
        h.store.deleteTypeDefinition(id: header.id)
        let saved = await h.session.save()
        guard case .saved = saved else { return XCTFail("\(saved)") }
        let removed = try reader(h.location).verifiedCheckpoint(wanted)
        guard case .mismatch(let field, _, let observed)? = removed.operations.first?.outcome else {
            return XCTFail("removed: \(removed.operations)")
        }
        XCTAssertEqual(field, "typeDefinition")
        XCTAssertEqual(observed, "0")
        XCTAssertFalse(removed.allOperationsPass)
        // Two live definitions with the same name: the persistent store keeps one definition per name
        // (UNIQUE (workspace_id, name), WorkspaceDatabase.typeDefinitionsSchemaSQL), so a reopened workspace
        // resolves exactly one and the judge confirms. The exactly-one guard covers in-memory subjects.
        h.store.upsertTypeDefinition(TypeDefinition(kind: .struct, name: "Header"))
        h.store.upsertTypeDefinition(TypeDefinition(kind: .struct, name: "Header"))
        XCTAssertEqual(h.store.snapshot.typeDefinitions.filter { $0.name == "Header" }.count, 2)
        let savedAgain = await h.session.save()
        guard case .saved = savedAgain else { return XCTFail("second save: \(savedAgain)") }
        let second = try reader(h.location)
        let duplicated = second.verifiedCheckpoint(wanted)
        XCTAssertEqual(second.snapshot.typeDefinitions.filter { $0.name == "Header" }.count, 1)
        XCTAssertEqual(duplicated.operations.first?.outcome, .confirmed)
    }

    // MARK: Headless journal tier: P5, H1-H4

    private struct Headless {
        let fixture: VCFixture.Store
        let package: URL
        let journal: URL
        let store: WorkspaceStore
        let key: ImageAddress
    }

    private func headless(types: [String] = []) throws -> Headless {
        let fixture = try VCFixture.makeStore(self)
        for name in types { VCFixture.addType(fixture.store, name) }
        let package = fixture.root.appendingPathComponent("Base.mscope")
        _ = try fixture.store.writeDocumentPackageThrowing(to: package)
        let store = try WorkspaceStore.restoredPackage(from: package)
        let journal = fixture.root.appendingPathComponent("edits.journal")
        try store.attachEditJournal(at: journal)
        return Headless(fixture: fixture, package: package, journal: journal, store: store,
                        key: ImageAddress(slot: store.snapshot.primarySlot, address: fixture.base))
    }

    private func restart(_ h: Headless) throws -> (store: WorkspaceStore, report: EditJournalReport) {
        let store = try WorkspaceStore.restoredPackage(from: h.package)
        store.recents = VCQuietRecents()
        return (store, try store.attachEditJournal(at: h.journal))
    }

    func testP5CommitCrashBeforeSaveIsConfirmedFromTheJournal() throws {
        let h = try headless()
        let req = try request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(req).isCommitted)
        let writerInstallation = h.store.documentInstallationID
        let wanted = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [writerInstallation])
        h.store.detachEditJournal()?.close()   // the writer "crashes": the package was never saved
        let again = try restart(h)
        XCTAssertEqual(again.report.replayed, 1)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmedFromJournal])
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertNil(report.journalTornTailBytes)
        XCTAssertEqual(report.unattachedAuditRecords, [])
        // Without the journal the same package has nothing to confirm.
        let bare = try WorkspaceStore.restoredPackage(from: h.package)
        XCTAssertEqual(bare.verifiedCheckpoint(wanted).packageOutcome, .auditUnattached)
    }

    func testJournalOnlyRejectionKeepsItsMeaningAndAcceptanceStaysConfirmedFromJournal() throws {
        let h = try headless()
        let rejected = try request(h.store, key: h.fixture.other, accepted: false)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(rejected).isCommitted)
        let accepted = try request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(accepted).isCommitted)
        let wanted = expectation(h.store, [operation(rejected, key: h.fixture.other), operation(accepted, key: h.key)],
                                 writerInstallations: [h.store.documentInstallationID])
        h.store.detachEditJournal()?.close()   // the package was never saved: both records come from the journal
        let again = try restart(h)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.rejectedRecordedFromJournal, .confirmedFromJournal],
                       "\(report.operations)")
        XCTAssertEqual(report.operations.first?.outcome.code, "rejectedRecordedFromJournal")
        XCTAssertTrue(report.allOperationsPass)
    }

    func testH1AppendFailureLeavesTheOperationAbsentAfterRestart() throws {
        let h = try headless()
        h.store.editJournal?.appendHook = { _ in throw NSError(domain: "VA4", code: 1) }
        let req = try request(h.store, key: h.key)
        XCTAssertEqual(h.store.commitVerifiedAnnotationHeadless(req).indeterminateCode, .journalAppendUncertain)
        let wanted = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [h.store.documentInstallationID])
        h.store.detachEditJournal()?.close()
        let again = try restart(h)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.operationAbsent])
        XCTAssertFalse(report.allOperationsPass)
    }

    func testH2UnsyncedLineIsNeverHalfConfirmed() throws {
        let h = try headless()
        h.store.editJournal?.beforeAppendSyncForTesting = { _ in throw NSError(domain: "VA4", code: 2) }
        let req = try request(h.store, key: h.key)
        XCTAssertEqual(h.store.commitVerifiedAnnotationHeadless(req).indeterminateCode, .journalAppendUncertain)
        let wanted = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [h.store.documentInstallationID])
        h.store.detachEditJournal()?.close()
        let again = try restart(h)
        let outcome = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: []).operations.first?.outcome
        // The line may or may not have reached the file; either way receipt and value agree.
        XCTAssertTrue(outcome == .confirmedFromJournal || outcome == .operationAbsent, "\(String(describing: outcome))")
    }

    func testH3DurableLineNotInstalledLiveIsConfirmedFromTheJournalAfterRestart() throws {
        let h = try headless()
        h.store.verifiedHeadlessBeforeInstallHookForTesting = { throw NSError(domain: "VA4", code: 3) }
        let req = try request(h.store, key: h.key)
        XCTAssertEqual(h.store.commitVerifiedAnnotationHeadless(req).indeterminateCode, .committedLiveNotInstalled)
        let wanted = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [h.store.documentInstallationID])
        h.store.detachEditJournal()?.close()
        let again = try restart(h)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmedFromJournal])
    }

    func testH4TornTailIsReportedAndTheOperationIsAbsent() throws {
        let h = try headless()
        let req = try request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(req).isCommitted)
        let wanted = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [h.store.documentInstallationID])
        h.store.detachEditJournal()?.close()
        var bytes = try Data(contentsOf: h.journal)
        let newlines = bytes.indices.filter { bytes[$0] == 10 }
        bytes = bytes.prefix(newlines[newlines.count - 2] + 1 + 40)
        try bytes.write(to: h.journal)
        let again = try restart(h)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.operationAbsent])
        XCTAssertNotNil(report.journalTornTailBytes)
        XCTAssertTrue(report.notes.contains { $0.hasPrefix("journal torn tail:") }, "\(report.notes)")
        XCTAssertFalse(report.passed)
    }

    func testForeignOwnerJournalRecordIsAuditUnattached() throws {
        let h = try headless()
        let req = try request(h.store, key: h.key)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(req).isCommitted)
        let wanted = expectation(h.store, [operation(req, key: h.key)], writerInstallations: [h.store.documentInstallationID])
        h.store.detachEditJournal()?.close()
        let other = try VCFixture.makeStore(self)
        other.store.recents = VCQuietRecents()
        let journalReport = try other.store.attachEditJournal(at: h.journal)
        // The same expectation, judged against a different workspace's store, is an identity finding;
        // the journal facts still name the foreign record.
        let sameOwner = VerifiedCheckpointExpectation(schemaVersion: 1, workspaceID: other.store.workspaceID,
            documentID: other.store.documentID, writerInstallationIDs: wanted.writerInstallationIDs,
            writerProcessID: wanted.writerProcessID, operations: wanted.operations)
        let report = other.store.verifiedCheckpoint(sameOwner, journal: journalReport, savedOperationIDs: [])
        XCTAssertEqual(report.unattachedAuditRecords, [req.operationID])
        XCTAssertEqual(report.operations.map(\.outcome), [.auditUnattached])
        XCTAssertFalse(report.allOperationsPass)
    }

    /// E4: a typed headless commit, crash before save, is confirmed from the journal after a restart.
    func testE4TypedCommitCrashBeforeSaveIsConfirmedFromTheJournal() throws {
        let h = try headless(types: ["Header"])
        let typedKey = h.fixture.other
        let req = try VCFixture.typedRequest(h.store, key: typedKey, type: "Header")
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(req).isCommitted)
        let writerInstallation = h.store.documentInstallationID
        let wanted = try roundTripped(typedExpectation(
            h.store, [typedOperation(req, key: typedKey, type: "Header")], writerInstallations: [writerInstallation]))
        h.store.detachEditJournal()?.close()   // the writer "crashes": the package was never saved
        let again = try restart(h)
        XCTAssertEqual(again.report.replayed, 1)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmedFromJournal], "\(report.operations)")
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertEqual(again.store.snapshot.addressOverrides[typedKey]?.appliedTypeName, "Header")
        // Without the journal the same package has nothing to confirm.
        let bare = try WorkspaceStore.restoredPackage(from: h.package)
        XCTAssertEqual(bare.verifiedCheckpoint(wanted).packageOutcome, .auditUnattached)
    }

    // MARK: VA-SCOPE E2E: real S6b signature commit -> real S5b checkpoint (function signature)

    private func sigA() -> FunctionSignatureOverride {
        VCFixture.signature([("tok-a1", "buf", "char *"), ("tok-a2", "len", "size_t")], returnType: "ssize_t")
    }

    private func sigB() -> FunctionSignatureOverride {
        VCFixture.signature([("tok-b1", "fd", "int")], returnType: "int")
    }

    private func canon(_ signature: FunctionSignatureOverride) throws -> String {
        try VerifiedFieldCodec.canonicalSignature(signature)
    }

    private func canonOrNil(_ signature: FunctionSignatureOverride?) throws -> String? {
        try signature.map(VerifiedFieldCodec.canonicalSignature)
    }

    private func signatureOperation(_ request: VerifiedAnnotationCommitRequest, key: ImageAddress, requested: String,
                                    baseline: String? = nil, erase: Bool = false) -> VerifiedCheckpointExpectation.Operation {
        let before = request.receipt.before.revision
        return VerifiedCheckpointExpectation.Operation.functionSignature(
            operationID: request.operationID, requestDigest: request.receipt.requestDigest,
            decision: request.isAccepted ? .accepted : .rejected, slot: key.slot.rawValue,
            address: key.address, requested: erase ? "" : requested, baseline: baseline,
            beforeRevision: before, afterRevision: request.isAccepted ? before + 1 : nil, erase: erase)
    }

    /// S1: accepted signature commit, saved, fresh store: confirmed. The expectation is schema 2 with the class,
    /// the canonical requested text and its digest. The text and JSON are dumped for FORMAT.md when asked.
    func testS1AcceptedSignatureCommitIsConfirmedAndTheExpectationRoundTripsAsSchema2() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let requested = sigA()
        let text = try canon(requested)
        let req = try h.signatureRequest(signature: requested)
        try await commitOK(h, req)
        let writerInstallation = h.store.documentInstallationID
        let written = typedExpectation(h.store, [signatureOperation(req, key: h.key, requested: text)],
                                       writerInstallations: [writerInstallation])
        let bytes = try written.encoded()
        let json = String(decoding: bytes, as: UTF8.self)
        XCTAssertTrue(json.contains("\"schemaVersion\":2"), json)
        XCTAssertTrue(json.contains("\"fieldClass\":\"functionSignature\""), json)
        XCTAssertTrue(json.contains("\"requestedDigest\":\""), json)
        XCTAssertFalse(json.contains("\"erase\""), json)
        let decoded = try roundTripped(written)
        let operation = try XCTUnwrap(decoded.operations.first)
        XCTAssertEqual(operation.fieldClass, "functionSignature")
        XCTAssertEqual(operation.requested, text)
        XCTAssertEqual(operation.requestedDigest, VerifiedAnnotationAuditCodec.sha256Hex(Data(text.utf8)))
        if let path = ProcessInfo.processInfo.environment["MACSCOPE_SIG_E2E_DUMP"], !path.isEmpty {
            let dump = "CANONICAL_SIGNATURE=\(text)\nEXPECTATION_JSON=\(json)\n"
            try dump.write(toFile: path, atomically: true, encoding: .utf8)
        }
        let second = try reader(h.location)
        XCTAssertNotEqual(second.documentInstallationID, writerInstallation)
        let report = second.verifiedCheckpoint(decoded)
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertEqual(try canonOrNil(second.snapshot.addressOverrides[h.key]?.signature), text)
    }

    /// S2: a real rejected signature receipt is recorded as a v1 record with no class; rejectedRecorded, and no
    /// signature is installed.
    func testS2RejectedSignatureCommitIsRecordedAndInstallsNoSignature() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let requested = sigA()
        let req = try VCFixture.signatureRequest(h.store, key: h.key, signature: requested, accepted: false)
        try await commitOK(h, req)
        let record = try XCTUnwrap(h.store.verifiedAnnotationAudit.records.first)
        XCTAssertNil(record.body.fieldClass, "a rejected receipt is a v1 record with no class")
        let written = typedExpectation(h.store, [signatureOperation(req, key: h.key, requested: try canon(requested))],
                                       writerInstallations: [h.store.documentInstallationID])
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(try roundTripped(written))
        XCTAssertEqual(report.operations.map(\.outcome), [.rejectedRecorded], "\(report.operations)")
        XCTAssertNil(second.snapshot.addressOverrides[h.key]?.signature)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.signature)
    }

    /// S3: a later manual signature edit saved over the receipt is a value mismatch, not a confirmation.
    func testS3LaterManualSignatureEditSavedOverTheReceiptIsAMismatchNotAConfirmation() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let requested = sigA()
        let req = try h.signatureRequest(signature: requested)
        try await commitOK(h, req)
        let wanted = try roundTripped(typedExpectation(
            h.store, [signatureOperation(req, key: h.key, requested: try canon(requested))],
            writerInstallations: [h.store.documentInstallationID]))
        h.store.setSignature(h.key.address, sigB())
        let saved = await h.session.save()
        guard case .saved = saved else { return XCTFail("\(saved)") }
        let report = try reader(h.location).verifiedCheckpoint(wanted)
        guard case .mismatch(let field, _, let observed)? = report.operations.first?.outcome else {
            return XCTFail("\(report.operations)")
        }
        XCTAssertEqual(field, "value")
        // The report shows a quoted, length-capped rendering of the observed text, so match the manual edit's content.
        XCTAssertTrue(observed.contains("\"name\":\"fd\""), observed)
        XCTAssertFalse(observed.contains("\"name\":\"buf\""), observed)
        XCTAssertFalse(report.allOperationsPass)
    }

    /// S4: a headless signature commit, crash before save, is confirmed from the journal after a restart.
    func testS4SignatureCommitCrashBeforeSaveIsConfirmedFromTheJournal() throws {
        let h = try headless()
        let requested = sigA()
        let text = try canon(requested)
        let req = try VCFixture.signatureRequest(h.store, key: h.key, signature: requested)
        XCTAssertTrue(h.store.commitVerifiedAnnotationHeadless(req).isCommitted)
        let wanted = try roundTripped(typedExpectation(
            h.store, [signatureOperation(req, key: h.key, requested: text)],
            writerInstallations: [h.store.documentInstallationID]))
        h.store.detachEditJournal()?.close()   // the writer "crashes": the package was never saved
        let again = try restart(h)
        XCTAssertEqual(again.report.replayed, 1)
        let report = again.store.verifiedCheckpoint(wanted, journal: again.report, savedOperationIDs: [])
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmedFromJournal], "\(report.operations)")
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertEqual(try canonOrNil(again.store.snapshot.addressOverrides[h.key]?.signature), text)
        // Without the journal the same package has nothing to confirm.
        let bare = try WorkspaceStore.restoredPackage(from: h.package)
        XCTAssertEqual(bare.verifiedCheckpoint(wanted).packageOutcome, .auditUnattached)
    }

    /// S5: clearing a user signature at a function with an imported prototype. The checkpoint judges the RAW
    /// override (`addressOverrides[key].signature`), not the effective leg: an erase expects the override to be
    /// absent, so it is confirmed even though the effective signature falls back to the imported prototype.
    func testS5SignatureEraseOverAnImportedPrototypeIsConfirmedOnTheRawOverride() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let imported = VCFixture.signature([("imp", "x", "double")], returnType: "double")
        let importedText = try canon(imported)
        h.store.snapshot.importedPrototypes[h.key] = imported
        // A pending manual edit elsewhere dirties the document so the first commit persists the prototype too.
        h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "pending")
        let requested = sigA()
        let oldText = try canon(requested)
        try await commitOK(h, try h.signatureRequest(signature: requested))
        let erase = try h.signatureRequest(signature: nil)
        try await commitOK(h, erase)
        let written = typedExpectation(
            h.store, [signatureOperation(erase, key: h.key, requested: "", baseline: oldText, erase: true)],
            writerInstallations: [h.store.documentInstallationID])
        let json = String(decoding: try written.encoded(), as: UTF8.self)
        XCTAssertTrue(json.contains("\"erase\":true"), json)
        XCTAssertTrue(json.contains("\"baseline\""), json)
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(try roundTripped(written))
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        XCTAssertNil(second.snapshot.addressOverrides[h.key]?.signature)
        // Separately: the effective signature falls back to the imported prototype, live and in the fresh store.
        let liveEffective = try canonOrNil(h.store.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address])
        XCTAssertEqual(liveEffective, importedText)
        let freshEffective = try canonOrNil(second.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address])
        XCTAssertEqual(freshEffective, importedText)
    }

    /// S6: a quarantine-only signature commits (S6b) and is judged on the raw override like any other value.
    func testS6QuarantineOnlySignatureCommitGoesThroughTheCheckpoint() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let quarantined = FunctionSignatureOverride(
            returnType: nil, parameterList: .unspecified, variadicState: .unspecified,
            quarantinedLegacyArgs: [LegacyArgOverride(originalIndex: 0, originalOrder: 0, name: "a", type: "int")],
            noReturnState: .unspecified)
        XCTAssertFalse(quarantined.hasAnalysisEffect)
        let text = try canon(quarantined)
        let req = try h.signatureRequest(signature: quarantined)
        try await commitOK(h, req)
        let wanted = try roundTripped(typedExpectation(
            h.store, [signatureOperation(req, key: h.key, requested: text)],
            writerInstallations: [h.store.documentInstallationID]))
        let second = try reader(h.location)
        let report = second.verifiedCheckpoint(wanted)
        XCTAssertEqual(report.operations.map(\.outcome), [.confirmed], "\(report.operations)")
        XCTAssertEqual(try canonOrNil(second.snapshot.addressOverrides[h.key]?.signature), text)
        XCTAssertNil(second.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address])
    }
}
#endif
