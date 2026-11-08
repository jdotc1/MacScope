import Combine
import Foundation
import XCTest
@testable import MacScope

// VA3b session-mode tests (DESIGN.md section 9, items 1-13). Every test ends in the SPEC row VA3
// contract: the canonical document and the receipt agree, or the backend refuses further mutation
// as indeterminate. Real reader, real probe, real publisher; faults are injected only at the
// documented seams.
#if DEBUG
@MainActor
final class VerifiedAnnotationCommitTests: XCTestCase {

    // MARK: Happy path and item 13

    func testCommitPublishesEditAndReceiptTogetherAndLeavesDocumentClean() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        guard case .committed(let snapshot, let info) = outcome else { return XCTFail(outcome.description) }
        XCTAssertTrue(info.annotationInstalled)
        XCTAssertFalse(info.liveAdvanced)
        XCTAssertEqual(snapshot.version, h.store.verifiedCommitVersionToken())
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "verified-name")
        XCTAssertFalse(h.store.hasUnsavedChanges, "Q2: the commit persists pending edits and ends clean")
        XCTAssertNil(h.store.verifiedCommitLatch)
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(disk.overrides[h.key]?.customName, "verified-name")
        try await h.assertAgreeOrLatched()
    }

    func testPendingManualEditIsPersistedByTheCommit() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "manual-before")
        XCTAssertTrue(h.store.hasUnsavedChanges)
        let outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        let disk = try await h.disk()
        XCTAssertEqual(disk.overrides[h.fixture.other]?.customName, "manual-before")
        XCTAssertFalse(h.store.hasUnsavedChanges)
    }

    func testVerifiedEditSurvivesReopenWithItsReceipt() async throws {
        let h = try await VCSession(test: self)
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        let liveEnvelope = try VerifiedAnnotationAuditCodec.encode(h.store.verifiedAnnotationAudit)
        let liveMirror = h.store.navigatorState(for: h.key.slot)?.state()
        h.session.close()

        // The publisher replaced the package directory; re-observe its identity once for every later read/install/bind.
        let reopened = try WorkspaceDocumentLocation.canonicalized(from: h.location.canonicalURL)
        let package = try await WorkspaceDocumentReader().readValidated(from: reopened)
        let fresh = WorkspaceStore(workspaceName: "", snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [:]),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        fresh.recents = VCQuietRecents()
        try fresh.installValidatedPackage(package, from: reopened)
        XCTAssertEqual(fresh.snapshot.addressOverrides[h.key]?.customName, "verified-name")
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(fresh.verifiedAnnotationAudit), liveEnvelope)
        XCTAssertEqual(fresh.navigatorState(for: h.key.slot)?.state(), liveMirror)
        XCTAssertEqual(fresh.verifiedCommitIdempotency(for: request), .exact)
    }

    func testInterruptedOrRejectedCandidateLeavesAcceptedWorkspaceUnchanged() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let baseline = VCFixture.dump(h.store)
        let diskBefore = try VCFixture.tree(h.destination)

        // Stage failure.
        h.publisher.failStage = true
        var outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .stageFailed, outcome.description)
        h.publisher.failStage = false
        XCTAssertEqual(VCFixture.dump(h.store), baseline)

        // Failure after staging, before publication.
        h.publisher.failBeforePublish = true
        outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .publishFailed, outcome.description)
        h.publisher.failBeforePublish = false
        XCTAssertEqual(VCFixture.dump(h.store), baseline)

        // Wrong version token and a receipt whose stamps do not match the native state.
        outcome = await h.session.commitVerifiedAnnotation(try h.request(expecting: "bogus"))
        XCTAssertEqual(outcome.refusalCode, .staleVersion)
        let lying = VerifiedCommitProjector()
        lying.lieOnCall = 1
        outcome = await h.session.commitVerifiedAnnotation(try h.request(projector: lying))
        XCTAssertEqual(outcome.refusalCode, .projectionMismatch, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), baseline)

        let diskAfter = try VCFixture.tree(h.destination)
        XCTAssertEqual(diskAfter, diskBefore, "no refusal path may touch the published package")
        XCTAssertNil(h.store.verifiedCommitLatch)
        try await h.assertAgreeOrLatched()
    }

    // MARK: Item 1: fault points P1-P7

    func testFaultBeforeStageCompletion() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let before = VCFixture.dump(h.store)
        h.publisher.failStage = true
        let outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .stageFailed, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertNil(h.store.verifiedCommitLatch)
        try await h.assertAgreeOrLatched()
    }

    func testFaultAfterStageReadback() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let before = VCFixture.dump(h.store)
        h.publisher.failBeforePublish = true
        let outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .publishFailed, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        let diskIDs1 = try await h.disk().operationIDs
        XCTAssertEqual(diskIDs1, [])
        try await h.assertAgreeOrLatched()
    }

    func testFaultBeforePublication() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let before = VCFixture.dump(h.store)
        h.reservations.refusePublication = true
        let outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .publishFailed, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        try await h.assertAgreeOrLatched()
    }

    func testFaultAfterNamespaceReplacementCrashImageAndRollback() async throws {
        // P4a: the publisher fails right after the rename. The publisher rolls the rename back.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            struct Injected: Error {}
            h.publisher.hooks.afterRename = { throw Injected() }
            let request = try h.request()
            let outcome = await h.session.commitVerifiedAnnotation(request)
            XCTAssertTrue(outcome.refusalCode != nil || outcome.indeterminateCode != nil, outcome.description)
            try await h.assertDiskSelfConsistent(operationID: request.operationID)
            try await h.assertAgreeOrLatched("P4a")
            if outcome.refusalCode != nil {
                let diskIDs2 = try await h.disk().operationIDs
                XCTAssertEqual(diskIDs2, [], "a refusal means the old package is on disk")
            }
        }
        // P4b: crash image. The process dies after the rename: a fresh store reopening the
        // destination sees the edit and the receipt together, or neither.
        do {
            let h = try await VCSession(test: self)
            let request = try h.request()
            h.publisher.hooks.afterRename = {
                // Simulated death: no rollback can be trusted. Emulate by a failure at rollback too.
                struct Died: Error {}
                throw Died()
            }
            h.publisher.hooks.beforeRollback = { struct Died: Error {}; throw Died() }
            let outcome = await h.session.commitVerifiedAnnotation(request)
            XCTAssertTrue(outcome.refusalCode != nil || outcome.indeterminateCode != nil || outcome.isCommitted, outcome.description)
            h.session.close()
            let crashImage = try await VCFixture.disk(h.location)
            XCTAssertEqual(crashImage.operationIDs.contains(request.operationID),
                           crashImage.overrides[h.key]?.customName == "verified-name",
                           "crash image must hold the edit and the receipt together")
        }
    }

    func testFaultDuringDirectorySynchronization() async throws {
        struct Injected: Error {}
        for rollbackFails in [false, true] {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            h.publisher.hooks.beforeDirectorySync = { throw Injected() }
            if rollbackFails { h.publisher.hooks.beforeRollback = { throw Injected() } }
            let request = try h.request()
            let outcome = await h.session.commitVerifiedAnnotation(request)
            XCTAssertTrue(outcome.refusalCode != nil || outcome.indeterminateCode != nil || outcome.isCommitted,
                          "rollbackFails=\(rollbackFails) \(outcome.description)")
            try await h.assertDiskSelfConsistent(operationID: request.operationID)
            try await h.assertAgreeOrLatched("P5 rollbackFails=\(rollbackFails)")
        }
    }

    func testFaultDuringPublishedReadbackDecoding() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        struct Injected: Error {}
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = { throw Injected() }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .publishedReadbackFailed, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        // Disk already holds both halves; live has neither yet.
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.customName)
        // Ordinary saves are refused with the typed reason until reconciliation.
        let save = await h.session.save()
        XCTAssertEqual(save, .failed("verified-commit-indeterminate"))
        let retry = await h.session.commitVerifiedAnnotation(try h.request(name: "other"))
        XCTAssertEqual(retry.refusalCode, .recoveryRequired)
        // Reconcile without the verified API: re-read canonical truth and install it.
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = nil
        let reconciled = await h.session.reconcileVerifiedCommit()
        XCTAssertEqual(reconciled, .committedAndInstalled(operationID: request.operationID))
        XCTAssertNil(h.store.verifiedCommitLatch)
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "verified-name")
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        try await h.assertAgreeOrLatched()
        let afterSave = await h.session.save()
        if case .failed(let reason) = afterSave { XCTFail("ordinary save must work after reconcile: \(reason)") }
    }

    /// T14 regression guard for the readback path that reuses the reader's validated contents: bytes
    /// corrupted on disk after the publish and before the readback are still read from disk, so the
    /// outcome stays indeterminate, the live store is untouched, and the manifest still holds the record.
    func testPublishedBytesCorruptedBeforeReadbackStayIndeterminateWithRecordOnDisk() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let request = try h.request()
        let destination = h.destination
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = {
            let attachments = destination.appendingPathComponent("attachments", isDirectory: true)
            let files = try XCTUnwrap(FileManager.default.enumerator(at: attachments, includingPropertiesForKeys: [.isRegularFileKey]))
                .compactMap { $0 as? URL }.filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
            let victim = try XCTUnwrap(files.first, "fixture must carry an attachment to corrupt")
            var bytes = try Data(contentsOf: victim)
            XCTAssertFalse(bytes.isEmpty)
            bytes[0] ^= 0xff
            try bytes.write(to: victim)
        }
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .publishedReadbackFailed, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.customName, "live store unchanged")
        XCTAssertTrue(h.store.verifiedAnnotationAudit.records.isEmpty, "live audit unchanged")
        let manifest = try MacScopeDocumentPackage.validatedManifest(
            manifestData: Data(contentsOf: destination.appendingPathComponent("manifest.json")))
        XCTAssertEqual(manifest.verifiedAnnotationAudit?.records.map(\.operationID), [request.operationID],
                       "the published manifest holds the record")
    }

    func testPerturbedPostInstallStampLatchesAndReconcileClears() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let projector = VerifiedCommitProjector()
        projector.lieOnCall = 3  // before, after, then the post-install live read
        let request = try h.request(projector: projector)
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveNotInstalled, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        let reconciled = await h.session.reconcileVerifiedCommit()
        XCTAssertEqual(reconciled, .committedAndInstalled(operationID: request.operationID))
        XCTAssertNil(h.store.verifiedCommitLatch)
        try await h.assertAgreeOrLatched()
    }

    func testFaultBeforeUICompletionAndBetweenInstallAndBookkeeping() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        struct Injected: Error {}
        h.session.verifiedCommitTestHooks.beforeLiveInstall = { throw Injected() }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveNotInstalled, outcome.description)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
        let diskIDs3 = try await h.disk().operationIDs
        XCTAssertEqual(diskIDs3, [request.operationID])
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.customName, "live is untouched before the install")
        h.session.verifiedCommitTestHooks.beforeLiveInstall = nil
        let reconciled = await h.session.reconcileVerifiedCommit()
        XCTAssertEqual(reconciled, .committedAndInstalled(operationID: request.operationID))
        try await h.assertAgreeOrLatched()
    }

    func testReconcileWithNothingCommittedClearsLatch() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        // Latch with the operation absent from disk: reconciliation must find the old package.
        let request = try h.request()
        let expected = try await WorkspacePackageVersionProbe().observe(h.location.canonicalURL)
        let admission = try XCTUnwrap(try? h.store.beginVerifiedCommit(request).get())
        let staged = try h.store.prepareVerifiedCommit(request, admission: admission, buildPayload: false)
        h.store.endVerifiedCommit(admission)
        h.store.verifiedCommitLatch = VerifiedCommitLatch(
            operationID: request.operationID, requestDigest: request.receipt.requestDigest, reason: "test",
            isHeadless: false, expectedVersion: expected)
        h.store.verifiedCommitRecovery = staged
        let reconciled = await h.session.reconcileVerifiedCommit()
        XCTAssertEqual(reconciled, .notCommitted(operationID: request.operationID))
        XCTAssertNil(h.store.verifiedCommitLatch)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.customName)
    }

    // MARK: Item 2: competing save, autosave demand, busy

    func testCompetingSaveIsExcludedAndAutosaveDemandDrainsOnce() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let gate = VCGate()
        h.publisher.gate = gate
        let request = try h.request()
        let commit = Task { await h.session.commitVerifiedAnnotation(request) }
        try await gate.waitUntilArrived()
        let save = await h.session.save()
        XCTAssertEqual(save, .failed("document-write-already-active"))
        let second = await h.session.commitVerifiedAnnotation(try h.request(name: "second", id: UUID()))
        XCTAssertEqual(second.refusalCode, .writeBusy, second.description)
        await gate.open()
        let outcome = await commit.value
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        let after = await h.session.save()
        if case .failed(let reason) = after { XCTFail("save after the commit must work: \(reason)") }
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(disk.overrides[h.key]?.customName, "verified-name")
    }

    // MARK: Item 3: second window ownership

    func testSecondWindowOwnershipRefusesBeforeRename() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let before = VCFixture.dump(h.store)
        let tree = try VCFixture.tree(h.destination)
        h.reservations.refusePublication = true
        let outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .publishFailed, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertEqual(try VCFixture.tree(h.destination), tree)
        try await h.assertAgreeOrLatched()
    }

    // MARK: Item 4: second process rewrite

    func testSecondProcessRewriteBetweenCaptureAndPublishIsAConflict() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        // A different valid package, written by "another process", replaces the destination
        // while the commit is suspended before its publish.
        let foreign = try await VCSession(test: self)
        defer { foreign.session.close() }
        foreign.store.setCustomName(foreign.fixture.other.address, in: foreign.fixture.other.slot, name: "foreign")
        _ = await foreign.session.save()
        let foreignCopy = h.fixture.root.appendingPathComponent("Foreign.mscope", isDirectory: true)
        try FileManager.default.copyItem(at: foreign.destination, to: foreignCopy)

        let gate = VCGate()
        h.publisher.gate = gate
        let before = VCFixture.dump(h.store)
        let request = try h.request()
        let commit = Task { await h.session.commitVerifiedAnnotation(request) }
        try await gate.waitUntilArrived()
        _ = try FileManager.default.replaceItemAt(h.destination, withItemAt: foreignCopy)
        await gate.open()
        let outcome = await commit.value
        XCTAssertTrue(outcome.refusalCode == .destinationChanged || outcome.indeterminateCode == .publicationUnknown,
                      outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before, "live is untouched")
        let disk = try await VCFixture.disk(try WorkspaceDocumentLocation.canonicalized(from: h.destination))
        XCTAssertEqual(disk.operationIDs, [], "no receipt anywhere")
        XCTAssertNil(disk.overrides[h.key]?.customName)
        if outcome.refusalCode == .destinationChanged {
            let save = await h.session.save()
            XCTAssertEqual(save, .failed("document-conflict-unresolved"), "session conflict state must be set")
        }
    }

    // MARK: Item 5: reload

    func testReloadDuringAwaitIsExcluded() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let gate = VCGate()
        h.publisher.gate = gate
        let commit = Task { await h.session.commitVerifiedAnnotation(try! h.request()) }
        try await gate.waitUntilArrived()
        let reload = await h.session.reloadFromDisk()
        if case .failure(let error) = reload { XCTAssertEqual(error, .writeAlreadyActive) } else { XCTFail("reload must be excluded") }
        await gate.open()
        let outcome = await commit.value
        XCTAssertTrue(outcome.isCommitted, outcome.description)
    }

    func testExternalReloadThenCommitLands() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let stale = try await WorkspaceDocumentReader().readValidated(from: h.location)
        nonisolated(unsafe) let store = h.store
        nonisolated(unsafe) let location = h.location
        nonisolated(unsafe) let package = stale
        h.publisher.hooks.afterRename = {
            vcOnMain { try? store.installValidatedPackage(package, from: location) }
        }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .sessionReplaced, outcome.description)
        XCTAssertNil(h.store.verifiedCommitLatch, "sessionReplaced is a proven-disk outcome")
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(disk.overrides[h.key]?.customName, "verified-name")
    }

    // MARK: Item 6: close during await

    func testCloseDuringAwait() async throws {
        // Before the seal: the fence is revoked by close and nothing is renamed.
        do {
            let h = try await VCSession(test: self)
            let gate = VCGate()
            h.publisher.gate = gate
            let request = try h.request()
            let commit = Task { await h.session.commitVerifiedAnnotation(request) }
            try await gate.waitUntilArrived()
            h.session.close()
            await gate.open()
            let outcome = await commit.value
            XCTAssertTrue(outcome.refusalCode == .sessionClosed || outcome.refusalCode == .liveFenceRevoked,
                          outcome.description)
            let disk = try await VCFixture.disk(h.location)
            XCTAssertEqual(disk.operationIDs, [])
            XCTAssertNil(disk.overrides[h.key]?.customName)
        }
        // After the rename: disk has both halves; the outcome says the commit may have landed.
        do {
            let h = try await VCSession(test: self)
            nonisolated(unsafe) let session = h.session
            h.publisher.hooks.afterRename = { vcOnMain { session.close() } }
            let request = try h.request()
            let outcome = await h.session.commitVerifiedAnnotation(request)
            // Closing after the seal revokes the fence mid-publication: the publisher rolls the
            // rename back. A proven-unchanged destination is a refusal; anything not proven is
            // indeterminate. Either way both halves agree on disk.
            XCTAssertTrue(outcome.indeterminateCode == .sessionClosedAfterPossibleCommit
                          || outcome.refusalCode == .sessionClosed, outcome.description)
            let disk = try await VCFixture.disk(h.location)
            XCTAssertEqual(disk.operationIDs.contains(request.operationID),
                           disk.overrides[h.key]?.customName == "verified-name")
            if outcome.refusalCode != nil {
                XCTAssertFalse(disk.operationIDs.contains(request.operationID), "refusal means proven unchanged")
            }
        }
    }

    // MARK: Item 7: manual edits against the fence

    func testManualEditBeforeSealRevokesFence() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let gate = VCGate()
        h.publisher.gate = gate
        let commit = Task { await h.session.commitVerifiedAnnotation(try! h.request()) }
        try await gate.waitUntilArrived()
        h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "manual")
        await gate.open()
        let outcome = await commit.value
        XCTAssertEqual(outcome.refusalCode, .liveFenceRevoked, outcome.description)
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [])
        XCTAssertNil(disk.overrides[h.key]?.customName)
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.fixture.other]?.customName, "manual")
        XCTAssertNil(h.store.verifiedCommitLatch)
    }

    func testManualEditAfterSealMergesByKeyCASAndKeepsDirty() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        nonisolated(unsafe) let store = h.store
        let other = h.fixture.other
        h.publisher.hooks.afterRename = {
            vcOnMain { store.setCustomName(other.address, in: other.slot, name: "manual-after-seal") }
        }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveAdvanced, outcome.description)
        guard case .indeterminate(let detail) = outcome else { return }
        XCTAssertEqual(detail.detail, "merged-forward")
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "verified-name")
        XCTAssertEqual(h.store.snapshot.addressOverrides[other]?.customName, "manual-after-seal")
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertTrue(h.store.hasUnsavedChanges, "the later manual edit is not on disk")
        XCTAssertNil(h.store.verifiedCommitLatch, "committedLiveAdvanced is a proven-disk outcome")
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertNil(disk.overrides[other]?.customName)
        try await h.assertAgreeOrLatched()
    }

    func testManualEditOnSameKeyAfterSealKeepsReceiptAsHistory() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        nonisolated(unsafe) let store = h.store
        let key = h.key
        h.publisher.hooks.afterRename = {
            vcOnMain { store.setCustomName(key.address, in: key.slot, name: "manual-wins") }
        }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .committedLiveAdvanced, outcome.description)
        guard case .indeterminate(let detail) = outcome else { return }
        XCTAssertEqual(detail.detail, "later-manual-value-won")
        XCTAssertEqual(h.store.snapshot.addressOverrides[key]?.customName, "manual-wins")
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
        XCTAssertTrue(h.store.hasUnsavedChanges)
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(disk.overrides[key]?.customName, "verified-name")
        try await h.assertAgreeOrLatched()
    }

    func testUndoAndImageReplacementRevokeFence() async throws {
        // Undo of a pending manual edit advances the generation.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "pending")
            let gate = VCGate()
            h.publisher.gate = gate
            let commit = Task { await h.session.commitVerifiedAnnotation(try! h.request()) }
            try await gate.waitUntilArrived()
            h.store.undoManager.undo()
            await gate.open()
            let outcome = await commit.value
            XCTAssertEqual(outcome.refusalCode, .liveFenceRevoked, outcome.description)
            let diskIDs4 = try await h.disk().operationIDs
            XCTAssertEqual(diskIDs4, [])
        }
        // A replaced installation (reload/open) revokes through the installation choke point.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            // The publisher replaced the package directory; re-observe its identity once for every later read/install/bind.
            let reopened = try WorkspaceDocumentLocation.canonicalized(from: h.location.canonicalURL)
            let package = try await WorkspaceDocumentReader().readValidated(from: reopened)
            let gate = VCGate()
            h.publisher.gate = gate
            let commit = Task { await h.session.commitVerifiedAnnotation(try! h.request()) }
            try await gate.waitUntilArrived()
            try h.store.installValidatedPackage(package, from: reopened)
            await gate.open()
            let outcome = await commit.value
            XCTAssertEqual(outcome.refusalCode, .liveFenceRevoked, outcome.description)
            let diskIDs5 = try await h.disk().operationIDs
            XCTAssertEqual(diskIDs5, [])
        }
    }

    // MARK: Item 8: version token CAS

    func testWrongGenerationAndStaleVersionTokenRefusedWithoutStaging() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let stale = try h.request()
        h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "drift")
        let stagesBefore = h.publisher.stageCalls
        var outcome = await h.session.commitVerifiedAnnotation(stale)
        XCTAssertEqual(outcome.refusalCode, .staleVersion, outcome.description)
        XCTAssertEqual(h.publisher.stageCalls, stagesBefore, "refused before staging")

        // Audit-only drift: a rejected receipt committed by another coordinator changes the token.
        let tokenBefore = h.store.verifiedCommitVersionToken()
        let rejected = await h.session.commitVerifiedAnnotation(try h.request(accepted: false))
        XCTAssertTrue(rejected.isCommitted, rejected.description)
        XCTAssertNotEqual(h.store.verifiedCommitVersionToken(), tokenBefore)
        let staleAfterAudit = try h.request(expecting: tokenBefore)
        let stagesAfter = h.publisher.stageCalls
        outcome = await h.session.commitVerifiedAnnotation(staleAfterAudit)
        XCTAssertEqual(outcome.refusalCode, .staleVersion, outcome.description)
        XCTAssertEqual(h.publisher.stageCalls, stagesAfter)
        try await h.assertAgreeOrLatched()
    }

    // MARK: Item 9: idempotency

    func testExactRetryReturnsExistingReceiptWithNoSecondWrite() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let request = try h.request()
        let first = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(first.isCommitted, first.description)
        let tree = try VCFixture.tree(h.destination)
        let stages = h.publisher.stageCalls, publishes = h.publisher.publishCalls
        let dump = VCFixture.dump(h.store)
        let retry = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(retry.isExisting, retry.description)
        XCTAssertEqual(h.publisher.stageCalls, stages)
        XCTAssertEqual(h.publisher.publishCalls, publishes)
        XCTAssertEqual(try VCFixture.tree(h.destination), tree)
        XCTAssertEqual(VCFixture.dump(h.store), dump)
    }

    func testChangedReuseOfOperationIDConflicts() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let id = UUID()
        let first = await h.session.commitVerifiedAnnotation(try h.request(id: id))
        XCTAssertTrue(first.isCommitted, first.description)
        let tree = try VCFixture.tree(h.destination)
        let changed = try h.request(name: "different", id: id, rationale: "changed reuse")
        let outcome = await h.session.commitVerifiedAnnotation(changed)
        XCTAssertEqual(outcome.refusalCode, .idempotencyConflict, outcome.description)
        XCTAssertEqual(try VCFixture.tree(h.destination), tree)
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "verified-name")
    }

    func testResponseLostRetryAfterReopenReturnsExisting() async throws {
        let h = try await VCSession(test: self)
        let request = try h.request()
        let first = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(first.isCommitted, first.description)
        h.session.close()  // the outcome is dropped; only disk survives

        // The publisher replaced the package directory; re-observe its identity once for every later read/install/bind.
        let reopened = try WorkspaceDocumentLocation.canonicalized(from: h.location.canonicalURL)
        let package = try await WorkspaceDocumentReader().readValidated(from: reopened)
        let fresh = WorkspaceStore(workspaceName: "", snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [:]),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        fresh.recents = VCQuietRecents()
        let session = WorkspaceDocumentSession(
            sessionID: .init(rawValue: UUID()), windowID: .fresh(), source: fresh,
            io: WorkspaceDocumentIO(), reservations: h.reservations)
        defer { session.close() }
        try fresh.installValidatedPackage(package, from: reopened)
        try session.bindOpenedPackage(package, at: reopened)
        let tree = try VCFixture.tree(h.destination)
        let outcome = await session.commitVerifiedAnnotation(request)
        XCTAssertTrue(outcome.isExisting, outcome.description)
        XCTAssertEqual(try VCFixture.tree(h.destination), tree)
    }

    // MARK: Item 10: journal

    func testJournalFailureLatchedBeforeCommitRefusesAndPreservesState() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let journal = h.fixture.root.appendingPathComponent("edits.journal")
        try h.store.attachEditJournal(at: journal)
        let writer = try XCTUnwrap(h.store.editJournal)
        struct Injected: Error {}
        writer.appendHook = { _ in throw Injected() }
        h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "journal-fails")
        XCTAssertNotNil(writer.failure)
        let before = VCFixture.dump(h.store)
        let tree = try VCFixture.tree(h.destination)
        let outcome = await h.session.commitVerifiedAnnotation(try h.request())
        XCTAssertEqual(outcome.refusalCode, .journalFailed, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertEqual(try VCFixture.tree(h.destination), tree)
    }

    func testJournalAppendFailureAfterInstallReportsCommittedDegraded() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        try h.store.attachEditJournal(at: h.fixture.root.appendingPathComponent("edits.journal"))
        let writer = try XCTUnwrap(h.store.editJournal)
        struct Injected: Error {}
        h.session.verifiedCommitTestHooks.beforeLiveInstall = { writer.appendHook = { _ in throw Injected() } }
        let request = try h.request()
        let outcome = await h.session.commitVerifiedAnnotation(request)
        guard case .committed(_, let info) = outcome else { return XCTFail(outcome.description) }
        XCTAssertTrue(info.journalDegraded)
        let diskIDs6 = try await h.disk().operationIDs
        XCTAssertEqual(diskIDs6, [request.operationID])
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.customName, "verified-name")
    }

    // MARK: Item 11: rejected receipt

    func testRejectedReceiptIsAuditOnlyTransaction() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let overrides = h.store.snapshot.addressOverrides
        let tokenBefore = h.store.verifiedCommitVersionToken()
        let request = try h.request(accepted: false)
        let outcome = await h.session.commitVerifiedAnnotation(request)
        guard case .committed(_, let info) = outcome else { return XCTFail(outcome.description) }
        XCTAssertFalse(info.annotationInstalled)
        XCTAssertEqual(h.store.snapshot.addressOverrides, overrides, "no annotation change")
        XCTAssertNotEqual(h.store.verifiedCommitVersionToken(), tokenBefore)
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(disk.envelope?.records.first?.body.decision, .rejected)
        XCTAssertEqual(disk.overrides, overrides)
        XCTAssertFalse(h.store.hasUnsavedChanges)
    }

    // MARK: Item 12: candidate payload isolation

    func testCapturedPayloadUsesCandidateNotLive() async throws {
        let fixture = try VCFixture.makeStore(self)
        let store = fixture.store
        var emissions = 0
        let cancellable = store.objectWillChange.sink { emissions += 1 }
        defer { cancellable.cancel() }

        let liveBefore = store.snapshot.addressOverrides
        let generation = store.mutationGeneration
        let canUndo = store.undoManager.canUndo
        let digestBefore = VerifiedCommitProjector.digest(liveBefore)
        let plainBefore = try store.makePackagePayload()
        let plainBeforeContents = try MacScopeDocumentPackage.validatedContents(
            manifestData: plainBefore.manifestData, attachmentsByBinaryID: plainBefore.attachmentsByBinaryID,
            reconstructionState: plainBefore.reconstructionState,
            instructionSidecarData: plainBefore.instructionSidecarData)
        emissions = 0

        let request = try VCFixture.request(store, key: fixture.key)
        let admission = try XCTUnwrap(try? store.beginVerifiedCommit(request).get())
        defer { store.endVerifiedCommit(admission) }
        let staged = try store.prepareVerifiedCommit(request, admission: admission, buildPayload: true)
        let payload = try XCTUnwrap(staged.payload)

        XCTAssertEqual(emissions, 0, "payload capture must not publish a live change")
        XCTAssertEqual(store.mutationGeneration, generation)
        XCTAssertEqual(store.undoManager.canUndo, canUndo)
        XCTAssertEqual(VerifiedCommitProjector.digest(store.snapshot.addressOverrides), digestBefore)
        XCTAssertNil(store.snapshot.addressOverrides[fixture.key]?.customName)
        XCTAssertTrue(store.verifiedAnnotationAudit.records.isEmpty)

        let contents = try MacScopeDocumentPackage.validatedContents(
            manifestData: payload.manifestData, attachmentsByBinaryID: payload.attachmentsByBinaryID,
            reconstructionState: payload.reconstructionState, instructionSidecarData: payload.instructionSidecarData)
        XCTAssertEqual(contents.snapshot.addressOverrides[fixture.key]?.customName, "verified-name")
        XCTAssertEqual(contents.manifest.verifiedAnnotationAudit, staged.nextEnvelope)

        // Regression: the ordinary payload path is unchanged by the refactor.
        let plainAfter = try store.makePackagePayload()
        let plainAfterContents = try MacScopeDocumentPackage.validatedContents(
            manifestData: plainAfter.manifestData, attachmentsByBinaryID: plainAfter.attachmentsByBinaryID,
            reconstructionState: plainAfter.reconstructionState,
            instructionSidecarData: plainAfter.instructionSidecarData)
        XCTAssertEqual(plainAfterContents.snapshot.addressOverrides, plainBeforeContents.snapshot.addressOverrides)
        XCTAssertEqual(plainAfterContents.manifest.verifiedAnnotationAudit,
                       plainBeforeContents.manifest.verifiedAnnotationAudit)
        XCTAssertEqual(plainAfter.attachmentsByBinaryID, plainBefore.attachmentsByBinaryID)
        XCTAssertEqual(plainAfter.instructionSidecarData, plainBefore.instructionSidecarData)
    }

    // MARK: VA-SCOPE S4: type-at-address class

    private func reopen(_ h: VCSession) async throws -> WorkspaceStore {
        let reopened = try WorkspaceDocumentLocation.canonicalized(from: h.location.canonicalURL)
        let package = try await WorkspaceDocumentReader().readValidated(from: reopened)
        let fresh = WorkspaceStore(workspaceName: "", snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [:]),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        fresh.recents = VCQuietRecents()
        try fresh.installValidatedPackage(package, from: reopened)
        return fresh
    }

    /// SPEC T1: "Type request, candidate, publish, reopen via real reader: observed equals requested
    /// through the raw and resolved legs".
    func testT1TypedCommitPublishesAndReopensThroughRawAndResolvedLegs() async throws {
        let h = try await VCSession(test: self)
        let header = VCFixture.addType(h.store, "Header")
        let request = try h.typedRequest(type: "Header")
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertNil(h.store.verifiedCommitLatch)
        XCTAssertFalse(h.store.hasUnsavedChanges)
        // Live, raw and resolved legs.
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
        XCTAssertEqual(h.store.snapshot.appliedType(at: h.typedKey)?.id, header.id)
        // The v2 record carries the class and nothing about the type value.
        let record = try XCTUnwrap(h.store.verifiedAnnotationAudit.records.first)
        XCTAssertEqual(record.body.fieldClass, .addressType)
        XCTAssertEqual(record.body.domain, VerifiedAnnotationAuditRecord.domainV2)
        let liveEnvelope = try VerifiedAnnotationAuditCodec.encode(h.store.verifiedAnnotationAudit)
        h.session.close()
        // Reopen through the real package reader.
        let fresh = try await reopen(h)
        XCTAssertEqual(fresh.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
        XCTAssertEqual(fresh.snapshot.appliedType(at: h.typedKey)?.id, header.id)
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(fresh.verifiedAnnotationAudit), liveEnvelope)
        XCTAssertEqual(fresh.verifiedCommitIdempotency(for: request), .exact)
    }

    /// SPEC T3: "Injected readback mismatch returns a typed error with the stage and leaves the
    /// workspace unchanged". Both legs; overrides, type table and undo history are unchanged.
    func testT3InjectedReadbackMismatchIsTypedWithStageAndLeavesWorkspaceUnchanged() async throws {
        try await injectedMismatch(leg: "content:raw-leg") { snapshot in
            let key = snapshot.addressOverrides.keys.first { snapshot.addressOverrides[$0]?.appliedTypeName != nil }
            if let key { snapshot.addressOverrides[key]?.appliedTypeName = "Other" }
        }
        try await injectedMismatch(leg: "content:resolved-leg") { snapshot in
            snapshot.typeDefinitions.removeAll { $0.name == "Header" }
        }
    }

    private func injectedMismatch(leg: String, mutate: @escaping @MainActor (inout WorkspaceSnapshot) -> Void) async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        VCFixture.addType(h.store, "Other")
        // Persist the pending type edits first so the commit's own dirty handling is not in play.
        _ = await h.session.save()
        let overridesBefore = h.store.snapshot.addressOverrides
        let typesBefore = h.store.snapshot.typeDefinitions
        let undoBefore = h.store.undoManager.canUndo
        let dumpBefore = VCFixture.dump(h.store)
        h.session.verifiedCommitTestHooks.mutateReadbackSnapshot = mutate
        let outcome = await h.session.commitVerifiedAnnotation(try h.typedRequest(type: "Header"))
        XCTAssertEqual(outcome.indeterminateCode, .publishedReadbackFailed, "\(leg) \(outcome.description)")
        XCTAssertTrue(outcome.description.contains(leg), "stage must name the failing leg: \(outcome.description)")
        // Nothing was installed live.
        XCTAssertEqual(h.store.snapshot.addressOverrides, overridesBefore, leg)
        XCTAssertEqual(h.store.snapshot.typeDefinitions, typesBefore, leg)
        XCTAssertEqual(h.store.undoManager.canUndo, undoBefore, leg)
        XCTAssertEqual(VCFixture.dump(h.store).overridesDigest, dumpBefore.overridesDigest, leg)
        XCTAssertNotNil(h.store.verifiedCommitLatch)
    }

    /// (d) Indeterminate then reconcile for a typed commit, plus existing-outcome idempotence.
    func testTypedCommitIndeterminateReconcileAndExistingIdempotence() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        struct Injected: Error {}
        let header = VCFixture.addType(h.store, "Header")
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = { throw Injected() }
        let request = try h.typedRequest(type: "Header")
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .publishedReadbackFailed, outcome.description)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.typedKey]?.appliedTypeName)
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(disk.overrides[h.typedKey]?.appliedTypeName, "Header")
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = nil
        let reconciled = await h.session.reconcileVerifiedCommit()
        XCTAssertEqual(reconciled, .committedAndInstalled(operationID: request.operationID))
        XCTAssertNil(h.store.verifiedCommitLatch)
        XCTAssertEqual(h.store.snapshot.appliedType(at: h.typedKey)?.id, header.id)
        // Existing outcome: the exact retry is idempotent, a conflicting reuse is refused.
        let retry = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(retry.isExisting, retry.description)
        let conflicting = await h.session.commitVerifiedAnnotation(
            try h.typedRequest(type: nil, id: request.operationID))
        XCTAssertEqual(conflicting.refusalCode, .idempotencyConflict, conflicting.description)
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.count, 1)
    }

    /// (e) Pseudocode is collateral. The fixture cannot produce a decompiler-output change honestly, so this
    /// asserts only what is checkable: a typed commit verifies and the readback reads raw override and
    /// resolved type only (the snapshot seam above is the sole data the readback consults).
    func testTypedCommitVerifiesWithoutReadingPseudocode() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        var sawSnapshot = false
        h.session.verifiedCommitTestHooks.mutateReadbackSnapshot = { snapshot in
            sawSnapshot = true
            _ = snapshot
        }
        let outcome = await h.session.commitVerifiedAnnotation(try h.typedRequest(type: "Header"))
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertTrue(sawSnapshot)
    }

    /// Clearing a type is a typed commit too: nil requested, resolved leg requires no applied type.
    func testTypedClearCommitsAndRemovesTheOverride() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        let firstTyped = await h.session.commitVerifiedAnnotation(try h.typedRequest(type: "Header"))
        XCTAssertTrue(firstTyped.isCommitted, firstTyped.description)
        let clear = await h.session.commitVerifiedAnnotation(try h.typedRequest(type: nil))
        XCTAssertTrue(clear.isCommitted, clear.description)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.typedKey], "an emptied override is pruned")
        XCTAssertNil(h.store.snapshot.appliedType(at: h.typedKey))
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.count, 2)
    }

    /// The signature class (S6b) still requires a `functionPrototype` Core edit: an addressType edit declared as a
    /// signature is refused as an invalid receipt before anything changes.
    func testSignatureClassWithAddressTypeEditIsInvalidReceipt() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let good = try h.typedRequest(type: "Header")
        let request = VerifiedAnnotationCommitRequest(
            state: good.state, receipt: good.receipt, nativeEvidenceLinks: good.nativeEvidenceLinks,
            target: good.target, fieldClass: .functionSignature, requested: good.requested,
            expectingVersion: good.expectingVersion, projector: good.projector)
        let before = VCFixture.dump(h.store)
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.refusalCode, .invalidReceipt, outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
    }

    /// A typed request whose Core edit disagrees with the declared class is refused as invalid.
    func testTypedRequestWithMismatchedEditKindIsInvalidReceipt() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        VCFixture.addType(h.store, "Header")
        let named = try h.request(name: "x", key: h.typedKey)  // functionName edit
        let request = VerifiedAnnotationCommitRequest(
            state: named.state, receipt: named.receipt, nativeEvidenceLinks: named.nativeEvidenceLinks,
            target: named.target, fieldClass: .addressType, requested: named.requested,
            expectingVersion: named.expectingVersion, projector: named.projector)
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.refusalCode, .invalidReceipt, outcome.description)
    }

    /// (f) Opus review: an UNVERIFIED applied type (old set-type path, no audit record) beside accepted
    /// name records from before S3. The projector digest now includes `type`, so the stamp recorded at the
    /// name commit no longer reproduces. No S4 path compares a stored stamp with a fresh one: publish,
    /// readback and reopen still succeed (checkpoint reproduction is informational, VerifiedCheckpoint.swift:391).
    func testUnverifiedAppliedTypeBesideOldNameRecordsDoesNotRefusePublishOrReopen() async throws {
        let h = try await VCSession(test: self)
        VCFixture.addType(h.store, "Header")
        let first = try h.request(name: "first-name")
        let firstName = await h.session.commitVerifiedAnnotation(first)
        XCTAssertTrue(firstName.isCommitted, firstName.description)
        let stampAtNameCommit = NativeAnnotationProjector.digest(h.store.snapshot.addressOverrides)
        // Old unverified path: no audit record.
        h.store.setAppliedType(h.typedKey.address, in: h.typedKey.slot, name: "Header")
        let recordsBefore = h.store.verifiedAnnotationAudit.records.count
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
        XCTAssertNotEqual(NativeAnnotationProjector.digest(h.store.snapshot.addressOverrides), stampAtNameCommit,
                          "the recorded stamp no longer reproduces once an unverified type exists")
        // A later verified commit (publish + readback) still succeeds.
        let second = try h.request(name: "second-name", key: h.fixture.key)
        let outcome = await h.session.commitVerifiedAnnotation(second)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.count, recordsBefore + 1)
        XCTAssertEqual(h.store.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
        h.session.close()
        // Reopen: the package still validates and carries the type and both records.
        let fresh = try await reopen(h)
        XCTAssertEqual(fresh.snapshot.addressOverrides[h.typedKey]?.appliedTypeName, "Header")
        XCTAssertEqual(fresh.verifiedAnnotationAudit.records.count, recordsBefore + 1)
    }

    // MARK: VA-SCOPE S6b: function signature class

    private func canonical(_ signature: FunctionSignatureOverride?) throws -> String? {
        try signature.map(VerifiedFieldCodec.canonicalSignature)
    }

    private func sigA() -> FunctionSignatureOverride {
        VCFixture.signature([("tok-a1", "buf", "char *"), ("tok-a2", "len", "size_t")], returnType: "ssize_t")
    }

    private func sigB() -> FunctionSignatureOverride {
        VCFixture.signature([("tok-b1", "fd", "int")], returnType: "int")
    }

    /// Reads the saved package through the real reader and returns the (repaired) snapshot plus the repair notes.
    private func packageContents(_ h: VCSession) async throws -> WorkspacePackageContents {
        let location = try WorkspaceDocumentLocation.canonicalized(from: h.location.canonicalURL)
        let package = try await WorkspaceDocumentReader().readValidated(from: location)
        return try MacScopeDocumentPackage.validatedContents(
            manifestData: package.manifestData, attachmentsByBinaryID: package.attachmentsByBinaryID,
            reconstructionState: package.reconstructionState, instructionSidecarData: package.instructionSidecarData)
    }

    /// SPEC T2: "Signature request, candidate, publish, reopen: observed equals requested through the raw and
    /// effective legs". Reopen goes through the real package reader.
    func testT2SignatureCommitPublishesAndReopensThroughRawAndEffectiveLegs() async throws {
        let h = try await VCSession(test: self)
        let requested = sigA()
        let text = try XCTUnwrap(try canonical(requested))
        let request = try h.signatureRequest(signature: requested)
        XCTAssertEqual(request.receipt.request.edits[0].value, text, "the Core edit carries the canonical text")
        XCTAssertEqual(request.requested, text)
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertNil(h.store.verifiedCommitLatch)
        XCTAssertFalse(h.store.hasUnsavedChanges)
        // Live: raw and effective legs.
        XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[h.key]?.signature), text)
        XCTAssertEqual(try canonical(h.store.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), text)
        // The v2 record carries the class and not the value.
        let record = try XCTUnwrap(h.store.verifiedAnnotationAudit.records.first)
        XCTAssertEqual(record.body.fieldClass, .functionSignature)
        XCTAssertEqual(record.body.domain, VerifiedAnnotationAuditRecord.domainV2)
        let liveEnvelope = try VerifiedAnnotationAuditCodec.encode(h.store.verifiedAnnotationAudit)
        h.session.close()
        // Reopen through the real reader: snapshot legs, repair notes and the store install.
        let contents = try await packageContents(h)
        XCTAssertEqual(try canonical(contents.snapshot.addressOverrides[h.key]?.signature), text)
        XCTAssertEqual(try canonical(contents.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), text)
        XCTAssertTrue(contents.analysisRepairs.allSatisfy(\.isEmpty), "no repair path touches signatures here")
        let fresh = try await reopen(h)
        XCTAssertEqual(try canonical(fresh.snapshot.addressOverrides[h.key]?.signature), text)
        XCTAssertEqual(try canonical(fresh.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), text)
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(fresh.verifiedAnnotationAudit), liveEnvelope)
        XCTAssertEqual(fresh.verifiedCommitIdempotency(for: request), .exact)
    }

    /// SPEC T3 for signatures: "Injected readback mismatch returns a typed error with the stage and leaves the
    /// workspace unchanged". Once per leg. The raw leg is tampered on a set; the effective leg is only independently
    /// falsifiable on a clear (an authoritative override always wins the merge), so it is tampered there.
    func testT3SignatureInjectedReadbackMismatchIsTypedWithStageAndLeavesWorkspaceUnchanged() async throws {
        // Raw leg, on a set.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            let target = h.key
            h.session.verifiedCommitTestHooks.mutateReadbackSnapshot = { snapshot in
                snapshot.addressOverrides[target]?.signature = FunctionSignatureOverride(returnType: "tampered")
            }
            try await assertSignatureReadbackMismatch(h, request: h.signatureRequest(signature: sigA()), leg: "content:raw-leg")
        }
        // Effective leg, on a clear with an imported prototype at the address.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            let imported = VCFixture.signature([("imp", "x", "double")], returnType: "double")
            h.store.snapshot.importedPrototypes[h.key] = imported
            var override = h.store.snapshot.addressOverrides[h.key] ?? AddressOverride()
            override.signature = sigA()
            h.store.applyOverride(h.key, override, actionName: "fixture")
            _ = await h.session.save()
            let target = h.key
            h.session.verifiedCommitTestHooks.mutateReadbackSnapshot = { snapshot in
                snapshot.importedPrototypes[target] = FunctionSignatureOverride(returnType: "tampered")
            }
            try await assertSignatureReadbackMismatch(h, request: h.signatureRequest(signature: nil), leg: "content:effective-leg")
        }
    }

    private func assertSignatureReadbackMismatch(
        _ h: VCSession, request: VerifiedAnnotationCommitRequest, leg: String
    ) async throws {
        let overridesBefore = h.store.snapshot.addressOverrides
        let typesBefore = h.store.snapshot.typeDefinitions
        let importedBefore = h.store.snapshot.importedPrototypes
        let undoBefore = h.store.undoManager.canUndo
        let dumpBefore = VCFixture.dump(h.store)
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .publishedReadbackFailed, "\(leg) \(outcome.description)")
        XCTAssertTrue(outcome.description.contains(leg), "stage must name the failing leg: \(outcome.description)")
        XCTAssertEqual(h.store.snapshot.addressOverrides, overridesBefore, leg)
        XCTAssertEqual(h.store.snapshot.typeDefinitions, typesBefore, leg)
        XCTAssertEqual(h.store.snapshot.importedPrototypes, importedBefore, leg)
        XCTAssertEqual(h.store.undoManager.canUndo, undoBefore, leg)
        XCTAssertEqual(VCFixture.dump(h.store).overridesDigest, dumpBefore.overridesDigest, leg)
        XCTAssertNotNil(h.store.verifiedCommitLatch, leg)
    }

    /// (b) A baseline with an imported prototype at the address: set then clear, effective leg correct both times.
    func testSignatureSetThenClearWithImportedPrototypeKeepsEffectiveLegCorrect() async throws {
        let h = try await VCSession(test: self)
        let imported = VCFixture.signature([("imp", "x", "double")], returnType: "double")
        let importedText = try XCTUnwrap(try canonical(imported))
        h.store.snapshot.importedPrototypes[h.key] = imported
        // A pending manual edit elsewhere dirties the document so the commit persists the prototype too.
        h.store.setCustomName(h.fixture.other.address, in: h.fixture.other.slot, name: "pending")
        XCTAssertEqual(try canonical(h.store.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), importedText)

        let requested = sigA()
        let text = try XCTUnwrap(try canonical(requested))
        let set = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: requested))
        XCTAssertTrue(set.isCommitted, set.description)
        XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[h.key]?.signature), text)
        XCTAssertEqual(try canonical(h.store.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), text,
                       "the authoritative override wins over the imported prototype")
        let afterSet = try await packageContents(h)
        XCTAssertEqual(try canonical(afterSet.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), text)
        XCTAssertEqual(try canonical(afterSet.snapshot.importedPrototypes[h.key]), importedText)

        let clear = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: nil))
        XCTAssertTrue(clear.isCommitted, clear.description)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.signature)
        XCTAssertEqual(try canonical(h.store.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), importedText,
                       "clearing falls back to the imported prototype")
        let afterClear = try await packageContents(h)
        XCTAssertNil(afterClear.snapshot.addressOverrides[h.key]?.signature)
        XCTAssertEqual(try canonical(afterClear.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address]), importedText)
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.count, 2)
        h.session.close()
    }

    /// A signature with only quarantined legacy rows persists but has no analysis effect, so it never reaches the
    /// effective view: the raw leg carries it and the effective leg expects the imported prototype (here none).
    func testQuarantineOnlySignatureCommitsWithNoEffectiveSignature() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let quarantined = FunctionSignatureOverride(
            returnType: nil, parameterList: .unspecified, variadicState: .unspecified,
            quarantinedLegacyArgs: [LegacyArgOverride(originalIndex: 0, originalOrder: 0, name: "a", type: "int")],
            noReturnState: .unspecified)
        XCTAssertTrue(quarantined.hasPersistedPayload)
        XCTAssertFalse(quarantined.hasAnalysisEffect)
        let outcome = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: quarantined))
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[h.key]?.signature), try canonical(quarantined))
        XCTAssertNil(h.store.snapshot.functionSignatureOverrides(in: h.key.slot)[h.key.address])
    }

    /// (c) A requested signature whose tokens differ from the stored ones still confirms; the commit lands the
    /// requested content and the session-only authority is reset by the signature `didSet`.
    func testRowTokenDifferenceStillConfirmsAndResetsSessionAuthority() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let stored = VCFixture.signature([("stored-1", "x", "int"), ("stored-2", "y", "long")])
        let requested = VCFixture.signature([("req-1", "x", "int"), ("req-2", "y", "long")])
        XCTAssertNotEqual(stored, requested)
        XCTAssertEqual(try canonical(stored), try canonical(requested))
        var override = h.store.snapshot.addressOverrides[h.key] ?? AddressOverride()
        override.signature = stored
        override.ownReturnAuthorityFile = "session-authority"
        h.store.applyOverride(h.key, override, actionName: "fixture")
        _ = await h.session.save()
        let outcome = await h.session.commitVerifiedAnnotation(
            try h.signatureRequest(signature: requested, production: true))
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        let live = try XCTUnwrap(h.store.snapshot.addressOverrides[h.key])
        XCTAssertEqual(try canonical(live.signature), try canonical(requested))
        XCTAssertNotEqual(live.signature, stored, "the committed tokens are the deterministic decoded ones")
        XCTAssertNil(live.ownReturnAuthorityFile)
    }

    /// SPEC T10 end to end: "Signature erase rule accepts only the `ownReturnAuthorityFile` reset as extra drift".
    func testT10SignatureCommitAcceptsOnlyTheAuthorityResetAsExtraDrift() async throws {
        // Accepted: a changed signature plus the didSet reset of the session authority.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            var override = h.store.snapshot.addressOverrides[h.key] ?? AddressOverride()
            override.signature = sigA()
            override.ownReturnAuthorityFile = "session-authority"
            h.store.applyOverride(h.key, override, actionName: "fixture")
            _ = await h.session.save()
            let outcome = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: sigB()))
            XCTAssertTrue(outcome.isCommitted, outcome.description)
            XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[h.key]?.signature), try canonical(sigB()))
            XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.ownReturnAuthorityFile)
        }
        // Refused: any other authority value, and any other protected member, beside the signature change.
        let drifts: [(String, @MainActor (inout NativeAnnotationCandidate, ImageAddress) -> Void)] = [
            ("other authority", { $0.overrides[$1]?.ownReturnAuthorityFile = "other-authority" }),
            ("tag", { $0.overrides[$1]?.tag = "collateral" }),
            ("applied type", { $0.overrides[$1]?.appliedTypeName = "Header" }),
        ]
        for (name, drift) in drifts {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            var override = h.store.snapshot.addressOverrides[h.key] ?? AddressOverride()
            override.signature = sigA()
            override.ownReturnAuthorityFile = "session-authority"
            h.store.applyOverride(h.key, override, actionName: "fixture")
            _ = await h.session.save()
            let target = h.key
            h.store.verifiedAnnotationCandidateTestHook = { drift(&$0, target) }
            let before = VCFixture.dump(h.store)
            let outcome = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: sigB()))
            XCTAssertEqual(outcome.refusalCode, .candidateRejected, "\(name) \(outcome.description)")
            XCTAssertEqual(VCFixture.dump(h.store), before, name)
            XCTAssertEqual(h.store.snapshot.addressOverrides[h.key]?.ownReturnAuthorityFile, "session-authority", name)
        }
    }

    /// Key-level CAS compares canonical signature text: a rowToken-only manual edit after the seal does not block
    /// the install, and a real manual signature edit wins and keeps the receipt as history.
    func testSignatureKeyLevelCASComparesCanonicalText() async throws {
        // rowToken-only manual edit: the verified signature still installs.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            let baseline = sigA()
            var override = h.store.snapshot.addressOverrides[h.key] ?? AddressOverride()
            override.signature = baseline
            h.store.applyOverride(h.key, override, actionName: "fixture")
            _ = await h.session.save()
            let retokened = VCFixture.signature([("manual-1", "buf", "char *"), ("manual-2", "len", "size_t")], returnType: "ssize_t")
            XCTAssertNotEqual(retokened, baseline)
            nonisolated(unsafe) let store = h.store
            let key = h.key
            h.publisher.hooks.afterRename = { vcOnMain { store.setSignature(key.address, retokened) } }
            let outcome = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: sigB()))
            XCTAssertEqual(outcome.indeterminateCode, .committedLiveAdvanced, outcome.description)
            guard case .indeterminate(let detail) = outcome else { return }
            XCTAssertEqual(detail.detail, "merged-forward")
            XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[key]?.signature), try canonical(sigB()))
        }
        // A real manual signature edit wins.
        do {
            let h = try await VCSession(test: self)
            defer { h.session.close() }
            nonisolated(unsafe) let store = h.store
            let key = h.key
            let manual = VCFixture.signature([("m1", "z", "short")], returnType: "short")
            h.publisher.hooks.afterRename = { vcOnMain { store.setSignature(key.address, manual) } }
            let request = try h.signatureRequest(signature: sigA())
            let outcome = await h.session.commitVerifiedAnnotation(request)
            XCTAssertEqual(outcome.indeterminateCode, .committedLiveAdvanced, outcome.description)
            guard case .indeterminate(let detail) = outcome else { return }
            XCTAssertEqual(detail.detail, "later-manual-value-won")
            XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[key]?.signature), try canonical(manual))
            XCTAssertEqual(h.store.verifiedAnnotationAudit.records.map(\.operationID), [request.operationID])
            XCTAssertTrue(h.store.hasUnsavedChanges)
        }
    }

    /// (d) Indeterminate then reconcile for a signature commit, plus existing-outcome idempotence.
    func testSignatureCommitIndeterminateReconcileAndExistingIdempotence() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        struct Injected: Error {}
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = { throw Injected() }
        let request = try h.signatureRequest(signature: sigA())
        let outcome = await h.session.commitVerifiedAnnotation(request)
        XCTAssertEqual(outcome.indeterminateCode, .publishedReadbackFailed, outcome.description)
        XCTAssertNil(h.store.snapshot.addressOverrides[h.key]?.signature)
        let disk = try await h.disk()
        XCTAssertEqual(disk.operationIDs, [request.operationID])
        XCTAssertEqual(try canonical(disk.overrides[h.key]?.signature), try canonical(sigA()))
        h.session.verifiedCommitTestHooks.afterPublishBeforeReadback = nil
        let reconciled = await h.session.reconcileVerifiedCommit()
        XCTAssertEqual(reconciled, .committedAndInstalled(operationID: request.operationID))
        XCTAssertNil(h.store.verifiedCommitLatch)
        XCTAssertEqual(try canonical(h.store.snapshot.addressOverrides[h.key]?.signature), try canonical(sigA()))
        let retry = await h.session.commitVerifiedAnnotation(request)
        XCTAssertTrue(retry.isExisting, retry.description)
        let conflicting = await h.session.commitVerifiedAnnotation(
            try h.signatureRequest(signature: nil, id: request.operationID))
        XCTAssertEqual(conflicting.refusalCode, .idempotencyConflict, conflicting.description)
        XCTAssertEqual(h.store.verifiedAnnotationAudit.records.count, 1)
    }

    /// An uncanonical requested value is refused at prepare as `invalidReceipt "signature-value"`, unchanged.
    func testNonCanonicalSignatureValueIsInvalidReceiptSignatureValue() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let before = VCFixture.dump(h.store)
        let outcome = await h.session.commitVerifiedAnnotation(
            try h.signatureRequest(signature: nil, rawText: "{\"not\":\"a signature\"}"))
        XCTAssertEqual(outcome.refusalCode, .invalidReceipt, outcome.description)
        XCTAssertTrue(outcome.description.contains("signature-value"), outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
    }

    /// 7(ii): an all-unspecified signature (`!hasPersistedPayload`, which the package writer would prune) is refused at
    /// prepare as `invalidReceipt "signature-no-effect"`, before any candidate or publish; workspace unchanged.
    func testAllUnspecifiedSignatureIsRefusedTypedAndLeavesWorkspaceUnchanged() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let empty = FunctionSignatureOverride()
        XCTAssertFalse(empty.hasPersistedPayload)
        let before = VCFixture.dump(h.store)
        let outcome = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: empty))
        XCTAssertEqual(outcome.refusalCode, .invalidReceipt, outcome.description)
        XCTAssertTrue(outcome.description.contains("signature-no-effect"), outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertTrue(h.store.verifiedAnnotationAudit.records.isEmpty)
    }

    /// A non-canonical requested value (pretty-printed; `decodeSignature` rejects it as `nonCanonicalSignature`) is
    /// refused at prepare as `invalidReceipt "signature-value"`: no publish, no audit record, workspace unchanged.
    func testNonCanonicalSignatureValueIsRefusedAtPrepare() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let canonicalText = try VerifiedFieldCodec.canonicalSignature(
            VCFixture.signature([("nc1", "buf", "char *")], returnType: "int"))
        let object = try JSONSerialization.jsonObject(with: Data(canonicalText.utf8))
        let pretty = try String(decoding: JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted]),
                                as: UTF8.self)
        XCTAssertNotEqual(pretty, canonicalText)
        XCTAssertThrowsError(try VerifiedFieldCodec.decodeSignature(pretty)) { error in
            XCTAssertEqual(error as? VerifiedFieldCodecError, .nonCanonicalSignature)
        }
        let before = VCFixture.dump(h.store)
        let outcome = await h.session.commitVerifiedAnnotation(try h.signatureRequest(signature: nil, rawText: pretty))
        XCTAssertEqual(outcome.refusalCode, .invalidReceipt, outcome.description)
        XCTAssertTrue(outcome.description.contains("signature-value"), outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
        XCTAssertTrue(h.store.verifiedAnnotationAudit.records.isEmpty)
        XCTAssertNil(h.store.verifiedCommitLatch)
    }

    /// A non-function target is refused typed through the commit path (the opposite of the type class).
    func testSignatureOnNonFunctionAddressIsRefusedNotFunctionEntry() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let before = VCFixture.dump(h.store)
        let outcome = await h.session.commitVerifiedAnnotation(
            try h.signatureRequest(signature: sigA(), key: h.typedKey))
        XCTAssertEqual(outcome.refusalCode, .candidateRejected, outcome.description)
        XCTAssertTrue(outcome.description.contains("notFunctionEntry"), outcome.description)
        XCTAssertEqual(VCFixture.dump(h.store), before)
    }
}
#endif
