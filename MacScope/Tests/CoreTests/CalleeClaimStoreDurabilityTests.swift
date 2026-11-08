import Foundation
import XCTest
@testable import MacScope

// Item 1256, pin 91b26a1bb. Authored, unrun. Synthetic data only.
#if DEBUG
@MainActor
final class CalleeClaimStoreDurabilityTests: XCTestCase {
    private struct Injected: Error {}
    private struct Fixture {
        let package: URL
        let journal: URL
        let store: WorkspaceStore
    }

    private func syntheticStore(at input: URL) throws -> WorkspaceStore {
        let bytes = Data("inert claim durability fixture".utf8)
        try bytes.write(to: input)
        var analysis = ImageAnalysis()
        analysis.imageBytes = bytes
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims",
            path: input.path, kind: "executable", architecture: "arm64",
            slot: .primary), analysis: analysis)
        return WorkspaceStore(workspaceName: "claims", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func fixture(attach: Bool = true) throws -> Fixture {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        let package = root.appendingPathComponent("Base.mscope")
        let original = try syntheticStore(at: root.appendingPathComponent("input.dat"))
        _ = try original.writeDocumentPackageThrowing(to: package)
        let store = try WorkspaceStore.restoredPackage(from: package, scheduleDurableRecovery: false)
        let journal = root.appendingPathComponent("edits.journal")
        if attach { try store.attachEditJournal(at: journal) }
        return Fixture(package: package, journal: journal, store: store)
    }

    private func inventory() throws -> VACalleeInventory {
        let entry = VACalleeInventoryEntry(callee: VAAddress64(0x3000), kind: .function,
            name: "synthetic helper", callSiteCount: 1, callSites: [VAAddress64(0x5004)],
            callSitesTruncated: false)
        return VACalleeInventory(function: VAAddress64(0x5000), callees: [entry],
            inventoryDigest: try VACalleeInventory.digest(
                callEdges: [(site: VAAddress64(0x5004), target: VAAddress64(0x3000))], limitations: []))
    }

    private func observation(_ store: WorkspaceStore) throws -> VACalleeClaimObservation {
        VACalleeClaimObservation(imageOwner: try XCTUnwrap(store.snapshot.binaries.first).id,
            generation: store.snapshot.analysisGenerationID, inventory: try inventory())
    }

    private func open(_ store: WorkspaceStore) throws -> UUID {
        let id = UUID(), inv = try inventory()
        let image = try XCTUnwrap(store.snapshot.binaries.first)
        let binding = VACalleeClaimBinding(imageOwner: image.id, slot: image.slot.rawValue,
            function: inv.function, analysisGeneration: store.snapshot.analysisGenerationID,
            inventoryDigest: inv.inventoryDigest)
        try store.calleeClaimLedgerBox.ledger.open(claimID: id, inventory: inv,
            binding: binding, atMilliseconds: 1)
        return id
    }

    private func outcome(_ store: WorkspaceStore, _ id: UUID, reason: String = "checked") throws {
        try store.calleeClaimLedgerBox.ledger.recordOutcome(claimID: id,
            callee: VAAddress64(0x3000), outcome: .irrelevant, reason: reason,
            observed: observation(store), atMilliseconds: 2)
    }

    private func reopen(_ f: Fixture) throws -> WorkspaceStore {
        try WorkspaceStore.restoredPackage(from: f.package, scheduleDurableRecovery: false)
    }

    private func save(_ f: Fixture) throws {
        _ = try f.store.writeDocumentPackageThrowing(to: f.package)
    }

    func testSaveAndReopenRestoresClaimsOutcomesRevisionsAndBindings() throws {
        let f = try fixture()
        let id = try open(f.store)
        try outcome(f.store, id)
        let expected = f.store.calleeClaimLedger
        let generation = f.store.snapshot.analysisGenerationID
        try save(f)
        f.store.detachEditJournal()?.close()
        let fresh = try reopen(f)
        XCTAssertEqual(fresh.calleeClaimLedger, expected)
        XCTAssertNotEqual(fresh.snapshot.analysisGenerationID, generation)
        XCTAssertEqual(fresh.calleeClaimDurability.rawValue, "package")
        let status = try fresh.calleeClaimLedger.report(claimID: id, observed: observation(fresh))
        XCTAssertEqual(status.status, .stale)
        XCTAssertEqual(status.staleKind, .generationAdvanced)
        XCTAssertTrue(status.rebindable)
        XCTAssertEqual(expected.events.last?.reason, "checked")
    }

    func testReopenRebindSaveReopenRetainsRebindAndOutcomeHistory() throws {
        let f = try fixture(attach: false)
        let id = try open(f.store)
        try outcome(f.store, id)
        try save(f)
        let rebound = try reopen(f)
        try rebound.calleeClaimLedgerBox.ledger.rebind(claimID: id,
            observed: observation(rebound), atMilliseconds: 3)
        XCTAssertEqual(rebound.calleeClaimLedger.events.last?.kind, .claimRebound)
        XCTAssertEqual(rebound.calleeClaimDurability.rawValue, "session")
        _ = try rebound.writeDocumentPackageThrowing(to: f.package)
        XCTAssertEqual(try reopen(f).calleeClaimLedger, rebound.calleeClaimLedger)
    }

    func testKillAfterAppendFreshStoreRestoresLastSynchronizedEvent() throws {
        let f = try fixture()
        let id = try open(f.store)
        try outcome(f.store, id, reason: "last synchronized event")
        let expected = f.store.calleeClaimLedger
        XCTAssertEqual(f.store.calleeClaimDurability.rawValue, "journal")
        f.store.detachEditJournal()?.close()
        let fresh = try reopen(f)
        XCTAssertTrue(fresh.calleeClaimLedger.events.isEmpty)
        try fresh.attachEditJournal(at: f.journal)
        XCTAssertEqual(fresh.calleeClaimLedger, expected)
        XCTAssertEqual(fresh.calleeClaimLedger.events.last?.reason, "last synchronized event")
        fresh.detachEditJournal()?.close()
        try fresh.attachEditJournal(at: f.journal)
        XCTAssertEqual(fresh.calleeClaimLedger, expected, "exact overlap must not append twice")
        fresh.detachEditJournal()?.close()
    }

    func testTornClaimTailFreshAttachDropsAndTruncatesOnlyUnsynchronizedSuffix() throws {
        let f = try fixture()
        let id = try open(f.store)
        let prefix = f.store.calleeClaimLedger
        try outcome(f.store, id)
        f.store.detachEditJournal()?.close()
        let original = try Data(contentsOf: f.journal)
        let lines = original.split(separator: 0x0a, omittingEmptySubsequences: true)
        XCTAssertEqual(lines.count, 3, "header, open claim, outcome")
        let final = try XCTUnwrap(lines.last)
        let completeCount = original.count - final.count - 1
        var torn = Data(original.prefix(completeCount))
        torn.append(contentsOf: final.prefix(max(1, final.count / 2)))
        try torn.write(to: f.journal)
        let parsed = try EditJournalReader.read(torn)
        XCTAssertNotNil(parsed.tornTail)
        let fresh = try reopen(f)
        let report = try fresh.attachEditJournal(at: f.journal)
        XCTAssertNotNil(report.tornTail)
        XCTAssertEqual(fresh.calleeClaimLedger, prefix)
        XCTAssertEqual(try Data(contentsOf: f.journal).count, parsed.completeByteCount)
        fresh.detachEditJournal()?.close()
        let again = try fresh.attachEditJournal(at: f.journal)
        XCTAssertNil(again.tornTail)
        XCTAssertEqual(fresh.calleeClaimLedger, prefix)
        fresh.detachEditJournal()?.close()
    }

    func testSaveRotationThenAppendKillReplayKeepsContiguousLedger() throws {
        let f = try fixture()
        let id = try open(f.store)
        try save(f)
        try outcome(f.store, id)
        let expected = f.store.calleeClaimLedger
        let contents = try EditJournalReader.read(Data(contentsOf: f.journal))
        XCTAssertEqual(contents.header?.version, 2)
        XCTAssertEqual(contents.records.map(\.seq), Array(1...UInt64(contents.records.count)))
        f.store.detachEditJournal()?.close()
        let fresh = try reopen(f)
        try fresh.attachEditJournal(at: f.journal)
        XCTAssertEqual(fresh.calleeClaimLedger, expected)
        fresh.detachEditJournal()?.close()
    }

    func testInterruptedRotationAlreadySavedPrefixIsNotAppliedTwice() throws {
        let f = try fixture()
        let id = try open(f.store)
        try outcome(f.store, id)
        let expected = f.store.calleeClaimLedger
        f.store.detachEditJournal()?.close()
        try save(f) // Publish manifest without rotating the detached writer.
        let fresh = try reopen(f)
        try fresh.attachEditJournal(at: f.journal)
        XCTAssertEqual(fresh.calleeClaimLedger, expected)
        fresh.detachEditJournal()?.close()
        let again = try reopen(f)
        try again.attachEditJournal(at: f.journal)
        XCTAssertEqual(again.calleeClaimLedger, expected)
        again.detachEditJournal()?.close()
    }

    func testConflictingJournalOverlapRefusesWithoutChangingStoreOrFile() throws {
        let f = try fixture()
        let id = try open(f.store)
        try outcome(f.store, id, reason: "journal branch")
        f.store.detachEditJournal()?.close()
        let events = f.store.calleeClaimLedger.events
        let last = try XCTUnwrap(events.last)
        let conflicting = VACalleeClaimEvent(sequence: last.sequence, atMilliseconds: last.atMilliseconds,
            claimID: id, kind: .outcomeRecorded, revision: last.revision, callee: last.callee,
            outcome: last.outcome, reason: "package branch")
        f.store.calleeClaimLedgerBox.ledger = try CalleeClaimLedger(events: [events[0], conflicting])
        try save(f)
        let fresh = try reopen(f)
        let before = fresh.calleeClaimLedger
        let bytes = try Data(contentsOf: f.journal)
        XCTAssertThrowsError(try fresh.attachEditJournal(at: f.journal))
        XCTAssertEqual(fresh.calleeClaimLedger, before)
        XCTAssertNil(fresh.editJournal)
        XCTAssertEqual(try Data(contentsOf: f.journal), bytes)
    }

    func testIdentityMismatchLoadsDetachedWithoutRewritingClaimsOrOutcomes() throws {
        let f = try fixture(attach: false)
        let id = try open(f.store)
        try outcome(f.store, id)
        let expected = f.store.calleeClaimLedger
        let foreign = try syntheticStore(at: f.package.deletingLastPathComponent().appendingPathComponent("other.dat"))
        foreign.calleeClaimLedgerBox.ledger = expected
        _ = try foreign.writeDocumentPackageThrowing(to: f.package)
        let fresh = try reopen(f)
        XCTAssertEqual(fresh.calleeClaimLedger, expected)
        XCTAssertEqual(fresh.calleeClaimAttachmentState(claimID: id).rawValue, "detached")
        XCTAssertEqual(fresh.calleeClaimLedger.events.last?.reason, "checked")
        XCTAssertEqual(try fresh.persistableCalleeClaims()?.makeLedger(), expected)
    }

    func testFailedAppendNeverClaimsJournalDurabilityAndFreshStoreRecoversOnlyPrefix() throws {
        let f = try fixture()
        let id = try open(f.store)
        let synchronized = f.store.calleeClaimLedger
        f.store.editJournal?.appendHook = { _ in throw Injected() }
        try outcome(f.store, id)
        XCTAssertEqual(f.store.calleeClaimDurability.rawValue, "session")
        XCTAssertNotNil(f.store.editJournal?.failure)
        f.store.detachEditJournal()?.close()
        let fresh = try reopen(f)
        try fresh.attachEditJournal(at: f.journal)
        XCTAssertEqual(fresh.calleeClaimLedger, synchronized)
        fresh.detachEditJournal()?.close()
    }

    func testFailedRotationKeepsPublishedLedgerAndStickyWriterFailure() throws {
        let f = try fixture()
        _ = try open(f.store)
        let expected = f.store.calleeClaimLedger
        f.store.editJournal?.rotateHook = { if $0 == "header" { throw Injected() } }
        try save(f)
        XCTAssertNotNil(f.store.editJournal?.failure)
        XCTAssertEqual(try reopen(f).calleeClaimLedger, expected)
        f.store.detachEditJournal()?.close()
    }

    func testCombinedAuditAndClaimsReplayInOneJournalWithoutLosingEitherHistory() throws {
        let f = try fixture()
        let id = try open(f.store)
        let stamp = VAProjectionStamp(workspaceID: f.store.workspaceID,
            documentID: f.store.documentID, installationID: UUID(), revision: 7,
            digest: String(repeating: "a", count: 64))
        let request = VAMutationRequest(id: UUID(), base: stamp,
            edits: [.init(target: .init(componentID: UUID(), function: VAAddress64(0x5000)),
                          kind: .functionName, value: "proposed", evidenceIDs: [])],
            rationale: "Synthetic audit replay")
        let receipt = try VAVerificationReceipt(request: request, decision: .rejected,
            before: stamp, after: nil, mechanical: .notVerified, persistence: .notApplicable,
            failure: "synthetic rejection", recordedAt: Date(timeIntervalSince1970: 1))
        let audit = try VerifiedAnnotationAuditRecord(receipt: receipt,
            nativeEvidenceLinks: [], checkpointReferences: [])
        f.store.editJournal?.appendVerifiedAnnotation(slot: -1, address: 0,
            changesOverride: false, value: nil, audit: audit)
        XCTAssertNil(f.store.editJournal?.failure)
        try outcome(f.store, id)
        let expected = f.store.calleeClaimLedger
        let contents = try EditJournalReader.read(Data(contentsOf: f.journal))
        XCTAssertEqual(contents.records.map(\.seq), [1, 2, 3])
        f.store.detachEditJournal()?.close()
        let fresh = try reopen(f)
        let report = try fresh.attachEditJournal(at: f.journal)
        XCTAssertTrue(report.unattachedAuditRecords.isEmpty)
        XCTAssertEqual(fresh.verifiedAnnotationAudit.records, [audit])
        XCTAssertEqual(fresh.calleeClaimLedger, expected)
        fresh.detachEditJournal()?.close()
    }

    func testReinstallSamePackageClosesOldClaimWriterAndResetsDurabilityMarkers() throws {
        let f = try fixture()
        let id = try open(f.store)
        try save(f)
        let saved = f.store.calleeClaimLedger
        try outcome(f.store, id)
        let oldWriter = try XCTUnwrap(f.store.editJournal)
        try f.store.restoreWorkspacePackage(from: f.package)
        XCTAssertNil(f.store.editJournal)
        XCTAssertEqual(oldWriter.observedHealth, .unavailable)
        XCTAssertEqual(f.store.calleeClaimLedger, saved)
        XCTAssertEqual(f.store.calleeClaimDurability.rawValue, "package")
        let newJournal = f.journal.deletingLastPathComponent().appendingPathComponent("new.journal")
        try f.store.attachEditJournal(at: newJournal)
        try f.store.calleeClaimLedgerBox.ledger.rebind(claimID: id,
            observed: observation(f.store), atMilliseconds: 3)
        try outcome(f.store, id)
        XCTAssertEqual(f.store.calleeClaimDurability.rawValue, "journal")
        f.store.detachEditJournal()?.close()
    }

    func testDelayedPublicationAcknowledgesOnlyCapturedClaimPrefix() throws {
        let f = try fixture(attach: false)
        let id = try open(f.store)
        let captured = f.store.calleeClaimLedger
        let payload = try f.store.makePackagePayload()
        try outcome(f.store, id)
        let current = f.store.calleeClaimLedger
        let manifest = try MacScopeDocumentPackage.validatedManifest(manifestData: payload.manifestData)
        XCTAssertEqual(try manifest.calleeClaims?.makeLedger(), captured)
        _ = try MacScopeDocumentPackage.writePackage(manifest,
            attachmentsByBinaryID: payload.attachmentsByBinaryID,
            reconstructionState: payload.reconstructionState,
            reconstructionAttachmentSources: payload.reconstructionAttachmentSources,
            to: f.package, instructionSidecarData: payload.instructionSidecarData)
        f.store.acceptPublishedWrite(capturedGeneration: payload.capturedMutationGeneration, adopting: nil)
        XCTAssertEqual(f.store.calleeClaimLedger, current)
        XCTAssertEqual(f.store.calleeClaimDurability.rawValue, "session")
        XCTAssertTrue(f.store.hasUnsavedChanges)
        XCTAssertEqual(try reopen(f).calleeClaimLedger, captured)
    }

    func testEmptyClaimAsyncPublicationLeavesExistingJournalBytesAndSequenceUnchanged() throws {
        let f = try fixture()
        let writer = try XCTUnwrap(f.store.editJournal)
        writer.appendSlotOverrides(f.store.snapshot.primarySlot, [:])
        XCTAssertNil(writer.failure)
        XCTAssertTrue(f.store.calleeClaimLedger.events.isEmpty)
        let bytes = try Data(contentsOf: f.journal)
        let sequence = writer.appendedSequence
        XCTAssertEqual(sequence, 1)
        let payload = try f.store.makePackagePayload()
        let manifest = try MacScopeDocumentPackage.validatedManifest(manifestData: payload.manifestData)
        _ = try MacScopeDocumentPackage.writePackage(manifest,
            attachmentsByBinaryID: payload.attachmentsByBinaryID,
            reconstructionState: payload.reconstructionState,
            reconstructionAttachmentSources: payload.reconstructionAttachmentSources,
            to: f.package, instructionSidecarData: payload.instructionSidecarData)
        f.store.acceptPublishedWrite(capturedGeneration: payload.capturedMutationGeneration, adopting: nil)
        XCTAssertEqual(try Data(contentsOf: f.journal), bytes)
        XCTAssertEqual(writer.appendedSequence, sequence)
        XCTAssertNil(writer.failure)
        f.store.detachEditJournal()?.close()
    }

    func testEmptyClaimsOmitEnvelopeAndFeatureAndPreserveManifestEncoding() throws {
        let f = try fixture(attach: false)
        let manifest = try MacScopeDocumentPackage.readManifest(from: f.package)
        XCTAssertNil(manifest.calleeClaims)
        XCTAssertFalse(manifest.requiredReaderFeatures.contains("callee-claims.v1"))
        let bytes = try MacScopeDocumentPackage.encodedManifest(manifest)
        var explicitEmpty = manifest
        explicitEmpty.calleeClaims = try CalleeClaimEnvelope(ledger: CalleeClaimLedger())
        let prepared = try MacScopeDocumentPackage.preparedManifest(explicitEmpty, reconstructionState: .empty)
        XCTAssertEqual(try MacScopeDocumentPackage.encodedManifest(prepared), bytes)
        XCTAssertEqual(f.store.calleeClaimDurability.rawValue, "session")
        XCTAssertNil(try f.store.persistableCalleeClaims())
    }

    // R3: command replies report the store's durability, read after the mutation returns.
    func testCommandRepliesReportStoreDurabilityAfterOpenAndSave() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        let input = root.appendingPathComponent("input.dat")
        let bytes = Data("inert claim durability fixture".utf8)
        try bytes.write(to: input)
        var analysis = ImageAnalysis()
        analysis.imageBytes = bytes
        analysis.functions = [
            FunctionSummary(id: UUID(), name: "_root", startAddress: 0x5000, endAddress: 0x5040, confidence: 1),
            FunctionSummary(id: UUID(), name: "_helper", startAddress: 0x3000, endAddress: 0x3010, confidence: 1),
        ]
        analysis.xrefs = [XRef(id: UUID(), from: 0x5004, to: 0x3000, kind: XRefKind.call)]
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims", path: input.path,
            kind: "executable", architecture: "arm64", slot: .primary), analysis: analysis)
        let store = WorkspaceStore(workspaceName: "claims", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        let opened = try api.execute("open-claim", arguments: .object(["address": .hex(0x5000)]))
        XCTAssertEqual(opened["ok"], .bool(true))
        XCTAssertEqual(opened["durability"], .string("session"))
        XCTAssertEqual(try api.execute("claim-status", arguments: .object([:]))["durability"], .string("session"))
        _ = try store.writeDocumentPackageThrowing(to: root.appendingPathComponent("Base.mscope"))
        XCTAssertEqual(store.calleeClaimDurability, .package)
        XCTAssertEqual(try api.execute("claim-status", arguments: .object([:]))["durability"], .string("package"))
    }
}
#endif
