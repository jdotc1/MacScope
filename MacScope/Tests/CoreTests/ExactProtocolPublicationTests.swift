import Foundation
import XCTest
@testable import MacScope

/// Fresh original-admission publication definitions only.
@MainActor
final class ExactProtocolPublicationTests: XCTestCase {
    private enum Outcome: CaseIterable { case found, absent, multiple }
    private final class Time {
        var instant = ContinuousClock.now
        var reads = 0
        var expireOnRead: Int?
        func now() -> ContinuousClock.Instant {
            reads += 1
            if let expireOnRead, reads >= expireOnRead { return instant.advanced(by: .seconds(11)) }
            return instant
        }
    }
    private struct Harness {
        let store: WorkspaceStore
        let session: WorkspaceDocumentSession
        let reservations: ExactProtocolReservations // Session retains this authority weakly.
        let controller: ExactProtocolReadController
        let selector: ExactProtocolReadSelector
        let time: Time
    }
    private func harness(_ outcome: Outcome) throws -> Harness {
        let binaryID = UUID()
        let p = ObjCProtocol(name: "P", address: 0x8000, adoptedProtocols: [], requiredMethods: [], optionalMethods: [], properties: [])
        var analysis = ImageAnalysis()
        switch outcome {
        case .found: analysis.objcProtocols = [p]
        case .absent: analysis.objcProtocols = []
        case .multiple: analysis.objcProtocols = [p, p]
        }
        // Inert, grammar-valid fixture identity strings adapted from the supplied real-store
        // fixture. No digest is computed or independently verified; bridge/ledger admission is real.
        analysis.analysisInputFingerprint = try AnalysisInputFingerprint(imageSlot: .primary,
            binaryID: binaryID, binaryName: "protocols", binaryPath: "/ignored/protocols",
            selectedSliceIndex: 0, artifactIdentity: nil, imageByteCount: 4,
            imageBytesSHA256: String(repeating: "b", count: 64),
            facets: [try AnalysisFacetFingerprint(kind: .selectedSliceBytes, itemCount: 1,
                byteCount: 4, sha256: String(repeating: "b", count: 64)),
                try AnalysisFacetFingerprint(kind: .functions, itemCount: 0, sha256: String(repeating: "c", count: 64)),
                try AnalysisFacetFingerprint(kind: .decodedInstructions, itemCount: 0, sha256: String(repeating: "d", count: 64))],
            overallSHA256: String(repeating: "a", count: 64))
        let store = WorkspaceStore(workspaceName: "protocols", snapshot: .init(binaries: [
            .init(id: binaryID, name: "protocols", path: "/ignored/protocols", kind: "Mach-O",
                architecture: "arm64", selectedSliceIndex: 0, slot: .primary)
        ], analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let reservations = ExactProtocolReservations()
        let session = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
            source: store, io: WorkspaceDocumentIO(), reservations: reservations)
        let owner = try XCTUnwrap(store.phase2ReadCurrentState(for: .primary).image?.owner)
        let time = Time()
        return .init(store: store, session: session, reservations: reservations,
            controller: .init(store: store, session: session, now: { time.now() }),
            selector: .init(owner: owner, entryID: .init(slot: .primary, kind: .objcProtocol, key: .address(0x8000))), time: time)
    }
    private func expectSuppressed(_ h: Harness, _ prepared: ExactProtocolReadController.Prepared,
                                  file: StaticString = #filePath, line: UInt = #line) {
        var writes = 0
        XCTAssertThrowsError(try h.controller.publish(prepared) { _ in writes += 1 }, file: file, line: line)
        XCTAssertEqual(writes, 0, file: file, line: line)
    }
    func testAllThreeOutcomesDeliverOnlyThroughOriginalAdmission() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            var delivered: ScriptValue?
            try h.controller.publish(prepared) { delivered = $0 }
            let expected: String
            switch outcome { case .found: expected = "found"; case .absent: expected = "absentInCurrentRecoveredRecords"; case .multiple: expected = "multiple" }
            XCTAssertEqual(delivered?["status"], .string(expected))
            XCTAssertEqual(delivered?["imageOwner"], .string(h.selector.owner.binaryID.uuidString))
        }
    }
    func testProtocolMutationSuppressesAllThreeOutcomes() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            var next = h.store.snapshot; var analysis = try XCTUnwrap(next.analysis(in: .primary))
            analysis.objcProtocols.append(.init(name: "Later", address: 0x9000, adoptedProtocols: [], requiredMethods: [], optionalMethods: [], properties: []))
            next.replaceAnalysis(analysis, in: .primary); h.store.snapshot = next
            expectSuppressed(h, prepared)
        }
    }
    func testOtherSourceMutationSuppressesAllThreeOutcomes() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            var next = h.store.snapshot; var analysis = try XCTUnwrap(next.analysis(in: .primary))
            analysis.swiftTypes = [.init(kind: .class, name: "Later", fields: [], descriptorAddress: 0xA000)]
            next.replaceAnalysis(analysis, in: .primary); h.store.snapshot = next
            expectSuppressed(h, prepared)
        }
    }
    func testSameFingerprintSnapshotTransitionStillAdvancesRevisionForAllOutcomes() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            let before = h.store.phase2ReadCurrentState(for: .primary)
            let retainedSnapshot = h.store.snapshot
            h.store.snapshot = retainedSnapshot
            let after = h.store.phase2ReadCurrentState(for: .primary)
            XCTAssertEqual(before.image?.analysisFingerprintSHA256, after.image?.analysisFingerprintSHA256)
            XCTAssertNotEqual(before.image?.analysisRevision, after.image?.analysisRevision)
            expectSuppressed(h, prepared)
        }
    }
    func testOwnerReplacementAndSliceChangesSuppressAllOutcomes() throws {
        for outcome in Outcome.allCases {
            for replaceOwner in [true, false] {
                let h = try harness(outcome); defer { h.session.close() }
                let prepared = try h.controller.prepare(selector: h.selector)
                var next = h.store.snapshot
                if replaceOwner {
                    next.binaries[0] = .init(id: UUID(), name: "replacement", path: "/ignored/replacement",
                        kind: "Mach-O", architecture: "arm64", selectedSliceIndex: 0, slot: .primary)
                }
                else { next.binaries[0].selectedSliceIndex = 1 }
                h.store.snapshot = next
                expectSuppressed(h, prepared)
            }
        }
    }
    func testWorkspaceMetadataAndUserAuthoringTransitionsSuppressAllOutcomes() throws {
        for outcome in Outcome.allCases {
            for metadata in [true, false] {
                let h = try harness(outcome); defer { h.session.close() }
                let prepared = try h.controller.prepare(selector: h.selector)
                if metadata { h.store.workspaceName = "renamed" }
                else {
                    h.store.setCustomComment(0x8000, in: .primary, comment: "authored after preparation")
                }
                expectSuppressed(h, prepared)
            }
        }
    }
    func testSessionCloseAndReopenSuppressAllOutcomesAndOldAdmission() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome)
            let prepared = try h.controller.prepare(selector: h.selector)
            h.session.close()
            expectSuppressed(h, prepared)
            let reopened = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
                source: h.store, io: WorkspaceDocumentIO(), reservations: h.reservations)
            defer { reopened.close() }
            let replacement = ExactProtocolReadController(store: h.store, session: reopened, now: { h.time.now() })
            XCTAssertThrowsError(try replacement.publish(prepared) { _ in XCTFail("reopened result escaped") })
            expectSuppressed(h, prepared)
        }
    }
    func testTerminationFenceSuppressesAllOutcomes() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            XCTAssertTrue(h.session.beginTerminationPreparation())
            expectSuppressed(h, prepared)
        }
    }
    func testDifferentControllerCannotBorrowAnyPreparedOutcome() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            let other = ExactProtocolReadController(store: h.store, session: h.session, now: { h.time.now() })
            XCTAssertThrowsError(try other.publish(prepared) { _ in XCTFail("wrong instance escaped") })
        }
    }
    func testCancellationAtDeliverySuppressesAllOutcomes() async throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            await Task { @MainActor in
                withUnsafeCurrentTask { $0?.cancel() }
                self.expectSuppressed(h, prepared)
            }.value
        }
    }
    func testCancellationBeforeAdmissionCannotPrepare() async throws {
        let h = try harness(.found); defer { h.session.close() }
        try await Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            XCTAssertThrowsError(try h.controller.prepare(selector: h.selector)) {
                XCTAssertTrue($0 is CancellationError)
            }
        }.value
    }
    func testDeadlineAtActualDeliverySuppressesEveryOutcomeWithoutSleep() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            var limits = ExactProtocolReadLimits(); limits.duration = .milliseconds(1)
            let prepared = try h.controller.prepare(selector: h.selector, limits: limits)
            h.time.instant = h.time.instant.advanced(by: .milliseconds(1))
            expectSuppressed(h, prepared)
        }
    }
    func testDeadlineRecheckedInsideActualBridgeSinkForEveryOutcome() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            // First publish check is current; actual post-bridge synchronous sink is expired.
            h.time.expireOnRead = h.time.reads + 2
            expectSuppressed(h, prepared)
        }
    }
    func testPreparationCannotResetDeadlineAfterAdmission() throws {
        let h = try harness(.found); defer { h.session.close() }
        h.time.expireOnRead = h.time.reads + 3
        XCTAssertThrowsError(try h.controller.prepare(selector: h.selector)) {
            XCTAssertEqual($0 as? ExactProtocolReadFailure, .deadlineExceeded)
        }
    }
    func testDeferredSinkMustRepublishRetainedPreparedValueForAllOutcomes() throws {
        for outcome in Outcome.allCases {
            let h = try harness(outcome); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: h.selector)
            var deferred: (() throws -> Void)?
            var writes = 0
            try h.controller.publish(prepared) { _ in
                // Deliberately retain Prepared, not an escaped freshness Boolean/value.
                deferred = { try h.controller.publish(prepared) { _ in writes += 1 } }
            }
            h.store.workspaceName = "changed before queued delivery"
            XCTAssertThrowsError(try XCTUnwrap(deferred)())
            XCTAssertEqual(writes, 0)
        }
    }
    func testCallerOwnerAndForeignSessionDoNotMintAuthority() throws {
        let h = try harness(.found), other = try harness(.found)
        defer { h.session.close(); other.session.close() }
        let wrong = ExactProtocolReadController(store: h.store, session: other.session, now: { h.time.now() })
        XCTAssertThrowsError(try wrong.prepare(selector: h.selector))
        let inventedOwner = Phase2ReadImageOwner(slot: .primary, binaryID: h.selector.owner.binaryID,
            architecture: "arm64", sliceIndex: 0, ownerGeneration: h.selector.owner.ownerGeneration + 1)
        XCTAssertThrowsError(try h.controller.prepare(selector: .init(owner: inventedOwner, entryID: h.selector.entryID)))
    }
}

// File-local real contract fixture, adapted only from the supplied reservation helper.
@MainActor
private final class ExactProtocolReservations: WorkspaceDocumentLocationReserving {
    private struct Reservation {
        let sessionID: WorkspaceDocumentSessionID
        let windowID: WorkspaceWindowID
        let physicalIdentity: WorkspaceFileObjectIdentity?
    }

    private struct Publication {
        let sessionID: WorkspaceDocumentSessionID
        let windowID: WorkspaceWindowID
        let retainingPublishedOwnership: Bool
    }

    private var reservations: [URL: Reservation] = [:]
    private var reservationsByPhysicalIdentity: [WorkspaceFileObjectIdentity: Reservation] = [:]
    private var forcedOwners: [URL: WorkspaceWindowID] = [:]
    private(set) var releasedLocations: [WorkspaceDocumentLocation] = []
    private(set) var releaseAllCount = 0
    private var activePublications:
        [WorkspaceDocumentPublicationReservation: Publication] = [:]
    private var nextPublicationCompletion:
        WorkspaceDocumentPublicationCompletionResult?
    private(set) var completedPublicationCount = 0

    var activePublicationCount: Int { activePublications.count }

    func forceNextPublicationCompletion(
        _ result: WorkspaceDocumentPublicationCompletionResult
    ) {
        nextPublicationCompletion = result
    }

    func forceOwner(_ owner: WorkspaceWindowID, for location: WorkspaceDocumentLocation) {
        forcedOwners[location.canonicalURL] = owner
    }

    func owner(of location: WorkspaceDocumentLocation) -> WorkspaceWindowID? {
        forcedOwners[location.canonicalURL]
            ?? reservations[location.canonicalURL]?.windowID
            ?? location.fileObjectIdentity.flatMap {
                reservationsByPhysicalIdentity[$0]?.windowID
            }
    }

    func reserve(
        _ location: WorkspaceDocumentLocation,
        for sessionID: WorkspaceDocumentSessionID,
        windowID: WorkspaceWindowID
    ) -> WorkspaceDocumentLocationReservationResult {
        if let forced = forcedOwners[location.canonicalURL] {
            return .alreadyOwned(forced)
        }
        if let existing = reservations[location.canonicalURL] {
            if existing.sessionID != sessionID {
                return .alreadyOwned(existing.windowID)
            }
        }
        if let identity = location.fileObjectIdentity,
           let existing = reservationsByPhysicalIdentity[identity],
           existing.sessionID != sessionID {
            return .alreadyOwned(existing.windowID)
        }
        let priorIdentity = reservations[location.canonicalURL]?.physicalIdentity
        let reservation = Reservation(
            sessionID: sessionID,
            windowID: windowID,
            physicalIdentity: location.fileObjectIdentity
        )
        reservations[location.canonicalURL] = reservation
        if let identity = location.fileObjectIdentity {
            reservationsByPhysicalIdentity[identity] = reservation
        }
        if priorIdentity != location.fileObjectIdentity,
           let priorIdentity,
           !reservations.values.contains(where: { owner in
               owner.physicalIdentity == priorIdentity
           }) {
            reservationsByPhysicalIdentity[priorIdentity] = nil
        }
        return .reserved
    }

    func release(
        _ location: WorkspaceDocumentLocation,
        for sessionID: WorkspaceDocumentSessionID
    ) {
        releasedLocations.append(location)
        guard let reservation = reservations[location.canonicalURL],
              reservation.sessionID == sessionID else { return }
        reservations[location.canonicalURL] = nil
        if let identity = location.fileObjectIdentity,
           reservationsByPhysicalIdentity[identity]?.sessionID == reservation.sessionID,
           reservationsByPhysicalIdentity[identity]?.windowID == reservation.windowID {
            reservationsByPhysicalIdentity[identity] = nil
        }
    }

    func releaseAll(for sessionID: WorkspaceDocumentSessionID) {
        releaseAllCount += 1
        reservations = reservations.filter { $0.value.sessionID != sessionID }
        reservationsByPhysicalIdentity = reservationsByPhysicalIdentity.filter {
            $0.value.sessionID != sessionID
        }
    }

    func beginPhysicalPublication(
        _ staged: WorkspaceDocumentStagedPackage,
        to destination: WorkspaceDocumentLocation,
        retainingPublishedOwnership: Bool,
        for sessionID: WorkspaceDocumentSessionID,
        windowID: WorkspaceWindowID
    ) -> WorkspaceDocumentPublicationReservationResult {
        if let owner = owner(of: destination), owner != windowID {
            return .alreadyOwned(owner)
        }
        let publication = WorkspaceDocumentPublicationReservation()
        activePublications[publication] = Publication(
            sessionID: sessionID,
            windowID: windowID,
            retainingPublishedOwnership: retainingPublishedOwnership
        )
        return .reserved(publication)
    }

    func completePhysicalPublication(
        _ publication: WorkspaceDocumentPublicationReservation,
        at publishedLocation: WorkspaceDocumentLocation
    ) -> WorkspaceDocumentPublicationCompletionResult {
        guard let pending = activePublications.removeValue(forKey: publication) else {
            return .invalid
        }
        if let forced = nextPublicationCompletion {
            nextPublicationCompletion = nil
            return forced
        }
        if pending.retainingPublishedOwnership {
            guard case .reserved = reserve(
                publishedLocation,
                for: pending.sessionID,
                windowID: pending.windowID
            ) else {
                return .invalid
            }
        }
        completedPublicationCount += 1
        return .completed
    }

    func cancelPhysicalPublication(
        _ publication: WorkspaceDocumentPublicationReservation
    ) {
        activePublications[publication] = nil
    }

    func isReserved(
        _ location: WorkspaceDocumentLocation,
        by sessionID: WorkspaceDocumentSessionID
    ) -> Bool {
        reservations[location.canonicalURL]?.sessionID == sessionID
    }
}

