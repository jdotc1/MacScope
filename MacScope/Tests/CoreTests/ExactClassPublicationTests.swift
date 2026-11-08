import Foundation
import XCTest
@testable import MacScope

/// Real-store/session/bridge definitions. No file operations or hash computation.
@MainActor
final class ExactClassPublicationTests: XCTestCase {
    private struct Harness {
        let store: WorkspaceStore
        let session: WorkspaceDocumentSession
        let reservations: ExactClassReservations
        let controller: ExactClassReadController
        let selector: ExactClassReadSelector
    }
    private func harness() throws -> Harness {
        let binaryID = UUID()
        var analysis = ImageAnalysis()
        analysis.objcClasses = [ObjCClass(name: "C", superclassName: "NSObject", adoptedProtocols: [],
            classMethods: [], instanceMethods: [], ivars: [], properties: [], address: 0x8000)]
        analysis.analysisInputFingerprint = try AnalysisInputFingerprint(imageSlot: .primary,
            binaryID: binaryID, binaryName: "classes", binaryPath: "/ignored/classes",
            selectedSliceIndex: 0, artifactIdentity: nil, imageByteCount: 4,
            imageBytesSHA256: String(repeating: "b", count: 64),
            facets: [try AnalysisFacetFingerprint(kind: .selectedSliceBytes, itemCount: 1,
                byteCount: 4, sha256: String(repeating: "b", count: 64)),
                try AnalysisFacetFingerprint(kind: .functions, itemCount: 0, sha256: String(repeating: "c", count: 64)),
                try AnalysisFacetFingerprint(kind: .decodedInstructions, itemCount: 0, sha256: String(repeating: "d", count: 64))],
            overallSHA256: String(repeating: "a", count: 64))
        let row = TypeAtlasEntry(id: .init(slot: .primary, kind: .objcClass, key: .address(0x8000)),
            kind: .objcClass, name: "C", superclass: "NSObject", members: [], conformances: [], methods: [],
            users: [], evidence: .descriptor)
        analysis.typeCatalog = .init(slot: .primary, entries: [row])
        let store = WorkspaceStore(workspaceName: "classes", snapshot: .init(binaries: [
            .init(id: binaryID, name: "classes", path: "/ignored/classes", kind: "Mach-O",
                  architecture: "arm64", selectedSliceIndex: 0, slot: .primary)
        ], analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let reservations = ExactClassReservations()
        let session = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
            source: store, io: WorkspaceDocumentIO(), reservations: reservations)
        let owner = try XCTUnwrap(store.phase2ReadCurrentState(for: .primary).image?.owner)
        return .init(store: store, session: session, reservations: reservations,
            controller: .init(store: store, session: session), selector: .init(owner: owner, entryID: row.id))
    }
    private func request(_ h: Harness, found: Bool) -> ExactClassReadSelector {
        .init(owner: h.selector.owner, entryID: .init(slot: .primary, kind: .objcClass,
            key: .address(found ? 0x8000 : 0x9000)))
    }
    func testFoundAndAbsentPublishThroughOriginalAdmission() throws {
        for found in [true, false] {
            let h = try harness(); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: request(h, found: found))
            var delivered: ScriptValue?
            try h.controller.publish(prepared) { delivered = $0 }
            XCTAssertEqual(delivered?["status"], .string(found ? "found" : "notFoundInCurrentCatalog"))
        }
    }
    func testClosedSessionSuppressesBothOutcomes() throws {
        for found in [true, false] {
            let h = try harness()
            let prepared = try h.controller.prepare(selector: request(h, found: found))
            h.session.close()
            var writes = 0
            XCTAssertThrowsError(try h.controller.publish(prepared) { _ in writes += 1 })
            XCTAssertEqual(writes, 0)
        }
    }
    func testSourceMutationSuppressesBothOutcomes() throws {
        for found in [true, false] {
            let h = try harness(); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: request(h, found: found))
            var next = h.store.snapshot
            var analysis = try XCTUnwrap(next.analysis(in: .primary))
            analysis.swiftTypes = [.init(kind: .class, name: "New", fields: [], descriptorAddress: 0xA000)]
            next.replaceAnalysis(analysis, in: .primary); h.store.snapshot = next
            var writes = 0
            XCTAssertThrowsError(try h.controller.publish(prepared) { _ in writes += 1 })
            XCTAssertEqual(writes, 0)
        }
    }
    func testReopenedControllerCannotBorrowPriorPreparedValue() throws {
        for found in [true, false] {
            let h = try harness()
            let prepared = try h.controller.prepare(selector: request(h, found: found))
            h.session.close()
            let reopened = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()), windowID: .fresh(),
                source: h.store, io: WorkspaceDocumentIO(), reservations: h.reservations)
            defer { reopened.close() }
            let replacement = ExactClassReadController(store: h.store, session: reopened)
            XCTAssertThrowsError(try replacement.publish(prepared) { _ in XCTFail("old result escaped") })
            XCTAssertThrowsError(try h.controller.publish(prepared) { _ in XCTFail("closed owner escaped") })
        }
    }
    func testOwnerReplacementCannotBorrowSameAddress() throws {
        for found in [true, false] {
            let h = try harness(); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: request(h, found: found))
            var next = h.store.snapshot
            next.binaries[0] = .init(id: UUID(), name: "replacement", path: "/ignored/new", kind: "Mach-O",
                                     architecture: "arm64", selectedSliceIndex: 0)
            h.store.snapshot = next
            XCTAssertThrowsError(try h.controller.publish(prepared) { _ in XCTFail("replacement escaped") })
        }
    }
    func testCancellationAtFinalHandoffSuppressesDelivery() async throws {
        for found in [true, false] {
            let h = try harness(); defer { h.session.close() }
            let prepared = try h.controller.prepare(selector: request(h, found: found))
            let task = Task { @MainActor in
                withUnsafeCurrentTask { $0?.cancel() }
                XCTAssertThrowsError(try h.controller.publish(prepared) { _ in XCTFail("cancelled result escaped") })
            }
            try await task.value
        }
    }
}

// File-local reservation fixture policy.
@MainActor
private final class ExactClassReservations: WorkspaceDocumentLocationReserving {
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

