import Foundation
import XCTest
@testable import MacScope

@MainActor
final class BoundedListingPublicationIntegrationTests: XCTestCase {
    private let secondary = ImageSlot(rawValue: 1)

    func testRealCapturePublishesSecondaryAtEqualPrimaryAddress() throws {
        let fixture = try makeFixture()
        defer { fixture.close() }
        let prepared = try capture(fixture)
        let destination = fixture.directory.appendingPathComponent("secondary.txt")

        XCTAssertEqual(fixture.store.focusedImageSlot, secondary)
        XCTAssertTrue(prepared.isCurrent())
        try prepared.publish(to: destination)

        let written = try String(contentsOf: destination, encoding: .utf8)
        XCTAssertEqual(written, prepared.content.listing.text)
        XCTAssertTrue(written.contains("ret"))
        XCTAssertTrue(written.contains("secondary-only"))
        XCTAssertFalse(written.contains("nop"))
        XCTAssertFalse(written.contains("primary-only"))
        XCTAssertTrue(prepared.content.listing.isComplete)
        XCTAssertEqual(prepared.content.listing.consumedRows, 1)
        XCTAssertEqual(prepared.content.suggestedName, "Publication-Secondary-listing")
    }

    func testRealCaptureRefusesMissingSecondaryAdmissionBeforePublication() throws {
        let fixture = try makeFixture(retainSecondaryFingerprint: false)
        defer { fixture.close() }
        let destination = fixture.directory.appendingPathComponent("unadmitted.txt")
        var captureReturned = false

        XCTAssertThrowsError(try {
            let prepared = try capture(fixture)
            captureReturned = true
            try prepared.publish(to: destination)
        }()) { error in
            XCTAssertEqual(error as? NEWFEATURESAdmissionFailure, .analysisRequired)
        }

        XCTAssertFalse(captureReturned)
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
        XCTAssertNotNil(fixture.store.snapshot.analysis(in: .primary)?.analysisInputFingerprint)
        XCTAssertNil(fixture.store.snapshot.analysis(in: secondary)?.analysisInputFingerprint)
    }

    func testRealAuthoringMutationPreventsPreparedFileReplacement() throws {
        let fixture = try makeFixture()
        defer { fixture.close() }
        let prepared = try capture(fixture)
        let destination = try existingDestination(in: fixture)
        let generation = fixture.store.mutationGeneration.rawValue

        XCTAssertTrue(prepared.isCurrent())
        fixture.store.setCustomComment(0x1000, in: secondary, comment: "changed-after-capture")

        XCTAssertGreaterThan(fixture.store.mutationGeneration.rawValue, generation)
        XCTAssertEqual(fixture.store.snapshot.addressOverrides[
            ImageAddress(slot: secondary, address: 0x1000)]?.customComment, "changed-after-capture")
        XCTAssertFalse(prepared.isCurrent())
        XCTAssertThrowsError(try prepared.publish(to: destination)) { error in
            guard case .staleSource? = error as? BoundedListingExportController.Failure else {
                return XCTFail("Expected stale source after a real authoring mutation, got \(error)")
            }
        }
        XCTAssertEqual(try String(contentsOf: destination, encoding: .utf8), "keep-existing-file")
    }

    func testRealSecondaryReplacementPreventsPreparedFileReplacement() throws {
        let fixture = try makeFixture()
        defer { fixture.close() }
        let prepared = try capture(fixture)
        let destination = try existingDestination(in: fixture)
        let originalID = try XCTUnwrap(fixture.store.snapshot.binary(in: secondary)?.id)
        let replacement = makeBinary(name: "Replacement", slot: secondary, directory: fixture.directory)
        let analysis = try makeAnalysis(binary: replacement, secondary: true, retainFingerprint: true)

        XCTAssertTrue(prepared.isCurrent())
        var snapshot = fixture.store.snapshot
        snapshot.removeImage(in: secondary)
        snapshot.insertImage(binary: replacement, analysis: analysis)
        fixture.store.snapshot = snapshot

        XCTAssertNotEqual(fixture.store.snapshot.binary(in: secondary)?.id, originalID)
        XCTAssertEqual(fixture.store.focusedImageSlot, secondary)
        XCTAssertFalse(prepared.isCurrent())
        XCTAssertThrowsError(try prepared.publish(to: destination)) { error in
            guard case .staleSource? = error as? BoundedListingExportController.Failure else {
                return XCTFail("Expected stale source after replacing the selected image, got \(error)")
            }
        }
        XCTAssertEqual(try String(contentsOf: destination, encoding: .utf8), "keep-existing-file")
    }

    func testRealSessionClosePreventsPreparedFileReplacement() throws {
        let fixture = try makeFixture()
        defer { fixture.close() }
        let prepared = try capture(fixture)
        let destination = try existingDestination(in: fixture)

        XCTAssertTrue(prepared.isCurrent())
        fixture.session.close()

        XCTAssertTrue(fixture.session.isClosedForWindowClose)
        XCTAssertFalse(prepared.isCurrent())
        XCTAssertThrowsError(try prepared.publish(to: destination)) { error in
            XCTAssertEqual(error as? NEWFEATURESAdmissionFailure, .documentClosed)
        }
        XCTAssertEqual(try String(contentsOf: destination, encoding: .utf8), "keep-existing-file")
    }

    func testRealFocusChangeRefusesPublicationInsteadOfRetargetingPrimary() throws {
        let fixture = try makeFixture()
        defer { fixture.close() }
        let prepared = try capture(fixture)
        let destination = try existingDestination(in: fixture)

        XCTAssertTrue(prepared.isCurrent())
        fixture.store.focusImage(.primary)

        XCTAssertEqual(fixture.store.focusedImageSlot, .primary)
        XCTAssertTrue(prepared.content.listing.text.contains("secondary-only"))
        XCTAssertFalse(prepared.content.listing.text.contains("primary-only"))
        // Focus changes advance the store's workspace revision, invalidating this capture.
        XCTAssertFalse(prepared.isCurrent())
        XCTAssertThrowsError(try prepared.publish(to: destination)) { error in
            guard case .staleSource? = error as? BoundedListingExportController.Failure else {
                return XCTFail("Expected stale source after changing focus, got \(error)")
            }
        }
        XCTAssertEqual(try String(contentsOf: destination, encoding: .utf8), "keep-existing-file")
    }

    private func capture(_ fixture: Fixture) throws -> BoundedListingExportController.Prepared {
        // Synthetic owner callback: native registry, window and Save-panel acceptance are separate.
        try BoundedListingExportController.capture(store: fixture.store, session: fixture.session,
            format: .plainText, limits: .init(), isCurrentOwner: { true })
    }

    private func makeFixture(retainSecondaryFingerprint: Bool = true) throws -> Fixture {
        let developerRoot = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Developer/MacScope", isDirectory: true).standardizedFileURL
        let testRoot = ProcessInfo.processInfo.environment["MACSCOPE_TEST_TEMP_ROOT"]
            .map { URL(fileURLWithPath: $0, isDirectory: true).standardizedFileURL }
            ?? developerRoot.appendingPathComponent("macscope-test-tmp", isDirectory: true)
        guard testRoot.path == developerRoot.path || testRoot.path.hasPrefix(developerRoot.path + "/") else {
            throw FixtureError.temporaryRootOutsideDeveloper
        }
        let directory = testRoot.appendingPathComponent(
            "BoundedListingPublication-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        do {
            let first = makeBinary(name: "Primary", slot: .primary, directory: directory)
            let second = makeBinary(name: "Secondary", slot: secondary, directory: directory)
            let snapshot = WorkspaceSnapshot(binaries: [first, second], analysisBySlot: [
                .primary: try makeAnalysis(binary: first, secondary: false, retainFingerprint: true),
                secondary: try makeAnalysis(binary: second, secondary: true,
                    retainFingerprint: retainSecondaryFingerprint)
            ])
            let store = WorkspaceStore(workspaceName: "Publication", snapshot: snapshot,
                engine: AnalysisEngine(), autosaveScheduler: nil)
            let reservations = ListingPublicationTestReservations()
            let session = WorkspaceDocumentSession(sessionID: .init(rawValue: UUID()),
                windowID: .fresh(), source: store, io: WorkspaceDocumentIO(), reservations: reservations)
            store.focusImage(secondary)
            return Fixture(store: store, session: session, reservations: reservations, directory: directory)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    private func makeBinary(name: String, slot: ImageSlot, directory: URL) -> BinaryImage {
        BinaryImage(id: UUID(), name: name, path: directory.appendingPathComponent(name).path,
            kind: "raw fixture", architecture: "arm64", slot: slot)
    }

    private func makeAnalysis(binary: BinaryImage, secondary: Bool,
                              retainFingerprint: Bool) throws -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.imageBytes = secondary ? Data([0xc0, 0x03, 0x5f, 0xd6]) : Data([0x1f, 0x20, 0x03, 0xd5])
        analysis.hexBytes = analysis.imageBytes
        analysis.instructions = [.init(address: 0x1000,
            bytes: secondary ? "c0 03 5f d6" : "1f 20 03 d5", mnemonic: secondary ? "ret" : "nop",
            operands: "", hasBreakpoint: false, comment: secondary ? "secondary-only" : "primary-only")]
        if retainFingerprint {
            // First identity construction for this newly created synthetic analysis only.
            analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
                binary: binary, analysis: analysis)
        }
        return analysis
    }

    private func existingDestination(in fixture: Fixture) throws -> URL {
        let destination = fixture.directory.appendingPathComponent("existing.txt")
        try "keep-existing-file".write(to: destination, atomically: true, encoding: .utf8)
        return destination
    }

    private enum FixtureError: Error {
        case temporaryRootOutsideDeveloper
    }

    @MainActor
    private struct Fixture {
        let store: WorkspaceStore
        let session: WorkspaceDocumentSession
        let reservations: ListingPublicationTestReservations
        let directory: URL

        func close() {
            session.close()
            try? FileManager.default.removeItem(at: directory)
        }
    }
}

/// Listing publication writes through Prepared; package reservation is not part of this fixture.
@MainActor
private final class ListingPublicationTestReservations: WorkspaceDocumentLocationReserving {
    func owner(of location: WorkspaceDocumentLocation) -> WorkspaceWindowID? { nil }
    func reserve(_ location: WorkspaceDocumentLocation, for sessionID: WorkspaceDocumentSessionID,
                 windowID: WorkspaceWindowID) -> WorkspaceDocumentLocationReservationResult {
        XCTFail("Listing publication must not reserve a workspace package")
        return .reserved
    }
    func release(_ location: WorkspaceDocumentLocation, for sessionID: WorkspaceDocumentSessionID) {}
    func releaseAll(for sessionID: WorkspaceDocumentSessionID) {}
    func beginPhysicalPublication(_ staged: WorkspaceDocumentStagedPackage,
        to destination: WorkspaceDocumentLocation, retainingPublishedOwnership: Bool,
        for sessionID: WorkspaceDocumentSessionID,
        windowID: WorkspaceWindowID) -> WorkspaceDocumentPublicationReservationResult {
        XCTFail("Listing publication must not publish a workspace package")
        return .reserved(WorkspaceDocumentPublicationReservation())
    }
    func completePhysicalPublication(_ publication: WorkspaceDocumentPublicationReservation,
        at publishedLocation: WorkspaceDocumentLocation) -> WorkspaceDocumentPublicationCompletionResult {
        XCTFail("Listing publication must not complete workspace package publication")
        return .invalid
    }
    func cancelPhysicalPublication(_ publication: WorkspaceDocumentPublicationReservation) {}
}
