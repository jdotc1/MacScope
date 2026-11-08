import Foundation
import XCTest
@testable import MacScope

@MainActor
final class BoundedListingExportCaptureTests: XCTestCase {
    private let secondary = ImageSlot(rawValue: 1)

    private func fixture() -> WorkspaceSnapshot {
        var first = ImageAnalysis()
        first.instructions = [.init(address: 0x1000, bytes: "1f 20 03 d5", mnemonic: "nop",
                                    operands: "", hasBreakpoint: false, comment: "primary")]
        var second = ImageAnalysis()
        second.instructions = [.init(address: 0x1000, bytes: "c0 03 5f d6", mnemonic: "ret",
                                     operands: "", hasBreakpoint: false, comment: "secondary")]
        return WorkspaceSnapshot(binaries: [
            .init(id: UUID(), name: "Primary", path: "/synthetic/primary", kind: "Mach-O",
                  architecture: "arm64", slot: .primary),
            .init(id: UUID(), name: "Secondary", path: "/synthetic/secondary", kind: "Mach-O",
                  architecture: "arm64", slot: secondary)
        ], analysisBySlot: [.primary: first, secondary: second])
    }

    private func state(document: UUID, workspace: UUID, binary: UUID,
                       owner: UInt64 = 1, revision: UInt64 = 1,
                       workspaceRevision: UInt64 = 1) -> Phase2ReadCurrentState {
        .init(workspace: .init(document: .init(instanceID: document), instanceID: workspace),
              workspaceRevision: workspaceRevision,
              image: .init(owner: .init(slot: secondary, binaryID: binary,
                                       architecture: "arm64", sliceIndex: 0, ownerGeneration: owner),
                           analysisRevision: revision, analysisFingerprintSHA256: "synthetic-retained-identity"),
              facetRevisions: [])
    }

    func testSecondaryCaptureDoesNotBorrowEqualPrimaryAddress() throws {
        let content = try BoundedListingExportController.render(snapshot: fixture(), slot: secondary,
            name: "secondary-listing", format: .plainText, limits: .init())
        XCTAssertTrue(content.listing.text.contains("ret"))
        XCTAssertTrue(content.listing.text.contains("secondary"))
        XCTAssertFalse(content.listing.text.contains("nop"))
        XCTAssertFalse(content.listing.text.contains("primary"))
    }

    func testSelectedFormatBindsPayloadAndExtension() throws {
        let snapshot = fixture()
        let text = try BoundedListingExportController.render(snapshot: snapshot, slot: secondary,
            name: "listing", format: .plainText, limits: .init())
        let html = try BoundedListingExportController.render(snapshot: snapshot, slot: secondary,
            name: "listing", format: .html, limits: .init())
        XCTAssertEqual(text.fileExtension, "txt")
        XCTAssertEqual(html.fileExtension, "html")
        XCTAssertFalse(text.listing.text.hasPrefix("<!doctype html>"))
        XCTAssertTrue(html.listing.text.hasPrefix("<!doctype html>"))
        XCTAssertEqual(text.listing.format, .plainText)
        XCTAssertEqual(html.listing.format, .html)
    }

    func testPartialCaptureKeepsExplicitNameMessageAndCounts() throws {
        var snapshot = fixture()
        snapshot.mutateAnalysis(in: secondary) { analysis in
            analysis.instructions.append(.init(address: 0x1004, bytes: "c0 03 5f d6",
                mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil))
        }
        let partial = try BoundedListingExportController.render(snapshot: snapshot, slot: secondary,
            name: "listing", format: .plainText, limits: .init(maximumRows: 1))
        XCTAssertEqual(partial.listing.inputRowCount, 2)
        XCTAssertEqual(partial.listing.consumedRows, 1)
        XCTAssertFalse(partial.listing.isComplete)
        XCTAssertEqual(partial.suggestedName, "listing-partial")
        XCTAssertTrue(partial.message.contains("Partial listing"))
        XCTAssertTrue(partial.message.contains("not a complete listing"))
        XCTAssertLessThan(partial.listing.consumedRows, partial.listing.inputRowCount)
    }

    func testMissingFocusedImageRefusesInsteadOfPrimaryFallback() throws {
        XCTAssertThrowsError(try BoundedListingExportController.render(
            snapshot: fixture(), slot: .init(rawValue: 99), name: "listing",
            format: .plainText, limits: .init()))
    }

    func testCancelledSelectionDoesNotValidateOrWrite() throws {
        var checks = 0
        var writes = 0
        let published = try BoundedListingExportController.publishSelection(nil,
            validate: { checks += 1 }, write: { _ in writes += 1 })
        XCTAssertFalse(published)
        XCTAssertEqual(checks, 0)
        XCTAssertEqual(writes, 0)
    }

    func testClosedOrChangedOwnerAtActualSinkSuppressesWrite() throws {
        var ownerIsCurrent = false
        var writes = 0
        let publish = {
            try BoundedListingExportController.publishSelection(URL(fileURLWithPath: "/synthetic/listing.txt"),
                validate: {
                    guard ownerIsCurrent else { throw BoundedListingExportController.Failure.staleSource }
                }, write: { _ in writes += 1 })
        }
        XCTAssertThrowsError(try publish())
        XCTAssertEqual(writes, 0)
        ownerIsCurrent = true
        XCTAssertTrue(try publish())
        XCTAssertEqual(writes, 1)
    }

    func testReopenedDocumentCannotMatchOriginalSourceStamp() {
        let workspace = UUID(), binary = UUID()
        let original = state(document: UUID(), workspace: workspace, binary: binary)
        let stamp = BoundedListingExportController.SourceStamp(state: original, mutationGeneration: 4)
        XCTAssertFalse(stamp.matches(state: state(document: UUID(), workspace: workspace, binary: binary),
                                     mutationGeneration: 4))
    }

    func testReplacementOwnerAndAnalysisRevisionEachInvalidate() {
        let document = UUID(), workspace = UUID(), binary = UUID()
        let original = state(document: document, workspace: workspace, binary: binary)
        let stamp = BoundedListingExportController.SourceStamp(state: original, mutationGeneration: 4)
        XCTAssertTrue(stamp.matches(state: original, mutationGeneration: 4))
        XCTAssertFalse(stamp.matches(state: state(document: document, workspace: workspace, binary: UUID()), mutationGeneration: 4))
        XCTAssertFalse(stamp.matches(state: state(document: document, workspace: workspace, binary: binary, owner: 2), mutationGeneration: 4))
        XCTAssertFalse(stamp.matches(state: state(document: document, workspace: workspace, binary: binary, revision: 2), mutationGeneration: 4))
    }

    func testAuthoringMutationAndWorkspaceRevisionEachInvalidate() {
        let document = UUID(), workspace = UUID(), binary = UUID()
        let original = state(document: document, workspace: workspace, binary: binary)
        let stamp = BoundedListingExportController.SourceStamp(state: original, mutationGeneration: 4)
        XCTAssertFalse(stamp.matches(state: original, mutationGeneration: 5))
        XCTAssertFalse(stamp.matches(state: state(document: document, workspace: workspace, binary: binary,
                                                 workspaceRevision: 2), mutationGeneration: 4))
    }

    func testSourceChangedDuringPanelCannotPublishCapturedBytes() throws {
        let document = UUID(), workspace = UUID(), binary = UUID()
        let original = state(document: document, workspace: workspace, binary: binary)
        let stamp = BoundedListingExportController.SourceStamp(state: original, mutationGeneration: 4)
        var current = original
        var writes = 0
        XCTAssertTrue(stamp.matches(state: current, mutationGeneration: 4)) // Before panel.
        current = state(document: document, workspace: workspace, binary: binary, revision: 2)
        XCTAssertThrowsError(try BoundedListingExportController.publishSelection(
            URL(fileURLWithPath: "/synthetic/listing.html"), validate: {
                guard stamp.matches(state: current, mutationGeneration: 4) else {
                    throw BoundedListingExportController.Failure.staleSource
                }
            }, write: { _ in writes += 1 }))
        XCTAssertEqual(writes, 0)
    }
}
