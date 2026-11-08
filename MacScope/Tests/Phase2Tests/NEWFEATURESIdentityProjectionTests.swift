import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

final class NEWFEATURESIdentityProjectionTests: XCTestCase {
    private let workspace = Phase2ReadWorkspaceIdentity(
        document: .init(instanceID: UUID()), instanceID: UUID())
    private let binaryID = UUID()
    private let raw = String(repeating: "a", count: 64)
    private let digest = String(repeating: "b", count: 64)

    private func state(workspace: Phase2ReadWorkspaceIdentity? = nil,
                       generation: UInt64 = 1, revision: UInt64 = 1,
                       architecture: String = "arm64") -> Phase2ReadCurrentState {
        .init(workspace: workspace ?? self.workspace, workspaceRevision: 1,
            image: .init(owner: .init(slot: .primary, binaryID: binaryID,
                architecture: architecture, sliceIndex: 0, ownerGeneration: generation),
                analysisRevision: revision, analysisFingerprintSHA256: digest),
            facetRevisions: [])
    }

    private func fingerprint(raw: String? = nil, slot: ImageSlot = .primary) throws -> AnalysisInputFingerprint {
        try .init(imageSlot: slot, binaryID: binaryID, binaryName: "fixture",
            binaryPath: "fixture", selectedSliceIndex: 0, artifactIdentity: nil,
            imageByteCount: 4, imageBytesSHA256: raw ?? self.raw, facets: [], overallSHA256: digest)
    }

    private func precondition(_ current: Phase2ReadCurrentState) -> Phase2ReadPrecondition {
        .init(workspace: current.workspace, workspaceRevision: current.workspaceRevision,
            strictWholeWorkspace: false, image: current.image, dependencies: [])
    }

    func testProjectionUsesRetainedRawDigestRatherThanOverallDigest() throws {
        let key = try NEWFEATURESIdentityProjection.make(current: state(), fingerprint: fingerprint())
        XCTAssertEqual(key.contentSHA256, raw)
        XCTAssertEqual(key.analysisInputFingerprintSHA256, digest)
    }

    func testUniversalArchitectureCanAdmitAndPublishWithoutNormalizingIdentity() throws {
        let architecture = "arm64 (universal slice 1/3 @ 0x4000)"
        let original = state(architecture: architecture)
        let key = try NEWFEATURESIdentityProjection.make(current: original, fingerprint: fingerprint())
        XCTAssertEqual(key.architecture, architecture)
        XCTAssertNoThrow(try NEWFEATURESIdentityProjection.requireCurrent(key,
            precondition: precondition(original), current: original, fingerprint: fingerprint()))
        XCTAssertThrowsError(try NEWFEATURESIdentityProjection.requireCurrent(key,
            precondition: precondition(original), current: state(), fingerprint: fingerprint()))
    }

    func testMissingAnalysisAndWrongFingerprintOwnerRefuse() throws {
        XCTAssertThrowsError(try NEWFEATURESIdentityProjection.make(current: state(), fingerprint: nil)) {
            XCTAssertEqual($0 as? NEWFEATURESAdmissionFailure, .analysisRequired)
        }
        XCTAssertThrowsError(try NEWFEATURESIdentityProjection.make(current: state(),
            fingerprint: fingerprint(slot: .init(rawValue: 1))))
    }

    func testPublicationRejectsReopenSlotReuseAndAnalysisChange() throws {
        let original = state()
        let key = try NEWFEATURESIdentityProjection.make(current: original, fingerprint: fingerprint())
        let reopened = Phase2ReadWorkspaceIdentity(document: .init(instanceID: UUID()), instanceID: UUID())
        for changed in [state(workspace: reopened), state(generation: 2), state(revision: 2)] {
            XCTAssertThrowsError(try NEWFEATURESIdentityProjection.requireCurrent(key,
                precondition: precondition(original), current: changed, fingerprint: fingerprint()))
        }
    }

    func testPublicationRejectsRawChangeEvenIfAnalysisFingerprintWasReused() throws {
        let original = state()
        let key = try NEWFEATURESIdentityProjection.make(current: original, fingerprint: fingerprint())
        XCTAssertThrowsError(try NEWFEATURESIdentityProjection.requireCurrent(key,
            precondition: precondition(original), current: original,
            fingerprint: fingerprint(raw: String(repeating: "c", count: 64))))
    }

    func testUnchangedRetainedIdentityCanPublishWithoutRehash() throws {
        let original = state()
        let key = try NEWFEATURESIdentityProjection.make(current: original, fingerprint: fingerprint())
        XCTAssertNoThrow(try NEWFEATURESIdentityProjection.requireCurrent(key,
            precondition: precondition(original), current: original, fingerprint: fingerprint()))
    }
    func testFunctionOwnershipRejectsOverlapsAndDuplicateUUIDs() throws {
        let id = UUID()
        let first = FunctionSummary(id: id, name: "first", startAddress: 0x1000,
                                    endAddress: 0x1100, confidence: 1)
        let overlap = FunctionSummary(id: UUID(), name: "overlap", startAddress: 0x1080,
                                      endAddress: 0x1200, confidence: 1)
        let duplicate = FunctionSummary(id: id, name: "duplicate", startAddress: 0x2000,
                                        endAddress: 0x2100, confidence: 1)
        XCTAssertEqual(try NEWFEATURESFunctionOwnership.resolve(address: 0x1000, functions: [first]), id)
        XCTAssertThrowsError(try NEWFEATURESFunctionOwnership.resolve(address: 0x1080,
                                                                     functions: [first, overlap]))
        XCTAssertThrowsError(try NEWFEATURESFunctionOwnership.resolve(address: 0x1000,
                                                                     functions: [first, duplicate]))
        XCTAssertThrowsError(try NEWFEATURESFunctionOwnership.resolve(address: 0x1100, functions: [first]))
    }

}
