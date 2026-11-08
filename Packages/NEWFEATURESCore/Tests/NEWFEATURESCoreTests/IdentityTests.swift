import Foundation
import XCTest
@testable import NEWFEATURESCore

final class IdentityTests: XCTestCase {
    private let document = UUID()
    private let workspace = UUID()
    private let binary = UUID()
    private let raw = String(repeating: "a", count: 64)
    private let analysis = String(repeating: "b", count: 64)

    private func key(document: UUID? = nil, workspace: UUID? = nil, slot: Int = 0,
                     binary: UUID? = nil, generation: UInt64 = 1,
                     architecture: String = "arm64", slice: Int? = 0,
                     raw: String? = nil, revision: UInt64 = 1,
                     fingerprint: String? = nil) throws -> NEWFEATURESImageKey {
        try NEWFEATURESImageKey(documentInstance: document ?? self.document,
            workspaceInstance: workspace ?? self.workspace, slot: slot,
            binaryID: binary ?? self.binary, ownerGeneration: generation,
            architecture: architecture, sliceIndex: slice, sha256: raw ?? self.raw,
            analysisRevision: revision, analysisInputFingerprintSHA256: fingerprint ?? analysis)
    }

    func testEveryIndependentDimensionParticipatesInFunctionIdentity() throws {
        let original = try key()
        let variants = try [key(document: UUID()), key(workspace: UUID()), key(slot: 1),
            key(binary: UUID()), key(generation: 2), key(architecture: "arm64e"),
            key(slice: 1), key(slice: nil), key(raw: String(repeating: "c", count: 64)),
            key(revision: 2), key(fingerprint: String(repeating: "d", count: 64))]
        for variant in variants {
            XCTAssertNotEqual(NEWFEATURESFunctionKey(image: original, address: 0x1000),
                              NEWFEATURESFunctionKey(image: variant, address: 0x1000))
            XCTAssertTrue(original < variant || variant < original)
        }
        XCTAssertEqual(Set(variants + [original]).count, variants.count + 1)
    }

    func testRawAndAnalysisDigestsStayIndependentAcrossCoding() throws {
        let original = try key()
        let decoded = try JSONDecoder().decode(NEWFEATURESImageKey.self,
            from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.contentSHA256, raw)
        XCTAssertEqual(decoded.analysisInputFingerprintSHA256, analysis)
        XCTAssertNotEqual(decoded.contentSHA256, decoded.analysisInputFingerprintSHA256)
    }

    func testMissingDimensionsCannotBeRemintedFromLegacyJSON() throws {
        let legacy: [String: Any] = ["slot": 0, "binaryID": binary.uuidString,
            "sha256": raw, "analysisRevision": 1]
        let data = try JSONSerialization.data(withJSONObject: legacy)
        XCTAssertThrowsError(try JSONDecoder().decode(NEWFEATURESImageKey.self, from: data))
    }

    func testMalformedDigestsAndNegativeSliceFailClosed() throws {
        XCTAssertThrowsError(try key(raw: "invalid"))
        XCTAssertThrowsError(try key(fingerprint: String(repeating: "A", count: 64)))
        XCTAssertThrowsError(try key(slice: -1))
        XCTAssertThrowsError(try key(generation: 0))
    }

    func testIdentityDoesNotRemoveX86StaticInspection() throws {
        XCTAssertEqual(try key(architecture: "x86_64").architecture, "x86_64")
    }

    func testUniversalArchitectureRetainsExactLedgerIdentity() throws {
        let architecture = "arm64 (universal slice 2/3 @ 0xc000)"
        let original = try key(architecture: architecture, slice: 1)
        XCTAssertEqual(original.architecture, architecture)
        let decoded = try JSONDecoder().decode(NEWFEATURESImageKey.self,
            from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        XCTAssertNotEqual(original, try key(architecture: "arm64", slice: 1))
        XCTAssertNotEqual(original, try key(
            architecture: "arm64 (universal slice 3/3 @ 0x18000)", slice: 2))
    }

    func testArchitectureStillRejectsEmptyControlAndOversizedValues() throws {
        for architecture in ["", " ", "arm64\n", "arm64\t", "arm64\u{7f}",
                             String(repeating: "a", count: 65)] {
            XCTAssertThrowsError(try key(architecture: architecture), architecture)
        }
    }
}
