import Foundation
import XCTest
@testable import MacScope

final class RegenerationInventoryCompositionTests: XCTestCase {
    private func input() -> RegenerationProjectInput {
        .init(applicationName: "Observed", image: .init(imageSlot: 0, selectedSliceIndex: nil,
            architecture: "arm64", selectedSliceSHA256: String(repeating: "a", count: 64),
            analysisFingerprintSHA256: String(repeating: "b", count: 64)), functions: [],
            originalDeploymentTarget: "11.0", dependentLibraries: [], referenceFiles: [:], diagnostics: [])
    }

    func testReportAndCapabilityAreEmittedTogether() throws {
        let report = Data("{\"dependencies\":[]}".utf8)
        let capability = RegenerationDependencyInventoryCapability(path: "DEPENDENCIES.json",
            coverage: "capturedSnapshotOnly", liveBundleObservations: "unassessed")
        let project = try RegenerationProjectRenderer.render(input(), dependencyFiles: [capability.path: report],
                                                              dependencyCapability: capability)
        XCTAssertEqual(project.files[capability.path], report)
        let manifest = try XCTUnwrap(project.files["REGEN-MANIFEST.json"])
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: manifest) as? [String: Any])
        let capabilities = try XCTUnwrap(root["capabilities"] as? [String: Any])
        let inventory = try XCTUnwrap(capabilities["dependencyInventory"] as? [String: String])
        XCTAssertEqual(inventory, ["path": "DEPENDENCIES.json", "coverage": "capturedSnapshotOnly",
                                   "liveBundleObservations": "unassessed"])
    }

    func testIncompleteReportCapabilityPairIsRejected() throws {
        let capability = RegenerationDependencyInventoryCapability(path: "DEPENDENCIES.json",
            coverage: "capturedSnapshotOnly", liveBundleObservations: "unassessed")
        XCTAssertThrowsError(try RegenerationProjectRenderer.render(input(), dependencyCapability: capability))
        XCTAssertThrowsError(try RegenerationProjectRenderer.render(input(), dependencyFiles: ["DEPENDENCIES.json": Data()]))
        let noInventory = try RegenerationProjectRenderer.render(input())
        XCTAssertNil(noInventory.manifest.capabilities)
        XCTAssertNil(noInventory.files["DEPENDENCIES.json"])
    }
}
