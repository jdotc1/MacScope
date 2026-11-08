import Foundation
import XCTest
@testable import MacScope

final class RegenerationResourceProvenanceTests: XCTestCase {
    func testResourceRoundTripPassDoesNotAssertBindingToCapturedImage() throws {
        let input = RegenerationProjectInput(applicationName: "Observed", image: .init(imageSlot: 0,
            selectedSliceIndex: nil, architecture: "arm64", selectedSliceSHA256: String(repeating: "a", count: 64),
            analysisFingerprintSHA256: String(repeating: "b", count: 64)), functions: [],
            originalDeploymentTarget: "11.0", dependentLibraries: [], referenceFiles: [:], diagnostics: [])
        let resource = ResourceRoundTripRecord(compiledPaths: ["en.lproj/Localizable.strings"],
            sourcePath: "Localizable.xcstrings", converter: "localization-v1", status: .converted,
            equivalence: .init(outcome: .passed, tool: "xcstringstool", receiptPath: "Support/Receipts/localization.json"),
            diagnostics: [])
        let project = try RegenerationProjectRenderer.render(input, resources: [resource])
        let bytes = try XCTUnwrap(project.files["REGEN-MANIFEST.json"])
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let provenance = try XCTUnwrap(json["resourceProvenance"] as? [String: String])
        XCTAssertEqual(provenance["captureBasis"], "currentBundlePath")
        XCTAssertEqual(provenance["imageBinding"], "unassessed")
        XCTAssertEqual(project.manifest.resources.first?.equivalence.outcome, .passed)
        XCTAssertTrue(project.manifest.diagnostics.contains(RegenerationResourceProvenance.diagnostic))
        XCTAssertTrue(RegenerationResourceProvenance.diagnostic.contains("same-path bundle may have been replaced"))
    }
}
