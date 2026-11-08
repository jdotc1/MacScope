import Foundation
import XCTest
@testable import MacScope

final class RegenerationStructuralReportTests: XCTestCase {
    func testUnavailableDimensionRetainsObservationsWithoutScore() throws {
        let input = StructuralDimensionInput(name: "partial", original: [.init(key: "class", value: "observed")],
                                             rebuilt: [.init(key: "selector", value: nil)], available: false)
        let report = StructuralReportBuilder.build(original: "a", rebuilt: "b", dimensions: [input])
        let dimension = try XCTUnwrap(report.dimensions.first)
        XCTAssertNil(dimension.comparison)
        XCTAssertEqual(dimension.unassessedOriginal.map(\.key), ["class"])
        XCTAssertEqual(dimension.unassessedRebuilt.map(\.key), ["selector"])
        XCTAssertTrue(StructuralReportBuilder.markdown(report).contains("Original observation: class"))
    }

    func testDuplicateDimensionsAreUnassessedAndKeepBothInputs() throws {
        let a = StructuralDimensionInput(name: "duplicates", original: [.init(key: "a", value: "1")], rebuilt: [], available: true)
        let b = StructuralDimensionInput(name: "duplicates", original: [.init(key: "b", value: "2")], rebuilt: [], available: true)
        let report = StructuralReportBuilder.build(original: "a", rebuilt: "b", dimensions: [b, a])
        let dimension = try XCTUnwrap(report.dimensions.first)
        XCTAssertNil(dimension.comparison)
        XCTAssertEqual(dimension.unassessedOriginal.map(\.key), ["a", "b"])
        XCTAssertTrue(dimension.status.contains("duplicate"))
    }

    func testCapturedRebuiltSizesAppearWhenPairingIsUnassessed() throws {
        let original = RegenerationImageIdentity(imageSlot: 0, selectedSliceIndex: nil,
            architecture: "arm64", selectedSliceSHA256: String(repeating: "a", count: 64),
            analysisFingerprintSHA256: String(repeating: "b", count: 64))
        let rebuilt = RebuiltImageIdentity(imageSlot: 1, selectedSliceIndex: nil,
            architecture: "arm64", selectedSliceSHA256: String(repeating: "c", count: 64),
            analysisFingerprintSHA256: String(repeating: "d", count: 64))
        let report = EquivalenceServiceReport(schemaVersion: 1, originalIdentity: original,
            rebuiltIdentity: rebuilt, structure: StructuralReportBuilder.build(original: "a", rebuilt: "c", dimensions: []),
            functionPairing: nil, originalFunctionSizes: [4], rebuiltFunctionSizes: [8, 12],
            functionPairingStatus: "unassessed", functionStates: [], limitations: [])
        let files = try EquivalenceReportFiles.make(report, budget: .start())
        let markdown = String(decoding: try XCTUnwrap(files["Equivalence/STRUCTURE-REPORT.md"]), as: UTF8.self)
        XCTAssertTrue(markdown.contains("Original functions: 1; rebuilt functions: 2"))
        XCTAssertTrue(markdown.contains("pairing: unassessed"))
    }

}
