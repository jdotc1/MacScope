import XCTest
@testable import MacScope

final class RegenerationStructuralComparisonTests: XCTestCase {
    private func record(_ key: String, _ value: String?) -> StructuralRecord {
        StructuralRecord(key: key, value: value)
    }

    func testClassifiesDifferencesWithoutCountingUnknowns() {
        let original = [record("selector", "v@:"), record("ivar", "i"),
                        record("missing", "value"), record("unknown", nil)]
        let rebuilt = [record("selector", "v@:"), record("ivar", "q"),
                       record("extra", "value"), record("unknown", nil)]
        let result = StructuralComparison.compare(original: original, rebuilt: rebuilt)
        XCTAssertEqual(result.matched.map(\.key), ["selector"])
        XCTAssertEqual(result.differing.map(\.key), ["ivar"])
        XCTAssertEqual(result.missing.map(\.key), ["missing"])
        XCTAssertEqual(result.extra.map(\.key), ["extra"])
        XCTAssertEqual(result.unassessed.map(\.key), ["unknown"])
        XCTAssertEqual(result.score, 0.25)
    }

    func testEmptyAndUnknownOnlyDimensionsAreNotScored() {
        XCTAssertNil(StructuralComparison.compare(original: [], rebuilt: []).score)
        XCTAssertNil(StructuralComparison.compare(original: [record("x", nil)],
                                                   rebuilt: [record("x", "known")]).score)
    }

    func testDuplicateIdentityIsUnassessedAndDoesNotInventPairing() {
        let result = StructuralComparison.compare(original: [record("a", "1"), record("a", "2")],
                                                  rebuilt: [record("a", "1")])
        XCTAssertTrue(result.matched.isEmpty)
        XCTAssertEqual(result.unassessed.map(\.key), ["a"])
        XCTAssertNil(result.score)
    }

    func testInputOrderingAndReverseDirection() throws {
        let original = [record("a", "1"), record("b", "2")]
        let rebuilt = [record("a", "1"), record("c", "3")]
        let result = StructuralComparison.compare(original: original, rebuilt: rebuilt)
        let reordered = StructuralComparison.compare(original: Array(original.reversed()), rebuilt: Array(rebuilt.reversed()))
        XCTAssertEqual(result, reordered)
        let reversed = StructuralComparison.compare(original: rebuilt, rebuilt: original)
        XCTAssertEqual(result.missing.map(\.key), reversed.extra.map(\.key))
        XCTAssertEqual(result.extra.map(\.key), reversed.missing.map(\.key))
    }
}
