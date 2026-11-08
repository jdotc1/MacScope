// AR3 TC08 (NF18). Expected outcomes are literal tables, never computed from the code under test.

import Foundation
import XCTest
@testable import MacScope

final class ComponentEvidenceSecurityDeltaValueTests: XCTestCase {
    private typealias SD = ComponentEvidenceSecurityDelta
    private typealias V = SD.Value

    private func budget(_ depth: Int = 32, _ nodes: Int = 10_000, _ bytes: Int = 65_536) throws -> SD.ValueBudget {
        try SD.ValueBudget(maximumDepth: depth, maximumNodes: nodes, maximumBytes: bytes)
    }

    private func compare(_ a: V, _ b: V) throws -> SD.ValueComparison {
        try SD.ValueAlgebra.compare(previous: a, current: b, budget: budget())
    }

    private func key(_ bytes: [UInt8]) throws -> SD.ExactKey { try SD.ExactKey(utf8: Data(bytes)) }

    func testStrictTagsAndLegacyNormalization() throws {
        XCTAssertEqual(try compare(.signed(1), .unsigned(1)), .different)
        XCTAssertEqual(try compare(.signed(1), .normalizedInteger("1")), .representationUnresolved)
        XCTAssertEqual(try compare(.unsigned(1), .normalizedInteger("1")), .representationUnresolved)
        XCTAssertEqual(try compare(.normalizedInteger("1"), .normalizedInteger("2")), .different)
        XCTAssertEqual(try compare(.normalizedInteger("1"), .normalizedInteger("1")), .equal)
        XCTAssertEqual(try compare(.signed(1), .normalizedInteger("2")), .different)
        XCTAssertEqual(try compare(.boolean(true), .signed(1)), .different)
        XCTAssertEqual(try compare(.signed(-1), .signed(-1)), .equal)
    }

    func testExactKeysAndNestedOrder() throws {
        // Composed U+00E9 (c3 a9) versus decomposed e + U+0301 (65 cc 81): different bytes, different keys.
        let composed = try key([0xc3, 0xa9]), decomposed = try key([0x65, 0xcc, 0x81])
        XCTAssertNotEqual(composed, decomposed)
        let left = V.dictionary([SD.ValueEntry(key: composed, value: .boolean(true))])
        let right = V.dictionary([SD.ValueEntry(key: decomposed, value: .boolean(true))])
        XCTAssertEqual(try compare(left, right), .different)
        XCTAssertEqual(try compare(left, left), .equal)
        XCTAssertEqual(try compare(.array([.signed(1), .signed(2)]), .array([.signed(2), .signed(1)])), .different)
        XCTAssertEqual(try compare(.array([.signed(1), .signed(2)]), .array([.signed(1), .signed(2)])), .equal)
        // Different always wins over unresolved inside a container.
        XCTAssertEqual(try compare(.array([.signed(1), .boolean(true)]), .array([.normalizedInteger("1"), .boolean(false)])), .different)
        XCTAssertEqual(try compare(.array([.signed(1)]), .array([.normalizedInteger("1")])), .representationUnresolved)
        // Dictionary entries are sorted into exact UTF-8 order, so input order cannot change the result.
        let ab = try SD.ValueAlgebra.dictionary([SD.ValueEntry(key: SD.ExactKey(text: "b"), value: .signed(2)),
                                                 SD.ValueEntry(key: SD.ExactKey(text: "a"), value: .signed(1))])
        guard case .dictionary(let entries) = ab else { return XCTFail("expected dictionary") }
        XCTAssertEqual(entries.map { String(data: $0.key.utf8, encoding: .utf8) }, ["a", "b"])
    }

    func testValidationAndInMemoryCopiesRetainTypes() throws {
        let all = V.array([.signed(1), .unsigned(1), .normalizedInteger("1"), .boolean(true)])
        let copy = all
        XCTAssertEqual(copy, all)
        XCTAssertEqual(try compare(all, copy), .equal)
        XCTAssertEqual(try compare(.unsigned(UInt64.max), .unsigned(UInt64.max)), .equal)
        XCTAssertEqual(try compare(.unsigned(UInt64.max), .normalizedInteger("18446744073709551615")), .representationUnresolved)
        XCTAssertEqual(try compare(.signed(Int64.min), .normalizedInteger("-9223372036854775808")), .representationUnresolved)
        // Real and date bits keep signed zero.
        XCTAssertEqual(try compare(.realBits(0), .realBits(0x8000_0000_0000_0000)), .different)
        XCTAssertEqual(try compare(.realBits(0), .dateBits(0)), .different)

        func rejects(_ value: V, _ expected: SD.ValueError, line: UInt = #line) throws {
            XCTAssertThrowsError(try SD.ValueAlgebra.validate(value, budget: budget()), line: line) {
                XCTAssertEqual($0 as? SD.ValueError, expected, line: line)
            }
        }
        try rejects(.normalizedInteger("01"), .invalidNormalizedInteger)
        try rejects(.normalizedInteger("-0"), .invalidNormalizedInteger)
        try rejects(.normalizedInteger(""), .invalidNormalizedInteger)
        try rejects(.normalizedInteger("1.5"), .invalidNormalizedInteger)
        try rejects(.realBits(Double.nan.bitPattern), .nonFiniteReal)
        try rejects(.realBits(Double.infinity.bitPattern), .nonFiniteReal)
        try rejects(.dateBits(Double.nan.bitPattern), .nonFiniteDate)
        let a = SD.ValueEntry(key: SD.ExactKey(text: "k"), value: .signed(1))
        try rejects(.dictionary([a, a]), .duplicateOrUnsortedKeys)
        try rejects(.dictionary([SD.ValueEntry(key: SD.ExactKey(text: "b"), value: .signed(1)),
                                 SD.ValueEntry(key: SD.ExactKey(text: "a"), value: .signed(1))]), .duplicateOrUnsortedKeys)
        XCTAssertThrowsError(try SD.ValueAlgebra.dictionary([a, a])) { XCTAssertEqual($0 as? SD.ValueError, .duplicateOrUnsortedKeys) }
        XCTAssertThrowsError(try SD.ExactKey(utf8: Data([0xff]))) // not UTF-8
        XCTAssertThrowsError(try SD.ValueBudget(maximumDepth: 33))
        XCTAssertThrowsError(try SD.ValueBudget(maximumNodes: 0))
        // A budget refusal never reaches the comparison: the limit is thrown, not an empty result.
        XCTAssertThrowsError(try SD.ValueAlgebra.compare(previous: .array([.signed(1)]), current: .signed(1), budget: budget(1)))
    }

    func testValueResourceCodesIdentifyTheReachedLimit() throws {
        func reached(_ value: V, _ depth: Int, _ nodes: Int, _ bytes: Int) throws -> SD.Cap? {
            do { try SD.ValueAlgebra.validate(value, budget: budget(depth, nodes, bytes)); return nil }
            catch let error as SD.ValueError { return error.cap }
        }
        let nested = V.array([.array([.signed(1)])])           // depth 3, nodes 3
        XCTAssertEqual(try reached(nested, 1, 100, 100), .typedDepthLimit)
        XCTAssertEqual(try reached(.array([.signed(1), .signed(2), .signed(3)]), 5, 2, 100), .typedNodeLimit)
        XCTAssertEqual(try reached(.string(SD.ExactKey(text: "long")), 5, 100, 3), .decodedByteLimit)
        // Exact boundary: depth 2, nodes 3, bytes 1 holds an array of one boolean and one one-byte string.
        let exact = V.array([.boolean(true), .string(SD.ExactKey(text: "x"))])
        XCTAssertNil(try reached(exact, 2, 3, 1))
        XCTAssertEqual(try reached(exact, 1, 3, 1), .typedDepthLimit)
        XCTAssertEqual(try reached(exact, 2, 2, 1), .typedNodeLimit)
        XCTAssertEqual(try reached(exact, 2, 3, 0), .decodedByteLimit)
    }

    func testBoundaryErrorsPreserveCancellationAndTypedCauses() throws {
        typealias CE = ComponentEvidence
        XCTAssertEqual(SD.BoundaryTranslator.translate(.cancelled), .cancelled)
        XCTAssertEqual(SD.BoundaryTranslator.translate(.unavailable(.read, errno: 5, range: nil)), .unavailable(.readFailed))
        XCTAssertEqual(SD.BoundaryTranslator.translate(try .shortRead(range: CE.ByteRange(start: 0, end: 4), expected: 4, actual: 1)),
                       .unavailable(.readFailed))
        XCTAssertEqual(SD.BoundaryTranslator.translate(.changedInput), .unavailable(.stale))
        XCTAssertEqual(SD.BoundaryTranslator.translate(.wrongSlice), .invalidReview(.evidenceBindingMismatch))
        XCTAssertEqual(SD.BoundaryTranslator.translate(.invalidEvidence(.keyMismatch)), .invalidReview(.invalidReview))
        XCTAssertEqual(SD.BoundaryTranslator.kind(of: .readFailed(.readError(errno: 5))), .readFailed)
        XCTAssertEqual(SD.BoundaryTranslator.kind(of: .readFailed(.shortRead(expected: 8, actual: 2))), .readFailed)
        XCTAssertEqual(SD.BoundaryTranslator.kind(of: .capReached(.slots)), .budget)
        XCTAssertEqual(SD.BoundaryTranslator.kind(of: .unsupportedArchitecture), .unsupported)
        XCTAssertEqual(SD.BoundaryTranslator.kind(of: .notExamined), .unavailable)
        // Unavailable never maps to an absence-shaped state: the kind set has no absent member.
        XCTAssertEqual(SD.BoundaryTranslator.kind(of: .unsupportedDigestAlgorithm(9)), .unsupported)
    }

    func testModelConstructionRefusesInvalidGraphs() throws {
        let report = UUID(), other = UUID()
        let row0 = try SD.RowID(reportID: report, ordinal: 0)
        XCTAssertThrowsError(try SD.RowID(reportID: report, ordinal: -1))
        XCTAssertThrowsError(try SD.Options(maximumObservations: 0))
        XCTAssertThrowsError(try SD.Options(maximumFindings: 2049))
        // Unresolved requires named limitations; a value requires an observed state.
        func observation(_ id: SD.RowID, disposition: SD.Disposition = .observedChange, limitations: [SD.Reason] = [],
                         previousState: SD.SourceState = .observed, previousValue: V? = .signed(1),
                         subject: String = "s") throws -> SD.Observation {
            try SD.Observation(id: id, category: .entitlements, componentPath: SD.ExactKey(text: "A"), subject: SD.ExactKey(text: subject),
                               disposition: disposition, previousState: previousState, currentState: .observed,
                               previousValue: previousValue, currentValue: .signed(2), evidence: [], limitations: limitations)
        }
        XCTAssertThrowsError(try observation(row0, disposition: .unresolved))
        XCTAssertThrowsError(try observation(row0, previousState: .unavailable))
        XCTAssertNoThrow(try observation(row0, previousState: .unavailable, previousValue: nil))
        let reason = try SD.Reason(code: .staticEvidenceOnly, diagnostic: "")
        XCTAssertNoThrow(try observation(row0, disposition: .unresolved, limitations: [reason]))
        XCTAssertThrowsError(try SD.Reason(code: .readFailed, diagnostic: String(repeating: "x", count: 257)))

        let zero = try SD.OpportunityCounts(accounted: 0, compared: 0, provenAbsent: 0, symmetricUnexamined: 0, unresolved: 0, excluded: 0, total: nil)
        XCTAssertThrowsError(try SD.OpportunityCounts(accounted: 2, compared: 1, provenAbsent: 0, symmetricUnexamined: 0, unresolved: 0, excluded: 0, total: nil))
        let slices = try SD.SliceCounts(observedKeys: 0, uniquelyPaired: 0, comparedSupported: 0, unexaminedNotCompared: 0, unmatched: 0, ambiguous: 0, total: nil)
        let coverage = try SD.Coverage(previousScope: .completeWithinScope, currentScope: .completeWithinScope, previousLocations: [],
                                       currentLocations: [], previousExclusions: [], currentExclusions: [], previousIssues: [],
                                       currentIssues: [], limitations: [], omissions: [],
                                       denominators: SD.Denominators(categories: zero, slices: slices, populationTotal: nil),
                                       status: .complete, partialDetails: [])
        let identity = SD.ReviewIdentity(previousInventoryID: UUID(), currentInventoryID: UUID(), architecture: "arm64", evidenceBasisID: report)
        let options = try SD.Options()
        let good = try observation(row0)
        XCTAssertNoThrow(try SD.Report(identity: identity, options: options, observations: [good], findings: [], coverage: coverage))
        // Wrong report, wrong ordinal and duplicate semantic content are refused.
        let foreign = try observation(SD.RowID(reportID: other, ordinal: 0))
        XCTAssertThrowsError(try SD.Report(identity: identity, options: options, observations: [foreign], findings: [], coverage: coverage))
        let row1 = try SD.RowID(reportID: report, ordinal: 1)
        XCTAssertThrowsError(try SD.Report(identity: identity, options: options, observations: [good, observation(row1)],
                                           findings: [], coverage: coverage))
        XCTAssertNoThrow(try SD.Report(identity: identity, options: options, observations: [good, observation(row1, subject: "t")],
                                       findings: [], coverage: coverage))
        // A finding must reference a retained row.
        let dangling = try SD.Finding(id: SD.FindingID(reportID: report, ordinal: 0), kind: .evidenceConflict, disposition: .unresolved,
                                      title: "t", explanation: "e", observationIDs: [row1], evidence: [], limitations: [])
        XCTAssertThrowsError(try SD.Report(identity: identity, options: options, observations: [good], findings: [dangling], coverage: coverage))
        XCTAssertThrowsError(try SD.Finding(id: SD.FindingID(reportID: report, ordinal: 0), kind: .evidenceConflict, disposition: .unresolved,
                                            title: "t", explanation: "e", observationIDs: [], evidence: [], limitations: []))
        // An unknown count is nil and nonexact; an exact count requires a value; a complete report carries no omission.
        XCTAssertThrowsError(try SD.Omission(count: nil, countIsExact: true, detailListComplete: false, reason: reason, domain: .observations,
                                             cap: nil, boundedRange: nil, remainderUnknown: true, lowerBound: nil))
        XCTAssertThrowsError(try SD.Omission(count: 3, countIsExact: false, detailListComplete: false, reason: reason, domain: .observations,
                                             cap: nil, boundedRange: nil, remainderUnknown: true, lowerBound: nil))
        XCTAssertNoThrow(try SD.Omission(count: nil, countIsExact: false, detailListComplete: false, reason: reason, domain: .observations,
                                         cap: .observationLimit, boundedRange: .notStarted, remainderUnknown: true, lowerBound: 4))
        XCTAssertThrowsError(try SD.BoundedRange.checkedRecords(side: nil, componentPath: nil, slice: nil, list: "l", start: 3, endExclusive: 2))
        XCTAssertThrowsError(try SD.SliceIdentity(cpuType: 1, cpuSubtype: 2, headerMagic: 3, index: 0, offset: UInt64.max, size: 1, recordedSHA256: nil))
        XCTAssertThrowsError(try SD.Refusal(code: .invalidReview, sideFailures: [
            SD.ReadSideFailure(side: .current, code: .currentUnavailable, underlyingKind: nil),
            SD.ReadSideFailure(side: .previous, code: .previousUnavailable, underlyingKind: nil)]))
    }
}
