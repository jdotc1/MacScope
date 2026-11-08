import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
#else
@testable import SwiftErrorFlow
#endif

final class SwiftErrorFlowTests: XCTestCase {
    // Catches reversed zero/nonzero polarity and wrong PC-relative bases.
    func testLiteralPositiveEdges() throws {
        let cases: [([UInt32], UInt64, UInt64)] = [
            ([0xb4000075], 16, 8), ([0xb5000075], 8, 16),
            ([0xf10002bf, 0x54000060], 20, 12), ([0xf10002bf, 0x54000061], 12, 20)
        ]
        for (words, success, error) in cases {
            let report = SwiftErrorFlowAnalyzer.analyze(request(words))
            let edge = try XCTUnwrap(report.edges.first)
            XCTAssertEqual(report.edges.count, 1)
            XCTAssertEqual(edge.callAddress, 0x1000)
            XCTAssertEqual(edge.calleeAddress, 0x1020)
            XCTAssertEqual(edge.successOffset, success)
            XCTAssertEqual(edge.errorOffset, error)
            XCTAssertEqual(edge.successAddress, 0x1000 + success)
            XCTAssertFalse(report.sourceReconstructionAllowed)
        }
    }

    // Catches propagation across unknown effects, narrow tests, wrong registers,
    // noncanonical/flag-clobbered compares, backward/out-of-bound successors.
    func testAdversarialWindowsAbstain() {
        let windows: [[UInt32]] = [
            [0xaa0003f5, 0xb4000075], [0xaa1503f3, 0xb4000073],
            [0x14000001, 0xb4000075], [0x94000001, 0xb4000075],
            [0xffffffff, 0xb4000075], [0xf94003e0, 0xb4000075],
            [0x34000075], [0x35000075], [0xb4000074], [0xb400007f],
            [0xb4000015], [0xb4000035], [0xb40000f5], [0xb4fffff5],
            [0xf10002bf, 0xd503201f, 0x54000060], [0xf10002bf, 0x54000062],
            [0xf10002bf, 0x54000070], [0xf10002bf, 0xf10002bf, 0x54000060],
            [0xf10002be, 0x54000060], [0xf10012bf, 0x54000060], [0x710002bf, 0x54000060]
        ]
        for words in windows { XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(request(words)).edges.isEmpty, "\(words)") }
    }

    // Catches the ninth word accidentally included in an eight-word budget.
    func testNOPWindowHasExactBound() {
        XCTAssertEqual(SwiftErrorFlowAnalyzer.analyze(request([0xd503201f, 0xb4000075])).edges.count, 1)
        XCTAssertEqual(SwiftErrorFlowAnalyzer.analyze(request(Array(repeating: 0xd503201f, count: 7) + [0xb4000075])).edges.count, 1)
        XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(request(Array(repeating: 0xd503201f, count: 8) + [0xb4000075])).edges.isEmpty)
        XCTAssertEqual(SwiftErrorFlowAnalyzer.analyze(request(Array(repeating: 0xd503201f, count: 6) + [0xf10002bf, 0x54000060])).edges.count, 1)
        XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(request(Array(repeating: 0xd503201f, count: 7) + [0xf10002bf, 0x54000060])).edges.isEmpty)
    }

    // Catches incorrectly attributing the second call's x21 to the first call.
    func testSecondCallStartsNewEvidenceRatherThanBridgingFirstCall() {
        let report = SwiftErrorFlowAnalyzer.analyze(request([0x94000007, 0xb4000075]))
        XCTAssertEqual(report.edges.count, 1)
        XCTAssertEqual(report.edges.first?.callAddress, 0x1004)
        XCTAssertTrue(report.abstentions.contains { $0.address == 0x1000 })
    }

    // Catches suffix-search false positives for async, typed throws and thunks.
    func testExactDeclarationsOnly() {
        for suffix in ["yS2iKF", "yySiKF", "yyKF", "SiyKF"] {
            XCTAssertEqual(SwiftErrorFlowAnalyzer.analyze(request([0xb4000075], symbol: "_$s4Demo5parse" + suffix)).edges.count, 1)
        }
        for symbol in ["_$s4Demo5parseyS2iF", "_$s4Demo5parseyS2iYaKF", "_$s4Demo5parseyS2iAA5FaultOYKF",
                       "_$s4Demo5parseyS2iKFTA", "_$s4Demo5parseyS2iKF.llvm.1", "_$s04Demo5parseyS2iKF",
                       "_$s4Dem5parseyS2iKF", "ordinary_c_function", "_$s4Dém5parseyyKF"] {
            XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(request([0xb4000075], symbol: symbol)).edges.isEmpty)
        }
    }

    // Catches silently accepted aliases/private/resolver symbols and mid-function BL.
    func testExactUniqueExternalEntryRequired() {
        var input = request([0xb4000075])
        input.symbols.append(.init(address: 0x1020, name: "other", nType: 0x0f, nDesc: 0, sectionOrdinal: 1))
        XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(input).edges.isEmpty)
        let facts: [(UInt8, UInt16, UInt8)] = [(0x1f, 0, 1), (0x0e, 0, 1), (0x0f, 0x100, 1), (0x0f, 0x200, 1), (0x0f, 0, 2)]
        for (kind, desc, section) in facts {
            input = request([0xb4000075]); input.symbols[0].nType = kind
            input.symbols[0].nDesc = desc; input.symbols[0].sectionOrdinal = section
            XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(input).edges.isEmpty)
        }
        input = request([0xb4000075]); input.code.words[0] = 0x94000009
        XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(input).edges.isEmpty)
        input.code.words[0] = 0x97ffffff
        XCTAssertTrue(SwiftErrorFlowAnalyzer.analyze(input).edges.isEmpty)
    }

    // Catches unsigned decoding of backward BL immediates.
    func testBackwardDirectCallToExactEntryIsSupported() throws {
        var input = request([0xb4000075])
        input.code.words[0] = 0xd65f03c0; input.code.words[1] = 0x97ffffff
        input.code.words[2] = 0xb4000075
        input.functions = [.init(start: 0x1000, endExclusive: 0x1004, boundarySource: "lc_function_starts"),
                           .init(start: 0x1004, endExclusive: 0x1024, boundarySource: "lc_function_starts")]
        input.symbols[0].address = 0x1000
        let edge = try XCTUnwrap(SwiftErrorFlowAnalyzer.analyze(input).edges.first)
        XCTAssertEqual(edge.calleeAddress, 0x1000)
        XCTAssertEqual(edge.successOffset, 16)
        XCTAssertEqual(edge.errorOffset, 8)
    }

    // Catches invalid identities, arithmetic wrap, tainted or overlapping ranges.
    func testMalformedInputRejectsWithoutEvidence() {
        let mutations: [(inout SwiftErrorFlowRequest) -> Void] = [
            { $0.slice.cpuSubtype = 2 }, { $0.slice.cpuType = 7 }, { $0.slice.littleEndian = false },
            { $0.slice.artifactSHA256 = "unverified" }, { $0.slice.sliceOffset = UInt64.max },
            { $0.code.baseAddress = UInt64.max - 3 }, { $0.code.sliceRelativeFileOffset = UInt64.max - 3 },
            { $0.functions[1].start = 0x101c }, { $0.functions[0].boundarySource = "symbols" },
            { $0.code.hasEmbeddedData = true }, { $0.code.hasRelocations = true },
            { $0.code.words = Array(repeating: 0xd503201f, count: 65_537) }
        ]
        for mutate in mutations {
            var input = request([0xb4000075]); mutate(&input)
            let report = SwiftErrorFlowAnalyzer.analyze(input)
            XCTAssertEqual(report.status, .rejected)
            XCTAssertTrue(report.edges.isEmpty)
            XCTAssertTrue(report.declarations.isEmpty)
        }
    }

    // Catches promotion of a byte pattern to execution or source authority.
    func testUnreachablePatternRemainsOnlyStructural() throws {
        var input = request([0xb4000075]); input.code.words[0] = 0x14000007
        input.code.words[1] = 0x94000007; input.code.words[2] = 0xb4000075
        let report = SwiftErrorFlowAnalyzer.analyze(input)
        XCTAssertEqual(report.edges.count, 1)
        XCTAssertFalse(report.runtimeReachabilityProven)
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any]
        XCTAssertEqual(json?["sourceReconstructionAllowed"] as? Bool, false)
        XCTAssertEqual(json?["runtimeReachabilityProven"] as? Bool, false)
    }

    // Catches drift against literal expected offsets captured from the frozen donor.
    func testPortableCodableFixtures() throws {
        #if SWIFT_PACKAGE
        let url = try XCTUnwrap(Bundle.module.url(forResource: "native-v1-fixtures", withExtension: "json", subdirectory: "Fixtures"))
        #else
        let url = TestSourceRoot.fileURL(#filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/SwiftErrorFlow/native-v1-fixtures.json")
        #endif
        let rows = try JSONDecoder().decode(Fixtures.self, from: Data(contentsOf: url))
        for row in rows.cases {
            let report = SwiftErrorFlowAnalyzer.analyze(row.request)
            XCTAssertEqual(report.edges.count, row.expected.edgeCount, row.name)
            XCTAssertEqual(report.edges.first?.successOffset, row.expected.successOffset, row.name)
            XCTAssertEqual(report.edges.first?.errorOffset, row.expected.errorOffset, row.name)
        }
    }

    private struct Fixtures: Decodable { var cases: [Fixture] }
    private struct Fixture: Decodable { var name: String; var request: SwiftErrorFlowRequest; var expected: Expected }
    private struct Expected: Decodable { var edgeCount: Int; var successOffset: UInt64?; var errorOffset: UInt64? }
    private func request(_ window: [UInt32], symbol: String = "_$s4Demo5parseyS2iKF") -> SwiftErrorFlowRequest {
        let calleeOffset = max(32, ((window.count + 8) / 8) * 32)
        var words = [UInt32(0x94000000) | UInt32(calleeOffset / 4)] + window
        words += Array(repeating: UInt32(0xd65f03c0), count: calleeOffset / 4 - words.count + 1)
        return .init(slice: .init(artifactSHA256: String(repeating: "a", count: 64), sliceOffset: 0, sliceByteCount: 4096, cpuType: 0x0100000c, cpuSubtype: 0, littleEndian: true),
                     code: .init(baseAddress: 0x1000, sliceRelativeFileOffset: 256, sectionOrdinal: 1, hasEmbeddedData: false, hasRelocations: false, words: words),
                     functions: [.init(start: 0x1000, endExclusive: 0x1000 + UInt64(calleeOffset), boundarySource: "lc_function_starts"), .init(start: 0x1000 + UInt64(calleeOffset), endExclusive: 0x1004 + UInt64(calleeOffset), boundarySource: "lc_function_starts")],
                     symbols: [.init(address: 0x1000 + UInt64(calleeOffset), name: symbol, nType: 0x0f, nDesc: 0, sectionOrdinal: 1)])
    }
}
