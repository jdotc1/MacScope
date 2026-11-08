import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
#else
@testable import SwiftErrorFlow
#endif

final class SwiftErrorFlowRegisterCopyTests: XCTestCase {
    func testCopiedErrorRegisterPreservesBothBranchPolarities() throws {
        for (branch, success, error) in [(UInt32(0xb4000073), UInt64(20), UInt64(12)),
                                         (UInt32(0xb5000073), UInt64(12), UInt64(20))] {
            let report = analyze([0xaa1503f3, branch]) // MOV X19,X21
            let edge = try XCTUnwrap(report.edges.first)
            XCTAssertEqual(report.edges.count, 1)
            XCTAssertEqual(edge.testedRegister, 19)
            XCTAssertEqual(edge.successOffset, success)
            XCTAssertEqual(edge.errorOffset, error)
            XCTAssertEqual(edge.successAddress, 0x1000 + success)
            XCTAssertEqual(edge.errorAddress, 0x1000 + error)
        }
    }

    func testTransitiveCopySurvivesOriginalAndIntermediateOverwrites() throws {
        // X21 -> X19 -> X20; overwrite X21 and X19 from unrelated X0.
        let report = analyze([0xaa1503f3, 0xaa1303f4, 0xaa0003f5, 0xaa0003f3, 0xb4000074])
        let edge = try XCTUnwrap(report.edges.first)
        XCTAssertEqual(edge.testedRegister, 20)
        XCTAssertEqual(edge.testAddress, 0x1014)
        XCTAssertEqual(edge.successAddress, 0x1020)
    }

    func testOverwriteRemovesOnlyTheDestinationAlias() throws {
        assertAbstention([0xaa1503f3, 0xaa0003f3, 0xb4000073], "not_error_result_test")
        let edge = try XCTUnwrap(analyze([0xaa1503f3, 0xaa0003f3, 0xb4000075]).edges.first)
        XCTAssertEqual(edge.testedRegister, 21)
    }

    func testKillingLastAliasCannotBeUndoneByLaterCopy() {
        assertAbstention([0xaa0003f5, 0xaa1503f3, 0xb4000073], "error_value_clobbered")
        assertAbstention([0xaa1503f3, 0xaa0003f5, 0xaa0003f3, 0xb4000073], "error_value_clobbered")
    }

    func testZeroRegisterIsDiscardedAndNeverBecomesAnAlias() throws {
        XCTAssertEqual(try XCTUnwrap(analyze([0xaa1503ff, 0xb4000075]).edges.first).testedRegister, 21)
        assertAbstention([0xaa1503ff, 0xb400007f], "not_error_result_test")
        assertAbstention([0xaa1f03f5, 0xb4000075], "error_value_clobbered")
        assertAbstention([0xaa1503f3, 0xaa1f03f3, 0xb4000073], "not_error_result_test")
    }

    func testSelfCopyRetainsOnlyAnAlreadyLiveAlias() throws {
        XCTAssertEqual(try XCTUnwrap(analyze([0xaa1503f5, 0xb4000075]).edges.first).testedRegister, 21)
        assertAbstention([0xaa1303f3, 0xb4000073], "not_error_result_test")
    }

    func testNoncanonicalCopyFormsStopObservation() {
        // Shifted ORR, non-XZR ORR, ORN, SP ADD alias, literal, load, W MOV.
        for word: UInt32 in [0xaa1507f3, 0xaa150013, 0xaa3503f3, 0x910002b3,
                             0xd2800013, 0xf94003f3, 0x2a1503f3] {
            assertAbstention([word, 0xb4000075], "intervening_instruction_or_test_unsupported")
        }
    }

    func testNarrowAliasTestsAreRefused() {
        for word: UInt32 in [0x34000073, 0x35000073] {
            assertAbstention([0xaa1503f3, word], "intervening_instruction_or_test_unsupported")
        }
    }

    func testCompareAliasPreservesRegisterAndPolarity() throws {
        for (branch, success, error) in [(UInt32(0x54000060), UInt64(24), UInt64(16)),
                                         (UInt32(0x54000061), UInt64(16), UInt64(24))] {
            let edge = try XCTUnwrap(analyze([0xaa1503f3, 0xf100027f, branch]).edges.first)
            XCTAssertEqual(edge.testedRegister, 19)
            XCTAssertEqual(edge.comparisonAddress, 0x1008)
            XCTAssertEqual(edge.testAddress, 0x100c)
            XCTAssertEqual(edge.successOffset, success)
            XCTAssertEqual(edge.errorOffset, error)
        }
    }

    func testCompareRequiresImmediateCanonicalEQOrNE() {
        for word: UInt32 in [0xd503201f, 0xaa1303f4, 0xf100027f, 0x54000062, 0x54000070] {
            assertAbstention([0xaa1503f3, 0xf100027f, word, 0x54000060],
                             "comparison_branch_not_adjacent_or_supported")
        }
    }

    func testCompareRequiresLiveFullWidthAliasAndExactZeroForm() {
        assertAbstention([0xaa1503f3, 0xaa0003f3, 0xf100027f, 0x54000060], "not_error_result_comparison")
        assertAbstention([0xf10003ff, 0x54000060], "not_error_result_comparison")
        for word: UInt32 in [0x7100027f, 0xf140027f, 0xf100067f, 0xf100027e] {
            assertAbstention([0xaa1503f3, word, 0x54000060], "intervening_instruction_or_test_unsupported")
        }
    }

    func testCopiesConsumeTheExistingEightWordWindow() {
        let copies = Array(repeating: UInt32(0xaa1503f3), count: 7)
        XCTAssertEqual(analyze(copies + [0xb4000073]).edges.count, 1)
        assertAbstention(copies + [0xaa1303f4, 0xb4000074], "postcall_window_exhausted")
        assertAbstention(copies + [0xf100027f, 0x54000060], "comparison_branch_missing_or_outside_window")
    }

    func testAnotherCallDoesNotCarryEarlierAliases() {
        // The second BL at 0x1008 still targets 0x1080, but starts with only X21.
        let report = analyze([0xaa1503f3, 0x9400001e, 0xb4000073])
        XCTAssertTrue(report.edges.isEmpty)
        XCTAssertEqual(report.abstentions.map(\.address), [0x1000, 0x1008])
        XCTAssertEqual(report.abstentions.map(\.code),
                       ["intervening_instruction_or_test_unsupported", "not_error_result_test"])
    }

    func testAliasSuccessorsStillRequireDistinctForwardCallerAddresses() {
        for word: UInt32 in [0xb4000013, 0xb4000033, 0xb4fffff3, 0xb40003d3] {
            assertAbstention([0xaa1503f3, word], "unsupported_successor_region")
        }
    }

    func testRejectedRequestRetainsRequestedModelWithoutEvidence() {
        var input = request([0xaa1503f3, 0xb4000073])
        input.code.hasRelocations = true
        let report = SwiftErrorFlowAnalyzer.analyze(input, model: .registerCopiesV2)
        XCTAssertEqual(report.model, SwiftErrorFlowModel.registerCopiesV2.rawValue)
        XCTAssertEqual(report.status, .rejected)
        XCTAssertEqual(report.abstentions.map(\.code), ["tainted_code_mapping"])
        XCTAssertTrue(report.edges.isEmpty)
        XCTAssertTrue(report.declarations.isEmpty)
    }

    func testDefaultKeepsV1OutputShapeAndAliasRefusal() throws {
        let report = SwiftErrorFlowAnalyzer.analyze(request([0xb4000075]))
        XCTAssertEqual(report.model, "macscope-swift-error-flow-native-v1")
        XCTAssertEqual(SwiftErrorFlowAnalyzer.model, report.model)
        let edge = try XCTUnwrap(report.edges.first)
        XCTAssertNil(edge.testedRegister)
        XCTAssertEqual(edge.testKind, "cbz_x21")
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(edge)) as? [String: Any])
        XCTAssertEqual(Set(json.keys), Set(["callerStart", "callAddress", "calleeAddress", "symbol", "testAddress",
                                           "successAddress", "errorAddress", "callOffset", "testOffset", "successOffset",
                                           "errorOffset", "testKind", "evidenceWords"]))
        let declined = SwiftErrorFlowAnalyzer.analyze(request([0xaa1503f3, 0xb4000073]))
        XCTAssertTrue(declined.edges.isEmpty)
        XCTAssertEqual(declined.abstentions.first?.code, "intervening_instruction_or_test_unsupported")
    }

    func testV2RetainsRawEvidenceAndCannotClaimRuntimeOrSourceAuthority() throws {
        let report = analyze([0xaa1503f3, 0xd503201f, 0xb4000073])
        let edge = try XCTUnwrap(report.edges.first)
        XCTAssertEqual(edge.evidenceWords, [0x94000020, 0xaa1503f3, 0xd503201f, 0xb4000073])
        XCTAssertEqual(try JSONDecoder().decode(SwiftErrorFlowEdge.self, from: JSONEncoder().encode(edge)), edge)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        XCTAssertEqual(json["model"] as? String, "macscope-swift-error-flow-native-v2-register-copies")
        XCTAssertEqual(json["sourceReconstructionAllowed"] as? Bool, false)
        XCTAssertEqual(json["runtimeReachabilityProven"] as? Bool, false)
    }

    private func analyze(_ window: [UInt32]) -> SwiftErrorFlowReport {
        SwiftErrorFlowAnalyzer.analyze(request(window), model: .registerCopiesV2)
    }

    private func assertAbstention(_ window: [UInt32], _ reason: String,
                                  file: StaticString = #filePath, line: UInt = #line) {
        let report = analyze(window)
        XCTAssertTrue(report.edges.isEmpty, file: file, line: line)
        XCTAssertEqual(report.abstentions.first?.address, 0x1000, file: file, line: line)
        XCTAssertEqual(report.abstentions.first?.code, reason, file: file, line: line)
    }

    private func request(_ window: [UInt32]) -> SwiftErrorFlowRequest {
        var words: [UInt32] = [0x94000020] + window
        words += Array(repeating: 0xd65f03c0, count: 33 - words.count)
        return .init(
            slice: .init(artifactSHA256: String(repeating: "a", count: 64), sliceOffset: 0,
                         sliceByteCount: 4096, cpuType: 0x0100000c, cpuSubtype: 0, littleEndian: true),
            code: .init(baseAddress: 0x1000, sliceRelativeFileOffset: 256, sectionOrdinal: 1,
                        hasEmbeddedData: false, hasRelocations: false, words: words),
            functions: [.init(start: 0x1000, endExclusive: 0x1080, boundarySource: "lc_function_starts"),
                        .init(start: 0x1080, endExclusive: 0x1084, boundarySource: "lc_function_starts")],
            symbols: [.init(address: 0x1080, name: "_$s4Demo5parseyS2iKF", nType: 0x0f, nDesc: 0, sectionOrdinal: 1)])
    }
}
