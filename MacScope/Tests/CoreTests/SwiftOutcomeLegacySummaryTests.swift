import XCTest
#if canImport(MacScope)
@testable import MacScope
#endif

/// Pure request-word counterparts; no CLI, file, renderer-budget or runtime claim.
final class SwiftOutcomeLegacySummaryTests: XCTestCase {
    private let literalLabel = "Recorded literal outcomes (structural; runtime unproven): "
    private let resultLabel = "Recorded call-result/error outcomes (structural; runtime unproven): "
    private let adjustedLabel = "Recorded adjusted-result/error outcomes (structural; runtime unproven): "
    private let shared: [UInt32] = [0xb40000b5,0xaa1503e0,0x94000010,0x92800000,0x14000002,0xd2800000,0xa9427bfd,0xa94157f6,0x9100c3ff,0xd65f03c0]
    private let direct: [UInt32] = [0xb4000075,0x92800000,0x14000001,0xd65f03c0]
    private let directEQ: [UInt32] = [0xf10002bf,0x54000060,0x92800000,0x14000001,0xd65f03c0]
    private let save: UInt32 = 0xaa0003f3, clear: UInt32 = 0xaa1f03e0, restore: UInt32 = 0xaa1303e0
    private func fixture(_ words: [UInt32]) -> SwiftOutcomeJSON { swiftOutcomeLegacyFixture(words) }
    private func summary(_ words: [UInt32]) -> String? { swiftOutcomeLegacySummary(call: fixture(words)) }
    private func set(_ value: inout SwiftOutcomeJSON, _ path: [String], _ replacement: SwiftOutcomeJSON) {
        guard let first = path.first else { value = replacement; return }
        var child = value[first]; set(&child, Array(path.dropFirst()), replacement); value[first] = child
    }
    private func assertWithheld(_ call: SwiftOutcomeJSON, _ mutations: [([String],SwiftOutcomeJSON)], file: StaticString = #filePath, line: UInt = #line) {
        for (path,value) in mutations {
            var changed = call; set(&changed,path,value)
            XCTAssertNil(swiftOutcomeLegacySummary(call: changed), path.joined(separator: "."), file: file, line: line)
        }
    }
    private func assertErrorConstantDeletionWithheld(_ call: SwiftOutcomeJSON, file: StaticString = #filePath, line: UInt = #line) {
        guard case .object(var fields) = call else {
            XCTFail("Expected a call object", file: file, line: line)
            return
        }
        XCTAssertNotNil(fields.removeValue(forKey: "error_constant"), file: file, line: line)
        XCTAssertNil(swiftOutcomeLegacySummary(call: .object(fields)), file: file, line: line)
    }
    func testLiteralEqualPatternsAndWordZeroExtensionAreNotCollapsed() {
        var equal = shared; equal[3] = 0xd2800000
        let width: [UInt32] = [0xb40000b5,0xaa1503e0,0x94000070,0x92800000,0x14000002,0x12800000,0xa9427bfd,0xa94157f6,0x9100c3ff,0xd65f03c0]
        let packed: [UInt32] = [0xb40000d5,0xaa1503e0,0x94000082,0x528acf00,0x72a24680,0x14000003,0x5299bde0,0x72b13560,0xa9427bfd,0xa94157f6,0x9100c3ff,0xd65f03c0]
        let cases: [([UInt32],String)] = [
            (equal,"success x0 bits 0x0000000000000000; error x0 bits 0x0000000000000000"),
            (width,"success x0 bits 0x00000000ffffffff; error x0 bits 0xffffffffffffffff"),
            (packed,"success x0 bits 0x0000000089abcdef; error x0 bits 0x0000000012345678")]
        for (words,text) in cases { XCTAssertEqual(summary(words),literalLabel + text) }
    }
    func testLiteralMismatchedChoiceOrUnderlyingBindingWithholdsSummary() {
        assertWithheld(fixture(shared),[
            (["return_choice","success","constant_bits"],.string("0x0000000000000001")),
            (["return_choice","call_pc"],.string("0x0")),(["return_choice","return_pc"],.string("0x0")),
            (["return_choice","condition","register"],.string("x20")),
            (["success_constant","success_pc"],.string("0x0")),
            (["error_constant","constant_bits"],.string("0x0000000000000001")),
            (["return_choice","runtime_value_proven"],.bool(true)),
            (["return_choice","runtime_value_proven"],.integer(0)),
            (["return_choice","same_constant_bits"],.integer(0))])
    }
    func testLiteralMissingConflictingBlockedAndNonliteralOutcomesHaveNoLiteralLine() {
        assertErrorConstantDeletionWithheld(fixture(shared))
        assertWithheld(fixture(shared),[
            (["error_constant"],.null),(["success_result","status"],.string("preserved_register_candidate")),
            (["presentation","status"],.string("blocked")),(["presentation","status"],.string("unresolved")),
            (["error_region","shared_epilogue","instructions"],.array([]))])
        for word in [UInt32(0xd503201f),0x91001400,0xd1001400] {
            var words = shared; words[5] = word
            XCTAssertFalse(summary(words)?.hasPrefix(literalLabel) ?? false)
        }
    }
    func testCallResultPreservedAndCopiedSuccessEntryKeepDistinction() {
        for words in [direct,directEQ] {
            XCTAssertEqual(summary(words),resultLabel + "success x0 preserved call-result candidate; error x0 bits 0xffffffffffffffff")
            XCTAssertEqual(summary([save,clear,restore] + words),resultLabel + "success x0 copied call-result candidate; error x0 bits 0xffffffffffffffff")
        }
    }
    func testCallResultWordZeroExtensionAndXWidthErrorLiteralsRemainDistinct() {
        for words in [direct,directEQ] {
            let prefixes: [[UInt32]] = [[],[save,clear,restore]]
            let literals: [(UInt32,String)] = [(0x12800000,"0x00000000ffffffff"),(0x92800000,"0xffffffffffffffff")]
            for prefix in prefixes {
                for (word,bits) in literals {
                    let changed = prefix + words.map { $0 == 0x92800000 ? word : $0 }
                    let kind = prefix.isEmpty ? "preserved" : "copied"
                    XCTAssertEqual(summary(changed),resultLabel + "success x0 " + kind + " call-result candidate; error x0 bits " + bits)
                }
            }
        }
    }
    func testCallResultMismatchedChoiceOrUnderlyingOutcomeWithholdsSummary() {
        for words in [direct,directEQ,[save,clear,restore] + direct,[save,clear,restore] + directEQ] {
            let call = fixture(words)
            assertWithheld(call,[
                (["return_choice","success","candidate_status"],.string("unresolved")),
                (["return_choice","success","register"],.string("x1")),
                (["return_choice","error","constant_bits"],.string("0x0000000000000001")),
                (["return_choice","condition","test_pc"],.string("0x0")),
                (["return_choice","call_pc"],.string("0x0")),(["return_choice","return_pc"],.string("0x0")),
                (["success_result","register"],.string("x1")),(["success_result","call_pc"],.string("0x0")),
                (["success_result","success_pc"],.string("0x0")),(["success_result","return_pc"],.string("0x0")),
                (["error_constant","error_pc"],.string("0x0")),(["error_constant","constant_bits"],.string("0x0000000000000001")),
                (["callee","result"],.string("Swift.UInt"))])
            var changed = call
            changed["success_result"]["status"] = call["success_result"]["status"] == .string("preserved_register_candidate") ? .string("copied_register_candidate") : .string("preserved_register_candidate")
            XCTAssertNil(swiftOutcomeLegacySummary(call: changed))
        }
    }
    func testCallResultProofFlagsEqualityAndErrorPatternsFailClosed() {
        let call = fixture(direct)
        let flags = ["source_reconstruction_allowed","runtime_value_proven","exclusive_path_proven","caller_return_type_proven","call_return_proven","handler_semantics_proven"]
        for section in ["return_choice","success_result","error_constant"] {
            for flag in (section == "success_result" ? Array(flags.prefix(4)) : flags) {
                assertWithheld(call,[([section,flag],.bool(true)),([section,flag],.integer(0))])
            }
        }
        for equality in [SwiftOutcomeJSON.bool(false),.bool(true),.integer(0),.string("")] {
            assertWithheld(call,[(["return_choice","same_constant_bits"],equality)])
        }
        for bits in [SwiftOutcomeJSON.string("0xffff"),.string("0xFFFFFFFFFFFFFFFF"),.integer(0),.string("\u{1b}[2J")] {
            var changed = call; changed["return_choice"]["error"]["constant_bits"] = bits; changed["error_constant"]["constant_bits"] = bits
            XCTAssertNil(swiftOutcomeLegacySummary(call: changed))
        }
    }
    func testCallResultMissingConflictingBlockedAndMalformedOutcomesHaveNoLine() {
        assertErrorConstantDeletionWithheld(fixture(direct))
        assertWithheld(fixture(direct),[
            (["error_constant"],.null),(["success_constant","status"],.string("constant_register_candidate")),
            (["presentation","status"],.string("blocked")),(["presentation","status"],.string("unresolved"))])
        var words = shared; words[5] = 0xd503201f
        assertErrorConstantDeletionWithheld(fixture(words))
        assertWithheld(fixture(words),[
            (["error_region","shared_epilogue","instructions"],.array([])),
            (["error_region","shared_epilogue","instructions"],.array([.null]))])
    }
    // Owned shared-arm variant exercises arithmetic without claiming absent LAYOUTS helpers.
    func testAdjustedAddSubtractAndShiftedAmountsOwnedSharedLayout() {
        let encodings: [(UInt32,String)] = [
            (0x91001400,"+ 5"),(0xd1001400,"- 5"),(0x91400400,"+ 4096"),(0xd1400400,"- 4096"),
            (0x917ffc00,"+ 16773120"),(0xd17ffc00,"- 16773120")]
        for (word,operation) in encodings {
            var words = shared; words[5] = word
            XCTAssertEqual(summary(words),adjustedLabel + "success x0 call result " + operation + " modulo 2^64; error x0 bits 0xffffffffffffffff")
        }
    }
    func testAdjustedErrorWordZeroExtensionAndXWidthPatternsAreDistinct() {
        let literals: [(UInt32,String)] = [(0x12800000,"0x00000000ffffffff"),(0x92800000,"0xffffffffffffffff")]
        for operation in [UInt32(0x91001400),0xd1001400] {
            for (literal,bits) in literals {
                var words = shared; words[3] = literal; words[5] = operation
                let sign = operation == 0x91001400 ? "+" : "-"
                XCTAssertEqual(summary(words),adjustedLabel + "success x0 call result " + sign + " 5 modulo 2^64; error x0 bits " + bits)
            }
        }
    }
    private func adjusted() -> SwiftOutcomeJSON { var words = shared; words[5] = 0x91001400; return fixture(words) }
    func testConsistentChoiceNormalizesBoolShiftButSummaryWithholds() {
        var call = adjusted()
        XCTAssertEqual(call["return_choice"]["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(call["return_choice"]["success"]["immediate"], .integer(5))
        call["return_choice"]["success"]["immediate_shift"] = .bool(false)
        let rebuilt = swiftOutcomeLegacyConsistentChoice(call)
        XCTAssertEqual(rebuilt?["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(rebuilt?["success"]["kind"], .string("call_result_add_immediate"))
        XCTAssertEqual(rebuilt?["success"]["immediate"], .integer(5))
        XCTAssertEqual(rebuilt?["success"]["immediate_shift"], .integer(0))
        XCTAssertEqual(call["return_choice"]["success"]["immediate_shift"], .bool(false))
        XCTAssertNil(swiftOutcomeLegacySummary(call: call))
    }
    func testConsistentChoiceNormalizesBoolOneImmediateButSummaryWithholds() {
        var words = shared; words[5] = 0x91000400 // ADD x0,x0,#1, unshifted.
        var call = fixture(words)
        XCTAssertEqual(swiftOutcomeLegacySummary(call: call),
            "Recorded adjusted-result/error outcomes (structural; runtime unproven): success x0 call result + 1 modulo 2^64; error x0 bits 0xffffffffffffffff")
        call["return_choice"]["success"]["immediate"] = .bool(true)
        let rebuilt = swiftOutcomeLegacyConsistentChoice(call)
        XCTAssertEqual(rebuilt?["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(rebuilt?["success"]["operation"], .string("add_immediate_modulo"))
        XCTAssertEqual(rebuilt?["success"]["immediate"], .integer(1))
        XCTAssertEqual(rebuilt?["success"]["immediate_shift"], .integer(0))
        XCTAssertEqual(call["return_choice"]["success"]["immediate"], .bool(true))
        XCTAssertNil(swiftOutcomeLegacySummary(call: call))
    }
    func testAdjustedInconsistentErrorPairWithholdsSummary() {
        let call = adjusted()
        assertErrorConstantDeletionWithheld(call)
        assertWithheld(call,[
            (["return_choice","error","constant_bits"],.string("0x0000000000000001")),
            (["error_constant","constant_bits"],.string("0x0000000000000001")),
            (["error_constant","error_pc"],.string("0x0")),(["error_constant","bit_width"],.bool(true)),
            (["error_constant","handler_semantics_proven"],.bool(true)),(["error_constant","runtime_value_proven"],.integer(0)),
            (["return_choice","same_constant_bits"],.bool(false)),(["error_constant","depends_on_call_result"],.bool(true)),
            (["error_constant"],.null),(["success_constant","status"],.string("constant_register_candidate"))])
        var changed = call; changed["return_choice"]["error"]["constant_bits"] = .string("0xFFFFFFFFFFFFFFF9"); changed["error_constant"]["constant_bits"] = .string("0xFFFFFFFFFFFFFFF9")
        XCTAssertNil(swiftOutcomeLegacySummary(call: changed))
    }
    func testAdjustedOperationDescriptorAndBindingMismatchesWithholdPair() {
        let call = adjusted()
        assertWithheld(call,[
            (["return_choice","success","kind"],.string("call_result_sub_immediate")),
            (["return_choice","success","operation"],.string("sub_immediate_modulo")),
            (["return_choice","success","register"],.string("x1")),(["return_choice","success","immediate"],.integer(6)),
            (["return_choice","success","immediate"],.bool(true)),(["return_choice","success","immediate_shift"],.integer(12)),
            (["return_choice","condition","test_pc"],.string("0x0")),(["return_choice","call_pc"],.string("0x0")),(["return_choice","return_pc"],.string("0x0"))])
        for flag in ["runtime_value_proven","source_reconstruction_allowed","exclusive_path_proven","caller_return_type_proven","call_return_proven","handler_semantics_proven"] {
            assertWithheld(call,[(["return_choice",flag],.bool(true)),(["return_choice",flag],.integer(0))])
        }
    }
    func testAdjustedConflictingRestoreProofWithholdsPair() {
        assertWithheld(adjusted(),[
            (["presentation","display_plan","shared_epilogue","restore_state_proven"],.bool(true)),
            (["presentation","display_plan","shared_epilogue","restore_state_proven"],.integer(0))])
    }
    func testAdjustedBlockedUnresolvedAndMalformedTailWithholdPair() {
        assertWithheld(adjusted(),[
            (["presentation","status"],.string("blocked")),(["presentation","status"],.string("unresolved")),
            (["error_region","shared_epilogue","instructions"],.array([])),(["error_region","shared_epilogue","instructions"],.array([.null]))])
    }
    func testLiteralPreservedCopiedAndAdjustedKeepSeparateLabelsAndDoNotMutateCall() {
        let fixtures = [fixture(shared),fixture(direct),fixture([save,clear,restore] + direct),adjusted()]
        let labels = [literalLabel,resultLabel,resultLabel,adjustedLabel]
        for (call,label) in zip(fixtures,labels) {
            let before = call
            XCTAssertTrue(swiftOutcomeLegacySummary(call: call)?.hasPrefix(label) ?? false)
            XCTAssertEqual(call,before)
        }
    }
    private func bypass(_ words: [UInt32], target: Int) -> [UInt32] {
        let source = 4 + words.count * 4
        return words + [0x14000000 | (UInt32(truncatingIfNeeded: (target - source) / 4) & 0x03ffffff)]
    }
    func testLiteralCLIUnderlyingSummaryAndBypassedAliasChoice() {
        // Pure counterpart only: no CLI execution, full renderer or byte-budget claim.
        let aliasWords = [UInt32(0xaa1503f6), (shared[0] & ~UInt32(31)) | 22] + Array(shared.dropFirst())
        XCTAssertEqual(summary(shared), literalLabel + "success x0 bits 0x0000000000000000; error x0 bits 0xffffffffffffffff")
        let call = fixture(bypass(aliasWords, target: 8))
        XCTAssertEqual(call["return_choice"]["status"], .string("unresolved"))
        XCTAssertNil(swiftOutcomeLegacySummary(call: call))
    }
    func testCallResultCLIUnderlyingPreservedCopiedAndBypassedChoice() {
        let copied = [save,clear,restore] + direct
        XCTAssertEqual(summary(direct), resultLabel + "success x0 preserved call-result candidate; error x0 bits 0xffffffffffffffff")
        XCTAssertEqual(summary(copied), resultLabel + "success x0 copied call-result candidate; error x0 bits 0xffffffffffffffff")
        let call = fixture(bypass(copied, target: 8))
        XCTAssertEqual(call["return_choice"]["status"], .string("unresolved"))
        XCTAssertNil(swiftOutcomeLegacySummary(call: call))
    }
    func testLiteralVariantsAvailableDirectCBZHasNoLiteralSummary() {
        // Exact cbz_direct member of literal_variants(); missing layouts are not synthesized.
        XCTAssertFalse(summary(direct)?.hasPrefix(literalLabel) ?? false)
    }
}
