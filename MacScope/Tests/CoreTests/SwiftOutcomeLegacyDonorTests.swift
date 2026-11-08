import XCTest
#if canImport(MacScope)
@testable import MacScope

// Literal donor fixture shape from test_swift_error_flow.py:14-21. Caller BL,
// exact retained window, RET padding to 32-byte callee entry. No Mach-O parser
// or donor code is invoked. All expected values below are literals.
let swiftOutcomeLegacyDonorBase: UInt64 = 0x100001000
let swiftOutcomeLegacySharedWords: [UInt32] = [0xb40000b5, 0xaa1503e0, 0x94000010, 0x92800000, 0x14000002, 0xd2800000, 0xa9427bfd, 0xa94157f6, 0x9100c3ff, 0xd65f03c0]
let swiftOutcomeLegacyCMPWords: [UInt32] = [0xf10002bf, 0x54000080, 0xaa1503e0, 0x9400000c, 0x92800000]
let swiftOutcomeLegacyForwardWords: [UInt32] = [0xb5000075, 0xd2800000, 0x14000004, 0xaa1503e0, 0x94000010, 0x92800000, 0xa9427bfd, 0xa94157f6, 0x9100c3ff, 0xd65f03c0]
func swiftOutcomeLegacyCaller(_ window: [UInt32], maxInstructions: Int? = nil) -> SwiftOutcomeLegacyRecovery {
    let count = max(8, ((window.count + 1 + 7) / 8) * 8)
    var words: [UInt32] = [0x94000000 | UInt32(count)] + window
    words += Array(repeating: 0xd65f03c0, count: count - words.count)
    return SwiftOutcomeLegacyRecovery(words: Array(words.prefix(maxInstructions ?? count)), start: swiftOutcomeLegacyDonorBase, endExclusive: swiftOutcomeLegacyDonorBase + UInt64(count) * 4)
}
func swiftOutcomeLegacyFixture(_ window: [UInt32], symbol: String = "_$s4Demo4readSiyKF", maxInstructions: Int? = nil) -> SwiftOutcomeJSON {
    let callee = parseThrowingDeclaration(symbol).map { swiftOutcomeLegacyWith($0.record(), ["symbol": .string(symbol)]) } ?? .null
    return swiftOutcomeLegacyCaller(window, maxInstructions: maxInstructions).recoverCall(callee: callee)
}
func swiftOutcomeLegacySuccess(_ body: [UInt32], tail: [UInt32]? = nil, errorCall: UInt32 = 0x94000010) -> SwiftOutcomeJSON {
    swiftOutcomeLegacyFixture(Array(swiftOutcomeLegacySharedWords.prefix(2)) + [errorCall, 0x92800000, 0x14000000 | UInt32(body.count + 1)] + body + (tail ?? Array(swiftOutcomeLegacySharedWords.dropFirst(6))))
}
func swiftOutcomeLegacyErrorArm(_ body: [UInt32], tail: [UInt32] = [0xd65f03c0]) -> SwiftOutcomeJSON {
    swiftOutcomeLegacyFixture([0xb4000015 | UInt32(body.count + 2) << 5] + body + [0x14000002, 0xd2800000] + tail)
}

final class SwiftOutcomeLegacyDonorTests: XCTestCase {
    // TP1: test_swift_cmp_outcomes.py:15-137, complete pure word/recovery cases.
    func testTP1PreservedResultAndErrorLiteralFormStructuralChoice() {
        let c = swiftOutcomeLegacyFixture(swiftOutcomeLegacyCMPWords, symbol: "_$s4Demo5parseyS2iKF")
        XCTAssertEqual(c["success_result"]["status"], .string("preserved_register_candidate"))
        XCTAssertEqual(c["error_constant"]["status"], .string("constant_register_candidate"))
        XCTAssertEqual(c["error_constant"]["constant_bits"], .string("0xffffffffffffffff"))
        XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(c["return_choice"]["success"]["kind"], .string("call_result"))
        XCTAssertEqual(c["return_choice"]["error"]["constant_bits"], .string("0xffffffffffffffff"))
        XCTAssertEqual(c["return_choice"]["condition"]["comparison_pc"], .string("0x100001004"))
        XCTAssertEqual(c["return_choice"]["condition"]["test_condition"], .string("eq"))
        XCTAssertEqual(c["return_choice"]["runtime_value_proven"], .bool(false))
        XCTAssertEqual(c["return_choice"]["source_reconstruction_allowed"], .bool(false))
        XCTAssertEqual(c["error_constant"]["call_return_proven"], .bool(false))
        XCTAssertEqual(c["success_constant"]["status"], .string("declined"))
    }
    func testTP1ErrorAliasCopyAndResultRoundtrip() {
        let alias: [UInt32] = [0xaa1503f3,0xf100027f,0x54000080,0xaa1303e0,0x9400000b,0x92800000]
        let c = swiftOutcomeLegacyFixture(alias)
        XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(c["return_choice"]["condition"]["register"], .string("x19"))
        let copied = swiftOutcomeLegacyFixture([0xaa0003f3,0xaa1f03e0,0xaa1303e0,0xf10002bf,0x54000080,0xaa1503e0,0x94000009,0x92800000])
        XCTAssertEqual(copied["success_result"]["status"], .string("copied_register_candidate"))
        XCTAssertEqual(copied["return_choice"]["status"], .string("structural_choice_candidate"))
    }
    func testTP1ErrorTestInX0CannotPreserveResult() {
        let c = swiftOutcomeLegacyFixture([0xaa1503e0,0xf100001f,0x54000080,0xaa1503e0,0x9400000b,0x92800000])
        XCTAssertEqual(c["success_result"]["status"], .string("declined")); XCTAssertEqual(c["return_choice"]["status"], .string("unresolved"))
    }
    func testTP1TailSideEntryWithholdsBothOutcomes() {
        let c = swiftOutcomeLegacyFixture(swiftOutcomeLegacyCMPWords + [0xd65f03c0,0x17ffffff])
        XCTAssertEqual(c["success_result"]["reason"], .string("unexpected_return_tail_entry")); XCTAssertEqual(c["error_constant"]["status"], .string("declined")); XCTAssertEqual(c["return_choice"]["status"], .string("unresolved"))
    }
    func testTP1FlagHandlerUnknownAndNERefusals() {
        for word in [UInt32(0x17fffffc),0x17fffffd] {
            let c = swiftOutcomeLegacyFixture(swiftOutcomeLegacyCMPWords + [word]); XCTAssertEqual(c["return_choice"]["status"], .string("unresolved")); XCTAssertEqual(c["success_result"]["status"], .string("declined"))
        }
        for words in [swiftOutcomeLegacyCMPWords + [0xffffffff], [0xf10002bf,0x54000081,0xaa1503e0,0x9400000c,0x92800000]] {
            XCTAssertEqual(swiftOutcomeLegacyFixture(words)["return_choice"]["status"], .string("unresolved"))
        }
    }
    func testTP1LiteralBeforeOpaqueCallAndWordWidth() {
        let c = swiftOutcomeLegacyFixture([0xf10002bf,0x54000080,0x92800000,0x9400000c,0xd503201f])
        XCTAssertEqual(c["success_result"]["status"], .string("preserved_register_candidate")); XCTAssertEqual(c["error_constant"]["status"], .string("declined")); XCTAssertEqual(c["return_choice"]["status"], .string("unresolved"))
        let w = swiftOutcomeLegacyFixture([0xf10002bf,0x54000080,0xaa1503e0,0x9400000c,0x12800000])
        XCTAssertEqual(w["error_constant"]["constant_bits"], .string("0x00000000ffffffff")); XCTAssertEqual(w["return_choice"]["error"]["constant_bits"], .string("0x00000000ffffffff"))
        let wrong = swiftOutcomeLegacyFixture(swiftOutcomeLegacyCMPWords + [0xd65f0000])
        XCTAssertEqual(wrong["success_result"]["status"], .string("declined")); XCTAssertEqual(wrong["return_choice"]["status"], .string("unresolved"))
    }
    func testTP1ComparisonConditionAndFalseProofs() {
        let original = swiftOutcomeLegacyFixture(swiftOutcomeLegacyCMPWords)
        let mutations: [(String, SwiftOutcomeJSON)] = [("comparison_pc",.string("0x100001000")),("test_condition",.string("ne")),("test_kind",.string("foreign"))]
        for (key, value) in mutations {
            var c = original; c["presentation"]["display_plan"]["condition"][key] = value
            XCTAssertEqual(swiftOutcomeLegacyReturnChoice(c)["status"], .string("unresolved"))
        }
        XCTAssertEqual(original["success_constant"]["reason"], .string("success_x0_constant_not_known"))
        for key in ["success_result","error_constant","return_choice"] { for proof in ["runtime_value_proven","source_reconstruction_allowed","exclusive_path_proven","caller_return_type_proven"] { XCTAssertEqual(original[key][proof], .bool(false)) } }
    }
    func testTP1ChangedCallerCannotReusePresentation() {
        let original = swiftOutcomeLegacyFixture(swiftOutcomeLegacyCMPWords), caller = swiftOutcomeLegacyCaller(swiftOutcomeLegacyCMPWords)
        let changes: [(Int, UInt32)] = [(1,0xf100029f),(2,0x54000081),(2,0x540000a0)]
        for (index, word) in changes {
            var words = caller.words; words[index] = word
            let changed = SwiftOutcomeLegacyRecovery(words: words, start: caller.start, endExclusive: caller.endExclusive)
            XCTAssertEqual(changed.successResult(call: original, scan: changed.directEdges())["status"], .string("declined"))
        }
    }
    // TP2: literal expressions in test_swift_movk_outcomes.py:7-14 expand below.
    func testTP2SeedFourLanesAndReplacement() {
        let c = swiftOutcomeLegacySuccess([0xd2824680,0xf2aacf00,0xf2d35780,0xf2fbde00])
        XCTAssertEqual(c["success_constant"]["status"], .string("constant_register_candidate")); XCTAssertEqual(c["success_constant"]["constant_bits"], .string("0xdef09abc56781234")); XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x92800000,0xf2a00000,0xf2a24680])["success_constant"]["constant_bits"], .string("0xffffffff1234ffff"))
    }
    func testTP2BareUnknownAndSavedAliasUpdates() {
        for body in [[UInt32(0xf2800020)],[UInt32(0xf2800020),0xf2a00040,0xf2c00060,0xf2e00080]] {
            let c = swiftOutcomeLegacySuccess(body)
            XCTAssertEqual(c["presentation"]["status"], .string("eligible_structural_only")); XCTAssertEqual(c["success_constant"]["reason"], .string("success_x0_constant_not_known")); XCTAssertEqual(c["success_result"]["status"], .string("declined"))
        }
        XCTAssertEqual(swiftOutcomeLegacySuccess([0xd2800020,0xaa1303e0,0xf2a00040])["success_constant"]["reason"], .string("success_x0_constant_not_known"))
        let c = swiftOutcomeLegacySuccess([0xaa0003f3,0xf2800033,0xaa1303e0]); XCTAssertEqual(c["success_result"]["status"], .string("declined")); XCTAssertEqual(c["success_constant"]["status"], .string("declined"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0xf2800033])["success_result"]["status"], .string("preserved_register_candidate"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0xd2800540,0xf2ffffff])["success_constant"]["constant_bits"], .string("0x000000000000002a"))
    }
    func testTP2OpaqueCallsInvalidateButFullSeedRecovers() {
        let c = swiftOutcomeLegacyErrorArm([0x94000100,0xd2824680,0xf2f579a0])
        XCTAssertEqual(c["error_constant"]["constant_bits"], .string("0xabcd000000001234")); XCTAssertEqual(c["error_constant"]["call_return_proven"], .bool(false)); XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(swiftOutcomeLegacyErrorArm([0xd2800020,0x94000100,0xf2a00040])["error_constant"]["reason"], .string("error_x0_constant_not_known"))
    }
    func testTP2ReservedPostcallAndExactLimits() {
        for word in [UInt32(0x72c00020),0x72e00020] { XCTAssertEqual(swiftOutcomeLegacySuccess([0xd2800020,word])["success_constant"]["status"], .string("declined")) }
        XCTAssertEqual(swiftOutcomeLegacyFixture([0xf2800033] + swiftOutcomeLegacySharedWords)["status"], .string("declined"))
        let body: [UInt32] = [0xd2800020,0xf2a00040,0xf2a00040,0xf2a00040,0xf2a00040,0xf2a00040,0xf2a00040,0xf2a00040]
        let tail: [UInt32] = [0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd65f03c0]
        let c = swiftOutcomeLegacySuccess(body, tail: tail, errorCall: 0x94000100)
        XCTAssertEqual(c["success_constant"]["status"], .string("constant_register_candidate")); XCTAssertEqual(c["success_constant"]["instructions"].array?.count, 16)
        XCTAssertEqual(swiftOutcomeLegacySuccess(body + [0xf2c00060], errorCall: 0x94000100)["success_constant"]["status"], .string("declined"))
    }
    func testTP2ForwardLiteralArms() {
        let c = swiftOutcomeLegacyFixture([0xb5000095,0xd2824680,0xf2aacf00,0x14000003,0x92800000,0xf2f579a0,0xd65f03c0])
        XCTAssertEqual(c["error_region"]["layout"], .string("success_fallthrough_error_forward")); XCTAssertEqual(c["success_constant"]["constant_bits"], .string("0x0000000056781234")); XCTAssertEqual(c["error_constant"]["constant_bits"], .string("0xabcdffffffffffff")); XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate")); XCTAssertEqual(c["return_choice"]["source_reconstruction_allowed"], .bool(false))
    }
    // TP3: test_swift_w_copy_outcomes.py:8-81; wide/wcopy expanded literally.
    func testTP3KnownLiteralWidthAndTransitiveCopies() {
        let c = swiftOutcomeLegacySuccess([0x52a24693,0x2a1303e0])
        XCTAssertEqual(c["success_constant"]["status"], .string("constant_register_candidate")); XCTAssertEqual(c["success_constant"]["constant_bits"], .string("0x0000000012340000")); XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x92800013,0x2a1303e0])["success_constant"]["constant_bits"], .string("0x00000000ffffffff"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x92800013,0xaa1303e0])["success_constant"]["constant_bits"], .string("0xffffffffffffffff"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x52800553,0x2a1303f4,0x2a1403e0,0x2a0003e0])["success_constant"]["constant_bits"], .string("0x000000000000002a"))
    }
    func testTP3UnknownCopyKillsKnownAndDoesNotPreserveXResult() {
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x52800020,0x2a1303e0])["success_constant"]["reason"], .string("success_x0_constant_not_known"))
        let bodies: [[UInt32]] = [[0x2a0003e0],[0xaa0003f3,0x2a1303e0]]
        for body in bodies { let c = swiftOutcomeLegacySuccess(body); XCTAssertEqual(c["success_result"]["status"], .string("declined")); XCTAssertEqual(c["success_constant"]["status"], .string("declined")) }
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x2a0003f3])["success_result"]["status"], .string("preserved_register_candidate"))
        XCTAssertEqual(swiftOutcomeLegacySuccess([0x52800033,0x2a1303ff,0x2a1f03e0])["success_constant"]["constant_bits"], .string("0x0000000000000000"))
    }
    func testTP3OnlyCanonicalAliasAndRawFields() throws {
        let ins = try decodeSwiftOutcomeLegacyInstruction(word: 0x2a1303e0, address: 0x1000)
        XCTAssertEqual(ins.kind, "wmov"); XCTAssertEqual(ins.word, 0x2a1303e0); XCTAssertEqual(ins.address, 0x1000); XCTAssertEqual(ins.rd, 0); XCTAssertEqual(ins.rn, 19)
        for word in [UInt32(0x2a1307e0),0x2a5303e0,0x2a1303c0,0x2a3303e0] {
            XCTAssertNotEqual(try decodeSwiftOutcomeLegacyInstruction(word: word).kind, "wmov")
            XCTAssertEqual(swiftOutcomeLegacySuccess([0x52800033,word])["success_constant"]["status"], .string("declined"))
        }
    }
    func testTP3OpaqueCopiesForwardAndScope() {
        let c = swiftOutcomeLegacyErrorArm([0x94000100,0x52800553,0x2a1303e0])
        XCTAssertEqual(c["error_constant"]["constant_bits"], .string("0x000000000000002a")); XCTAssertEqual(c["error_constant"]["call_return_proven"], .bool(false))
        XCTAssertEqual(swiftOutcomeLegacyErrorArm([0x52800553,0x94000100,0x2a1303e0])["error_constant"]["reason"], .string("error_x0_constant_not_known"))
        let forward = swiftOutcomeLegacyFixture([0xb5000095,0x52800033,0x2a1303e0,0x14000003,0x12800013,0x2a1303e0,0xd65f03c0])
        XCTAssertEqual(forward["return_choice"]["success"]["constant_bits"], .string("0x0000000000000001")); XCTAssertEqual(forward["return_choice"]["error"]["constant_bits"], .string("0x00000000ffffffff"))
        XCTAssertEqual(swiftOutcomeLegacyFixture([0x2a1503f3] + swiftOutcomeLegacySharedWords)["status"], .string("declined"))
        XCTAssertEqual(swiftOutcomeLegacyFixture(Array(swiftOutcomeLegacySharedWords.prefix(6)) + [0x2a1303e0,0xd65f03c0])["success_constant"]["status"], .string("declined"))
    }
    func testTP3ExactCopyLimitsAndOverflow() {
        let body: [UInt32] = [0x52800033,0x2a1303e0,0x2a1303e0,0x2a1303e0,0x2a1303e0,0x2a1303e0,0x2a1303e0,0x2a1303e0]
        let tail: [UInt32] = [0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd503201f,0xd65f03c0]
        let c = swiftOutcomeLegacySuccess(body, tail: tail, errorCall: 0x94000100)
        XCTAssertEqual(c["success_constant"]["status"], .string("constant_register_candidate")); XCTAssertEqual(c["success_constant"]["instructions"].array?.count, 16)
        XCTAssertEqual(swiftOutcomeLegacySuccess(body + [0x2a0003e0], errorCall: 0x94000100)["success_constant"]["status"], .string("declined"))
    }
    // TP4: exact supplied shared/forward/direct Void layouts.
    func testTP4VoidLiteralScopeAndForwardProofFlags() {
        let c = swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords, symbol: "_$s4Demo8validateyyKF")
        XCTAssertEqual(c["success_constant"]["status"], .string("constant_register_candidate")); XCTAssertEqual(c["error_constant"]["constant_bits"], .string("0xffffffffffffffff")); XCTAssertEqual(c["return_choice"]["status"], .string("structural_choice_candidate")); XCTAssertEqual(c["success_result"]["status"], .string("declined")); XCTAssertEqual(c["success_result"]["reason"], .string("callee_result_not_scalar_int"))
        let arg = swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords, symbol: "_$s4Demo8validateyySiKF")
        XCTAssertEqual(arg["callee"]["parameters"], .array([.string("Swift.Int")])); XCTAssertEqual(arg["callee"]["result"], .string("Swift.Void")); XCTAssertEqual(arg["return_choice"]["success"]["constant_bits"], .string("0x0000000000000000")); XCTAssertEqual(arg["return_choice"]["error"]["constant_bits"], .string("0xffffffffffffffff"))
        let forward = swiftOutcomeLegacyFixture(swiftOutcomeLegacyForwardWords, symbol: "_$s4Demo8validateyyKF")
        XCTAssertEqual(forward["return_choice"]["status"], .string("structural_choice_candidate"))
        for key in ["success_constant","error_constant","return_choice"] { for proof in ["runtime_value_proven","source_reconstruction_allowed","caller_return_type_proven","exclusive_path_proven"] { XCTAssertEqual(forward[key][proof], .bool(false)) } }
    }
    func testTP4VoidX0AndNonsharedTailDoNotBorrowIntProof() {
        var words = swiftOutcomeLegacySharedWords; words[5] = 0xd503201f
        let c = swiftOutcomeLegacyFixture(words, symbol: "_$s4Demo8validateyyKF")
        XCTAssertEqual(c["success_result"]["status"], .string("declined")); XCTAssertEqual(c["success_constant"]["reason"], .string("success_x0_constant_not_known")); XCTAssertEqual(c["return_choice"]["status"], .string("unresolved"))
        let direct = swiftOutcomeLegacyFixture([0xb4000075,0x92800000,0x14000001,0xd65f03c0], symbol: "_$s4Demo8validateyyKF")
        XCTAssertEqual(direct["error_constant"]["reason"], .string("validated_success_return_tail_missing")); XCTAssertEqual(direct["return_choice"]["status"], .string("unresolved"))
    }
    func testTP4UnsupportedConflictIncompleteUnknownAndStaleMetadata() {
        for symbol in ["_$s4Demo8validateyyF","_$s4Demo8validateyyYaKF","_$s4Demo8validateSSyKF"] { XCTAssertEqual(swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords, symbol: symbol)["return_choice"]["status"], .string("unresolved")) }
        XCTAssertEqual(swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords + [0x17fffffb], symbol: "_$s4Demo8validateyyKF")["return_choice"]["status"], .string("unresolved"))
        XCTAssertEqual(swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords, symbol: "_$s4Demo8validateyyKF", maxInstructions: 10)["return_choice"]["status"], .string("unresolved"))
        var c = swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords, symbol: "_$s4Demo8validateyyKF"); c["callee"]["result"] = .string("Swift.String")
        let caller = SwiftOutcomeLegacyRecovery(words: [0x94000010] + swiftOutcomeLegacySharedWords, start: swiftOutcomeLegacyDonorBase, endExclusive: 0x10000102c)
        XCTAssertEqual(caller.pathConstant(call: c)["reason"], .string("callee_result_outside_admitted_subset"))
        c = swiftOutcomeLegacyFixture(swiftOutcomeLegacySharedWords, symbol: "_$s4Demo8validateyyKF"); c["success_result"] = c["success_constant"]; c["success_result"]["status"] = .string("preserved_register_candidate"); c["success_constant"]["status"] = .string("declined")
        XCTAssertEqual(swiftOutcomeLegacyReturnChoice(c)["reason"], .string("outcome_evidence_inconsistent"))
    }
    func testTP4CurrentModelIdentities() throws {
        let models = try sourceModels("legacy")
        XCTAssertEqual(models["success_constant"], .string("swift-success-constant-v17")); XCTAssertEqual(models["error_constant"], .string("swift-error-constant-v19")); XCTAssertEqual(models["return_choice"], .string("swift-return-choice-v45"))
    }
    // TP8: exact compiler-emitted literal windows at original source:8-12.
    func testTP8CompilerLiteralAndWidthPairs() {
        let words: [UInt32] = [0xb40000d5,0xaa1503e0,0x94000082,0x528acf00,0x72a24680,0x14000003,0x5299bde0,0x72b13560,0xa9427bfd,0xa94157f6,0x9100c3ff,0xd65f03c0]
        let c = swiftOutcomeLegacyFixture(words, symbol: "_$s15AIRSWordChoices8validateyyKF")
        XCTAssertEqual(c["return_choice"]["success"]["constant_bits"], .string("0x0000000089abcdef")); XCTAssertEqual(c["return_choice"]["error"]["constant_bits"], .string("0x0000000012345678")); XCTAssertEqual(c["error_region"]["success_interval"]["instructions"].array?.map { $0["kind"] }, [.string("wmovz"), .string("wmovk")])
        let width: [UInt32] = [0xb40000b5,0xaa1503e0,0x94000070,0x92800000,0x14000002,0x12800000,0xa9427bfd,0xa94157f6,0x9100c3ff,0xd65f03c0]
        let choice = swiftOutcomeLegacyFixture(width, symbol: "_$s15AIRSWordChoices8validateyyKF")["return_choice"]
        XCTAssertEqual(choice["success"]["constant_bits"], .string("0x00000000ffffffff")); XCTAssertEqual(choice["error"]["constant_bits"], .string("0xffffffffffffffff")); XCTAssertEqual(choice["same_constant_bits"], .bool(false)); XCTAssertEqual(choice["source_reconstruction_allowed"], .bool(false))
        var noSeed = words; noSeed[3] = 0xd503201f
        let removed = swiftOutcomeLegacyFixture(noSeed, symbol: "_$s15AIRSWordChoices8validateyyKF")
        XCTAssertEqual(removed["presentation"]["status"], .string("eligible_structural_only")); XCTAssertEqual(removed["error_constant"]["reason"], .string("error_x0_constant_not_known")); XCTAssertEqual(removed["return_choice"]["status"], .string("unresolved"))
        var xWidth = width; xWidth[5] = 0x92800000
        let changed = swiftOutcomeLegacyFixture(xWidth, symbol: "_$s15AIRSWordChoices8validateyyKF")["return_choice"]
        XCTAssertEqual(changed["success"]["constant_bits"], .string("0xffffffffffffffff")); XCTAssertEqual(changed["same_constant_bits"], .bool(true))
        let conflict = swiftOutcomeLegacyFixture(words + [0x17fffffa], symbol: "_$s15AIRSWordChoices8validateyyKF")
        XCTAssertEqual(conflict["presentation"]["status"], .string("blocked")); XCTAssertEqual(conflict["return_choice"]["status"], .string("unresolved"))
    }
    func testTP4RequestAliasesAndDefaultOptionAbsence() throws {
        let caller = swiftOutcomeLegacyCaller(swiftOutcomeLegacySharedWords)
        let target = caller.endExclusive
        let slice = SwiftErrorFlowSliceIdentity(artifactSHA256: "fixture", sliceOffset: 0, sliceByteCount: 256, cpuType: 0x0100000c, cpuSubtype: 0, littleEndian: true)
        let code = SwiftErrorFlowCode(baseAddress: swiftOutcomeLegacyDonorBase, sliceRelativeFileOffset: 0, sectionOrdinal: 1, hasEmbeddedData: false, hasRelocations: false, words: caller.words + [0xd65f03c0])
        let functions = [SwiftErrorFlowFunction(start: caller.start, endExclusive: target, boundarySource: "lc_function_starts"), SwiftErrorFlowFunction(start: target, endExclusive: target + 4, boundarySource: "lc_function_starts")]
        let symbol = SwiftErrorFlowSymbol(address: target, name: "_$s4Demo8validateyyKF", nType: 0x0f, nDesc: 0, sectionOrdinal: 1)
        var request = SwiftErrorFlowRequest(slice: slice, code: code, functions: functions, symbols: [symbol])
        let absent = try recoverSwiftOutcomeLegacyRequest(request)
        XCTAssertNil(absent.object?["return_choice_model_version"])
        XCTAssertNil(absent["calls"].array?.first?.object?["return_choice"])
        let report = try recoverSwiftOutcomeLegacyRequest(request, includeErrorRegions: true, validateRegionEntries: true, includeStructuredPresentation: true)
        XCTAssertEqual(report["success_constant_model_version"], .string("swift-success-constant-v17"))
        XCTAssertEqual(report["error_constant_model_version"], .string("swift-error-constant-v19"))
        XCTAssertEqual(report["return_choice_model_version"], .string("swift-return-choice-v45"))
        request.symbols.append(SwiftErrorFlowSymbol(address: target, name: "_$s4Demo5otheryyKF", nType: 0x0f, nDesc: 0, sectionOrdinal: 1))
        let ambiguous = try recoverSwiftOutcomeLegacyRequest(request, includeErrorRegions: true, validateRegionEntries: true, includeStructuredPresentation: true)
        XCTAssertEqual(ambiguous["calls"].array?.first?["reason"], .string("callee_symbol_absent_or_ambiguous"))
        XCTAssertEqual(ambiguous["calls"].array?.first?["return_choice"]["status"], .string("unresolved"))
    }
    func testCMPDirectTailZeroRetainedEndpointRefusesWithoutUnderflow() {
        // Literal DIRECT_EQ from test_swift_preserved_result_binding.py.
        let directEQ: [UInt32] = [0xf10002bf,0x54000060,0x92800000,0x14000001,0xd65f03c0]
        let caller = swiftOutcomeLegacyCaller(directEQ)
        let scan = caller.directEdges()
        var call = swiftOutcomeLegacyFixture(directEQ)
        XCTAssertEqual(call["presentation"]["status"], .string("eligible_structural_only"))
        XCTAssertEqual(scan["caller_scan_complete"], .bool(true))
        call["error_region"]["end_pc_exclusive"] = .string("0x0")
        let result = caller.pathConstant(call: call, scan: scan)
        XCTAssertEqual(result["status"], .string("declined"))
        XCTAssertEqual(result["reason"], .string("unexpected_return_tail_entry"))
        XCTAssertEqual(result["unexpected_tail_entry_count"], .integer(1))
        XCTAssertEqual(result["tail_entry_details_complete"], .bool(true))
        XCTAssertEqual(result["unexpected_tail_entries"], .array([.object([
            "source_pc": .string("0x100001010"), "target_pc": .string("0x100001014"),
            "word": .string("0x14000001"), "kind": .string("b")])]))
        XCTAssertEqual(result["runtime_value_proven"], .bool(false))
        XCTAssertEqual(result["source_reconstruction_allowed"], .bool(false))
    }
    func testInvalidCallerSpanRefusesWithoutAddressWrap() {
        let invalid = SwiftOutcomeLegacyRecovery(words: [0x94000001,0xd65f03c0], start: 0xfffffffffffffffc)
        XCTAssertFalse(invalid.validSpan)
        XCTAssertEqual(invalid.edges(callOffset: 0)["reason"], .string("legacy_caller_span"))
        XCTAssertEqual(invalid.recoverCall(callee: .object([:]))["reason"], .string("legacy_caller_span"))
        XCTAssertEqual(invalid.directEdges()["caller_scan_complete"], .bool(false))
        XCTAssertNil(invalid.sharedReturnTail(join: 0xfffffffffffffffc))
    }
}
#endif
