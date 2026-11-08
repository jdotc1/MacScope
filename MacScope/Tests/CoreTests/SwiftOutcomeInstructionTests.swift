import Foundation
import XCTest
@testable import MacScope

final class SwiftOutcomeInstructionTests: XCTestCase {
    private func refusal(_ word: UInt32, _ code: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try decodeSwiftOutcomeInstruction(word: word, address: 0x1000), file: file, line: line) {
            XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: code), file: file, line: line)
        }
    }
    func testXD01DirectCall() throws {
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0x94000004, address: 0x1000), SwiftOutcomeInstruction(address: 0x1000, word: 0x94000004, kind: "bl", immediate: 16))
    }
    func testXD02ReturnAndNOP() throws {
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0xd65f03c0, address: 0), SwiftOutcomeInstruction(address: 0, word: 0xd65f03c0, kind: "ret", rn: 30))
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0xd503201f, address: 0), SwiftOutcomeInstruction(address: 0, word: 0xd503201f, kind: "nop"))
    }
    func testXD03CompareBranch() throws {
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0xb5000055, address: 0x1004), SwiftOutcomeInstruction(address: 0x1004, word: 0xb5000055, kind: "xcbnz", rn: 21, immediate: 8))
    }
    func testXD04RegisterMove() throws {
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0xaa1503f3, address: 0), SwiftOutcomeInstruction(address: 0, word: 0xaa1503f3, kind: "mov", rd: 19, rn: 21))
    }
    func testXD05MoveWide() throws {
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0xd2824680, address: 0), SwiftOutcomeInstruction(address: 0, word: 0xd2824680, kind: "movz", immediate: 0x1234))
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0x52824680, address: 0), SwiftOutcomeInstruction(address: 0, word: 0x52824680, kind: "wmovz", immediate: 0x1234))
    }
    func testXD06PairPreIndex() throws {
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0xa9bf7bfd, address: 0), SwiftOutcomeInstruction(address: 0, word: 0xa9bf7bfd, kind: "stp", rd: 29, rn: 31, rt2: 30, immediate: -16, addressing: "pre"))
    }
    func testXD07DonorRefusals() {
        refusal(0x00000000, "unsupported_instruction")
        refusal(0xd503233f, "unsupported_pauth")
        refusal(0xd61f0000, "unsupported_control_flow")
    }
    func testXD08NativeAgreement() throws {
        let descriptor = SwiftOutcomeInstruction(address: 0x1000, word: 0x94000004, kind: "bl", immediate: 16)
        let decoded = try XCTUnwrap(ARM64Decoder().decode(Data([0x04, 0x00, 0x00, 0x94]), baseAddress: 0x1000, maxInstructionCount: 1).first)
        XCTAssertEqual(decoded.flow, InstructionFlow.call)
        XCTAssertEqual(decoded.branchTarget, UInt64(0x1010))
        XCTAssertNoThrow(try SwiftOutcomeDecoderCrossCheck.check(descriptor, decoded: decoded))
    }
    func testXD09NativeDisagreement() {
        let descriptor = SwiftOutcomeInstruction(address: 0x1000, word: 0x94000004, kind: "bl", immediate: 16)
        let wrongFlow = DecodedInstruction(address: 0x1000, bytes: [0x04, 0x00, 0x00, 0x94], mnemonic: "b", operands: "", branchTarget: 0x1010, comment: nil, flow: .jump)
        let wrongTarget = DecodedInstruction(address: 0x1000, bytes: [0x04, 0x00, 0x00, 0x94], mnemonic: "bl", operands: "", branchTarget: 0x1014, comment: nil, flow: .call)
        for decoded in [wrongFlow, wrongTarget] {
            XCTAssertThrowsError(try SwiftOutcomeDecoderCrossCheck.check(descriptor, decoded: decoded)) {
                XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "decoder_form_mismatch"))
            }
        }
    }
    func testXD10MissingNativeForms() {
        // Each literal is its donor mask value with zero operand fields.
        let cases: [(String, UInt32)] = [
            ("scvtf_s_w",0x1e220000), ("scvtf_s_x",0x9e220000),
            ("scvtf_d_w",0x1e620000), ("scvtf_d_x",0x9e620000),
            ("fcvtzs_w_s",0x1e380000), ("fcvtzs_x_s",0x9e380000),
            ("fcvtzs_w_d",0x1e780000), ("fcvtzs_x_d",0x9e780000),
            ("fmov_s_w",0x1e270000), ("fmov_d_x",0x9e670000),
            ("fmov_w_s",0x1e260000), ("fmov_x_d",0x9e660000),
            ("fmov_s_reg",0x1e204000), ("fmov_d_reg",0x1e604000),
            ("fmov_s_imm",0x1e201000), ("fmov_d_imm",0x1e601000),
            ("fdiv_s",0x1e201800), ("fdiv_d",0x1e601800),
            ("fcmp_s_reg",0x1e202000), ("fcmp_d_reg",0x1e602000),
            ("fcmp_s_zero",0x1e202008), ("fcmp_d_zero",0x1e602008),
            ("qstr",0x3d800000), ("qldr",0x3dc00000),
            ("sstr",0xbd000000), ("sldr",0xbd400000),
            ("dstr",0xfd000000), ("dldr",0xfd400000),
            ("movi_2s_lsl24",0x0f006400)
        ]
        for (kind, word) in cases {
            XCTAssertNil(SwiftOutcomeDecoderCrossCheck.mnemonics(for: kind))
            refusal(word, "decoder_form_missing")
        }
        // The alternative unscaled encodings share the same refusal kinds.
        let unscaled: [UInt32] = [0xbc000000, 0xbc400000, 0xfc000000, 0xfc400000]
        for word in unscaled {
            refusal(word, "decoder_form_missing")
        }
    }
    func testDonorGuardsAndBackwardBranch() throws {
        refusal(0x52c00000, "swift_wide_shift")
        refusal(0x72c00000, "invalid_movk_shift")
        refusal(0x8b201400, "broad_extend_shift")
        refusal(0xf8400400, "broad_memory_writeback_overlap")
        refusal(0x5400000e, "cfg_condition_not_modeled")
        XCTAssertEqual(try decodeSwiftOutcomeInstruction(word: 0x17ffffff, address: 0x1000), SwiftOutcomeInstruction(address: 0x1000, word: 0x17ffffff, kind: "b", immediate: -4))
    }
    func testBranchTargetOverflowIsMismatch() {
        XCTAssertThrowsError(try decodeSwiftOutcomeInstruction(word: 0x17ffffff, address: 0)) {
            XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "decoder_form_mismatch"))
        }
    }

    func testTP1TP3TP8PortableDescriptors() throws {
        let copy = try decodeSwiftOutcomeInstruction(word:0x2a1303e0,address:0x1000)
        XCTAssertEqual(copy.kind,String("wmov")); XCTAssertEqual(copy.rd,Int(0)); XCTAssertEqual(copy.rn,Int(19))
        XCTAssertEqual(copy.word,UInt32(0x2a1303e0)); XCTAssertEqual(copy.address,UInt64(0x1000))
        // Broad decoding can classify noncanonical ORR variants, but must never call them wmov.
        let variants: [UInt32] = [0x2a1307e0,0x2a5303e0,0x2a1303c0,0x2a3303e0]
        for modified in variants {
            do { XCTAssertNotEqual(try decodeSwiftOutcomeInstruction(word:modified).kind,String("wmov")) }
            catch { XCTAssertNotNil(error as? SwiftOutcomeError) }
        }
        let compare = try decodeSwiftOutcomeInstruction(word:0xf100027f,address:0x1008)
        XCTAssertEqual(compare.kind,String("xsubs")); XCTAssertEqual(compare.rd,Int(31)); XCTAssertEqual(compare.rn,Int(19)); XCTAssertEqual(compare.immediate,Int128(0))
        let ne = try decodeSwiftOutcomeInstruction(word:0x54000081,address:0x100c)
        XCTAssertEqual(ne.kind,String("bcond")); XCTAssertEqual(ne.addressing,String("1")); XCTAssertEqual(ne.immediate,Int128(16))
        XCTAssertThrowsError(try decodeSwiftOutcomeInstruction(word:0xd65f0000)) {
            XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "unsupported_control_flow"))
        }
        let backwards = try decodeSwiftOutcomeInstruction(word:0x17fffffa,address:0x1034)
        XCTAssertEqual(backwards.kind,String("b")); XCTAssertEqual(backwards.immediate,Int128(-24))
        let badLanes: [UInt32] = [0x72c00020,0x72e00020]
        for word in badLanes { XCTAssertThrowsError(try decodeSwiftOutcomeInstruction(word:word)) }
    }

    func testTP1TP4RawMutationDescriptors() throws {
        let branches: [(UInt32, Int128)] = [(0x17ffffff,-4),(0x17fffffc,-16),(0x17fffffd,-12),(0x17fffffb,-20)]
        for (word, expected) in branches {
            let result = try decodeSwiftOutcomeInstruction(word: word, address: 0x1030)
            XCTAssertEqual(result.kind, String("b")); XCTAssertEqual(result.immediate, expected)
        }
        let compare = try decodeSwiftOutcomeInstruction(word: 0xf100029f, address: 0x1004)
        XCTAssertEqual(compare.kind, String("xsubs")); XCTAssertEqual(compare.rn, Int(20)); XCTAssertEqual(compare.immediate, Int128(0))
        let conditions: [(UInt32, Int128, String)] = [(0x54000081,16,"1"),(0x540000a0,20,"0")]
        for (word, displacement, condition) in conditions {
            let result = try decodeSwiftOutcomeInstruction(word: word, address: 0x1008)
            XCTAssertEqual(result.kind, String("bcond")); XCTAssertEqual(result.immediate, displacement); XCTAssertEqual(result.addressing, condition)
        }
        refusal(0xffffffff, "unsupported_instruction")
    }

    func testCrossCheckExtremeDescriptorRefusesWithoutOverflow() {
        let descriptor = SwiftOutcomeInstruction(address: 1, word: 0x94000000, kind: "bl", immediate: Int128.max)
        let decoded = DecodedInstruction(address: 1, bytes: [0,0,0,0x94], mnemonic: "bl", operands: "", branchTarget: 1, comment: nil, flow: .call)
        XCTAssertThrowsError(try SwiftOutcomeDecoderCrossCheck.check(descriptor, decoded: decoded)) {
            XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "decoder_form_mismatch"))
        }
    }

    func testSupplementSystemNOPBodyAndHintBoundary() throws {
        let nop = try XCTUnwrap(ARM64Decoder().decode(Data([0x1f,0x20,0x03,0xd5]), baseAddress: 0x1000, maxInstructionCount: 1).first)
        XCTAssertEqual(nop.mnemonic, String("nop"))
        XCTAssertEqual(nop.flow, InstructionFlow.normal)
        XCTAssertNil(nop.branchTarget)
        let otherOp1 = try XCTUnwrap(ARM64Decoder().decode(Data([0x1f,0x20,0x00,0xd5]), baseAddress: 0x1000, maxInstructionCount: 1).first)
        XCTAssertNotEqual(otherOp1.mnemonic, String("nop"))
        let descriptor = SwiftOutcomeInstruction(address: 0x1000, word: 0xd503201f, kind: "nop")
        XCTAssertThrowsError(try SwiftOutcomeDecoderCrossCheck.check(descriptor, decoded: otherOp1)) {
            XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "decoder_form_mismatch"))
        }
    }

}
