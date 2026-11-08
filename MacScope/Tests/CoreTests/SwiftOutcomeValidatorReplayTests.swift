import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

/// Donor test names are preserved after the UC prefix for traceability.
final class SwiftOutcomeValidatorReplayTests: XCTestCase {
    private let origin: SwiftOutcomeJSON = .array([.string("call_result"), .string("0x1000"), .integer(64)])
    private func constant(_ n: Int128) -> SwiftOutcomeJSON { .array([.string("constant"), .integer(n), .integer(64)]) }
    private func replay(_ words: [UInt32], state: SwiftOutcomeScalarReplay? = nil) throws -> SwiftOutcomeScalarReplay {
        let s = state ?? SwiftOutcomeScalarReplay(callPC: 0x1000, limits: BroadWitnessLimits())
        for (i, word) in words.enumerated() { try s.step(decodeSwiftOutcomeInstruction(word: word, address: 0x1004 + UInt64(i * 4))) }
        return s
    }
    /// ar4a's production decoder refuses FP/SIMD forms (decoder_form_missing, SwiftOutcomeInstructionTests).
    /// These replay tests exercise the replay's handling of the broad descriptor kinds directly,
    /// using the descriptors the broad word classifier assigns to these literal words.
    private static let fpKinds: [UInt32: (String, Int, Int)] = [
        0x1e270000: ("fmov_s_w", 0, 0), 0x1e260000: ("fmov_w_s", 0, 0), 0x3d8003e0: ("qstr", 0, 31),
        0x0f0267e0: ("movi_2s_lsl24", 0, 0), 0xbd0003e0: ("sstr", 0, 31), 0xfd0003e0: ("dstr", 0, 31),
        0xbd4003e0: ("sldr", 0, 31), 0xfd4003e0: ("dldr", 0, 31)
    ]
    private func replayBroad(_ words: [UInt32]) throws -> SwiftOutcomeScalarReplay {
        let s = SwiftOutcomeScalarReplay(callPC: 0x1000, limits: BroadWitnessLimits())
        for (i, word) in words.enumerated() {
            let pc = 0x1004 + UInt64(i * 4)
            if let (kind, rd, rn) = Self.fpKinds[word] {
                try s.step(SwiftOutcomeInstruction(address: pc, word: word, kind: kind, rd: rd, rn: rn, addressing: kind.hasSuffix("str") || kind.hasSuffix("ldr") ? "offset" : ""))
            } else { try s.step(decodeSwiftOutcomeInstruction(word: word, address: pc)) }
        }
        return s
    }
    func testUC14_postcall_x0_error_copy_cannot_retain_result() throws {
        XCTAssertNotEqual(try replay([0xaa1503e0]).registers[0], origin)
    }
    func testUC14_postcall_unknown_copy_kills_result() throws { XCTAssertNil(try replay([0xaa0103e0]).registers[0]) }
    func testUC14_narrow_then_wide_does_not_resurrect_result() throws {
        let s = try replay([0x2a0003e1,0xaa0103e0]); XCTAssertNotEqual(s.registers[0], origin)
        XCTAssertEqual(s.registers[0]?.array?.first?.string, "zero_extend")
    }
    func testUC14_wide_copy_preserves_result() throws { XCTAssertEqual(try replay([0xaa0003e1,0xaa0103e0]).registers[0], origin) }
    func testUC14_constant_lane_and_arithmetic() throws { XCTAssertEqual(try replay([0xd2800020,0xf2a00040,0x91000400]).registers[0], constant(0x20002)) }
    func testUC14_stack_result_spill_reload_with_frame() throws {
        let s = try replay([0xd10043ff,0xf90003e0,0xd2800000,0xf94003e0,0x910043ff])
        XCTAssertEqual(s.registers[0], origin); XCTAssertEqual(s.sp, 0); XCTAssertTrue(s.cells.isEmpty)
    }
    func testUC14_stack_overlapping_store_invalidates_old_wide_cell() throws { XCTAssertNil(try replay([0xd10043ff,0xf90003e0,0xb90007ff,0xf94003e0]).registers[0]) }
    func testUC14_call_clobber_cannot_retain_old_result_or_stack() throws {
        let s = try replay([0xd10043ff,0xf90003e0,0x94000001]); XCTAssertNil(s.registers[0]); XCTAssertTrue(s.cells.isEmpty)
    }
    func testUC14_opaque_call_kills_error_and_saved_aliases() throws {
        let s = try replay([0xaa1503f3,0x94000001]); XCTAssertNil(s.registers[19]); XCTAssertNil(s.registers[21])
    }
    func testUC14_narrow_literal_is_zero_extended() throws { XCTAssertEqual(try replay([0x12800000]).registers[0], constant(0xffffffff)) }

    // UC25 DecoderEffectBreadthTests, donor lines 649–665.
    func testUC25_fp_destination_zero_does_not_clobber_gpr_zero() throws { XCTAssertEqual(try replayBroad([0x1e270000]).registers[0], origin) }
    func testUC25_fp_to_gpr_zero_cannot_preserve_result_origin() throws { XCTAssertNil(try replayBroad([0x1e260000]).registers[0]) }
    func testUC25_narrow_byte_store_invalidates_overlapping_wide_cell() throws { XCTAssertNil(try replay([0xd10043ff,0xf90003e0,0x390007ff,0xf94003e0]).registers[0]) }
    func testUC25_narrow_halfword_literal_store_load_zero_extends() throws { XCTAssertEqual(try replay([0xd10043ff,0x12800000,0x790003e0,0x794003e1]).registers[1], constant(0xffff)) }

    // UC25 ScalarResultAllocationTests.
    func testUC25_reserved_scalar_result_encodings_do_not_count_as_writes() {
        for word: UInt32 in [0x0b00fc00,0x8bc00000,0x32800000,0x0a00fc00,0x1a800800,0x1a80f000,0x3b000000] { XCTAssertFalse(swiftOutcomeAllocatedResultGPRWrite(word, register: 0)) }
    }
    func testUC25_allocated_csel_madd_and_move_are_separate_result_writes() {
        for word: UInt32 in [0x1a800000,0x1b000000,0xd2800020,0x8b00fc00] { XCTAssertTrue(swiftOutcomeAllocatedResultGPRWrite(word, register: 0)) }
    }
    // UC25 NewPrimitiveConsumerTests.
    func testUC25_xadd_register_retains_both_input_origins() throws {
        let s = try replay([0xd2800021,0x8b010000]); XCTAssertEqual(s.registers[0]?.array?.first?.string, "add"); XCTAssertEqual(s.registers[0]?.array?[1], origin)
    }
    func testUC25_unknown_raw_base_load_kills_destination_and_store_invalidates_cells() throws {
        let s = try replay([0xd10043ff,0xf90003e0,0xf9000101,0xf9400100]); XCTAssertNil(s.registers[0]); XCTAssertTrue(s.cells.isEmpty)
    }
    func testUC25_signed_unscaled_frame_spill_reloads_original_result() throws { XCTAssertEqual(try replay([0xd10083ff,0x910083fd,0xf81f83a0,0xd2800000,0xf85f83a0]).registers[0], origin) }
    func testUC25_q_store_invalidates_scalar_stack_origin() throws { XCTAssertNil(try replayBroad([0xd10083ff,0xf90003e0,0x3d8003e0,0xf94003e0]).registers[0]) }
    func testUC25_movi_v0_leaves_x0_origin_untouched() throws { XCTAssertEqual(try replayBroad([0x0f0267e0]).registers[0], origin) }

    // UC26 B11MemoryWritebackTests: state deliberately created independently.
    func testUC26_unknown_memory_base_writeback_kills_each_retained_origin() throws {
        let origins: [SwiftOutcomeJSON?] = [constant(0x2000), .array([.string("call_result"),.string("0x2000"),.integer(64)]), .array([.string("error_result"),.string("0x2000"),.integer(64)]), nil]
        for retained in origins {
            for op: UInt32 in [0xa8c00000,0xa9c00000,0xa8800000,0xa9800000] {
                let s = SwiftOutcomeScalarReplay(callPC: 0x2000, limits: BroadWitnessLimits())
                try s.write(29, retained); try s.write(1, constant(7)); try s.write(2, constant(8))
                s.cells[-8] = .init(size: 8, epoch: 0, value: .array([.string("call_result"),.string("0x2000"),.integer(64)]))
                try s.step(decodeSwiftOutcomeInstruction(word: op | (2 << 15) | (2 << 10) | (29 << 5) | 1, address: 0x2004))
                XCTAssertNil(s.read(29)); try s.step(decodeSwiftOutcomeInstruction(word: 0xaa1d03e0, address: 0x2004)); XCTAssertNil(s.read(0))
                if [UInt32(0xa8c00000),0xa9c00000].contains(op) { XCTAssertNil(s.read(1)); XCTAssertNil(s.read(2)) } else { XCTAssertTrue(s.cells.isEmpty) }
            }
        }
    }
    func testUC26_unknown_sp_does_not_preserve_frame_alias_writeback() throws {
        for base: UInt32 in [29,31] {
            for op: UInt32 in [0xa8c00000,0xa9c00000,0xa8800000,0xa9800000] {
                let s = SwiftOutcomeScalarReplay(callPC: 0x2000, limits: BroadWitnessLimits()); s.stackPointer = nil
                try s.write(29, .array([.string("stack_address"),.integer(-32),.integer(64)]))
                try s.step(decodeSwiftOutcomeInstruction(word: op | (2 << 15) | (2 << 10) | (base << 5) | 1, address: 0x2004))
                XCTAssertNil(s.stackPointer); if base == 29 { XCTAssertNil(s.read(29)) }
            }
        }
    }
    func testUC26_unknown_load_destinations_and_writeback_overlap_refuse() throws {
        for (rd, rt2) in [(1,1),(29,2),(1,29)] {
            let s = SwiftOutcomeScalarReplay(callPC: 0x2000, limits: BroadWitnessLimits()); try s.write(29, constant(0x2000))
            XCTAssertThrowsError(try s.step(SwiftOutcomeInstruction(address: 0x2004, word: 0, kind: "ldp", rd: rd, rn: 29, rt2: rt2, immediate: 16, addressing: "post"))) { XCTAssertTrue($0 is SwiftOutcomeValidatorStop) }
        }
        let s = SwiftOutcomeScalarReplay(callPC: 0x2000, limits: BroadWitnessLimits()); try s.write(29, constant(0x2000))
        try s.step(decodeSwiftOutcomeInstruction(word: 0xa9400000 | (2 << 10) | (29 << 5) | 29, address: 0x2004)); XCTAssertNil(s.read(29)); XCTAssertNil(s.read(2))
    }

    func testUC26_known_sp_pre_store_post_load_retains_only_actual_cells() throws {
        let s = SwiftOutcomeScalarReplay(callPC: 0x2000, limits: BroadWitnessLimits()); try s.write(1, constant(9))
        try s.step(decodeSwiftOutcomeInstruction(word: 0xa9bf07e0, address: 0x2004)); XCTAssertEqual(s.sp, -16)
        try s.write(0, nil); try s.write(1, nil)
        try s.step(decodeSwiftOutcomeInstruction(word: 0xa8c107e0, address: 0x2004))
        XCTAssertEqual(s.sp, 0); XCTAssertTrue(s.cells.isEmpty)
        XCTAssertEqual(s.read(0), .array([.string("call_result"),.string("0x2000"),.integer(64)])); XCTAssertEqual(s.read(1), constant(9))
    }

    // UC26 SixIntegrationResidualTests: the two scalar-replay methods.
    func testUC26_unsigned_bitfield_exact_literal_wrap_and_symbolic_unknown() throws {
        for (immr, imms, expected) in [(4,7,15),(63,62,486)] {
            let word: UInt32 = 0xd3400000 | (UInt32(immr) << 16) | (UInt32(imms) << 10)
            XCTAssertEqual(try replay([0xd2801e60,word]).registers[0], constant(Int128(expected)))
        }
        XCTAssertEqual(try replay([0xd37ff800]).registers[0]?.array?.first?.string, "unsigned_bitfield")
        XCTAssertNil(try replay([0xd340fc20]).registers[0])
    }
    func testUC26_unsigned_word_bitfield_zero_extends_without_source_value_invention() throws { XCTAssertEqual(try replay([0xd2801e60,0x53041c00]).registers[0], constant(15)) }
    // UC26 TypedLogicalAndSelectTests.
    func testUC26_decoded_logical_immediate_literals_and_word_zero_extension() throws {
        XCTAssertEqual(try replay([0xd2801e60,0x12000000,0x32001c00,0x52000000]).registers[0], constant(254))
        XCTAssertEqual(try replay([0x12800000,0x72000000]).registers[0], constant(1))
    }
    func testUC26_logical_symbolic_transform_and_unknown_are_distinct() throws {
        XCTAssertEqual(try replay([0x92400000]).registers[0], .array([.string("and"),origin,constant(1),.integer(64)]))
        XCTAssertNil(try replay([0x92400020]).registers[0])
    }
    func testUC26_flag_only_add_sub_and_logical_to_zr_do_not_write_sp_or_result() throws {
        for word: UInt32 in [0x7100011f,0xb100041f,0xf100041f,0x3100041f,0x7200001f] {
            let s = try replay([word]); XCTAssertEqual(s.sp, 0); XCTAssertEqual(s.registers[0], origin); XCTAssertNil(s.registers[31])
        }
    }
    func testUC26_all_select_family_destinations_are_unknown_without_nzcv() throws {
        for word: UInt32 in [0x1a800000,0x1a800400,0x5a800000,0x5a800400,0x9a800000,0x9a880500,0xda800000,0xda800400] { XCTAssertNil(try replay([word]).registers[0]) }
    }
    func testUC26_value_refusal_retains_one_bounded_raw_instruction_diagnostic() {
        XCTAssertThrowsError(try replay([0x9ac00800])) {
            XCTAssertEqual(($0 as? SwiftOutcomeValidatorStop)?.instruction, .object(["pc":.string("0x1004"),"word":.string("0x9ac00800"),"kind":.string("xudiv")]))
        }
    }
    // UC26 Repair2RegisterArithmeticTests.
    func testUC26_shifted_flag_arithmetic_to_zr_has_no_gpr_or_sp_destination() throws {
        for word: UInt32 in [0xeb09011f,0xab01001f,0x6b01001f,0x2b01001f] {
            let s = try replay([word]); XCTAssertEqual(s.sp, 0); XCTAssertEqual(s.registers[0], origin); XCTAssertNil(s.registers[31])
        }
    }
    func testUC26_shifted_flag_arithmetic_literals_sign_and_word_width() throws {
        XCTAssertEqual(try replay([0xd2800060,0xd2800041,0xab010800]).registers[0], constant(11))
        XCTAssertEqual(try replay([0xd2800060,0x92800001,0xeb810800]).registers[0], constant(4))
        XCTAssertEqual(try replay([0x12800000,0x52800021,0x2b010000]).registers[0], constant(0))
    }
    func testUC26_shifted_arithmetic_origins_and_unknown_are_not_interchangeable() throws {
        XCTAssertEqual(try replay([0xd2800041,0xab010000]).registers[0], .array([.string("add"),origin,constant(2),.integer(64)]))
        XCTAssertNil(try replay([0xab020020]).registers[0])
    }
    func testUC26_logical_register_width_and_inverted_operand_are_exact() throws {
        XCTAssertEqual(try replay([0xd2801e60,0xd28001e1,0x0a010000]).registers[0], constant(3))
        XCTAssertEqual(try replay([0xd2801e60,0xd28001e1,0x0a210000]).registers[0], constant(240))
    }
    func testUC26_raw_invalid_shift_encodings_remain_decoder_refusals() {
        for word: UInt32 in [0x2b00fc00,0xabc00000,0x0a00fc00] { XCTAssertThrowsError(try decodeSwiftOutcomeInstruction(word: word, address: 0x1004)) }
    }
    // UC26 Repair2MemoryAndExtendedTests.
    func testUC26_extended_add_sub_sp_and_sign_rules_are_explicit() throws {
        let s = try replay([0xd10083ff,0xd2800201,0x8b2143e2,0xcb2143ff]); XCTAssertEqual(s.sp, -48)
        XCTAssertEqual(s.registers[2], .array([.string("stack_address"),.integer(-16),.integer(64)]))
        XCTAssertEqual(try replay([0xd28000a0,0x12800001,0x8b21c400]).registers[0], constant(3))
    }
    func testUC26_extended_sp_offset_cannot_escape_unique_signed_arm64_coordinate_domain() {
        XCTAssertThrowsError(try replay([0xd2f00001,0xcb2163ff])) { XCTAssertEqual(($0 as? SwiftOutcomeValidatorStop)?.reason, "stack_offset_unqualified") }
    }
    func testUC26_raw_and_unscaled_word_memory_zero_extend_real_cells() throws {
        XCTAssertEqual(try replay([0xd10043ff,0x910003e9,0x12800000,0xb9000520,0xd2800000,0xb9400520]).registers[0], constant(0xffffffff))
        XCTAssertEqual(try replay([0xd10043ff,0x910043fd,0xd2824680,0xb81fc3a0,0xd2800000,0xb85fc3a0]).registers[0], constant(0x1234))
    }
    func testUC26_scalar_fp_stores_invalidate_overlaps_without_gpr_number_alias() throws {
        for store: UInt32 in [0xbd0003e0,0xfd0003e0] { XCTAssertNil(try replayBroad([0xd10043ff,0xf90003e0,store,0xf94003e0]).registers[0]) }
    }
    func testUC26_fp_load_destinations_are_not_integer_registers() throws {
        for load: UInt32 in [0xbd4003e0,0xfd4003e0] { XCTAssertEqual(try replayBroad([load]).registers[0], origin) }
    }
    func testUC26_known_sp_writeback_spill_and_reload_retire_the_cell() throws {
        let s = try replay([0xf81f0fe0,0xd2800000,0xf84107e0]); XCTAssertEqual(s.registers[0], origin); XCTAssertEqual(s.sp, 0); XCTAssertTrue(s.cells.isEmpty)
    }
    func testUC26_known_non_sp_writeback_updates_only_the_pointer() throws {
        let s = try replay([0xd10083ff,0x910043e9,0xf81f8d20,0xd2800000,0xf8408520]); XCTAssertEqual(s.registers[0], origin); XCTAssertEqual(s.sp, -32)
        XCTAssertEqual(s.registers[9], .array([.string("stack_address"),.integer(-16),.integer(64)]))
    }
}
#endif
