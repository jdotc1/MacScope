import XCTest
@testable import MacScope

// Source-authored test definitions.
final class C2MachineFlowKillExposureTests: XCTestCase {
    private func rows(_ instructions: [(String, String)]) -> [MacIRSourceSpan] {
        instructions.enumerated().map { index, instruction in
            MacIRSourceSpan(address: UInt64(0x7800 + index * 4), byteText: "00 00 00 00",
                mnemonic: instruction.0, operands: instruction.1)
        }
    }

    func testSC1PairLoadKillsExposure() {
        XCTAssertNil(C2MachineFlow(rows: rows([("bl", "0x9000"), ("ldp", "q8, q9, [sp]"),
            ("str", "q8, [x0]"), ("ret", "")])).error)
    }

    func testSC2BranchAroundKillRemainsExposed() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"), ("cbnz", "x1, 0x780c"),
            ("ldp", "q8, q9, [sp]"), ("str", "q8, [x0]"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC3SecondCallReexposes() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"), ("ldp", "q8, q9, [sp]"),
            ("bl", "0x9000"), ("str", "q8, [x0]"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC4MoveIsNotAnAllowedKill() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"), ("mov", "v8.16b, v0.16b"),
            ("str", "q8, [x0]"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC5InsertReadsOldDestination() {
        let flow = C2MachineFlow(rows: rows([("bl", "0x9000"), ("ins", "v8.s[1], w0"),
            ("str", "q8, [x0]"), ("ret", "")]))
        XCTAssertEqual(flow.error, "call with v8-v15 use requires partial-register reaching definitions")
        XCTAssertTrue(flow.reads[1].contains("v8"))
    }

    func testSC6UnsignedLowHalfSource() {
        let flow = C2MachineFlow(rows: rows([("movi", "v8.4h, #0x80, lsl #8"), ("bl", "0x9000"),
            ("umull", "v18.4s, v3.4h, v8.4h"), ("ret", "")]))
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.reads[2], Set(["v3", "v8"]))
        XCTAssertEqual(flow.writes[2], Set(["v18"]))
        XCTAssertEqual(flow.before[2]["v8"], Set([UInt64(0x7800)]))
    }

    func testSC7UpperHalfMultiplyRemainsExposed() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("umull2", "v19.4s, v3.8h, v8.8h"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC8IndexedMultiplyRemainsExposed() {
        for lane in [1, 7] {
            XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"),
                ("umull", "v0.4s, v1.4h, v8.h[\(lane)]"), ("ret", "")])).error,
                "call with v8-v15 use requires partial-register reaching definitions")
        }
    }

    func testSC9SignedLowHalfBothSources() {
        XCTAssertNil(C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("smull", "v0.2d, v8.2s, v9.2s"), ("ret", "")])).error)
    }

    func testSC10GeneralPurposeMultiplyUnaffected() {
        XCTAssertNil(C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("umull", "x0, w1, w2"), ("ret", "")])).error)
    }

    func testSC11AccumulatorRemainsExposed() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("umlal", "v8.4s, v1.4h, v2.4h"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC12MismatchedArrangementRemainsExposed() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("umull", "v0.4s, v1.8h, v8.8h"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC13LowHalfReadDoesNotKillWholeRead() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("umull", "v0.4s, v1.4h, v8.4h"), ("str", "q8, [x0]"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC14OtherRegisterKillDoesNotHelp() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("bl", "0x9000"), ("ldp", "q12, q9, [sp]"),
            ("str", "q8, [x0]"), ("ret", "")])).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testSC15CompositeRequiresKillsAndLowHalfRead() {
        XCTAssertNil(C2MachineFlow(rows: rows([("movi", "v8.4h, #0x80, lsl #8"),
            ("movi", "v10.8h, #0x80, lsl #8"), ("bl", "0x9000"), ("ldp", "q12, q9, [sp]"),
            ("movi", "v10.8h, #0x80, lsl #8"), ("umull", "v18.4s, v3.4h, v8.4h"),
            ("umull2", "v19.4s, v3.8h, v10.8h"), ("umlsl", "v22.4s, v3.4h, v9.4h"),
            ("ret", "")])).error)
    }

    func testSC16DOnlyPermitUnchanged() {
        let source = rows([("bl", "0x9000"), ("str", "d8, [sp]"), ("ret", "")])
        XCTAssertEqual(C2MachineFlow(rows: source).error,
            "call with v8-v15 use requires partial-register reaching definitions")
        XCTAssertNil(C2MachineFlow(rows: source, permitDOnlyCallProjection: true).error)
    }

    func testSC17SystemRegisterGateUnchanged() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("sqxtun", "v0.8b, v1.8h"), ("bl", "0x9000")])).error,
            "call with floating-point system-register use requires bit-level ABI preservation")
    }

    func testSC18ORRImmediateReadsOldDestination() {
        for operands in ["v8.4h, #1", "v8.4h, #1, lsl #0", "v8.4h, #1, lsl #8",
                         "v8.8h, #1", "v8.8h, #1, lsl #0", "v8.8h, #1, lsl #8",
                         "v8.2s, #1", "v8.2s, #1, lsl #0", "v8.2s, #1, lsl #8",
                         "v8.2s, #1, lsl #16", "v8.2s, #1, lsl #24",
                         "v8.4s, #1", "v8.4s, #1, lsl #0", "v8.4s, #1, lsl #8",
                         "v8.4s, #1, lsl #16", "v8.4s, #1, lsl #24"] {
            let flow = C2MachineFlow(rows: rows([("bl", "0x9000"), ("orr", operands), ("ret", "")]))
            XCTAssertTrue(flow.reads[1].contains("v8"), operands)
            XCTAssertEqual(flow.writes[1], Set(["v8"]), operands)
            XCTAssertEqual(flow.error, "call with v8-v15 use requires partial-register reaching definitions", operands)
        }
    }

    func testSC19BICImmediateReadsOldDestinationAtPin() {
        // Extends the BIC-immediate destination-read check to the 4H/8H/2S/LSL forms.
        for operands in ["v8.4h, #1", "v8.4h, #1, lsl #0", "v8.4h, #1, lsl #8",
                         "v8.8h, #1", "v8.8h, #1, lsl #0", "v8.8h, #1, lsl #8",
                         "v8.2s, #1", "v8.2s, #1, lsl #0", "v8.2s, #1, lsl #8",
                         "v8.2s, #1, lsl #16", "v8.2s, #1, lsl #24",
                         "v8.4s, #1", "v8.4s, #1, lsl #0", "v8.4s, #1, lsl #8",
                         "v8.4s, #1, lsl #16", "v8.4s, #1, lsl #24"] {
            let flow = C2MachineFlow(rows: rows([("bl", "0x9000"), ("bic", operands), ("ret", "")]))
            XCTAssertTrue(flow.reads[1].contains("v8"), operands)
            XCTAssertEqual(flow.writes[1], Set(["v8"]), operands)
            XCTAssertEqual(flow.error, "call with v8-v15 use requires partial-register reaching definitions", operands)
        }
    }

    func testSC26OverlappingPairLoadCannotGuaranteeExposureKill() {
        for operands in ["s8, s8, [x0]", "d8, d8, [x0]", "q8, q8, [x0]",
                         "s8, s8, [x0], #0", "d8, d8, [x0], #0", "q8, q8, [x0], #0",
                         "s8, s8, [x0, #0]!", "d8, d8, [x0, #0]!", "q8, q8, [x0, #0]!"] {
            let flow = C2MachineFlow(rows: rows([("bl", "0x9000"), ("ldp", operands),
                ("str", "q8, [x1]"), ("ret", "")]))
            XCTAssertEqual(flow.error, "call with v8-v15 use requires partial-register reaching definitions", operands)
        }
    }

    func testSC27OverlappingNonTemporalLoadRetainsPossibleEntryDefinition() {
        for operands in ["s8, s8, [x0]", "d8, d8, [x0]", "q8, q8, [x0]"] {
            let flow = C2MachineFlow(rows: rows([("ldnp", operands), ("str", "q8, [x1]"), ("ret", "")]))
            XCTAssertTrue(flow.before[1]["v8"]?.contains(UInt64(0)) == true, operands)
            XCTAssertTrue(flow.before[1]["v8"]?.contains(0x7800) == true, operands)
        }
    }

    func testOverlappingPairLoadReachesBothEntryAndOwnDefinition() {
        for operands in ["s8, s8, [x0]", "d8, d8, [x0]", "q8, q8, [x0]"] {
            let flow = C2MachineFlow(rows: rows([("ldp", operands), ("str", "q8, [x1]"), ("ret", "")]))
            XCTAssertTrue(flow.before[1]["v8"]?.contains(UInt64(0)) == true, operands)
            XCTAssertTrue(flow.before[1]["v8"]?.contains(0x7800) == true, operands)
        }
    }

    func testSC28OverlappingSingleLoadsRetainPossibleEntryDefinition() {
        // Arm LDR/B/H/SB/SH/SW writeback overlap permits NOP, so x5 is not definitely defined.
        for (mnemonic, destination, stride) in [
            ("ldr", "x5", 8), ("ldr", "w5", 4), ("ldrb", "w5", 1),
            ("ldrh", "w5", 2), ("ldrsb", "x5", 1), ("ldrsb", "w5", 1),
            ("ldrsh", "x5", 2), ("ldrsh", "w5", 2), ("ldrsw", "x5", 4)
        ] {
            for operands in ["\(destination), [x5], #\(stride)",
                             "\(destination), [x5, #\(stride)]!"] {
                let flow = C2MachineFlow(rows: rows([(mnemonic, operands),
                    ("str", "x5, [x10]"), ("ret", "")]))
                XCTAssertNil(flow.error, "\(mnemonic) \(operands)")
                XCTAssertTrue(flow.before[1]["x5"]?.contains(UInt64(0)) == true,
                              "\(mnemonic) \(operands)")
            }
        }
    }

    func testSC29OverlappingSingleStoresRetainPossibleBaseDefinition() {
        // Arm STR/B/H writeback overlap permits NOP, so the base update is not guaranteed.
        for (mnemonic, source, stride) in [
            ("str", "x5", 8), ("str", "w5", 4), ("strb", "w5", 1), ("strh", "w5", 2)
        ] {
            for operands in ["\(source), [x5], #\(stride)",
                             "\(source), [x5, #\(stride)]!"] {
                let flow = C2MachineFlow(rows: rows([(mnemonic, operands),
                    ("str", "x5, [x10]"), ("ret", "")]))
                XCTAssertNil(flow.error, "\(mnemonic) \(operands)")
                XCTAssertTrue(flow.before[1]["x5"]?.contains(UInt64(0)) == true,
                              "\(mnemonic) \(operands)")
            }
        }
    }

    func testSC30PairLoadWritebackOverlapRetainsPossibleDefinitions() {
        // Arm LDP base overlap permits NOP even with distinct destinations; neither write is definite.
        for operands in ["x5, x6, [x5], #16", "x5, x6, [x5, #16]!",
                         "x6, x5, [x5], #16", "x6, x5, [x5, #16]!",
                         "w5, w6, [x5], #8", "w5, w6, [x5, #8]!",
                         "w6, w5, [x5], #8", "w6, w5, [x5, #8]!"] {
            let flow = C2MachineFlow(rows: rows([("ldp", operands),
                ("stp", "x5, x6, [x10]"), ("ret", "")]))
            XCTAssertNil(flow.error, operands)
            XCTAssertTrue(flow.before[1]["x5"]?.contains(UInt64(0)) == true, operands)
            XCTAssertTrue(flow.before[1]["x6"]?.contains(UInt64(0)) == true, operands)
        }
    }

    func testSC31LDPSWOverlapRetainsPossibleEntryDefinition() {
        // Arm LDPSW permits NOP for duplicate destinations or a writeback/base overlap.
        for operands in ["x5, x5, [x9]", "x5, x5, [x9], #8", "x5, x5, [x9, #8]!",
                         "x5, x6, [x5], #8", "x5, x6, [x5, #8]!",
                         "x6, x5, [x5], #8", "x6, x5, [x5, #8]!"] {
            let flow = C2MachineFlow(rows: rows([("ldpsw", operands),
                ("str", "x5, [x10]"), ("ret", "")]))
            XCTAssertNil(flow.error, operands)
            XCTAssertTrue(flow.before[1]["x5"]?.contains(UInt64(0)) == true, operands)
        }
    }

    func testSC32PairStoreWritebackOverlapRetainsPossibleBaseDefinition() {
        // Arm STP writeback/base overlap permits NOP, so the base definition can survive.
        for operands in ["x5, x6, [x5], #16", "x5, x6, [x5, #16]!",
                         "x6, x5, [x5], #16", "x6, x5, [x5, #16]!",
                         "w5, w6, [x5], #8", "w5, w6, [x5, #8]!",
                         "w6, w5, [x5], #8", "w6, w5, [x5, #8]!"] {
            let flow = C2MachineFlow(rows: rows([("stp", operands),
                ("str", "x5, [x10]"), ("ret", "")]))
            XCTAssertNil(flow.error, operands)
            XCTAssertTrue(flow.before[1]["x5"]?.contains(UInt64(0)) == true, operands)
        }
    }

    func testSC33STLRPreindexOverlapRetainsPossibleBaseDefinition() {
        // Arm FEAT_LRCPC3 STLR pre-index overlap permits NOP, not a guaranteed base write.
        for operands in ["x5, [x5, #-8]!", "w5, [x5, #-4]!"] {
            let flow = C2MachineFlow(rows: rows([("stlr", operands),
                ("str", "x5, [x10]"), ("ret", "")]))
            XCTAssertNil(flow.error, operands)
            XCTAssertTrue(flow.before[1]["x5"]?.contains(UInt64(0)) == true, operands)
        }
    }

    func testSC34NonSaturatingOperationsRetainPossibleFPSRDefinition() {
        // Arm SQXTUN/2, SQSHRN2 and SQSHLU leave FPSR untouched when no element saturates.
        for instruction in [("sqxtun", "v0.8b, v1.8h"),
                            ("sqxtun2", "v0.16b, v1.8h"),
                            ("sqshrn2", "v0.16b, v1.8h, #1"),
                            ("sqshlu", "v0.8h, v1.8h, #0")] {
            let flow = C2MachineFlow(rows: rows([instruction,
                ("sqxtun", "v2.8b, v3.8h"), ("ret", "")]))
            XCTAssertNil(flow.error, instruction.0)
            XCTAssertTrue(flow.before[1]["fpsr"]?.contains(UInt64(0)) == true, instruction.0)
        }
    }

    func testSC35PAuthHintsRetainPossibleLinkRegisterDefinition() {
        // Arm PAC/AUT SP hints and XPACLRI are NOPs without FEAT_PAuth; x30 can remain unchanged.
        for mnemonic in ["paciasp", "pacibsp", "autiasp", "autibsp", "xpaclri"] {
            let flow = C2MachineFlow(rows: rows([(mnemonic, ""), ("ret", "")]))
            XCTAssertNil(flow.error, mnemonic)
            XCTAssertTrue(flow.before[1]["x30"]?.contains(UInt64(0)) == true, mnemonic)
        }
    }

    func testSC36PAuthLRAuthenticationIncludesSecondModifierRead() {
        // Arm AUTIASP/AUTIBSP with FEAT_PAuth_LR and PACM=1 read x16 as the second modifier.
        for mnemonic in ["autiasp", "autibsp"] {
            let flow = C2MachineFlow(rows: rows([(mnemonic, ""), ("ret", "")]))
            XCTAssertNil(flow.error, mnemonic)
            XCTAssertTrue(flow.reads[0].contains("x16"), mnemonic)
        }
    }
}
