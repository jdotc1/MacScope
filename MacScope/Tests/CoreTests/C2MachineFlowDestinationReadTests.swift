import XCTest
@testable import MacScope

final class C2MachineFlowDestinationReadTests: XCTestCase {
    private func rows(_ instructions: [(String, String, String)]) -> [MacIRSourceSpan] {
        instructions.enumerated().map { index, instruction in
            MacIRSourceSpan(address: UInt64(0x7800 + index * 4), byteText: instruction.0,
                mnemonic: instruction.1, operands: instruction.2)
        }
    }

    private func check(_ bytes: String, _ mnemonic: String, _ operands: String,
                       reads: Set<String>, writes: Set<String>,
                       file: StaticString = #filePath, line: UInt = #line) {
        let flow = C2MachineFlow(rows: rows([(bytes, mnemonic, operands)]))
        XCTAssertNil(flow.error, file: file, line: line)
        XCTAssertEqual(flow.reads[0], reads, file: file, line: line)
        XCTAssertEqual(flow.writes[0], writes, file: file, line: line)
    }

    func testB1EightHalfwordImmediateReadsDestination() {
        check("e5 b7 07 6f", "bic", "v5.8h, #0xff, lsl #8", reads: ["v5"], writes: ["v5"])
        check("e5 97 07 6f", "bic", "v5.8h, #0xff", reads: ["v5"], writes: ["v5"])
    }

    func testB2FourWordImmediateReadsDestination() {
        check("d7 37 07 6f", "bic", "v23.4s, #0xfe, lsl #8", reads: ["v23"], writes: ["v23"])
    }

    func testB3FourHalfwordImmediateReadsDestination() {
        check("e5 b7 07 2f", "bic", "v5.4h, #0xff, lsl #8", reads: ["v5"], writes: ["v5"])
        check("e5 97 07 2f", "bic", "v5.4h, #0xff", reads: ["v5"], writes: ["v5"])
    }

    func testB4TwoWordImmediateReadsDestination() {
        check("c2 37 07 2f", "bic", "v2.2s, #0xfe, lsl #8", reads: ["v2"], writes: ["v2"])
        check("22 14 00 2f", "bic", "v2.2s, #1", reads: ["v2"], writes: ["v2"])
        check("22 54 00 2f", "bic", "v2.2s, #1, lsl #16", reads: ["v2"], writes: ["v2"])
        check("22 74 00 2f", "bic", "v2.2s, #1, lsl #24", reads: ["v2"], writes: ["v2"])
    }

    func testB5TwoOperandImmediateReadsDestination() {
        check("24 14 00 6f", "bic", "v4.4s, #0x1", reads: ["v4"], writes: ["v4"])
    }

    func testB6HigherWordShiftsReadDestination() {
        check("24 54 00 6f", "bic", "v4.4s, #0x1, lsl #16", reads: ["v4"], writes: ["v4"])
        check("24 74 00 6f", "bic", "v4.4s, #0x1, lsl #24", reads: ["v4"], writes: ["v4"])
    }

    func testB7ImmediateAfterCallRemainsExposedWithDOnlyPermit() {
        let source = rows([("00 06 00 94", "bl", "0x9000"),
            ("28 14 00 6f", "bic", "v8.4s, #0x1"), ("c0 03 5f d6", "ret", "")])
        for permit in [false, true] {
            let flow = C2MachineFlow(rows: source, permitDOnlyCallProjection: permit)
            XCTAssertEqual(flow.reads[1], ["v8"])
            XCTAssertEqual(flow.writes[1], ["v8"])
            XCTAssertEqual(flow.error, "call with v8-v15 use requires partial-register reaching definitions")
        }
    }

    func testN1VectorRegisterFormDoesNotReadDestination() {
        check("20 1c 62 4e", "bic", "v0.16b, v1.16b, v2.16b", reads: ["v1", "v2"], writes: ["v0"])
    }

    func testN2ScalarRegisterFormsDoNotReadDestination() {
        check("20 00 22 8a", "bic", "x0, x1, x2", reads: ["x1", "x2"], writes: ["x0"])
        check("20 0c 22 8a", "bic", "x0, x1, x2, lsl #3", reads: ["x1", "x2"], writes: ["x0"])
    }

    func testN3FlagSettingFormDoesNotReadDestination() {
        check("20 00 22 6a", "bics", "w0, w1, w2", reads: ["x1", "x2"], writes: ["x0", "nzcv"])
    }

    func testN4ImmediateMovesDoNotReadDestination() {
        check("00 04 00 4f", "movi", "v0.4s, #0", reads: [], writes: ["v0"])
        check("20 04 00 6f", "mvni", "v0.4s, #1", reads: [], writes: ["v0"])
    }

    func testORRFourHalfwordImmediateShiftClasses() {
        // ORR 4H: reverting the mnemonic widening removes the destination read.
        check("25 94 00 0f", "orr", "v5.4h, #1", reads: ["v5"], writes: ["v5"])
        check("25 94 00 0f", "orr", "v5.4h, #1, lsl #0", reads: ["v5"], writes: ["v5"])
        check("25 b4 00 0f", "orr", "v5.4h, #1, lsl #8", reads: ["v5"], writes: ["v5"])
    }

    func testORREightHalfwordImmediateShiftClasses() {
        // ORR 8H: reverting the mnemonic widening removes the destination read.
        check("25 94 00 4f", "orr", "v5.8h, #1", reads: ["v5"], writes: ["v5"])
        check("25 94 00 4f", "orr", "v5.8h, #1, lsl #0", reads: ["v5"], writes: ["v5"])
        check("e5 b7 07 4f", "orr", "v5.8h, #0xff, lsl #8", reads: ["v5"], writes: ["v5"])
    }

    func testORRTwoWordImmediateShiftClasses() {
        // ORR 2S: reverting the mnemonic widening removes the destination read.
        check("25 14 00 0f", "orr", "v5.2s, #1", reads: ["v5"], writes: ["v5"])
        check("25 14 00 0f", "orr", "v5.2s, #1, lsl #0", reads: ["v5"], writes: ["v5"])
        check("25 34 00 0f", "orr", "v5.2s, #1, lsl #8", reads: ["v5"], writes: ["v5"])
        check("25 54 00 0f", "orr", "v5.2s, #1, lsl #16", reads: ["v5"], writes: ["v5"])
        check("25 74 00 0f", "orr", "v5.2s, #1, lsl #24", reads: ["v5"], writes: ["v5"])
    }

    func testORRFourWordImmediateShiftClasses() {
        // ORR 4S: reverting the mnemonic widening removes the destination read.
        check("25 14 00 4f", "orr", "v5.4s, #1", reads: ["v5"], writes: ["v5"])
        check("25 14 00 4f", "orr", "v5.4s, #1, lsl #0", reads: ["v5"], writes: ["v5"])
        check("25 34 00 4f", "orr", "v5.4s, #1, lsl #8", reads: ["v5"], writes: ["v5"])
        check("25 54 00 4f", "orr", "v5.4s, #1, lsl #16", reads: ["v5"], writes: ["v5"])
        check("25 74 00 4f", "orr", "v5.4s, #1, lsl #24", reads: ["v5"], writes: ["v5"])
        check("24 14 00 4f", "orr", "v4.4s, #0x1", reads: ["v4"], writes: ["v4"])
    }

    func testORRAfterCallRemainsExposedWithEitherPermit() {
        // ORR v8 after BL: reverting the fix loses the read and its call-exposure refusal.
        let source = rows([("00 06 00 94", "bl", "0x9000"),
            ("28 14 00 4f", "orr", "v8.4s, #0x1"), ("c0 03 5f d6", "ret", "")])
        for permit in [false, true] {
            let flow = C2MachineFlow(rows: source, permitDOnlyCallProjection: permit)
            XCTAssertEqual(flow.reads[1], ["v8"])
            XCTAssertEqual(flow.writes[1], ["v8"])
            XCTAssertEqual(flow.error, "call with v8-v15 use requires partial-register reaching definitions")
        }
    }

    func testBICAndORRCanonicalBoundariesAndUppercase() {
        // G5/G6 positive boundaries: the existing BIC path stays valid and ORR needs G1 widened.
        check("20 94 00 2f", "BIC", "V0.4H, #1, LSL #0", reads: ["v0"], writes: ["v0"])
        check("3f 94 00 6f", "BIC", "V31.8H, #1, LSL #0", reads: ["v31"], writes: ["v31"])
        check("20 14 00 2f", "BIC", "V0.2S, #1, LSL #0", reads: ["v0"], writes: ["v0"])
        check("3f 14 00 6f", "BIC", "V31.4S, #1, LSL #0", reads: ["v31"], writes: ["v31"])
        check("20 94 00 0f", "ORR", "V0.4H, #1, LSL #0", reads: ["v0"], writes: ["v0"])
        check("3f 94 00 4f", "ORR", "V31.8H, #1, LSL #0", reads: ["v31"], writes: ["v31"])
        check("20 14 00 0f", "ORR", "V0.2S, #1, LSL #0", reads: ["v0"], writes: ["v0"])
        check("3f 14 00 4f", "ORR", "V31.4S, #1, LSL #0", reads: ["v31"], writes: ["v31"])
    }

    func testG1RejectsOtherMnemonicsWithOtherwiseMatchingShape() {
        // G1 only: removing it would incorrectly add v5 for each otherwise matching shape.
        for mnemonic in ["movi", "mvni", "fmov"] {
            check("00 00 00 00", mnemonic, "v5.4s, #1", reads: [], writes: ["v5"])
        }
        check("00 00 00 00", "bics", "v5.4s, #1", reads: [], writes: ["v5", "nzcv"])
    }

    func testG2BICAndORRRejectFourOperandsOnly() {
        // G2 only: removing the count guard would add v5; G1 and G3-G6 all match.
        for mnemonic in ["bic", "orr"] {
            check("00 00 00 00", mnemonic, "v5.8h, #1, lsl #0, #0", reads: [], writes: ["v5"])
        }
    }

    func testG3BICAndORRRequireImmediatePrefixOnly() {
        // G3 only: removing the prefix guard would add v5; every other guard matches.
        for mnemonic in ["bic", "orr"] {
            check("00 00 00 00", mnemonic, "v5.8h, 1", reads: [], writes: ["v5"])
        }
    }

    func testG4BICAndORRRejectExtraDotComponentOnly() {
        // G4 only: removing the split-count guard would add v5; the first two pieces match G5/G6.
        for mnemonic in ["bic", "orr"] {
            check("00 00 00 00", mnemonic, "v5.8h.extra, #1", reads: [], writes: ["v5"])
        }
    }

    func testG5BICAndORRRequireCanonicalRegisterRoundTripOnly() {
        // G5 round-trip only: canonicalRegister maps v05 to v5, exposing a removed round-trip guard.
        for mnemonic in ["bic", "orr"] {
            check("00 00 00 00", mnemonic, "v05.8h, #1", reads: [], writes: ["v5"])
        }
    }

    func testG6BICAndORRRejectExcludedArrangementsOnly() {
        // G6 only: removing the arrangement guard would add v5 for each excluded arrangement.
        for mnemonic in ["bic", "orr"] {
            for arrangement in ["16b", "8b", "2d", "1d"] {
                check("00 00 00 00", mnemonic, "v5.\(arrangement), #1", reads: [], writes: ["v5"])
            }
        }
    }

    func testORRVectorAndScalarRegisterNeighbors() {
        // Valid register neighbors: broadening ORR without the shape guards would add x0 or v0.
        check("20 1c a2 4e", "orr", "v0.16b, v1.16b, v2.16b", reads: ["v1", "v2"], writes: ["v0"])
        check("20 00 02 aa", "orr", "x0, x1, x2", reads: ["x1", "x2"], writes: ["x0"])
        check("20 0c 02 aa", "orr", "x0, x1, x2, lsl #3", reads: ["x1", "x2"], writes: ["x0"])
    }

    func testORRScalarLogicalImmediateNeighbor() {
        // Scalar logical immediate: dropping vector-shape restrictions would incorrectly add x0.
        check("20 00 40 b2", "orr", "x0, x1, #1", reads: ["x1"], writes: ["x0"])
    }

    func testFMOVVectorImmediateNeighbor() {
        // FMOV immediate: admitting its mnemonic would incorrectly add v0.
        check("00 f6 03 4f", "fmov", "v0.4s, #1.0", reads: [], writes: ["v0"])
    }

    func testBICAndORRStillRefuseIndexedDestinations() {
        // Partial-destination boundary: the earlier refusal must remain ahead of the helper.
        for mnemonic in ["bic", "orr"] {
            let flow = C2MachineFlow(rows: rows([("00 00 00 00", mnemonic, "v5.h[0], #1")]))
            XCTAssertEqual(flow.error, "0x7800: partial vector destination")
            XCTAssertEqual(flow.reads[0], [])
            XCTAssertEqual(flow.writes[0], [])
        }
    }
}
