import XCTest
@testable import MacScope

// Source-only definitions. Expectations derive from supplied
// SPEC-RULES R1-R12 (paraphrase of a mirror, official Arm text not confirmed).
final class FPControlFieldSetTests: XCTestCase {
    private struct Case {
        let id: String
        let source: MacIRSourceSpan
        let expected: [MacIRVectorFP.ControlField]?
    }

    private func row(_ bytes: String, _ mnemonic: String, _ operands: String) -> MacIRSourceSpan {
        MacIRSourceSpan(address: 0x1000, byteText: bytes, mnemonic: mnemonic, operands: operands)
    }

    private var cases: [Case] {
        [
            // T01: R1 R2 R5 R7.
            Case(id: "T01", source: row("20 68 21 0e", "fcvtn", "v0.4h, v1.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision]),
            // T02: R1 R2 R5 R7.
            Case(id: "T02", source: row("20 68 21 4e", "fcvtn2", "v0.8h, v1.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision]),
            // T03: R1 R2 R5 R7.
            Case(id: "T03", source: row("a5 68 21 0e", "fcvtn", "v5.4h, v5.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision]),
            // T04: R1 R2 R5 R7.
            Case(id: "T04", source: row("a5 68 21 4e", "fcvtn2", "v5.8h, v5.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision]),
            // T05: R2 R9.
            Case(id: "T05", source: row("21 68 61 0e", "fcvtn", "v1.2s, v1.2d"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T06: R2 R9.
            Case(id: "T06", source: row("42 68 61 0e", "fcvtn", "v2.2s, v2.2d"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T07: R2 R9.
            Case(id: "T07", source: row("61 68 61 4e", "fcvtn2", "v1.4s, v3.2d"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T08: R2 R9.
            Case(id: "T08", source: row("02 68 61 4e", "fcvtn2", "v2.4s, v0.2d"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T09: R4 R10.
            Case(id: "T09", source: row("42 d4 20 4e", "fadd", "v2.4s, v2.4s, v0.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T10: R4 R10.
            Case(id: "T10", source: row("44 cc 21 4e", "fmla", "v4.4s, v2.4s, v1.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T11: R4 R10.
            Case(id: "T11", source: row("00 dc 63 6e", "fmul", "v0.2d, v0.2d, v3.2d"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding, .flushInputsToZero, .defaultNaN]),
            // T12: R4 R10; FE:414,423-424,486: instruction ZERO, no DN.
            Case(id: "T12", source: row("42 b8 a1 4e", "fcvtzs", "v2.4s, v2.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .flushInputsToZero]),
            // T13: R4 R10; FE:387-390,423-424: integer input, no FIZ/DN.
            Case(id: "T13", source: row("21 d8 21 4e", "scvtf", "v1.4s, v1.4s"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding]),
            // T14: R4 R10; FE:387-390,423-424: integer input, no FIZ/DN.
            Case(id: "T14", source: row("21 d8 61 6e", "ucvtf", "v1.2d, v1.2d"),
                 expected: [.flushToZero, .alternateHandling, .exceptionEnables, .rounding]),
            // T15: R6; FE:446-447,453 refuses half arithmetic.
            Case(id: "T15", source: row("20 14 42 4e", "fadd", "v0.8h, v1.8h, v2.8h"),
                 expected: nil),
            // T16: R6; FE:446-447,453 refuses half arithmetic.
            Case(id: "T16", source: row("20 1c 42 6e", "fmul", "v0.8h, v1.8h, v2.8h"),
                 expected: nil),
            // T17: R7; FE:441-445,453 refuses scalar destination.
            Case(id: "T17", source: row("20 c0 23 1e", "fcvt", "h0, s1"),
                 expected: nil),
            // T18: R8; FE:441-445,453 refuses scalar destination.
            Case(id: "T18", source: row("20 40 e2 1e", "fcvt", "s0, h1"),
                 expected: nil),
            // T19: R11; decoder spelling NOT CONFIRMED; first failing guard FE:453 shape parse, else FE:438-439.
            Case(id: "T19", source: row("a5 68 a1 0e", "bfcvtn", "v5.4h, v5.4s"),
                 expected: nil),
            // T20: R8; decoder spelling NOT CONFIRMED; first failing guard FE:454 source shape parse, else FE:438-439.
            Case(id: "T20", source: row("20 78 21 0e", "fcvtl", "v0.4s, v1.4h"),
                 expected: nil)
        ]
    }

    func testT01ThroughT20LiteralFieldSetsAndRefusals() throws {
        for entry in cases {
            if let expected = entry.expected {
                let fp = try XCTUnwrap(MacIRVectorFP(source: entry.source), entry.id)
                XCTAssertEqual(fp.controlFields, expected, entry.id)
            } else {
                XCTAssertNil(MacIRVectorFP(source: entry.source), entry.id)
            }
        }
    }

    func testT21AlternateHalfPrecisionExactlyForHalfNarrowResults() throws {
        // T21: R1 R7 R9; FE:488 supplies the result width for T01-T08.
        for entry in cases.prefix(8) {
            let fp = try XCTUnwrap(MacIRVectorFP(source: entry.source), entry.id)
            XCTAssertEqual(fp.controlFields.contains(.alternateHalfPrecision), fp.resultBits == 16, entry.id)
        }
    }

    func testT22AllAdmittedListsHaveNoDuplicates() throws {
        // T22: FE:421-425 appends distinct cases once, including the new last case.
        for entry in cases.prefix(14) {
            let fp = try XCTUnwrap(MacIRVectorFP(source: entry.source), entry.id)
            XCTAssertEqual(Set(fp.controlFields).count, fp.controlFields.count, entry.id)
        }
    }

    func testT23HalfListsPreserveTheDoubleNarrowPrefix() throws {
        // T23: R7 R9; FE:421-424 preserves F6, AHP is appended after it.
        let retained = try XCTUnwrap(cases[4].expected)
        for entry in cases.prefix(4) {
            let fp = try XCTUnwrap(MacIRVectorFP(source: entry.source), entry.id)
            XCTAssertEqual(Array(fp.controlFields.prefix(6)), retained, entry.id)
        }
    }
}
