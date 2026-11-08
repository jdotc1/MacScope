import Foundation
import XCTest
@testable import MacScope

final class ScalarLogicalGeneralVectorRegionTests: XCTestCase {
    // PS rows: make35720:209; encode95772:174/252/355;
    // ifast255620:63/92/129; huff330724:296/317/1274; refine334456:618.
    // VG:633-639 previously required a NEON descriptor for these scalar rows.
    // Expected text uses the existing MB:1125-1131,1193-1197,1376-1388 lowering.
    func testEvidencedThreeOperandShapesUseScalarProducers() throws {
        let cases: [(String, String, String)] = [
            ("and", "w21, w22, w21", " & "),
            ("and", "x10, x9, x10", " & "),
            ("orr", "w1, w17, w0", " | "),
            ("orr", "x28, x9, x8", " | "),
            ("bic", "x10, x19, x10", " & "),
            ("and", "w8, w23, #0xff", " & "),
            ("and", "w9, w9, #7", " & "),
            ("and", "w1, w0, #0xffff", " & "),
            ("and", "w7, w7, #0xffff0000", " & "),
            ("eor", "w9, w9, #0x3f", " ^ ")
        ]
        for (mnemonic, operands, expectedText) in cases {
            try checkScalar(mnemonic, operands, expectedText: expectedText,
                            complement: mnemonic == "bic", shiftText: nil)
        }
    }

    // PS finish300732:590/661/740 and start315836:341.
    // MB:3127-3144 and3152-3194 model these exact shifts before the core switch.
    // Expected lifted text keeps ORR's << and BIC's ~(signed >>31).
    func testEvidencedShiftedShapesUseScalarProducers() throws {
        try checkScalar("orr", "w21, w10, w3, lsl #3",
                        expectedText: " | ", complement: false, shiftText: " << ")
        try checkScalar("orr", "w27, w11, w24, lsl #2",
                        expectedText: " | ", complement: false, shiftText: " << ")
        try checkScalar("bic", "w8, w8, w8, asr #31",
                        expectedText: " & ", complement: true, shiftText: " >> ")
    }

    // Structural expansion delegates to MB:1125-1131,1193-1206,
    // 1376-1388 and3127-3194 rather than matching census literals.
    func testStructuralMasksShiftsAndComplementMnemonics() throws {
        try checkScalar("and", "w0, w1, #0xf0",
                        expectedText: " & ", complement: false, shiftText: nil)
        try checkScalar("orr", "x0, x1, x2, lsr #7",
                        expectedText: " | ", complement: false, shiftText: " >> ")
        try checkScalar("orn", "x0, x1, x2",
                        expectedText: " | ", complement: true, shiftText: nil)
        try checkScalar("eon", "w0, w1, w2",
                        expectedText: " ^ ", complement: true, shiftText: nil)
        try checkScalar("eor", "x8, x9, x10",
                        expectedText: " ^ ", complement: false, shiftText: nil)
        try checkScalar("bic", "w8, w9, w10",
                        expectedText: " & ", complement: true, shiftText: nil)
        try checkScalar("eor", "w0, w1, w2, ror #11",
                        expectedText: " ^ ", complement: false, shiftText: " >> ")
        try checkScalar("and", "w0, w1, wzr",
                        expectedText: " & ", complement: false, shiftText: nil)
    }

    // ROR's out-of-range amount is refused by MB:3184-3185. The
    // structural gate accepts its spelling; VG:655-687 must restore state.
    func testScalarDefaultRefusalRollsBackBeforeGeneralRefusal() throws {
        let operands = "x0, x1, x2, ror #64"
        XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(
            mnemonic: "orr", operands: operands))
        let function = build("orr", operands, consumer: "x0")
        let refused = try XCTUnwrap(function.instructions.first { $0.source.address == 0x100c })
        guard case let .unknown(destination, _, mnemonic, originalOperands) = refused.operation else {
            return XCTFail("Unsupported scalar form must become a conservative refusal")
        }
        XCTAssertNil(destination, "The tentative core unknown's destination must not survive rollback")
        XCTAssertEqual(mnemonic, "orr")
        XCTAssertEqual(originalOperands, operands)
        let following = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1010 })
        guard case let .assign(_, value) = following.operation else {
            return XCTFail("Expected the same-width following read")
        }
        XCTAssertEqual(value, .unknown("unavailable_x0"))
        let text = PseudocodePrinter().render(operation: refused.operation,
                                               names: PseudocodeNameContext(function: function))
        XCTAssertTrue(text.hasPrefix("__unknown("))
    }

    // VG:633-641 and VL:12-24 retain real vector logical descriptors.
    // VL:173-216 retains vector BIC immediates before the logical switch.
    func testGenuineVectorLogicalAndBICImmediateKeepTypedRoutes() throws {
        let logical = build("orr", "v8.16b, v4.16b, v4.16b", consumer: "x19")
        let vector = try XCTUnwrap(logical.instructions.first { $0.source.address == 0x100c })
        XCTAssertNotNil(vector.neonLogical)
        XCTAssertFalse(MacIRBuilder.isScalarRegionLogical(
            mnemonic: "orr", operands: "v8.16b, v4.16b, v4.16b"))
        let immediate = build("bic", "v12.4s, #0xfe, lsl #8", consumer: "x19")
        let effects = immediate.instructions.filter { $0.source.address == 0x100c }
        XCTAssertEqual(effects.filter { $0.neonImmediate != nil }.count, 1)
        XCTAssertEqual(effects.filter { $0.neonLogical != nil }.count, 1)
    }

    // RE:1097-1112 identifies first-operand read families; VG:1180-1181
    // must still print their refused form without an invented destination.
    func testReadFirstStoreRemainsBareAndKeepsItsInput() throws {
        let function = build("st64b", "x19, [x20]", consumer: "x20")
        let refused = try XCTUnwrap(function.instructions.first { $0.source.address == 0x100c })
        guard case let .unknown(destination, inputs, _, _) = refused.operation else {
            return XCTFail("Unsupported read-first store must remain an unknown")
        }
        XCTAssertNil(destination)
        XCTAssertTrue(inputs.mayRead.contains { $0.register == "x19" })
        let text = PseudocodePrinter().render(operation: refused.operation,
                                               names: PseudocodeNameContext(function: function))
        XCTAssertTrue(text.hasPrefix("__unknown("))
        XCTAssertFalse(MacIRBuilder.isScalarRegionLogical(
            mnemonic: "st64b", operands: "x19, [x20]"))
    }

    // Structural routing must reject vectors, mismatched widths and malformed
    // syntax. MB:3173-3194 leaves non-ROR shift bounds unchecked.
    func testBoundaryShapesRemainExcluded() throws {
        for (mnemonic, operands) in [
            ("orr", "x8, v4.16b, x9"), ("orr", "w8, x9, w10"),
            ("and", "w31, w9, w10"), ("and", "sp, x9, x10"),
            ("and", "wzr, w9, w10"), ("orr", "x8, xzr, x9"),
            ("and", "w8, w9, w10, lsl #32"), ("orr", "x8, x9, x10, lsr #64"),
            ("bic", "w8, w9, w10, asr #-1"), ("and", "w8, w9, #"),
            ("and", "w8, w9, #v1"), ("orr", "x8, x9, x10, lsr"),
            ("and", "w8, w9, w10,"),
            ("and", "w8,,w9,w10")
        ] {
            XCTAssertFalse(MacIRBuilder.isScalarRegionLogical(
                mnemonic: mnemonic, operands: operands), operands)
        }
        let mixed = build("orr", "x8, v4.16b, x9", consumer: "x19")
        let row = try XCTUnwrap(mixed.instructions.first { $0.source.address == 0x100c })
        guard case let .unknown(destination, _, _, _) = row.operation else {
            return XCTFail("A mixed vector row must not become scalar arithmetic")
        }
        XCTAssertNil(destination)

        let unsafeShift = build("and", "w8, w9, w10, lsl #32", consumer: "w8")
        let unsafeRow = try XCTUnwrap(unsafeShift.instructions.first { $0.source.address == 0x100c })
        guard case let .unknown(unsafeDestination, _, _, _) = unsafeRow.operation else {
            return XCTFail("Unchecked out-of-range LSL must not reach scalar arithmetic")
        }
        XCTAssertNil(unsafeDestination)
    }

    // Encode95772 PS:252 has an unavailable x19 input. A real destination
    // must not erase that uncertainty from the producer's operand (CE:1404).
    func testScalarDestinationDoesNotInventAnAvailableInput() {
        var state = BuilderState()
        state.recordUnmodeledDefiniteWrite(for: "x19")
        let source = MacIRSourceSpan(address: 0x1000, byteText: "", mnemonic: "bic",
                                    operands: "x10, x19, x10", comment: nil)
        XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(
            mnemonic: source.mnemonic, operands: source.operands))
        let operation = MacIRBuilder().operationForVectorRegion(for: source, state: &state)
        guard case let .binary(destination, "&", left, _) = operation else {
            return XCTFail("Scalar BIC must have an actual result")
        }
        XCTAssertEqual(left, .unknown("unavailable_x19"))
        XCTAssertEqual(state.readRegister("x10"), destination)
    }

    func testUnparsedLogicalLiteralsAreWholeRowRefusals() throws {
        for (mnemonic, operands) in [
            ("eor", "x0, x1, #0x8000000000000000"),
            ("eor", "x0, x1, #0xaaaaaaaaaaaaaaaa"),
            ("orr", "x0, x1, #0x8000000000000000"),
            ("eor", "x0, x1, #+0x8"),
            ("and", "x0, x1, #+0x8"),
            ("orr", "x0, x1, #0X8"),
            ("and", "x0, x1, #0X8"),
            ("eor", "x0, x1, #0x10000000000000000"),
            ("and", "x0, x1, #0x10000000000000000"),
            ("eon", "x0, x1, #9223372036854775808")
        ] {
            try checkRejectedScalarRow(mnemonic, operands)
        }
    }

    func testANDTopBitMasksUseExactRegisterImmediateParser() {
        let cases: [(String, Int64)] = [
            ("x0, x1, #0x8000000000000000", Int64.min),
            ("x0, x1, #0xaaaaaaaaaaaaaaaa", Int64(bitPattern: 0xaaaa_aaaa_aaaa_aaaa))
        ]
        for (operands, expected) in cases {
            XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(mnemonic: "and", operands: operands))
            var state = BuilderState()
            let expectedLeft = state.readRegister("x1")
            let source = MacIRSourceSpan(address: 0x100c, byteText: "", mnemonic: "and",
                                         operands: operands, comment: nil)
            let operation = MacIRBuilder().operationForVectorRegion(for: source, state: &state)
            guard case let .binary(destination, "&", left, right) = operation else {
                XCTFail("AND must preserve an exactly parsed mask")
                continue
            }
            XCTAssertEqual(destination, state.readRegister("x0"), operands)
            XCTAssertEqual(left, expectedLeft, operands)
            XCTAssertEqual(right, .immediate(expected))
        }
    }

    func testMixedShiftWhitespaceIsRefusedAtBothBoundaries() throws {
        try checkRejectedScalarRow("orr", "x0, x1, x2, lsl \t #3")
        try checkRejectedScalarRow("orr", "x0, x1, x2, lsl\t#3")
    }

    func testSpaceDelimitedShiftPreservesItsExactAmount() {
        let operands = "x0, x1, x2, lsl #3"
        XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(mnemonic: "orr", operands: operands))
        var state = BuilderState()
        let expectedLeft = state.readRegister("x1")
        let expectedBase = state.readRegister("x2")
        let source = MacIRSourceSpan(address: 0x100c, byteText: "", mnemonic: "orr",
                                     operands: operands, comment: nil)
        let operation = MacIRBuilder().operationForVectorRegion(for: source, state: &state)
        guard case let .binary(destination, "|", left, right) = operation else {
            return XCTFail("Expected a shifted scalar ORR")
        }
        XCTAssertEqual(destination, state.readRegister("x0"), operands)
        XCTAssertEqual(left, expectedLeft, operands)
        XCTAssertEqual(right, .binaryExpression(op: "<<",
            left: .unary(op: "(uint64_t)", value: expectedBase), right: .immediate(3)))
    }

    func testCompatibleSignedAndPlusDecimalLiteralsStayExact() {
        let cases: [(String, String, Int64)] = [
            ("and", "x0, x1, #-0x10", -16),
            ("eor", "x0, x1, #-0x10", -16),
            ("eor", "x0, x1, #+8", 8),
            ("orr", "x0, x1, #8", 8)
        ]
        for (mnemonic, operands, expected) in cases {
            XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(mnemonic: mnemonic, operands: operands))
            var state = BuilderState()
            let expectedLeft = state.readRegister("x1")
            XCTAssertNotEqual(expectedLeft, .immediate(0), "\(mnemonic) \(operands)")
            let source = MacIRSourceSpan(address: 0x100c, byteText: "", mnemonic: mnemonic,
                                         operands: operands, comment: nil)
            let operation = MacIRBuilder().operationForVectorRegion(for: source, state: &state)
            guard case let .binary(destination, op, left, right) = operation else {
                XCTFail("Expected scalar arithmetic with an exact immediate")
                continue
            }
            XCTAssertEqual(destination, state.readRegister("x0"), "\(mnemonic) \(operands)")
            XCTAssertEqual(left, expectedLeft, "\(mnemonic) \(operands)")
            XCTAssertEqual(op, mnemonic == "and" ? "&" : mnemonic == "eor" ? "^" : "|", "\(mnemonic) \(operands)")
            XCTAssertEqual(right, .immediate(expected))
        }
    }

    func testIsolatedScalarBoundaryFailures() {
        for (mnemonic, operands) in [
            ("add", "x0, x1, x2"),
            ("and", "x0, x1, x2, lsl #1, extra"),
            ("orr", "x0, x1, x2, rol #3"),
            ("orr", "x0, x1, x2, lsl #9223372036854775808"),
            ("and", "x0, x1, w2")
        ] {
            XCTAssertFalse(MacIRBuilder.isScalarRegionLogical(
                mnemonic: mnemonic, operands: operands), "\(mnemonic) \(operands)")
        }
    }

    func testF1BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("and", "w0, w1, #+8", .binary("&", { _ in .immediate(8) })), // F1-01
            ("and", "w0, w1, #+0x8", .refused), // F1-02
            ("and", "w0, w1, #0X8", .refused), // F1-03
            ("and", "w0, w1, #-0x10", .binary("&", { _ in .immediate(4294967280) })), // F1-04
            ("and", "w0, w1, #-0x1", .binary("&", { _ in .immediate(4294967295) })), // F1-05
            ("and", "w0, w1, #-1", .binary("&", { _ in .immediate(-1) })), // F1-06
            ("and", "w0, w1, #-0", .binary("&", { _ in .immediate(0) })), // F1-07
            ("and", "w0, w1, #0xFF", .binary("&", { _ in .immediate(255) })), // F1-08
            ("and", "w0, w1, #0x8000000000000000", .binary("&", { _ in .immediate(0) })), // F1-09
            ("and", "w0, w1, #0xaaaaaaaaaaaaaaaa", .binary("&", { _ in .immediate(2863311530) })), // F1-10
            ("and", "w0, w1, #0x100000000", .binary("&", { _ in .immediate(0) })), // F1-11
            ("and", "w0, w1, #4294967296", .binary("&", { _ in .immediate(4294967296) })), // F1-12
            ("and", "w0, w1, #0x10000000000000000", .refused), // F1-13
            ("and", "w0, w1, #9223372036854775808", .refused), // F1-14
            ("and", "w0, w1, #-9223372036854775808", .refused), // F1-15
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF2BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("bic", "x0, x1, #8", .binary("&", { _ in .unary(op: "~", value: .immediate(8)) })), // F2-01
            ("bic", "x0, x1, #-0x10", .binary("&", { _ in .unary(op: "~", value: .immediate(-16)) })), // F2-02
            ("bic", "x0, x1, #+8", .binary("&", { _ in .unary(op: "~", value: .immediate(8)) })), // F2-03
            ("bic", "x0, x1, #-0", .binary("&", { _ in .unary(op: "~", value: .immediate(0)) })), // F2-04
            ("bic", "x0, x1, #+0x8", .refused), // F2-05
            ("bic", "x0, x1, #0X8", .refused), // F2-06
            ("bic", "x0, x1, #0x8000000000000000", .refused), // F2-07
            ("bic", "x0, x1, #0xaaaaaaaaaaaaaaaa", .refused), // F2-08
            ("bic", "x0, x1, #0x10000000000000000", .refused), // F2-09
            ("bic", "x0, x1, #9223372036854775808", .refused), // F2-10
            ("orn", "x0, x1, #8", .binary("|", { _ in .unary(op: "~", value: .immediate(8)) })), // F2-11
            ("orn", "x0, x1, #-0x10", .binary("|", { _ in .unary(op: "~", value: .immediate(-16)) })), // F2-12
            ("orn", "x0, x1, #+8", .binary("|", { _ in .unary(op: "~", value: .immediate(8)) })), // F2-13
            ("orn", "x0, x1, #-0", .binary("|", { _ in .unary(op: "~", value: .immediate(0)) })), // F2-14
            ("orn", "x0, x1, #+0x8", .refused), // F2-15
            ("orn", "x0, x1, #0X8", .refused), // F2-16
            ("orn", "x0, x1, #0x8000000000000000", .refused), // F2-17
            ("orn", "x0, x1, #0xaaaaaaaaaaaaaaaa", .refused), // F2-18
            ("orn", "x0, x1, #0x10000000000000000", .refused), // F2-19
            ("orn", "x0, x1, #9223372036854775808", .refused), // F2-20
            ("eon", "x0, x1, #8", .binary("^", { _ in .unary(op: "~", value: .immediate(8)) })), // F2-21
            ("eon", "x0, x1, #-0x10", .binary("^", { _ in .unary(op: "~", value: .immediate(-16)) })), // F2-22
            ("eon", "x0, x1, #+8", .binary("^", { _ in .unary(op: "~", value: .immediate(8)) })), // F2-23
            ("eon", "x0, x1, #-0", .binary("^", { _ in .unary(op: "~", value: .immediate(0)) })), // F2-24
            ("eon", "x0, x1, #+0x8", .refused), // F2-25
            ("eon", "x0, x1, #0X8", .refused), // F2-26
            ("eon", "x0, x1, #0x8000000000000000", .refused), // F2-27
            ("eon", "x0, x1, #0xaaaaaaaaaaaaaaaa", .refused), // F2-28
            ("eon", "x0, x1, #0x10000000000000000", .refused), // F2-29
            ("eon", "x0, x1, #9223372036854775808", .refused), // F2-30
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF3BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("orr", "x0, x1, #8", .binary("|", { _ in .immediate(8) })), // F3-01
            ("orr", "x0, x1, #-0x10", .binary("|", { _ in .immediate(-16) })), // F3-02
            ("orr", "x0, x1, #+8", .binary("|", { _ in .immediate(8) })), // F3-03
            ("orr", "x0, x1, #-0", .assignLeft), // F3-04
            ("orr", "x0, x1, #00", .assignLeft), // F3-05
            ("orr", "x0, x1, #0x7fffffffffffffff", .binary("|", { _ in .immediate(9223372036854775807) })), // F3-06
            ("orr", "x0, x1, #+0x8", .refused), // F3-07
            ("orr", "x0, x1, #0X8", .refused), // F3-08
            ("orr", "x0, x1, #0x8000000000000000", .refused), // F3-09
            ("orr", "x0, x1, #0xaaaaaaaaaaaaaaaa", .refused), // F3-10
            ("orr", "x0, x1, #0x10000000000000000", .refused), // F3-11
            ("orr", "x0, x1, #9223372036854775808", .refused), // F3-12
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF4BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("eor", "x0, x1, #8", .binary("^", { _ in .immediate(8) })), // F4-01
            ("eor", "x0, x1, #-0x10", .binary("^", { _ in .immediate(-16) })), // F4-02
            ("eor", "x0, x1, #+8", .binary("^", { _ in .immediate(8) })), // F4-03
            ("eor", "x0, x1, #-0", .binary("^", { _ in .immediate(0) })), // F4-04
            ("eor", "x0, x1, #00", .binary("^", { _ in .immediate(0) })), // F4-05
            ("eor", "x0, x1, #0x7fffffffffffffff", .binary("^", { _ in .immediate(9223372036854775807) })), // F4-06
            ("eor", "x0, x1, #+0x8", .refused), // F4-07
            ("eor", "x0, x1, #0X8", .refused), // F4-08
            ("eor", "x0, x1, #0x8000000000000000", .refused), // F4-09
            ("eor", "x0, x1, #0xaaaaaaaaaaaaaaaa", .refused), // F4-10
            ("eor", "x0, x1, #0x10000000000000000", .refused), // F4-11
            ("eor", "x0, x1, #9223372036854775808", .refused), // F4-12
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF5BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("bic", "x0, x1, x2, lsl #3", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3))) })), // F5-01
            ("bic", "x0, x1, x2, lsr #3", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3))) })), // F5-02
            ("bic", "x0, x1, x2, asr #3", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(int64_t)", value: base), right: .immediate(3))) })), // F5-03
            ("bic", "x0, x1, x2, ror #3", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)), right: .binaryExpression(op: "<<", left: base, right: .immediate(61)))) })), // F5-04
            ("orn", "x0, x1, x2, lsl #3", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3))) })), // F5-05
            ("orn", "x0, x1, x2, lsr #3", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3))) })), // F5-06
            ("orn", "x0, x1, x2, asr #3", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(int64_t)", value: base), right: .immediate(3))) })), // F5-07
            ("orn", "x0, x1, x2, ror #3", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)), right: .binaryExpression(op: "<<", left: base, right: .immediate(61)))) })), // F5-08
            ("eon", "x0, x1, x2, lsl #3", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3))) })), // F5-09
            ("eon", "x0, x1, x2, lsr #3", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3))) })), // F5-10
            ("eon", "x0, x1, x2, asr #3", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(int64_t)", value: base), right: .immediate(3))) })), // F5-11
            ("eon", "x0, x1, x2, ror #3", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)), right: .binaryExpression(op: "<<", left: base, right: .immediate(61)))) })), // F5-12
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF6BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("orr", "w0, w1, w2, ror #0", .binary("|", { base in base })), // F6-01
            ("orr", "w0, w1, w2, ror #31", .binary("|", { base in .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1))) })), // F6-02
            ("orr", "w0, w1, w2, ror #32", .regionRefusal), // F6-03
            ("orr", "w0, w1, w2, ror #-1", .regionRefusal), // F6-04
            ("orr", "x0, x1, x2, ror #0", .binary("|", { base in base })), // F6-05
            ("orr", "x0, x1, x2, ror #63", .binary("|", { base in .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1))) })), // F6-06
            ("orr", "x0, x1, x2, ror #64", .regionRefusal), // F6-07
            ("orr", "x0, x1, x2, ror #-1", .regionRefusal), // F6-08
            ("and", "x0, x1, x2, ror #63", .binary("&", { base in .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1))) })), // F6-09
            ("and", "x0, x1, x2, ror #64", .regionRefusal), // F6-10
            ("and", "w0, w1, w2, ror #31", .binary("&", { base in .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1))) })), // F6-11
            ("and", "w0, w1, w2, ror #32", .regionRefusal), // F6-12
            ("eor", "x0, x1, x2, ror #63", .binary("^", { base in .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1))) })), // F6-13
            ("eor", "x0, x1, x2, ror #64", .regionRefusal), // F6-14
            ("eor", "w0, w1, w2, ror #31", .binary("^", { base in .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1))) })), // F6-15
            ("eor", "w0, w1, w2, ror #32", .regionRefusal), // F6-16
            ("bic", "x0, x1, x2, ror #63", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1)))) })), // F6-17
            ("bic", "x0, x1, x2, ror #64", .regionRefusal), // F6-18
            ("bic", "w0, w1, w2, ror #31", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1)))) })), // F6-19
            ("bic", "w0, w1, w2, ror #32", .regionRefusal), // F6-20
            ("orn", "x0, x1, x2, ror #63", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1)))) })), // F6-21
            ("orn", "x0, x1, x2, ror #64", .regionRefusal), // F6-22
            ("orn", "w0, w1, w2, ror #31", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1)))) })), // F6-23
            ("orn", "w0, w1, w2, ror #32", .regionRefusal), // F6-24
            ("eon", "x0, x1, x2, ror #63", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1)))) })), // F6-25
            ("eon", "x0, x1, x2, ror #64", .regionRefusal), // F6-26
            ("eon", "w0, w1, w2, ror #31", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: "|", left: .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)), right: .binaryExpression(op: "<<", left: base, right: .immediate(1)))) })), // F6-27
            ("eon", "w0, w1, w2, ror #32", .regionRefusal), // F6-28
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF7BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("orr", "w0, w1, w2, lsl #0", .binary("|", { base in base })), // F7-01
            ("orr", "w0, w1, w2, lsl #31", .binary("|", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)) })), // F7-02
            ("orr", "w0, w1, w2, lsl #32", .refused), // F7-03
            ("orr", "w0, w1, w2, lsl #-1", .refused), // F7-04
            ("orr", "x0, x1, x2, lsl #0", .binary("|", { base in base })), // F7-05
            ("orr", "x0, x1, x2, lsl #63", .binary("|", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)) })), // F7-06
            ("orr", "x0, x1, x2, lsl #64", .refused), // F7-07
            ("orr", "x0, x1, x2, lsl #-1", .refused), // F7-08
            ("orr", "w0, w1, w2, lsr #0", .binary("|", { base in base })), // F7-09
            ("orr", "w0, w1, w2, lsr #31", .binary("|", { base in .binaryExpression(op: ">>", left: .unary(op: "(uint32_t)", value: base), right: .immediate(31)) })), // F7-10
            ("orr", "w0, w1, w2, lsr #32", .refused), // F7-11
            ("orr", "w0, w1, w2, lsr #-1", .refused), // F7-12
            ("orr", "x0, x1, x2, lsr #0", .binary("|", { base in base })), // F7-13
            ("orr", "x0, x1, x2, lsr #63", .binary("|", { base in .binaryExpression(op: ">>", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)) })), // F7-14
            ("orr", "x0, x1, x2, lsr #64", .refused), // F7-15
            ("orr", "x0, x1, x2, lsr #-1", .refused), // F7-16
            ("orr", "w0, w1, w2, asr #0", .binary("|", { base in base })), // F7-17
            ("orr", "w0, w1, w2, asr #31", .binary("|", { base in .binaryExpression(op: ">>", left: .unary(op: "(int32_t)", value: base), right: .immediate(31)) })), // F7-18
            ("orr", "w0, w1, w2, asr #32", .refused), // F7-19
            ("orr", "w0, w1, w2, asr #-1", .refused), // F7-20
            ("orr", "x0, x1, x2, asr #0", .binary("|", { base in base })), // F7-21
            ("orr", "x0, x1, x2, asr #63", .binary("|", { base in .binaryExpression(op: ">>", left: .unary(op: "(int64_t)", value: base), right: .immediate(63)) })), // F7-22
            ("orr", "x0, x1, x2, asr #64", .refused), // F7-23
            ("orr", "x0, x1, x2, asr #-1", .refused), // F7-24
            ("and", "x0, x1, x2, lsl #63", .binary("&", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)) })), // F7-25
            ("and", "x0, x1, x2, lsl #64", .refused), // F7-26
            ("and", "w0, w1, w2, asr #31", .binary("&", { base in .binaryExpression(op: ">>", left: .unary(op: "(int32_t)", value: base), right: .immediate(31)) })), // F7-27
            ("and", "w0, w1, w2, asr #32", .refused), // F7-28
            ("eor", "x0, x1, x2, lsl #63", .binary("^", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63)) })), // F7-29
            ("eor", "x0, x1, x2, lsl #64", .refused), // F7-30
            ("eor", "w0, w1, w2, asr #31", .binary("^", { base in .binaryExpression(op: ">>", left: .unary(op: "(int32_t)", value: base), right: .immediate(31)) })), // F7-31
            ("eor", "w0, w1, w2, asr #32", .refused), // F7-32
            ("bic", "x0, x1, x2, lsl #63", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63))) })), // F7-33
            ("bic", "x0, x1, x2, lsl #64", .refused), // F7-34
            ("bic", "w0, w1, w2, asr #31", .binary("&", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(int32_t)", value: base), right: .immediate(31))) })), // F7-35
            ("bic", "w0, w1, w2, asr #32", .refused), // F7-36
            ("orn", "x0, x1, x2, lsl #63", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63))) })), // F7-37
            ("orn", "x0, x1, x2, lsl #64", .refused), // F7-38
            ("orn", "w0, w1, w2, asr #31", .binary("|", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(int32_t)", value: base), right: .immediate(31))) })), // F7-39
            ("orn", "w0, w1, w2, asr #32", .refused), // F7-40
            ("eon", "x0, x1, x2, lsl #63", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(63))) })), // F7-41
            ("eon", "x0, x1, x2, lsl #64", .refused), // F7-42
            ("eon", "w0, w1, w2, asr #31", .binary("^", { base in .unary(op: "~", value: .binaryExpression(op: ">>", left: .unary(op: "(int32_t)", value: base), right: .immediate(31))) })), // F7-43
            ("eon", "w0, w1, w2, asr #32", .refused), // F7-44
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF8BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("orr", "w0, w1, wzr, lsl #3", .refused), // F8-01
            ("orr", "x0, x1, xzr, lsl #3", .refused), // F8-02
            ("and", "w0, w1, #5, lsl #3", .refused), // F8-03
            ("bic", "x0, x1, xzr, lsl #3", .refused), // F8-04
            ("eor", "w0, w1, wzr, ror #3", .refused), // F8-05
            ("orr", "x0, x1, #5, lsl #3", .refused), // F8-06
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    func testF9BoundaryMatrix() throws {
        let rows: [BoundaryRow] = [
            ("orr", "x0, x1, x2, lsl  #3", .binary("|", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)) })), // F9-01
            ("orr", "x0, x1, x2,  lsl #3 ", .binary("|", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)) })), // F9-02
            ("orr", "x0, x1, x2, lsl #+3", .binary("|", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)) })), // F9-03
            ("orr", "x0, x1, x2, lsl #-0", .binary("|", { base in base })), // F9-04
            ("orr", "x0, x1, x2, lsl #00", .binary("|", { base in base })), // F9-05
            ("orr", "x0, x1, x2, lsl #0x3", .binary("|", { base in .binaryExpression(op: "<<", left: .unary(op: "(uint64_t)", value: base), right: .immediate(3)) })), // F9-06
            ("orr", "x0, x1, x2, lsl #0X3", .refused), // F9-07
            ("orr", "x0, x1, x2, lsl #+0x3", .refused), // F9-08
            ("orr", "x0, x1, x2, lsl \t #3", .refused), // F9-09
            ("orr", "x0, x1, x2, lsl\t#3", .refused), // F9-10
            ("orr", "x0, x1, x2, lsl \t#3", .refused), // F9-11
            ("orr", "x0, x1, x2, lsl\t #3", .refused), // F9-12
            ("orr", "x0, x1, x2, lsl\t\t#3", .refused), // F9-13
            ("orr", "x0, x1, x2, lsl\u{00A0}#3", .refused), // F9-14
            ("orr", "x0, x1, x2, LSL #3", .refused), // F9-15
            ("orr", "X0, X1, X2", .refused), // F9-16
            ("orr", "W0, W1, W2", .refused), // F9-17
            ("orr", "x0, x1, X2, lsl #3", .refused), // F9-18
        ]
        for row in rows { try checkBoundaryRow(row) }
    }

    private enum BoundaryExpected {
        case binary(String, (MacIRValue) -> MacIRValue)
        case assignLeft
        case refused
        case regionRefusal
    }
    private typealias BoundaryRow = (mnemonic: String, operands: String, expected: BoundaryExpected)

    private func checkBoundaryRow(_ row: BoundaryRow) throws {
        let label = "\(row.mnemonic) \(row.operands.debugDescription)"
        let operands = row.operands.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let destinationName = operands[0].lowercased()
        switch row.expected {
        case .refused:
            if destinationName == "x0" {
                try checkRejectedScalarRow(row.mnemonic, row.operands)
            } else {
                try checkRejectedScalarRow(row.mnemonic, row.operands,
                                           destinationRegister: destinationName)
            }
        case .regionRefusal:
            XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(
                mnemonic: row.mnemonic, operands: row.operands), label)
            let function = build(row.mnemonic, row.operands, consumer: destinationName)
            let instruction = try XCTUnwrap(function.instructions.first {
                $0.source.address == 0x100c
            }, label)
            guard case let .unknown(destination, _, mnemonic, text) = instruction.operation else {
                return XCTFail("Expected region-level refusal: \(label)")
            }
            XCTAssertNil(destination, label)
            XCTAssertEqual(mnemonic, row.mnemonic, label)
            XCTAssertEqual(text, row.operands, label)
            if destinationName == "x0" {
                let consumer = try XCTUnwrap(function.instructions.first {
                    $0.source.address == 0x1010
                }, label)
                guard case let .assign(_, value) = consumer.operation else {
                    return XCTFail("Expected following X read: \(label)")
                }
                XCTAssertEqual(value, .unknown("unavailable_x0"), label)
            }
        case .binary, .assignLeft:
            XCTAssertTrue(MacIRBuilder.isScalarRegionLogical(
                mnemonic: row.mnemonic, operands: row.operands), label)
            var state = BuilderState()
            let expectedLeft = state.readRegister(operands[1])
            // A zero left would select ORR's other assign arm instead of this fixture's path.
            XCTAssertNotEqual(expectedLeft, .immediate(0), label)
            let base: MacIRValue = operands.count == 4
                ? state.readRegister(operands[2]) : .immediate(0)
            let source = MacIRSourceSpan(address: 0x100c, byteText: "", mnemonic: row.mnemonic,
                                         operands: row.operands, comment: nil)
            let operation = MacIRBuilder().operationForVectorRegion(for: source, state: &state)
            let expectedDestination = state.readRegister(destinationName)
            switch row.expected {
            case let .binary(expectedOperator, expectedRight):
                guard case let .binary(destination, op, left, right) = operation else {
                    return XCTFail("Expected binary: \(label)")
                }
                XCTAssertEqual(destination, expectedDestination, label)
                XCTAssertEqual(op, expectedOperator, label)
                XCTAssertEqual(left, expectedLeft, label)
                XCTAssertEqual(right, expectedRight(base), label)
            case .assignLeft:
                guard case let .assign(destination, value) = operation else {
                    return XCTFail("Expected ORR zero-immediate assign: \(label)")
                }
                XCTAssertEqual(destination, expectedDestination, label)
                XCTAssertEqual(value, expectedLeft, label)
            default:
                XCTFail("Unexpected table dispatch: \(label)")
            }
        }
    }

    private func checkRejectedScalarRow(_ mnemonic: String, _ operands: String,
                                        destinationRegister: String = "x0") throws {
        let label = "\(mnemonic) \(operands.debugDescription)"
        XCTAssertFalse(MacIRBuilder.isScalarRegionLogical(mnemonic: mnemonic, operands: operands), label)
        var state = BuilderState()
        let previous = state.readRegister(destinationRegister)
        let source = MacIRSourceSpan(address: 0x100c, byteText: "", mnemonic: mnemonic,
                                     operands: operands, comment: nil)
        let operation = MacIRBuilder().operationForVectorRegion(for: source, state: &state)
        guard case let .unknown(destination, _, actualMnemonic, actualOperands) = operation else {
            return XCTFail("Rejected text must not become an opaque arithmetic operand: \(label)")
        }
        XCTAssertNil(destination, label)
        XCTAssertEqual(actualMnemonic, mnemonic, label)
        XCTAssertEqual(actualOperands, operands, label)
        XCTAssertEqual(state.readRegister(destinationRegister), previous, label)
        let function = build(mnemonic, operands, consumer: destinationRegister)
        let row = try XCTUnwrap(function.instructions.first { $0.source.address == 0x100c }, label)
        guard case let .unknown(regionDestination, _, _, _) = row.operation else {
            return XCTFail("The region must refuse the whole row: \(label)")
        }
        XCTAssertNil(regionDestination, label)
        guard destinationRegister == "x0" else { return }
        let consumer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1010 }, label)
        guard case let .assign(_, value) = consumer.operation else {
            return XCTFail("Expected the consumer after the refused row: \(label)")
        }
        XCTAssertEqual(value, .unknown("unavailable_x0"), label)
    }

    private func checkScalar(_ mnemonic: String, _ operands: String,
                             expectedText: String, complement: Bool,
                             shiftText: String?) throws {
        for requestedSSA in [false, true] {
            let destinationName = String(operands.split(separator: ",")[0])
            let function = build(mnemonic, operands, consumer: destinationName,
                                 requestedSSA: requestedSSA)
            let producer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x100c })
            XCTAssertNil(producer.neonLogical)
            guard case let .binary(destination, _, _, _) = producer.operation else {
                return XCTFail("Scalar row must define a binary result: \(operands)")
            }
            let use = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1010 })
            guard case let .assign(_, read) = use.operation else {
                return XCTFail("Consumer must read the scalar result")
            }
            XCTAssertEqual(read, destination, "Same-width read must use the fresh producer")
            let text = PseudocodePrinter().render(operation: producer.operation,
                                                   names: PseudocodeNameContext(function: function))
            XCTAssertTrue(text.contains(expectedText), text)
            XCTAssertFalse(text.contains("__unknown("), text)
            XCTAssertFalse(text.contains("unavailable_"), text)
            if complement { XCTAssertTrue(text.contains("~"), text) }
            if let shiftText { XCTAssertTrue(text.contains(shiftText), text) }
        }
    }

    private func build(_ mnemonic: String, _ operands: String, consumer: String,
                       requestedSSA: Bool = false) -> MacIRFunction {
        // The decoded MOVI spelling and non-entry backedge reserve the general
        // vector region as in SV:63-89; no decoder invocation is needed here.
        let prefix = consumer.hasPrefix("w") ? "w" : "x"
        let text = [
            ("movi", "v4.16b, #7"), ("mov", "x19, #17"), ("mov", "x20, #5"),
            (mnemonic, operands), ("mov", "\(prefix)22, \(consumer)"),
            ("nop", ""), ("cbnz", "x5, 0x1014"), ("ret", "")
        ]
        let rows = text.enumerated().map { index, pair in
            InstructionRow(address: 0x1000 + UInt64(index * 4),
                bytes: index == 0 ? "e4 e4 00 4f" : "", mnemonic: pair.0,
                operands: pair.1, hasBreakpoint: false, comment: nil)
        }
        XCTAssertTrue(MacIRBuilder.attemptsGeneralVectorRegion(rows))
        let function = MacIRBuilder(ssaEnabled: requestedSSA).buildFunction(
            name: "scalar_logical_region", startAddress: 0x1000, instructions: rows)
        XCTAssertNotNil(function.instructions.first { $0.source.address == 0x1000 }?.neonImmediate)
        XCTAssertFalse(function.ssaEnabled, "Region return precedes the ordinary SSA dispatcher")
        return function
    }
}
