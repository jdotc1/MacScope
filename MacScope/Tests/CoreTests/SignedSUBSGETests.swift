import XCTest
@testable import MacScope

/// Invented, explicitly typed predicate observations only. No retained DEA
/// fixture, source signature, subtraction result or whole function is executed.
final class SignedSUBSGETests: XCTestCase {
    private let base: UInt64 = 0x7000

    private func row(_ offset: UInt64, _ word: UInt32, _ mnemonic: String, _ operands: String) -> InstructionRow {
        let bytes = (0..<4).map { String(format: "%02x", (word >> ($0 * 8)) & 255) }.joined(separator: " ")
        return .init(address: base + offset, bytes: bytes, mnemonic: mnemonic,
                     operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func pair() -> [InstructionRow] {
        [row(0, 0x6b01_0000, "subs", "w0, w0, w1"),
         row(4, 0x5400_004a, "b.ge", "0x700c"),
         row(8, 0xd65f_03c0, "ret", ""), row(12, 0xd65f_03c0, "ret", "")]
    }

    private func plan(_ left: String = "uint32_t", _ right: String = "uint32_t",
                      width: Int = 32) throws -> MacIRAuthoritativeParameterPlan {
        let parameters = try [left, right].enumerated().map { index, type in
            try XCTUnwrap(MacIRFunctionParameter(id: .init(rawValue: "subs-input-\(index)"),
                bindingID: .gpr(index), sourcePosition: index, abiLocation: .gpr(index: index, carrierWidth: width),
                type: type, name: index == 0 ? "left_word" : "right_word", evidence: .authoritativeUser))
        }
        return try XCTUnwrap(MacIRAuthoritativeParameterPlan(parameters: parameters, isVariadic: false))
    }

    private func build(_ rows: [InstructionRow], plan: MacIRAuthoritativeParameterPlan?) -> MacIRFunction {
        MacIRBuilder(ssaEnabled: false).buildFunction(name: "signed_subs_observation", startAddress: base,
            authoritativeParameterPlan: plan, instructions: rows)
    }

    private func branch(_ function: MacIRFunction, at offset: UInt64 = 4) throws -> MacIRInstruction {
        try XCTUnwrap(function.instructions.first { $0.source.address == base + offset })
    }

    private func containsProjection(_ value: MacIRValue) -> Bool {
        switch value {
        case let .binaryExpression(op, left, right):
            return op == MacIRBuilder.signedProjectionOperator || containsProjection(left) || containsProjection(right)
        case let .unary(_, inner): return containsProjection(inner)
        default: return false
        }
    }

    private func assertUnprojected(_ function: MacIRFunction, offset: UInt64 = 4,
                                   file: StaticString = #filePath, line: UInt = #line) throws {
        let instruction = try branch(function, at: offset)
        if case let .conditionalBranch(_, left, right, _) = instruction.operation {
            XCTAssertFalse(containsProjection(left) || containsProjection(right), file: file, line: line)
        } else if case let .compareToBool(_, _, left, right) = instruction.operation {
            XCTAssertFalse(containsProjection(left) || containsProjection(right), file: file, line: line)
        } else if case .intrinsic = instruction.operation {
            // A fallback intrinsic is a refusal, not a signed predicate proof.
        } else {
            XCTFail("unexpected consumer shape: \(instruction.operation)", file: file, line: line)
        }
    }

    private func predicateProgram(_ function: MacIRFunction, inputType: OrdinaryC.CType) throws -> OrdinaryC.Program {
        let instruction = try branch(function)
        guard case let .conditionalBranch(condition, left, right, _) = instruction.operation else {
            throw OrdinaryC.Failure.invalidContract("missing synthetic predicate")
        }
        XCTAssertEqual(condition, ">=")
        XCTAssertTrue(containsProjection(left) && containsProjection(right))
        let names = PseudocodeNameContext(function: function)
        let statement = PseudocodePrinter().render(operation: .compareToBool(
            destination: .temporary(0), condition: condition, left: left, right: right), names: names)
        let type = inputType == .i32 ? "int32_t" : inputType == .u32 ? "uint32_t" : "uint64_t"
        let signature = "int32_t signed_subs_predicate(\(type) left_word, \(type) right_word) {"
        let terminal = "return tmp_0;"
        // This terminal is test observation scaffolding, not an original RET.
        let observation: UInt64 = 0x7100
        let contract = OrdinaryC.Contract(signature: signature,
            inputs: [.init(name: "left_word", type: inputType, entrySlot: 0),
                     .init(name: "right_word", type: inputType, entrySlot: 1)],
            fields: [], calls: [:], exterior: [:], terminalRow: 99, terminalPayload: terminal,
            terminalName: "tmp_0", returnType: .i32,
            rowsByAddress: [instruction.source.address: 1, observation: 99], allowedLabels: [],
            memoryEffects: [:], helpers: [:], deadResults: [], permissions: [])
        return try OrdinaryC.Program(lines: [
            .init(text: signature, source: nil, envelope: .signature),
            .init(text: "int32_t tmp_0;", source: nil, envelope: .body),
            .init(text: statement + ";", source: instruction.source.address, envelope: .body),
            .init(text: terminal, source: observation, envelope: .body),
            .init(text: "}", source: nil, envelope: .closingBrace)
        ], contract: contract)
    }

    private func evaluate(_ program: OrdinaryC.Program, _ left: UInt64, _ right: UInt64,
                          type: OrdinaryC.CType) throws -> UInt64? {
        let result = try OrdinaryC.Machine(program: program, scenario: .init(name: "new-subs-ge",
            inputs: ["left_word": .init(left, type), "right_word": .init(right, type)],
            memory: [:], responses: [])).run()
        XCTAssertTrue(result.returned)
        return result.terminal?.bits
    }

    func testEmittedPredicateUsesSignedWOrderingForExplicitIntegerInputs() throws {
        // Expected decisions are independent of the emitted expression. The last
        // two unequal pairs require N==V, not the sign of a wrapped subtraction.
        let cases: [(UInt64, UInt64, UInt64)] = [
            (0, 0, 1), (1, 0, 1), (0, 1, 0),
            (0xffff_ffff, 0, 0), (0, 0xffff_ffff, 1),
            (0x8000_0000, 0x8000_0000, 1), (0x7fff_ffff, 0x7fff_ffff, 1),
            (0xffff_ffff, 0xffff_ffff, 1),
            (0x8000_0000, 0x7fff_ffff, 0), (0x7fff_ffff, 0xffff_ffff, 1)
        ]
        for (spelling, type) in [("uint32_t", OrdinaryC.CType.u32), ("int32_t", .i32)] {
            let function = build(pair(), plan: try plan(spelling, spelling))
            let program = try predicateProgram(function, inputType: type)
            for (left, right, expected) in cases {
                XCTAssertEqual(try evaluate(program, left, right, type: type), expected,
                    "\(spelling): \(left) >=signedW \(right)")
            }
        }
    }

    func testWReadKeepsLowWordNormalizationOfWiderIntegerInputs() throws {
        let function = build(pair(), plan: try plan("uint64_t", "uint64_t", width: 64))
        let producer = try XCTUnwrap(function.instructions.first { $0.source.address == base })
        guard case let .binary(_, "-", left, right) = producer.operation else { return XCTFail("missing SUBS") }
        XCTAssertEqual(left, .unary(op: "(uint32_t)", value: .argument(bindingID: .gpr(0))))
        XCTAssertEqual(right, .unary(op: "(uint32_t)", value: .argument(bindingID: .gpr(1))))
        let program = try predicateProgram(function, inputType: .u64)
        let cases: [(UInt64, UInt64, UInt64)] = [
            (0x1234_5678_ffff_ffff, 0xabcd_ef01_0000_0000, 0),
            (0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff, 1),
            (0xffff_ffff_8000_0000, 0x0000_0000_7fff_ffff, 0),
            (0x0000_0001_7fff_ffff, 0xffff_ffff_ffff_ffff, 1),
            (0xffff_ffff_0000_0001, 0x0000_0000_0000_0001, 1)
        ]
        for (left, right, expected) in cases {
            XCTAssertEqual(try evaluate(program, left, right, type: .u64), expected)
        }
    }

    func testAliasedDestinationUsesBothBeforeWriteDefinitions() throws {
        let rows = [row(0, 0x2a00_03e8, "mov", "w8, w0"), row(4, 0x2a01_03e9, "mov", "w9, w1"),
            row(8, 0x6b09_0108, "subs", "w8, w8, w9"), row(12, 0x5400_004a, "b.ge", "0x7014"),
            row(16, 0xd65f_03c0, "ret", ""), row(20, 0xd65f_03c0, "ret", "")]
        let function = build(rows, plan: try plan())
        let producer = try XCTUnwrap(function.instructions.first { $0.source.address == base + 8 })
        guard case let .binary(destination, "-", beforeLeft, beforeRight) = producer.operation,
              case let .conditionalBranch(">=", projectedLeft, projectedRight, _) = try branch(function, at: 12).operation else {
            return XCTFail("missing original SUBS/GE operations")
        }
        XCTAssertNotEqual(destination, beforeLeft)
        XCTAssertNotEqual(destination, beforeRight)
        XCTAssertEqual(MacIRBuilder.droppingSignedProjection(projectedLeft), .unary(op: "(uint32_t)", value: beforeLeft))
        XCTAssertEqual(MacIRBuilder.droppingSignedProjection(projectedRight), .unary(op: "(uint32_t)", value: beforeRight))
        XCTAssertFalse(containsProjection(beforeLeft) || containsProjection(beforeRight), "do not rewrite the subtraction result")
    }

    func testProducerAndConsumerEncodingDisagreementsRefuseProjection() throws {
        let parameterPlan = try plan()
        let producerWords: [UInt32] = [
            0xeb01_0000, // X width.
            0x6b41_0000, // Shifted register kind.
            0x6b01_0400, // LSL #1.
            0x6b21_0000, // Extended register.
            0x7100_0400, // Immediate subtraction.
            0x2b01_0000, // ADDS.
            0x6b01_001f, // CMP alias / WZR destination.
            0x6b1f_0000, // WZR right operand.
            0x6b01_03e0, // WZR left operand.
            0x6b02_0000  // Different right register.
        ]
        for word in producerWords {
            var rows = pair(); rows[0] = row(0, word, "subs", "w0, w0, w1")
            try assertUnprojected(build(rows, plan: parameterPlan))
        }
        for operands in ["w8, w0, w1", "w0, w0, w1, lsl #0", "w0, w0, #1", "x0, x0, x1"] {
            var rows = pair(); rows[0].operands = operands
            try assertUnprojected(build(rows, plan: parameterPlan))
        }
        for word in [UInt32(0x5400_0042), 0x5400_005a, 0x5400_006a] {
            var rows = pair(); rows[1] = row(4, word, "b.ge", "0x700c")
            try assertUnprojected(build(rows, plan: parameterPlan))
        }
        for bytes in ["00 00 01", "gg 00 01 6b"] {
            var rows = pair(); rows[0].bytes = bytes
            try assertUnprojected(build(rows, plan: parameterPlan))
        }
    }

    func testAlternateEntriesAndUnknownTransfersRefuseProjection() throws {
        let parameterPlan = try plan()
        for first in [row(0, 0x5400_0040, "b.eq", "0x7008"),
                      row(0, 0x3400_0042, "cbz", "w2, 0x7008"),
                      row(0, 0x3600_0042, "tbz", "w2, #0, 0x7008")] {
            let rows = [first, row(4, 0x6b01_0000, "subs", "w0, w0, w1"),
                row(8, 0x5400_004a, "b.ge", "0x7010"), row(12, 0xd65f_03c0, "ret", ""),
                row(16, 0xd65f_03c0, "ret", "")]
            try assertUnprojected(build(rows, plan: parameterPlan), offset: 8)
        }
        for terminal in [row(12, 0xd61f_0040, "br", "x2"),
                         row(12, 0xd61f_0040, "nop", ""),
                         row(12, 0x9400_0001, "bl", "0x7010"),
                         row(12, 0x1400_0002, "b", "0x7014")] {
            var rows = pair(); rows[3] = terminal
            try assertUnprojected(build(rows, plan: parameterPlan))
        }
        let separated = [row(0, 0x6b01_0000, "subs", "w0, w0, w1"), row(4, 0xd503_201f, "nop", ""),
            row(8, 0x5400_004a, "b.ge", "0x7010"), row(12, 0xd65f_03c0, "ret", ""),
            row(16, 0xd65f_03c0, "ret", "")]
        try assertUnprojected(build(separated, plan: parameterPlan), offset: 8)
        var gap = pair(); gap[3].address += 4
        try assertUnprojected(build(gap, plan: parameterPlan))
    }

    func testUnknownPointerAndNarrowCarriersRemainUnqualified() throws {
        try assertUnprojected(build(pair(), plan: nil))
        for spelling in ["float *", "void *", "unresolved_word", "int8_t", "uint16_t"] {
            let parameterPlan = try plan(spelling, "uint64_t", width: 64)
            let function = build(pair(), plan: parameterPlan)
            try assertUnprojected(function)
        }
        var state = BuilderState(parameters: [])
        let untyped = state.writeRegister("w8")
        XCTAssertFalse(state.hasKnownIntegerSUBSCarrier(untyped),
                       "default registerTemporary int32 hint is not type evidence")
        XCTAssertFalse(state.hasKnownIntegerSUBSCarrier(.unary(op: "(uint32_t)", value: .unknown("effect()"))))
        XCTAssertFalse(state.hasKnownIntegerSUBSCarrier(.unary(op: "(uint32_t)", value: .stackSlot(offset: 0))))
    }

    func testOtherConsumersAndDisabledPolicyStayOutsideRule() throws {
        let parameterPlan = try plan()
        for suffix in ["lt", "hs", "eq"] {
            let condition: UInt32 = suffix == "lt" ? 11 : suffix == "hs" ? 2 : 0
            var rows = pair(); rows[1] = row(4, 0x5400_0040 | condition, "b.\(suffix)", "0x700c")
            try assertUnprojected(build(rows, plan: parameterPlan))
        }
        var setRows = pair(); setRows[1] = row(4, 0x1a9f_b7e2, "cset", "w2, ge")
        try assertUnprojected(build(setRows, plan: parameterPlan))
        let disabled = MacIRBuilder(skippingRejectedCFGReconciliation: true,
            explicitCFGEnabled: false, nativeSignedWordCMPEnabled: false).buildFunction(
                name: "disabled_subs_observation", startAddress: base,
                authoritativeParameterPlan: parameterPlan, instructions: pair())
        try assertUnprojected(disabled)
    }

    func testClosedLoopDoesNotRequireLaterFlagClosure() throws {
        for neutral in [row(12, 0xd503_201f, "nop", ""), row(12, 0x0a21_0002, "bic", "w2, w0, w1")] {
            // W8 is distinct from both input registers, so the backedge does not
            // turn either input into an unavailable entry-phi value.
            let rows = [row(0, 0x6b01_0008, "subs", "w8, w0, w1"),
                row(4, 0x5400_006a, "b.ge", "0x7010"), row(8, 0x17ff_fffe, "b", "0x7000"),
                neutral, row(16, 0xd65f_03c0, "ret", "")]
            // Inspect the newly generated predicate; do not execute this loop.
            let function = build(rows, plan: try plan())
            guard case let .conditionalBranch(">=", left, right, _) = try branch(function).operation else {
                return XCTFail("missing loop predicate")
            }
            XCTAssertTrue(containsProjection(left) && containsProjection(right))
        }
    }
}
