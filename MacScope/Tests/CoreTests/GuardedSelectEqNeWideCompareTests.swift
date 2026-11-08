import Foundation
import Darwin
import XCTest
@testable import MacScope

// Authored IR and literal machine rows only.
final class GuardedSelectEqNeWideCompareTests: XCTestCase {
    func testEN1RawEquality() { assertAccepted(fixture(1)) }
    func testEN2RawInequality() { assertAccepted(fixture(2)) }
    func testEN3NestedRegisterEquality() { assertAccepted(fixture(3)) }
    func testEN4NestedRegisterInequality() { assertAccepted(fixture(4)) }
    func testEN5RawRegisterEquality() { assertAccepted(fixture(5)) }
    func testEN6FalseArmIncrement() { assertAccepted(fixture(6)) }
    func testEN7WNamedImmediate() { assertAccepted(fixture(7)) }
    func testEN8WNamedRegister() { assertAccepted(fixture(8)) }
    func testEN9ZeroAndRawArm() { assertAccepted(fixture(9)) }
    func testEN10SharedCompare() { assertAccepted(fixture(10)) }
    func testEN11OverwrittenArm() { assertRefused(fixture(11), guardID: "extension.true-arm-definition", registers: ["x1"], sourceLine: 890) }
    func testEN12BareXLeft() { assertRefused(fixture(12), guardID: "old.compare-inputs", registers: ["x1", "x2"], sourceLine: 792) }
    func testEN13BareXRight() { assertRefused(fixture(13), guardID: "old.compare-inputs", registers: ["x1", "x2"], sourceLine: 792) }
    func testEN14WrongRightRegister() {
        // Complete analysis includes the independent wrong-register flags use.
        for mode in [false, true] {
            let result = analyze(fixture(14), ssaAccountingEnabled: mode)
            XCTAssertEqual(result.skippedReason,
                "guarded select arm needs path-predicate proof; predicate operand provenance is not a direct flag-producer input")
            XCTAssertTrue(result.rows.isEmpty)
            XCTAssertEqual(result.refusalDetails.count, 3)
            XCTAssertEqual(result.refusalDetails.compactMap(\.register), ["x5", "x1", "x2"])
            XCTAssertEqual(result.refusalDetails.map(\.reason), [
                "predicate operand provenance is not a direct flag-producer input",
                "guarded select arm needs path-predicate proof: old-gate-failed",
                "guarded select arm needs path-predicate proof: old-gate-failed"])
            XCTAssertEqual(result.refusalDetails.map { $0.guardedFailure?.guardID },
                [nil, "old.compare-inputs", "old.compare-inputs"])
            XCTAssertEqual(result.refusalDetails.compactMap(\.instructionAddress), [0x7a08, 0x7a0c, 0x7a0c])
            XCTAssertEqual(result.refusalDetails.map { $0.guardedFailure?.sourceLine }, [nil, 792, 792])
        }
    }
    func testEN15WrongImmediate() { assertRefused(fixture(15), guardID: "old.compare-inputs", registers: ["x1", "x2"]) }
    func testEN16LiteralForRegister() { assertRefused(fixture(16), guardID: "old.compare-inputs", registers: ["x1", "x2"]) }
    func testEN17UnsignedImmediate() { assertRefused(fixture(17), guardID: "old.predicate-projection", registers: ["x1", "x2"]) }
    func testEN18UnsignedRegister() { assertRefused(fixture(18), guardID: "old.predicate-projection", registers: ["x1", "x2"]) }
    func testEN19SignedRawImmediate() { assertRefused(fixture(19), guardID: "old.predicate-projection", registers: ["x1", "x2"]) }
    func testEN20SignedRawRegister() { assertRefused(fixture(20), guardID: "old.predicate-projection", registers: ["x1", "x2"]) }
    func testEN21LogicalTst() { assertRefused(fixture(21), guardID: "old.predicate-projection", registers: ["x1", "x2"]) }
    func testEN22LogicalSubs() { assertRefused(fixture(22), guardID: "old.logical-operands", registers: ["x1", "x2"]) }
    func testEN23ZeroRegisterRHS() { assertRefused(fixture(23), guardID: "old.predicate-projection", registers: ["x1", "x2"]) }
    func testEN24CincAlias() { assertAccepted(fixture(24)) }
    func testEN25EqualWidthControl() { assertAccepted(fixture(25)) }

    private func assertAccepted(_ function: MacIRFunction,
                                file: StaticString = #filePath, line: UInt = #line) {
        for mode in [false, true] {
            let result = analyze(function, ssaAccountingEnabled: mode)
            XCTAssertNil(result.skippedReason, function.name, file: file, line: line)
            XCTAssertTrue(result.rows.isEmpty, function.name, file: file, line: line)
            XCTAssertTrue(result.refusalDetails.isEmpty, function.name, file: file, line: line)
        }
    }
    private func assertRefused(_ function: MacIRFunction, guardID: String, registers: [String],
                               sourceLine: Int? = nil,
                               file: StaticString = #filePath, line: UInt = #line) {
        for mode in [false, true] {
            let result = analyze(function, ssaAccountingEnabled: mode)
            XCTAssertEqual(result.skippedReason, "guarded select arm needs path-predicate proof",
                           function.name, file: file, line: line)
            XCTAssertTrue(result.rows.isEmpty, function.name, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.count, registers.count, function.name, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.compactMap(\.register), registers, function.name, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.compactMap { $0.guardedFailure?.guardID },
                           Array(repeating: guardID, count: registers.count), function.name, file: file, line: line)
            if let sourceLine {
                XCTAssertEqual(result.refusalDetails.compactMap { $0.guardedFailure?.sourceLine },
                               Array(repeating: sourceLine, count: registers.count), function.name, file: file, line: line)
            }
        }
    }

    private func reg(_ number: Int, _ version: Int) -> MacIRValue {
        .register(name: "x\(number)", version: version)
    }

    private func instruction(_ address: UInt64, _ mnemonic: String, _ operands: String,
                             _ operation: MacIROperation) -> MacIRInstruction {
        MacIRInstruction(source: MacIRSourceSpan(address: address, byteText: "00 00 00 00",
            mnemonic: mnemonic, operands: operands), operation: operation)
    }
    private func analyze(_ function: MacIRFunction,
                         expectedPrintedValue: MacIRValue? = nil,
                         expectedUseAddress: UInt64 = 0x4008,
                         ssaAccountingEnabled: Bool = false,
                         machine: [MacIRSourceSpan]? = nil) -> C2DataflowCensus.Analysis {
        let printer = PseudocodePrinter(options: DecompilerOptions(structureControlFlow: false,
            deadCodeElimination: false, nopElision: false, functionSizeGate: 1024))
        let document = printer.print(function: function)
        let projected = MacIRFPEnvironmentPseudocodeProjection.project(function)
        var names = PseudocodeNameContext(function: projected)
        names.redundantCompareIndices = printer.redundantCompareIndices(function: projected, names: names)
        if let value = expectedPrintedValue {
            let text = printer.valueText(for: value, names: names)
            XCTAssertTrue(document.lines.contains {
                $0.kind == .instruction && $0.sourceAddress == expectedUseAddress && $0.text.contains(text)
            }, "The fixture must print \(text) at its use")
        }
        return C2DataflowCensus.analyze(function: projected, document: document,
            machine: machine ?? function.instructions.map(\.source), printer: printer, names: names,
            ssaAccountingEnabled: ssaAccountingEnabled)
    }

    private func fixture(_ number: Int) -> MacIRFunction {
        func w(_ n: Int, _ v: Int) -> MacIRValue { .register(name: "w\(n)", version: v) }
        func low(_ value: MacIRValue) -> MacIRValue { .unary(op: "(uint32_t)", value: value) }
        func extended(_ value: MacIRValue) -> MacIRValue { .unary(op: "(uint64_t)", value: low(value)) }
        // EN7/EN8 reproduce CT's width-32 CMP mismatch fixtures, including entry arms.
        if number == 7 || number == 8 {
            let rhs: MacIRValue = number == 7 ? .immediate(3) : w(4, 0)
            let rows = [
                instruction(0x7600, "cmp", number == 7 ? "w3, #3" : "w3, w4",
                    .intrinsic(destination: nil, name: "compare", arguments: [w(3, 0), rhs])),
                instruction(0x7604, "csel", "x0, x1, x2, eq",
                    .select(destination: reg(0, 1), condition: "==", left: w(3, 0), right: rhs,
                            trueValue: reg(1, 0), falseValue: reg(2, 0))),
                instruction(0x7608, "ret", "", .returnValue(nil))]
            return MacIRFunction(name: "guarded_eqne_EN\(number)", startAddress: 0x7600,
                                 returnType: "void", instructions: rows)
        }
        let nested = [3, 4, 13, 14, 16, 23].contains(number)
        let registerRHS = [3, 4, 5, 13, 14, 16, 18, 20].contains(number)
        let signed = number == 19 || number == 20
        let unsigned = number == 17 || number == 18
        let wide = number == 25
        let suffix = signed ? "gt" : (unsigned ? "lo" : ([2, 4].contains(number) ? "ne" : "eq"))
        let condition = signed ? ">" : (unsigned ? "<" : ([2, 4].contains(number) ? "!=" : "=="))
        let producer = number == 21 ? "tst" : (number == 22 ? "subs" : "cmp")
        let yesLeaf = nested ? w(1, 1) : reg(1, 1)
        let noLeaf = nested ? w(2, 1) : reg(2, 1)
        var left = wide || number == 12 ? reg(3, 0) : low(reg(3, 0))
        if signed { left = .unary(op: "(int32_t)", value: reg(3, 0)) }
        var right: MacIRValue = registerRHS ? low(reg(4, 0)) : .immediate(number == 21 ? 1 : 0)
        if number == 13 { right = reg(4, 0) }
        if number == 14 { right = low(reg(5, 0)) }
        if number == 16 { right = .immediate(0) }
        if number == 20 { right = .unary(op: "(int32_t)", value: reg(4, 0)) }
        let yes = nested ? extended(yesLeaf) : yesLeaf
        var no = nested ? extended(noLeaf) : noLeaf
        if number == 9 { no = .immediate(0) }
        if number == 6 { no = .binaryExpression(op: "+", left: no, right: .immediate(1)) }
        if number == 24 { no = .binaryExpression(op: "+", left: yes, right: .immediate(1)) }
        let sourceRight = number == 23 ? "wzr" : (registerRHS ? "w4" : (number == 15 || number == 21 ? "#1" : "#0"))
        let compareRight: MacIRValue = registerRHS ? reg(4, 0) : .immediate(number == 15 || number == 21 ? 1 : 0)
        var rows = [
            instruction(0x7a00, "mov", "w1, #0x38", .assign(destination: yesLeaf, source: .immediate(0x38))),
            instruction(0x7a04, "mov", "w2, #0x48", .assign(destination: noLeaf, source: .immediate(0x48))),
            instruction(0x7a08, producer, (number == 22 ? "w5, " : "") + (wide ? "x3, " : "w3, ") + sourceRight,
                .intrinsic(destination: nil, name: "compare", arguments: [reg(3, 0), compareRight]))]
        if number == 11 {
            rows.append(instruction(0x7a0c, "mov", "x1, #0x100000000",
                .assign(destination: reg(1, 2), source: .immediate(0x100000000))))
        }
        let address: UInt64 = number == 11 ? 0x7a10 : 0x7a0c
        let mnemonic = number == 24 ? "cinc" : (number == 6 ? "csinc" : "csel")
        let operands = number == 24 ? "x1, x1, ne" : "x0, x1, \(number == 9 ? "xzr" : "x2"), \(suffix)"
        rows.append(instruction(address, mnemonic, operands,
            .select(destination: reg(number == 24 ? 1 : 0, number == 24 ? 2 : 1), condition: condition,
                    left: left, right: right, trueValue: yes, falseValue: no)))
        if number == 10 {
            rows.append(instruction(address + 4, "csel", "x6, x1, x2, eq",
                .select(destination: reg(6, 1), condition: "==", left: left, right: right,
                        trueValue: yes, falseValue: no)))
        }
        rows.append(instruction(rows.last!.source.address + 4, "ret", "", .returnValue(nil)))
        return MacIRFunction(name: "guarded_eqne_EN\(number)", startAddress: 0x7a00,
                             returnType: "void", instructions: rows)
    }
}
