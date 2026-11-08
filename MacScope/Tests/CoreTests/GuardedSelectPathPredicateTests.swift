import Foundation
import Darwin
import XCTest
@testable import MacScope

// Authored IR and literal machine rows only.
final class GuardedSelectPathPredicateTests: XCTestCase {
    func testGAEqualityAndInequalityUseTheComparedWView() {
        for fixture in ["ga", "gaNe", "rawArms", "registerRHS"] { assertAccepted(fixture) }
    }

    func testGARefusesOrderedRawArmsWideCompareAndLogicalProducer() {
        for fixture in ["ordered", "narrow", "logical"] {
            assertRefused(fixture, guardID: "old.predicate-projection", registers: ["x1", "x2"])
        }
        assertRefused("subs", guardID: "old.logical-operands", registers: ["x1", "x2"])
    }

    func testGARawXPredicateDoesNotBecomeAnInferredWView() {
        assertRefused("rawPredicate", guardID: "old.compare-inputs", registers: ["x1", "x2"])
    }

    func testGANestedArmMustStillBeASameRegisterWImmediateMove() {
        assertRefused("loadArm", guardID: "old.arm-binding.yes-leaf", registers: ["x1", "x2"])
    }

    func testGCExactZeroForCselAndCsincAndCombinedGA() {
        for fixture in ["gc64", "gcYes64", "gc32", "combined"] { assertAccepted(fixture) }
    }

    func testGCRegisterNamedZeroAndNonzeroConstantAreNotZeroProofs() {
        for fixture in ["zeroRegisterIR", "nonzero", "inverseNonzero", "negativeNonzero"] {
            assertRefused(fixture, guardID: "old.arm-binding.no-leaf", registers: ["x1"])
        }
        assertRefused("wrongZeroWidth", guardID: "old.select-view", registers: ["x1"])
        assertRefused("twoZeroSpellings", guardID: "old.select-view", registers: ["x1"])
        assertRefused("zeroAlias", guardID: "old.select-view", registers: ["x1", "x1"])
    }

    func testGCDoesNotExcuseTheRegisterArmOverwrite() {
        assertRefused("overwrite", guardID: "extension.true-arm-definition", registers: ["x1"])
    }

    func testGASharedPredicateStillChecksBothSelects() {
        assertAccepted("shared")
        assertRefused("sharedOverwrite", guardID: "extension.true-arm-definition", registers: ["x1"])
    }

    private func assertAccepted(_ fixtureName: String,
                                file: StaticString = #filePath, line: UInt = #line) {
        for mode in [false, true] {
            let result = analyze(fixture(fixtureName), ssaAccountingEnabled: mode)
            XCTAssertNil(result.skippedReason, fixtureName, file: file, line: line)
            XCTAssertTrue(result.rows.isEmpty, fixtureName, file: file, line: line)
            XCTAssertTrue(result.refusalDetails.isEmpty, fixtureName, file: file, line: line)
        }
    }

    private func assertRefused(_ fixtureName: String, guardID: String, registers: [String],
                               file: StaticString = #filePath, line: UInt = #line) {
        for mode in [false, true] {
            let result = analyze(fixture(fixtureName), ssaAccountingEnabled: mode)
            XCTAssertEqual(result.skippedReason, "guarded select arm needs path-predicate proof",
                           fixtureName, file: file, line: line)
            XCTAssertTrue(result.rows.isEmpty, fixtureName, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.count, registers.count, fixtureName, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.compactMap(\.register), registers,
                           fixtureName, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.compactMap { $0.guardedFailure?.guardID },
                           Array(repeating: guardID, count: registers.count), fixtureName, file: file, line: line)
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

    private func fixture(_ mode: String) -> MacIRFunction {
        func w(_ n: Int, _ v: Int) -> MacIRValue { .register(name: "w\(n)", version: v) }
        func low(_ value: MacIRValue) -> MacIRValue { .unary(op: "(uint32_t)", value: value) }
        func extended(_ value: MacIRValue) -> MacIRValue { .unary(op: "(uint64_t)", value: low(value)) }
        let gc = ["gc64", "gcYes64", "gc32", "zeroRegisterIR", "nonzero", "inverseNonzero",
                  "negativeNonzero", "wrongZeroWidth", "twoZeroSpellings", "zeroAlias", "overwrite"].contains(mode)
        let narrow = mode == "narrow" || mode == "gc32"
        let selectBits = narrow ? 32 : 64
        let prefix = selectBits == 32 ? "w" : "x"
        let rawLeaves = gc || mode == "rawArms" || mode == "narrow"
        let yesLeaf = rawLeaves ? reg(1, 1) : w(1, 1)
        let noLeaf = rawLeaves ? reg(2, 1) : w(2, 1)
        let wideCompare = gc && mode != "gc32" || mode == "narrow"
        let comparePrefix = wideCompare ? "x" : "w"
        let producer = mode == "logical" ? "tst" : (mode == "subs" ? "subs" : "cmp")
        let ordered = mode == "ordered"
        let suffix = ordered ? "lo" : (mode == "gaNe" ? "ne" : "eq")
        let condition = ordered ? "<" : (mode == "gaNe" ? "!=" : "==")
        let lhs = wideCompare || mode == "rawPredicate" ? reg(3, 0) : low(reg(3, 0))
        let rhs: MacIRValue = mode == "registerRHS" ? low(reg(4, 0)) : .immediate(mode == "logical" ? 1 : 0)
        var yes: MacIRValue = gc ? (narrow ? low(yesLeaf) : yesLeaf)
            : (mode == "rawArms" ? yesLeaf : (narrow ? low(yesLeaf) : extended(yesLeaf)))
        var no: MacIRValue = gc ? .immediate(0)
            : (mode == "rawArms" ? noLeaf : (narrow ? low(noLeaf) : extended(noLeaf)))
        var mnemonic = "csel"
        var yesSpelling = "\(prefix)1"
        var noSpelling = gc || mode == "combined" ? (narrow ? "wzr" : "xzr") : "\(prefix)2"
        if mode == "gcYes64" {
            yes = .immediate(0); no = yesLeaf; yesSpelling = "xzr"; noSpelling = "x1"
        }
        if mode == "combined" { no = .immediate(0) }
        if mode == "zeroRegisterIR" { no = .register(name: "xzr", version: 0) }
        if ["nonzero", "inverseNonzero", "negativeNonzero"].contains(mode) { no = .immediate(5) }
        if mode == "wrongZeroWidth" { noSpelling = "wzr" }
        if mode == "twoZeroSpellings" { yesSpelling = "xzr"; no = .immediate(0) }
        if mode == "gc32" {
            mnemonic = "csinc"
            no = .binaryExpression(op: "+", left: no, right: .immediate(1))
            yes = w(1, 1)
        }
        if mode == "inverseNonzero" { mnemonic = "csinv"; no = .unary(op: "~", value: no) }
        if mode == "negativeNonzero" { mnemonic = "csneg"; no = .unary(op: "-", value: no) }
        if mode == "zeroAlias" {
            mnemonic = "cinc"; yesSpelling = "xzr"
            no = .binaryExpression(op: "+", left: yes, right: .immediate(1))
        }
        let storedYes = mode == "gc32" ? w(1, 1) : yesLeaf
        var rows = [instruction(0x7a00, mode == "loadArm" ? "ldr" : "mov",
            mode == "loadArm" ? "w1, [x5]" : "w1, #0x38",
            mode == "loadArm" ? .load(destination: storedYes, address: reg(5, 0)) : .assign(destination: storedYes, source: .immediate(0x38))),
            instruction(0x7a04, "mov", "w2, #0x48", .assign(destination: noLeaf, source: .immediate(0x48))),
            instruction(0x7a08, producer,
                (mode == "subs" ? "w5, " : "") + "\(comparePrefix)3, " + (mode == "registerRHS" ? "w4" : (mode == "logical" ? "#1" : "#0")),
                .intrinsic(destination: nil, name: "compare", arguments: [reg(3, 0), mode == "registerRHS" ? reg(4, 0) : rhs]))]
        if mode == "overwrite" {
            rows.append(instruction(0x7a0c, "mov", "x1, #0x100000000", .assign(destination: reg(1, 2), source: .immediate(0x100000000))))
        }
        let address: UInt64 = mode == "overwrite" ? 0x7a10 : 0x7a0c
        let operands = mode == "zeroAlias" ? "x0, xzr, ne" : "\(prefix)0, \(yesSpelling), \(noSpelling), \(suffix)"
        rows.append(instruction(address, mnemonic, operands,
            .select(destination: narrow ? w(0, 1) : reg(0, 1), condition: condition,
                left: lhs, right: rhs, trueValue: yes, falseValue: no)))
        if mode == "shared" || mode == "sharedOverwrite" {
            if mode == "sharedOverwrite" {
                rows.append(instruction(address + 4, "mov", "x1, #0x100000000", .assign(destination: reg(1, 2), source: .immediate(0x100000000))))
            }
            let secondAddress = address + (mode == "sharedOverwrite" ? 8 : 4)
            rows.append(instruction(secondAddress, "csel", "x6, x1, x2, eq",
                .select(destination: reg(6, 1), condition: "==", left: lhs, right: rhs, trueValue: yes, falseValue: no)))
        }
        rows.append(instruction(rows.last!.source.address + 4, "ret", "", .returnValue(nil)))
        return MacIRFunction(name: "guarded_select_\(mode)", startAddress: 0x7a00,
                             returnType: "void", instructions: rows)
    }
}
