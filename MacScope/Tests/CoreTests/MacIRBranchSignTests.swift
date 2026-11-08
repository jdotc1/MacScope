import Foundation
import XCTest
@testable import MacScope

// Source definitions only.
final class MacIRBranchSignTests: XCTestCase {
    private func row(_ address: UInt64, _ word: UInt32, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        InstructionRow(address: address,
            bytes: (0..<4).map { String(format: "%02x", (word >> ($0 * 8)) & 255) }.joined(separator: " "),
            mnemonic: mnemonic, operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func lift(_ rows: [InstructionRow]) -> MacIRFunction {
        MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            .buildFunction(name: "branch_sign",
                authoritativeParameterPlan: MacIRAuthoritativeParameterPlan(parameters: [], isVariadic: false),
                instructions: rows)
    }

    private func pair(_ mnemonic: String, _ operands: String, suffix: String = "mi", word: UInt32 = 0x6b020020) -> MacIRFunction {
        let branchWord: UInt32
        switch suffix {
        case "pl": branchWord = 0x54000065
        case "vs": branchWord = 0x54000066
        case "ge": branchWord = 0x5400006a
        default: branchWord = 0x54000064
        }
        return lift([row(0x1000, word, mnemonic, operands),
              row(0x1004, branchWord, "b.\(suffix)", "0x1010"),
              row(0x1008, 0x52800000, "mov", "w0, #0"), row(0x100c, 0xd65f03c0, "ret"),
              row(0x1010, 0x52800020, "mov", "w0, #1"), row(0x1014, 0xd65f03c0, "ret")])
    }

    func testWordSUBSMIHasLiteralMaskAndNoRawPrinterMarker() {
        let function = pair("subs", "w0, w1, w2")
        XCTAssertEqual(function.instructions[1].operation,
            .conditionalBranch(condition: "!=", left: .binaryExpression(op: "&",
                left: .unary(op: "(uint32_t)", value: .binaryExpression(op: "-",
                    left: .unary(op: "(uint32_t)", value: .register(name: "w1", version: 0)),
                    right: .unary(op: "(uint32_t)", value: .register(name: "w2", version: 0)))),
                right: .immediate(2147483648)), right: .immediate(0), target: .immediate(0x1010)))
        let text = PseudocodePrinter().print(function: function).text
        XCTAssertFalse(text.contains("__branch_mi"), text)
        XCTAssertTrue(text.contains("0x80000000"), text)
    }

    func testWordSUBSPLHasLiteralPolarity() {
        let function = pair("subs", "w0, w1, w2", suffix: "pl")
        guard case let .conditionalBranch(condition, _, right, target) = function.instructions[1].operation else {
            return XCTFail("Expected sign branch")
        }
        XCTAssertEqual(condition, "==")
        XCTAssertEqual(right, .immediate(0))
        XCTAssertEqual(target, .immediate(0x1010))
    }

    func testDoublewordSUBSMIHasLiteralSignedImmediateMask() {
        let function = pair("subs", "x0, x1, x2", word: 0xeb020020)
        XCTAssertEqual(function.instructions[1].operation,
            .conditionalBranch(condition: "!=", left: .binaryExpression(op: "&",
                left: .unary(op: "(uint64_t)", value: .binaryExpression(op: "-",
                    left: .unary(op: "(uint64_t)", value: .register(name: "x1", version: 0)),
                    right: .unary(op: "(uint64_t)", value: .register(name: "x2", version: 0)))),
                right: .immediate(-9223372036854775808)), right: .immediate(0), target: .immediate(0x1010)))
        let text = PseudocodePrinter().print(function: function).text
        XCTAssertTrue(text.contains("-0x8000000000000000"), text)
        XCTAssertFalse(text.contains("__branch_mi"), text)
    }

    func testCMPZeroDestinationLowers() {
        let function = pair("cmp", "w0, #1", word: 0x7100041f)
        XCTAssertEqual(function.instructions[1].operation,
            .conditionalBranch(condition: "!=", left: .binaryExpression(op: "&",
                left: .unary(op: "(uint32_t)", value: .binaryExpression(op: "-",
                    left: .unary(op: "(uint32_t)", value: .register(name: "w0", version: 0)),
                    right: .unary(op: "(uint32_t)", value: .immediate(1)))),
                right: .immediate(2147483648)), right: .immediate(0), target: .immediate(0x1010)))
    }

    func testFCMPPLStillUsesBooleanPostpass() {
        let function = pair("fcmp", "d0, d1", suffix: "pl", word: 0x1e612000)
        guard case let .compareToBool(destination, condition, left, right) = function.instructions[0].operation,
              case let .conditionalBranch(branch, flag, zero, target) = function.instructions[1].operation else {
            return XCTFail("Expected FCMP Boolean boundary")
        }
        XCTAssertEqual(condition, "<")
        XCTAssertEqual(left, .unary(op: "(double)", value: .register(name: "d0", version: 0)))
        XCTAssertEqual(right, .unary(op: "(double)", value: .register(name: "d1", version: 0)))
        XCTAssertEqual(branch, "==")
        XCTAssertEqual(flag, destination)
        XCTAssertEqual(zero, .immediate(0))
        XCTAssertEqual(target, .immediate(0x1010))
    }

    func testEarlierCMPDoesNotFeedFCMPMI() {
        let function = lift([row(0x0ffc, 0x7100041f, "cmp", "w0, #1"),
            row(0x1000, 0x1e612000, "fcmp", "d0, d1"), row(0x1004, 0x54000064, "b.mi", "0x1010"),
            row(0x1008, 0x52800000, "mov", "w0, #0"), row(0x100c, 0xd65f03c0, "ret"),
            row(0x1010, 0x52800020, "mov", "w0, #1"), row(0x1014, 0xd65f03c0, "ret")])
        guard case let .compareToBool(destination, "<", _, _) = function.instructions[1].operation,
              case let .conditionalBranch(condition, flag, zero, _) = function.instructions[2].operation else {
            return XCTFail("Earlier CMP must not replace FCMP predicate")
        }
        XCTAssertEqual(condition, "!=")
        XCTAssertEqual(flag, destination)
        XCTAssertEqual(zero, .immediate(0))
    }

    func testMSRFlagClobberKeepsRawMI() {
        let function = lift([row(0x1000, 0x6b020020, "subs", "w0, w1, w2"),
            row(0x1004, 0xd51b4200, "msr", "nzcv, x0"),
            row(0x1008, 0x54000044, "b.mi", "0x1010"), row(0x100c, 0xd65f03c0, "ret"),
            row(0x1010, 0xd65f03c0, "ret")])
        XCTAssertEqual(function.instructions[2].operation,
            .intrinsic(destination: nil, name: "branch_mi", arguments: [.immediate(0x1010)]))
    }

    func testIndirectEntryKeepsRawPL() {
        let function = lift([row(0x0ff8, 0xd2820089, "mov", "x9, #0x1004"),
            row(0x0ffc, 0xd61f0120, "br", "x9"),
            row(0x1000, 0x1e612000, "fcmp", "d0, d1"), row(0x1004, 0x54000065, "b.pl", "0x1010"),
            row(0x1008, 0x52800000, "mov", "w0, #0"), row(0x100c, 0xd65f03c0, "ret"),
            row(0x1010, 0x52800020, "mov", "w0, #1"), row(0x1014, 0xd65f03c0, "ret")])
        XCTAssertEqual(function.instructions[3].operation,
            .intrinsic(destination: nil, name: "branch_pl", arguments: [.immediate(0x1010)]))
    }

    func testVSRemainsRaw() {
        XCTAssertEqual(pair("subs", "w0, w1, w2", suffix: "vs").instructions[1].operation,
            .intrinsic(destination: nil, name: "branch_vs", arguments: [.immediate(0x1010)]))
    }

    func testGELiteralOperationAndRenderedBytesAreUnchanged() {
        let function = pair("subs", "w0, w1, w2", suffix: "ge")
        let expected = MacIROperation.conditionalBranch(condition: ">=",
            left: .register(name: "w1", version: 0), right: .register(name: "w2", version: 0), target: .immediate(0x1010))
        XCTAssertEqual(function.instructions[1].operation, expected)
        var literalBaseline = function
        literalBaseline.instructions[1].operation = expected
        XCTAssertEqual(Array(PseudocodePrinter().print(function: function).text.utf8),
                       Array(PseudocodePrinter().print(function: literalBaseline).text.utf8))
    }

    func testTSTUsesLiteralLogicalResultRatherThanSubtraction() {
        let function = pair("tst", "w1, w2", word: 0x6a02003f)
        XCTAssertEqual(function.instructions[1].operation,
            .conditionalBranch(condition: "!=", left: .binaryExpression(op: "&",
                left: .unary(op: "(uint32_t)", value: .unary(op: "(int32_t)", value:
                    .binaryExpression(op: "&", left: .unary(op: "(uint32_t)", value: .register(name: "w1", version: 0)),
                                      right: .register(name: "w2", version: 0)))),
                right: .immediate(2147483648)), right: .immediate(0), target: .immediate(0x1010)))
    }

    func testANDSUncastLogicalResultKeepsRawMI() {
        XCTAssertEqual(pair("ands", "w0, w1, w2", word: 0x6a020020).instructions[1].operation,
            .intrinsic(destination: nil, name: "branch_mi", arguments: [.immediate(0x1010)]))
    }

    func testCMNAndADDSUseNegatedRightModuloSign() {
        let cases: [(String, String, UInt32)] = [
            ("cmn", "w1, w2", 0x2b02003f), ("adds", "w0, w1, w2", 0x2b020020)
        ]
        for (mnemonic, operands, word) in cases {
            let function = pair(mnemonic, operands, word: word)
            XCTAssertEqual(function.instructions[1].operation,
                .conditionalBranch(condition: "!=", left: .binaryExpression(op: "&",
                    left: .unary(op: "(uint32_t)", value: .binaryExpression(op: "-",
                        left: .unary(op: "(uint32_t)", value: .register(name: "w1", version: 0)),
                        right: .unary(op: "(uint32_t)", value: .unary(op: "-", value: .register(name: "w2", version: 0))))),
                    right: .immediate(2147483648)), right: .immediate(0), target: .immediate(0x1010)))
        }
    }

    func testOverwrittenSourceUsesPrewriteValue() {
        let function = pair("subs", "w1, w1, w2", word: 0x6b020021)
        XCTAssertEqual(function.instructions[1].operation,
            .conditionalBranch(condition: "!=", left: .binaryExpression(op: "&",
                left: .unary(op: "(uint32_t)", value: .binaryExpression(op: "-",
                    left: .unary(op: "(uint32_t)", value: .register(name: "w1", version: 0)),
                    right: .unary(op: "(uint32_t)", value: .register(name: "w2", version: 0)))),
                right: .immediate(2147483648)), right: .immediate(0), target: .immediate(0x1010)))
    }

    func testCCMPChainKeepsRawMI() {
        var state = BuilderState()
        let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
        _ = builder.operation(for: .init(address: 0x1000, byteText: "", mnemonic: "cmp", operands: "w1, #1"), state: &state)
        _ = builder.operation(for: .init(address: 0x1004, byteText: "", mnemonic: "ccmp", operands: "w2, #0, #0, ne"), state: &state)
        let result = builder.operation(for: .init(address: 0x1008, byteText: "", mnemonic: "b.mi", operands: "0x1010"), state: &state)
        XCTAssertEqual(result, .intrinsic(destination: nil, name: "branch_mi", arguments: [.immediate(0x1010)]))
    }

    func testExplicitRefusalGuardsKeepRawMI() {
        for refusal in 0...5 {
            var state = BuilderState()
            let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            let comparison = BuilderComparison(left: .register(name: "w1", version: 0),
                right: .immediate(1), sourceAddress: 0x1000)
            state.recordPlainComparison(comparison)
            switch refusal {
            case 0: state.lastAdjacentComparison = nil
            case 1: state.sawConditionalCompareSinceComparison = true
            case 2: state.flagsPhiContext = FlagsPhiContext(blockAddress: 0x1004, rowAddress: 0x1004,
                incomings: [(predecessorAddress: 0x1000, comparison: comparison)])
            case 3: state.lastAdjacentComparison?.left = .immediate(1)
            case 4: state.lastAdjacentComparison?.sourceAddress = nil
            default: state.lastComparison?.sourceAddress = 0x0ffc
            }
            let result = builder.operation(for: .init(address: 0x1004, byteText: "", mnemonic: "b.mi", operands: "0x1010"), state: &state)
            XCTAssertEqual(result, .intrinsic(destination: nil, name: "branch_mi", arguments: [.immediate(0x1010)]))
        }
    }
}
