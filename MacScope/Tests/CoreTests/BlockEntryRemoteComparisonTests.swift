import XCTest
@testable import MacScope

final class BlockEntryRemoteComparisonTests: XCTestCase {
    private enum FixtureError: Error { case comparison }
    private func rows(_ assembly: [(String, String)]) -> [InstructionRow] {
        assembly.enumerated().map { index, item in
            InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "00 00 00 00",
                           mnemonic: item.0, operands: item.1, hasBreakpoint: false, comment: nil)
        }
    }

    private func lift(_ rows: [InstructionRow]) -> MacIRFunction {
        MacIRBuilder(ssaEnabled: true).buildFunction(name: "ssa_remote", startAddress: rows[0].address,
                                                   callerReturnWidth: .x0, instructions: rows)
    }

    private func operation(_ function: MacIRFunction, at address: UInt64) throws -> MacIROperation {
        try XCTUnwrap(function.instructions.first { $0.source.address == address }?.operation)
    }

    private func comparison(_ function: MacIRFunction, at address: UInt64 = 0x1000) throws -> [MacIRValue] {
        guard case let .intrinsic(nil, "compare", operands) = try operation(function, at: address),
              operands.count == 2 else {
            XCTFail("expected a two-operand compare producer")
            throw FixtureError.comparison
        }
        return operands
    }

    private func solePredecessor(_ branch: String) -> [InstructionRow] {
        rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"), ("bl", "_opaque"),
              ("ret", ""), (branch, "0x1018"), ("mov", "x0, #3"), ("ret", "")])
    }

    func testRemoteSolePredecessorLTUsesExactComparison() throws {
        let function = lift(solePredecessor("b.lt"))
        let operands = try comparison(function)
        XCTAssertEqual(try operation(function, at: 0x1010), .conditionalBranch(
            condition: "<", left: operands[0], right: operands[1], target: .immediate(0x1018)))
    }

    func testRemoteSolePredecessorEQIsAlreadyPresented() throws {
        let function = lift(solePredecessor("b.eq"))
        let operands = try comparison(function)
        XCTAssertEqual(try operation(function, at: 0x1010), .conditionalBranch(
            condition: "==", left: operands[0], right: operands[1], target: .immediate(0x1018)))
        XCTAssertEqual(PseudocodePrinter.ssaComparisonPresentation(of: function), function)
    }

    func testMultiplePredecessorsAgreeOnOneDefinition() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("mov", "x2, #2"), ("mov", "x3, #3"), ("b.lt", "0x1018"),
            ("mov", "x0, #3"), ("ret", "")]))
        let operands = try comparison(function)
        XCTAssertEqual(try operation(function, at: 0x1010), .conditionalBranch(
            condition: "<", left: operands[0], right: operands[1], target: .immediate(0x1018)))
    }

    func testCallOnOneIncomingPathKeepsBranchRaw() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("nop", ""), ("b.lt", "0x1018"),
            ("mov", "x0, #3"), ("ret", "")]))
        XCTAssertEqual(try operation(function, at: 0x1010),
            .intrinsic(destination: nil, name: "branch_lt", arguments: [.immediate(0x1018)]))
    }

    func testUnestablishedBackEdgeKeepsBranchRaw() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("add", "x2, x2, #1"),
            ("b.lt", "0x1004"), ("ret", "")]))
        XCTAssertEqual(try operation(function, at: 0x1008),
            .intrinsic(destination: nil, name: "branch_lt", arguments: [.immediate(0x1004)]))
    }

    func testLocalComparisonReplacesRemoteCarry() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("ret", ""), ("cmp", "w2, #2"),
            ("b.lt", "0x101c"), ("mov", "x0, #3"), ("ret", "")]))
        let operands = try comparison(function, at: 0x1010)
        // The adjacent compare keeps its signed W-view projection on the left operand.
        guard case let .conditionalBranch("<", left, right, .immediate(0x101c)) = try operation(function, at: 0x1014) else {
            return XCTFail("local compare must drive the branch")
        }
        XCTAssertEqual(right, operands[1])
        XCTAssertTrue(String(describing: left).hasPrefix(String(describing: operands[0]) + " "))
    }

    func testConditionalCompareDefinitionIsNotCarried() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("ccmp", "w3, #2, #0, ne"),
            ("cbz", "x0, 0x1014"), ("bl", "_opaque"), ("ret", ""),
            ("b.lt", "0x101c"), ("mov", "x0, #3"), ("ret", "")]))
        XCTAssertEqual(try operation(function, at: 0x1014),
            .intrinsic(destination: nil, name: "branch_lt", arguments: [.immediate(0x101c)]))
    }

    func testLogicalFlagsDoNotAcquireUnsignedCondition() throws {
        let function = lift(rows([("tst", "w1, w2"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("ret", ""), ("b.hs", "0x1018"),
            ("mov", "x0, #3"), ("ret", "")]))
        XCTAssertEqual(try operation(function, at: 0x1010),
            .intrinsic(destination: nil, name: "branch_hs", arguments: [.immediate(0x1018)]))
    }

    func testRemoteCsetSharesCarry() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("ret", ""), ("cset", "w2, lt"), ("ret", "")]))
        guard case .compareToBool(_, "<", _, _) = try operation(function, at: 0x1010) else {
            return XCTFail("remote cset must use the carried comparison")
        }
    }

    func testRemoteCselSharesCarry() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("ret", ""), ("csel", "x3, x4, x5, lt"), ("ret", "")]))
        guard case .select(_, "<", _, _, _, _) = try operation(function, at: 0x1010) else {
            return XCTFail("remote csel must use the carried comparison")
        }
    }

    func testRemoteCnegSharesCarry() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("ret", ""), ("cneg", "w2, w3, mi"), ("ret", "")]))
        guard case .select(_, "!=", _, .immediate(0), _, _) = try operation(function, at: 0x1010) else {
            return XCTFail("remote cneg must test the carried subtraction result sign")
        }
    }

    func testFlagOffDoesNotEnterSSADriver() {
        let fixture = solePredecessor("b.lt")
        let function = MacIRBuilder(ssaEnabled: false).buildFunction(name: "ssa_remote",
            startAddress: fixture[0].address, callerReturnWidth: .x0, instructions: fixture)
        XCTAssertFalse(function.ssaEnabled)
        XCTAssertNil(function.ssaInfo)
    }

    func testUnavailableComparisonOperandCannotBeCarried() throws {
        let function = lift(rows([("bl", "_opaque"), ("cmp", "w1, #1"),
            ("cbz", "x19, 0x1014"), ("bl", "_opaque"), ("ret", ""),
            ("b.lt", "0x101c"), ("mov", "x0, #3"), ("ret", "")]))
        let operands = try comparison(function, at: 0x1004)
        guard case .unknown = operands[0] else {
            return XCTFail("call-clobbered W1 must be an unavailable comparison operand")
        }
        XCTAssertEqual(try operation(function, at: 0x1014),
            .intrinsic(destination: nil, name: "branch_lt", arguments: [.immediate(0x101c)]))
    }

    func testRemoteCMNRetainsCarryMetadata() throws {
        for (suffix, condition) in [("hs", ">"), ("lo", "<=")] {
            let function = lift(rows([("cmn", "x1, #1"), ("cbz", "x0, 0x1010"),
                ("bl", "_opaque"), ("ret", ""), ("b." + suffix, "0x1018"),
                ("mov", "x0, #3"), ("ret", "")]))
            let operands = try comparison(function)
            XCTAssertEqual(try operation(function, at: 0x1010), .conditionalBranch(
                condition: condition, left: .unary(op: "(uint64_t)", value: operands[0]),
                right: .unary(op: "(uint64_t)", value: .unary(op: "~",
                    value: .unary(op: "(uint64_t)", value: .immediate(1)))), target: .immediate(0x1018)))
        }
    }

    func testRemoteEntryCCMPDoesNotGainAdjacency() throws {
        let function = lift(rows([("cmp", "w1, #1"), ("cbz", "x0, 0x1010"),
            ("bl", "_opaque"), ("ret", ""), ("ccmp", "w3, #2, #0, ne"),
            ("b.lt", "0x101c"), ("mov", "x0, #3"), ("ret", "")]))
        XCTAssertEqual(try operation(function, at: 0x1014),
            .intrinsic(destination: nil, name: "branch_lt", arguments: [.immediate(0x101c)]))
    }
}
