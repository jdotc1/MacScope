import Foundation
import XCTest
@testable import MacScope

// No return authority is supplied by these fixtures.
final class SSAReturnProofFlagOnlyBranchTests: XCTestCase {
    private typealias Operation = (String, String)
    private let marker = MacIRValue.unknown(MacIRIndirectTargetResolution.unresolvedReturnContractMarker)

    private func rows(_ operations: [Operation]) -> [InstructionRow] {
        operations.enumerated().map { index, operation in
            InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "", mnemonic: operation.0,
                           operands: operation.1, hasBreakpoint: false, comment: nil)
        }
    }

    private func lift(_ operations: [Operation], ssa: Bool) -> MacIRFunction {
        MacIRBuilder(ssaEnabled: ssa).buildFunction(name: "ssa_flag_only", startAddress: 0x1000,
                                                 instructions: rows(operations))
    }

    private func returnValues(_ function: MacIRFunction) -> [MacIRValue?] {
        function.instructions.compactMap { instruction in
            guard case let .returnValue(value) = instruction.operation else { return nil }
            return .some(value)
        }
    }

    private func branchRows(_ mnemonic: String) -> [Operation] {
        [(mnemonic, "0x100c"), ("mov", "w0, #1"), ("ret", ""),
         ("mov", "w0, #0"), ("ret", "")]
    }

    private func assertReturns(_ operations: [Operation], ssa: Bool, admitted: Bool, count: Int,
                               file: StaticString = #filePath, line: UInt = #line) {
        let values = returnValues(lift(operations, ssa: ssa))
        XCTAssertEqual(values.count, count, file: file, line: line)
        for value in values {
            if admitted {
                XCTAssertNotNil(value, "producer evidence cannot establish void", file: file, line: line)
                XCTAssertNotEqual(value, marker, file: file, line: line)
            } else {
                XCTAssertEqual(value, marker, file: file, line: line)
            }
        }
    }

    // TC1/TC2: the existing testFlagOnlyBranchesPreserveKnownEdgesAndRefuseMissingEdges
    // pins these rows in the process-default mode; these modes are explicit.
    func testFlagOnlyBranchesAdmitBothReturnsInExplicitModes() {
        for suffix in ["mi", "pl", "vs", "vc"] {
            for ssa in [true, false] {
                assertReturns(branchRows("b.\(suffix)"), ssa: ssa, admitted: true, count: 2)
            }
        }
    }

    // TC3: the same existing test pins all five refusal neighbors.
    func testFiveRefusalFormsStayRefusedInSSA() {
        let branches: [Operation] = [
            ("b.pl", "0x5000"), ("b.mi", "unresolved_target"),
            ("b.invalid", "0x1004"), ("b.pl", "0x1004, x0"),
            // A suffix-list-only change would wrongly admit this row.
            ("b.invalid.pl", "0x1004"),
        ]
        for branch in branches {
            assertReturns([branch, ("mov", "w0, #1"), ("ret", "")],
                          ssa: true, admitted: false, count: 1)
        }
    }

    // TC4: new direct suffix coverage; cbz producer neighbors are already pinned by
    // testAllPathsImmediateAndLoadKeepBothReturns and testAllPathsImmediateAndArithmeticKeepBothReturns.
    func testAlreadyKnownSuffixesStayAdmittedInSSA() {
        for suffix in ["eq", "ne", "lt", "le", "gt", "ge", "hs", "cs", "lo", "cc", "hi", "ls"] {
            assertReturns(branchRows("b.\(suffix)"), ssa: true, admitted: true, count: 2)
        }
    }

    // TC5: new producer-proof coverage. testAlwaysConditionalBranchesDoNotReachSkippedCall
    // tests caller evidence instead, and does not establish producer acceptance.
    func testALAndNVStayRefusedInSSA() {
        for suffix in ["al", "nv"] {
            assertReturns(branchRows("b.\(suffix)"), ssa: true, admitted: false, count: 2)
        }
    }

    // TC6: new compare-before-flag-only-branch coverage. Scalar-FP result-bank
    // neighbors remain pinned by testLaterScalarFPResultDoesNotBorrowIntegerReturnContract.
    func testCompareBeforeFlagOnlyBranchInExplicitModes() {
        let operations: [Operation] = [
            ("cmp", "w1, #0"), ("b.mi", "0x1010"), ("mov", "w0, #1"),
            ("ret", ""), ("mov", "w0, #0"), ("ret", ""),
        ]
        for ssa in [true, false] {
            assertReturns(operations, ssa: ssa, admitted: true, count: 2)
        }
    }

    // TC8: marker parity, not lowered-value equality. New guard against helper drift.
    func testConditionalBranchMarkerParityAcrossExplicitModes() {
        for suffix in ["mi", "pl", "vs", "vc", "eq", "ne", "lt", "le", "gt", "ge",
                       "hs", "cs", "lo", "cc", "hi", "ls", "al", "nv", "invalid", "mi.mi", ""] {
            let operations = branchRows("b.\(suffix)")
            let on = returnValues(lift(operations, ssa: true))
            let off = returnValues(lift(operations, ssa: false))
            XCTAssertEqual(on.count, 2, suffix)
            XCTAssertEqual(off.count, 2, suffix)
            XCTAssertEqual(on.map { $0 == marker }, off.map { $0 == marker }, suffix)
        }
    }
}
