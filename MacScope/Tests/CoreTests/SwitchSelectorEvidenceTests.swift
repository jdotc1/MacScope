import Foundation
import XCTest
@testable import MacScope

final class SwitchSelectorEvidenceTests: XCTestCase {
    private func rows(_ assembly: [(String, String)], start: UInt64 = 0x1000) -> [InstructionRow] {
        assembly.enumerated().map { index, row in
            InstructionRow(address: start + UInt64(index * 4), bytes: "", mnemonic: row.0,
                           operands: row.1, hasBreakpoint: false, comment: nil)
        }
    }

    private func dispatch(_ function: MacIRFunction, at address: UInt64,
                          file: StaticString = #filePath, line: UInt = #line) throws -> MacIRInstruction {
        let matches = function.instructions.filter { $0.source.address == address }
        XCTAssertEqual(matches.count, 1, file: file, line: line)
        let instruction = try XCTUnwrap(matches.first, file: file, line: line)
        guard case .switchDispatch = instruction.operation else {
            XCTFail("Expected recovered switch at dispatch address", file: file, line: line)
            throw NSError(domain: "SwitchSelectorEvidenceFixture", code: 1)
        }
        return instruction
    }

    private func scalarRows() -> [InstructionRow] {
        rows([("sub", "w8, w0, #1"), ("cmp", "w8, #2"), ("b.hi", "0x2100"),
              ("adrp", "x9, 0x3000"), ("add", "x9, x9, #0"),
              ("ldrsw", "x8, [x9, x8, lsl #2]"), ("add", "x8, x9, x8"),
              ("br", "x8")], start: 0x2000)
    }

    private func region(_ input: [InstructionRow], tables: [UInt64: [UInt64]]) throws -> MacIRFunction {
        try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "selector_region", startAddress: 0x1000,
                rows: input, initialState: BuilderState(parameters: []), jumpTables: tables,
                hasExternalFacts: false, isVariadic: false))
    }

    // SC1: the bounds-branch capture point is CMP, not the prior SUB or reused target.
    func testSC1ScalarBoundsBranchRecordsCapturePoint() throws {
        let function = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false)
            .buildFunction(name: "scalar_selector", startAddress: 0x2000,
                jumpTables: [0x201c: [0x2040, 0x2050, 0x2060]], instructions: scalarRows())
        let instruction = try dispatch(function, at: 0x201c)
        XCTAssertEqual(instruction.source.switchSelector,
                       MacIRSwitchSelectorEvidence(definitionAddress: 0x2004, register: "w8"))
    }

    // SC2: all targets are owned rows; assert the SSA result, not ambient configuration.
    func testSC2SSABoundsBranchRecordsCapturePoint() throws {
        let input = rows([("sub", "w8, w0, #6"), ("cmp", "w8, #9"), ("b.hi", "0x1028"),
            ("adrp", "x9, 0x2000"), ("add", "x9, x9, #0"), ("adr", "x10, 0x1024"),
            ("ldrb", "w11, [x9, x8]"), ("add", "x10, x10, x11, lsl #2"),
            ("br", "x10"), ("ret", ""), ("ret", "")])
        let function = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true)
            .buildFunction(name: "ssa_selector", startAddress: 0x1000,
                jumpTables: [0x1020: [0x1024, 0x1024, 0x1024, 0x1024, 0x1024,
                                      0x1024, 0x1024, 0x1024, 0x1024, 0x1024]], instructions: input)
        XCTAssertTrue(function.ssaEnabled, "Fixture must exercise the SSA path")
        XCTAssertEqual(try dispatch(function, at: 0x1020).source.switchSelector,
                       MacIRSwitchSelectorEvidence(definitionAddress: 0x1004, register: "w8"))
    }

    // SC3: the post-CSEL value is captured at the clamping write.
    func testSC3ScalarClampRecordsSelect() throws {
        let input = rows([("cmp", "x16, #2"), ("csel", "x16, x16, xzr, ls"),
            ("adrp", "x17, 0x3000"), ("add", "x17, x17, #0"),
            ("ldr", "x16, [x17, x16, lsl #3]"), ("br", "x16")], start: 0x2800)
        let function = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false)
            .buildFunction(name: "clamp_selector", startAddress: 0x2800,
                jumpTables: [0x2814: [0x2840, 0x2850, 0x2860]], instructions: input)
        XCTAssertEqual(try dispatch(function, at: 0x2814).source.switchSelector,
                       MacIRSwitchSelectorEvidence(definitionAddress: 0x2804, register: "x16"))
    }

    // SC4: D06's first nine rows; only a case-local loop follows the selector capture.
    func testSC4RegionBoundsBranchWithoutSelectorBackEdgeRecordsCapturePoint() throws {
        let input = rows([("mov", "w3, w0"), ("cmp", "w3, #1"), ("b.hi", "0x1040"),
            ("mov", "w8, w3"), ("adr", "x9, 0x2000"), ("adr", "x10, 0x1024"),
            ("ldrb", "w11, [x9, x8]"), ("add", "x10, x10, x11, lsl #2"), ("br", "x10"),
            ("add", "v0.8h, v0.8h, v1.8h"), ("b", "0x1034"),
            ("eor", "v0.16b, v0.16b, v2.16b"), ("b", "0x1034"),
            ("subs", "w4, w4, #1"), ("b.ne", "0x1034"), ("b", "0x1040"), ("ret", "")])
        let function = try region(input, tables: [0x1020: [0x1024, 0x102c]])
        XCTAssertEqual(try dispatch(function, at: 0x1020).source.switchSelector,
                       MacIRSwitchSelectorEvidence(definitionAddress: 0x1004, register: "w3"))
    }

    // SC5: signedGuard's dispatch prefix; a case-local loop admits the region without a selector phi.
    func testSC5RegionBoundedRangeRecordsRowBeforeIndexLoad() throws {
        let input = rows([("cmp", "w0, #16"), ("b.ge", "0x102c"),
            ("subs", "w1, w0, #1"), ("b.lt", "0x102c"),
            ("adrp", "x9, 0x2000"), ("add", "x9, x9, #0"), ("adr", "x10, 0x1028"),
            ("ldrb", "w11, [x9, x1]"), ("add", "x10, x10, x11, lsl #2"),
            ("br", "x10"), ("add", "v0.8h, v0.8h, v1.8h"), ("b", "0x1030"),
            ("subs", "w4, w4, #1"), ("b.ne", "0x1030"), ("ret", "")])
        let tables: [UInt64: [UInt64]] = [0x1024: [0x1028, 0x1028, 0x1028, 0x1028, 0x1028,
            0x1028, 0x1028, 0x1028, 0x1028, 0x1028, 0x1028, 0x1028, 0x1028, 0x1028, 0x1028]]
        XCTAssertNil(JumpTableResolver.proveSelector(rows: input, dispatchIndex: 9))
        let proof = try XCTUnwrap(JumpTableResolver.proveRegionSelector(
            rows: input, dispatchIndex: 9, jumpTables: tables))
        XCTAssertEqual(proof.guardKind, .boundedRange)
        XCTAssertEqual(proof.caseCount, 15)
        XCTAssertEqual(proof.definitionAddress, 0x1018)
        XCTAssertEqual(proof.register, "x1")
        let function = try region(input, tables: tables)
        XCTAssertEqual(try dispatch(function, at: 0x1024).source.switchSelector,
                       MacIRSwitchSelectorEvidence(definitionAddress: 0x1018, register: "x1"))
    }

    // SC6: a table hint is not a selector proof, and ordinary rows acquire no evidence.
    func testSC6NoProofPlainBranchAndNonBranchRowsHaveNoEvidence() throws {
        let input = rows([("br", "x8")], start: 0x3000)
        let builder = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false)
        let hinted = builder.buildFunction(name: "unproven_selector", startAddress: 0x3000,
            jumpTables: [0x3000: [0x3040, 0x3050]], instructions: input)
        let instruction = try dispatch(hinted, at: 0x3000)
        XCTAssertNil(instruction.source.switchSelector)
        guard case let .switchDispatch(index, _, _) = instruction.operation else { return XCTFail("Switch missing") }
        XCTAssertEqual(index, .unknown("unproven_switch_selector"))
        let plain = builder.buildFunction(name: "plain_branch", startAddress: 0x3000, instructions: input)
        XCTAssertTrue(plain.instructions.allSatisfy { $0.source.switchSelector == nil })
        let proven = builder.buildFunction(name: "nonbranch_rows", startAddress: 0x2000,
            jumpTables: [0x201c: [0x2040, 0x2050, 0x2060]], instructions: scalarRows())
        XCTAssertFalse(proven.instructions.filter { $0.source.mnemonic != "br" }.isEmpty)
        XCTAssertTrue(proven.instructions.filter { $0.source.mnemonic != "br" }
            .allSatisfy { $0.source.switchSelector == nil })
    }
}
