import XCTest
@testable import MacScope

/// Source-only definitions. Removing the SSA chain arm must break A–E.
final class ConditionalCompareChainTests: XCTestCase {
    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: "00 00 00 00", mnemonic: mnemonic, operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func text(ssa: Bool, _ rows: [InstructionRow]) -> String {
        let function = MacIRBuilder(ssaEnabled: ssa).buildFunction(name: "_pending", instructions: rows)
        return PseudocodePrinter().print(function: function).text
    }

    // DC.testConditionalCompareAndCompoundStructuresAndSuppressesSourceRows pins the one-link neighbor.
    // Each prefix row advances four bytes; target MOV follows RET, then B returns to RET.
    private func branchRows(_ prefix: [InstructionRow], suffix: String = "ne") -> [InstructionRow] {
        let branch = UInt64(0x1000) + UInt64(prefix.count) * 4
        return prefix + [row(branch, "b.\(suffix)", "0x\(String(branch + 8, radix: 16))"),
            row(branch + 4, "ret", ""), row(branch + 8, "mov", "x0, #0x1"),
            row(branch + 12, "b", "0x\(String(branch + 4, radix: 16))")]
    }

    private var two: [InstructionRow] { [
        row(0x1000, "cmp", "x0, #0x0"),
        row(0x1004, "ccmp", "x1, #0x1, #0x0, eq"),
        row(0x1008, "ccmp", "x2, #0x2, #0x0, eq")
    ] }

    private func noHelpers(_ out: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(out.contains("__branch_ne"), out, file: file, line: line)
        XCTAssertFalse(out.contains("__compare("), out, file: file, line: line)
        XCTAssertFalse(out.contains("__conditional_compare"), out, file: file, line: line)
    }

    func testATwoConditionalCompares() {
        let out = text(ssa: true, branchRows(two))
        // B.conditionHolds(ne,0)=true at both levels: inv(eq)=ne, OR twice.
        // PP.renderCompoundCondition wraps the nested left compound (PP:6113–6136).
        XCTAssertTrue(out.contains("if (((arg0 != 0x0) || (x1_0 != 0x1)) || (x2_0 != 0x2))"), out)
        noHelpers(out)
    }

    func testBThreeConditionalCompares() {
        let out = text(ssa: true, branchRows(two + [row(0x100c, "ccmp", "x3, #0x3, #0x0, eq")]))
        // Cond3(ne)=Cond2(ne)||(x3!=3); Cond2 is A, same PP nesting rule.
        XCTAssertTrue(out.contains("if ((((arg0 != 0x0) || (x1_0 != 0x1)) || (x2_0 != 0x2)) || (x3_0 != 0x3))"), out)
        noHelpers(out)
    }

    func testCMixedAndOr() {
        let out = text(ssa: true, branchRows([
            row(0x1000, "cmp", "x0, #0x0"),
            row(0x1004, "ccmp", "x1, #0x0, #0x0, ne"),
            row(0x1008, "ccmp", "x2, #0x0, #0x0, ne")], suffix: "eq"))
        // Cond2(eq)=Cond1(ne)&&(x2==0); Cond1(ne)=Cond0(eq)||(x1!=0).
        // DC.testConditionalCompareNegativeSubsetFallsBack pins these rows with SSA off.
        XCTAssertTrue(out.contains("((arg0 == 0x0) || (x1_0 != 0x0)) && (x2_0 == 0x0)"), out)
        XCTAssertFalse(out.contains("__branch_eq"), out)
        noHelpers(out)
    }

    func testDCsetConsumer() {
        let out = text(ssa: true, [row(0x1000, "cmp", "w0, #0x1"),
            row(0x1004, "ccmp", "w1, #0x2, #0x0, ne"),
            row(0x1008, "ccmp", "w2, #0x3, #0x0, ne"),
            row(0x100c, "cset", "w3, eq"), row(0x1010, "ret", "")])
        // Same recurrence as C, constants 1,2,3; R7.testThreeDeepCcmpChainVetoesCompoundCset.
        XCTAssertTrue(out.contains("((arg0 == 0x1) || (w1_0 != 0x2)) && (w2_0 == 0x3)"), out)
        XCTAssertFalse(out.contains("__unknown(\"cset\""), out)
        noHelpers(out)
    }

    func testENeutralRowBeforeSecondConditionalCompare() {
        let out = text(ssa: true, branchRows([two[0], two[1],
            row(0x1008, "mov", "x9, #0x7d"), row(0x100c, "ccmp", "x2, #0x2, #0x0, eq")]))
        // RE:944–957 protects the still-top first ccmp; x9 is not x0/x1. Same A recurrence.
        // PT.testCmpLslCcmpCsetLiftsCompoundConditionUnderSSA pins neutral carry for one link.
        XCTAssertTrue(out.contains("if (((arg0 != 0x0) || (x1_0 != 0x1)) || (x2_0 != 0x2))"), out)
        noHelpers(out)
    }

    func testFFlagWriterBreak() {
        let out = text(ssa: true, branchRows([two[0], two[1],
            row(0x1008, "adcs", "x7, x7, xzr"), row(0x100c, "ccmp", "x2, #0x2, #0x0, eq")]))
        // B:641 clears pending; RE:986–993 and the allowlist do not restore ADCS.
        // PT.testInterveningNZCVWriterClearsPendingComparison pins the adjacent neighbor.
        XCTAssertTrue(out.contains("__conditional_compare_eq("), out)
        XCTAssertFalse(out.contains("(x1_0 != 0x1)"), out)
    }

    func testGNonAllowlistedBreak() {
        let out = text(ssa: true, branchRows([two[0], two[1],
            row(0x1008, "fmov", "d0, x9"), row(0x100c, "ccmp", "x2, #0x2, #0x0, eq")]))
        // RE:935–941 excludes FMOV; B:1783 cannot restart without an adjacent compare.
        XCTAssertTrue(out.contains("__conditional_compare_eq("), out)
        XCTAssertTrue(out.contains("__branch_ne("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testHLengthOneAndFlagOffControls() {
        let on = text(ssa: true, branchRows([row(0x1000, "cmp", "x0, #0x0"),
            row(0x1004, "ccmp", "x1, #0x0, #0x0, ne")], suffix: "eq"))
        // Earlier empty: original B:3955–4026 body, conditionHolds(eq,0)=false => AND.
        XCTAssertTrue(on.contains("if ((arg0 != 0x0) && (x1_0 == 0x0))"), on)
        let off = text(ssa: false, branchRows(two))
        // DC.testConditionalCompareNegativeSubsetFallsBack: extension requires SSA.
        XCTAssertTrue(off.contains("__conditional_compare_eq("), off)
        XCTAssertFalse(off.contains("||"), off)
    }

    func testIInvalidSecondGuard() {
        let out = text(ssa: true, branchRows([two[0], two[1], row(0x1008, "ccmp", "x2, #0x2, #0x0, al")]))
        // Original builder guard B:3789–3794 reused: AL declines pending, intrinsic survives.
        XCTAssertTrue(out.contains("__conditional_compare_al("), out)
        XCTAssertTrue(out.contains("__branch_ne("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testJNinthConditionalCompareRefuses() {
        var prefix = [row(0x1000, "cmp", "x0, #0x0")]
        for n in 1...9 { prefix.append(row(0x1000 + UInt64(n) * 4, "ccmp", "x\(n), #\(n), #0x0, eq")) }
        let out = text(ssa: true, branchRows(prefix))
        // Earlier.count+2 <= 8 fails at ninth row; B:641 leaves pending cleared.
        XCTAssertTrue(out.contains("__branch_ne("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testEightConditionalComparesLift() {
        var prefix = [row(0x1000, "cmp", "x0, #0x0")]
        for n in 1...8 { prefix.append(row(0x1000 + UInt64(n) * 4, "ccmp", "x\(n), #\(n), #0x0, eq")) }
        let out = text(ssa: true, branchRows(prefix))
        // Eight admitted: all fallback NZCV=0 make NE true, so eight nested OR operators.
        XCTAssertTrue(out.contains("(x8_0 != 0x8)"), out)
        XCTAssertEqual(out.components(separatedBy: " || ").count - 1, 8, out)
        noHelpers(out)
    }

    func testStandaloneGapAfterSecondRefusesEvenNeutralWrite() {
        let out = text(ssa: true, branchRows(two + [row(0x100c, "mov", "x1, #0x7d")]))
        // Q8 standalone: RE does not protect earlier links. Any gap after ccmp2 refuses.
        XCTAssertTrue(out.contains("__branch_ne("), out)
        XCTAssertTrue(out.contains("__conditional_compare_eq("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testUnequalGuardsAndFallbackPolarity() {
        let out = text(ssa: true, branchRows([two[0], two[1],
            row(0x1008, "ccmp", "x2, #0x2, #0x4, lt")], suffix: "eq"))
        // EQ(#4)=true: Cond1(ge)||(x2==2). GE(#0)=true: Cond0(ne)||(x1>=1).
        // Signed projection is requested by SSA; only pin operators/operand immediates here.
        XCTAssertFalse(out.contains("__branch_eq("), out)
        XCTAssertTrue(out.contains("||"), out)
        XCTAssertTrue(out.contains("(x2_0 == 0x2)"), out)
    }

    func testCselConsumer() {
        let out = text(ssa: true, two + [row(0x100c, "csel", "x3, x4, x5, ne"), row(0x1010, "ret", "")])
        // Same Cond2(ne) as A, consumed by B.conditionalSelectOperation.
        XCTAssertTrue(out.contains("((in_x0 != 0x0) || (x1_0 != 0x1)) || (x2_0 != 0x2)"), out)
        XCTAssertFalse(out.contains("__unknown(\"csel\""), out)
        noHelpers(out)
    }

    func testUnliftedFinalFlagsReaderKeepsHelpers() {
        let out = text(ssa: true, two + [row(0x100c, "cset", "w3, ne"),
            row(0x1010, "adc", "x7, x8, x9"), row(0x1014, "ret", "")])
        // CSET records the chain; ADC still reads final NZCV, so SSA reader verdict vetoes elision.
        // CCE.testCcmpFlagsReadByUnliftedConsumerKeepsChain is named-only, full body not supplied.
        XCTAssertTrue(out.contains("__compare("), out)
        XCTAssertTrue(out.contains("__conditional_compare_eq("), out)
        XCTAssertTrue(out.contains("((arg0 != 0x0) || (x1_0 != 0x1)) || (x2_0 != 0x2)"), out)
    }

    func testCallBreak() {
        let out = text(ssa: true, branchRows([two[0], two[1], row(0x1008, "bl", "0x2000"),
            row(0x100c, "ccmp", "x2, #0x2, #0x0, eq")]))
        // ST:732–735 invalidates comparison state at calls; the old prefix cannot enter a compound.
        XCTAssertTrue(out.contains("__conditional_compare_eq("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testBlockEntryBreak() {
        let out = text(ssa: true, branchRows([row(0x1000, "cbz", "x5, 0x100c"),
            row(0x1004, "cmp", "x0, #0x0"), row(0x1008, "ccmp", "x1, #0x1, #0x0, eq"),
            row(0x100c, "ccmp", "x2, #0x2, #0x0, eq")]))
        // SSA:811 resets pending at the target block. PT.testBlockBoundaryBetweenCmpAndCsetClearsPendingComparison.
        XCTAssertTrue(out.contains("__conditional_compare_eq("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testLevelTwoOperandAndNzcvRefusals() {
        for operands in ["x2, #0x2, #0x10, eq", "#0x2, x2, #0x0, eq", "x2, #0x2, #0x0, nv"] {
            let out = text(ssa: true, branchRows([two[0], two[1], row(0x1008, "ccmp", operands)]))
            // B.conditionalCompare original operand/NZCV/guard validation reused at level 2.
            XCTAssertFalse(out.contains("||"), out)
        }
    }

    func testTstFirstGuardRemainsRestrictedButLaterGuardIsArithmetic() {
        let bad = text(ssa: true, branchRows([row(0x1000, "tst", "x0, x4"),
            row(0x1004, "ccmp", "x1, #0x1, #0x0, lt"),
            row(0x1008, "ccmp", "x2, #0x2, #0x0, eq")], suffix: "eq"))
        // B:3795–3799: TST level-1 guard LT has no first pending; level 2 cannot restart.
        XCTAssertTrue(bad.contains("__branch_eq("), bad)
        XCTAssertFalse(bad.contains("&&"), bad)
        let good = text(ssa: true, branchRows([row(0x1000, "tst", "x0, x4"),
            row(0x1004, "ccmp", "x1, #0x1, #0x0, eq"),
            row(0x1008, "ccmp", "x2, #0x2, #0x0, lt")], suffix: "eq"))
        // Cond2(eq)=Cond1(lt)&&(x2==2); Cond1(lt)=Cond0(eq)&&(x1<1).
        // TST's only requested suffix is EQ; the later LT sees CCMP flags, so is legal.
        XCTAssertFalse(good.contains("__branch_eq("), good)
        XCTAssertTrue(good.contains("(x2_0 == 0x2)"), good)
        XCTAssertTrue(good.contains("&&"), good)
        noHelpers(good)
    }

    func testCcmnLevelTwoCarryGate() {
        for addend in ["x4", "#0x0"] {
            let out = text(ssa: true, branchRows([two[0], two[1],
                row(0x1008, "ccmn", "x2, \(addend), #0x0, eq")], suffix: "hi"))
            // B:3873–3880: carry relations need an immediate nonzero addend.
            XCTAssertTrue(out.contains("__branch_hi("), out)
            XCTAssertFalse(out.contains("&&"), out)
        }
        let one = text(ssa: true, branchRows([two[0], two[1],
            row(0x1008, "ccmn", "x2, #0x1, #0x0, eq")], suffix: "hi"))
        // HI(#0)=false. +1 is carry-equivalent: Cond1(eq) && unsigned(x2)>unsigned(-1).
        XCTAssertFalse(one.contains("__branch_hi("), one)
        XCTAssertTrue(one.contains("&&"), one)
        noHelpers(one)
    }

    func testCcmnEarlierLinkChecksTheRequestedGuard() {
        let out = text(ssa: true, branchRows([two[0],
            row(0x1004, "ccmn", "x1, x4, #0x0, eq"),
            row(0x1008, "ccmp", "x2, #0x2, #0x0, lt")], suffix: "eq"))
        // EQ(#0)=false requests LT on CCMN1; register addend has no signed-V equivalence.
        XCTAssertTrue(out.contains("__branch_eq("), out)
        XCTAssertFalse(out.contains("&&"), out)
    }

    func testCcmnEqualityAndCmnFirstComparison() {
        let out = text(ssa: true, branchRows([row(0x1000, "cmn", "x0, #0x1"),
            row(0x1004, "ccmp", "x1, #0x1, #0x0, eq"),
            row(0x1008, "ccmn", "x2, x4, #0x0, eq")], suffix: "eq"))
        // Cond2(eq)=Cond1(eq)&&CCMN2(eq), Cond1(eq)=CMN0(eq)&&(x1==1).
        // EQ addition gates allow register addends; compoundComparisonTerm emits modular casts.
        XCTAssertFalse(out.contains("__branch_eq("), out)
        XCTAssertTrue(out.contains("(x1_0 == 0x1)"), out)
        XCTAssertTrue(out.contains("&&"), out)
        noHelpers(out)
    }

    func testTwoIndependentChainsBothElide() {
        let out = text(ssa: true, two + [row(0x100c, "cset", "x10, ne"),
            row(0x1010, "cmp", "x4, #0x4"), row(0x1014, "ccmp", "x5, #0x5, #0x0, eq"),
            row(0x1018, "ccmp", "x6, #0x6, #0x0, eq"), row(0x101c, "cset", "x11, ne"),
            row(0x1020, "ret", "")])
        // Each chain's NZCV definitions have only its own next links and lifted consumer.
        // Row verdicts are ANDed per address, not overwritten by a different chain.
        XCTAssertTrue(out.contains("((in_x0 != 0x0) || (x1_0 != 0x1)) || (x2_0 != 0x2)"), out)
        XCTAssertTrue(out.contains("((in_x4 != 0x4) || (x5_0 != 0x5)) || (x6_0 != 0x6)"), out)
        noHelpers(out)
    }

    func testStandaloneGapBetweenSecondAndThirdRefuses() {
        let out = text(ssa: true, branchRows(two + [row(0x100c, "mov", "x1, #0x7d"),
            row(0x1010, "ccmp", "x3, #0x3, #0x0, eq")]))
        // Recursing through link 3 checks the link-2 to link-3 gap before forming any compound.
        XCTAssertTrue(out.contains("__branch_ne("), out)
        XCTAssertFalse(out.contains("||"), out)
    }

    func testMiPlVsVcConsumersKeepRawChain() {
        for suffix in ["mi", "pl", "vs", "vc"] {
            let out = text(ssa: true, branchRows(two, suffix: suffix))
            // B.conditionHolds and branchCondition do not support these suffixes.
            XCTAssertTrue(out.contains("__branch_\(suffix)("), out)
            XCTAssertFalse(out.contains("||"), out)
        }
    }
}
