import XCTest
@testable import MacScope

/// Source-authored regression definitions.
final class PendingComparisonMemoryRowsTests: XCTestCase {
    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: "00 00 00 00", mnemonic: mnemonic, operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func text(ssa: Bool, _ rows: [InstructionRow]) -> String {
        let function = MacIRBuilder(ssaEnabled: ssa).buildFunction(name: "_pending", instructions: rows)
        return PseudocodePrinter().print(function: function).text
    }

    private func branchRows(_ body: [(String, String)], suffix: String = "eq") -> [InstructionRow] {
        var rows = body.enumerated().map { row(0x1000 + UInt64($0.offset) * 4, $0.element.0, $0.element.1) }
        let next = 0x1000 + UInt64(body.count) * 4
        rows += [row(next, "b.\(suffix)", "0x1100"), row(next + 4, "ret", ""), row(0x1100, "ret", "")]
        return rows
    }

    private func assertCompound(_ body: [(String, String)], suffix: String = "eq", file: StaticString = #filePath, line: UInt = #line) {
        let on = text(ssa: true, branchRows(body, suffix: suffix))
        XCTAssertFalse(on.contains("__branch_\(suffix)("), on, file: file, line: line)
        XCTAssertFalse(on.contains("__conditional_compare_"), on, file: file, line: line)
    }

    private func assertRaw(_ body: [(String, String)], file: StaticString = #filePath, line: UInt = #line) {
        let on = text(ssa: true, branchRows(body))
        XCTAssertTrue(on.contains("__branch_eq("), on, file: file, line: line)
    }

    // Neighbor: PT.testCmpLslCcmpCsetLiftsCompoundConditionUnderSSA.
    func test40572ScalarStackLoadBeforeCcmp() {
        assertCompound([("cmp", "w26, #0x10"), ("ldr", "x1, [sp, #0x18]"),
                        ("ccmp", "x25, x1, #0x2, ge")], suffix: "ls")
    }

    // Neighbor: same PT positive; no existing supplied pair-load fixture.
    func test53122PairAndScalarLoadsAfterCcmp() {
        assertCompound([("cmp", "w6, w8"), ("ccmp", "w6, w22, #0x2, eq"),
                        ("mov", "x30, x19"), ("ldp", "w3, w5, [x29, #-0xb8]"),
                        ("ldr", "w7, [x29, #-0xb0]")], suffix: "hs")
    }

    // Neighbor: PT.testInterveningNZCVWriterClearsPendingComparison.
    func test42000SubsStoreAndLoadBeforeCcmp() {
        assertCompound([("subs", "w8, w8, w21"), ("stp", "w8, w9, [x19, #0x70]"),
                        ("ldr", "w10, [x22, #0x160]"), ("ccmp", "w9, w10, #0x0, eq")], suffix: "lt")
    }

    func testStoreSourceMayBeComparedRegister() {
        assertCompound([("cmp", "w0, #0x1"), ("str", "w0, [x3]"), ("ccmp", "w2, #0x3, #0x0, ne")])
    }

    // Neighbor: PT.testInterveningWriteToComparedRegisterClearsPendingComparison.
    func testLoadDestinationComparedByFirstOrSecondTermRefuses() {
        assertRaw([("cmp", "w0, #0x1"), ("ldr", "w0, [x3]"), ("ccmp", "w2, #0x3, #0x0, ne")])
        assertRaw([("cmp", "w0, #0x1"), ("ccmp", "w2, #0x3, #0x0, ne"), ("ldr", "w2, [x3]")])
        assertRaw([("cmp", "w0, #0x1"), ("ldp", "w4, w0, [x3]"), ("ccmp", "w2, #0x3, #0x0, ne")])
        assertRaw([("cmp", "w0, #0x1"), ("ccmp", "w2, #0x3, #0x0, ne"), ("ldpsw", "x4, x2, [x3]")])
    }

    func testEveryWritebackRefuses() {
        for transfer in [("ldr", "x2, [x3, #8]!"), ("ldr", "x2, [x3], #8"),
                         ("stp", "x1, x2, [x3, #0x10]!"), ("str", "x0, [x1], #8")] {
            assertRaw([("cmp", "w0, #0x1"), transfer, ("ccmp", "w4, #0x3, #0x0, ne")])
        }
    }

    // Neighbor: FC.testInterveningRowsCannotReuseFCMPOrEarlierIntegerFlags
    // pins FP invalidation, not these integer-memory shapes.
    func testUnsupportedAndUnparseableDestinationsRefuse() {
        for transfer in [("ldxr", "x2, [x3]"), ("ldadd", "x2, x4, [x3]"),
                         ("stxr", "w2, x4, [x3]"), ("ldr", "d0, [x1]"),
                         ("ldr", "wzr, [x1]"), ("ldr", "xzr, [x1]"),
                         ("ldr", "not_a_register, [x1]"), ("ldp", "x4, not_a_register, [x1]"),
                         ("prfm", "pldl1keep, [x1]"), ("str", "d0, [x1]"),
                         ("ldar", "x2, [x3]"), ("swp", "x2, x4, [x3]"), ("cas", "x2, x4, [x3]"),
                         ("ldp", "q2, q3, [x1]"), ("stp", "q2, q3, [x1]")] {
            assertRaw([("cmp", "w0, #0x1"), transfer, ("ccmp", "w5, #0x3, #0x0, ne")])
        }
    }

    // Neighbor: DC.testConditionalCompareNegativeSubsetFallsBack (flag-off).
    func testFlagOffKeepsLegacyMemoryGapFallback() {
        let off = text(ssa: false, branchRows([("cmp", "w26, #0x10"),
            ("ldr", "x1, [sp, #0x18]"), ("ccmp", "x25, x1, #0x2, ge")], suffix: "ls"))
        XCTAssertTrue(off.contains("__branch_ls("), off)
        XCTAssertTrue(off.contains("__conditional_compare_ge("), off)
        // Byte identity is a source proof in REPORT.md, not a fabricated golden text.
    }

    func testRegisterWriteStaysRawAndCompoundChainFolds() {
        // The three-compare chain is a compound ccmp chain, which the chain elision lowers.
        assertCompound([("cmp", "w0, #0x1"), ("ccmp", "w2, #0x3, #0x0, ne"), ("ccmp", "w4, #0x1, #0x0, ne")])
        assertRaw([("cmp", "w0, #0x1"), ("ccmp", "x9, #0x3, #0x0, ne"), ("add", "x9, x9, #1")])
    }

    // Neighbor: PT.testCmpAcrossAddressMaterializationLiftsCselUnderSSA.
    func testLoadBeforeCsetAndCsel() {
        for consumer in [("cset", "w15, lt"), ("csel", "w15, w4, w5, lt")] {
            let on = text(ssa: true, [row(0x1000, "cmp", "w0, #1"),
                row(0x1004, "ldr", "w3, [x1]"), row(0x1008, consumer.0, consumer.1), row(0x100c, "ret", "")])
            XCTAssertFalse(on.contains("__unknown(\"\(consumer.0)\""), on)
        }
    }

    func testPairBaseOverlapLiteralAndSignedLoads() {
        for transfer in [("ldp", "x1, x2, [x2]"), ("ldr", "x1, 0x2000"),
                         ("ldrsw", "x1, [x3]"), ("ldursw", "x1, [x3, #-4]")] {
            assertCompound([("cmp", "w0, #1"), transfer, ("ccmp", "w4, #3, #0, ne")])
        }
    }

    func testMaterializedStackLoadSurvivesLaterStore() {
        assertCompound([("ldr", "w6, [sp, #0x18]"), ("cmp", "w6, #1"),
            ("str", "w0, [sp, #0x18]"), ("ccmp", "w4, #3, #0, ne")])
    }

    // Neighbor: DC.testConditionalCompareOrRegisterAndCcmnShapes.
    func testCmnEqualityGuardSurvivesMemoryRow() {
        assertCompound([("cmn", "w0, #1"), ("ldr", "w3, [x1]"), ("ccmp", "w4, #3, #0, ne")])
    }

    // Neighbors: PT.testBlockBoundaryBetweenCmpAndCsetClearsPendingComparison;
    // PT.testInterveningNZCVWriterClearsPendingComparison.
    func testCallAndBlockBoundaryStillClearCarriedState() {
        assertRaw([("cmp", "w0, #1"), ("ldr", "w3, [x1]"), ("bl", "0x2000"), ("ccmp", "w4, #3, #0, ne")])
        let on = text(ssa: true, [row(0x1000, "cbz", "w5, 0x100c"), row(0x1004, "cmp", "w0, #1"),
            row(0x1008, "ldr", "w3, [x1]"), row(0x100c, "ccmp", "w4, #3, #0, ne"),
            row(0x1010, "cset", "w15, eq"), row(0x1014, "ret", "")])
        XCTAssertTrue(on.contains("__unknown(\"cset\""), on)
    }

    func testCompoundCsetAndCselAcrossMemoryRow() {
        for consumer in [("cset", "w15, eq"), ("csel", "w15, w4, w5, eq")] {
            let on = text(ssa: true, [row(0x1000, "cmp", "w0, #1"),
                row(0x1004, "ldr", "w3, [x1]"), row(0x1008, "ccmp", "w2, #3, #0, ne"),
                row(0x100c, consumer.0, consumer.1), row(0x1010, "ret", "")])
            XCTAssertFalse(on.contains("__unknown(\"\(consumer.0)\""), on)
            XCTAssertFalse(on.contains("__conditional_compare_"), on)
        }
    }

    func testStoreRejectsCapturedLazyMemoryValue() {
        for value in [MacIRValue.stackSlot(offset: 24), .unary(op: "*", value: .register(name: "x6", version: 1)),
                      .binaryExpression(op: "+", left: .stackSlot(offset: 24), right: .immediate(1))] {
            let comparison = BuilderComparison(left: value, right: .immediate(1), sourceAddress: 0x1000)
            XCTAssertFalse(MacIRBuilder.preservesPendingComparison(mnemonic: "str", operands: ["w0", "[sp, #0x18]"],
                adjacent: comparison, pending: nil, destinationValues: []))
        }
    }

    func testEveryPreRowValueIsCheckedIndependentOfRegisterName() {
        let captured = MacIRValue.temporary(7)
        let comparison = BuilderComparison(left: captured, right: .immediate(1), sourceAddress: 0x1000)
        XCTAssertFalse(MacIRBuilder.preservesPendingComparison(mnemonic: "ldp", operands: ["x3", "x5", "[x6]"],
            adjacent: comparison, pending: nil, destinationValues: [.temporary(8), captured]))
        XCTAssertFalse(MacIRBuilder.preservesPendingComparison(mnemonic: "ldpsw", operands: ["x3", "x5", "[x6]"],
            adjacent: comparison, pending: nil, destinationValues: [.temporary(8), captured]))
        XCTAssertFalse(MacIRBuilder.preservesPendingComparison(mnemonic: "ldr", operands: ["x3", "[x6]"],
            adjacent: comparison, pending: nil, destinationValues: [captured]))
    }

    func testFlagWriterAfterMemoryStartsNewComparison() {
        let on = text(ssa: true, [row(0x1000, "cmp", "w0, #1"), row(0x1004, "ldr", "w3, [x1]"),
            row(0x1008, "adds", "w14, w1, #2"), row(0x100c, "ccmp", "w2, #3, #0, ne"),
            row(0x1010, "cset", "w15, eq"), row(0x1014, "ret", "")])
        XCTAssertFalse(on.contains("arg0 != 0x1"), on)
        XCTAssertTrue(on.contains("arg1"), on)
    }
}
