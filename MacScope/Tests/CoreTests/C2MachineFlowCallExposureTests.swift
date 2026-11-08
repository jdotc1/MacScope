import XCTest
@testable import MacScope

// Source-authored test definitions.
final class C2MachineFlowCallExposureTests: XCTestCase {
    private func rows(_ instructions: [(String, String)]) -> [MacIRSourceSpan] {
        instructions.enumerated().map { index, instruction in
            MacIRSourceSpan(address: UInt64(0x7800 + index * 4), byteText: "00 00 00 00",
                mnemonic: instruction.0, operands: instruction.1)
        }
    }

    func testTC1LastCallDoesNotExposeEarlierWideRead() {
        let source = rows([("fmov", "d8, d0"), ("str", "q8, [x0]"), ("bl", "0x9000")])
        let flow = C2MachineFlow(rows: source)
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.before[1]["v8"], Set([UInt64(0x7800)]))
        XCTAssertEqual(flow.reads[1], Set(["v8", "x0"]))
        XCTAssertNil(C2MachineFlow(rows: source, permitDOnlyCallProjection: true).error)
    }

    func testTC2WideReadAfterDirectOrRegisterCallRefuses() {
        for call in [("bl", "0x9000"), ("blr", "x9")] {
            let flow = C2MachineFlow(rows: rows([call, ("str", "q8, [x0]"), ("ret", "")]))
            XCTAssertEqual(flow.error,
                "call with v8-v15 use requires partial-register reaching definitions")
        }
    }

    func testTC3WideReadAfterCallRefusesWithPermit() {
        let flow = C2MachineFlow(rows: rows([("bl", "0x9000"), ("str", "q8, [x0]"), ("ret", "")]),
            permitDOnlyCallProjection: true)
        XCTAssertEqual(flow.error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testTC4LoopExposesEarlierWideRead() {
        let flow = C2MachineFlow(rows: rows([("str", "q8, [x0]"), ("bl", "0x9000"),
            ("cbnz", "x1, 0x7800"), ("ret", "")]))
        XCTAssertEqual(flow.error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testTC5EarlierReadWithoutLoopIsAdmitted() {
        XCTAssertNil(C2MachineFlow(rows: rows([("str", "q8, [x0]"), ("bl", "0x9000"), ("ret", "")])).error)
    }

    func testTC6PairRestoreAfterCallIsNotARead() {
        let flow = C2MachineFlow(rows: rows([("bl", "0x9000"), ("ldp", "d8, d9, [sp], #16"), ("ret", "")]))
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.reads[1], Set(["sp"]))
    }

    func testTC7ReadModifyWriteAfterCallRefuses() {
        let flow = C2MachineFlow(rows: rows([("bl", "0x9000"),
            ("bsl", "v8.16b, v1.16b, v2.16b"), ("ret", "")]))
        XCTAssertEqual(flow.error,
            "call with v8-v15 use requires partial-register reaching definitions")
        XCTAssertTrue(flow.reads[1].contains("v8"))
    }

    func testTC8ReadOnlyOnCallSkippingPathIsAdmitted() {
        XCTAssertNil(C2MachineFlow(rows: rows([("cbz", "x0, 0x780c"), ("bl", "0x9000"),
            ("b", "0x7810"), ("str", "q8, [x1]"), ("ret", "")])).error)
    }

    func testTC9Low64AfterCallRequiresPermit() {
        let source = rows([("bl", "0x9000"), ("str", "d8, [sp]"), ("ret", "")])
        XCTAssertEqual(C2MachineFlow(rows: source).error,
            "call with v8-v15 use requires partial-register reaching definitions")
        XCTAssertNil(C2MachineFlow(rows: source, permitDOnlyCallProjection: true).error)
    }

    func testAllAuthenticatedRegisterCallsExposeSuccessorRead() {
        for call in [("blraa", "x9, x10"), ("blrab", "x9, x10"), ("blraaz", "x9"), ("blrabz", "x9")] {
            XCTAssertEqual(C2MachineFlow(rows: rows([call, ("str", "q8, [x0]"), ("ret", "")])).error,
                "call with v8-v15 use requires partial-register reaching definitions")
        }
    }

    func testWholeFunctionDOnlyGateDoesNotNarrowToExposedRows() {
        let source = rows([("str", "q8, [x0]"), ("bl", "0x9000"), ("str", "d8, [sp]"), ("ret", "")])
        XCTAssertEqual(C2MachineFlow(rows: source, permitDOnlyCallProjection: true).error,
            "call with v8-v15 use requires partial-register reaching definitions")
    }

    func testTailBranchOutsideRowsEndsExposurePath() {
        XCTAssertNil(C2MachineFlow(rows: rows([("bl", "0x9000"), ("b", "0xa000"),
            ("str", "q8, [x0]"), ("ret", "")])).error)
    }

    func testEarlierUnsupportedSemanticsKeepsItsError() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("opaque", ""), ("bl", "0x9000"),
            ("str", "q8, [x0]")])).error, "0x7800: unsupported machine mnemonic opaque")
    }

    func testFloatingPointSystemRegisterRefusalStaysFlowInsensitive() {
        XCTAssertEqual(C2MachineFlow(rows: rows([("sqxtun", "v0.8b, v1.8h"), ("bl", "0x9000")])).error,
            "call with floating-point system-register use requires bit-level ABI preservation")
    }
}
