import XCTest
@testable import MacScope

/// Synthetic reductions of existing e04d53b2b dump shapes; no binary is loaded.
final class DecompilerDeadLabelTests: XCTestCase {
    private func row(_ address: UInt64, _ operation: MacIROperation) -> MacIRInstruction {
        MacIRInstruction(source: .init(address: address, byteText: "00 00 00 00",
            mnemonic: "nop", operands: ""), operation: operation)
    }
    private func effect(_ address: UInt64, _ name: String) -> MacIRInstruction {
        row(address, .intrinsic(destination: nil, name: name, arguments: []))
    }
    private func guardRow(_ address: UInt64, _ target: Int64) -> MacIRInstruction {
        row(address, .conditionalBranch(condition: "!=", left: .register(name: "x0", version: 0),
            right: .immediate(0), target: .immediate(target)))
    }
    private func phi(_ address: UInt64, _ predecessors: [UInt64]) -> MacIRPhi {
        MacIRPhi(blockAddress: address, destination: .register(name: "x1", version: 9), bitWidth: 64,
            incoming: predecessors.enumerated().map {
                .init(predecessorAddress: $0.element, value: .immediate(Int64($0.offset + 1)))
            })
    }
    private func text(_ rows: [MacIRInstruction], _ phis: [MacIRPhi]) -> String {
        PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            instructions: rows, phis: phis)).text
    }
    // _quantize_float: entry falls into a loop; the back edge still names the header.
    private func loop() -> String {
        text([effect(0x1000, "entry_effect"), effect(0x1004, "loop_effect"),
              guardRow(0x1008, 0x1004), row(0x100c, .returnValue(.immediate(7)))],
             [phi(0x1004, [0x1000, 0x1008])])
    }
    func testLexicalFallthroughHasNoLabel() {
        let output = text([guardRow(0x1000, 0x100c), effect(0x1004, "fallthrough_effect"),
                           effect(0x1008, "next_effect"), row(0x100c, .returnValue(.immediate(7)))],
                          [phi(0x100c, [0x1000, 0x1008])])
        XCTAssertFalse(output.contains("goto L_1004;"))
        XCTAssertFalse(output.contains("L_1004:"), output)
        XCTAssertTrue(output.contains("__fallthrough_effect()"), output)
    }
    func testBackwardGotoKeepsLoopLabel() {
        let output = loop()
        XCTAssertTrue(output.contains("goto L_1004;"), output)
        XCTAssertTrue(output.contains("L_1004:"), output)
        XCTAssertTrue(output.contains("__loop_effect()"), output)
    }
    func testGotoAndFallthroughKeepSharedLabel() {
        let output = text([guardRow(0x1000, 0x1008), effect(0x1004, "fallthrough_effect"),
                           effect(0x1008, "shared_effect"), row(0x100c, .returnValue(.immediate(7)))],
                          [phi(0x1008, [0x1000, 0x1004])])
        XCTAssertEqual(output.components(separatedBy: "goto L_1008;").count - 1, 1, output)
        XCTAssertTrue(output.contains("L_1008:"), output)
        XCTAssertTrue(output.contains("__shared_effect()"), output)
    }
    // _convsamp L_739c / _quantize_float L_6c80: entry labels were already dead before G1.
    func testPreexistingDeadEntryLabelIsRemoved() {
        let output = loop()
        XCTAssertFalse(output.contains("goto L_1000;"))
        XCTAssertFalse(output.contains("L_1000:"), output)
        XCTAssertTrue(output.contains("__entry_effect()"), output)
    }
    // Class A analogue: the branch is represented by an if, not a printed goto.
    // This definition also checks that no empty label statement is left behind.
    func testClassAStructuredTransferHasNoDefinition() {
        let rows = [guardRow(0x1000, 0x1008), effect(0x1004, "body"),
                    row(0x1008, .returnValue(.immediate(7)))]
        let cond = BranchCondition(branchIndex: 0, compareIndex: nil,
            left: .register(name: "x0", version: 0), condition: "!=", right: .immediate(0), isZeroCheck: false)
        let output = PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            instructions: rows), forcedRegionForTesting: .sequence([
                .ifThen(cond: cond, body: .gotoLeaf(blocks: [1]), join: 2, inverted: true),
                .gotoLeaf(blocks: [2])]))
        XCTAssertEqual(output.lines.map(\.text), [
            "int64_t _dead_labels(void) {",
            "    // entry 0x0000000000001000; no stack frame; calls none",
            "    if (x0_0 == 0x0) { // conditional branch",
            "        __body();",
            "    }",
            "    return 0x7; // return",
            "}"
        ])
    }

    // Class C, DELTA1 ruling: preserve the scenario and all three definitions.
    // Duplicate-definition repair is separate from zero-mention label elision.
    func testClassCRepeatedAddressDefinitionsAreRetained() {
        let rows = [guardRow(0x1000, 0x1008), effect(0x1004, "body"),
                    effect(0x1008, "first"), effect(0x1008, "second"),
                    effect(0x1008, "third"), row(0x100c, .returnValue(.immediate(7)))]
        let cond = BranchCondition(branchIndex: 0, compareIndex: nil,
            left: .register(name: "x0", version: 0), condition: "!=", right: .immediate(0), isZeroCheck: false)
        let output = PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            instructions: rows), forcedRegionForTesting: .sequence([
                .ifThen(cond: cond, body: .gotoLeaf(blocks: [1]), join: 2, inverted: true),
                .gotoLeaf(blocks: [2])]))
        XCTAssertEqual(output.lines.map(\.text), [
            "int64_t _dead_labels(void) {",
            "    // entry 0x0000000000001000; no stack frame; calls none",
            "    if (x0_0 == 0x0) { // conditional branch",
            "        __body();",
            "    }",
            "    L_1008:",
            "    __first();",
            "    L_1008:",
            "    __second();",
            "    L_1008:",
            "    __third();",
            "    return 0x7; // return",
            "}"
        ])
    }

    // Class D: a raw branch operand is a real reference, not a metric-dead label.
    // Symbolic targets deliberately exercise conservative operand retention.
    func testClassDRawBranchOperandKeepsDefinition() {
        let rows = [guardRow(0x1000, 0x1008),
                    row(0x1004, .intrinsic(destination: nil, name: "branch_mi", arguments: [.symbol("L_1008")])),
                    row(0x1008, .returnValue(.immediate(7)))]
        let cond = BranchCondition(branchIndex: 0, compareIndex: nil,
            left: .register(name: "x0", version: 0), condition: "!=", right: .immediate(0), isZeroCheck: false)
        let output = PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            instructions: rows), forcedRegionForTesting: .sequence([
                .ifThen(cond: cond, body: .gotoLeaf(blocks: [1]), join: 2, inverted: true),
                .gotoLeaf(blocks: [2])]))
        XCTAssertEqual(output.lines.map(\.text), [
            "int64_t _dead_labels(void) {",
            "    // entry 0x0000000000001000; no stack frame; calls none",
            "    if (x0_0 == 0x0) { // conditional branch",
            "        __branch_mi(L_1008); // conditional branch",
            "    }",
            "    L_1008:",
            "    return 0x7; // return",
            "}"
        ])
    }

    // Real-goto control: an emitted transfer continues to own its definition.
    func testRealGotoLiteralDefinitionIsPreserved() {
        let rows = [row(0x1000, .intrinsic(destination: nil, name: "branch", arguments: [.immediate(0x1008)])),
                    effect(0x1004, "skipped"), row(0x1008, .returnValue(.immediate(7)))]
        let output = PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            instructions: rows), forcedRegionForTesting: .gotoLeaf(blocks: [0, 1, 2]))
        XCTAssertEqual(output.lines.map(\.text), [
            "int64_t _dead_labels(void) {",
            "    // entry 0x0000000000001000; no stack frame; calls none",
            "    goto L_1008; // unconditional branch",
            "    __skipped();",
            "    L_1008:",
            "    return 0x7; // return",
            "}"
        ])
    }

    // Control: a function with no dead labels retains every byte of its text.
    func testNoDeadLabelLiteralByteIdentity() {
        XCTAssertEqual(text([effect(0x1000, "effect"), row(0x1004, .returnValue(.immediate(7)))], []), """
        int64_t _dead_labels(void) {
            // entry 0x0000000000001000; no stack frame; calls none
            __effect();
            return 0x7; // return
        }
        """)
    }

    // DELTA1: names are not a whole-function gate. L_1010 is the
    // synthetic latch label left by a branch now printed as a loop break;
    // L_100c is still named by the entry block's real goto.
    func testNamedArgumentAndLocalUsePerLabelReferences() {
        var test = guardRow(0x1008, 0x1010)
        test.source.mnemonic = "cbnz"
        var copy = row(0x1010, .assign(destination: .temporary(0), source: .immediate(1)))
        var backedge = row(0x1014, .intrinsic(destination: nil, name: "branch", arguments: [.immediate(0x1004)]))
        let identity = MacIRPhiEdgeIdentity(blockAddress: 0x1004, predecessorAddress: 0x1008, destination: .temporary(0))
        copy.source.syntheticPhiEdge = identity
        backedge.source.syntheticPhiEdge = identity
        let rows = [guardRow(0x1000, 0x100c), effect(0x1004, "loop"), test,
                    row(0x100c, .returnValue(.immediate(7))), copy, backedge]
        var argument = MacIRFunctionParameter(index: 0, register: "x0", type: "int64_t", name: "value")
        argument.sourcePosition = 0
        let function = MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            parameters: [argument],
            localVariables: [.init(offset: -8, name: "scratch", type: "int64_t", byteWidth: 8)],
            instructions: rows)
        let output = PseudocodePrinter().print(function: function, forcedRegionForTesting: .sequence([
            .block(blockIndex: 0), .naturalLoop(body: .sequence([.block(blockIndex: 1), .block(blockIndex: 3)]), header: 1), .block(blockIndex: 2)]))
        XCTAssertEqual(output.lines.map(\.text), [
            "int64_t _dead_labels(int64_t value) {",
            "    // entry 0x0000000000001000; no stack frame; calls none",
            "    int64_t scratch;",
            "    if (x0_0 != 0x0) goto L_100c; // conditional branch",
            "    while (true) {",
            "        __loop();",
            "        if (!x0_0) { // conditional branch",
            "            break;",
            "        }",
            "        tmp_0 = 0x1;",
            "    }",
            "L_100c:;",
            "    return 0x7; // return",
            "}"
        ])
    }

    // DELTA1: a raw opaque argument naming just one label retains that label.
    // It is not necessary for the operand to be a typed immediate branch target.
    func testRawIntrinsicOpaqueOperandLiteralKeepsLabel() {
        let rows = [guardRow(0x1000, 0x1008),
                    row(0x1004, .intrinsic(destination: nil, name: "branch_mi", arguments: [.unknown("L_1008")])),
                    row(0x1008, .returnValue(.immediate(7)))]
        let cond = BranchCondition(branchIndex: 0, compareIndex: nil,
            left: .register(name: "x0", version: 0), condition: "!=", right: .immediate(0), isZeroCheck: false)
        let output = PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels", startAddress: 0x1000,
            instructions: rows), forcedRegionForTesting: .sequence([
                .ifThen(cond: cond, body: .gotoLeaf(blocks: [1]), join: 2, inverted: true),
                .gotoLeaf(blocks: [2])]))
        XCTAssertEqual(output.lines.map(\.text), [
            "int64_t _dead_labels(void) {",
            "    // entry 0x0000000000001000; no stack frame; calls none",
            "    if (x0_0 == 0x0) { // conditional branch",
            "        __branch_mi(L_1008); // conditional branch",
            "    }",
            "    L_1008:",
            "    return 0x7; // return",
            "}"
        ])
    }

}
