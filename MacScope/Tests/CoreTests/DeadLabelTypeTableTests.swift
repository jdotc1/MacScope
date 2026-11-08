import XCTest
@testable import MacScope

// Source-authored regression definitions.
final class DeadLabelTypeTableTests: XCTestCase {
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
    private func structured(_ types: [TypeDefinition], base: UInt64 = 0x1000,
                            printer: PseudocodePrinter = PseudocodePrinter()) -> [String] {
        let rows = [guardRow(base, Int64(base + 8)), effect(base + 4, "body"),
                    row(base + 8, .returnValue(.immediate(7)))]
        let cond = BranchCondition(branchIndex: 0, compareIndex: nil,
            left: .register(name: "x0", version: 0), condition: "!=", right: .immediate(0), isZeroCheck: false)
        return printer.print(function: MacIRFunction(name: "_dead_labels", startAddress: base,
            instructions: rows), forcedRegionForTesting: .sequence([
                .ifThen(cond: cond, body: .gotoLeaf(blocks: [1]), join: 2, inverted: true),
                .gotoLeaf(blocks: [2])]), types: types).lines.map(\.text)
    }
    private func noLabels(_ types: [TypeDefinition]) -> String {
        let rows = [effect(0x1000, "effect"), row(0x1004, .returnValue(.immediate(7)))]
        return PseudocodePrinter().print(function: MacIRFunction(name: "_dead_labels",
            startAddress: 0x1000, instructions: rows), types: types).text
    }
    private var elided: [String] {
        ["int64_t _dead_labels(void) {",
         "    // entry 0x0000000000001000; no stack frame; calls none",
         "    if (x0_0 == 0x0) { // conditional branch",
         "        __body();",
         "    }",
         "    return 0x7; // return",
         "}"]
    }
    private var retained: [String] {
        ["int64_t _dead_labels(void) {",
         "    // entry 0x0000000000001000; no stack frame; calls none",
         "    if (x0_0 == 0x0) { // conditional branch",
         "        __body();",
         "    }",
         "    L_1008:",
         "    return 0x7; // return",
         "}"]
    }
    func testT1TableWithoutLabelSpellings() {
        let types = [TypeDefinition(kind: .struct, name: "Pair", fields: [
            FieldDef(name: "a", type: "int64_t"), FieldDef(name: "b", type: "int64_t")]),
            TypeDefinition(kind: .struct, name: "Holder", fields: [
                FieldDef(name: "p", type: "Pair"), FieldDef(name: "tail", type: "int64_t")])]
        XCTAssertEqual(noLabels(types), """
        int64_t _dead_labels(void) {
            // entry 0x0000000000001000; no stack frame; calls none
            __effect();
            return 0x7; // return
        }
        """, "T1: DecompilerDeadLabelTests.swift:155; PseudocodePrinter.swift:4314-4317")
    }
    func testT1bReferenceDoesNotCreateLabel() {
        let types = [TypeDefinition(kind: .struct, name: "Box", fields: [FieldDef(name: "L_1000", type: "int64_t")])]
        XCTAssertEqual(noLabels(types), """
        int64_t _dead_labels(void) {
            // entry 0x0000000000001000; no stack frame; calls none
            __effect();
            return 0x7; // return
        }
        """, "T1b: PseudocodePrinter.swift:2085,4493; DecompilerDeadLabelTests.swift:155")
    }
    func testT2NearMisses() {
        let types = [TypeDefinition(kind: .struct, name: "Near", fields: [
            FieldDef(name: "L_2000", type: "int64_t"), FieldDef(name: "L_1008x", type: "int64_t"),
            FieldDef(name: "L_1008_extra", type: "int64_t")]), TypeDefinition(kind: .struct, name: "L_10080")]
        let output = structured(types)
        XCTAssertEqual(output, elided, "T2: PseudocodePrinter.swift:4286 exact token equality")
        XCTAssertEqual(output, structured([]), "T2: PseudocodePrinter.swift:4286")
    }
    func testT3MemberNameCollision() {
        XCTAssertEqual(structured([TypeDefinition(kind: .struct, name: "Box", fields: [
            FieldDef(name: "L_1008", type: "int64_t")])]), retained,
            "T3: PseudocodePrinter.swift:4317; AnalysisModels+TypeDefinitions.swift:603")
    }
    func testT4MemberTypeCollision() {
        XCTAssertEqual(structured([TypeDefinition(kind: .struct, name: "Box", fields: [
            FieldDef(name: "p", type: "struct L_1008 *")])]), retained,
            "T4: PseudocodePrinter.swift:4284-4286,4317")
    }
    func testT5TypeNameCollision() {
        XCTAssertEqual(structured([TypeDefinition(kind: .typedef, name: "L_1008")]), retained,
            "T5: PseudocodePrinter.swift:4315; AnalysisModels+TypeDefinitions.swift:375")
    }
    func testT6PromotedInlineMember() {
        let types = [TypeDefinition(kind: .struct, name: "Outer", fields: [
            FieldDef(name: "", type: "", inlineAggregateKind: .struct,
                inlineFields: [FieldDef(name: "L_1008", type: "int64_t")], promotesInlineFields: true)])]
        XCTAssertEqual(structured(types), retained,
            "T6: AnalysisModels+TypeDefinitions.swift:600,726; recursive inlineFields prefilter")
    }
    func testT6bDeepPromotedInlineMember() {
        let leaf = FieldDef(name: "L_1008", type: "int64_t")
        let inner = FieldDef(name: "", type: "", inlineAggregateKind: .union,
            inlineFields: [leaf], promotesInlineFields: true)
        let middle = FieldDef(name: "", type: "", inlineAggregateKind: .struct,
            inlineFields: [inner], promotesInlineFields: true)
        let outer = FieldDef(name: "", type: "", inlineAggregateKind: .union,
            inlineFields: [middle], promotesInlineFields: true)
        XCTAssertEqual(structured([TypeDefinition(kind: .struct, name: "Deep", fields: [outer])]), retained,
            "T6b: AnalysisModels+TypeDefinitions.swift:600,691,726,745; inlineFields at depth three")
    }
    func testT7NonPromotedInlineMember() {
        let types = [TypeDefinition(kind: .struct, name: "Outer", fields: [
            FieldDef(name: "inner", type: "", inlineAggregateKind: .struct,
                inlineFields: [FieldDef(name: "L_1008", type: "int64_t")], promotesInlineFields: false)])]
        let output = structured(types)
        XCTAssertEqual(output, elided, "T7: AnalysisModels+TypeDefinitions.swift:603,726")
        XCTAssertEqual(output, structured([]), "T7: AnalysisModels+TypeDefinitions.swift:603,726")
    }
    func testT8UnknownLayoutTruncation() {
        let types = [TypeDefinition(kind: .struct, name: "Cut", fields: [
            FieldDef(name: "u", type: "int64_t", layoutIsUnknown: true),
            FieldDef(name: "L_1008", type: "int64_t")])]
        let output = structured(types)
        XCTAssertEqual(output, elided, "T8: AnalysisModels+TypeDefinitions.swift:494,500")
        XCTAssertEqual(output, structured([]), "T8: AnalysisModels+TypeDefinitions.swift:494,500")
    }
    func testT9NoStateBetweenFunctions() {
        let box = [TypeDefinition(kind: .struct, name: "Box", fields: [FieldDef(name: "L_1008", type: "int64_t")])]
        let p = PseudocodePrinter()
        let first = structured(box, printer: p)
        let second = structured(box, base: 0x2000, printer: p)
        let third = structured(box, printer: p)
        XCTAssertTrue(first.contains("    L_1008:"), "T9: PseudocodePrinter.swift:4276,4286")
        XCTAssertFalse(second.contains("    L_2008:"), "T9: PseudocodePrinter.swift:4276,4286")
        XCTAssertFalse(second.contains("    L_1008:"), "T9: PseudocodePrinter.swift:4276,4286")
        XCTAssertTrue(third.contains("    L_1008:"), "T9: PseudocodePrinter.swift:4276,4286")
    }
}
