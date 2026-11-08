import Foundation
import XCTest
@testable import MacScope

final class SwitchSelectorCensusTests: XCTestCase {
    private let refusal = "printed operand is not a direct machine read"
    private typealias Tables = [UInt64: [UInt64]]
    private func rows(_ assembly: [(String, String)], base: UInt64 = 0x1000) -> [InstructionRow] {
        assembly.enumerated().map { i, a in
            InstructionRow(address: base + UInt64(i * 4), bytes: "", mnemonic: a.0,
                operands: a.1, hasBreakpoint: false, comment: nil)
        }
    }
    private func fixture(clamp: Bool = false) -> [InstructionRow] {
        rows([("sub", "w8, w0, #6"), ("cmp", clamp ? "w8, #2" : "w8, #9"),
            (clamp ? "csel" : "b.hi", clamp ? "w8, w8, wzr, ls" : "0x1028"),
            ("adrp", "x9, 0x2000"), ("add", "x9, x9, #0"), ("adr", "x10, 0x1024"),
            ("ldrb", "w11, [x9, x8]"), ("add", "x10, x10, x11, lsl #2"),
            ("br", "x10"), ("ret", ""), ("ret", "")])
    }
    private func tables(clamp: Bool = false) -> Tables {
        [0x1020: Array(repeating: 0x1024, count: clamp ? 3 : 10)]
    }
    private func build(_ input: [InstructionRow], tables: Tables, ssa: Bool) -> MacIRFunction {
        let f = PseudocodePrinter().buildFunction(functionName: "selector_census", startAddress: 0x1000,
            jumpTables: tables, explicitCFGEnabled: true, ssaEnabled: ssa, instructions: input)
        XCTAssertEqual(f.ssaEnabled, ssa, "FIXTURE ERROR: requested SSA path did not run")
        return f
    }
    private func span(_ row: InstructionRow) -> MacIRSourceSpan {
        MacIRSourceSpan(address: row.address, byteText: row.bytes, mnemonic: row.mnemonic,
            operands: row.operands, comment: row.comment, structuredOperands: row.structuredOperands)
    }
    private func mutate(_ f: inout MacIRFunction, at address: UInt64,
                        _ edit: (inout MacIRInstruction) -> Void) {
        for i in f.instructions.indices where f.instructions[i].source.address == address { edit(&f.instructions[i]) }
        // Keep the saved SSA render input in step; do not let a projection restore a stale control.
        if var original = f.ssaOriginalInstructions {
            for i in original.indices where original[i].source.address == address { edit(&original[i]) }
            f.ssaOriginalInstructions = original
        }
    }
    private func indexValue(_ f: MacIRFunction, br: UInt64) throws -> MacIRValue {
        let i = try XCTUnwrap(f.instructions.first { $0.source.address == br })
        guard case let .switchDispatch(value, _, _) = i.operation else {
            XCTFail("FIXTURE ERROR: missing switch"); throw FixtureError.missingSwitch
        }
        return value
    }
    private enum FixtureError: Error { case missingSwitch }
    private func replacingIndex(_ f: inout MacIRFunction, br: UInt64, value: MacIRValue) {
        mutate(&f, at: br) { i in
            guard case let .switchDispatch(_, cases, defaultTarget) = i.operation else { return }
            i.operation = .switchDispatch(index: value, cases: cases, defaultTarget: defaultTarget)
        }
    }
    private func leaf(_ value: MacIRValue) -> MacIRValue {
        if case let .unary(_, inner) = value { return leaf(inner) }
        return value
    }
    private func machine(_ input: [InstructionRow], function: MacIRFunction) -> [MacIRSourceSpan] {
        var result = input.map(span)
        if result.count != function.instructions.count || zip(result, function.instructions).contains(where: { $0.address != $1.source.address }) {
            var seen = Set<UInt64>()
            result = function.instructions.map(\.source).filter { seen.insert($0.address).inserted }
        }
        XCTAssertEqual(result.count, function.instructions.count, "FIXTURE ERROR: multiple IR rows per machine row")
        XCTAssertEqual(result.map(\.address), function.instructions.map { $0.source.address }, "FIXTURE ERROR: row alignment")
        XCTAssertEqual(Set(result.map(\.address)).count, result.count, "FIXTURE ERROR: duplicate machine addresses")
        return result
    }
    private func analyze(_ function: MacIRFunction, input: [InstructionRow], tables: Tables,
                         br: UInt64 = 0x1020, d: UInt64 = 0x1004,
                         evidencePresent: Bool = true, machineOverride: [MacIRSourceSpan]? = nil,
                         trailingUnreachable: Bool = false) throws -> C2DataflowCensus.Analysis {
        // buildFunction inputs have RegionalLexicalProof projection already; direct region inputs do not.
        // Every analyze input below additionally passes through the FP-environment projection.
        let projected = MacIRFPEnvironmentPseudocodeProjection.project(function)
        let dispatch = try XCTUnwrap(projected.instructions.first { $0.source.address == br })
        XCTAssertEqual(dispatch.source.switchSelector != nil, evidencePresent, "FIXTURE ERROR: evidence lost by projection")
        let value = try indexValue(projected, br: br)
        guard case .register = leaf(value) else {
            XCTFail("FIXTURE ERROR: dispatch index is not a physical register leaf"); throw FixtureError.missingSwitch
        }
        let printer = PseudocodePrinter(options: DecompilerOptions(structureControlFlow: false,
            deadCodeElimination: false, nopElision: false, functionSizeGate: 1024))
        let document = printer.print(function: projected)
        var names = PseudocodeNameContext(function: projected)
        names.redundantCompareIndices = printer.redundantCompareIndices(function: projected, names: names)
        let text = printer.valueText(for: value, names: names)
        XCTAssertTrue(document.lines.contains { $0.sourceAddress == br && $0.text.contains(text) },
            "FIXTURE ERROR: selector is not printed at BR")
        let baseline = machine(input, function: projected)
        let physical = machineOverride ?? baseline
        if trailingUnreachable {
            XCTAssertEqual(physical.count, projected.instructions.count + 1)
            XCTAssertEqual(Array(physical.dropLast()).map(\.address), projected.instructions.map { $0.source.address })
            XCTAssertEqual(physical.last?.address, 0x102c)
        } else {
            XCTAssertEqual(physical.count, projected.instructions.count)
            XCTAssertEqual(physical.map(\.address), projected.instructions.map { $0.source.address })
        }
        let flow = C2MachineFlow(rows: physical, resolvedJumpTables: tables)
        XCTAssertNil(flow.error, "FIXTURE ERROR: machine flow failed before selector gate")
        let result = C2DataflowCensus.analyze(function: projected, document: document, machine: physical,
            printer: printer, names: names, resolvedJumpTables: tables)
        XCTAssertFalse(result.refusalDetails.contains { $0.instructionAddress == nil }, "FIXTURE ERROR: unbound refusal")
        if let error = flow.error { XCTAssertFalse(result.skippedReason?.contains(error) ?? false) }
        return result
    }
    private func accepted(_ result: C2DataflowCensus.Analysis, br: UInt64 = 0x1020, d: UInt64 = 0x1004) {
        XCTAssertFalse(result.refusalDetails.contains { $0.instructionAddress == br || $0.instructionAddress == d })
        XCTAssertFalse(result.rows.contains { $0.useAddress == br || $0.useAddress == d })
    }
    private func refused(_ result: C2DataflowCensus.Analysis, br: UInt64 = 0x1020, d: UInt64 = 0x1004) {
        let addressed = result.refusalDetails.filter { $0.instructionAddress == br || $0.instructionAddress == d }
        XCTAssertTrue(addressed.contains { $0.instructionAddress == br && $0.reason == refusal })
        if d != br { XCTAssertFalse(addressed.contains { $0.instructionAddress == d && $0.reason == refusal }) }
    }
    private func control(ssa: Bool) throws -> MacIRFunction {
        let f = build(fixture(), tables: tables(), ssa: ssa)
        let dispatch = try XCTUnwrap(f.instructions.first { $0.source.address == 0x1020 })
        XCTAssertEqual(dispatch.source.switchSelector, .init(definitionAddress: 0x1004, register: "w8"))
        accepted(try analyze(f, input: fixture(), tables: tables()))
        return f
    }

    func testSC7ScalarAndSSAAndStrictBoundsCapture() throws {
        for ssa in [false, true] {
            _ = try control(ssa: ssa) // Nonvacuous all-R1–R6 accepting bounds branch, including SSA-flag check.
            let f = build(fixture(clamp: false), tables: tables(clamp: false), ssa: ssa)
            let value = leaf(try indexValue(f, br: 0x1020))
            guard case .register = value else { return XCTFail("FIXTURE ERROR: index must be a register leaf or casts over one") }
            accepted(try analyze(f, input: fixture(clamp: false), tables: tables(clamp: false), d: 0x1004))
        }
    }
    private func region(_ bounded: Bool) throws -> (MacIRFunction, [InstructionRow], Tables, UInt64, UInt64) {
        let input: [InstructionRow]
        let t: Tables
        let br: UInt64
        let d: UInt64
        if bounded {
            input = rows([("cmp", "w0, #16"), ("b.ge", "0x102c"), ("subs", "w1, w0, #1"),
                ("b.lt", "0x102c"), ("adrp", "x9, 0x2000"), ("add", "x9, x9, #0"),
                ("adr", "x10, 0x1028"), ("ldrb", "w11, [x9, x1]"),
                ("add", "x10, x10, x11, lsl #2"), ("br", "x10"),
                ("add", "v0.8h, v0.8h, v1.8h"), ("b", "0x1030"),
                ("subs", "w4, w4, #1"), ("b.ne", "0x1030"), ("ret", "")])
            t = [0x1024: Array(repeating: 0x1028, count: 15)]; br = 0x1024; d = 0x1018
        } else {
            input = rows([("mov", "w8, w0"), ("cmp", "w8, #1"), ("b.hi", "0x1040"),
                ("mov", "w3, w8"), ("adr", "x9, 0x2000"), ("adr", "x10, 0x1024"),
                ("ldrb", "w11, [x9, x8]"), ("add", "x10, x10, x11, lsl #2"),
                ("br", "x10"), ("add", "v0.8h, v0.8h, v1.8h"), ("b", "0x1034"),
                ("eor", "v0.16b, v0.16b, v2.16b"), ("b", "0x1034"),
                ("subs", "w4, w4, #1"), ("b.ne", "0x1034"), ("b", "0x1040"), ("ret", "")])
            t = [0x1020: [0x1024, 0x102c]]; br = 0x1020; d = 0x1004
        }
        let f = try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "selector_region", startAddress: 0x1000, rows: input,
                initialState: BuilderState(parameters: []), jumpTables: t, hasExternalFacts: false, isVariadic: false))
        return (f, input, t, br, d)
    }
    func testSC8RegionBoundsAdmission() throws {
        _ = try control(ssa: false)
        let (f, r, t, br, d) = try region(false)
        accepted(try analyze(f, input: r, tables: t, br: br, d: d), br: br, d: d)
    }
    func testSC9RegionBoundedRangeAdmission() throws {
        _ = try control(ssa: false)
        let (f, r, t, br, d) = try region(true)
        accepted(try analyze(f, input: r, tables: t, br: br, d: d), br: br, d: d)
    }
    func testSC10AbsentEvidence() throws {
        for ssa in [false, true] {
            var f = try control(ssa: ssa)
            mutate(&f, at: 0x1020) { $0.source.switchSelector = nil }
            refused(try analyze(f, input: fixture(), tables: tables(), evidencePresent: false))
        }
    }
    func testSC11WrongAndUncanonicalRegister() throws {
        for ssa in [false, true] { for name in ["x9", "not_a_register"] {
            var f = try control(ssa: ssa)
            mutate(&f, at: 0x1020) { $0.source.switchSelector = .init(definitionAddress: 0x1004, register: name) }
            refused(try analyze(f, input: fixture(), tables: tables()))
        } }
    }
    func testSC12BadCaptureRow() throws {
        for ssa in [false, true] { for address in [UInt64(0x1020), 0x9990, 0x1024, 0x102c] {
            var f = try control(ssa: ssa)
            mutate(&f, at: 0x1020) { $0.source.switchSelector = .init(definitionAddress: address, register: "w8") }
            var physical = machine(fixture(), function: f)
            if address == 0x102c { physical.append(MacIRSourceSpan(address: 0x102c, byteText: "", mnemonic: "ret", operands: "")) }
            refused(try analyze(f, input: fixture(), tables: tables(), machineOverride: physical, trailingUnreachable: address == 0x102c), d: address)
        } }
    }
    func testSC13StaleSelector() throws {
        for ssa in [false, true] {
            var f = try control(ssa: ssa)
            replacingIndex(&f, br: 0x1020, value: .register(name: "w8", version: 0))
            refused(try analyze(f, input: fixture(), tables: tables()))
        }
    }
    func testSC14PhiSelector() throws {
        _ = try control(ssa: true)
        let input = rows([("mov", "w8, #0"), ("add", "w8, w8, #1"), ("cmp", "w8, #3"),
            ("b.lo", "0x1004"), ("sub", "w8, w0, #6"), ("cmp", "w8, #9"),
            ("b.hi", "0x1038"), ("adrp", "x9, 0x2000"), ("add", "x9, x9, #0"),
            ("adr", "x10, 0x1034"), ("ldrb", "w11, [x9, x8]"),
            ("add", "x10, x10, x11, lsl #2"), ("br", "x10"), ("ret", ""), ("ret", "")])
        let t: Tables = [0x1030: Array(repeating: 0x1034, count: 10)]
        var f = build(input, tables: t, ssa: true)
        let phi = try XCTUnwrap(f.phis.first { $0.blockAddress == 0x1004 && $0.cell == 8 })
        XCTAssertFalse(phi.incoming.isEmpty)
        XCTAssertTrue(phi.incoming.allSatisfy { $0.machineAddress != nil }, "FIXTURE ERROR: virtual entry phi")
        accepted(try analyze(f, input: input, tables: t, br: 0x1030, d: 0x1014), br: 0x1030, d: 0x1014)
        replacingIndex(&f, br: 0x1030, value: phi.destination)
        refused(try analyze(f, input: input, tables: t, br: 0x1030, d: 0x1014), br: 0x1030, d: 0x1014)
    }
    func testSC15DirectBRReadUnchanged() throws {
        let input = rows([("sub", "w8, w0, #1"), ("cmp", "w8, #2"), ("b.hi", "0x1028"),
            ("adrp", "x9, 0x3000"), ("add", "x9, x9, #0"), ("ldrsw", "x8, [x9, x8, lsl #2]"),
            ("add", "x8, x9, x8"), ("br", "x8"), ("ret", ""), ("ret", ""), ("ret", "")])
        let t: Tables = [0x101c: [0x1020, 0x1024, 0x1020]]
        var f = build(input, tables: t, ssa: false)
        let present = try analyze(f, input: input, tables: t, br: 0x101c, d: 0x1004)
        mutate(&f, at: 0x101c) { $0.source.switchSelector = nil }
        let absent = try analyze(f, input: input, tables: t, br: 0x101c, d: 0x1004, evidencePresent: false)
        XCTAssertEqual(present.rows, absent.rows)
        XCTAssertEqual(present.skippedReason, absent.skippedReason)
        XCTAssertEqual(present.refusalDetails, absent.refusalDetails)
        XCTAssertEqual(present.indirectBranchSites, absent.indirectBranchSites)
        XCTAssertEqual(present.detectorSkippedReason, absent.detectorSkippedReason)
        XCTAssertEqual(present.lifterRefusals, absent.lifterRefusals)
    }
    func testR6NoInterveningSelectorRead() throws {
        for ssa in [false, true] {
            let f = try control(ssa: ssa)
            var physical = machine(fixture(), function: f)
            let j = try XCTUnwrap(physical.firstIndex { $0.address == 0x1018 })
            physical[j].operands = "w11, [x9, x12]"
            physical[j].structuredOperands = nil
            let capture = try XCTUnwrap(physical.firstIndex { $0.address == 0x1004 })
            physical[capture].mnemonic = "nop"; physical[capture].operands = ""; physical[capture].structuredOperands = nil
            let flow = C2MachineFlow(rows: physical, resolvedJumpTables: tables())
            let d = try XCTUnwrap(physical.firstIndex { $0.address == 0x1004 })
            let b = try XCTUnwrap(physical.firstIndex { $0.address == 0x1020 })
            XCTAssertTrue(((d)..<b).allSatisfy { !flow.reads[$0].contains("x8") })
            XCTAssertTrue(flow.dominates(d, j) && flow.dominates(j, b))
            refused(try analyze(f, input: fixture(), tables: tables(), machineOverride: physical))
            // An unrelated selector read must not turn the wrong indexed load into table evidence.
            let unrelated = try XCTUnwrap(physical.firstIndex { $0.address == 0x1010 })
            physical[unrelated].mnemonic = "cmp"; physical[unrelated].operands = "w8, #2"; physical[unrelated].structuredOperands = nil
            refused(try analyze(f, input: fixture(), tables: tables(), machineOverride: physical))
        }
    }
    func testR6RewriteBetweenCaptureAndActualLoad() throws {
        for ssa in [false, true] {
            let f = try control(ssa: ssa)
            var physical = machine(fixture(), function: f)
            let rewrite = try XCTUnwrap(physical.firstIndex { $0.address == 0x1010 })
            physical[rewrite].mnemonic = "mov"; physical[rewrite].operands = "w8, #1"; physical[rewrite].structuredOperands = nil
            let flow = C2MachineFlow(rows: physical, resolvedJumpTables: tables())
            let j = try XCTUnwrap(physical.firstIndex { $0.address == 0x1018 })
            XCTAssertTrue(flow.reads[j].contains("x8"))
            XCTAssertEqual(flow.before[j]["x8"], Set([UInt64(0x1010)]))
            refused(try analyze(f, input: fixture(), tables: tables(), machineOverride: physical))
        }
    }
    func testR6CompareAndLoadObserveDifferentDefinitions() throws {
        for ssa in [false, true] {
            var f = try control(ssa: ssa)
            let newSelector = MacIRValue.register(name: "w8", version: 99)
            mutate(&f, at: 0x1010) { $0.operation = .assign(destination: newSelector, source: .immediate(1)) }
            replacingIndex(&f, br: 0x1020, value: newSelector)
            var physical = machine(fixture(), function: f)
            let write = try XCTUnwrap(physical.firstIndex { $0.address == 0x1010 })
            physical[write].mnemonic = "mov"; physical[write].operands = "w8, #1"; physical[write].structuredOperands = nil
            let flow = C2MachineFlow(rows: physical, resolvedJumpTables: tables())
            let d = try XCTUnwrap(physical.firstIndex { $0.address == 0x1004 })
            let j = try XCTUnwrap(physical.firstIndex { $0.address == 0x1018 })
            XCTAssertEqual(flow.before[d]["x8"], Set([UInt64(0x1000)]))
            XCTAssertEqual(flow.before[j]["x8"], Set([UInt64(0x1010)]))
            // Requested CMP mismatch: R6(c) is false; R5 also rejects this nonwriting D.
            refused(try analyze(f, input: fixture(), tables: tables(), machineOverride: physical))
        }
    }
    func testR6ReadingWritingCaptureMustObserveActualDefinition() throws {
        _ = try control(ssa: false)
        let f = build(fixture(clamp: true), tables: tables(clamp: true), ssa: false)
        let physical = machine(fixture(clamp: true), function: f)
        let flow = C2MachineFlow(rows: physical, resolvedJumpTables: tables(clamp: true))
        let d = try XCTUnwrap(physical.firstIndex { $0.address == 0x1008 })
        let j = try XCTUnwrap(physical.firstIndex { $0.address == 0x1018 })
        XCTAssertTrue(flow.reads[d].contains("x8") && flow.writes[d].contains("x8"))
        XCTAssertEqual(flow.before[d]["x8"], Set([UInt64(0x1000)]))
        XCTAssertEqual(flow.before[j]["x8"], Set([UInt64(0x1008)]))
        // R5 identifies the post-CSEL S=D, and R6(a,b) hold, but R6(c) alone fails.
        refused(try analyze(f, input: fixture(clamp: true), tables: tables(clamp: true), d: 0x1008), d: 0x1008)
    }
}
