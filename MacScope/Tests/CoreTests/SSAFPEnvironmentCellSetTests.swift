import Foundation
import XCTest
@testable import MacScope

/// Source-only regression definitions.
final class SSAFPEnvironmentCellSetTests: XCTestCase {
    func testP1CellSetCapacityAndAlgebra() {
        let cells = MacIRSSA.CellSet([97, 98, 99, 100, 101, 127, -1])
        XCTAssertEqual(cells.cells, [97, 98, 99, 100], "MacIRSSA.swift:17,52 retain exactly the supported cells")
        for cell in [99, 100] {
            XCTAssertTrue(cells.contains(cell), "MacIRSSA.swift:23 retains FP environment cells")
        }
        for cell in [-1, 101, 127] {
            XCTAssertFalse(cells.contains(cell), "MacIRSSA.swift:23 rejects unsupported cells")
        }
        let environment = MacIRSSA.CellSet([99, 100])
        XCTAssertEqual(MacIRSSA.CellSet([97]).union(environment).cells, [97, 99, 100],
                       "MacIRSSA.swift:28 union keeps both high-word environment bits")
        XCTAssertEqual(cells.subtracting(.init([97, 98])).cells, [99, 100],
                       "MacIRSSA.swift:37 subtraction keeps unremoved environment bits")
        XCTAssertEqual(cells.intersection(environment).cells, [99, 100],
                       "MacIRSSA.swift:44 intersection keeps shared environment bits")
    }

    func testP2DiamondBindsExceptionPhi() throws {
        let fixture = rows([("cbz", "x2, 0x100c"), ("mov", "w0, #7"), ("b", "0x1010"),
                            ("mov", "w0, #0"), ("ret", "")])
        let cfg = try graph(fixture)
        let plan = try MacIRSSA.plan(cfg: cfg, rows: [
            effect(0x1000, reads: [2]), effect(0x1004, writes: [(99, 32)]),
            effect(0x1008), effect(0x100c, writes: [(99, 32)]), effect(0x1010, reads: [99])
        ], cellCount: 101)
        XCTAssertEqual(plan.phis.count, 1, "MacIRSSA.swift:291,301-302 place the live exception phi")
        let phi = try XCTUnwrap(plan.phis.first, "MacIRSSA.swift:342 enumerates cell 99")
        XCTAssertEqual(phi.cell, 99, "MacIRSSA.swift:342 preserves the exception cell")
        XCTAssertEqual(cfg.blocks[phi.block].startAddress, 0x1010, "MacIRSSA.swift:301 places at the join")
        XCTAssertEqual(plan.definitions[phi.destination].bitWidth, 32, "MacIRSSA.swift:342 preserves write width")
        XCTAssertEqual(phi.incoming.map(\.machineAddress), [0x1008, 0x100c],
                       "MacIRSSA.swift:387-391 preserve predecessor slots")
        XCTAssertEqual(phi.incoming.map { plan.definitions[$0.definition].origin },
                       [.instruction(0x1004), .instruction(0x100c)], "MacIRSSA.swift:391 carries both arm definitions")
        XCTAssertEqual(plan.rowReadBindings[4][99], phi.destination, "MacIRSSA.swift:387,390 bind the join read")
        XCTAssertTrue(plan.liveIn[phi.block].contains(99), "MacIRSSA.swift:262,277 expose the join use")
    }

    func testP3StraightLineBindsControlDefinition() throws {
        let cfg = try graph(rows([("mov", "w0, #1"), ("mov", "w1, w0"), ("ret", "")]))
        let plan = try MacIRSSA.plan(cfg: cfg, rows: [effect(0x1000, writes: [(100, 32)]),
            effect(0x1004, reads: [100]), effect(0x1008)], cellCount: 101)
        let write = try XCTUnwrap(plan.rowWriteBindings[0][100], "MacIRSSA.swift:391 keeps control definition")
        let read = try XCTUnwrap(plan.rowReadBindings[1][100], "MacIRSSA.swift:390 enumerates control reads")
        XCTAssertEqual(read, write, "MacIRSSA.swift:390-391 bind the reaching control definition")
    }

    func testP4StaleCellCountStillThrowsInvalidInput() throws {
        let cfg = try graph(rows([("ret", "")]))
        XCTAssertThrowsError(try MacIRSSA.plan(cfg: cfg, rows: [effect(0x1000, reads: [99])], cellCount: 98),
                             "MacIRSSA.swift:242 must see the out-of-range read") { error in
            guard case MacIRSSA.PlanningError.invalidInput = error else {
                return XCTFail("MacIRSSA.swift:242 requires invalidInput, got \(error)")
            }
        }
    }

    func testP5WriteOnlyControlNeedsNoPhi() throws {
        let cfg = try graph(rows([("ret", "")]))
        let plan = try MacIRSSA.plan(cfg: cfg, rows: [effect(0x1000, writes: [(100, 32)])], cellCount: 101)
        XCTAssertTrue(plan.phis.isEmpty, "MacIRSSA.swift:301 prunes a control cell with no live read")
        XCTAssertNotNil(plan.rowWriteBindings[0][100], "MacIRSSA.swift:252 retains write-only control")
    }

    func testSC1ThroughSC5ExactVectorEnvironmentEffects() {
        // SC2/SC3 require item 792's accepted half-admission postimage at landing.
        // At this pin MacIRFPEnvironment.swift:449,477-478 rejects 4h/8h and 32-to-16 narrowing.
        // 797 alone fixes CellSet; these two typed-effects assertions require that integration.
        let fixtures: [(name: String, bytes: String, mnemonic: String, operands: String, reads: [Int], writes: [Int])] = [
            ("SC1 fadd", "42 d4 20 4e", "fadd", "v2.4s, v2.4s, v0.4s", [32, 34, 64, 66, 99, 100], [34, 66, 99]),
            ("SC2 E01", "20 68 21 0e", "fcvtn", "v0.4h, v1.4s", [33, 65, 99, 100], [32, 64, 99]),
            ("SC3 E02", "20 68 21 4e", "fcvtn2", "v0.8h, v1.4s", [32, 33, 64, 65, 99, 100], [32, 64, 99]),
            ("SC4 E03", "21 68 61 0e", "fcvtn", "v1.2s, v1.2d", [33, 65, 99, 100], [33, 65, 99]),
            ("SC5 E04", "61 68 61 4e", "fcvtn2", "v1.4s, v3.2d", [33, 35, 65, 67, 99, 100], [33, 65, 99])
        ]
        for fixture in fixtures {
            let effects = MacIRBuilder.ssaEffects(for: MacIRSourceSpan(address: 0x1000,
                byteText: fixture.bytes, mnemonic: fixture.mnemonic, operands: fixture.operands))
            XCTAssertEqual(Set(effects.reads.cells), Set(fixture.reads),
                           "\(fixture.name): MacIRBuilder+SSAEffects.swift:258-265 and MacIRSSA.swift:17,52")
            XCTAssertEqual(Set(effects.writes.map(\.cell)), Set(fixture.writes),
                           "\(fixture.name): MacIRBuilder+SSAEffects.swift:261,266")
            XCTAssertTrue(effects.refusals.isEmpty, "\(fixture.name): MacIRBuilder+SSAEffects.swift:121,367")
        }
    }

    func testSC6SC7StatusAccessRemainsRefused() {
        for (mnemonic, operands) in [("msr", "fpcr, x8"), ("mrs", "x0, fpsr")] {
            let effects = MacIRBuilder.ssaEffects(for: MacIRSourceSpan(address: 0x1000,
                byteText: "", mnemonic: mnemonic, operands: operands))
            if mnemonic == "mrs" {
                XCTAssertTrue(effects.reads.contains(99), "SC7: MacIRBuilder+SSAEffects.swift:275 retains FPSR read")
            }
            for cell in [99, 100, 96, 97] {
                XCTAssertTrue(effects.writes.contains { $0.cell == cell },
                              "SC6/SC7: MacIRBuilder+SSAEffects.swift:280-283,379-380 retain refused writes")
            }
            XCTAssertFalse(effects.refusals.isEmpty, "SC6/SC7: MacIRBuilder+SSAEffects.swift:121,377 refuse status access")
        }
    }

    private func rows(_ assembly: [(String, String)], at base: UInt64 = 0x1000) -> [InstructionRow] {
        assembly.enumerated().map { index, item in
            InstructionRow(address: base + UInt64(index * 4), bytes: "00 00 00 00",
                           mnemonic: item.0, operands: item.1, hasBreakpoint: false, comment: nil)
        }
    }

    private func graph(_ rows: [InstructionRow]) throws -> MacIRCFG {
        let instructions = rows.map { row in
            MacIRInstruction(source: .init(address: row.address, byteText: row.bytes,
                mnemonic: row.mnemonic, operands: row.operands),
                operation: .intrinsic(destination: nil, name: "planner_row", arguments: []))
        }
        return try XCTUnwrap(MacIRCFG.build(instructions: instructions, jumpTables: [:],
            knownTailCallTargets: [:], authoredCallSignaturesByTarget: [:]))
    }

    private func effect(_ address: UInt64, reads: [Int] = [],
                        writes: [(cell: Int, width: Int)] = []) -> MacIRSSA.RowEffects {
        .init(address: address, reads: .init(reads), writes: writes.map {
            .init(cell: $0.cell, bitWidth: $0.width, origin: .instruction(address))
        })
    }
}
