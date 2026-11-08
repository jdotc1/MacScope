import Foundation
import XCTest
@testable import MacScope

/// Authored from retained 2026-10-19 listing and table records; not an execution receipt.
/// The first listing occurrence supplies exact instruction bytes. ADRP operands are
/// normalized to the absolute page printed in that same row, as the decoder emits.
/// Table entries are retained CASES.csv values, encoded at their recorded widths.
final class JumpTableShadowedBaseTests: XCTestCase {
    func testRealReadMarkers63CasesEnterIndependentMachineEdges() throws {
        let fixture = RetainedIndirectTableRows.readMarkers
        let tables = fixture.resolve()
        // The retained 63 cases are not a certificate: three direct entries at
        // 0x32660 skip the selected X25 base at 0x32658. Refuse conservatively.
        XCTAssertEqual(fixture.expected[0x32678]?.count, 63)
        XCTAssertNil(tables[0x32678])
        let flow = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: tables)
        let dispatch = try XCTUnwrap(fixture.rows.firstIndex { $0.address == 0x32678 })
        XCTAssertTrue(flow.indirectBranchSites.contains(0x32678))
        XCTAssertTrue(flow.successors[dispatch].isEmpty)
        XCTAssertEqual(flow.error, "unresolved indirect branch at 0x32678")
    }

    func testScalarCaseEdgesCarryIndependentDefinitions() throws {
        // Explicitly synthetic scalar rows, not claimed as specimen machine bytes.
        let rows = synthetic([
            (0x1000, "mov", "w0, w0"), (0x1004, "cmp", "w0, #1"),
            (0x1008, "b.hi", "0x1030"), (0x100c, "adrp", "x8, 0x2000"),
            (0x1010, "add", "x8, x8, #0"), (0x1014, "ldr", "x9, [x8, x0, lsl #3]"),
            (0x1018, "br", "x9"), (0x101c, "ret", ""),
            (0x1020, "mov", "x5, x1"), (0x1024, "b", "0x1034"),
            (0x1028, "mov", "x5, x2"), (0x102c, "b", "0x1034"),
            (0x1030, "mov", "x5, x3"), (0x1034, "add", "x6, x5, #1"),
            (0x1038, "ret", "")
        ])
        let tables = resolveSynthetic(rows)
        XCTAssertEqual(tables[0x1018], [0x1020, 0x1028])
        let flow = C2MachineFlow(rows: RetainedIndirectTableRows.sources(rows), resolvedJumpTables: tables)
        XCTAssertNil(flow.error)
        let join = try XCTUnwrap(rows.firstIndex { $0.address == 0x1034 })
        XCTAssertEqual(flow.before[join]["x5"], Set<UInt64>([0x1020, 0x1028, 0x1030]))
    }

    func testEntryAtCompareCannotBypassNearestBaseBeforeGuard() {
        // Both old and nearest ADRP are before CMP. The incoming edge targets
        // CMP itself, which the legacy strictly-after-guard check cannot reject.
        // Full-width X0 comparison avoids relying on a bypassed W-definition.
        let rows = synthetic([
            (0x0ff0, "cbnz", "x1, 0x1010"),
            (0x0ff4, "adrp", "x8, 0x3000"), (0x0ff8, "add", "x8, x8, #0"),
            (0x0ffc, "adrp", "x8, 0x2000"), (0x1000, "add", "x8, x8, #0"),
            (0x1004, "nop", ""), (0x1008, "nop", ""), (0x100c, "nop", ""),
            (0x1010, "cmp", "x0, #1"), (0x1014, "b.hi", "0x1030"),
            (0x1018, "ldr", "x9, [x8, x0, lsl #3]"), (0x101c, "br", "x9"),
            (0x1020, "ret", ""), (0x1024, "ret", ""),
            (0x1028, "ret", ""), (0x102c, "ret", ""), (0x1030, "ret", "")
        ])
        XCTAssertNil(resolveSynthetic(rows)[0x101c])
    }

    func testProductMapCombinationAndDefaultRefusal() throws {
        let fixture = RetainedIndirectTableRows.color12
        let tables = fixture.resolve()
        let targets = try XCTUnwrap(tables[0x45e4])
        XCTAssertEqual(targets, fixture.expected[0x45e4])
        let dispatch = try XCTUnwrap(fixture.rows.firstIndex { $0.address == 0x45e4 })
        let indices = Dictionary(uniqueKeysWithValues: fixture.rows.enumerated().map { ($0.element.address, $0.offset) })
        let mapped = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: tables)
        XCTAssertEqual(Set(mapped.successors[dispatch]), Set(targets.compactMap { indices[$0] }))
        XCTAssertFalse(mapped.indirectBranchSites.contains(0x45e4))
        let omitted = C2MachineFlow(rows: fixture.sources)
        let empty = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: [:])
        XCTAssertTrue(omitted.indirectBranchSites.contains(0x45e4))
        XCTAssertTrue(omitted.successors[dispatch].isEmpty)
        XCTAssertEqual(omitted.indirectBranchSites, empty.indirectBranchSites)
        XCTAssertEqual(omitted.error, empty.error)
    }

    func testShadowedBaseBeforeGuardResolvesWithoutIncomingBypass() {
        func rows(shadowed: Bool) -> [InstructionRow] {
            synthetic([
                (0x1000, shadowed ? "adrp" : "nop", shadowed ? "x8, 0x3000" : ""),
                (0x1004, "nop", ""), (0x1008, "adrp", "x8, 0x2000"),
                (0x100c, "cmp", "x0, #1"), (0x1010, "b.hi", "0x1030"),
                (0x1014, "ldr", "x9, [x8, x0, lsl #3]"), (0x1018, "br", "x9"),
                (0x1020, "ret", ""), (0x1028, "ret", ""), (0x1030, "ret", "")
            ])
        }
        // The sole direct target is beyond dispatch, so the entry predicate
        // alone cannot distinguish these controls. Only the old ADRP differs; both paths execute the selected base.
        XCTAssertEqual(resolveSynthetic(rows(shadowed: false))[0x1018], [0x1020, 0x1028])
        XCTAssertEqual(resolveSynthetic(rows(shadowed: true))[0x1018], [0x1020, 0x1028])
    }

    func testAdjacentSameRegisterADRPDefinitionsRefuseBeforeReading() {
        for olderPage in ["0x2000", "0x3000"] {
            let rows = synthetic([
                (0x1000, "cmp", "x0, #1"), (0x1004, "b.hi", "0x1030"),
                (0x1008, "adrp", "x8, \(olderPage)"), (0x100c, "adrp", "x8, 0x2000"),
                (0x1010, "ldr", "x9, [x8, x0, lsl #3]"), (0x1014, "br", "x9"),
                (0x1020, "ret", ""), (0x1028, "ret", ""), (0x1030, "ret", "")
            ])
            var reads = 0
            let tables = JumpTableResolver().resolve(instructions: rows,
                readBytes: { _, _ in reads += 1; return nil },
                codeRange: .init(lowerBound: 0x1000, upperBound: 0x1034))
            XCTAssertNil(tables[0x1014])
            XCTAssertEqual(reads, 0)
        }
    }

    private func synthetic(_ values: [(UInt64, String, String)]) -> [InstructionRow] {
        values.map { address, mnemonic, operands in
            InstructionRow(address: address, bytes: "", mnemonic: mnemonic,
                operands: operands, hasBreakpoint: false, comment: "synthetic assembly-only unit row")
        }
    }

    private func resolveSynthetic(_ rows: [InstructionRow]) -> [UInt64: [UInt64]] {
        JumpTableResolver().resolve(instructions: rows,
            readBytes: { address, count in
                guard count == 8 else { return nil }
                let target: UInt64
                switch address {
                case 0x2000: target = 0x1020
                case 0x2008: target = 0x1028
                default: return nil
                }
                return Data((0..<8).map { UInt8(truncatingIfNeeded: target >> ($0 * 8)) })
            }, codeRange: .init(lowerBound: 0x0ff0, upperBound: 0x1040))
    }

    func testAllSixRealShadowedBasesUseOnlyNearestDefinition() throws {
        for fixture in [RetainedIndirectTableRows.color12,
                        RetainedIndirectTableRows.color16,
                        RetainedIndirectTableRows.merged12] {
            let tables = fixture.resolve()
            for (branch, targets) in fixture.expected {
                XCTAssertEqual(tables[branch], targets, "branch \(String(branch, radix: 16))")
            }
        }
    }

    func testSmallerRealTableUsesSameProductMapInMachineFlow() throws {
        let fixture = RetainedIndirectTableRows.color12
        let tables = fixture.resolve()
        let targets = try XCTUnwrap(tables[0x45e4])
        XCTAssertEqual(targets.count, 10)
        let flow = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: tables)
        let dispatch = try XCTUnwrap(fixture.rows.firstIndex { $0.address == 0x45e4 })
        let indices = Dictionary(uniqueKeysWithValues: fixture.rows.enumerated().map { ($0.element.address, $0.offset) })
        XCTAssertEqual(Set(flow.successors[dispatch]), Set(targets.compactMap { indices[$0] }))
        XCTAssertFalse(flow.indirectBranchSites.contains(0x45e4))
        // An unrelated runtime-pointer BR is not certified by resolving the table.
        XCTAssertTrue(flow.indirectBranchSites.contains(0x44b4))
    }

    func testShortTableReadLeavesWholeBranchUnresolvedInCensus() {
        let fixture = RetainedIndirectTableRows.readMarkers
        let tables = fixture.resolve(omittingByte: 0x59635)
        XCTAssertNil(tables[0x32678])
        let flow = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: tables)
        XCTAssertTrue(flow.indirectBranchSites.contains(0x32678))
        XCTAssertEqual(flow.error, "unresolved indirect branch at 0x32678")
    }

    func testBadBoundLeavesWholeBranchUnresolvedInCensus() {
        let fixture = RetainedIndirectTableRows.readMarkers
        let rows = fixture.replacing(0x32664, mnemonic: "cmp", operands: "w8, #-1")
        let tables = fixture.resolve(rows: rows)
        XCTAssertNil(tables[0x32678])
        let flow = C2MachineFlow(rows: RetainedIndirectTableRows.sources(rows), resolvedJumpTables: tables)
        XCTAssertTrue(flow.indirectBranchSites.contains(0x32678))
    }

    func testEntryBypassingNearestADRPDoesNotReuseOlderValue() {
        let fixture = RetainedIndirectTableRows.color12
        // Counterfactual assembly-only mutation, not claimed to be original bytes:
        // old x8 is formed at 45c4/45c8; this edge skips the killing ADRP at 45d0.
        let rows = fixture.replacing(0x45cc, mnemonic: "b", operands: "0x45d4")
        XCTAssertNil(fixture.resolve(rows: rows)[0x45e4])
    }

    func testPostDefinitionClobberStillRefuses() {
        let fixture = RetainedIndirectTableRows.color12
        // Replacing the anchor with a base clobber cannot authorize a table.
        let rows = fixture.replacing(0x45d8, mnemonic: "mov", operands: "x8, x0")
        XCTAssertNil(fixture.resolve(rows: rows)[0x45e4])
    }

    func testNonRoleBaseClobberRefusesOtherwiseCompleteCompactDispatch() {
        // Explicitly synthetic pair: all mandatory guard/base/anchor/load roles
        // are identical. Only the non-role instruction at 1014 changes.
        func rows(clobber: Bool) -> [InstructionRow] {
            synthetic([
                (0x1000, "mov", "w0, w0"), (0x1004, "cmp", "w0, #1"),
                (0x1008, "b.hi", "0x1040"), (0x100c, "adrp", "x8, 0x2000"),
                (0x1010, "add", "x8, x8, #0"),
                (0x1014, clobber ? "mov" : "nop", clobber ? "x8, x0" : ""),
                (0x1018, "adr", "x10, 0x1030"),
                (0x101c, "ldrb", "w11, [x8, x0]"),
                (0x1020, "add", "x10, x10, x11, lsl #2"),
                (0x1024, "br", "x10"), (0x1028, "ret", ""),
                (0x102c, "ret", ""), (0x1030, "ret", ""),
                (0x1034, "ret", ""), (0x1038, "ret", ""),
                (0x103c, "ret", ""), (0x1040, "ret", "")
            ])
        }
        func resolve(_ rows: [InstructionRow]) -> [UInt64: [UInt64]] {
            JumpTableResolver().resolve(instructions: rows,
                readBytes: { address, count in
                    guard count == 1 else { return nil }
                    switch address {
                    case 0x2000: return Data([UInt8(0)])
                    case 0x2001: return Data([UInt8(1)])
                    default: return nil
                    }
                }, codeRange: .init(lowerBound: 0x1000, upperBound: 0x1044))
        }
        XCTAssertEqual(resolve(rows(clobber: false))[0x1024], [0x1030, 0x1034])
        XCTAssertNil(resolve(rows(clobber: true))[0x1024])
    }

    func testIncompleteLocalTargetMapIsNotPartiallyAdmitted() throws {
        let fixture = RetainedIndirectTableRows.readMarkers
        let tables = fixture.resolve()
        XCTAssertNil(tables[0x32678])
        let dispatch = try XCTUnwrap(fixture.rows.firstIndex { $0.address == 0x32678 })
        let refused = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: tables)
        XCTAssertTrue(refused.indirectBranchSites.contains(0x32678))
        XCTAssertTrue(refused.successors[dispatch].isEmpty)
        XCTAssertEqual(refused.error, "unresolved indirect branch at 0x32678")
        // Counterfactual caller map, explicitly not a resolver certificate:
        // retain the all-or-nothing local-target check despite product refusal.
        var incomplete = fixture.expected
        var targets = try XCTUnwrap(incomplete[0x32678])
        targets[0] = 0xffff_ffff_ffff_fffc
        incomplete[0x32678] = targets
        let flow = C2MachineFlow(rows: fixture.sources, resolvedJumpTables: incomplete)
        XCTAssertTrue(flow.indirectBranchSites.contains(0x32678))
        XCTAssertTrue(flow.successors[dispatch].isEmpty)
        XCTAssertEqual(flow.error, "unresolved indirect branch at 0x32678")
    }

}

private struct RetainedIndirectTableRows {
    let rows: [InstructionRow]
    let lower: UInt64
    let upper: UInt64
    let bytes: [UInt64: UInt8]
    let expected: [UInt64: [UInt64]]
    var sources: [MacIRSourceSpan] { Self.sources(rows) }

    static func sources(_ rows: [InstructionRow]) -> [MacIRSourceSpan] {
        rows.map { MacIRSourceSpan(address: $0.address, byteText: $0.bytes,
            mnemonic: $0.mnemonic, operands: $0.operands, comment: nil) }
    }

    func replacing(_ address: UInt64, mnemonic: String, operands: String) -> [InstructionRow] {
        rows.map { row in
            guard row.address == address else { return row }
            return InstructionRow(address: address, bytes: "", mnemonic: mnemonic,
                operands: operands, hasBreakpoint: false, comment: "assembly-only negative mutation")
        }
    }

    func resolve(rows suppliedRows: [InstructionRow]? = nil,
                 omittingByte missing: UInt64? = nil) -> [UInt64: [UInt64]] {
        JumpTableResolver().resolve(instructions: suppliedRows ?? rows,
            readBytes: { address, count in
                var result: [UInt8] = []
                for offset in 0..<count {
                    let location = address + UInt64(offset)
                    guard location != missing, let byte = bytes[location] else { return nil }
                    result.append(byte)
                }
                return Data(result)
            }, codeRange: .init(lowerBound: lower, upperBound: upper))
    }

    private static func parse(_ text: String) -> [InstructionRow] {
        text.split(separator: "\n").map { line in
            let fields = line.split(separator: "|", omittingEmptySubsequences: false)
            return InstructionRow(address: UInt64(fields[0], radix: 16)!, bytes: String(fields[1]),
                mnemonic: String(fields[2]), operands: String(fields[3]), hasBreakpoint: false, comment: nil)
        }
    }

    private static func storage(_ tableRows: [(UInt64, [UInt8])]) -> [UInt64: UInt8] {
        var result: [UInt64: UInt8] = [:]
        for (address, values) in tableRows {
            for (offset, byte) in values.enumerated() { result[address + UInt64(offset)] = byte }
        }
        return result
    }

    // _read_markers, retained first-occurrence listing lines 51275...52185.
    static let readMarkers = Self(
        rows: parse("""
            32540|ff 03 07 d1|sub|sp, sp, #0x1c0
            32544|fc 6f 16 a9|stp|x28, x27, [sp, #0x160]
            32548|fa 67 17 a9|stp|x26, x25, [sp, #0x170]
            3254c|f8 5f 18 a9|stp|x24, x23, [sp, #0x180]
            32550|f6 57 19 a9|stp|x22, x21, [sp, #0x190]
            32554|f4 4f 1a a9|stp|x20, x19, [sp, #0x1a0]
            32558|fd 7b 1b a9|stp|x29, x30, [sp, #0x1b0]
            3255c|fd c3 06 91|add|x29, sp, #0x1b0
            32560|f3 03 00 aa|mov|x19, x0
            32564|b7 c7 01 d1|sub|x23, x29, #0x71
            32568|68 01 00 d0|adrp|x8, 0x60000
            3256c|08 0d 40 f9|ldr|x8, [x8, #0x18]
            32570|08 01 40 f9|ldr|x8, [x8]
            32574|09 20 03 91|add|x9, x0, #0xc8
            32578|e9 17 00 f9|str|x9, [sp, #0x28]
            3257c|09 20 04 91|add|x9, x0, #0x108
            32580|e9 0b 00 f9|str|x9, [sp, #0x10]
            32584|a8 03 1a f8|stur|x8, [x29, #-0x60]
            32588|08 a0 03 91|add|x8, x0, #0xe8
            3258c|e8 07 00 f9|str|x8, [sp, #0x8]
            32590|1b 10 05 91|add|x27, x0, #0x144
            32594|1c 50 05 91|add|x28, x0, #0x154
            32598|08 90 05 91|add|x8, x0, #0x164
            3259c|e8 1b 00 f9|str|x8, [sp, #0x30]
            325a0|14 34 42 b9|ldr|w20, [x0, #0x234]
            325a4|39 01 00 f0|adrp|x25, 0x59000
            325a8|39 e3 16 91|add|x25, x25, #0x5b8
            325ac|b4 05 00 35|cbnz|w20, 0x32660
            325b0|68 32 41 f9|ldr|x8, [x19, #0x260]
            325b4|08 19 40 b9|ldr|w8, [x8, #0x18]
            325b8|c8 00 00 34|cbz|w8, 0x325d0
            325bc|e0 03 13 aa|mov|x0, x19
            325c0|6a ff ff 97|bl|_next_marker
            325c4|a0 6b 00 34|cbz|w0, 0x33338
            325c8|74 36 42 b9|ldr|w20, [x19, #0x234]
            325cc|25 00 00 14|b|0x32660
            325d0|76 16 40 f9|ldr|x22, [x19, #0x28]
            325d4|c8 06 40 f9|ldr|x8, [x22, #0x8]
            325d8|c8 00 00 b5|cbnz|x8, 0x325f0
            325dc|c8 0e 40 f9|ldr|x8, [x22, #0x18]
            325e0|e0 03 13 aa|mov|x0, x19
            325e4|00 01 3f d6|blr|x8
            325e8|80 6a 00 34|cbz|w0, 0x33338
            325ec|c8 06 40 f9|ldr|x8, [x22, #0x8]
            325f0|d5 02 40 f9|ldr|x21, [x22]
            325f4|b8 16 40 38|ldrb|w24, [x21], #0x1
            325f8|19 05 00 f1|subs|x25, x8, #0x1
            325fc|c1 00 00 54|b.ne|0x32614
            32600|c8 0e 40 f9|ldr|x8, [x22, #0x18]
            32604|e0 03 13 aa|mov|x0, x19
            32608|00 01 3f d6|blr|x8
            3260c|60 69 00 34|cbz|w0, 0x33338
            32610|d5 66 40 a9|ldp|x21, x25, [x22]
            32614|b4 16 40 38|ldrb|w20, [x21], #0x1
            32618|1f ff 03 71|cmp|w24, #0xff
            3261c|61 00 00 54|b.ne|0x32628
            32620|9f 62 03 71|cmp|w20, #0xd8
            32624|40 01 00 54|b.eq|0x3264c
            32628|68 02 40 f9|ldr|x8, [x19]
            3262c|e9 06 80 52|mov|w9, #0x37
            32630|09 61 05 29|stp|w9, w24, [x8, #0x28]
            32634|68 02 40 f9|ldr|x8, [x19]
            32638|14 31 00 b9|str|w20, [x8, #0x30]
            3263c|68 02 40 f9|ldr|x8, [x19]
            32640|08 01 40 f9|ldr|x8, [x8]
            32644|e0 03 13 aa|mov|x0, x19
            32648|00 01 3f d6|blr|x8
            3264c|28 07 00 d1|sub|x8, x25, #0x1
            32650|74 36 02 b9|str|w20, [x19, #0x234]
            32654|d5 22 00 a9|stp|x21, x8, [x22]
            32658|39 01 00 f0|adrp|x25, 0x59000
            3265c|39 e3 16 91|add|x25, x25, #0x5b8
            32660|88 02 03 51|sub|w8, w20, #0xc0
            32664|1f f9 00 71|cmp|w8, #0x3e
            32668|08 03 00 54|b.hi|0x326c8
            3266c|89 00 00 10|adr|x9, #16
            32670|2a 7b 68 78|ldrh|w10, [x25, x8, lsl #1]
            32674|29 09 0a 8b|add|x9, x9, x10, lsl #2
            32678|20 01 1f d6|br|x9
            3267c|68 32 41 f9|ldr|x8, [x19, #0x260]
            32680|89 82 03 51|sub|w9, w20, #0xe0
            32684|08 4d 29 8b|add|x8, x8, w9, uxtw #3
            32688|08 19 40 f9|ldr|x8, [x8, #0x30]
            3268c|e0 03 13 aa|mov|x0, x19
            32690|00 01 3f d6|blr|x8
            32694|20 65 00 34|cbz|w0, 0x33338
            32698|ea 01 00 14|b|0x32e40
            3269c|68 02 40 f9|ldr|x8, [x19]
            326a0|c9 07 80 52|mov|w9, #0x3e
            326a4|09 51 05 29|stp|w9, w20, [x8, #0x28]
            326a8|68 02 40 f9|ldr|x8, [x19]
            326ac|08 01 40 f9|ldr|x8, [x8]
            326b0|e0 03 13 aa|mov|x0, x19
            326b4|00 01 3f d6|blr|x8
            326b8|e2 01 00 14|b|0x32e40
            326bc|e0 03 13 aa|mov|x0, x19
            326c0|01 00 80 52|mov|w1, #0x0
            326c4|1e 01 00 14|b|0x32b3c
            326c8|9f 06 00 71|cmp|w20, #0x1
            326cc|41 01 00 54|b.ne|0x326f4
            326d0|68 02 40 f9|ldr|x8, [x19]
            326d4|c9 0b 80 52|mov|w9, #0x5e
            326d8|09 51 05 29|stp|w9, w20, [x8, #0x28]
            326dc|68 02 40 f9|ldr|x8, [x19]
            326e0|08 05 40 f9|ldr|x8, [x8, #0x8]
            326e4|e0 03 13 aa|mov|x0, x19
            326e8|21 00 80 52|mov|w1, #0x1
            326ec|00 01 3f d6|blr|x8
            326f0|d4 01 00 14|b|0x32e40
            326f4|68 02 40 f9|ldr|x8, [x19]
            326f8|c9 08 80 52|mov|w9, #0x46
            326fc|ea ff ff 17|b|0x326a4
            32700|e0 03 13 aa|mov|x0, x19
            32704|01 00 80 52|mov|w1, #0x0
            32708|ca 01 00 14|b|0x32e30
            3270c|e0 03 13 aa|mov|x0, x19
            32710|01 00 80 52|mov|w1, #0x0
            32714|22 00 80 52|mov|w2, #0x1
            32718|0a 01 00 14|b|0x32b40
            3271c|fc ef 01 a9|stp|x28, x27, [sp, #0x18]
            32720|74 16 40 f9|ldr|x20, [x19, #0x28]
            32724|88 06 40 f9|ldr|x8, [x20, #0x8]
            32728|c8 00 00 b5|cbnz|x8, 0x32740
            3272c|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32730|e0 03 13 aa|mov|x0, x19
            32734|00 01 3f d6|blr|x8
            32738|00 60 00 34|cbz|w0, 0x33338
            3273c|88 06 40 f9|ldr|x8, [x20, #0x8]
            32740|9c 02 40 f9|ldr|x28, [x20]
            32744|95 17 40 38|ldrb|w21, [x28], #0x1
            32748|08 05 00 f1|subs|x8, x8, #0x1
            3274c|c1 00 00 54|b.ne|0x32764
            32750|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32754|e0 03 13 aa|mov|x0, x19
            32758|00 01 3f d6|blr|x8
            3275c|e0 5e 00 34|cbz|w0, 0x33338
            32760|9c 22 40 a9|ldp|x28, x8, [x20]
            32764|a9 de 78 d3|lsl|x9, x21, #8
            32768|19 05 00 d1|sub|x25, x8, #0x1
            3276c|88 17 40 38|ldrb|w8, [x28], #0x1
            32770|28 01 08 aa|orr|x8, x9, x8
            32774|18 09 00 d1|sub|x24, x8, #0x2
            32778|1f 4d 00 f1|cmp|x8, #0x13
            3277c|63 15 00 54|b.lo|0x32a28
            32780|d9 00 00 b5|cbnz|x25, 0x32798
            32784|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32788|e0 03 13 aa|mov|x0, x19
            3278c|00 01 3f d6|blr|x8
            32790|40 5d 00 34|cbz|w0, 0x33338
            32794|9c 66 40 a9|ldp|x28, x25, [x20]
            32798|9b 17 40 38|ldrb|w27, [x28], #0x1
            3279c|68 02 40 f9|ldr|x8, [x19]
            327a0|49 0a 80 52|mov|w9, #0x52
            327a4|09 6d 05 29|stp|w9, w27, [x8, #0x28]
            327a8|68 02 40 f9|ldr|x8, [x19]
            327ac|08 05 40 f9|ldr|x8, [x8, #0x8]
            327b0|e0 03 13 aa|mov|x0, x19
            327b4|21 00 80 52|mov|w1, #0x1
            327b8|00 01 3f d6|blr|x8
            327bc|15 00 80 52|mov|w21, #0x0
            327c0|bf f3 18 38|sturb|wzr, [x29, #-0x71]
            327c4|39 07 00 d1|sub|x25, x25, #0x1
            327c8|36 00 80 52|mov|w22, #0x1
            327cc|d9 00 00 b5|cbnz|x25, 0x327e4
            327d0|88 0e 40 f9|ldr|x8, [x20, #0x18]
            327d4|e0 03 13 aa|mov|x0, x19
            327d8|00 01 3f d6|blr|x8
            327dc|e0 5a 00 34|cbz|w0, 0x33338
            327e0|9c 66 40 a9|ldp|x28, x25, [x20]
            327e4|88 17 40 38|ldrb|w8, [x28], #0x1
            327e8|e8 6a 36 38|strb|w8, [x23, x22]
            327ec|b5 02 08 0b|add|w21, w21, w8
            327f0|d6 06 00 91|add|x22, x22, #0x1
            327f4|39 07 00 d1|sub|x25, x25, #0x1
            327f8|df 46 00 f1|cmp|x22, #0x11
            327fc|81 fe ff 54|b.ne|0x327cc
            32800|18 47 00 d1|sub|x24, x24, #0x11
            32804|68 02 40 f9|ldr|x8, [x19]
            32808|b6 c7 01 d1|sub|x22, x29, #0x71
            3280c|c0 12 40 bc|ldur|s0, [x22, #0x1]
            32810|00 a4 08 2f|ushll.8h|v0, v0, #0x0
            32814|00 a4 10 2f|ushll.4s|v0, v0, #0x0
            32818|00 c1 82 3c|stur|q0, [x8, #0x2c]
            3281c|c0 52 40 bc|ldur|s0, [x22, #0x5]
            32820|00 a4 08 2f|ushll.8h|v0, v0, #0x0
            32824|00 a4 10 2f|ushll.4s|v0, v0, #0x0
            32828|00 c1 83 3c|stur|q0, [x8, #0x3c]
            3282c|1a 0b 80 52|mov|w26, #0x58
            32830|1a 29 00 b9|str|w26, [x8, #0x28]
            32834|08 05 40 f9|ldr|x8, [x8, #0x8]
            32838|e0 03 13 aa|mov|x0, x19
            3283c|41 00 80 52|mov|w1, #0x2
            32840|00 01 3f d6|blr|x8
            32844|68 02 40 f9|ldr|x8, [x19]
            32848|c0 92 40 bc|ldur|s0, [x22, #0x9]
            3284c|00 a4 08 2f|ushll.8h|v0, v0, #0x0
            32850|00 a4 10 2f|ushll.4s|v0, v0, #0x0
            32854|00 c1 82 3c|stur|q0, [x8, #0x2c]
            32858|b7 c7 01 d1|sub|x23, x29, #0x71
            3285c|c0 d2 40 bc|ldur|s0, [x22, #0xd]
            32860|00 a4 08 2f|ushll.8h|v0, v0, #0x0
            32864|00 a4 10 2f|ushll.4s|v0, v0, #0x0
            32868|00 c1 83 3c|stur|q0, [x8, #0x3c]
            3286c|1a 29 00 b9|str|w26, [x8, #0x28]
            32870|08 05 40 f9|ldr|x8, [x8, #0x8]
            32874|e0 03 13 aa|mov|x0, x19
            32878|41 00 80 52|mov|w1, #0x2
            3287c|00 01 3f d6|blr|x8
            32880|bf 02 04 71|cmp|w21, #0x100
            32884|a8 00 00 54|b.hi|0x32898
            32888|1f 03 15 eb|cmp|x24, x21
            3288c|6b 00 00 54|b.lt|0x32898
            32890|35 01 00 35|cbnz|w21, 0x328b4
            32894|15 00 00 14|b|0x328e8
            32898|68 02 40 f9|ldr|x8, [x19]
            3289c|29 01 80 52|mov|w9, #0x9
            328a0|09 29 00 b9|str|w9, [x8, #0x28]
            328a4|08 01 40 f9|ldr|x8, [x8]
            328a8|e0 03 13 aa|mov|x0, x19
            328ac|00 01 3f d6|blr|x8
            328b0|d5 01 00 34|cbz|w21, 0x328e8
            328b4|f6 ff 00 91|add|x22, sp, #0x3f
            328b8|fa 03 15 aa|mov|x26, x21
            328bc|d9 00 00 b5|cbnz|x25, 0x328d4
            328c0|88 0e 40 f9|ldr|x8, [x20, #0x18]
            328c4|e0 03 13 aa|mov|x0, x19
            328c8|00 01 3f d6|blr|x8
            328cc|60 53 00 34|cbz|w0, 0x33338
            328d0|9c 66 40 a9|ldp|x28, x25, [x20]
            328d4|39 07 00 d1|sub|x25, x25, #0x1
            328d8|88 17 40 38|ldrb|w8, [x28], #0x1
            328dc|c8 16 00 38|strb|w8, [x22], #0x1
            328e0|5a 07 00 f1|subs|x26, x26, #0x1
            328e4|c1 fe ff 54|b.ne|0x328bc
            328e8|08 20 80 52|mov|w8, #0x100
            328ec|08 01 15 4b|sub|w8, w8, w21
            328f0|01 7d 40 93|sxtw|x1, w8
            328f4|e8 ff 00 91|add|x8, sp, #0x3f
            328f8|00 01 15 8b|add|x0, x8, x21
            328fc|47 97 00 94|bl|0x58618
            32900|bb 01 20 37|tbnz|w27, #0x4, 0x32934
            32904|7f 13 00 71|cmp|w27, #0x4
            32908|03 01 00 54|b.lo|0x32928
            3290c|68 02 40 f9|ldr|x8, [x19]
            32910|e9 03 80 52|mov|w9, #0x1f
            32914|09 6d 05 29|stp|w9, w27, [x8, #0x28]
            32918|68 02 40 f9|ldr|x8, [x19]
            3291c|08 01 40 f9|ldr|x8, [x8]
            32920|e0 03 13 aa|mov|x0, x19
            32924|00 01 3f d6|blr|x8
            32928|e8 07 40 f9|ldr|x8, [sp, #0x8]
            3292c|16 0d 1b 8b|add|x22, x8, x27, lsl #3
            32930|0d 00 00 14|b|0x32964
            32934|76 43 00 51|sub|w22, w27, #0x10
            32938|7f 53 00 71|cmp|w27, #0x14
            3293c|03 01 00 54|b.lo|0x3295c
            32940|68 02 40 f9|ldr|x8, [x19]
            32944|e9 03 80 52|mov|w9, #0x1f
            32948|09 59 05 29|stp|w9, w22, [x8, #0x28]
            3294c|68 02 40 f9|ldr|x8, [x19]
            32950|08 01 40 f9|ldr|x8, [x8]
            32954|e0 03 13 aa|mov|x0, x19
            32958|00 01 3f d6|blr|x8
            3295c|e8 0b 40 f9|ldr|x8, [sp, #0x10]
            32960|16 4d 36 8b|add|x22, x8, w22, uxtw #3
            32964|c0 02 40 f9|ldr|x0, [x22]
            32968|80 00 00 b5|cbnz|x0, 0x32978
            3296c|e0 03 13 aa|mov|x0, x19
            32970|1e a3 ff 97|bl|_jpeg_alloc_huff_table
            32974|c0 02 00 f9|str|x0, [x22]
            32978|a8 f3 59 38|ldurb|w8, [x29, #-0x61]
            3297c|08 40 00 39|strb|w8, [x0, #0x10]
            32980|a0 f3 d8 3c|ldur|q0, [x29, #-0x71]
            32984|00 00 80 3d|str|q0, [x0]
            32988|c8 02 40 f9|ldr|x8, [x22]
            3298c|e0 f3 cf 3c|ldur|q0, [sp, #0xff]
            32990|e9 43 00 91|add|x9, sp, #0x10
            32994|21 f1 cf 3c|ldur|q1, [x9, #0xff]
            32998|00 11 8d 3c|stur|q0, [x8, #0xd1]
            3299c|01 11 8e 3c|stur|q1, [x8, #0xe1]
            329a0|e9 83 00 91|add|x9, sp, #0x20
            329a4|20 f1 cf 3c|ldur|q0, [x9, #0xff]
            329a8|e9 c3 00 91|add|x9, sp, #0x30
            329ac|21 f1 cf 3c|ldur|q1, [x9, #0xff]
            329b0|00 11 8f 3c|stur|q0, [x8, #0xf1]
            329b4|e0 f3 cb 3c|ldur|q0, [sp, #0xbf]
            329b8|e2 f3 cc 3c|ldur|q2, [sp, #0xcf]
            329bc|00 11 89 3c|stur|q0, [x8, #0x91]
            329c0|02 11 8a 3c|stur|q2, [x8, #0xa1]
            329c4|e0 f3 cd 3c|ldur|q0, [sp, #0xdf]
            329c8|e2 f3 ce 3c|ldur|q2, [sp, #0xef]
            329cc|00 11 8b 3c|stur|q0, [x8, #0xb1]
            329d0|02 11 8c 3c|stur|q2, [x8, #0xc1]
            329d4|e0 f3 c7 3c|ldur|q0, [sp, #0x7f]
            329d8|e2 f3 c8 3c|ldur|q2, [sp, #0x8f]
            329dc|00 11 85 3c|stur|q0, [x8, #0x51]
            329e0|02 11 86 3c|stur|q2, [x8, #0x61]
            329e4|e0 f3 c9 3c|ldur|q0, [sp, #0x9f]
            329e8|e2 f3 ca 3c|ldur|q2, [sp, #0xaf]
            329ec|00 11 87 3c|stur|q0, [x8, #0x71]
            329f0|02 11 88 3c|stur|q2, [x8, #0x81]
            329f4|e0 f3 c3 3c|ldur|q0, [sp, #0x3f]
            329f8|e2 f3 c4 3c|ldur|q2, [sp, #0x4f]
            329fc|00 11 81 3c|stur|q0, [x8, #0x11]
            32a00|02 11 82 3c|stur|q2, [x8, #0x21]
            32a04|e0 f3 c5 3c|ldur|q0, [sp, #0x5f]
            32a08|e2 f3 c6 3c|ldur|q2, [sp, #0x6f]
            32a0c|00 11 83 3c|stur|q0, [x8, #0x31]
            32a10|02 11 84 3c|stur|q2, [x8, #0x41]
            32a14|18 03 15 cb|sub|x24, x24, x21
            32a18|08 45 00 91|add|x8, x8, #0x11
            32a1c|01 3d 80 3d|str|q1, [x8, #0xf0]
            32a20|1f 43 00 f1|cmp|x24, #0x10
            32a24|ec ea ff 54|b.gt|0x32780
            32a28|f8 00 00 b4|cbz|x24, 0x32a44
            32a2c|68 02 40 f9|ldr|x8, [x19]
            32a30|89 01 80 52|mov|w9, #0xc
            32a34|09 29 00 b9|str|w9, [x8, #0x28]
            32a38|08 01 40 f9|ldr|x8, [x8]
            32a3c|e0 03 13 aa|mov|x0, x19
            32a40|00 01 3f d6|blr|x8
            32a44|9c 66 00 a9|stp|x28, x25, [x20]
            32a48|ed 00 00 14|b|0x32dfc
            32a4c|74 16 40 f9|ldr|x20, [x19, #0x28]
            32a50|88 06 40 f9|ldr|x8, [x20, #0x8]
            32a54|c8 00 00 b5|cbnz|x8, 0x32a6c
            32a58|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32a5c|e0 03 13 aa|mov|x0, x19
            32a60|00 01 3f d6|blr|x8
            32a64|a0 46 00 34|cbz|w0, 0x33338
            32a68|88 06 40 f9|ldr|x8, [x20, #0x8]
            32a6c|96 02 40 f9|ldr|x22, [x20]
            32a70|d8 16 40 38|ldrb|w24, [x22], #0x1
            32a74|15 05 00 f1|subs|x21, x8, #0x1
            32a78|c1 00 00 54|b.ne|0x32a90
            32a7c|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32a80|e0 03 13 aa|mov|x0, x19
            32a84|00 01 3f d6|blr|x8
            32a88|80 45 00 34|cbz|w0, 0x33338
            32a8c|96 56 40 a9|ldp|x22, x21, [x20]
            32a90|08 df 78 d3|lsl|x8, x24, #8
            32a94|c9 16 40 38|ldrb|w9, [x22], #0x1
            32a98|08 01 09 aa|orr|x8, x8, x9
            32a9c|1f 11 00 f1|cmp|x8, #0x4
            32aa0|e0 00 00 54|b.eq|0x32abc
            32aa4|68 02 40 f9|ldr|x8, [x19]
            32aa8|89 01 80 52|mov|w9, #0xc
            32aac|09 29 00 b9|str|w9, [x8, #0x28]
            32ab0|08 01 40 f9|ldr|x8, [x8]
            32ab4|e0 03 13 aa|mov|x0, x19
            32ab8|00 01 3f d6|blr|x8
            32abc|a8 06 00 d1|sub|x8, x21, #0x1
            32ac0|c8 00 00 b5|cbnz|x8, 0x32ad8
            32ac4|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32ac8|e0 03 13 aa|mov|x0, x19
            32acc|00 01 3f d6|blr|x8
            32ad0|40 43 00 34|cbz|w0, 0x33338
            32ad4|96 22 40 a9|ldp|x22, x8, [x20]
            32ad8|d5 16 40 38|ldrb|w21, [x22], #0x1
            32adc|08 05 00 f1|subs|x8, x8, #0x1
            32ae0|c1 00 00 54|b.ne|0x32af8
            32ae4|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32ae8|e0 03 13 aa|mov|x0, x19
            32aec|00 01 3f d6|blr|x8
            32af0|40 42 00 34|cbz|w0, 0x33338
            32af4|96 22 40 a9|ldp|x22, x8, [x20]
            32af8|a9 5e 18 53|lsl|w9, w21, #8
            32afc|15 05 00 d1|sub|x21, x8, #0x1
            32b00|c8 16 40 38|ldrb|w8, [x22], #0x1
            32b04|38 01 08 2a|orr|w24, w9, w8
            32b08|68 02 40 f9|ldr|x8, [x19]
            32b0c|89 0a 80 52|mov|w9, #0x54
            32b10|09 61 05 29|stp|w9, w24, [x8, #0x28]
            32b14|68 02 40 f9|ldr|x8, [x19]
            32b18|08 05 40 f9|ldr|x8, [x8, #0x8]
            32b1c|e0 03 13 aa|mov|x0, x19
            32b20|21 00 80 52|mov|w1, #0x1
            32b24|00 01 3f d6|blr|x8
            32b28|78 76 01 b9|str|w24, [x19, #0x174]
            32b2c|96 56 00 a9|stp|x22, x21, [x20]
            32b30|c4 00 00 14|b|0x32e40
            32b34|e0 03 13 aa|mov|x0, x19
            32b38|21 00 80 52|mov|w1, #0x1
            32b3c|02 00 80 52|mov|w2, #0x0
            32b40|03 00 80 52|mov|w3, #0x0
            32b44|bd 00 00 14|b|0x32e38
            32b48|68 02 40 f9|ldr|x8, [x19]
            32b4c|09 0d 80 52|mov|w9, #0x68
            32b50|09 29 00 b9|str|w9, [x8, #0x28]
            32b54|08 05 40 f9|ldr|x8, [x8, #0x8]
            32b58|e0 03 13 aa|mov|x0, x19
            32b5c|21 00 80 52|mov|w1, #0x1
            32b60|00 01 3f d6|blr|x8
            32b64|68 32 41 f9|ldr|x8, [x19, #0x260]
            32b68|09 19 40 b9|ldr|w9, [x8, #0x18]
            32b6c|09 01 00 34|cbz|w9, 0x32b8c
            32b70|68 02 40 f9|ldr|x8, [x19]
            32b74|e9 07 80 52|mov|w9, #0x3f
            32b78|09 29 00 b9|str|w9, [x8, #0x28]
            32b7c|08 01 40 f9|ldr|x8, [x8]
            32b80|e0 03 13 aa|mov|x0, x19
            32b84|00 01 3f d6|blr|x8
            32b88|68 32 41 f9|ldr|x8, [x19, #0x260]
            32b8c|7f 7f 00 a9|stp|xzr, xzr, [x27]
            32b90|e9 c3 00 b2|mov|x9, #0x101010101010101
            32b94|89 27 00 a9|stp|x9, x9, [x28]
            32b98|e9 1b 40 f9|ldr|x9, [sp, #0x30]
            32b9c|ea c3 06 b2|mov|x10, #0x404040404040404
            32ba0|4a c1 00 b2|orr|x10, x10, #0x101010101010101
            32ba4|2a 29 00 a9|stp|x10, x10, [x9]
            32ba8|69 d2 05 91|add|x9, x19, #0x174
            32bac|3f 01 00 f9|str|xzr, [x9]
            32bb0|7f 3e 00 b9|str|wzr, [x19, #0x3c]
            32bb4|7f 8e 01 b9|str|wzr, [x19, #0x18c]
            32bb8|29 20 80 52|mov|w9, #0x101
            32bbc|69 fa 02 79|strh|w9, [x19, #0x17c]
            32bc0|7f fa 05 39|strb|wzr, [x19, #0x17e]
            32bc4|e9 83 00 32|mov|w9, #0x10001
            32bc8|69 c2 00 f9|str|x9, [x19, #0x180]
            32bcc|7f 22 06 39|strb|wzr, [x19, #0x188]
            32bd0|29 00 80 52|mov|w9, #0x1
            32bd4|09 19 00 b9|str|w9, [x8, #0x18]
            32bd8|9a 00 00 14|b|0x32e40
            32bdc|79 16 40 f9|ldr|x25, [x19, #0x28]
            32be0|28 07 40 f9|ldr|x8, [x25, #0x8]
            32be4|c8 00 00 b5|cbnz|x8, 0x32bfc
            32be8|28 0f 40 f9|ldr|x8, [x25, #0x18]
            32bec|e0 03 13 aa|mov|x0, x19
            32bf0|00 01 3f d6|blr|x8
            32bf4|20 3a 00 34|cbz|w0, 0x33338
            32bf8|28 07 40 f9|ldr|x8, [x25, #0x8]
            32bfc|3a 03 40 f9|ldr|x26, [x25]
            32c00|54 17 40 38|ldrb|w20, [x26], #0x1
            32c04|08 05 00 f1|subs|x8, x8, #0x1
            32c08|fc ef 01 a9|stp|x28, x27, [sp, #0x18]
            32c0c|c1 00 00 54|b.ne|0x32c24
            32c10|28 0f 40 f9|ldr|x8, [x25, #0x18]
            32c14|e0 03 13 aa|mov|x0, x19
            32c18|00 01 3f d6|blr|x8
            32c1c|e0 38 00 34|cbz|w0, 0x33338
            32c20|3a 23 40 a9|ldp|x26, x8, [x25]
            32c24|89 de 78 d3|lsl|x9, x20, #8
            32c28|18 05 00 d1|sub|x24, x8, #0x1
            32c2c|48 17 40 38|ldrb|w8, [x26], #0x1
            32c30|28 01 08 aa|orr|x8, x9, x8
            32c34|1c 09 00 d1|sub|x28, x8, #0x2
            32c38|1f 0d 00 f1|cmp|x8, #0x3
            32c3c|03 0d 00 54|b.lo|0x32ddc
            32c40|d8 00 00 b5|cbnz|x24, 0x32c58
            32c44|28 0f 40 f9|ldr|x8, [x25, #0x18]
            32c48|e0 03 13 aa|mov|x0, x19
            32c4c|00 01 3f d6|blr|x8
            32c50|40 37 00 34|cbz|w0, 0x33338
            32c54|3a 63 40 a9|ldp|x26, x24, [x25]
            32c58|5b 03 40 39|ldrb|w27, [x26]
            32c5c|68 7f 04 53|lsr|w8, w27, #4
            32c60|75 0f 40 92|and|x21, x27, #0xf
            32c64|69 02 40 f9|ldr|x9, [x19]
            32c68|6a 0a 80 52|mov|w10, #0x53
            32c6c|2a 55 05 29|stp|w10, w21, [x9, #0x28]
            32c70|69 02 40 f9|ldr|x9, [x19]
            32c74|28 31 00 b9|str|w8, [x9, #0x30]
            32c78|68 02 40 f9|ldr|x8, [x19]
            32c7c|08 05 40 f9|ldr|x8, [x8, #0x8]
            32c80|e0 03 13 aa|mov|x0, x19
            32c84|21 00 80 52|mov|w1, #0x1
            32c88|00 01 3f d6|blr|x8
            32c8c|bf 12 00 71|cmp|w21, #0x4
            32c90|03 01 00 54|b.lo|0x32cb0
            32c94|68 02 40 f9|ldr|x8, [x19]
            32c98|09 04 80 52|mov|w9, #0x20
            32c9c|09 55 05 29|stp|w9, w21, [x8, #0x28]
            32ca0|68 02 40 f9|ldr|x8, [x19]
            32ca4|08 01 40 f9|ldr|x8, [x8]
            32ca8|e0 03 13 aa|mov|x0, x19
            32cac|00 01 3f d6|blr|x8
            32cb0|e8 17 40 f9|ldr|x8, [sp, #0x28]
            32cb4|14 79 75 f8|ldr|x20, [x8, x21, lsl #3]
            32cb8|d4 00 00 b5|cbnz|x20, 0x32cd0
            32cbc|e0 03 13 aa|mov|x0, x19
            32cc0|40 a2 ff 97|bl|_jpeg_alloc_quant_table
            32cc4|f4 03 00 aa|mov|x20, x0
            32cc8|e8 17 40 f9|ldr|x8, [sp, #0x28]
            32ccc|00 79 35 f8|str|x0, [x8, x21, lsl #3]
            32cd0|16 00 80 d2|mov|x22, #0x0
            32cd4|18 07 00 d1|sub|x24, x24, #0x1
            32cd8|5a 07 00 91|add|x26, x26, #0x1
            32cdc|7f 43 00 71|cmp|w27, #0x10
            32ce0|22 01 00 54|b.hs|0x32d04
            32ce4|d8 00 00 b5|cbnz|x24, 0x32cfc
            32ce8|28 0f 40 f9|ldr|x8, [x25, #0x18]
            32cec|e0 03 13 aa|mov|x0, x19
            32cf0|00 01 3f d6|blr|x8
            32cf4|20 32 00 34|cbz|w0, 0x33338
            32cf8|3a 63 40 a9|ldp|x26, x24, [x25]
            32cfc|48 03 40 39|ldrb|w8, [x26]
            32d00|12 00 00 14|b|0x32d48
            32d04|d8 00 00 b5|cbnz|x24, 0x32d1c
            32d08|28 0f 40 f9|ldr|x8, [x25, #0x18]
            32d0c|e0 03 13 aa|mov|x0, x19
            32d10|00 01 3f d6|blr|x8
            32d14|20 31 00 34|cbz|w0, 0x33338
            32d18|3a 63 40 a9|ldp|x26, x24, [x25]
            32d1c|55 17 40 38|ldrb|w21, [x26], #0x1
            32d20|18 07 00 f1|subs|x24, x24, #0x1
            32d24|c1 00 00 54|b.ne|0x32d3c
            32d28|28 0f 40 f9|ldr|x8, [x25, #0x18]
            32d2c|e0 03 13 aa|mov|x0, x19
            32d30|00 01 3f d6|blr|x8
            32d34|20 30 00 34|cbz|w0, 0x33338
            32d38|3a 63 40 a9|ldp|x26, x24, [x25]
            32d3c|a8 5e 18 53|lsl|w8, w21, #8
            32d40|49 03 40 39|ldrb|w9, [x26]
            32d44|08 01 09 2a|orr|w8, w8, w9
            32d48|29 01 00 f0|adrp|x9, 0x59000
            32d4c|29 c1 3a 91|add|x9, x9, #0xeb0
            32d50|29 69 b6 b8|ldrsw|x9, [x9, x22]
            32d54|88 7a 29 78|strh|w8, [x20, x9, lsl #1]
            32d58|18 07 00 d1|sub|x24, x24, #0x1
            32d5c|5a 07 00 91|add|x26, x26, #0x1
            32d60|d6 12 00 91|add|x22, x22, #0x4
            32d64|df 02 04 f1|cmp|x22, #0x100
            32d68|a1 fb ff 54|b.ne|0x32cdc
            32d6c|68 02 40 f9|ldr|x8, [x19]
            32d70|08 7d 40 b9|ldr|w8, [x8, #0x7c]
            32d74|1f 09 00 71|cmp|w8, #0x2
            32d78|f6 0b 80 52|mov|w22, #0x5f
            32d7c|4b 02 00 54|b.lt|0x32dc4
            32d80|94 22 00 91|add|x20, x20, #0x8
            32d84|f5 00 80 92|mov|x21, #-0x8
            32d88|68 02 40 f9|ldr|x8, [x19]
            32d8c|80 86 7f 6d|ldp|d0, d1, [x20, #-0x8]
            32d90|00 a4 10 2f|ushll.4s|v0, v0, #0x0
            32d94|00 c1 82 3c|stur|q0, [x8, #0x2c]
            32d98|20 a4 10 2f|ushll.4s|v0, v1, #0x0
            32d9c|00 c1 83 3c|stur|q0, [x8, #0x3c]
            32da0|16 29 00 b9|str|w22, [x8, #0x28]
            32da4|08 05 40 f9|ldr|x8, [x8, #0x8]
            32da8|e0 03 13 aa|mov|x0, x19
            32dac|41 00 80 52|mov|w1, #0x2
            32db0|00 01 3f d6|blr|x8
            32db4|b5 22 00 91|add|x21, x21, #0x8
            32db8|94 42 00 91|add|x20, x20, #0x10
            32dbc|bf e2 00 f1|cmp|x21, #0x38
            32dc0|43 fe ff 54|b.lo|0x32d88
            32dc4|7f 43 00 71|cmp|w27, #0x10
            32dc8|08 10 80 92|mov|x8, #-0x81
            32dcc|09 08 80 92|mov|x9, #-0x41
            32dd0|28 31 88 9a|csel|x8, x9, x8, lo
            32dd4|1c 01 1c ab|adds|x28, x8, x28
            32dd8|4c f3 ff 54|b.gt|0x32c40
            32ddc|fc 00 00 b4|cbz|x28, 0x32df8
            32de0|68 02 40 f9|ldr|x8, [x19]
            32de4|89 01 80 52|mov|w9, #0xc
            32de8|09 29 00 b9|str|w9, [x8, #0x28]
            32dec|08 01 40 f9|ldr|x8, [x8]
            32df0|e0 03 13 aa|mov|x0, x19
            32df4|00 01 3f d6|blr|x8
            32df8|3a 63 00 a9|stp|x26, x24, [x25]
            32dfc|fc ef 41 a9|ldp|x28, x27, [sp, #0x18]
            32e00|39 01 00 f0|adrp|x25, 0x59000
            32e04|39 e3 16 91|add|x25, x25, #0x5b8
            32e08|0e 00 00 14|b|0x32e40
            32e0c|68 32 41 f9|ldr|x8, [x19, #0x260]
            32e10|08 15 40 f9|ldr|x8, [x8, #0x28]
            32e14|1e fe ff 17|b|0x3268c
            32e18|e0 03 13 aa|mov|x0, x19
            32e1c|01 00 80 52|mov|w1, #0x0
            32e20|22 00 80 52|mov|w2, #0x1
            32e24|04 00 00 14|b|0x32e34
            32e28|e0 03 13 aa|mov|x0, x19
            32e2c|21 00 80 52|mov|w1, #0x1
            32e30|02 00 80 52|mov|w2, #0x0
            32e34|23 00 80 52|mov|w3, #0x1
            32e38|f6 02 00 94|bl|_get_sof
            32e3c|e0 27 00 34|cbz|w0, 0x33338
            32e40|14 00 80 52|mov|w20, #0x0
            32e44|7f 36 02 b9|str|wzr, [x19, #0x234]
            32e48|54 bb ff 34|cbz|w20, 0x325b0
            32e4c|05 fe ff 17|b|0x32660
            32e50|74 16 40 f9|ldr|x20, [x19, #0x28]
            32e54|88 06 40 f9|ldr|x8, [x20, #0x8]
            32e58|c8 00 00 b5|cbnz|x8, 0x32e70
            32e5c|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32e60|e0 03 13 aa|mov|x0, x19
            32e64|00 01 3f d6|blr|x8
            32e68|80 26 00 34|cbz|w0, 0x33338
            32e6c|88 06 40 f9|ldr|x8, [x20, #0x8]
            32e70|98 02 40 f9|ldr|x24, [x20]
            32e74|15 17 40 38|ldrb|w21, [x24], #0x1
            32e78|08 05 00 f1|subs|x8, x8, #0x1
            32e7c|c1 00 00 54|b.ne|0x32e94
            32e80|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32e84|e0 03 13 aa|mov|x0, x19
            32e88|00 01 3f d6|blr|x8
            32e8c|60 25 00 34|cbz|w0, 0x33338
            32e90|98 22 40 a9|ldp|x24, x8, [x20]
            32e94|a9 de 78 d3|lsl|x9, x21, #8
            32e98|0a 17 40 38|ldrb|w10, [x24], #0x1
            32e9c|39 01 0a aa|orr|x25, x9, x10
            32ea0|16 05 00 d1|sub|x22, x8, #0x1
            32ea4|3f 0f 00 f1|cmp|x25, #0x3
            32ea8|23 08 00 54|b.lo|0x32fac
            32eac|d6 00 00 b5|cbnz|x22, 0x32ec4
            32eb0|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32eb4|e0 03 13 aa|mov|x0, x19
            32eb8|00 01 3f d6|blr|x8
            32ebc|e0 23 00 34|cbz|w0, 0x33338
            32ec0|98 5a 40 a9|ldp|x24, x22, [x20]
            32ec4|1a 17 40 38|ldrb|w26, [x24], #0x1
            32ec8|d6 06 00 f1|subs|x22, x22, #0x1
            32ecc|c1 00 00 54|b.ne|0x32ee4
            32ed0|88 0e 40 f9|ldr|x8, [x20, #0x18]
            32ed4|e0 03 13 aa|mov|x0, x19
            32ed8|00 01 3f d6|blr|x8
            32edc|e0 22 00 34|cbz|w0, 0x33338
            32ee0|98 5a 40 a9|ldp|x24, x22, [x20]
            32ee4|15 03 40 39|ldrb|w21, [x24]
            32ee8|68 02 40 f9|ldr|x8, [x19]
            32eec|29 0a 80 52|mov|w9, #0x51
            32ef0|09 69 05 29|stp|w9, w26, [x8, #0x28]
            32ef4|68 02 40 f9|ldr|x8, [x19]
            32ef8|15 31 00 b9|str|w21, [x8, #0x30]
            32efc|68 02 40 f9|ldr|x8, [x19]
            32f00|08 05 40 f9|ldr|x8, [x8, #0x8]
            32f04|e0 03 13 aa|mov|x0, x19
            32f08|21 00 80 52|mov|w1, #0x1
            32f0c|00 01 3f d6|blr|x8
            32f10|5f 83 00 71|cmp|w26, #0x20
            32f14|23 01 00 54|b.lo|0x32f38
            32f18|68 02 40 f9|ldr|x8, [x19]
            32f1c|a9 03 80 52|mov|w9, #0x1d
            32f20|09 69 05 29|stp|w9, w26, [x8, #0x28]
            32f24|68 02 40 f9|ldr|x8, [x19]
            32f28|08 01 40 f9|ldr|x8, [x8]
            32f2c|e0 03 13 aa|mov|x0, x19
            32f30|00 01 3f d6|blr|x8
            32f34|03 00 00 14|b|0x32f40
            32f38|5f 43 00 71|cmp|w26, #0x10
            32f3c|43 01 00 54|b.lo|0x32f64
            32f40|48 43 00 51|sub|w8, w26, #0x10
            32f44|e9 1b 40 f9|ldr|x9, [sp, #0x30]
            32f48|35 49 28 38|strb|w21, [x9, w8, uxtw]
            32f4c|18 07 00 91|add|x24, x24, #0x1
            32f50|d6 06 00 d1|sub|x22, x22, #0x1
            32f54|39 0b 00 d1|sub|x25, x25, #0x2
            32f58|28 0b 00 f1|subs|x8, x25, #0x2
            32f5c|88 fa ff 54|b.hi|0x32eac
            32f60|14 00 00 14|b|0x32fb0
            32f64|a8 0e 00 12|and|w8, w21, #0xf
            32f68|68 4b 3a 38|strb|w8, [x27, w26, uxtw]
            32f6c|a9 7e 04 53|lsr|w9, w21, #4
            32f70|89 4b 3a 38|strb|w9, [x28, w26, uxtw]
            32f74|1f 11 55 6b|cmp|w8, w21, lsr #4
            32f78|a9 fe ff 54|b.ls|0x32f4c
            32f7c|68 02 40 f9|ldr|x8, [x19]
            32f80|c9 03 80 52|mov|w9, #0x1e
            32f84|09 55 05 29|stp|w9, w21, [x8, #0x28]
            32f88|68 02 40 f9|ldr|x8, [x19]
            32f8c|08 01 40 f9|ldr|x8, [x8]
            32f90|e0 03 13 aa|mov|x0, x19
            32f94|00 01 3f d6|blr|x8
            32f98|ed ff ff 17|b|0x32f4c
            32f9c|e0 03 13 aa|mov|x0, x19
            32fa0|1e 01 00 94|bl|_skip_variable
            32fa4|a0 1c 00 34|cbz|w0, 0x33338
            32fa8|a6 ff ff 17|b|0x32e40
            32fac|28 0b 00 d1|sub|x8, x25, #0x2
            32fb0|39 01 00 f0|adrp|x25, 0x59000
            32fb4|39 e3 16 91|add|x25, x25, #0x5b8
            32fb8|e8 00 00 b4|cbz|x8, 0x32fd4
            32fbc|68 02 40 f9|ldr|x8, [x19]
            32fc0|89 01 80 52|mov|w9, #0xc
            32fc4|09 29 00 b9|str|w9, [x8, #0x28]
            32fc8|08 01 40 f9|ldr|x8, [x8]
            32fcc|e0 03 13 aa|mov|x0, x19
            32fd0|00 01 3f d6|blr|x8
            32fd4|98 5a 00 a9|stp|x24, x22, [x20]
            32fd8|9a ff ff 17|b|0x32e40
            32fdc|68 02 40 f9|ldr|x8, [x19]
            32fe0|e9 0a 80 52|mov|w9, #0x57
            32fe4|09 29 00 b9|str|w9, [x8, #0x28]
            32fe8|08 05 40 f9|ldr|x8, [x8, #0x8]
            32fec|e0 03 13 aa|mov|x0, x19
            32ff0|21 00 80 52|mov|w1, #0x1
            32ff4|00 01 3f d6|blr|x8
            32ff8|7f 36 02 b9|str|wzr, [x19, #0x234]
            32ffc|54 00 80 52|mov|w20, #0x2
            33000|cf 00 00 14|b|0x3333c
            33004|75 16 40 f9|ldr|x21, [x19, #0x28]
            33008|b6 52 40 a9|ldp|x22, x20, [x21]
            3300c|68 32 41 f9|ldr|x8, [x19, #0x260]
            33010|08 1d 40 b9|ldr|w8, [x8, #0x1c]
            33014|e8 00 00 35|cbnz|w8, 0x33030
            33018|68 02 40 f9|ldr|x8, [x19]
            3301c|09 08 80 52|mov|w9, #0x40
            33020|09 29 00 b9|str|w9, [x8, #0x28]
            33024|08 01 40 f9|ldr|x8, [x8]
            33028|e0 03 13 aa|mov|x0, x19
            3302c|00 01 3f d6|blr|x8
            33030|d4 00 00 b5|cbnz|x20, 0x33048
            33034|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            33038|e0 03 13 aa|mov|x0, x19
            3303c|00 01 3f d6|blr|x8
            33040|c0 17 00 34|cbz|w0, 0x33338
            33044|b6 52 40 a9|ldp|x22, x20, [x21]
            33048|d7 16 40 38|ldrb|w23, [x22], #0x1
            3304c|88 06 00 f1|subs|x8, x20, #0x1
            33050|c1 00 00 54|b.ne|0x33068
            33054|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            33058|e0 03 13 aa|mov|x0, x19
            3305c|00 01 3f d6|blr|x8
            33060|c0 16 00 34|cbz|w0, 0x33338
            33064|b6 22 40 a9|ldp|x22, x8, [x21]
            33068|d8 16 40 38|ldrb|w24, [x22], #0x1
            3306c|14 05 00 f1|subs|x20, x8, #0x1
            33070|c1 00 00 54|b.ne|0x33088
            33074|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            33078|e0 03 13 aa|mov|x0, x19
            3307c|00 01 3f d6|blr|x8
            33080|c0 15 00 34|cbz|w0, 0x33338
            33084|b6 52 40 a9|ldp|x22, x20, [x21]
            33088|e8 de 78 d3|lsl|x8, x23, #8
            3308c|17 01 18 aa|orr|x23, x8, x24
            33090|da 02 40 39|ldrb|w26, [x22]
            33094|68 02 40 f9|ldr|x8, [x19]
            33098|29 0d 80 52|mov|w9, #0x69
            3309c|09 69 05 29|stp|w9, w26, [x8, #0x28]
            330a0|68 02 40 f9|ldr|x8, [x19]
            330a4|08 05 40 f9|ldr|x8, [x8, #0x8]
            330a8|e0 03 13 aa|mov|x0, x19
            330ac|21 00 80 52|mov|w1, #0x1
            330b0|00 01 3f d6|blr|x8
            330b4|48 7f 7f d3|ubfiz|x8, x26, #1, #32
            330b8|08 19 00 91|add|x8, x8, #0x6
            330bc|49 17 00 51|sub|w9, w26, #0x5
            330c0|ff 02 08 eb|cmp|x23, x8
            330c4|20 09 44 3a|ccmn|w9, #0x4, #0x0, eq
            330c8|c2 01 00 54|b.hs|0x33100
            330cc|68 02 40 f9|ldr|x8, [x19]
            330d0|89 01 80 52|mov|w9, #0xc
            330d4|09 29 00 b9|str|w9, [x8, #0x28]
            330d8|08 01 40 f9|ldr|x8, [x8]
            330dc|e0 03 13 aa|mov|x0, x19
            330e0|00 01 3f d6|blr|x8
            330e4|7a ba 01 b9|str|w26, [x19, #0x1b8]
            330e8|00 e4 00 6f|movi.2d|v0, #0000000000000000
            330ec|60 02 0e ad|stp|q0, q0, [x19, #0x1c0]
            330f0|d6 06 00 91|add|x22, x22, #0x1
            330f4|88 06 00 d1|sub|x8, x20, #0x1
            330f8|fa 00 00 35|cbnz|w26, 0x33114
            330fc|59 00 00 14|b|0x33260
            33100|7a ba 01 b9|str|w26, [x19, #0x1b8]
            33104|00 e4 00 6f|movi.2d|v0, #0000000000000000
            33108|60 02 0e ad|stp|q0, q0, [x19, #0x1c0]
            3310c|d6 06 00 91|add|x22, x22, #0x1
            33110|88 06 00 d1|sub|x8, x20, #0x1
            33114|17 00 80 d2|mov|x23, #0x0
            33118|78 02 07 91|add|x24, x19, #0x1c0
            3311c|99 00 80 52|mov|w25, #0x4
            33120|fa 1b 00 f9|str|x26, [sp, #0x30]
            33124|c8 00 00 b5|cbnz|x8, 0x3313c
            33128|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            3312c|e0 03 13 aa|mov|x0, x19
            33130|00 01 3f d6|blr|x8
            33134|20 10 00 34|cbz|w0, 0x33338
            33138|b6 22 40 a9|ldp|x22, x8, [x21]
            3313c|dc 16 40 38|ldrb|w28, [x22], #0x1
            33140|1a 05 00 f1|subs|x26, x8, #0x1
            33144|c1 00 00 54|b.ne|0x3315c
            33148|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            3314c|e0 03 13 aa|mov|x0, x19
            33150|00 01 3f d6|blr|x8
            33154|20 0f 00 34|cbz|w0, 0x33338
            33158|b6 6a 40 a9|ldp|x22, x26, [x21]
            3315c|d4 02 40 39|ldrb|w20, [x22]
            33160|7b 9a 40 f9|ldr|x27, [x19, #0x130]
            33164|68 3a 40 b9|ldr|w8, [x19, #0x38]
            33168|1f 05 00 71|cmp|w8, #0x1
            3316c|4b 02 00 54|b.lt|0x331b4
            33170|1f 11 00 71|cmp|w8, #0x4
            33174|08 31 99 1a|csel|w8, w8, w25, lo
            33178|09 05 00 51|sub|w9, w8, #0x1
            3317c|0a 0c 80 52|mov|w10, #0x60
            33180|29 6d aa 9b|umaddl|x9, w9, w10, x27
            33184|29 81 01 91|add|x9, x9, #0x60
            33188|ea 03 18 aa|mov|x10, x24
            3318c|6b 03 40 b9|ldr|w11, [x27]
            33190|7f 01 1c 6b|cmp|w11, w28
            33194|61 00 00 54|b.ne|0x331a0
            33198|4b 01 40 f9|ldr|x11, [x10]
            3319c|8b 01 00 b4|cbz|x11, 0x331cc
            331a0|7b 83 01 91|add|x27, x27, #0x60
            331a4|4a 21 00 91|add|x10, x10, #0x8
            331a8|08 05 00 f1|subs|x8, x8, #0x1
            331ac|01 ff ff 54|b.ne|0x3318c
            331b0|fb 03 09 aa|mov|x27, x9
            331b4|68 02 40 f9|ldr|x8, [x19]
            331b8|19 71 05 29|stp|w25, w28, [x8, #0x28]
            331bc|68 02 40 f9|ldr|x8, [x19]
            331c0|08 01 40 f9|ldr|x8, [x8]
            331c4|e0 03 13 aa|mov|x0, x19
            331c8|00 01 3f d6|blr|x8
            331cc|1b 7b 37 f8|str|x27, [x24, x23, lsl #3]
            331d0|88 7e 04 53|lsr|w8, w20, #4
            331d4|89 0e 00 12|and|w9, w20, #0xf
            331d8|68 a7 02 29|stp|w8, w9, [x27, #0x14]
            331dc|68 02 40 f9|ldr|x8, [x19]
            331e0|1c 2d 00 b9|str|w28, [x8, #0x2c]
            331e4|69 17 40 b9|ldr|w9, [x27, #0x14]
            331e8|09 31 00 b9|str|w9, [x8, #0x30]
            331ec|69 1b 40 b9|ldr|w9, [x27, #0x18]
            331f0|09 35 00 b9|str|w9, [x8, #0x34]
            331f4|49 0d 80 52|mov|w9, #0x6a
            331f8|09 29 00 b9|str|w9, [x8, #0x28]
            331fc|08 05 40 f9|ldr|x8, [x8, #0x8]
            33200|e0 03 13 aa|mov|x0, x19
            33204|21 00 80 52|mov|w1, #0x1
            33208|00 01 3f d6|blr|x8
            3320c|f7 01 00 b4|cbz|x23, 0x33248
            33210|14 00 80 d2|mov|x20, #0x0
            33214|68 0e 14 8b|add|x8, x19, x20, lsl #3
            33218|08 e1 40 f9|ldr|x8, [x8, #0x1c0]
            3321c|1f 01 1b eb|cmp|x8, x27
            33220|e1 00 00 54|b.ne|0x3323c
            33224|68 02 40 f9|ldr|x8, [x19]
            33228|19 71 05 29|stp|w25, w28, [x8, #0x28]
            3322c|68 02 40 f9|ldr|x8, [x19]
            33230|08 01 40 f9|ldr|x8, [x8]
            33234|e0 03 13 aa|mov|x0, x19
            33238|00 01 3f d6|blr|x8
            3323c|94 06 00 91|add|x20, x20, #0x1
            33240|ff 02 14 eb|cmp|x23, x20
            33244|81 fe ff 54|b.ne|0x33214
            33248|f7 06 00 91|add|x23, x23, #0x1
            3324c|d6 06 00 91|add|x22, x22, #0x1
            33250|48 07 00 d1|sub|x8, x26, #0x1
            33254|e9 1b 40 f9|ldr|x9, [sp, #0x30]
            33258|ff 02 09 eb|cmp|x23, x9
            3325c|41 f6 ff 54|b.ne|0x33124
            33260|c8 00 00 b5|cbnz|x8, 0x33278
            33264|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            33268|e0 03 13 aa|mov|x0, x19
            3326c|00 01 3f d6|blr|x8
            33270|40 06 00 34|cbz|w0, 0x33338
            33274|b6 22 40 a9|ldp|x22, x8, [x21]
            33278|c9 16 40 38|ldrb|w9, [x22], #0x1
            3327c|69 16 02 b9|str|w9, [x19, #0x214]
            33280|08 05 00 f1|subs|x8, x8, #0x1
            33284|c1 00 00 54|b.ne|0x3329c
            33288|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            3328c|e0 03 13 aa|mov|x0, x19
            33290|00 01 3f d6|blr|x8
            33294|20 05 00 34|cbz|w0, 0x33338
            33298|b6 22 40 a9|ldp|x22, x8, [x21]
            3329c|c9 16 40 38|ldrb|w9, [x22], #0x1
            332a0|69 1a 02 b9|str|w9, [x19, #0x218]
            332a4|08 05 00 f1|subs|x8, x8, #0x1
            332a8|c1 00 00 54|b.ne|0x332c0
            332ac|a8 0e 40 f9|ldr|x8, [x21, #0x18]
            332b0|e0 03 13 aa|mov|x0, x19
            332b4|00 01 3f d6|blr|x8
            332b8|00 04 00 34|cbz|w0, 0x33338
            332bc|b6 22 40 a9|ldp|x22, x8, [x21]
            332c0|c9 16 40 38|ldrb|w9, [x22], #0x1
            332c4|2a 7d 04 53|lsr|w10, w9, #4
            332c8|6a 1e 02 b9|str|w10, [x19, #0x21c]
            332cc|29 0d 00 12|and|w9, w9, #0xf
            332d0|69 22 02 b9|str|w9, [x19, #0x220]
            332d4|69 02 40 f9|ldr|x9, [x19]
            332d8|6a 16 42 b9|ldr|w10, [x19, #0x214]
            332dc|6b 0d 80 52|mov|w11, #0x6b
            332e0|2a 2d 00 b9|str|w10, [x9, #0x2c]
            332e4|6a 1a 42 b9|ldr|w10, [x19, #0x218]
            332e8|2a 31 00 b9|str|w10, [x9, #0x30]
            332ec|6a 1e 42 b9|ldr|w10, [x19, #0x21c]
            332f0|2a 35 00 b9|str|w10, [x9, #0x34]
            332f4|6a 22 42 b9|ldr|w10, [x19, #0x220]
            332f8|2a 39 00 b9|str|w10, [x9, #0x38]
            332fc|17 05 00 d1|sub|x23, x8, #0x1
            33300|2b 29 00 b9|str|w11, [x9, #0x28]
            33304|28 05 40 f9|ldr|x8, [x9, #0x8]
            33308|34 00 80 52|mov|w20, #0x1
            3330c|e0 03 13 aa|mov|x0, x19
            33310|21 00 80 52|mov|w1, #0x1
            33314|00 01 3f d6|blr|x8
            33318|68 32 41 f9|ldr|x8, [x19, #0x260]
            3331c|1f 21 00 b9|str|wzr, [x8, #0x20]
            33320|68 ae 40 b9|ldr|w8, [x19, #0xac]
            33324|08 05 00 11|add|w8, w8, #0x1
            33328|68 ae 00 b9|str|w8, [x19, #0xac]
            3332c|b6 5e 00 a9|stp|x22, x23, [x21]
            33330|7f 36 02 b9|str|wzr, [x19, #0x234]
            33334|02 00 00 14|b|0x3333c
            33338|14 00 80 52|mov|w20, #0x0
            3333c|a8 03 5a f8|ldur|x8, [x29, #-0x60]
            33340|69 01 00 b0|adrp|x9, 0x60000
            33344|29 0d 40 f9|ldr|x9, [x9, #0x18]
            33348|29 01 40 f9|ldr|x9, [x9]
            3334c|3f 01 08 eb|cmp|x9, x8
            33350|41 01 00 54|b.ne|0x33378
            33354|e0 03 14 aa|mov|x0, x20
            33358|fd 7b 5b a9|ldp|x29, x30, [sp, #0x1b0]
            3335c|f4 4f 5a a9|ldp|x20, x19, [sp, #0x1a0]
            33360|f6 57 59 a9|ldp|x22, x21, [sp, #0x190]
            33364|f8 5f 58 a9|ldp|x24, x23, [sp, #0x180]
            33368|fa 67 57 a9|ldp|x26, x25, [sp, #0x170]
            3336c|fc 6f 56 a9|ldp|x28, x27, [sp, #0x160]
            33370|ff 03 07 91|add|sp, sp, #0x1c0
            33374|c0 03 5f d6|ret|
            33378|a5 94 00 94|bl|0x5860c
            """),
        lower: 0x32540, upper: 0x3337c,
        bytes: storage([
            (0x595b8, [0x10, 0x00, 0x10, 0x00, 0x2e, 0x01, 0x24, 0x00, 0x28, 0x00, 0x08, 0x00, 0x08, 0x00, 0x08, 0x00, 0x08, 0x00, 0x21, 0x00, 0xeb, 0x01, 0xe7, 0x01, 0xf5, 0x01, 0x08, 0x00, 0x08, 0x00, 0x08, 0x00, 0x15, 0x00, 0x15, 0x00, 0x15, 0x00, 0x15, 0x00, 0x15, 0x00, 0x15, 0x00, 0x15, 0x00, 0x15, 0x00, 0x33, 0x01, 0x58, 0x02, 0x62, 0x02, 0x58, 0x01, 0x48, 0x02, 0xf4, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0xe4, 0x01])
        ]),
        expected: [
            0x32678: [0x326bc, 0x326bc, 0x32b34, 0x3270c, 0x3271c, 0x3269c, 0x3269c, 0x3269c, 0x3269c, 0x32700, 0x32e28, 0x32e18, 0x32e50, 0x3269c, 0x3269c, 0x3269c, 0x326d0, 0x326d0, 0x326d0, 0x326d0, 0x326d0, 0x326d0, 0x326d0, 0x326d0, 0x32b48, 0x32fdc, 0x33004, 0x32bdc, 0x32f9c, 0x32a4c, 0x326f4, 0x326f4, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x3267c, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x326f4, 0x32e0c]
        ])

    // _j12init_color_converter, retained first-occurrence listing lines 3423...3792.
    static let color12 = Self(
        rows: parse("""
            417c|f6 57 bd a9|stp|x22, x21, [sp, #-0x30]!
            4180|f4 4f 01 a9|stp|x20, x19, [sp, #0x10]
            4184|fd 7b 02 a9|stp|x29, x30, [sp, #0x20]
            4188|fd 83 00 91|add|x29, sp, #0x20
            418c|f4 03 00 aa|mov|x20, x0
            4190|08 f8 40 f9|ldr|x8, [x0, #0x1f0]
            4194|09 21 40 b9|ldr|w9, [x8, #0x20]
            4198|08 58 40 b9|ldr|w8, [x0, #0x58]
            419c|a9 0f 00 34|cbz|w9, 0x4390
            41a0|09 35 00 51|sub|w9, w8, #0xd
            41a4|3f 11 00 31|cmn|w9, #0x4
            41a8|02 01 00 54|b.hs|0x41c8
            41ac|89 02 40 f9|ldr|x9, [x20]
            41b0|0a 02 80 52|mov|w10, #0x10
            41b4|2a 21 05 29|stp|w10, w8, [x9, #0x28]
            41b8|88 02 40 f9|ldr|x8, [x20]
            41bc|08 01 40 f9|ldr|x8, [x8]
            41c0|e0 03 14 aa|mov|x0, x20
            41c4|00 01 3f d6|blr|x8
            41c8|88 06 40 f9|ldr|x8, [x20, #0x8]
            41cc|08 01 40 f9|ldr|x8, [x8]
            41d0|35 00 80 52|mov|w21, #0x1
            41d4|e0 03 14 aa|mov|x0, x20
            41d8|21 00 80 52|mov|w1, #0x1
            41dc|02 06 80 52|mov|w2, #0x30
            41e0|00 01 3f d6|blr|x8
            41e4|f3 03 00 aa|mov|x19, x0
            41e8|80 0e 01 f9|str|x0, [x20, #0x218]
            41ec|08 00 00 90|adrp|x8, 0x4000
            41f0|08 11 1d 91|add|x8, x8, #0x744
            41f4|08 00 00 f9|str|x8, [x0]
            41f8|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            41fc|1f 3d 00 71|cmp|w8, #0xf
            4200|08 1d 00 54|b.hi|0x45a0
            4204|a9 22 c8 1a|lsl|w9, w21, w8
            4208|8a f8 9f 52|mov|w10, #0xffc4
            420c|3f 01 0a 6a|tst|w9, w10
            4210|60 0c 00 54|b.eq|0x439c
            4214|89 3a 40 b9|ldr|w9, [x20, #0x38]
            4218|aa 02 00 90|adrp|x10, 0x58000
            421c|4a 11 1f 91|add|x10, x10, #0x7c4
            4220|48 59 68 b8|ldr|w8, [x10, w8, uxtw #2]
            4224|3f 01 08 6b|cmp|w9, w8
            4228|e0 00 00 54|b.eq|0x4244
            422c|88 02 40 f9|ldr|x8, [x20]
            4230|49 01 80 52|mov|w9, #0xa
            4234|09 29 00 b9|str|w9, [x8, #0x28]
            4238|08 01 40 f9|ldr|x8, [x8]
            423c|e0 03 14 aa|mov|x0, x20
            4240|00 01 3f d6|blr|x8
            4244|88 62 40 b9|ldr|w8, [x20, #0x60]
            4248|1f 09 00 71|cmp|w8, #0x2
            424c|ed 04 00 54|b.le|0x42e8
            4250|1f 0d 00 71|cmp|w8, #0x3
            4254|40 0b 00 54|b.eq|0x43bc
            4258|1f 11 00 71|cmp|w8, #0x4
            425c|c0 0e 00 54|b.eq|0x4434
            4260|1f 15 00 71|cmp|w8, #0x5
            4264|a1 16 00 54|b.ne|0x4538
            4268|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            426c|08 21 40 b9|ldr|w8, [x8, #0x20]
            4270|48 01 00 34|cbz|w8, 0x4298
            4274|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            4278|1f 15 00 71|cmp|w8, #0x5
            427c|e0 00 00 54|b.eq|0x4298
            4280|88 02 40 f9|ldr|x8, [x20]
            4284|89 03 80 52|mov|w9, #0x1c
            4288|09 29 00 b9|str|w9, [x8, #0x28]
            428c|08 01 40 f9|ldr|x8, [x8]
            4290|e0 03 14 aa|mov|x0, x20
            4294|00 01 3f d6|blr|x8
            4298|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            429c|1f 11 00 71|cmp|w8, #0x4
            42a0|e0 00 00 54|b.eq|0x42bc
            42a4|88 02 40 f9|ldr|x8, [x20]
            42a8|69 01 80 52|mov|w9, #0xb
            42ac|09 29 00 b9|str|w9, [x8, #0x28]
            42b0|08 01 40 f9|ldr|x8, [x8]
            42b4|e0 03 14 aa|mov|x0, x20
            42b8|00 01 3f d6|blr|x8
            42bc|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            42c0|1f 15 00 71|cmp|w8, #0x5
            42c4|40 15 00 54|b.eq|0x456c
            42c8|1f 11 00 71|cmp|w8, #0x4
            42cc|41 0e 00 54|b.ne|0x4494
            42d0|08 00 00 90|adrp|x8, 0x4000
            42d4|08 71 1e 91|add|x8, x8, #0x79c
            42d8|68 02 00 f9|str|x8, [x19]
            42dc|08 00 00 b0|adrp|x8, 0x5000
            42e0|08 91 1f 91|add|x8, x8, #0x7e4
            42e4|a4 00 00 14|b|0x4574
            42e8|1f 05 00 71|cmp|w8, #0x1
            42ec|60 0e 00 54|b.eq|0x44b8
            42f0|1f 09 00 71|cmp|w8, #0x2
            42f4|21 12 00 54|b.ne|0x4538
            42f8|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            42fc|08 21 40 b9|ldr|w8, [x8, #0x20]
            4300|a8 01 00 34|cbz|w8, 0x4334
            4304|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            4308|1f 09 00 71|cmp|w8, #0x2
            430c|40 01 00 54|b.eq|0x4334
            4310|08 19 00 51|sub|w8, w8, #0x6
            4314|1f 29 00 71|cmp|w8, #0xa
            4318|e3 00 00 54|b.lo|0x4334
            431c|88 02 40 f9|ldr|x8, [x20]
            4320|89 03 80 52|mov|w9, #0x1c
            4324|09 29 00 b9|str|w9, [x8, #0x28]
            4328|08 01 40 f9|ldr|x8, [x8]
            432c|e0 03 14 aa|mov|x0, x20
            4330|00 01 3f d6|blr|x8
            4334|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            4338|1f 0d 00 71|cmp|w8, #0x3
            433c|e0 00 00 54|b.eq|0x4358
            4340|88 02 40 f9|ldr|x8, [x20]
            4344|69 01 80 52|mov|w9, #0xb
            4348|09 29 00 b9|str|w9, [x8, #0x28]
            434c|08 01 40 f9|ldr|x8, [x8]
            4350|e0 03 14 aa|mov|x0, x20
            4354|00 01 3f d6|blr|x8
            4358|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            435c|29 00 80 52|mov|w9, #0x1
            4360|29 21 c8 9a|lsl|x9, x9, x8
            4364|8a 18 82 52|mov|w10, #0x10c4
            4368|3f 01 0a ea|tst|x9, x10
            436c|80 00 00 54|b.eq|0x437c
            4370|8a 28 80 52|mov|w10, #0x144
            4374|29 01 0a 8a|and|x9, x9, x10
            4378|a9 0f 00 b5|cbnz|x9, 0x456c
            437c|1f 09 00 71|cmp|w8, #0x2
            4380|61 16 00 54|b.ne|0x464c
            4384|08 00 00 b0|adrp|x8, 0x5000
            4388|08 d1 00 91|add|x8, x8, #0x34
            438c|7a 00 00 14|b|0x4574
            4390|1f 31 00 71|cmp|w8, #0xc
            4394|c1 f0 ff 54|b.ne|0x41ac
            4398|8c ff ff 17|b|0x41c8
            439c|29 00 80 52|mov|w9, #0x1
            43a0|29 21 c8 1a|lsl|w9, w9, w8
            43a4|3f 05 1c 72|tst|w9, #0x30
            43a8|00 0f 00 54|b.eq|0x4588
            43ac|88 3a 40 b9|ldr|w8, [x20, #0x38]
            43b0|1f 11 00 71|cmp|w8, #0x4
            43b4|c1 f3 ff 54|b.ne|0x422c
            43b8|a3 ff ff 17|b|0x4244
            43bc|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            43c0|08 21 40 b9|ldr|w8, [x8, #0x20]
            43c4|48 01 00 34|cbz|w8, 0x43ec
            43c8|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            43cc|1f 0d 00 71|cmp|w8, #0x3
            43d0|e0 00 00 54|b.eq|0x43ec
            43d4|88 02 40 f9|ldr|x8, [x20]
            43d8|89 03 80 52|mov|w9, #0x1c
            43dc|09 29 00 b9|str|w9, [x8, #0x28]
            43e0|08 01 40 f9|ldr|x8, [x8]
            43e4|e0 03 14 aa|mov|x0, x20
            43e8|00 01 3f d6|blr|x8
            43ec|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            43f0|1f 0d 00 71|cmp|w8, #0x3
            43f4|e0 00 00 54|b.eq|0x4410
            43f8|88 02 40 f9|ldr|x8, [x20]
            43fc|69 01 80 52|mov|w9, #0xb
            4400|09 29 00 b9|str|w9, [x8, #0x28]
            4404|08 01 40 f9|ldr|x8, [x8]
            4408|e0 03 14 aa|mov|x0, x20
            440c|00 01 3f d6|blr|x8
            4410|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            4414|1f 09 00 71|cmp|w8, #0x2
            4418|01 0d 00 54|b.ne|0x45b8
            441c|08 00 00 90|adrp|x8, 0x4000
            4420|08 71 1e 91|add|x8, x8, #0x79c
            4424|68 02 00 f9|str|x8, [x19]
            4428|08 00 00 b0|adrp|x8, 0x5000
            442c|08 71 1b 91|add|x8, x8, #0x6dc
            4430|51 00 00 14|b|0x4574
            4434|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            4438|08 21 40 b9|ldr|w8, [x8, #0x20]
            443c|48 01 00 34|cbz|w8, 0x4464
            4440|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            4444|1f 11 00 71|cmp|w8, #0x4
            4448|e0 00 00 54|b.eq|0x4464
            444c|88 02 40 f9|ldr|x8, [x20]
            4450|89 03 80 52|mov|w9, #0x1c
            4454|09 29 00 b9|str|w9, [x8, #0x28]
            4458|08 01 40 f9|ldr|x8, [x8]
            445c|e0 03 14 aa|mov|x0, x20
            4460|00 01 3f d6|blr|x8
            4464|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            4468|1f 11 00 71|cmp|w8, #0x4
            446c|e0 00 00 54|b.eq|0x4488
            4470|88 02 40 f9|ldr|x8, [x20]
            4474|69 01 80 52|mov|w9, #0xb
            4478|09 29 00 b9|str|w9, [x8, #0x28]
            447c|08 01 40 f9|ldr|x8, [x8]
            4480|e0 03 14 aa|mov|x0, x20
            4484|00 01 3f d6|blr|x8
            4488|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            448c|1f 11 00 71|cmp|w8, #0x4
            4490|e0 06 00 54|b.eq|0x456c
            4494|88 02 40 f9|ldr|x8, [x20]
            4498|89 03 80 52|mov|w9, #0x1c
            449c|09 29 00 b9|str|w9, [x8, #0x28]
            44a0|01 01 40 f9|ldr|x1, [x8]
            44a4|e0 03 14 aa|mov|x0, x20
            44a8|fd 7b 42 a9|ldp|x29, x30, [sp, #0x20]
            44ac|f4 4f 41 a9|ldp|x20, x19, [sp, #0x10]
            44b0|f6 57 c3 a8|ldp|x22, x21, [sp], #0x30
            44b4|20 00 1f d6|br|x1
            44b8|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            44bc|08 21 40 b9|ldr|w8, [x8, #0x20]
            44c0|48 01 00 34|cbz|w8, 0x44e8
            44c4|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            44c8|1f 05 00 71|cmp|w8, #0x1
            44cc|e0 00 00 54|b.eq|0x44e8
            44d0|88 02 40 f9|ldr|x8, [x20]
            44d4|89 03 80 52|mov|w9, #0x1c
            44d8|09 29 00 b9|str|w9, [x8, #0x28]
            44dc|08 01 40 f9|ldr|x8, [x8]
            44e0|e0 03 14 aa|mov|x0, x20
            44e4|00 01 3f d6|blr|x8
            44e8|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            44ec|1f 05 00 71|cmp|w8, #0x1
            44f0|e0 00 00 54|b.eq|0x450c
            44f4|88 02 40 f9|ldr|x8, [x20]
            44f8|69 01 80 52|mov|w9, #0xb
            44fc|09 29 00 b9|str|w9, [x8, #0x28]
            4500|08 01 40 f9|ldr|x8, [x8]
            4504|e0 03 14 aa|mov|x0, x20
            4508|00 01 3f d6|blr|x8
            450c|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            4510|1f 05 00 71|cmp|w8, #0x1
            4514|80 0b 00 54|b.eq|0x4684
            4518|1f 09 00 71|cmp|w8, #0x2
            451c|41 07 00 54|b.ne|0x4604
            4520|08 00 00 90|adrp|x8, 0x4000
            4524|08 71 1e 91|add|x8, x8, #0x79c
            4528|68 02 00 f9|str|x8, [x19]
            452c|08 00 00 90|adrp|x8, 0x4000
            4530|08 41 2f 91|add|x8, x8, #0xbd0
            4534|10 00 00 14|b|0x4574
            4538|89 3e 40 b9|ldr|w9, [x20, #0x3c]
            453c|1f 01 09 6b|cmp|w8, w9
            4540|a1 00 00 54|b.ne|0x4554
            4544|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            4548|89 3a 40 b9|ldr|w9, [x20, #0x38]
            454c|1f 01 09 6b|cmp|w8, w9
            4550|e0 00 00 54|b.eq|0x456c
            4554|88 02 40 f9|ldr|x8, [x20]
            4558|89 03 80 52|mov|w9, #0x1c
            455c|09 29 00 b9|str|w9, [x8, #0x28]
            4560|08 01 40 f9|ldr|x8, [x8]
            4564|e0 03 14 aa|mov|x0, x20
            4568|00 01 3f d6|blr|x8
            456c|08 00 00 90|adrp|x8, 0x4000
            4570|08 61 31 91|add|x8, x8, #0xc58
            4574|68 0a 00 f9|str|x8, [x19, #0x10]
            4578|fd 7b 42 a9|ldp|x29, x30, [sp, #0x20]
            457c|f4 4f 41 a9|ldp|x20, x19, [sp, #0x10]
            4580|f6 57 c3 a8|ldp|x22, x21, [sp], #0x30
            4584|c0 03 5f d6|ret|
            4588|1f 0d 00 71|cmp|w8, #0x3
            458c|a1 00 00 54|b.ne|0x45a0
            4590|88 3a 40 b9|ldr|w8, [x20, #0x38]
            4594|1f 0d 00 71|cmp|w8, #0x3
            4598|a1 e4 ff 54|b.ne|0x422c
            459c|2a ff ff 17|b|0x4244
            45a0|1f 05 00 71|cmp|w8, #0x1
            45a4|81 02 00 54|b.ne|0x45f4
            45a8|88 3a 40 b9|ldr|w8, [x20, #0x38]
            45ac|1f 05 00 71|cmp|w8, #0x1
            45b0|e1 e3 ff 54|b.ne|0x422c
            45b4|24 ff ff 17|b|0x4244
            45b8|09 19 00 51|sub|w9, w8, #0x6
            45bc|3f 25 00 71|cmp|w9, #0x9
            45c0|08 04 00 54|b.hi|0x4640
            45c4|08 00 00 90|adrp|x8, 0x4000
            45c8|08 71 1e 91|add|x8, x8, #0x79c
            45cc|68 02 00 f9|str|x8, [x19]
            45d0|a8 02 00 90|adrp|x8, 0x58000
            45d4|08 91 1e 91|add|x8, x8, #0x7a4
            45d8|8a 00 00 10|adr|x10, #16
            45dc|0b 69 69 38|ldrb|w11, [x8, x9]
            45e0|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            45e4|40 01 1f d6|br|x10
            45e8|08 00 00 b0|adrp|x8, 0x5000
            45ec|08 91 06 91|add|x8, x8, #0x1a4
            45f0|e1 ff ff 17|b|0x4574
            45f4|88 3a 40 b9|ldr|w8, [x20, #0x38]
            45f8|1f 01 00 71|cmp|w8, #0x0
            45fc|8d e1 ff 54|b.le|0x422c
            4600|11 ff ff 17|b|0x4244
            4604|09 19 00 51|sub|w9, w8, #0x6
            4608|3f 25 00 71|cmp|w9, #0x9
            460c|88 03 00 54|b.hi|0x467c
            4610|08 00 00 90|adrp|x8, 0x4000
            4614|08 71 1e 91|add|x8, x8, #0x79c
            4618|68 02 00 f9|str|x8, [x19]
            461c|a8 02 00 90|adrp|x8, 0x58000
            4620|08 e1 1e 91|add|x8, x8, #0x7b8
            4624|8a 00 00 10|adr|x10, #16
            4628|0b 69 69 38|ldrb|w11, [x8, x9]
            462c|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            4630|40 01 1f d6|br|x10
            4634|08 00 00 90|adrp|x8, 0x4000
            4638|08 61 24 91|add|x8, x8, #0x918
            463c|ce ff ff 17|b|0x4574
            4640|1f 0d 00 71|cmp|w8, #0x3
            4644|81 f2 ff 54|b.ne|0x4494
            4648|c9 ff ff 17|b|0x456c
            464c|08 19 00 51|sub|w8, w8, #0x6
            4650|1f 25 00 71|cmp|w8, #0x9
            4654|08 f2 ff 54|b.hi|0x4494
            4658|a9 02 00 90|adrp|x9, 0x58000
            465c|29 b9 1e 91|add|x9, x9, #0x7ae
            4660|8a 00 00 10|adr|x10, #16
            4664|2b 69 68 38|ldrb|w11, [x9, x8]
            4668|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            466c|40 01 1f d6|br|x10
            4670|08 00 00 90|adrp|x8, 0x4000
            4674|08 71 38 91|add|x8, x8, #0xe1c
            4678|bf ff ff 17|b|0x4574
            467c|1f 0d 00 71|cmp|w8, #0x3
            4680|a1 f0 ff 54|b.ne|0x4494
            4684|08 00 00 90|adrp|x8, 0x4000
            4688|08 21 1d 91|add|x8, x8, #0x748
            468c|ba ff ff 17|b|0x4574
            4690|08 00 00 b0|adrp|x8, 0x5000
            4694|08 41 17 91|add|x8, x8, #0x5d0
            4698|b7 ff ff 17|b|0x4574
            469c|08 00 00 b0|adrp|x8, 0x5000
            46a0|08 e1 0e 91|add|x8, x8, #0x3b8
            46a4|b4 ff ff 17|b|0x4574
            46a8|08 00 00 b0|adrp|x8, 0x5000
            46ac|08 11 13 91|add|x8, x8, #0x4c4
            46b0|b1 ff ff 17|b|0x4574
            46b4|08 00 00 90|adrp|x8, 0x4000
            46b8|08 11 2d 91|add|x8, x8, #0xb44
            46bc|ae ff ff 17|b|0x4574
            46c0|08 00 00 90|adrp|x8, 0x4000
            46c4|08 b1 28 91|add|x8, x8, #0xa2c
            46c8|ab ff ff 17|b|0x4574
            46cc|08 00 00 90|adrp|x8, 0x4000
            46d0|08 e1 2a 91|add|x8, x8, #0xab8
            46d4|a8 ff ff 17|b|0x4574
            46d8|08 00 00 90|adrp|x8, 0x4000
            46dc|08 21 3f 91|add|x8, x8, #0xfc8
            46e0|a5 ff ff 17|b|0x4574
            46e4|08 00 00 b0|adrp|x8, 0x5000
            46e8|08 71 02 91|add|x8, x8, #0x9c
            46ec|a2 ff ff 17|b|0x4574
            46f0|08 00 00 90|adrp|x8, 0x4000
            46f4|08 c1 3b 91|add|x8, x8, #0xef0
            46f8|9f ff ff 17|b|0x4574
            46fc|08 00 00 b0|adrp|x8, 0x5000
            4700|08 b1 0a 91|add|x8, x8, #0x2ac
            4704|9c ff ff 17|b|0x4574
            4708|08 00 00 90|adrp|x8, 0x4000
            470c|08 71 3d 91|add|x8, x8, #0xf5c
            4710|99 ff ff 17|b|0x4574
            4714|08 00 00 90|adrp|x8, 0x4000
            4718|08 41 22 91|add|x8, x8, #0x890
            471c|96 ff ff 17|b|0x4574
            4720|08 00 00 90|adrp|x8, 0x4000
            4724|08 81 26 91|add|x8, x8, #0x9a0
            4728|93 ff ff 17|b|0x4574
            472c|08 00 00 90|adrp|x8, 0x4000
            4730|08 d1 36 91|add|x8, x8, #0xdb4
            4734|90 ff ff 17|b|0x4574
            4738|08 00 00 90|adrp|x8, 0x4000
            473c|08 11 3a 91|add|x8, x8, #0xe84
            4740|8d ff ff 17|b|0x4574
            """),
        lower: 0x417c, upper: 0x4744,
        bytes: storage([
            (0x587a4, [0x3f, 0x00, 0x45, 0x2d, 0x30, 0x2a, 0x00, 0x2d, 0x30, 0x2a]),
            (0x587b8, [0x38, 0x00, 0x3b, 0x23, 0x26, 0x20, 0x00, 0x23, 0x26, 0x20]),
            (0x587ae, [0x2f, 0x00, 0x32, 0x20, 0x26, 0x1a, 0x00, 0x20, 0x26, 0x1a])
        ]),
        expected: [
            0x45e4: [0x46e4, 0x45e8, 0x46fc, 0x469c, 0x46a8, 0x4690, 0x45e8, 0x469c, 0x46a8, 0x4690],
            0x4630: [0x4714, 0x4634, 0x4720, 0x46c0, 0x46cc, 0x46b4, 0x4634, 0x46c0, 0x46cc, 0x46b4],
            0x466c: [0x472c, 0x4670, 0x4738, 0x46f0, 0x4708, 0x46d8, 0x4670, 0x46f0, 0x4708, 0x46d8]
        ])

    // _j16init_color_converter, retained first-occurrence listing lines 4958...5327.
    static let color16 = Self(
        rows: parse("""
            590c|f6 57 bd a9|stp|x22, x21, [sp, #-0x30]!
            5910|f4 4f 01 a9|stp|x20, x19, [sp, #0x10]
            5914|fd 7b 02 a9|stp|x29, x30, [sp, #0x20]
            5918|fd 83 00 91|add|x29, sp, #0x20
            591c|f4 03 00 aa|mov|x20, x0
            5920|08 f8 40 f9|ldr|x8, [x0, #0x1f0]
            5924|09 21 40 b9|ldr|w9, [x8, #0x20]
            5928|08 58 40 b9|ldr|w8, [x0, #0x58]
            592c|a9 0f 00 34|cbz|w9, 0x5b20
            5930|09 45 00 51|sub|w9, w8, #0x11
            5934|3f 11 00 31|cmn|w9, #0x4
            5938|02 01 00 54|b.hs|0x5958
            593c|89 02 40 f9|ldr|x9, [x20]
            5940|0a 02 80 52|mov|w10, #0x10
            5944|2a 21 05 29|stp|w10, w8, [x9, #0x28]
            5948|88 02 40 f9|ldr|x8, [x20]
            594c|08 01 40 f9|ldr|x8, [x8]
            5950|e0 03 14 aa|mov|x0, x20
            5954|00 01 3f d6|blr|x8
            5958|88 06 40 f9|ldr|x8, [x20, #0x8]
            595c|08 01 40 f9|ldr|x8, [x8]
            5960|35 00 80 52|mov|w21, #0x1
            5964|e0 03 14 aa|mov|x0, x20
            5968|21 00 80 52|mov|w1, #0x1
            596c|02 05 80 52|mov|w2, #0x28
            5970|00 01 3f d6|blr|x8
            5974|f3 03 00 aa|mov|x19, x0
            5978|80 0e 01 f9|str|x0, [x20, #0x218]
            597c|08 00 00 90|adrp|x8, 0x5000
            5980|08 51 3b 91|add|x8, x8, #0xed4
            5984|08 00 00 f9|str|x8, [x0]
            5988|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            598c|1f 3d 00 71|cmp|w8, #0xf
            5990|08 1d 00 54|b.hi|0x5d30
            5994|a9 22 c8 1a|lsl|w9, w21, w8
            5998|8a f8 9f 52|mov|w10, #0xffc4
            599c|3f 01 0a 6a|tst|w9, w10
            59a0|60 0c 00 54|b.eq|0x5b2c
            59a4|89 3a 40 b9|ldr|w9, [x20, #0x38]
            59a8|8a 02 00 f0|adrp|x10, 0x58000
            59ac|4a a1 20 91|add|x10, x10, #0x828
            59b0|48 59 68 b8|ldr|w8, [x10, w8, uxtw #2]
            59b4|3f 01 08 6b|cmp|w9, w8
            59b8|e0 00 00 54|b.eq|0x59d4
            59bc|88 02 40 f9|ldr|x8, [x20]
            59c0|49 01 80 52|mov|w9, #0xa
            59c4|09 29 00 b9|str|w9, [x8, #0x28]
            59c8|08 01 40 f9|ldr|x8, [x8]
            59cc|e0 03 14 aa|mov|x0, x20
            59d0|00 01 3f d6|blr|x8
            59d4|88 62 40 b9|ldr|w8, [x20, #0x60]
            59d8|1f 09 00 71|cmp|w8, #0x2
            59dc|ed 04 00 54|b.le|0x5a78
            59e0|1f 0d 00 71|cmp|w8, #0x3
            59e4|40 0b 00 54|b.eq|0x5b4c
            59e8|1f 11 00 71|cmp|w8, #0x4
            59ec|c0 0e 00 54|b.eq|0x5bc4
            59f0|1f 15 00 71|cmp|w8, #0x5
            59f4|a1 16 00 54|b.ne|0x5cc8
            59f8|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            59fc|08 21 40 b9|ldr|w8, [x8, #0x20]
            5a00|48 01 00 34|cbz|w8, 0x5a28
            5a04|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5a08|1f 15 00 71|cmp|w8, #0x5
            5a0c|e0 00 00 54|b.eq|0x5a28
            5a10|88 02 40 f9|ldr|x8, [x20]
            5a14|89 03 80 52|mov|w9, #0x1c
            5a18|09 29 00 b9|str|w9, [x8, #0x28]
            5a1c|08 01 40 f9|ldr|x8, [x8]
            5a20|e0 03 14 aa|mov|x0, x20
            5a24|00 01 3f d6|blr|x8
            5a28|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            5a2c|1f 11 00 71|cmp|w8, #0x4
            5a30|e0 00 00 54|b.eq|0x5a4c
            5a34|88 02 40 f9|ldr|x8, [x20]
            5a38|69 01 80 52|mov|w9, #0xb
            5a3c|09 29 00 b9|str|w9, [x8, #0x28]
            5a40|08 01 40 f9|ldr|x8, [x8]
            5a44|e0 03 14 aa|mov|x0, x20
            5a48|00 01 3f d6|blr|x8
            5a4c|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5a50|1f 15 00 71|cmp|w8, #0x5
            5a54|40 15 00 54|b.eq|0x5cfc
            5a58|1f 11 00 71|cmp|w8, #0x4
            5a5c|41 0e 00 54|b.ne|0x5c24
            5a60|08 00 00 90|adrp|x8, 0x5000
            5a64|08 b1 3c 91|add|x8, x8, #0xf2c
            5a68|68 02 00 f9|str|x8, [x19]
            5a6c|08 00 00 b0|adrp|x8, 0x6000
            5a70|08 71 12 91|add|x8, x8, #0x49c
            5a74|a4 00 00 14|b|0x5d04
            5a78|1f 05 00 71|cmp|w8, #0x1
            5a7c|60 0e 00 54|b.eq|0x5c48
            5a80|1f 09 00 71|cmp|w8, #0x2
            5a84|21 12 00 54|b.ne|0x5cc8
            5a88|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            5a8c|08 21 40 b9|ldr|w8, [x8, #0x20]
            5a90|a8 01 00 34|cbz|w8, 0x5ac4
            5a94|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5a98|1f 09 00 71|cmp|w8, #0x2
            5a9c|40 01 00 54|b.eq|0x5ac4
            5aa0|08 19 00 51|sub|w8, w8, #0x6
            5aa4|1f 29 00 71|cmp|w8, #0xa
            5aa8|e3 00 00 54|b.lo|0x5ac4
            5aac|88 02 40 f9|ldr|x8, [x20]
            5ab0|89 03 80 52|mov|w9, #0x1c
            5ab4|09 29 00 b9|str|w9, [x8, #0x28]
            5ab8|08 01 40 f9|ldr|x8, [x8]
            5abc|e0 03 14 aa|mov|x0, x20
            5ac0|00 01 3f d6|blr|x8
            5ac4|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            5ac8|1f 0d 00 71|cmp|w8, #0x3
            5acc|e0 00 00 54|b.eq|0x5ae8
            5ad0|88 02 40 f9|ldr|x8, [x20]
            5ad4|69 01 80 52|mov|w9, #0xb
            5ad8|09 29 00 b9|str|w9, [x8, #0x28]
            5adc|08 01 40 f9|ldr|x8, [x8]
            5ae0|e0 03 14 aa|mov|x0, x20
            5ae4|00 01 3f d6|blr|x8
            5ae8|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5aec|29 00 80 52|mov|w9, #0x1
            5af0|29 21 c8 9a|lsl|x9, x9, x8
            5af4|8a 18 82 52|mov|w10, #0x10c4
            5af8|3f 01 0a ea|tst|x9, x10
            5afc|80 00 00 54|b.eq|0x5b0c
            5b00|8a 28 80 52|mov|w10, #0x144
            5b04|29 01 0a 8a|and|x9, x9, x10
            5b08|a9 0f 00 b5|cbnz|x9, 0x5cfc
            5b0c|1f 09 00 71|cmp|w8, #0x2
            5b10|61 16 00 54|b.ne|0x5ddc
            5b14|08 00 00 b0|adrp|x8, 0x6000
            5b18|08 a1 0e 91|add|x8, x8, #0x3a8
            5b1c|7a 00 00 14|b|0x5d04
            5b20|1f 41 00 71|cmp|w8, #0x10
            5b24|c1 f0 ff 54|b.ne|0x593c
            5b28|8c ff ff 17|b|0x5958
            5b2c|29 00 80 52|mov|w9, #0x1
            5b30|29 21 c8 1a|lsl|w9, w9, w8
            5b34|3f 05 1c 72|tst|w9, #0x30
            5b38|00 0f 00 54|b.eq|0x5d18
            5b3c|88 3a 40 b9|ldr|w8, [x20, #0x38]
            5b40|1f 11 00 71|cmp|w8, #0x4
            5b44|c1 f3 ff 54|b.ne|0x59bc
            5b48|a3 ff ff 17|b|0x59d4
            5b4c|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            5b50|08 21 40 b9|ldr|w8, [x8, #0x20]
            5b54|48 01 00 34|cbz|w8, 0x5b7c
            5b58|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5b5c|1f 0d 00 71|cmp|w8, #0x3
            5b60|e0 00 00 54|b.eq|0x5b7c
            5b64|88 02 40 f9|ldr|x8, [x20]
            5b68|89 03 80 52|mov|w9, #0x1c
            5b6c|09 29 00 b9|str|w9, [x8, #0x28]
            5b70|08 01 40 f9|ldr|x8, [x8]
            5b74|e0 03 14 aa|mov|x0, x20
            5b78|00 01 3f d6|blr|x8
            5b7c|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            5b80|1f 0d 00 71|cmp|w8, #0x3
            5b84|e0 00 00 54|b.eq|0x5ba0
            5b88|88 02 40 f9|ldr|x8, [x20]
            5b8c|69 01 80 52|mov|w9, #0xb
            5b90|09 29 00 b9|str|w9, [x8, #0x28]
            5b94|08 01 40 f9|ldr|x8, [x8]
            5b98|e0 03 14 aa|mov|x0, x20
            5b9c|00 01 3f d6|blr|x8
            5ba0|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5ba4|1f 09 00 71|cmp|w8, #0x2
            5ba8|01 0d 00 54|b.ne|0x5d48
            5bac|08 00 00 90|adrp|x8, 0x5000
            5bb0|08 b1 3c 91|add|x8, x8, #0xf2c
            5bb4|68 02 00 f9|str|x8, [x19]
            5bb8|08 00 00 b0|adrp|x8, 0x6000
            5bbc|08 21 12 91|add|x8, x8, #0x488
            5bc0|51 00 00 14|b|0x5d04
            5bc4|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            5bc8|08 21 40 b9|ldr|w8, [x8, #0x20]
            5bcc|48 01 00 34|cbz|w8, 0x5bf4
            5bd0|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5bd4|1f 11 00 71|cmp|w8, #0x4
            5bd8|e0 00 00 54|b.eq|0x5bf4
            5bdc|88 02 40 f9|ldr|x8, [x20]
            5be0|89 03 80 52|mov|w9, #0x1c
            5be4|09 29 00 b9|str|w9, [x8, #0x28]
            5be8|08 01 40 f9|ldr|x8, [x8]
            5bec|e0 03 14 aa|mov|x0, x20
            5bf0|00 01 3f d6|blr|x8
            5bf4|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            5bf8|1f 11 00 71|cmp|w8, #0x4
            5bfc|e0 00 00 54|b.eq|0x5c18
            5c00|88 02 40 f9|ldr|x8, [x20]
            5c04|69 01 80 52|mov|w9, #0xb
            5c08|09 29 00 b9|str|w9, [x8, #0x28]
            5c0c|08 01 40 f9|ldr|x8, [x8]
            5c10|e0 03 14 aa|mov|x0, x20
            5c14|00 01 3f d6|blr|x8
            5c18|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5c1c|1f 11 00 71|cmp|w8, #0x4
            5c20|e0 06 00 54|b.eq|0x5cfc
            5c24|88 02 40 f9|ldr|x8, [x20]
            5c28|89 03 80 52|mov|w9, #0x1c
            5c2c|09 29 00 b9|str|w9, [x8, #0x28]
            5c30|01 01 40 f9|ldr|x1, [x8]
            5c34|e0 03 14 aa|mov|x0, x20
            5c38|fd 7b 42 a9|ldp|x29, x30, [sp, #0x20]
            5c3c|f4 4f 41 a9|ldp|x20, x19, [sp, #0x10]
            5c40|f6 57 c3 a8|ldp|x22, x21, [sp], #0x30
            5c44|20 00 1f d6|br|x1
            5c48|88 fa 40 f9|ldr|x8, [x20, #0x1f0]
            5c4c|08 21 40 b9|ldr|w8, [x8, #0x20]
            5c50|48 01 00 34|cbz|w8, 0x5c78
            5c54|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5c58|1f 05 00 71|cmp|w8, #0x1
            5c5c|e0 00 00 54|b.eq|0x5c78
            5c60|88 02 40 f9|ldr|x8, [x20]
            5c64|89 03 80 52|mov|w9, #0x1c
            5c68|09 29 00 b9|str|w9, [x8, #0x28]
            5c6c|08 01 40 f9|ldr|x8, [x8]
            5c70|e0 03 14 aa|mov|x0, x20
            5c74|00 01 3f d6|blr|x8
            5c78|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            5c7c|1f 05 00 71|cmp|w8, #0x1
            5c80|e0 00 00 54|b.eq|0x5c9c
            5c84|88 02 40 f9|ldr|x8, [x20]
            5c88|69 01 80 52|mov|w9, #0xb
            5c8c|09 29 00 b9|str|w9, [x8, #0x28]
            5c90|08 01 40 f9|ldr|x8, [x8]
            5c94|e0 03 14 aa|mov|x0, x20
            5c98|00 01 3f d6|blr|x8
            5c9c|88 3e 40 b9|ldr|w8, [x20, #0x3c]
            5ca0|1f 05 00 71|cmp|w8, #0x1
            5ca4|80 0b 00 54|b.eq|0x5e14
            5ca8|1f 09 00 71|cmp|w8, #0x2
            5cac|41 07 00 54|b.ne|0x5d94
            5cb0|08 00 00 90|adrp|x8, 0x5000
            5cb4|08 b1 3c 91|add|x8, x8, #0xf2c
            5cb8|68 02 00 f9|str|x8, [x19]
            5cbc|08 00 00 90|adrp|x8, 0x5000
            5cc0|08 e1 3e 91|add|x8, x8, #0xfb8
            5cc4|10 00 00 14|b|0x5d04
            5cc8|89 3e 40 b9|ldr|w9, [x20, #0x3c]
            5ccc|1f 01 09 6b|cmp|w8, w9
            5cd0|a1 00 00 54|b.ne|0x5ce4
            5cd4|88 5e 40 b9|ldr|w8, [x20, #0x5c]
            5cd8|89 3a 40 b9|ldr|w9, [x20, #0x38]
            5cdc|1f 01 09 6b|cmp|w8, w9
            5ce0|e0 00 00 54|b.eq|0x5cfc
            5ce4|88 02 40 f9|ldr|x8, [x20]
            5ce8|89 03 80 52|mov|w9, #0x1c
            5cec|09 29 00 b9|str|w9, [x8, #0x28]
            5cf0|08 01 40 f9|ldr|x8, [x8]
            5cf4|e0 03 14 aa|mov|x0, x20
            5cf8|00 01 3f d6|blr|x8
            5cfc|08 00 00 90|adrp|x8, 0x5000
            5d00|08 31 3f 91|add|x8, x8, #0xfcc
            5d04|68 0e 00 f9|str|x8, [x19, #0x18]
            5d08|fd 7b 42 a9|ldp|x29, x30, [sp, #0x20]
            5d0c|f4 4f 41 a9|ldp|x20, x19, [sp, #0x10]
            5d10|f6 57 c3 a8|ldp|x22, x21, [sp], #0x30
            5d14|c0 03 5f d6|ret|
            5d18|1f 0d 00 71|cmp|w8, #0x3
            5d1c|a1 00 00 54|b.ne|0x5d30
            5d20|88 3a 40 b9|ldr|w8, [x20, #0x38]
            5d24|1f 0d 00 71|cmp|w8, #0x3
            5d28|a1 e4 ff 54|b.ne|0x59bc
            5d2c|2a ff ff 17|b|0x59d4
            5d30|1f 05 00 71|cmp|w8, #0x1
            5d34|81 02 00 54|b.ne|0x5d84
            5d38|88 3a 40 b9|ldr|w8, [x20, #0x38]
            5d3c|1f 05 00 71|cmp|w8, #0x1
            5d40|e1 e3 ff 54|b.ne|0x59bc
            5d44|24 ff ff 17|b|0x59d4
            5d48|09 19 00 51|sub|w9, w8, #0x6
            5d4c|3f 25 00 71|cmp|w9, #0x9
            5d50|08 04 00 54|b.hi|0x5dd0
            5d54|08 00 00 90|adrp|x8, 0x5000
            5d58|08 b1 3c 91|add|x8, x8, #0xf2c
            5d5c|68 02 00 f9|str|x8, [x19]
            5d60|88 02 00 f0|adrp|x8, 0x58000
            5d64|08 21 20 91|add|x8, x8, #0x808
            5d68|8a 00 00 10|adr|x10, #16
            5d6c|0b 69 69 38|ldrb|w11, [x8, x9]
            5d70|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            5d74|40 01 1f d6|br|x10
            5d78|08 00 00 b0|adrp|x8, 0x6000
            5d7c|08 91 10 91|add|x8, x8, #0x424
            5d80|e1 ff ff 17|b|0x5d04
            5d84|88 3a 40 b9|ldr|w8, [x20, #0x38]
            5d88|1f 01 00 71|cmp|w8, #0x0
            5d8c|8d e1 ff 54|b.le|0x59bc
            5d90|11 ff ff 17|b|0x59d4
            5d94|09 19 00 51|sub|w9, w8, #0x6
            5d98|3f 25 00 71|cmp|w9, #0x9
            5d9c|88 03 00 54|b.hi|0x5e0c
            5da0|08 00 00 90|adrp|x8, 0x5000
            5da4|08 b1 3c 91|add|x8, x8, #0xf2c
            5da8|68 02 00 f9|str|x8, [x19]
            5dac|88 02 00 f0|adrp|x8, 0x58000
            5db0|08 71 20 91|add|x8, x8, #0x81c
            5db4|8a 00 00 10|adr|x10, #16
            5db8|0b 69 69 38|ldrb|w11, [x8, x9]
            5dbc|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            5dc0|40 01 1f d6|br|x10
            5dc4|08 00 00 90|adrp|x8, 0x5000
            5dc8|08 51 3d 91|add|x8, x8, #0xf54
            5dcc|ce ff ff 17|b|0x5d04
            5dd0|1f 0d 00 71|cmp|w8, #0x3
            5dd4|81 f2 ff 54|b.ne|0x5c24
            5dd8|c9 ff ff 17|b|0x5cfc
            5ddc|08 19 00 51|sub|w8, w8, #0x6
            5de0|1f 25 00 71|cmp|w8, #0x9
            5de4|08 f2 ff 54|b.hi|0x5c24
            5de8|89 02 00 f0|adrp|x9, 0x58000
            5dec|29 49 20 91|add|x9, x9, #0x812
            5df0|8a 00 00 10|adr|x10, #16
            5df4|2b 69 68 38|ldrb|w11, [x9, x8]
            5df8|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            5dfc|40 01 1f d6|br|x10
            5e00|08 00 00 b0|adrp|x8, 0x6000
            5e04|08 41 06 91|add|x8, x8, #0x190
            5e08|bf ff ff 17|b|0x5d04
            5e0c|1f 0d 00 71|cmp|w8, #0x3
            5e10|a1 f0 ff 54|b.ne|0x5c24
            5e14|08 00 00 90|adrp|x8, 0x5000
            5e18|08 61 3b 91|add|x8, x8, #0xed8
            5e1c|ba ff ff 17|b|0x5d04
            5e20|08 00 00 b0|adrp|x8, 0x6000
            5e24|08 d1 11 91|add|x8, x8, #0x474
            5e28|b7 ff ff 17|b|0x5d04
            5e2c|08 00 00 b0|adrp|x8, 0x6000
            5e30|08 31 11 91|add|x8, x8, #0x44c
            5e34|b4 ff ff 17|b|0x5d04
            5e38|08 00 00 b0|adrp|x8, 0x6000
            5e3c|08 81 11 91|add|x8, x8, #0x460
            5e40|b1 ff ff 17|b|0x5d04
            5e44|08 00 00 90|adrp|x8, 0x5000
            5e48|08 91 3e 91|add|x8, x8, #0xfa4
            5e4c|ae ff ff 17|b|0x5d04
            5e50|08 00 00 90|adrp|x8, 0x5000
            5e54|08 f1 3d 91|add|x8, x8, #0xf7c
            5e58|ab ff ff 17|b|0x5d04
            5e5c|08 00 00 90|adrp|x8, 0x5000
            5e60|08 41 3e 91|add|x8, x8, #0xf90
            5e64|a8 ff ff 17|b|0x5d04
            5e68|08 00 00 b0|adrp|x8, 0x6000
            5e6c|08 f1 0c 91|add|x8, x8, #0x33c
            5e70|a5 ff ff 17|b|0x5d04
            5e74|08 00 00 b0|adrp|x8, 0x6000
            5e78|08 41 10 91|add|x8, x8, #0x410
            5e7c|a2 ff ff 17|b|0x5d04
            5e80|08 00 00 b0|adrp|x8, 0x6000
            5e84|08 91 09 91|add|x8, x8, #0x264
            5e88|9f ff ff 17|b|0x5d04
            5e8c|08 00 00 b0|adrp|x8, 0x6000
            5e90|08 e1 10 91|add|x8, x8, #0x438
            5e94|9c ff ff 17|b|0x5d04
            5e98|08 00 00 b0|adrp|x8, 0x6000
            5e9c|08 41 0b 91|add|x8, x8, #0x2d0
            5ea0|99 ff ff 17|b|0x5d04
            5ea4|08 00 00 90|adrp|x8, 0x5000
            5ea8|08 01 3d 91|add|x8, x8, #0xf40
            5eac|96 ff ff 17|b|0x5d04
            5eb0|08 00 00 90|adrp|x8, 0x5000
            5eb4|08 a1 3d 91|add|x8, x8, #0xf68
            5eb8|93 ff ff 17|b|0x5d04
            5ebc|08 00 00 b0|adrp|x8, 0x6000
            5ec0|08 a1 04 91|add|x8, x8, #0x128
            5ec4|90 ff ff 17|b|0x5d04
            5ec8|08 00 00 b0|adrp|x8, 0x6000
            5ecc|08 e1 07 91|add|x8, x8, #0x1f8
            5ed0|8d ff ff 17|b|0x5d04
            """),
        lower: 0x590c, upper: 0x5ed4,
        bytes: storage([
            (0x58808, [0x3f, 0x00, 0x45, 0x2d, 0x30, 0x2a, 0x00, 0x2d, 0x30, 0x2a]),
            (0x5881c, [0x38, 0x00, 0x3b, 0x23, 0x26, 0x20, 0x00, 0x23, 0x26, 0x20]),
            (0x58812, [0x2f, 0x00, 0x32, 0x20, 0x26, 0x1a, 0x00, 0x20, 0x26, 0x1a])
        ]),
        expected: [
            0x5d74: [0x5e74, 0x5d78, 0x5e8c, 0x5e2c, 0x5e38, 0x5e20, 0x5d78, 0x5e2c, 0x5e38, 0x5e20],
            0x5dc0: [0x5ea4, 0x5dc4, 0x5eb0, 0x5e50, 0x5e5c, 0x5e44, 0x5dc4, 0x5e50, 0x5e5c, 0x5e44],
            0x5dfc: [0x5ebc, 0x5e00, 0x5ec8, 0x5e80, 0x5e98, 0x5e68, 0x5e00, 0x5e80, 0x5e98, 0x5e68]
        ])

    // _j12init_merged_upsampler, retained first-occurrence listing lines 56370...56561.
    static let merged12 = Self(
        rows: parse("""
            37440|f4 4f be a9|stp|x20, x19, [sp, #-0x20]!
            37444|fd 7b 01 a9|stp|x29, x30, [sp, #0x10]
            37448|fd 43 00 91|add|x29, sp, #0x10
            3744c|f3 03 00 aa|mov|x19, x0
            37450|08 28 41 b9|ldr|w8, [x0, #0x128]
            37454|1f 31 00 71|cmp|w8, #0xc
            37458|00 01 00 54|b.eq|0x37478
            3745c|69 02 40 f9|ldr|x9, [x19]
            37460|0a 02 80 52|mov|w10, #0x10
            37464|2a 21 05 29|stp|w10, w8, [x9, #0x28]
            37468|68 02 40 f9|ldr|x8, [x19]
            3746c|08 01 40 f9|ldr|x8, [x8]
            37470|e0 03 13 aa|mov|x0, x19
            37474|00 01 3f d6|blr|x8
            37478|68 06 40 f9|ldr|x8, [x19, #0x8]
            3747c|08 01 40 f9|ldr|x8, [x8]
            37480|e0 03 13 aa|mov|x0, x19
            37484|21 00 80 52|mov|w1, #0x1
            37488|02 11 80 52|mov|w2, #0x88
            3748c|00 01 3f d6|blr|x8
            37490|f4 03 00 aa|mov|x20, x0
            37494|60 3e 01 f9|str|x0, [x19, #0x278]
            37498|08 00 00 90|adrp|x8, 0x37000
            3749c|08 01 1d 91|add|x8, x8, #0x740
            374a0|08 00 00 f9|str|x8, [x0]
            374a4|1f 40 00 b9|str|wzr, [x0, #0x40]
            374a8|68 8a 40 b9|ldr|w8, [x19, #0x88]
            374ac|69 92 40 b9|ldr|w9, [x19, #0x90]
            374b0|28 7d 08 1b|mul|w8, w9, w8
            374b4|08 7c 00 b9|str|w8, [x0, #0x7c]
            374b8|69 9e 41 b9|ldr|w9, [x19, #0x19c]
            374bc|3f 09 00 71|cmp|w9, #0x2
            374c0|21 02 00 54|b.ne|0x37504
            374c4|09 00 00 90|adrp|x9, 0x37000
            374c8|29 51 1d 91|add|x9, x9, #0x754
            374cc|89 0a 00 f9|str|x9, [x20, #0x10]
            374d0|69 42 40 b9|ldr|w9, [x19, #0x40]
            374d4|2a 19 00 51|sub|w10, w9, #0x6
            374d8|5f 25 00 71|cmp|w10, #0x9
            374dc|08 07 00 54|b.hi|0x375bc
            374e0|09 01 00 d0|adrp|x9, 0x59000
            374e4|29 e9 1c 91|add|x9, x9, #0x73a
            374e8|8b 00 00 10|adr|x11, #16
            374ec|2c 69 6a 38|ldrb|w12, [x9, x10]
            374f0|6b 09 0c 8b|add|x11, x11, x12, lsl #2
            374f4|60 01 1f d6|br|x11
            374f8|09 00 00 90|adrp|x9, 0x37000
            374fc|29 31 29 91|add|x9, x9, #0xa4c
            37500|45 00 00 14|b|0x37614
            37504|08 00 00 b0|adrp|x8, 0x38000
            37508|08 71 2a 91|add|x8, x8, #0xa9c
            3750c|88 0a 00 f9|str|x8, [x20, #0x10]
            37510|68 42 40 b9|ldr|w8, [x19, #0x40]
            37514|09 19 00 51|sub|w9, w8, #0x6
            37518|3f 25 00 71|cmp|w9, #0x9
            3751c|48 06 00 54|b.hi|0x375e4
            37520|08 01 00 d0|adrp|x8, 0x59000
            37524|08 c1 1c 91|add|x8, x8, #0x730
            37528|8a 00 00 10|adr|x10, #16
            3752c|0b 69 69 38|ldrb|w11, [x8, x9]
            37530|4a 09 0b 8b|add|x10, x10, x11, lsl #2
            37534|40 01 1f d6|br|x10
            37538|08 00 00 b0|adrp|x8, 0x38000
            3753c|08 11 30 91|add|x8, x8, #0xc04
            37540|41 00 00 14|b|0x37644
            37544|09 00 00 b0|adrp|x9, 0x38000
            37548|29 31 07 91|add|x9, x9, #0x1cc
            3754c|32 00 00 14|b|0x37614
            37550|08 00 00 d0|adrp|x8, 0x39000
            37554|08 81 02 91|add|x8, x8, #0xa0
            37558|3b 00 00 14|b|0x37644
            3755c|09 00 00 90|adrp|x9, 0x37000
            37560|29 f1 37 91|add|x9, x9, #0xdfc
            37564|2c 00 00 14|b|0x37614
            37568|08 00 00 b0|adrp|x8, 0x38000
            3756c|08 21 39 91|add|x8, x8, #0xe48
            37570|35 00 00 14|b|0x37644
            37574|09 00 00 90|adrp|x9, 0x37000
            37578|29 91 3f 91|add|x9, x9, #0xfe4
            3757c|26 00 00 14|b|0x37614
            37580|08 00 00 b0|adrp|x8, 0x38000
            37584|08 d1 3d 91|add|x8, x8, #0xf74
            37588|2f 00 00 14|b|0x37644
            3758c|09 00 00 90|adrp|x9, 0x37000
            37590|29 11 22 91|add|x9, x9, #0x884
            37594|20 00 00 14|b|0x37614
            37598|08 00 00 b0|adrp|x8, 0x38000
            3759c|08 b1 2b 91|add|x8, x8, #0xaec
            375a0|29 00 00 14|b|0x37644
            375a4|09 00 00 90|adrp|x9, 0x37000
            375a8|29 d1 30 91|add|x9, x9, #0xc34
            375ac|1a 00 00 14|b|0x37614
            375b0|08 00 00 b0|adrp|x8, 0x38000
            375b4|08 c1 34 91|add|x8, x8, #0xd30
            375b8|23 00 00 14|b|0x37644
            375bc|0a 00 00 b0|adrp|x10, 0x38000
            375c0|4a d1 0e 91|add|x10, x10, #0x3b4
            375c4|8a 26 00 f9|str|x10, [x20, #0x48]
            375c8|3f 41 00 71|cmp|w9, #0x10
            375cc|61 02 00 54|b.ne|0x37618
            375d0|69 72 40 b9|ldr|w9, [x19, #0x70]
            375d4|c9 01 00 34|cbz|w9, 0x3760c
            375d8|09 00 00 b0|adrp|x9, 0x38000
            375dc|29 f1 15 91|add|x9, x9, #0x57c
            375e0|0d 00 00 14|b|0x37614
            375e4|09 00 00 d0|adrp|x9, 0x39000
            375e8|29 31 07 91|add|x9, x9, #0x1cc
            375ec|89 26 00 f9|str|x9, [x20, #0x48]
            375f0|1f 41 00 71|cmp|w8, #0x10
            375f4|a1 02 00 54|b.ne|0x37648
            375f8|68 72 40 b9|ldr|w8, [x19, #0x70]
            375fc|08 02 00 34|cbz|w8, 0x3763c
            37600|08 00 00 d0|adrp|x8, 0x39000
            37604|08 91 0b 91|add|x8, x8, #0x2e4
            37608|0f 00 00 14|b|0x37644
            3760c|09 00 00 b0|adrp|x9, 0x38000
            37610|29 91 21 91|add|x9, x9, #0x864
            37614|89 26 00 f9|str|x9, [x20, #0x48]
            37618|69 06 40 f9|ldr|x9, [x19, #0x8]
            3761c|29 05 40 f9|ldr|x9, [x9, #0x8]
            37620|02 7d 7f d3|ubfiz|x2, x8, #1, #32
            37624|e0 03 13 aa|mov|x0, x19
            37628|21 00 80 52|mov|w1, #0x1
            3762c|20 01 3f d6|blr|x9
            37630|80 3a 00 f9|str|x0, [x20, #0x70]
            37634|74 3e 41 f9|ldr|x20, [x19, #0x278]
            37638|05 00 00 14|b|0x3764c
            3763c|08 00 00 d0|adrp|x8, 0x39000
            37640|08 01 12 91|add|x8, x8, #0x480
            37644|88 26 00 f9|str|x8, [x20, #0x48]
            37648|9f 3a 00 f9|str|xzr, [x20, #0x70]
            3764c|68 06 40 f9|ldr|x8, [x19, #0x8]
            37650|08 01 40 f9|ldr|x8, [x8]
            37654|e0 03 13 aa|mov|x0, x19
            37658|21 00 80 52|mov|w1, #0x1
            3765c|02 00 88 52|mov|w2, #0x4000
            37660|00 01 3f d6|blr|x8
            37664|80 2a 00 f9|str|x0, [x20, #0x50]
            37668|68 06 40 f9|ldr|x8, [x19, #0x8]
            3766c|08 01 40 f9|ldr|x8, [x8]
            37670|e0 03 13 aa|mov|x0, x19
            37674|21 00 80 52|mov|w1, #0x1
            37678|02 00 88 52|mov|w2, #0x4000
            3767c|00 01 3f d6|blr|x8
            37680|80 2e 00 f9|str|x0, [x20, #0x58]
            37684|68 06 40 f9|ldr|x8, [x19, #0x8]
            37688|08 01 40 f9|ldr|x8, [x8]
            3768c|e0 03 13 aa|mov|x0, x19
            37690|21 00 80 52|mov|w1, #0x1
            37694|02 00 90 52|mov|w2, #0x8000
            37698|00 01 3f d6|blr|x8
            3769c|80 32 00 f9|str|x0, [x20, #0x60]
            376a0|68 06 40 f9|ldr|x8, [x19, #0x8]
            376a4|08 01 40 f9|ldr|x8, [x8]
            376a8|e0 03 13 aa|mov|x0, x19
            376ac|21 00 80 52|mov|w1, #0x1
            376b0|02 00 90 52|mov|w2, #0x8000
            376b4|00 01 3f d6|blr|x8
            376b8|08 00 80 d2|mov|x8, #0x0
            376bc|80 36 00 f9|str|x0, [x20, #0x68]
            376c0|89 2a 45 a9|ldp|x9, x10, [x20, #0x50]
            376c4|eb ff 91 92|mov|x11, #-0x9000
            376c8|6b 3a be f2|movk|x11, #0xf1d3, lsl #16
            376cc|ec ff 98 92|mov|x12, #-0xc800
            376d0|2c 99 be f2|movk|x12, #0xf4c9, lsl #16
            376d4|0d 00 8a 52|mov|w13, #0x5000
            376d8|2d 58 a0 72|movk|w13, #0x2c1, lsl #16
            376dc|0e 00 92 52|mov|w14, #0x9000
            376e0|ce b6 a0 72|movk|w14, #0x5b6, lsl #16
            376e4|8f 32 40 f9|ldr|x15, [x20, #0x60]
            376e8|30 03 8b 92|mov|x16, #-0x581a
            376ec|31 da 96 92|mov|x17, #-0xb6d2
            376f0|41 b4 98 52|mov|w1, #0xc5a2
            376f4|21 00 a0 72|movk|w1, #0x1, lsl #16
            376f8|22 dd 8c 52|mov|w2, #0x66e9
            376fc|22 00 a0 72|movk|w2, #0x1, lsl #16
            37700|83 fd 50 d3|lsr|x3, x12, #16
            37704|23 79 28 b8|str|w3, [x9, x8, lsl #2]
            37708|63 fd 50 d3|lsr|x3, x11, #16
            3770c|43 79 28 b8|str|w3, [x10, x8, lsl #2]
            37710|ee 79 28 f8|str|x14, [x15, x8, lsl #3]
            37714|0d 78 28 f8|str|x13, [x0, x8, lsl #3]
            37718|08 05 00 91|add|x8, x8, #0x1
            3771c|ad 01 10 8b|add|x13, x13, x16
            37720|ce 01 11 8b|add|x14, x14, x17
            37724|6b 01 01 8b|add|x11, x11, x1
            37728|8c 01 02 8b|add|x12, x12, x2
            3772c|1f 05 40 f1|cmp|x8, #0x1, lsl #12
            37730|81 fe ff 54|b.ne|0x37700
            37734|fd 7b 41 a9|ldp|x29, x30, [sp, #0x10]
            37738|f4 4f c2 a8|ldp|x20, x19, [sp], #0x20
            3773c|c0 03 5f d6|ret|
            """),
        lower: 0x37440, upper: 0x37740,
        bytes: storage([
            (0x5973a, [0x25, 0x00, 0x2b, 0x19, 0x1f, 0x13, 0x00, 0x19, 0x1f, 0x13]),
            (0x59730, [0x18, 0x00, 0x1e, 0x0c, 0x12, 0x06, 0x00, 0x0c, 0x12, 0x06])
        ]),
        expected: [
            0x374f4: [0x3758c, 0x374f8, 0x375a4, 0x3755c, 0x37574, 0x37544, 0x374f8, 0x3755c, 0x37574, 0x37544],
            0x37534: [0x37598, 0x37538, 0x375b0, 0x37568, 0x37580, 0x37550, 0x37538, 0x37568, 0x37580, 0x37550]
        ])
}
