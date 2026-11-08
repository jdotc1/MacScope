import Foundation
import XCTest
@testable import MacScope

/// New source-first tests against existing production entry points, not recovered
/// historical tests. No report API is used: the positive assertion is intended to
/// execute as behavioral red on the pin. The harness must establish that outcome.
@MainActor
final class S1RecoveryRelativeTableProofTests: XCTestCase {
    private let leaf: UInt64 = 0x1014
    private let switchStart: UInt64 = 0x1020
    private let dispatch: UInt64 = 0x103c
    private let table: UInt64 = 0x1054

    private func adr(_ register: UInt32, at pc: UInt64, to target: UInt64) -> UInt32 {
        let delta = Int64(target) - Int64(pc)
        precondition((-(Int64(1) << 20)..<(Int64(1) << 20)).contains(delta))
        let immediate = UInt32(truncatingIfNeeded: delta) & 0x1fffff
        return 0x10000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5) | register
    }

    private func switchBody(at start: UInt64, table: UInt64, anchor: UInt64,
                            guarded: Bool = true) -> [UInt32] {
        [guarded ? 0x71000c1f : 0xd503201f, // cmp w0,#3, or nop
         0x54000168,                       // b.hi start+0x30
         0x2a0003e8,                       // mov w8,w0
         adr(9, at: start + 12, to: table),
         adr(10, at: start + 16, to: anchor),
         0x3868692b,                       // ldrb w11,[x9,x8]
         0x8b0b094a,                       // add x10,x10,x11,lsl #2
         0xd61f0140,                       // br x10
         0xd65f03c0, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0, // four cases
         0xd65f03c0]                       // default
    }

    private func fixture(guarded: Bool = true, anchor: UInt64 = 0x1040,
                         declaredLength: UInt16 = 4, shared: Bool = false,
                         orphan: Bool = false, otherEntry: Bool = false) -> Data {
        var body = switchBody(at: switchStart, table: table, anchor: anchor, guarded: guarded)
        body.append(0x03020100) // four unsigned byte offsets, not instructions
        if orphan { body.append(0x03020100) }
        var bodies: [UInt64: (String, [UInt32])] = [
            0x1000: ("caller", [0xa9bf7bfd, 0x94000004, 0xd2800000, 0xa8c17bfd, 0xd65f03c0]),
            // The caller restores LR and overwrites x0 before returning.
            0x1014: ("leaf", [0xf9400008, 0xf9000028, 0xd65f03c0]),
            switchStart: ("switcher", body)
        ]
        if shared {
            bodies[0x1058] = ("second_switch", switchBody(at: 0x1058, table: table, anchor: 0x1078))
        }
        if otherEntry { bodies[0x1040] = ("other_entry", [0xd65f03c0]) }
        var declarations: [S1RecoveryMachOFixture.DataInCode] = [
            .init(offset: UInt32(table), length: declaredLength, kind: 2)
        ]
        if orphan { declarations.append(.init(offset: UInt32(table + 4), length: 4, kind: 2)) }
        return S1RecoveryMachOFixture.make(bodies: bodies, exported: [], dataInCode: declarations)
    }

    private func analyze(_ bytes: Data) throws -> WorkspaceSnapshot {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("s1-relative-proof-\(UUID().uuidString).dylib")
        try bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let snapshot = try AnalysisEngine().analyze(url: url)
        XCTAssertEqual(snapshot.analysis(in: .primary)?.imageBytes, bytes)
        XCTAssertTrue(snapshot.functions.contains { $0.startAddress == leaf })
        return snapshot
    }

    private func render(_ snapshot: WorkspaceSnapshot) -> String {
        DocumentExportService().pseudocodeText(
            for: snapshot.pseudocodeRenderInput(selectedAddress: leaf, in: .primary), options: .default)
    }

    private func signature(_ text: String, file: StaticString = #filePath, line: UInt = #line) throws -> String {
        try XCTUnwrap(text.split(separator: "\n").first {
            $0.range(of: #"\b_?leaf\s*\("#, options: .regularExpression) != nil
        }.map(String.init), text, file: file, line: line)
    }

    private func isVoid(_ signature: String) -> Bool {
        signature.range(of: #"^\s*void\s+_?leaf\s*\("#, options: .regularExpression) != nil
    }

    /// 7c29b7631: complete caller discard is diagnostic evidence only. The closed-world
    /// certificate is observable as a `discard_without_return_type_authority` refusal
    /// for the leaf (all six conditions satisfied), never as a published void contract.
    /// An independent void declaration would skip the audit (`effectiveSignatures`
    /// must have no return type), so the proof is observed here without one.
    private func discardCertified(_ snapshot: WorkspaceSnapshot) throws -> Bool {
        let analysis = try XCTUnwrap(snapshot.analysis(in: .primary))
        let rows = analysis.instructions.filter { $0.address >= 0x1000 && $0.address < leaf }
        let caller = MacIRBuilder().buildFunction(name: "caller", startAddress: 0x1000, instructions: rows)
        let report = MacIRCallerReturnEvidence.collectClosedWorld(analysis: analysis, functions: [caller])
        XCTAssertNil(report.contracts[leaf], "Caller discard must never publish a void contract")
        return report.refusals.contains {
            $0.functionAddress == leaf && $0.reason == "discard_without_return_type_authority"
        }
    }

    private func positive(file: StaticString = #filePath, line: UInt = #line) throws {
        let bytes = fixture()
        let parsed = try MachOParser().parse(bytes)
        XCTAssertEqual(parsed.dataInCodeEntries.map(\.address), [table], file: file, line: line)
        XCTAssertEqual(parsed.functionStarts.map(\.address), [0x1000, leaf, switchStart], file: file, line: line)
        let snapshot = try analyze(bytes)
        XCTAssertEqual(snapshot.jumpTables[dispatch], [0x1040, 0x1044, 0x1048, 0x104c], file: file, line: line)
        let before = try signature(render(snapshot), file: file, line: line)
        XCTAssertFalse(isVoid(before), before, file: file, line: line)
        XCTAssertNotNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true), file: file, line: line)
        let after = try signature(render(snapshot), file: file, line: line)
        XCTAssertFalse(isVoid(after), "Caller discard alone is not return-type authority (7c29b7631): \(after)", file: file, line: line)
        XCTAssertEqual(after, before, file: file, line: line)
        XCTAssertTrue(try discardCertified(snapshot),
            "Complete guarded internal table must still certify caller discard as diagnostic evidence", file: file, line: line)
        XCTAssertTrue(snapshot.addressOverrides.isEmpty, file: file, line: line)
        let input = snapshot.pseudocodeRenderInput(selectedAddress: leaf, in: .primary)
        let baseFunction = PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides, types: input.types, instructions: input.instructions)
        let returnOnlyFunction = PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides, callerReturnType: input.callerReturnType,
            types: input.types, instructions: input.instructions)
        XCTAssertEqual(returnOnlyFunction.parameters, baseFunction.parameters,
            "Caller-derived void must not erase or rebind recovered parameters", file: file, line: line)
    }

    private func preservesBaseline(_ snapshot: WorkspaceSnapshot,
                                   file: StaticString = #filePath, line: UInt = #line) throws {
        // Read the actual cold fixture signature. Do not invent an unresolved
        // marker or an int64_t spelling for a negative test.
        let before = try signature(render(snapshot), file: file, line: line)
        XCTAssertFalse(isVoid(before), before, file: file, line: line)
        _ = snapshot.imageWideIndirectCalls(in: .primary, compute: true)
        let after = try signature(render(snapshot), file: file, line: line)
        XCTAssertEqual(after, before, "An unrelated bad table vetoes image-wide closure", file: file, line: line)
        XCTAssertFalse(isVoid(after), after, file: file, line: line)
        XCTAssertFalse(try discardCertified(snapshot),
            "An unrelated bad table vetoes the closed-world discard certificate", file: file, line: line)
    }

    func testGuardedInternalRelativeTableAllowsCallerOnlyVoid() throws {
        try positive()
    }

    /// FX-MR R2 / PR #327 follow-up: positive path with the relative-table proof admitted.
    /// Decider walk (MacIRCallerReturnEvidence.swift, collectClosedWorld):
    /// - `relative_tables_admitted` (l.1721) counts the guard-bounded table the proof admitted;
    ///   condition 5 `tablesComplete` (l.1725, detail l.1761) holds only when that inventory is complete.
    /// - The loop publishes `discard_without_return_type_authority` (l.1773) only after
    ///   `guard conditions.allSatisfy, effectiveSignatures[target]?.returnType == nil else { continue }`
    ///   (l.1769). A leaf return-type authority makes that guard `continue`: all six conditions
    ///   stay in `evidence[leaf]` (l.1764), no refusal row, and no contract is published (the
    ///   declaration route, not this audit, supplies the type). Any non-nil returnType passes; "int" is used.
    private func closedWorldReport(_ snapshot: WorkspaceSnapshot,
                                   signatures: [UInt64: FunctionSignatureOverride])
        throws -> MacIRCallerReturnEvidence.ClosedWorldReport {
        let analysis = try XCTUnwrap(snapshot.analysis(in: .primary))
        let rows = analysis.instructions.filter { $0.address >= 0x1000 && $0.address < leaf }
        let caller = MacIRBuilder().buildFunction(name: "caller", startAddress: 0x1000, instructions: rows)
        return MacIRCallerReturnEvidence.collectClosedWorld(analysis: analysis, functions: [caller],
            effectiveSignatures: signatures)
    }

    func testRelativeTableProofAdmitsWithReturnTypeAuthority() throws {
        try positive()
        let snapshot = try analyze(fixture())
        let declarations = CTypeHeaderParser.parse("int leaf(void);")
        XCTAssertTrue(declarations.diagnostics.isEmpty, declarations.diagnostics.joined(separator: "; "))
        let authority = try XCTUnwrap(declarations.prototypes.first { $0.name == "leaf" }?.signature)
        XCTAssertEqual(authority.returnType, "int32_t") // CTypeHeaderParser normalizes int (xcresult run-1, l.172)

        // With authority: table admitted, all six conditions hold, audit skips (l.1769), no refusal.
        let admitted = try closedWorldReport(snapshot, signatures: [leaf: authority])
        XCTAssertEqual(admitted.census["relative_tables_admitted"], 1)
        XCTAssertEqual(admitted.evidence[leaf]?.count, 6)
        XCTAssertTrue(admitted.evidence[leaf]?.allSatisfy(\.satisfied) == true,
            "Relative-table proof must certify all six conditions: \(String(describing: admitted.evidence[leaf]))")
        XCTAssertTrue(admitted.evidence[leaf]?.first { $0.condition == 5 }?.detail
            .hasPrefix("relative tables guard-bounded") == true)
        XCTAssertFalse(admitted.refusals.contains {
            $0.functionAddress == leaf && $0.reason == "discard_without_return_type_authority"
        })
        XCTAssertNil(admitted.census["discard_without_return_type_authority"])
        XCTAssertNil(admitted.contracts[leaf], "Authority comes from the declaration, never a published contract")

        // Paired control: removing only the authority yields the refusal, same certificate.
        let control = try closedWorldReport(snapshot, signatures: [:])
        XCTAssertEqual(control.census["relative_tables_admitted"], 1)
        XCTAssertTrue(control.evidence[leaf]?.allSatisfy(\.satisfied) == true)
        XCTAssertTrue(control.refusals.contains {
            $0.functionAddress == leaf && $0.reason == "discard_without_return_type_authority"
        })
        XCTAssertEqual(control.census["discard_without_return_type_authority"], 1)
    }

    func testUnboundedTableInUnrelatedFunctionRefusesImageWideClosure() throws {
        try positive()
        let snapshot = try analyze(fixture(guarded: false))
        XCTAssertNil(snapshot.jumpTables[dispatch])
        try preservesBaseline(snapshot)
    }

    func testContainingOtherAndExternalEntryTargetsRefuseImageWideClosure() throws {
        try positive()
        try preservesBaseline(analyze(fixture(anchor: switchStart)))
        try preservesBaseline(analyze(fixture(anchor: leaf)))
        try preservesBaseline(analyze(fixture(anchor: 0x4000)))
        try preservesBaseline(analyze(fixture(otherEntry: true)))
    }

    func testDeclaredTableExtentMustBeFullyAttributedToExactlyOneBranch() throws {
        try positive()
        try preservesBaseline(analyze(fixture(declaredLength: 3)))
        let shared = try analyze(fixture(shared: true))
        XCTAssertEqual(shared.jumpTables[dispatch], [0x1040, 0x1044, 0x1048, 0x104c])
        XCTAssertEqual(shared.jumpTables[0x1074], [0x1078, 0x107c, 0x1080, 0x1084])
        try preservesBaseline(shared)
        try preservesBaseline(analyze(fixture(orphan: true)))
    }

    func testIndirectTableEdgeCannotBypassItsGuard() throws {
        try positive()
        // Edges into ADR/load/add/BR are strictly inside the function but do not
        // justify another dispatch without re-entering the bounds guard.
        try preservesBaseline(analyze(fixture(anchor: 0x1030)))
    }

    func testFunctionStartsWithoutTerminatorDoesNotCertifyClosure() throws {
        try positive()
        var bytes = fixture()
        let parsed = try MachOParser().parse(bytes)
        let command = try XCTUnwrap(parsed.loadCommands.first { $0.command == 0x26 })
        let offset = Int(command.offset) + 12
        let size = uint32(bytes, at: offset)
        XCTAssertGreaterThan(size, 0)
        put32(size - 1, in: &bytes, at: offset)
        // Shipped parse still returns the full prefix. That is not a complete
        // declared stream certificate, and must not authorize closed-world use.
        XCTAssertEqual(try MachOParser().parse(bytes).functionStarts.map(\.address),
                       parsed.functionStarts.map(\.address))
        try preservesBaseline(analyze(bytes))
    }

    func testMalformedDataInCodeCannotMasqueradeAsNoTables() throws {
        try positive()
        var bytes = fixture()
        let parsed = try MachOParser().parse(bytes)
        let command = try XCTUnwrap(parsed.loadCommands.first { $0.command == 0x29 })
        put32(7, in: &bytes, at: Int(command.offset) + 12)
        // Preserve shipped behavior as evidence inside this paired red selector.
        XCTAssertTrue(try MachOParser().parse(bytes).dataInCodeEntries.isEmpty)
        try preservesBaseline(analyze(bytes))
    }

    func testMissingOrMismatchedDecodedRowsCannotCertifyWholeImageCoverage() throws {
        try positive()
        var missing = try analyze(fixture())
        missing.instructions.removeAll { $0.address == 0x1028 }
        try preservesBaseline(missing)
        var mismatch = try analyze(fixture())
        let index = try XCTUnwrap(mismatch.instructions.firstIndex { $0.address == 0x1028 })
        mismatch.instructions[index].bytes = "1f 20 03 d5"
        try preservesBaseline(mismatch)
    }

    func testSkippedMalformedFixupWalkCannotCertifyCallerClosure() throws {
        try positive()
        var bytes = fixture()
        let parsed = try MachOParser().parse(bytes)
        let command = try XCTUnwrap(parsed.loadCommands.first { $0.command == 0x80000034 })
        let payload = Int(uint32(bytes, at: Int(command.offset) + 8))
        XCTAssertEqual(uint32(bytes, at: payload + 4), 28)
        put32(UInt32.max, in: &bytes, at: payload + 32)
        XCTAssertTrue(try MachOParser().parse(bytes).dyldChainedFixups?.fixups.isEmpty == true)
        try preservesBaseline(analyze(bytes))
    }

    func testSkippedNlistSymbolCannotCertifyPrivateCallerClosure() throws {
        try positive()
        var bytes = fixture()
        let parsed = try MachOParser().parse(bytes)
        let command = try XCTUnwrap(parsed.loadCommands.first { $0.command == 2 })
        let symbols = Int(uint32(bytes, at: Int(command.offset) + 8))
        put32(0, in: &bytes, at: symbols)
        XCTAssertEqual(try MachOParser().parse(bytes).symbols.count, parsed.symbols.count - 1)
        try preservesBaseline(analyze(bytes))
    }

    func testCyclicAndResolverExportTriesCannotHideFunctionEntries() throws {
        try positive()
        let tries: [[UInt8]] = [[0, 1, 0x78, 0, 0],
                              [0, 1, 0x73, 0, 5, 5, 0x10, 0x80, 0x20, 0x94, 0x20, 0]]
        for trie in tries {
            var bytes = fixture()
            let parsed = try MachOParser().parse(bytes)
            let command = try XCTUnwrap(parsed.loadCommands.first { $0.command == 0x80000033 })
            let payload = bytes.count
            bytes.append(contentsOf: trie)
            put32(UInt32(payload), in: &bytes, at: Int(command.offset) + 8)
            put32(UInt32(trie.count), in: &bytes, at: Int(command.offset) + 12)
            // Exact fixture __LINKEDIT segment declaration; preserve mapping.
            put32(uint32(bytes, at: 216) + UInt32(trie.count), in: &bytes, at: 216)
            put32(uint32(bytes, at: 232) + UInt32(trie.count), in: &bytes, at: 232)
            let reparsed = try MachOParser().parse(bytes)
            if trie.count == 5 { XCTAssertTrue(reparsed.exports.isEmpty) }
            else { XCTAssertEqual(reparsed.exports.compactMap(\.address), [0x1000]) }
            try preservesBaseline(analyze(bytes))
        }
    }

    private func uint32(_ bytes: Data, at offset: Int) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | (UInt32(bytes[offset + $1]) << (8 * $1)) }
    }
    private func put32(_ value: UInt32, in bytes: inout Data, at offset: Int) {
        for index in 0..<4 { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (8 * index)) }
    }
}
