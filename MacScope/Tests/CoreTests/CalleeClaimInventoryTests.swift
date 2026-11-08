import Foundation
import XCTest
@testable import MacScope

/// VI3 slice B (DESIGN section 4, "B:" list): the typed direct-callee inventory reader over
/// synthetic snapshot fixtures. No app, no binary corpus, no registered command.
final class CalleeClaimInventoryTests: XCTestCase {
    private typealias Inventory = CalleeClaimInventorySnapshot

    private func call(_ from: UInt64, _ to: UInt64, _ kind: String = XRefKind.call) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }

    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: "", mnemonic: mnemonic, operands: operands,
                       hasBreakpoint: false, comment: nil)
    }

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    /// Layout: `_root` 0x5000..0x5040 is the function under inventory; `_helper` 0x3000, `_other`
    /// 0x6000..0x6040 (0x6010 is interior), `_handler` 0x9040, `_objc_msgSend$beta` 0x7200 are
    /// targets; symbols give a stub (0x7000) and an import (0x7100); 0x8000 is unnamed.
    private func makeSnapshot(xrefs: [XRef], edges: [ControlFlowEdge] = [],
                              withIndirect: Bool = false,
                              extraFunctions: [FunctionSummary] = []) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.functions = [
            function("_root", 0x5000, 0x5040), function("_helper", 0x3000, 0x3010),
            function("_other", 0x6000, 0x6040), function("_handler", 0x9040, 0x9044),
            function("_objc_msgSend$beta", 0x7200, 0x7210),
        ] + extraFunctions
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: "_objc_msgSend$alpha", address: 0x7000, kind: "stub", libraryName: nil),
            SymbolSummary(id: UUID(), name: "_malloc", address: 0x7100, kind: "import", libraryName: nil),
        ]
        analysis.xrefs = xrefs
        analysis.controlFlowEdges = edges
        if withIndirect {
            analysis.instructions = [
                row(0x5000, "adrp", "x9, 0x9000"), row(0x5004, "add", "x9, x9, #0x40"),
                row(0x5008, "str", "x9, [x0, #0x18]"), row(0x500c, "ldr", "x8, [x0, #0x18]"),
                row(0x5010, "blr", "x8"), row(0x5014, "ldr", "x10, [x1, #0x20]"),
                row(0x5018, "blr", "x10"), row(0x501c, "ret", ""), row(0x9040, "ret", ""),
            ]
        }
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims", path: "/tmp/callee-claims",
                                                 kind: "executable", architecture: "arm64", slot: .primary),
                             analysis: analysis)
        return snapshot
    }

    private func inventory(_ snapshot: WorkspaceSnapshot, at address: UInt64 = 0x5000) throws -> Inventory {
        try WorkspaceScriptingAPI.calleeClaimInventory(
            arguments: .object(["address": .hex(address)]), snapshot: snapshot, checkpoint: {})
    }

    private let permanent = Inventory.Limitation.indirectTailCallsNotInventoried

    // B: 3 direct call xrefs (two to the same target, one to a stub) -> 2 required callees.
    func testTwoCallsToOneTargetAndOneStubYieldTwoRequiredCallees() throws {
        let result = try inventory(makeSnapshot(xrefs: [
            call(0x5004, 0x3000), call(0x5008, 0x3000), call(0x5020, 0x7000),
        ]))
        XCTAssertEqual(result.callees.map(\.address), [0x3000, 0x7000])
        XCTAssertEqual(result.callees.map(\.callSiteCount), [2, 1])
        XCTAssertEqual(result.callees[0].callSites, [0x5004, 0x5008])
        XCTAssertEqual(result.callees[0].name, "_helper")
        XCTAssertEqual(result.callees[1].kind, .stub)
        XCTAssertEqual(result.callees[1].name, "_objc_msgSend$alpha")
        XCTAssertEqual(result.functionStart, 0x5000)
        XCTAssertTrue(result.limitations.contains(permanent))
    }

    // B: every callee kind is produced by its own fixture row.
    func testTargetsAreTypedFunctionInteriorStubExternalUnnamed() throws {
        let result = try inventory(makeSnapshot(xrefs: [
            call(0x5004, 0x3000), call(0x5008, 0x6010), call(0x500c, 0x7000),
            call(0x5010, 0x7100), call(0x5014, 0x8000), call(0x5018, 0x7200),
        ]))
        let byAddress = Dictionary(uniqueKeysWithValues: result.callees.map { ($0.address, $0) })
        XCTAssertEqual(byAddress[0x3000]?.kind, .function)
        XCTAssertEqual(byAddress[0x6010]?.kind, .interior)
        XCTAssertEqual(byAddress[0x6010]?.containingFunction, 0x6000)
        XCTAssertEqual(byAddress[0x6010]?.offsetInContainingFunction, 0x10)
        XCTAssertEqual(byAddress[0x7000]?.kind, .stub)
        XCTAssertEqual(byAddress[0x7100]?.kind, .external)
        XCTAssertEqual(byAddress[0x7100]?.name, "_malloc")
        XCTAssertEqual(byAddress[0x8000]?.kind, .unnamed)
        XCTAssertNil(byAddress[0x8000]?.name)
        XCTAssertNil(byAddress[0x8000]?.containingFunction)
        // A function whose own name is an objc stub spelling is a stub, not a plain function.
        XCTAssertEqual(byAddress[0x7200]?.kind, .stub)
        XCTAssertEqual(result.callees.count, 6)
    }

    // B: a non-call xref kind inside the function is excluded.
    func testNonCallXRefKindsInsideFunctionAreExcluded() throws {
        let result = try inventory(makeSnapshot(xrefs: [
            call(0x5004, 0x6000), call(0x5008, 0x3000, XRefKind.data),
            call(0x500c, 0x3000, XRefKind.string), call(0x5010, 0x7000, XRefKind.selref),
            call(0x5014, 0x7100, "reference"),
        ]))
        XCTAssertEqual(result.callees.map(\.address), [0x6000])
        XCTAssertEqual(result.callees[0].callSiteCount, 1)
    }

    // B: an xref outside the function range is excluded (both range edges).
    func testCallXRefsOutsideTheFunctionRangeAreExcluded() throws {
        let result = try inventory(makeSnapshot(xrefs: [
            call(0x4000, 0x3000), call(0x4fff, 0x3000), call(0x5040, 0x3000),
            call(0x503c, 0x6000), call(0x5000, 0x7000),
        ]))
        XCTAssertEqual(result.callees.map(\.address), [0x6000, 0x7000])
    }

    // B: one resolved + one refused indirect site -> 1 advisory + unresolved == 1, no extra callee.
    func testIndirectResolvedIsAdvisoryAndRefusedIsCountedWithoutGuessedCallee() throws {
        let result = try inventory(makeSnapshot(xrefs: [call(0x5030, 0x3000)], withIndirect: true))
        XCTAssertEqual(result.callees.map(\.address), [0x3000], "indirect targets never become required callees")
        XCTAssertEqual(result.resolvedIndirect, [
            .init(callSite: 0x5010, target: 0x9040, targetName: "_handler", scope: "function"),
        ])
        XCTAssertEqual(result.unresolvedIndirectCallSites, 1)
        XCTAssertEqual(result.unresolvedIndirectReasons.values.reduce(0, +), 1)
        XCTAssertTrue(result.limitations.contains(Inventory.Limitation.unresolvedIndirectCallSites))
        XCTAssertFalse(result.limitations.contains(Inventory.Limitation.indirectCallTypingRefused))
    }

    // B: work-budget exhaustion is a typed budgetExceeded refusal, never an empty list.
    func testWorkBudgetExhaustionRefusesInsteadOfReturningAnEmptyList() throws {
        let limit = WorkspaceScriptingAPI.maximumSnapshotSelectionWork
        let xrefs = (0...limit).map { call(0x10_0000 + UInt64($0) * 4, 0x3000) }
        let snapshot = makeSnapshot(xrefs: xrefs, extraFunctions: [function("_big", 0x10_0000, 0x20_0000)])
        do {
            let result = try inventory(snapshot, at: 0x10_0000)
            XCTFail("expected a budget refusal, got \(result.callees.count) callees")
        } catch ScriptingError.structuredRefusal(let refusal) {
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget?.unit, .workSteps)
        }
    }

    // B: no landed analysis is `inventoryUnavailable`, not an empty callee list.
    func testMissingAnalysisIsInventoryUnavailable() {
        let image = BinaryImage(id: UUID(), name: "cold", path: "/tmp/cold", kind: "executable",
                                architecture: "arm64", slot: .primary)
        let snapshot = WorkspaceSnapshot(binaries: [image], analysisBySlot: [:])
        XCTAssertThrowsError(try inventory(snapshot)) { error in
            guard case CalleeClaimInventoryError.inventoryUnavailable = error else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    // B: a rename of a callee leaves inventoryDigest unchanged (names are not digest inputs).
    func testCalleeRenameLeavesDigestUnchanged() throws {
        let original = makeSnapshot(xrefs: [call(0x5004, 0x3000), call(0x5008, 0x6000)])
        let before = try inventory(original)
        var renamed = original
        var override = AddressOverride()
        override.customName = "renamed_helper"
        renamed.addressOverrides[ImageAddress(slot: .primary, address: 0x3000)] = override
        let after = try inventory(renamed)
        XCTAssertEqual(after.callees.first?.name, "renamed_helper")
        XCTAssertEqual(before.inventoryDigest, after.inventoryDigest)
        XCTAssertEqual(before.callees.map(\.address), after.callees.map(\.address))
        XCTAssertNotEqual(before.analysisGeneration, after.analysisGeneration,
                          "a rename advances the VI2 generation; the digest is what survives it")
    }

    // B: adding (or removing) a call xref changes inventoryDigest; xref order and ids do not.
    func testAddingACallXRefChangesDigestAndOrderDoesNot() throws {
        let base = [call(0x5004, 0x3000), call(0x5008, 0x6000)]
        let snapshot = makeSnapshot(xrefs: base)
        let digest = try inventory(snapshot).inventoryDigest
        XCTAssertEqual(try inventory(makeSnapshot(xrefs: base.reversed())).inventoryDigest, digest,
                       "digest ignores xref order and ids")
        var added = snapshot
        added.mutateAnalysis(in: .primary) { $0.xrefs.append(call(0x5010, 0x7000)) }
        XCTAssertNotEqual(try inventory(added).inventoryDigest, digest)
        var extraSite = snapshot
        extraSite.mutateAnalysis(in: .primary) { $0.xrefs.append(call(0x500c, 0x3000)) }
        XCTAssertNotEqual(try inventory(extraSite).inventoryDigest, digest, "a new call site to a known target counts")
        XCTAssertNotEqual(try inventory(makeSnapshot(xrefs: [base[0]])).inventoryDigest, digest)
    }

    // B: tail-call behaviour as established from the analysis code (see the file header):
    // direct out-of-function branches are enumerable (advisory, never required); indirect tail
    // calls are not, so every inventory carries `indirectTailCallsNotInventoried`.
    func testDirectOutOfFunctionBranchesAreAdvisoryAndIndirectTailCallsAreALimitation() throws {
        func edge(_ from: UInt64, _ to: UInt64, _ kind: String) -> ControlFlowEdge {
            ControlFlowEdge(id: UUID(), from: from, to: to, kind: kind)
        }
        let edges = [
            edge(0x503c, 0x3000, "branch"), edge(0x503c, 0x3000, "branch"),
            edge(0x5038, 0x7000, "branch"), edge(0x5034, 0x5038, "branch"),
            edge(0x5030, 0x6000, "fallthrough"), edge(0x5030, 0x5100, "switch"),
            edge(0x5004, 0x6000, "call"), edge(0x4000, 0x3000, "branch"),
        ]
        let xrefs = [call(0x5004, 0x6000)]
        let withBranches = try inventory(makeSnapshot(xrefs: xrefs, edges: edges))
        XCTAssertEqual(withBranches.callees.map(\.address), [0x6000], "branches never become required callees")
        XCTAssertEqual(withBranches.outOfFunctionBranches, [
            .init(from: 0x5038, target: 0x7000, targetKind: .stub, targetName: "_objc_msgSend$alpha"),
            .init(from: 0x503c, target: 0x3000, targetKind: .function, targetName: "_helper"),
        ])
        XCTAssertTrue(withBranches.limitations.contains(permanent))
        XCTAssertFalse(withBranches.limitations.contains(Inventory.Limitation.controlFlowEdgesUnavailable))

        // With no stored control-flow edges the branch scan cannot be claimed either.
        let withoutEdges = try inventory(makeSnapshot(xrefs: xrefs))
        XCTAssertTrue(withoutEdges.outOfFunctionBranches.isEmpty)
        XCTAssertEqual(withoutEdges.limitations,
                       [Inventory.Limitation.controlFlowEdgesUnavailable, permanent].sorted())
        XCTAssertNotEqual(withBranches.inventoryDigest, withoutEdges.inventoryDigest)
    }

    // B: a function with no direct calls still carries the permanent limitation (never "complete").
    func testFunctionWithNoCallsHasNoCalleesButKeepsTheTailCallLimitation() throws {
        let result = try inventory(makeSnapshot(xrefs: [call(0x4000, 0x3000)]))
        XCTAssertTrue(result.callees.isEmpty)
        XCTAssertTrue(result.limitations.contains(permanent))
        XCTAssertEqual(result.limitations, result.limitations.sorted())
    }
}
