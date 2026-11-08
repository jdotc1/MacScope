import Foundation
import XCTest
@testable import MacScope

/// VI3 slice C (DESIGN section 4, "C:" list): the three session-only claim commands over synthetic
/// store fixtures (the layout of `CalleeClaimInventoryTests`). No app, no binary corpus.
@MainActor
final class CalleeClaimCommandTests: XCTestCase {
    private let permanent = CalleeClaimInventorySnapshot.Limitation.indirectTailCallsNotInventoried

    private func call(_ from: UInt64, _ to: UInt64) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: XRefKind.call)
    }

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    /// `_root` 0x5000..0x5040 calls `_helper` 0x3000 (twice) and the stub 0x7000: two required callees.
    /// `_helper` has no calls. `_other` 0x6000 is the unrelated function a rename touches.
    private func analysis(root: String = "_root") -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.functions = [
            function(root, 0x5000, 0x5040), function("_helper", 0x3000, 0x3010),
            function("_other", 0x6000, 0x6040), function("_objc_msgSend$beta", 0x7200, 0x7210),
        ]
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: "_objc_msgSend$alpha", address: 0x7000, kind: "stub", libraryName: nil),
        ]
        analysis.xrefs = [call(0x5004, 0x3000), call(0x5008, 0x3000), call(0x5020, 0x7000)]
        return analysis
    }

    private func makeStore(twoImages: Bool = false) -> WorkspaceStore {
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims", path: "/tmp/callee-claims",
                                                 kind: "executable", architecture: "arm64", slot: .primary),
                             analysis: analysis())
        if twoImages {
            snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims2", path: "/tmp/callee-claims-2",
                                                     kind: "executable", architecture: "arm64",
                                                     slot: ImageSlot(rawValue: 1)),
                                 analysis: analysis())
        }
        return WorkspaceStore(workspaceName: "claims", snapshot: snapshot, engine: AnalysisEngine(),
                              autosaveScheduler: nil)
    }

    private func run(_ store: WorkspaceStore, _ command: String, _ fields: [String: ScriptValue]) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute(command, arguments: .object(fields))
    }

    private func open(_ store: WorkspaceStore, _ fields: [String: ScriptValue] = ["address": .hex(0x5000)]) throws -> ScriptValue {
        try run(store, "open-claim", fields)
    }

    private func record(_ store: WorkspaceStore, _ claim: String, _ callee: ScriptValue, _ outcome: String,
                        reason: String = "checked", extra: [String: ScriptValue] = [:]) throws -> ScriptValue {
        var fields: [String: ScriptValue] = ["claim": .string(claim), "callee": callee,
                                             "outcome": .string(outcome), "reason": .string(reason)]
        for (key, value) in extra { fields[key] = value }
        return try run(store, "record-callee-outcome", fields)
    }

    private func claimID(_ reply: ScriptValue, file: StaticString = #filePath, line: UInt = #line) throws -> String {
        try XCTUnwrap(reply["claim"]?.stringValue, "reply has no claim: \(reply)", file: file, line: line)
    }

    private func strings(_ value: ScriptValue?) -> [String] {
        value?.arrayValue?.compactMap(\.stringValue) ?? []
    }

    // (a) by name and by address return the same claim; the second call is alreadyOpen.
    func testOpenClaimByNameAndByAddressReturnsTheSameClaim() throws {
        let store = makeStore()
        let first = try open(store, ["address": .hex(0x5000)])
        XCTAssertEqual(first["ok"], .bool(true))
        XCTAssertEqual(first["alreadyOpen"], .bool(false))
        XCTAssertEqual(first["durability"], .string("session"))
        XCTAssertEqual(first["revision"], .int(1))
        XCTAssertEqual(first["status"], .string("open"))
        XCTAssertEqual(first["coverage"]?["required"], .int(2))
        XCTAssertEqual(first["coverage"]?["open"], .int(2))
        XCTAssertTrue(strings(first["limitations"]).contains(permanent))
        let second = try open(store, ["function": .string("_root")])
        XCTAssertEqual(try claimID(second), try claimID(first))
        XCTAssertEqual(second["alreadyOpen"], .bool(true))
        XCTAssertEqual(second["revision"], .int(1))
        XCTAssertEqual(try run(store, "claim-status", [:])["total"], .int(1), "one claim, not two")
    }

    // (b) claim-status lists only open callees by default.
    func testClaimStatusListsOnlyOpenCalleesByDefault() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        _ = try record(store, id, .hex(0x3000), "irrelevant")
        let status = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(status["openCalleesTotal"], .int(1))
        let rows = try XCTUnwrap(status["openCallees"]?.arrayValue)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0]["callee"], .string("0x7000"))
        XCTAssertNil(status["callees"], "the full list needs detail:all")
        let all = try run(store, "claim-status", ["claim": .string(id), "detail": .string("all")])
        XCTAssertEqual(all["callees"]?.arrayValue?.count, 2)
        // The claim-list mode defaults to open claims and filters by state.
        XCTAssertEqual(try run(store, "claim-status", [:])["total"], .int(1))
        XCTAssertEqual(try run(store, "claim-status", ["state": .string("closed")])["total"], .int(0))
    }

    // (c) the claim closes after the last outcome.
    func testClaimClosesAfterTheLastOutcome() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        let afterFirst = try record(store, id, .hex(0x3000), "irrelevant")
        XCTAssertEqual(afterFirst["status"], .string("open"))
        let afterLast = try record(store, id, .string("_objc_msgSend$alpha"), "deferred", reason: "later")
        XCTAssertEqual(afterLast["status"], .string("closed"))
        XCTAssertEqual(afterLast["coverage"]?["open"], .int(0))
        XCTAssertEqual(afterLast["closedWithDeferrals"], .bool(true))
        XCTAssertEqual(try run(store, "claim-status", [:])["total"], .int(0), "closed claims leave the default list")
        XCTAssertEqual(try run(store, "claim-status", ["state": .string("closed")])["total"], .int(1))
    }

    // (d) a basedOnGeneration mismatch is staleEvidence and the ledger is unchanged.
    func testBasedOnGenerationMismatchIsStaleEvidenceAndLeavesTheLedgerUnchanged() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        let before = store.calleeClaimLedger
        XCTAssertThrowsError(try record(store, id, .hex(0x3000), "irrelevant",
                                        extra: ["basedOnGeneration": .string(UUID().uuidString)])) { error in
            guard case ScriptingError.staleEvidence = error else { return XCTFail("expected staleEvidence, got \(error)") }
        }
        XCTAssertEqual(store.calleeClaimLedger, before)
        XCTAssertThrowsError(try open(store, ["address": .hex(0x3000), "basedOnGeneration": .string(UUID().uuidString)]))
        XCTAssertEqual(store.calleeClaimLedger, before)
        // The matching generation is accepted.
        let current = store.snapshot.analysisGenerationID.uuidString
        let ok = try record(store, id, .hex(0x3000), "irrelevant", extra: ["basedOnGeneration": .string(current)])
        XCTAssertEqual(ok["ok"], .bool(true))
    }

    // (e) renaming an unrelated function makes the claim stale; a later outcome is claimStale.
    func testRenamingAnUnrelatedFunctionMakesTheClaimStale() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        let before = store.snapshot.analysisGenerationID
        _ = try run(store, "rename", ["address": .hex(0x6000), "name": .string("renamedOther")])
        XCTAssertNotEqual(store.snapshot.analysisGenerationID, before)
        let status = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(status["status"], .string("stale"))
        // The root call xrefs are untouched, so the digest is equal: generationAdvanced, rebindable (slice D).
        XCTAssertEqual(status["staleKind"], .string("generationAdvanced"))
        XCTAssertEqual(status["rebindable"], .bool(true))
        let refused = try record(store, id, .hex(0x3000), "irrelevant")
        XCTAssertEqual(refused["ok"], .bool(false))
        XCTAssertEqual(refused["error"], .string("claimStale"))
        XCTAssertEqual(refused["rebindable"], .bool(true))
        XCTAssertEqual(refused["durability"], .string("session"))
        // rebind itself is covered by CalleeClaimRebindTests.
    }

    // (f) neither command changes the analysis generation or registers an undo step.
    func testNeitherCommandChangesTheGenerationOrRegistersAnUndoStep() throws {
        let store = makeStore()
        let generation = store.snapshot.analysisGenerationID
        XCTAssertFalse(store.undoManager.canUndo)
        let opened = try open(store)
        XCTAssertEqual(opened["generation"], .string(generation.uuidString))
        let id = try claimID(opened)
        _ = try run(store, "instructions", ["function": .string("_helper")])
        let recorded = try record(store, id, .hex(0x3000), "examined", reason: "read it")
        XCTAssertEqual(recorded["generation"], .string(generation.uuidString))
        _ = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(store.snapshot.analysisGenerationID, generation)
        XCTAssertFalse(store.undoManager.canUndo)
        XCTAssertNil(store.undoManager.undoActionName.isEmpty ? nil : store.undoManager.undoActionName)
    }

    // (g) the MCP catalog lists all three commands and drops none of the existing ones.
    func testMCPCatalogListsTheThreeCommandsAndDropsNone() throws {
        let store = makeStore()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")])
        let tools = try XCTUnwrap(server.handle(request)?["result"]?["tools"]?.arrayValue)
        let names = Set(tools.compactMap { $0["name"]?.stringValue })
        for name in ["open-claim", "record-callee-outcome", "claim-status"] {
            XCTAssertEqual(tools.filter { $0["name"] == .string(name) }.count, 1, name)
        }
        for name in ["callees", "callers", "xrefs", "functions", "decompile", "call-graph", "call-path", "rename",
                     "set-comment", "undo-last", "indirect-call-targets", "function-facts", "commands", "info"] {
            XCTAssertTrue(names.contains(name), "\(name) must remain in the catalog")
        }
        let status = try XCTUnwrap(tools.first { $0["name"] == .string("claim-status") })
        XCTAssertEqual(status["annotations"]?["readOnlyHint"], .bool(true))
    }

    // (h) the two-image fixture needs imageSlot to select a claim.
    func testTwoImagesNeedImageSlotToSelectTheClaim() throws {
        let store = makeStore(twoImages: true)
        let primary = try open(store, ["address": .hex(0x5000), "imageSlot": .int(0)])
        let second = try open(store, ["address": .hex(0x5000), "imageSlot": .int(1)])
        XCTAssertNotEqual(try claimID(primary), try claimID(second))
        XCTAssertEqual(second["imageSlot"], .int(1))
        XCTAssertEqual(second["binding"]?["imageSlot"], .int(1))
        let ambiguous = try run(store, "claim-status", ["function": .string("_root")])
        XCTAssertEqual(ambiguous["ok"], .bool(false))
        XCTAssertEqual(ambiguous["error"], .string("claimAmbiguous"))
        XCTAssertEqual(ambiguous["imageSlots"], .array([.int(0), .int(1)]))
        let chosen = try run(store, "claim-status", ["function": .string("_root"), "imageSlot": .int(1)])
        XCTAssertEqual(try claimID(chosen), try claimID(second))
        // Both claims are listed when no selector is given.
        XCTAssertEqual(try run(store, "claim-status", [:])["total"], .int(2))
    }

    // (i) a complete inventory that carries a limitation closes with the limitation disclosed.
    func testCompleteInventoryWithALimitationClosesWithItDisclosed() throws {
        let store = makeStore()
        let opened = try open(store, ["address": .hex(0x3000)])
        XCTAssertEqual(opened["coverage"]?["required"], .int(0))
        XCTAssertEqual(opened["status"], .string("closed"))
        XCTAssertEqual(opened["leaf"], .bool(false), "a limitation keeps a claim from being a proven leaf")
        XCTAssertTrue(strings(opened["limitations"]).contains(permanent))
        XCTAssertTrue(strings(opened["coverage"]?["limitations"]).contains(permanent))
        XCTAssertEqual(opened["coverage"]?["scope"]?.stringValue?.hasPrefix("Stored direct call xrefs"), true)
    }

    // (j) supersede:true on a stale claim opens revision 2 with every callee open.
    func testSupersedeOnAStaleClaimOpensRevisionTwoWithEveryCalleeOpen() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        _ = try record(store, id, .hex(0x3000), "irrelevant")
        _ = try run(store, "rename", ["address": .hex(0x6000), "name": .string("renamedOther")])
        let stillStale = try open(store)
        XCTAssertEqual(stillStale["alreadyOpen"], .bool(true))
        XCTAssertEqual(stillStale["status"], .string("stale"), "without supersede the stale claim is returned as is")
        let next = try open(store, ["address": .hex(0x5000), "supersede": .bool(true)])
        XCTAssertEqual(try claimID(next), id)
        XCTAssertEqual(next["revision"], .int(2))
        XCTAssertEqual(next["superseded"], .bool(true))
        XCTAssertEqual(next["status"], .string("open"))
        XCTAssertEqual(next["coverage"]?["open"], .int(2))
        XCTAssertEqual(next["coverage"]?["required"], .int(2))
        XCTAssertEqual(next["binding"]?["generation"], .string(store.snapshot.analysisGenerationID.uuidString))
        XCTAssertEqual(next["openCallees"]?.arrayValue?.count, 2)
        // Outcomes are accepted again on the new revision.
        XCTAssertEqual(try record(store, id, .hex(0x3000), "irrelevant")["ok"], .bool(true))
    }

    // (k) slice E: examined needs a read witness. The stub 0x7000 has no code to read, so it is refused; a
    // witnessed callee is accepted and no longer lists examinedNotWitnessed.
    func testExaminedNeedsAWitnessAndWitnessedExaminedDoesNotListTheLimitation() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        let irrelevant = try record(store, id, .hex(0x3000), "irrelevant")
        XCTAssertFalse(strings(irrelevant["limitations"]).contains("examinedNotWitnessed"))
        let refused = try record(store, id, .hex(0x7000), "examined", reason: "read the body",
                                 extra: ["bearing": .string("supports")])
        XCTAssertEqual(refused["ok"], .bool(false))
        XCTAssertEqual(refused["error"], .string("examinedWithoutWitness"))
        _ = try run(store, "instructions", ["function": .string("_helper")])
        let examined = try record(store, id, .hex(0x3000), "examined", reason: "read the body",
                                  extra: ["bearing": .string("supports")])
        XCTAssertEqual(examined["ok"], .bool(true))
        XCTAssertFalse(strings(examined["limitations"]).contains("examinedNotWitnessed"))
        XCTAssertFalse(strings(examined["coverage"]?["limitations"]).contains("examinedNotWitnessed"))
        XCTAssertEqual(examined["recorded"]?["witness"]?["command"], .string("instructions"))
        XCTAssertNil(examined["witnessNote"])
        let status = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertFalse(strings(status["limitations"]).contains("examinedNotWitnessed"))
    }

    // (l) the B-to-A mapping sorts unsorted B output and drops duplicates.
    func testMappingSortsUnsortedInventoryOutput() throws {
        let store = makeStore()
        var read = try WorkspaceScriptingAPI.calleeClaimInventory(
            arguments: .object(["address": .hex(0x5000)]), snapshot: store.snapshot, checkpoint: {})
        XCTAssertEqual(read.callees.map(\.address), [0x3000, 0x7000])
        read.callees.reverse()
        read.callees.append(read.callees[0])
        XCTAssertEqual(read.callees.map(\.address), [0x7000, 0x3000, 0x7000])
        let mapped = try WorkspaceScriptingAPI.calleeClaimVAInventory(from: read)
        XCTAssertEqual(mapped.callees.map(\.callee.rawValue), [0x3000, 0x7000])
        XCTAssertEqual(mapped.callees.map(\.kind), [.function, .stub])
        XCTAssertEqual(mapped.function.rawValue, 0x5000)
        XCTAssertEqual(mapped.limitations, read.limitations)
        XCTAssertEqual(mapped.inventoryDigest, read.inventoryDigest)
        XCTAssertTrue(mapped.limitations.contains(permanent))
        XCTAssertEqual(mapped.completeness, .complete)
    }

    // The typed refusals of the writer: unknownClaim, calleeNotInClaim, outcomeInvalid.
    func testRecordRefusalsAreTyped() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        let before = store.calleeClaimLedger
        XCTAssertEqual(try record(store, UUID().uuidString, .hex(0x3000), "irrelevant")["error"], .string("unknownClaim"))
        XCTAssertEqual(try record(store, id, .hex(0x9999), "irrelevant")["error"], .string("calleeNotInClaim"))
        XCTAssertEqual(try record(store, id, .hex(0x3000), "irrelevant", reason: "")["error"], .string("outcomeInvalid"))
        XCTAssertEqual(try record(store, id, .hex(0x3000), "guessed")["error"], .string("outcomeInvalid"))
        XCTAssertEqual(store.calleeClaimLedger, before, "a refusal never touches the ledger")
    }
}
