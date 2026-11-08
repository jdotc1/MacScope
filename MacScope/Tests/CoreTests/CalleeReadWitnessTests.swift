import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// VI3 slice E (DESIGN section 2.5 and the slice E test list; RULINGS Q5 (a)): `record-callee-outcome examined`
/// needs an in-memory read witness for the callee at the current analysis generation. Same synthetic fixture
/// layout as `CalleeClaimCommandTests`. `decompile` is not exercised: the fixture has no instructions to lift,
/// and a decompile that cannot lift would not be an honest witness read.
@MainActor
final class CalleeReadWitnessTests: XCTestCase {
    private func call(_ from: UInt64, _ to: UInt64) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: XRefKind.call)
    }

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    /// `_root` 0x5000 calls `_helper` 0x3000 and the stub 0x7000. `_other` 0x6000 is unrelated.
    private func analysis() -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.functions = [
            function("_root", 0x5000, 0x5040), function("_helper", 0x3000, 0x3010), function("_other", 0x6000, 0x6040),
        ]
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: "_objc_msgSend$alpha", address: 0x7000, kind: "stub", libraryName: nil),
        ]
        analysis.xrefs = [call(0x5004, 0x3000), call(0x5008, 0x3000), call(0x5020, 0x7000)]
        analysis.stringLiteralCoverage = .complete
        analysis.stringLiterals = []
        analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: [], cfStrings: [:])
        analysis.basicBlocks = [BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: 0x3000,
                                                  endAddress: 0x3010, instructionCount: 4)]
        return analysis
    }

    private func makeStore(twoImages: Bool = false) -> WorkspaceStore {
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims", path: "/tmp/callee-witness",
                                                 kind: "executable", architecture: "arm64", slot: .primary),
                             analysis: analysis())
        if twoImages {
            snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims2", path: "/tmp/callee-witness-2",
                                                     kind: "executable", architecture: "arm64",
                                                     slot: ImageSlot(rawValue: 1)),
                                 analysis: analysis())
        }
        return WorkspaceStore(workspaceName: "witness", snapshot: snapshot, engine: AnalysisEngine(),
                              autosaveScheduler: nil)
    }

    private func run(_ store: WorkspaceStore, _ command: String, _ fields: [String: ScriptValue]) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute(command, arguments: .object(fields))
    }

    private func open(_ store: WorkspaceStore, _ extra: [String: ScriptValue] = [:]) throws -> String {
        var fields: [String: ScriptValue] = ["address": .hex(0x5000)]
        for (key, value) in extra { fields[key] = value }
        let reply = try run(store, "open-claim", fields)
        return try XCTUnwrap(reply["claim"]?.stringValue, "reply has no claim: \(reply)")
    }

    private func examine(_ store: WorkspaceStore, _ claim: String, _ callee: UInt64 = 0x3000) throws -> ScriptValue {
        try run(store, "record-callee-outcome", ["claim": .string(claim), "callee": .hex(callee),
                                                 "outcome": .string("examined"), "reason": .string("read it")])
    }

    private func readFields(_ command: String) -> [String: ScriptValue] {
        command == "function-facts" ? ["address": .hex(0x3000)] : ["function": .string("_helper")]
    }

    // (a) callees and xrefs on the callee do not witness; the refusal leaves the ledger untouched.
    func testCalleesCallersAndXrefsDoNotWitness() throws {
        let store = makeStore()
        let id = try open(store)
        _ = try run(store, "callees", ["function": .string("_helper")])
        _ = try run(store, "callers", ["function": .string("_helper")])
        _ = try run(store, "xrefs", ["to": .hex(0x3000)])
        _ = try run(store, "xrefs", ["from": .hex(0x3000)])
        XCTAssertEqual(store.calleeClaimLedgerBox.readWitnesses.count, 0)
        let events = store.calleeClaimLedger.events.count
        let refused = try examine(store, id)
        XCTAssertEqual(refused["ok"], .bool(false))
        XCTAssertEqual(refused["error"], .string("examinedWithoutWitness"))
        let hint = try XCTUnwrap(refused["hint"]?.stringValue)
        for name in ["instructions", "decompile", "basic-blocks", "function-facts"] {
            XCTAssertTrue(hint.contains(name), "the hint names \(name)")
        }
        XCTAssertEqual(store.calleeClaimLedger.events.count, events, "no event is recorded")
    }

    // (b) each witnessing command makes examined acceptable and is named by the stored witness.
    func testInstructionsBasicBlocksAndFunctionFactsEachWitness() throws {
        for command in ["instructions", "basic-blocks", "function-facts"] {
            let store = makeStore()
            let id = try open(store)
            _ = try run(store, command, readFields(command))
            let reply = try examine(store, id)
            XCTAssertEqual(reply["ok"], .bool(true), "\(command): \(reply)")
            XCTAssertEqual(reply["recorded"]?["witness"]?["command"], .string(command))
            XCTAssertEqual(reply["recorded"]?["witness"]?["generation"],
                           .string(store.snapshot.analysisGenerationID.uuidString))
            XCTAssertEqual(reply["recorded"]?["witness"]?["sequence"], .int(1))
            XCTAssertNil(reply["witnessNote"])
            XCTAssertEqual(store.calleeClaimLedger.events.last?.witness?.command, command)
        }
    }

    // (b, async) the MCP/async entry points witness too: they never run the registry closures.
    func testTheAsyncEntryPointsWitnessToo() async throws {
        for command in ["instructions", "basic-blocks", "function-facts"] {
            let store = makeStore()
            let id = try open(store)
            _ = try await WorkspaceScriptingAPI(store: store).executeAsync(command, arguments: .object(readFields(command)))
            let reply = try examine(store, id)
            XCTAssertEqual(reply["ok"], .bool(true), "\(command): \(reply)")
            XCTAssertEqual(reply["recorded"]?["witness"]?["command"], .string(command))
        }
    }

    // (c) an address+count range read is not a function read.
    func testInstructionsRangeReadDoesNotWitness() throws {
        let store = makeStore()
        let id = try open(store)
        _ = try run(store, "instructions", ["address": .hex(0x3000), "count": .int(4)])
        XCTAssertEqual(store.calleeClaimLedgerBox.readWitnesses.count, 0)
        XCTAssertEqual(try examine(store, id)["error"], .string("examinedWithoutWitness"))
    }

    // A failed read appends nothing.
    func testAFailedReadAppendsNothing() throws {
        let store = makeStore()
        let id = try open(store)
        XCTAssertThrowsError(try run(store, "instructions", ["function": .string("_nonexistent")]))
        XCTAssertThrowsError(try run(store, "basic-blocks", ["function": .string("_nonexistent")]))
        XCTAssertEqual(store.calleeClaimLedgerBox.readWitnesses.count, 0)
        XCTAssertEqual(try examine(store, id)["error"], .string("examinedWithoutWitness"))
    }

    // (d) ring overflow: once enough newer entries displace it, the old witness is gone.
    func testRingOverflowLosesTheOldWitness() throws {
        let store = makeStore()
        store.calleeClaimLedgerBox.readWitnesses = CalleeReadWitnessLog(capacity: 3)
        let id = try open(store)
        _ = try run(store, "instructions", ["function": .string("_helper")])
        for _ in 0..<3 { _ = try run(store, "instructions", ["function": .string("_other")]) }
        XCTAssertEqual(store.calleeClaimLedgerBox.readWitnesses.count, 3)
        XCTAssertEqual(try examine(store, id)["error"], .string("examinedWithoutWitness"))
        _ = try run(store, "instructions", ["function": .string("_helper")])
        XCTAssertEqual(try examine(store, id)["ok"], .bool(true))
    }

    func testDefaultRingHoldsExactly4096AndKeepsMonotonicSequences() {
        var log = CalleeReadWitnessLog()
        XCTAssertEqual(log.capacity, 4_096)
        let generation = UUID()
        log.append(imageSlot: 0, functionStart: 0x3000, command: "instructions", generation: generation)
        for _ in 0..<4_095 { log.append(imageSlot: 0, functionStart: 0x6000, command: "instructions", generation: generation) }
        XCTAssertEqual(log.count, 4_096)
        XCTAssertEqual(log.latest(imageSlot: 0, functionStart: 0x3000, generation: generation)?.sequence, 1)
        log.append(imageSlot: 0, functionStart: 0x6000, command: "basic-blocks", generation: generation)
        XCTAssertEqual(log.count, 4_096)
        XCTAssertNil(log.latest(imageSlot: 0, functionStart: 0x3000, generation: generation),
                     "4,096 newer entries displaced the first")
        XCTAssertEqual(log.latest(imageSlot: 0, functionStart: 0x6000, generation: generation)?.sequence, 4_097)
        XCTAssertEqual(log.latest(imageSlot: 0, functionStart: 0x6000, generation: generation)?.command, "basic-blocks")
    }

    // (e) a witness taken before a generation bump does not count; a fresh read does.
    func testAWitnessFromBeforeAGenerationBumpDoesNotCount() throws {
        let store = makeStore()
        let id = try open(store)
        _ = try run(store, "instructions", ["function": .string("_helper")])
        let before = store.snapshot.analysisGenerationID
        _ = try run(store, "rename", ["address": .hex(0x6000), "name": .string("renamedOther")])
        XCTAssertNotEqual(store.snapshot.analysisGenerationID, before)
        let rebound = try run(store, "open-claim", ["address": .hex(0x5000), "rebind": .bool(true)])
        XCTAssertEqual(rebound["ok"], .bool(true), "\(rebound)")
        let events = store.calleeClaimLedger.events.count
        let refused = try examine(store, id)
        XCTAssertEqual(refused["error"], .string("examinedWithoutWitness"), "\(refused)")
        XCTAssertEqual(store.calleeClaimLedger.events.count, events)
        _ = try run(store, "instructions", ["function": .string("_helper")])
        let accepted = try examine(store, id)
        XCTAssertEqual(accepted["ok"], .bool(true), "\(accepted)")
        XCTAssertEqual(accepted["recorded"]?["witness"]?["generation"],
                       .string(store.snapshot.analysisGenerationID.uuidString))
    }

    // (f) the witness summary persists on the outcome and claim-status shows it.
    func testTheWitnessSummaryPersistsOnTheOutcomeAndShowsInClaimStatus() throws {
        let store = makeStore()
        let id = try open(store)
        _ = try run(store, "basic-blocks", ["function": .string("_helper")])
        _ = try run(store, "function-facts", ["address": .hex(0x3000)])
        XCTAssertEqual(try examine(store, id)["ok"], .bool(true))
        let status = try run(store, "claim-status", ["claim": .string(id), "detail": .string("all")])
        let row = try XCTUnwrap(status["callees"]?.arrayValue?.first { $0["callee"] == .string("0x3000") })
        let witness = try XCTUnwrap(row["outcome"]?["witness"], "\(row)")
        XCTAssertEqual(witness["command"], .string("function-facts"), "the latest witnessing read wins")
        XCTAssertEqual(witness["sequence"], .int(2))
        XCTAssertEqual(witness["generation"], .string(store.snapshot.analysisGenerationID.uuidString))
        let stored = try XCTUnwrap(store.calleeClaimLedger.events.last?.witness)
        XCTAssertEqual(stored.command, "function-facts")
        XCTAssertEqual(stored.sequence, 2)
    }

    // (g) a different function start, or a different image slot, does not witness.
    func testADifferentFunctionOrADifferentSlotDoesNotWitness() throws {
        let store = makeStore(twoImages: true)
        let id = try open(store)
        _ = try run(store, "instructions", ["function": .string("_other")])
        XCTAssertEqual(try examine(store, id)["error"], .string("examinedWithoutWitness"))
        _ = try run(store, "function-facts", ["address": .hex(0x3000), "imageSlot": .int(1)])
        XCTAssertEqual(store.calleeClaimLedgerBox.readWitnesses.count, 2)
        XCTAssertEqual(try examine(store, id)["error"], .string("examinedWithoutWitness"),
                       "the read answered in slot 1; the claim is on slot 0")
        _ = try run(store, "function-facts", ["address": .hex(0x3000), "imageSlot": .int(0)])
        XCTAssertEqual(try examine(store, id)["ok"], .bool(true))
    }

    // irrelevant and deferred need no witness.
    func testIrrelevantAndDeferredNeedNoWitness() throws {
        let store = makeStore()
        let id = try open(store)
        for (callee, outcome) in [(UInt64(0x3000), "irrelevant"), (UInt64(0x7000), "deferred")] {
            let reply = try run(store, "record-callee-outcome", ["claim": .string(id), "callee": .hex(callee),
                                                                 "outcome": .string(outcome), "reason": .string("later")])
            XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
            XCTAssertEqual(reply["recorded"]?["witness"], .null)
            XCTAssertNil(reply["witnessNote"])
        }
    }
}
