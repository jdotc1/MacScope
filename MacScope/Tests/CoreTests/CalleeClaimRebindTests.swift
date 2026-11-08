import Foundation
import XCTest
@testable import MacScope

/// VI3 slice D (DESIGN section 4, "D:" list; RULINGS Q4 (a)): the digest-bound claim, `rebind:true`,
/// `invalidatedCallees`, the `inventoryChanged` diff and `supersede:true` with `priorOutcomes`, over the
/// same synthetic store fixtures as `CalleeClaimCommandTests` (plus one external import callee). No app,
/// no binary corpus.
@MainActor
final class CalleeClaimRebindTests: XCTestCase {
    private func call(_ from: UInt64, _ to: UInt64) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: XRefKind.call)
    }

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    /// `_root` 0x5000..0x5040 calls `_helper` 0x3000 (twice), the stub 0x7000 and the import `_malloc` 0x7100:
    /// three required callees. `_helper` 0x3000..0x3010 has no calls. `_other` 0x6000..0x6040 is a function
    /// the root does not call. The stub and the import have no body in the image.
    private func makeStore() -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.functions = [
            function("_root", 0x5000, 0x5040), function("_helper", 0x3000, 0x3010),
            function("_other", 0x6000, 0x6040),
        ]
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: "_objc_msgSend$alpha", address: 0x7000, kind: "stub", libraryName: nil),
            SymbolSummary(id: UUID(), name: "_malloc", address: 0x7100, kind: "import", libraryName: nil),
        ]
        analysis.xrefs = [call(0x5004, 0x3000), call(0x5008, 0x3000), call(0x5020, 0x7000), call(0x5030, 0x7100)]
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "claims", path: "/tmp/callee-claims",
                                                 kind: "executable", architecture: "arm64", slot: .primary),
                             analysis: analysis)
        return WorkspaceStore(workspaceName: "claims", snapshot: snapshot, engine: AnalysisEngine(),
                              autosaveScheduler: nil)
    }

    private func run(_ store: WorkspaceStore, _ command: String, _ fields: [String: ScriptValue]) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute(command, arguments: .object(fields))
    }

    private func open(_ store: WorkspaceStore, _ extra: [String: ScriptValue] = [:]) throws -> ScriptValue {
        var fields: [String: ScriptValue] = ["address": .hex(0x5000)]
        for (key, value) in extra { fields[key] = value }
        return try run(store, "open-claim", fields)
    }

    private func record(_ store: WorkspaceStore, _ claim: String, _ callee: UInt64, _ outcome: String,
                        reason: String = "checked", bearing: String? = nil) throws -> ScriptValue {
        var fields: [String: ScriptValue] = ["claim": .string(claim), "callee": .hex(callee),
                                             "outcome": .string(outcome), "reason": .string(reason)]
        if let bearing { fields["bearing"] = .string(bearing) }
        return try run(store, "record-callee-outcome", fields)
    }

    private func claimID(_ reply: ScriptValue, file: StaticString = #filePath, line: UInt = #line) throws -> String {
        try XCTUnwrap(reply["claim"]?.stringValue, "reply has no claim: \(reply)", file: file, line: line)
    }

    private func hexes(_ value: ScriptValue?) -> [String] { value?.arrayValue?.compactMap(\.stringValue) ?? [] }

    private func renameHelper(_ store: WorkspaceStore) throws {
        _ = try run(store, "rename", ["address": .hex(0x3000), "name": .string("renamedHelper")])
    }

    /// The minimal witnessing read of `_helper` (slice E): one function-selected `instructions` call.
    private func readHelper(_ store: WorkspaceStore) throws {
        _ = try run(store, "instructions", ["function": .string("_helper")])
    }

    /// The stub 0x7000 and the import 0x7100 are not functions, so no read can witness them and
    /// `record-callee-outcome examined` refuses them. Tests that need an examined external callee on the
    /// ledger (to exercise rebind and `bodyNotDigestible`) append it at the ledger level instead.
    private func seedExaminedExternal(_ store: WorkspaceStore, _ claim: String, _ callee: UInt64,
                                      reason: String, bearing: VACalleeBearing? = nil) throws {
        let id = try XCTUnwrap(UUID(uuidString: claim))
        let box = store.calleeClaimLedgerBox
        let inventory = try XCTUnwrap(box.ledger.events.last { $0.claimID == id && $0.inventory != nil }?.inventory)
        let owner = try XCTUnwrap(store.snapshot.binary(in: .primary)?.id)
        let observed = VACalleeClaimObservation(imageOwner: owner, generation: store.snapshot.analysisGenerationID,
                                                inventory: inventory)
        try box.ledger.recordOutcome(claimID: id, callee: VAAddress64(callee), outcome: .examined, reason: reason,
                                     bearing: bearing, observed: observed, atMilliseconds: 1)
    }

    private func openAndExamineAll(_ store: WorkspaceStore) throws -> String {
        let id = try claimID(try open(store))
        try readHelper(store)
        XCTAssertEqual(try record(store, id, 0x3000, "examined", reason: "read it", bearing: "supports")["ok"], .bool(true))
        for callee: UInt64 in [0x7000, 0x7100] {
            try seedExaminedExternal(store, id, callee, reason: "read it", bearing: .supports)
        }
        return id
    }

    // (a) a rename of an examined callee, then rebind:true, preserves every outcome and records both generations.
    func testRenameOfAnExaminedCalleeThenRebindPreservesEveryOutcome() throws {
        let store = makeStore()
        let id = try openAndExamineAll(store)
        let original = store.snapshot.analysisGenerationID
        XCTAssertEqual(store.calleeClaimLedger.events.count, 4)
        try renameHelper(store)
        let renamed = store.snapshot.analysisGenerationID
        XCTAssertNotEqual(renamed, original)

        let status = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(status["status"], .string("stale"))
        XCTAssertEqual(status["staleKind"], .string("generationAdvanced"))
        XCTAssertEqual(status["rebindable"], .bool(true))

        let reply = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
        XCTAssertEqual(try claimID(reply), id)
        XCTAssertEqual(reply["rebound"], .bool(true))
        XCTAssertEqual(reply["previousGeneration"], .string(original.uuidString))
        XCTAssertEqual(reply["analysisGeneration"], .string(renamed.uuidString))
        XCTAssertEqual(reply["invalidatedCallees"], .array([]))
        XCTAssertEqual(hexes(reply["bodyNotDigestible"]), ["0x7000", "0x7100"],
                       "the stub and the import have no body here; the gap is disclosed, not hidden")
        XCTAssertEqual(reply["status"], .string("closed"))
        XCTAssertEqual(reply["revision"], .int(1))
        XCTAssertEqual(reply["coverage"]?["examined"], .int(3))
        XCTAssertEqual(reply["coverage"]?["open"], .int(0))
        XCTAssertEqual(reply["binding"]?["generation"], .string(renamed.uuidString))
        XCTAssertEqual(reply["generation"], .string(renamed.uuidString))
        XCTAssertEqual(store.snapshot.analysisGenerationID, renamed, "rebind never changes the analysis generation")

        let events = store.calleeClaimLedger.events
        XCTAssertEqual(events.count, 5, "exactly one claimRebound event")
        let last = try XCTUnwrap(events.last)
        XCTAssertEqual(last.kind, .claimRebound)
        XCTAssertEqual(last.previousGeneration, original)
        XCTAssertEqual(last.binding?.analysisGeneration, renamed)
        XCTAssertEqual(last.invalidatedCallees, [])

        // The claim is current again and accepts a new outcome.
        let after = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(after["status"], .string("closed"))
        XCTAssertEqual(after["rebindable"], .bool(false))
        XCTAssertEqual(try record(store, id, 0x3000, "deferred", reason: "later")["ok"], .bool(true))
    }

    // (b) a patched callee body returns only that callee to open and lists it in invalidatedCallees.
    func testPatchedCalleeBodyReturnsOnlyThatCalleeToOpen() throws {
        let store = makeStore()
        let id = try openAndExamineAll(store)
        let original = store.snapshot.analysisGenerationID
        let before = try XCTUnwrap(store.calleeClaimLedger.events.first { $0.callee?.rawValue == 0x3000 }?.bodyDigest)
        // A stored call xref inside _helper's range; the root's own call edges are unchanged.
        store.snapshot.mutateAnalysis(in: .primary) { $0.xrefs.append(call(0x3004, 0x6000)) }
        XCTAssertNotEqual(store.snapshot.analysisGenerationID, original)
        XCTAssertEqual(try run(store, "claim-status", ["claim": .string(id)])["staleKind"], .string("generationAdvanced"))

        let reply = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
        XCTAssertEqual(hexes(reply["invalidatedCallees"]), ["0x3000"])
        XCTAssertEqual(hexes(reply["bodyNotDigestible"]), ["0x7000", "0x7100"])
        XCTAssertEqual(reply["status"], .string("open"))
        XCTAssertEqual(reply["coverage"]?["open"], .int(1))
        XCTAssertEqual(reply["coverage"]?["examined"], .int(2))
        XCTAssertEqual(reply["openCallees"]?.arrayValue?.compactMap { $0["callee"]?.stringValue }, ["0x3000"])
        let last = try XCTUnwrap(store.calleeClaimLedger.events.last)
        XCTAssertEqual(last.kind, .claimRebound)
        XCTAssertEqual(last.invalidatedCallees?.map(\.rawValue), [0x3000])

        // The invalidated callee shows no standing outcome, and its replacement carries the new digest.
        let all = try run(store, "claim-status", ["claim": .string(id), "detail": .string("all")])
        let helper = try XCTUnwrap(all["callees"]?.arrayValue?.first { $0["callee"] == .string("0x3000") })
        XCTAssertEqual(helper["outcome"], .null)
        try readHelper(store)
        let rerecorded = try record(store, id, 0x3000, "examined", reason: "read the patched body")
        XCTAssertEqual(rerecorded["status"], .string("closed"))
        let after = try XCTUnwrap(store.calleeClaimLedger.events.last?.bodyDigest)
        XCTAssertNotEqual(after, before, "the new outcome records the patched body's digest")
        // A second rebind after a further rename keeps the re-examined callee: its digest still matches.
        try renameHelper(store)
        let second = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(second["invalidatedCallees"], .array([]), "\(second)")
        XCTAssertEqual(second["status"], .string("closed"))
    }

    // (c) an external callee, examined, survives rebind and is listed in bodyNotDigestible.
    func testExaminedExternalCalleeSurvivesRebindAndIsListedAsNotDigestible() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        try seedExaminedExternal(store, id, 0x7100, reason: "libc import")
        XCTAssertNil(store.calleeClaimLedger.events.last?.bodyDigest, "an external callee has no body to digest")
        try renameHelper(store)
        let reply = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
        XCTAssertEqual(hexes(reply["bodyNotDigestible"]), ["0x7100"])
        XCTAssertEqual(reply["invalidatedCallees"], .array([]))
        XCTAssertEqual(reply["coverage"]?["examined"], .int(1))
        XCTAssertEqual(reply["coverage"]?["open"], .int(2))
    }

    // (d) a changed root edge set: stale/inventoryChanged with the diff; rebind refused; supersede lists
    // priorOutcomes without satisfying the new revision.
    func testChangedRootEdgesAreInventoryChangedRebindIsRefusedAndSupersedeListsPriorOutcomes() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        _ = try record(store, id, 0x3000, "irrelevant", reason: "a")
        _ = try record(store, id, 0x7000, "deferred", reason: "b")
        try seedExaminedExternal(store, id, 0x7100, reason: "c", bearing: .supports)
        // Add a call to _other and drop the call to the import.
        store.snapshot.mutateAnalysis(in: .primary) { (analysis: inout ImageAnalysis) in
            analysis.xrefs.removeAll { $0.to == 0x7100 }
            analysis.xrefs.append(call(0x5010, 0x6000))
        }
        let events = store.calleeClaimLedger.events.count

        let status = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(status["status"], .string("stale"))
        XCTAssertEqual(status["staleKind"], .string("inventoryChanged"))
        XCTAssertEqual(status["rebindable"], .bool(false))
        XCTAssertEqual(hexes(status["addedCallees"]), ["0x6000"])
        XCTAssertEqual(hexes(status["removedCallees"]), ["0x7100"])
        XCTAssertEqual(status["addedCalleeNames"]?.arrayValue?.first?["name"], .string("_other"))

        let refusedOutcome = try record(store, id, 0x3000, "irrelevant")
        XCTAssertEqual(refusedOutcome["error"], .string("claimStale"))
        XCTAssertEqual(refusedOutcome["rebindable"], .bool(false))
        XCTAssertEqual(hexes(refusedOutcome["addedCallees"]), ["0x6000"])

        let rebind = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(rebind["ok"], .bool(false))
        XCTAssertEqual(rebind["error"], .string("claimStale"))
        XCTAssertEqual(rebind["staleKind"], .string("inventoryChanged"))
        XCTAssertEqual(rebind["rebindable"], .bool(false))
        XCTAssertEqual(hexes(rebind["addedCallees"]), ["0x6000"])
        XCTAssertEqual(hexes(rebind["removedCallees"]), ["0x7100"])
        XCTAssertEqual(store.calleeClaimLedger.events.count, events, "a refused rebind appends no event")

        let next = try open(store, ["supersede": .bool(true)])
        XCTAssertEqual(next["ok"], .bool(true), "\(next)")
        XCTAssertEqual(next["revision"], .int(2))
        XCTAssertEqual(next["superseded"], .bool(true))
        XCTAssertEqual(next["status"], .string("open"))
        XCTAssertEqual(next["coverage"]?["required"], .int(3))
        XCTAssertEqual(next["coverage"]?["open"], .int(3), "prior outcomes never close the new revision")
        let prior = try XCTUnwrap(next["priorOutcomes"]?.arrayValue)
        XCTAssertEqual(prior.compactMap { $0["callee"]?.stringValue }, ["0x3000", "0x7000"],
                       "ascending, and only callees still present (the dropped import is not listed)")
        XCTAssertEqual(prior.map { $0["outcome"] }, [.string("irrelevant"), .string("deferred")])
        XCTAssertEqual(prior.map { $0["reason"] }, [.string("a"), .string("b")])
        XCTAssertTrue(prior.allSatisfy { $0["satisfies"] == .bool(false) })
        XCTAssertTrue(prior.allSatisfy { $0["sequence"]?.intValue != nil })
        XCTAssertTrue(prior.allSatisfy { $0["bearing"] != nil })
    }

    // (e) rebind on a current claim is alreadyCurrent and appends no event.
    func testRebindOnACurrentClaimIsAlreadyCurrentWithNoEvent() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        let before = store.calleeClaimLedger
        let reply = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(reply["ok"], .bool(true))
        XCTAssertEqual(try claimID(reply), id)
        XCTAssertEqual(reply["alreadyCurrent"], .bool(true))
        XCTAssertNil(reply["rebound"])
        XCTAssertEqual(store.calleeClaimLedger, before)
    }

    // A rebind with no claim to rebind is refused and opens nothing.
    func testRebindWithoutAClaimIsRefusedAndOpensNothing() throws {
        let store = makeStore()
        let reply = try open(store, ["rebind": .bool(true)])
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["error"], .string("unknownClaim"))
        XCTAssertTrue(store.calleeClaimLedger.events.isEmpty)
    }

    // VI3-E: open-claim on a function that no longer resolves classifies the existing claim first.
    private func removeRoot(_ store: WorkspaceStore) {
        store.snapshot.mutateAnalysis(in: .primary) { (analysis: inout ImageAnalysis) in
            analysis.functions.removeAll { $0.startAddress == 0x5000 }
        }
    }

    private func assertFunctionGone(_ reply: ScriptValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(reply["ok"], .bool(false), "\(reply)", file: file, line: line)
        XCTAssertEqual(reply["error"], .string("claimStale"), file: file, line: line)
        XCTAssertEqual(reply["staleKind"], .string("functionGone"), file: file, line: line)
        XCTAssertEqual(reply["rebindable"], .bool(false), file: file, line: line)
    }

    func testOpenClaimRebindOnAGoneFunctionIsFunctionGoneAndRecordsNothing() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        removeRoot(store)
        let events = store.calleeClaimLedger.events.count
        let reply = try open(store, ["rebind": .bool(true)])
        assertFunctionGone(reply)
        XCTAssertEqual(reply["claim"], .string(id))
        XCTAssertEqual(store.calleeClaimLedger.events.count, events)
    }

    func testOpenClaimWithNoFlagsOnAGoneFunctionIsFunctionGoneAndRecordsNothing() throws {
        let store = makeStore()
        _ = try open(store)
        removeRoot(store)
        let events = store.calleeClaimLedger.events.count
        assertFunctionGone(try open(store))
        XCTAssertEqual(store.calleeClaimLedger.events.count, events)
    }

    func testOpenClaimSupersedeOnAGoneFunctionIsTheSameRefusalAndRecordsNothing() throws {
        let store = makeStore()
        _ = try open(store)
        removeRoot(store)
        let events = store.calleeClaimLedger.events.count
        assertFunctionGone(try open(store, ["supersede": .bool(true)]))
        XCTAssertEqual(store.calleeClaimLedger.events.count, events)
    }

    func testOpenClaimOnANeverClaimedUnresolvedSelectorKeepsTheCurrentError() throws {
        let store = makeStore()
        _ = try open(store)
        let events = store.calleeClaimLedger.events.count
        func assertUnchanged(file: StaticString = #filePath, line: UInt = #line) {
            // 0x9000 is in no function and was never claimed: today's unknownSubject refusal.
            XCTAssertThrowsError(try run(store, "open-claim", ["address": .hex(0x9000)]), file: file, line: line) { error in
                guard case ScriptingError.structuredRefusal(let refusal) = error, refusal.code == .unknownSubject else {
                    return XCTFail("\(error)", file: file, line: line)
                }
            }
            // A name that matches nothing: today's invalidArgument.
            XCTAssertThrowsError(try run(store, "open-claim", ["function": .string("_nope")]), file: file, line: line) { error in
                guard case ScriptingError.invalidArgument = error else { return XCTFail("\(error)", file: file, line: line) }
            }
            XCTAssertEqual(store.calleeClaimLedger.events.count, events, file: file, line: line)
        }
        assertUnchanged()
        // Removing the claimed function does not change an unrelated selector either.
        removeRoot(store)
        assertUnchanged()
    }

    func testClaimStatusOnAGoneClaimStillReportsFunctionGone() throws {
        let store = makeStore()
        let id = try claimID(try open(store))
        removeRoot(store)
        let events = store.calleeClaimLedger.events.count
        let status = try run(store, "claim-status", ["claim": .string(id)])
        XCTAssertEqual(status["ok"], .bool(true))
        XCTAssertEqual(status["status"], .string("stale"))
        XCTAssertEqual(status["staleKind"], .string("functionGone"))
        XCTAssertEqual(status["rebindable"], .bool(false))
        XCTAssertEqual(store.calleeClaimLedger.events.count, events)
    }

    // (f) rebind together with supersede is a typed invalidArguments refusal.
    func testRebindTogetherWithSupersedeIsRefused() throws {
        let store = makeStore()
        _ = try open(store)
        let before = store.calleeClaimLedger
        let reply = try open(store, ["rebind": .bool(true), "supersede": .bool(true)])
        XCTAssertEqual(reply["ok"], .bool(false))
        XCTAssertEqual(reply["error"], .string("invalidArguments"))
        XCTAssertEqual(store.calleeClaimLedger, before)
    }

    // (g) a basedOnGeneration mismatch on a rebind is staleEvidence and leaves the ledger unchanged.
    func testBasedOnGenerationMismatchOnRebindIsStaleEvidenceAndLeavesTheLedgerUnchanged() throws {
        let store = makeStore()
        _ = try openAndExamineAll(store)
        try renameHelper(store)
        let before = store.calleeClaimLedger
        XCTAssertThrowsError(try open(store, ["rebind": .bool(true), "basedOnGeneration": .string(UUID().uuidString)])) { error in
            guard case ScriptingError.staleEvidence = error else { return XCTFail("expected staleEvidence, got \(error)") }
        }
        XCTAssertEqual(store.calleeClaimLedger, before)
        let current = store.snapshot.analysisGenerationID.uuidString
        let ok = try open(store, ["rebind": .bool(true), "basedOnGeneration": .string(current)])
        XCTAssertEqual(ok["rebound"], .bool(true))
        XCTAssertEqual(store.calleeClaimLedger.events.count, before.events.count + 1)
    }

    // (h) pure functions: a rename leaves bodyDigest and inventoryDigest unchanged; an added call xref
    // inside the callee changes bodyDigest (and not the root's inventoryDigest).
    func testBodyDigestIgnoresNamesAndTracksCallXRefsInsideTheCallee() throws {
        let store = makeStore()
        func read() throws -> CalleeClaimInventorySnapshot {
            try WorkspaceScriptingAPI.calleeClaimInventory(
                arguments: .object(["address": .hex(0x5000)]), snapshot: store.snapshot, checkpoint: {})
        }
        func digest(_ address: UInt64, _ inventory: CalleeClaimInventorySnapshot) throws -> String? {
            let callee = try XCTUnwrap(inventory.callees.first { $0.address == address })
            return try WorkspaceScriptingAPI.calleeBodyDigest(callee: callee, snapshot: store.snapshot)
        }
        let before = try read()
        let helperBefore = try XCTUnwrap(try digest(0x3000, before))
        XCTAssertTrue(VACanonicalJSON.isSHA256(helperBefore))

        try renameHelper(store)
        let renamed = try read()
        XCTAssertEqual(try digest(0x3000, renamed), helperBefore, "a rename is not a body digest input")
        XCTAssertEqual(renamed.inventoryDigest, before.inventoryDigest)

        store.snapshot.mutateAnalysis(in: .primary) { $0.xrefs.append(call(0x3004, 0x6000)) }
        let patched = try read()
        XCTAssertNotEqual(try digest(0x3000, patched), helperBefore, "a call xref inside the callee changes its digest")
        XCTAssertEqual(patched.inventoryDigest, before.inventoryDigest, "the root's own edge set did not change")

        // A call xref outside the callee's range does not.
        store.snapshot.mutateAnalysis(in: .primary) { $0.xrefs.append(call(0x6004, 0x3000)) }
        XCTAssertEqual(try digest(0x3000, try read()), try digest(0x3000, patched))

        // No body in this image: stub symbol and external import.
        XCTAssertNil(try digest(0x7000, patched))
        XCTAssertNil(try digest(0x7100, patched))
    }

    // An interior callee digests its owning function; an unnamed target has no body.
    func testInteriorCalleeUsesTheOwningFunctionAndUnnamedHasNoBody() throws {
        let store = makeStore()
        store.snapshot.mutateAnalysis(in: .primary) { (analysis: inout ImageAnalysis) in
            analysis.xrefs.append(call(0x5010, 0x6010))
            analysis.xrefs.append(call(0x5014, 0x6000))
            analysis.xrefs.append(call(0x5018, 0x8000))
        }
        let read = try WorkspaceScriptingAPI.calleeClaimInventory(
            arguments: .object(["address": .hex(0x5000)]), snapshot: store.snapshot, checkpoint: {})
        func digest(_ address: UInt64) throws -> String? {
            let callee = try XCTUnwrap(read.callees.first { $0.address == address })
            return try WorkspaceScriptingAPI.calleeBodyDigest(callee: callee, snapshot: store.snapshot)
        }
        XCTAssertEqual(read.callees.first { $0.address == 0x6010 }?.kind, .interior)
        XCTAssertEqual(read.callees.first { $0.address == 0x8000 }?.kind, .unnamed)
        let owner = try XCTUnwrap(try digest(0x6000))
        XCTAssertEqual(try digest(0x6010), owner)
        XCTAssertNil(try digest(0x8000))
    }
}
