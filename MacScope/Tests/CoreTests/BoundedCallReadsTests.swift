// Controls for item 1239 (M3 F3 bounded call reads).
// TG Pro acceptance is NOT RUN (no TG Pro binary here; new skips are refused by dev_loop):
//   call-path {from:"0x1001e8440", to:"0x100157d8c"} must return the direct edge;
//   call-graph {root:"0x100157ebc", direction:"callers", depth:1} must return 20 callers.
// project.yml:2312 includes Tests/CoreTests; module/fixture conventions match GraphRowNamesTests.
import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

@MainActor
final class BoundedCallReadsTests: XCTestCase {
    private func function(_ start: UInt64, end: UInt64? = nil, name: String? = nil) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name ?? "f\(start)", startAddress: start,
                        endAddress: end ?? start + 16, confidence: 1)
    }
    private func ref(_ from: UInt64, _ to: UInt64, kind: String = XRefKind.call) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }
    private func snapshot(_ functions: [FunctionSummary], _ refs: [XRef]) -> WorkspaceSnapshot {
        WorkspaceSnapshot(binaries: [], functions: functions, instructions: [], xrefs: refs, hexBytes: Data())
    }
    private func context() -> GraphPageContext {
        GraphPageSession().capture(workspace: UUID(), document: UUID())
    }
    private func pathArgs(_ cursor: ScriptValue? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = ["from": .hex(0x100), "to": .hex(0x200), "maxDepth": .int(2)]
        if let cursor { fields["cursor"] = cursor }
        return .object(fields)
    }
    private func read(_ args: ScriptValue, _ snapshot: WorkspaceSnapshot, _ context: GraphPageContext,
                      visits: Int = 100_000, autoVisits: Int? = nil,
                      checkpoint: () throws -> Void = {}) throws -> ScriptValue {
        // Existing controls pin the pre-auto-continue behaviour: the cap equals the quantum.
        try WorkspaceScriptingAPI.boundedCallRead("call-path", arguments: args, snapshot: snapshot,
            context: context, visitLimit: visits, autoContinueVisitLimit: autoVisits ?? visits,
            checkpoint: checkpoint)
    }

    private func graphArgs(_ cursor: ScriptValue? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = ["root": .hex(0x100), "depth": .int(1), "direction": .string("callees")]
        if let cursor { fields["cursor"] = cursor }
        return .object(fields)
    }
    private func graph(_ args: ScriptValue, _ snapshot: WorkspaceSnapshot, _ context: GraphPageContext,
                       visits: Int, autoVisits: Int? = nil) throws -> ScriptValue {
        if let autoVisits {
            return try WorkspaceScriptingAPI.boundedCallRead("call-graph", arguments: args, snapshot: snapshot,
                context: context, visitLimit: visits, autoContinueVisitLimit: autoVisits, checkpoint: {})
        }
        return try WorkspaceScriptingAPI.boundedCallRead("call-graph", arguments: args, snapshot: snapshot,
            context: context, visitLimit: visits, checkpoint: {})
    }
    private func manyUnrelatedThenEdge() -> WorkspaceSnapshot {
        var refs: [XRef] = (0..<20).map { ref(0x900 + UInt64($0), 0x900) }
        refs.append(ref(0x101, 0x200))
        return snapshot([function(0x100), function(0x200), function(0x900)], refs)
    }

    func testAutoContinueFirstReplyHasEdgeWhenQuantumIsSmall() throws {
        let s = manyUnrelatedThenEdge()
        let g = try graph(graphArgs(), s, context(), visits: 5)
        XCTAssertEqual(g["edges"]?.arrayValue?.count, 1)
        XCTAssertEqual(g["isTruncated"], .bool(false))
        let p = try read(pathArgs(), s, context(), visits: 5, autoVisits: 4_000_000)
        XCTAssertEqual(p["witnessExists"], .bool(true))
        XCTAssertEqual(p["edges"]?.arrayValue?.count, 1)
    }

    func testAutoContinueCallPathFirstReplyHasWitnessSeveralHopsAway() throws {
        var refs: [XRef] = (0..<20).map { ref(0x900 + UInt64($0), 0x900) }
        refs += [ref(0x101, 0x200), ref(0x201, 0x300), ref(0x301, 0x400)]
        let s = snapshot([function(0x100), function(0x200), function(0x300), function(0x400), function(0x900)], refs)
        let args: ScriptValue = .object(["from": .hex(0x100), "to": .hex(0x400), "maxDepth": .int(4)])
        let first = try read(args, s, context(), visits: 5, autoVisits: 4_000_000)
        XCTAssertEqual(first["witnessExists"], .bool(true))
        XCTAssertEqual(first["edges"]?.arrayValue?.count, 3)
    }

    func testAutoContinueCapReturnsEmptyPartialPageWithUsableCursor() throws {
        let s = manyUnrelatedThenEdge()
        let c = context()
        // Cap 10 total visits < the 20 unrelated xrefs: reply is the empty partial page.
        let first = try graph(graphArgs(), s, c, visits: 5, autoVisits: 10)
        XCTAssertEqual(first["edges"], .array([]))
        XCTAssertEqual(first["isTruncated"], .bool(true))
        var cursor = try XCTUnwrap(first["nextCursor"])
        XCTAssertNotEqual(cursor, .null)
        var rows = 0, pages = 0
        while cursor != .null, pages < 20 {
            let next = try graph(graphArgs(cursor), s, c, visits: 5, autoVisits: 10)
            rows += next["edges"]?.arrayValue?.count ?? 0
            cursor = next["nextCursor"] ?? .null
            pages += 1
        }
        XCTAssertEqual(rows, 1)  // same row as the auto-continued single reply
        XCTAssertEqual(cursor, .null)
    }

    func testWitnessDoesNotHideLaterPartialTerminal() throws {
        let s = snapshot([function(0x100), function(0x200), function(0x300)],
                         [ref(0x101, 0x200), ref(0x201, 0x300)])
        let c = context()
        let partial = try read(pathArgs(), s, c, visits: 4)
        XCTAssertEqual(partial["witnessExists"], .bool(true))
        XCTAssertEqual(partial["sourceComplete"], .null)
        XCTAssertEqual(partial["completeWithinScope"], .bool(false))
        XCTAssertEqual(partial["shortestHopProven"], .bool(false))
        let cursor = try XCTUnwrap(partial["nextCursor"])
        XCTAssertNotEqual(cursor, .null)
        let terminal = try read(pathArgs(cursor), s, c)
        XCTAssertEqual(terminal["witnessExists"], .bool(true))
        XCTAssertEqual(terminal["completeWithinScope"], .bool(true))
        XCTAssertEqual(terminal["shortestHopProven"], .bool(true))
        XCTAssertEqual(terminal["sourceComplete"], .null)
    }

    func testIncompleteEmptyFirstPageReportsUnknownWitness() throws {
        // Many unrelated raw xrefs precede the direct edge, so a small visit quantum is spent
        // scanning on page 1 (the TG Pro shape): no edge yet, absence is unproven.
        var refs: [XRef] = (0..<20).map { ref(0x900 + UInt64($0), 0x900) }
        refs.append(ref(0x101, 0x200))
        let s = snapshot([function(0x100), function(0x200), function(0x900)], refs)
        let c = context()
        let first = try read(pathArgs(), s, c, visits: 5)
        XCTAssertEqual(first["edges"]?.arrayValue?.count, 0)
        XCTAssertEqual(first["isTruncated"], .bool(true))
        XCTAssertEqual(first["witnessExists"], .null)
        XCTAssertEqual(first["incompleteReason"], .string("resumeNextCursor"))
        var cursor = try XCTUnwrap(first["nextCursor"])
        var last = first
        for _ in 0..<20 where cursor != .null {
            last = try read(pathArgs(cursor), s, c, visits: 5)
            cursor = last["nextCursor"] ?? .null
        }
        XCTAssertEqual(last["witnessExists"], .bool(true))
        XCTAssertEqual(last["edges"]?.arrayValue?.count, 1)
        XCTAssertEqual(last["incompleteReason"], .null)
        let none = try read(.object(["from": .hex(0x200), "to": .hex(0x100), "maxDepth": .int(2)]), s, context())
        XCTAssertEqual(none["witnessExists"], .bool(false))
        XCTAssertEqual(none["incompleteReason"], .null)
    }

    func testAscendingNeighbourTieIgnoresRawInsertionOrder() throws {
        let f = [function(0x100), function(0x200), function(0x300), function(0x400)]
        let refs = [ref(0x102, 0x300), ref(0x101, 0x200), ref(0x301, 0x400), ref(0x201, 0x400)]
        let args: ScriptValue = .object(["from": .hex(0x100), "to": .hex(0x400), "maxDepth": .int(2)])
        let a = try read(args, snapshot(f, refs), context())
        let b = try read(args, snapshot(f, Array(refs.reversed())), context())
        XCTAssertEqual(a["edges"], b["edges"])
        XCTAssertEqual(a["edges"]?.arrayValue?.first?["callee"], .hex(0x200))
    }

    func testRawPolicyIgnoresManualEditsAndTheirNonGeneration() throws {
        var s = snapshot([function(0x100), function(0x200)], [ref(0x101, 0x200)])
        let generation = s.analysisGenerationID
        s.manualXRefs = [ManualXRef(from: 0x101, to: 0x200, kind: XRefKind.call, isSuppression: true)]
        XCTAssertEqual(s.analysisGenerationID, generation)
        let result = try read(pathArgs(), s, context())
        XCTAssertEqual(result["edgePolicy"], .string("rawExplicitCalls"))
        XCTAssertEqual(result["witnessExists"], .bool(true))
    }

    func testAnalysisChangeStalesContinuation() throws {
        var s = snapshot([function(0x100), function(0x200)], [ref(0x101, 0x200)])
        let c = context()
        let first = try read(pathArgs(), s, c, visits: 1)
        let cursor = try XCTUnwrap(first["nextCursor"])
        s.xrefs.append(ref(0x102, 0x200))
        XCTAssertThrowsError(try read(pathArgs(cursor), s, c)) { error in
            XCTAssertTrue(error.localizedDescription.contains("staleCursor"))
        }
    }

    func testEpochAndDocumentAreBoundToCursor() throws {
        let s = snapshot([function(0x100), function(0x200)], [ref(0x101, 0x200)])
        let c = context()
        let cursor = try XCTUnwrap(try read(pathArgs(), s, c, visits: 1)["nextCursor"])
        let other = c.session.capture(workspace: c.workspace, document: UUID())
        XCTAssertThrowsError(try read(pathArgs(cursor), s, other))
        c.session.invalidate()
        XCTAssertThrowsError(try read(pathArgs(cursor), s, c))
    }

    func testRefusalAndCancellationLeaveInputReplayable() throws {
        let s = snapshot([function(0x100), function(0x200)], [ref(0x101, 0x200)])
        let c = context()
        let cursor = try XCTUnwrap(try read(pathArgs(), s, c, visits: 1)["nextCursor"])
        var checkpoints = 0
        XCTAssertThrowsError(try read(pathArgs(cursor), s, c, checkpoint: {
            checkpoints += 1
            // Initial checkpoint + warm-index checkpoint + loop + pending emission.
            // The fourth occurs after begin has leased the resumed state.
            if checkpoints == 4 { throw CancellationError() }
        }))
        XCTAssertEqual(checkpoints, 4)
        XCTAssertEqual(try read(pathArgs(cursor), s, c)["witnessExists"], .bool(true))
    }

    func testStrictArgumentsAndMCPExposure() throws {
        for invalid: ScriptValue in [.object(["root": .hex(0x100), "depth": .double(1)]),
                                     .object(["root": .hex(0x100), "direction": .string("both")]),
                                     .object(["root": .hex(0x100), "limit": .int(0)]),
                                     .object(["root": .hex(0x100), "cursor": .null]),
                                     .object(["root": .string("0x10000000000000000")])] {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedCallOptions("call-graph", invalid))
        }
        let commands = Set(HeadlessAutomationAuthority.availableCommands.map(\.name))
        XCTAssertTrue(commands.contains("call-graph")); XCTAssertTrue(commands.contains("call-path"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("call-graph"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("call-path"))
    }

    func testAdjacencyCapIsTypedRefusal() throws {
        let f = [function(0x100, end: 0x3000), function(0x4000)]
        let refs = (0...4096).map { ref(UInt64(0x101 + $0), 0x4000) }
        XCTAssertThrowsError(try read(.object(["from": .hex(0x100), "to": .hex(0x4000)]),
                                       snapshot(f, refs), context())) { error in
            guard let failure = error as? ScriptingError, case .structuredRefusal(let refusal) = failure else {
                XCTFail("expected typed budget refusal"); return
            }
            XCTAssertEqual(refusal.code, .budgetExceeded)
        }
    }

    func testTotalNodeCapAcrossContinuationsIsTypedRefusal() throws {
        let targets = (0..<1024).map { UInt64(0x20000 + $0 * 16) }
        let functions = [function(0x100, end: 0x10000)] + targets.map { function($0) }
        let refs = targets.enumerated().map { ref(UInt64(0x101 + $0.offset), $0.element) }
        let s = snapshot(functions, refs), c = context()
        var args: [String: ScriptValue] = ["root": .hex(0x100), "depth": .int(1)]
        var refused = false
        for _ in 0..<11 {
            do {
                let value = try WorkspaceScriptingAPI.boundedCallRead("call-graph", arguments: .object(args),
                    snapshot: s, context: c, checkpoint: {})
                args["cursor"] = value["nextCursor"]
            } catch ScriptingError.structuredRefusal(let failure) {
                XCTAssertEqual(failure.code, .budgetExceeded)
                XCTAssertTrue(failure.detail.contains("node cap")); refused = true; break
            }
        }
        XCTAssertTrue(refused)
    }

    func testExplicitSiblingSlotAndPrimaryDefaultDoNotMixSameAddresses() throws {
        let sibling = ImageSlot(rawValue: 1)
        let primary = BinaryImage(id: UUID(), name: "primary", path: "", kind: "fixture", architecture: "arm64")
        let other = BinaryImage(id: UUID(), name: "other", path: "", kind: "fixture", architecture: "arm64", slot: sibling)
        var a = ImageAnalysis(), b = ImageAnalysis()
        a.functions = [function(0x100, name: "primaryA"), function(0x200, name: "primaryB")]
        b.functions = [function(0x100, name: "siblingA"), function(0x200, name: "siblingB")]
        a.xrefs = [ref(0x101, 0x200)]; b.xrefs = []
        let s = WorkspaceSnapshot(binaries: [primary, other], analysisBySlot: [.primary: a, sibling: b])
        let defaultResult = try read(pathArgs(), s, context())
        let explicitArgs: ScriptValue = .object(["from": .hex(0x100), "to": .hex(0x200), "imageSlot": .int(1)])
        let explicitResult = try read(explicitArgs, s, context())
        XCTAssertEqual(defaultResult["witnessExists"], .bool(true))
        XCTAssertEqual(defaultResult["imageSlot"], .int(0))
        XCTAssertEqual(explicitResult["witnessExists"], .bool(false))
        XCTAssertEqual(explicitResult["imageSlot"], .int(1))
        XCTAssertEqual(explicitResult["nodes"]?.arrayValue?.first?["name"], .string("siblingA"))
    }

    func testFinalOuterFrameRefusalDoesNotConsumeTraversalInput() throws {
        let long = String(repeating: "quoted\\\"\\\\name", count: 200)
        let s = snapshot([function(0x100, name: long), function(0x200, name: long), function(0x300)],
                         [ref(0x101, 0x200), ref(0x201, 0x300)])
        let c = context()
        let input = try XCTUnwrap(try read(pathArgs(), s, c, visits: 1)["nextCursor"])
        let output = try read(pathArgs(input), s, c, visits: 4)
        let text = String(decoding: try output.jsonData(), as: UTF8.self)
        let response: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
            "result": .object(["content": .array([.object(["type": .string("text"), "text": .string(text)])]),
                               "isError": .bool(false)])])
        let serialized = try response.jsonData()
        XCTAssertGreaterThan(serialized.count, 512)
        let id = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(Data("1".utf8), limits: .providerEnvelope)
        let frame = try MCPFrameAdmission.response(serialized, id: id, maximumBytes: 512,
            failureMessage: "Response exceeds limit", compactMessage: "")
        XCTAssertLessThanOrEqual(frame.count, 512)
        XCTAssertTrue(MCPFrameAdmission.fits(frame, maximumBytes: 512))
        XCTAssertNotEqual(frame, serialized)
        // This directly authors the pin's final-frame boundary; it is not a full
        // MCPServer integration test. The normal inner half-limit can refuse earlier.
        XCTAssertEqual(try read(pathArgs(input), s, c)["witnessExists"], .bool(true))
    }

    func testEmptyPartialGraphPageAndCursorReassembly() throws {
        let s = snapshot([function(0x100), function(0x200)],
                         [ref(0x101, 0x200, kind: XRefKind.data), ref(0x102, 0x200)])
        let c = context()
        var args: [String: ScriptValue] = ["root": .hex(0x100), "depth": .int(1), "direction": .string("callees")]
        let first = try WorkspaceScriptingAPI.boundedCallRead("call-graph", arguments: .object(args),
            snapshot: s, context: c, visitLimit: 1, autoContinueVisitLimit: 1, checkpoint: {})
        XCTAssertEqual(first["edges"], .array([])); XCTAssertEqual(first["isTruncated"], .bool(true))
        args["cursor"] = try XCTUnwrap(first["nextCursor"])
        let last = try WorkspaceScriptingAPI.boundedCallRead("call-graph", arguments: .object(args),
            snapshot: s, context: c, checkpoint: {})
        XCTAssertEqual(last["edges"]?.arrayValue?.count, 1)
        XCTAssertEqual(last["nextCursor"], .null)
        XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(last), 131_072)
    }

    func testS1NameRefusalIsNotEmptySuccess() throws {
        let s = snapshot([function(0x100, name: String(repeating: "x", count: 8193)), function(0x200)],
                         [ref(0x101, 0x200)])
        XCTAssertThrowsError(try read(pathArgs(), s, context())) { error in
            guard let failure = error as? ScriptingError, case .structuredRefusal(let refusal) = failure else {
                XCTFail("expected reused S1 name refusal"); return
            }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertTrue(refusal.detail.contains("Graph name enrichment refused"))
        }
    }

    func testFullWitnessByteRefusalIsNotFixedByLimitAlone() throws {
        let addresses = (0...16).map { UInt64(0x100 + $0 * 16) }
        let name = String(repeating: "q", count: 8192)
        let s = snapshot(addresses.map { function($0, name: name) },
            (0..<16).map { ref(addresses[$0] + 1, addresses[$0 + 1]) })
        let c = context()
        var args: [String: ScriptValue] = ["from": .hex(0x100), "to": .hex(0x200), "maxDepth": .int(16)]
        let first = try read(.object(args), s, c, visits: 1)
        args["cursor"] = try XCTUnwrap(first["nextCursor"])
        XCTAssertThrowsError(try read(.object(args), s, c)) { error in
            guard let failure = error as? ScriptingError, case .structuredRefusal(let refusal) = failure else {
                XCTFail("expected witness byte refusal"); return
            }
            XCTAssertTrue(refusal.detail.contains("limit does not shrink a witness"))
        }
        // Input remains available after the refusal. A one-edge work page delays
        // discovery, but does not promise the eventual full witness will fit.
        args["limit"] = .int(1)
        XCTAssertEqual(try read(.object(args), s, c)["isTruncated"], .bool(true))
    }

    func testNewCommandsThroughInlineAsyncAttachedAndMCPPreserveLegacyArrays() async throws {
        let s = snapshot([function(0x100), function(0x200)], [ref(0x101, 0x200)])
        let store = WorkspaceStore(workspaceName: "bounded calls", snapshot: s,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        let args: ScriptValue = .object(["from": .hex(0x100), "to": .hex(0x200), "maxDepth": .int(1)])
        XCTAssertEqual(try api.execute("call-path", arguments: args)["witnessExists"], .bool(true))
        let asynchronousResult = try await api.executeAsync("call-path", arguments: args)
        XCTAssertEqual(asynchronousResult["witnessExists"], .bool(true))
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        let attachedResult = try await attached.execute("call-path", args)
        XCTAssertEqual(attachedResult["witnessExists"], .bool(true))
        for asynchronous in [false, true] {
            let server = MCPServer(api: api)
            let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
                "method": .string("tools/call"), "params": .object(["name": .string("call-path"), "arguments": args])])
            let bytes = try request.jsonData()
            let response: Data?
            if asynchronous { response = await server.handleMessageAsync(bytes) }
            else { response = server.handleMessage(bytes) }
            let reply = try ScriptValue.decode(try XCTUnwrap(response))
            XCTAssertNil(reply["error"]); XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(text.utf8))["witnessExists"], .bool(true))
        }
        let legacy = try api.execute("callers", arguments: .object(["address": .hex(0x200)]))
        XCTAssertEqual(legacy.arrayValue?.count, 1)
        let graph = try api.execute("call-graph", arguments: .object([
            "root": .hex(0x200), "depth": .int(1), "direction": .string("callers")]))
        XCTAssertEqual(graph["edges"]?.arrayValue?.count, 1)
        XCTAssertEqual(store.snapshot.analysisGenerationID, s.analysisGenerationID)
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testMCPInnerRefusalPreservesTraversalInputAcrossSyncAndAsync() async throws {
        let long = String(repeating: "quoted\\\"", count: 100)
        let s = snapshot([function(0x100, name: long), function(0x200, name: long)], [ref(0x101, 0x200)])
        let store = WorkspaceStore(workspaceName: "bounded envelope", snapshot: s,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        let c = store.graphPageContext
        let input = try XCTUnwrap(try read(pathArgs(), s, c, visits: 1)["nextCursor"])
        let configuration = MCPServer.Configuration(maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8)
        for asynchronous in [false, true] {
            let server = MCPServer(api: api, configuration: configuration)
            let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
                "method": .string("tools/call"), "params": .object([
                    "name": .string("call-path"), "arguments": pathArgs(input)])])
            let bytes = try request.jsonData()
            let response: Data?
            if asynchronous { response = await server.handleMessageAsync(bytes) }
            else { response = server.handleMessage(bytes) }
            let frame = try XCTUnwrap(response)
            XCTAssertTrue(MCPFrameAdmission.fits(frame, maximumBytes: 512))
            let reply = try ScriptValue.decode(frame)
            XCTAssertEqual(reply["error"]?["code"], .int(-32603))
            XCTAssertEqual(reply["error"]?["message"], .string("Response exceeds limit"))
            XCTAssertEqual(try read(pathArgs(input), s, c)["witnessExists"], .bool(true))
        }
    }
}
