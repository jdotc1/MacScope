import Darwin
import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

@MainActor
final class MCPServerTests: XCTestCase {
    func testVI2EveryReadShapeCarriesModelVisibleGenerationWithoutChangingFirstPayload() async throws {
        for asynchronous in [false, true] {
            let (server, store) = makeServer()
            let api = WorkspaceScriptingAPI(store: store)
            let generation = store.snapshot.analysisGenerationID
            let cases: [(String, ScriptValue)] = [
                ("info", .object([:])),
                ("functions", .object(["limit": .int(0)])), // Empty array still has a generation.
                ("instructions", .object(["function": .string("_main")])),
                ("name-at", .object(["address": .hex(0x1000)])), // Bare string stays a string.
                ("basic-blocks", .object(["function": .string("_main")])),
            ]
            for (command, arguments) in cases {
                let expected = try api.execute(command, arguments: arguments)
                let reply = try await p2Reply(server, "tools/call", params: .object([
                    "name": .string(command), "arguments": arguments]), asynchronous: asynchronous)
                let result = try XCTUnwrap(reply["result"])
                XCTAssertEqual(result["isError"], .bool(false), command)
                XCTAssertEqual(result["_meta"]?["generation"], .string(generation.uuidString), command)
                let blocks = try XCTUnwrap(result["content"]?.arrayValue)
                let first = try XCTUnwrap(blocks.first?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(first.utf8)), expected, command)
                let last = try XCTUnwrap(blocks.last?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(last.utf8)),
                    .object(["generation": .string(generation.uuidString)]), command)
            }
            XCTAssertEqual(store.snapshot.analysisGenerationID, generation)
        }
    }

    func testVI2SyncAndAsyncMCPReturnTypedStaleEvidenceWithBothGenerations() async throws {
        for asynchronous in [false, true] {
            let (server, store) = makeServer()
            let initial = store.snapshot.analysisGenerationID
            let params: ScriptValue = .object(["name": .string("rename"), "arguments": .object([
                "address": .hex(0x1000), "name": .string("vi2"),
                "basedOnGeneration": .string(initial.uuidString)])])
            let success = try await p2Reply(server, "tools/call", params: params, asynchronous: asynchronous)
            XCTAssertEqual(success["result"]?["isError"], .bool(false))
            let next = store.snapshot.analysisGenerationID
            XCTAssertNotEqual(next, initial)
            XCTAssertEqual(success["result"]?["_meta"]?["generation"], .string(next.uuidString))
            let successText = try XCTUnwrap(success["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(successText.utf8))["generation"], .string(next.uuidString))
            let before = store.snapshot.addressOverrides
            let undo = store.undoManager.undoActionName
            let stale = try await p2Reply(server, "tools/call", params: params, asynchronous: asynchronous)
            XCTAssertNil(stale["error"], "A stale write is a typed tool refusal, not a JSON-RPC failure")
            XCTAssertEqual(stale["result"]?["isError"], .bool(true))
            let text = try XCTUnwrap(stale["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), .object([
                "error": .string("staleEvidence"), "basedOnGeneration": .string(initial.uuidString),
                "currentGeneration": .string(next.uuidString)]))
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            XCTAssertEqual(store.snapshot.analysisGenerationID, next)
            XCTAssertEqual(store.undoManager.undoActionName, undo)
            let chained = try await p2Reply(server, "tools/call", params: .object([
                "name": .string("set-comment"), "arguments": .object([
                    "address": .hex(0x1000), "comment": .string("fresh"),
                    "basedOnGeneration": .string(next.uuidString)])]), asynchronous: asynchronous)
            XCTAssertEqual(chained["result"]?["isError"], .bool(false))
            XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.customComment, "fresh")
            XCTAssertEqual(chained["result"]?["_meta"]?["generation"],
                .string(store.snapshot.analysisGenerationID.uuidString))
        }
    }

    func testVI2DetachedListAndHeavyReadKeepTheGenerationOfTheirCapturedSnapshot() async throws {
        for command in ["functions", "decompile"] {
            let (_, store) = makeServer()
            let gate = SnapshotReadCheckpointGate(holdAt: 1)
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store,
                snapshotReadCheckpoint: { gate.checkpoint() }))
            let captured = store.snapshot.analysisGenerationID
            let arguments: ScriptValue = command == "functions" ? .object([:]) : .object(["function": .string("_main")])
            let data = try request("tools/call", params: .object([
                "name": .string(command), "arguments": arguments])).jsonData()
            let operation = Task { @MainActor in await server.handleMessageAsync(data) }
            defer { gate.open() }
            try await gate.waitUntilHeld()
            store.setCustomName(0x1000, in: .primary, name: "new-live-name")
            let current = store.snapshot.analysisGenerationID
            XCTAssertNotEqual(current, captured)
            gate.open()
            let returned = await operation.value
            let responseData = try XCTUnwrap(returned)
            let reply = try ScriptValue.decode(responseData)
            XCTAssertEqual(reply["result"]?["_meta"]?["generation"], .string(captured.uuidString), command)
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let payload = try ScriptValue.decode(Data(text.utf8))
            if command == "functions" { XCTAssertEqual(payload.arrayValue?.first?["name"], .string("_main")) }
            else { XCTAssertEqual(payload["function"], .string("_main")) }
            let refused = try await p2Reply(server, "tools/call", params: .object([
                "name": .string("set-comment"), "arguments": .object([
                    "address": .hex(0x1000), "comment": .string("must not apply"),
                    "basedOnGeneration": .string(captured.uuidString)])]), asynchronous: true)
            let refusalText = try XCTUnwrap(refused["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let refusal = try ScriptValue.decode(Data(refusalText.utf8))
            XCTAssertEqual(refusal["error"], .string("staleEvidence"))
            XCTAssertEqual(refusal["basedOnGeneration"], .string(captured.uuidString))
            XCTAssertEqual(refusal["currentGeneration"], .string(current.uuidString))
            XCTAssertNil(store.snapshot.addressOverrides[.primary(0x1000)]?.customComment)
        }
    }

    func testVI2StaleMCPWritesNeverStartMutationOutcomes() async throws {
        for asynchronous in [false, true] {
            for command in ["rename", "set-comment", "set-tags", "navigator-revert"] {
                let (server, store) = makeServer()
                let current = store.snapshot.analysisGenerationID, stale = UUID()
                var fields: [String: ScriptValue]
                switch command {
                case "rename": fields = ["address": .hex(0x1000), "name": .string("stale")]
                case "set-comment": fields = ["address": .hex(0x1000), "comment": .string("stale")]
                case "set-tags": fields = ["entries": .array([
                    .object(["address": .hex(0x1000), "tag": .string("stale")])])]
                default: fields = ["imageSlot": .int(0), "id": .string("fact"), "session": .string("vi2")]
                }
                fields["basedOnGeneration"] = .string(stale.uuidString)
                let outcome = MCPMutationOutcome()
                let reply = try await MCPExecutionFence.$outcome.withValue(outcome) {
                    try await p2Call(server, command, .object(fields), asynchronous: asynchronous)
                }
                XCTAssertEqual(reply["result"]?["isError"], .bool(true), command)
                let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), .object([
                    "error": .string("staleEvidence"), "basedOnGeneration": .string(stale.uuidString),
                    "currentGeneration": .string(current.uuidString)]), command)
                XCTAssertEqual(outcome.snapshot, .notStarted, command)
                XCTAssertNil(outcome.batchReceipt, command)
                XCTAssertTrue(store.snapshot.addressOverrides.isEmpty, command)
                XCTAssertEqual(store.snapshot.analysisGenerationID, current, command)
                XCTAssertFalse(store.undoManager.canUndo, command)
            }
        }
    }

    func testVI2AttachedDetachedReadsKeepCapturedGenerationAndRejectItsStaleWrite() async throws {
        for command in ["functions", "decompile"] {
            let (_, store) = makeServer()
            let gate = SnapshotReadCheckpointGate(holdAt: 1)
            let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { gate.checkpoint() })
            let executor = MCPAttachExecutor(store: store, api: { _ in api })
            executor.setConsent(.allowed)
            let server = MCPServer(api: api, configuration: .attached,
                asyncCommandExecutor: { try await executor.execute($0, $1) },
                allowedCommands: MCPAttachExecutor.attachCommands)
            let captured = store.snapshot.analysisGenerationID
            let arguments: ScriptValue = command == "functions" ? .object([:]) : .object(["function": .string("_main")])
            let data = try request("tools/call", params: .object([
                "name": .string(command), "arguments": arguments])).jsonData()
            let operation = Task { @MainActor in await server.handleMessageAsync(data) }
            defer { gate.open() }
            try await gate.waitUntilHeld()
            store.setCustomName(0x1000, in: .primary, name: "new-live-name")
            let current = store.snapshot.analysisGenerationID
            XCTAssertNotEqual(current, captured)
            gate.open()
            let returned = await operation.value
            let reply = try ScriptValue.decode(try XCTUnwrap(returned))
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            XCTAssertEqual(reply["result"]?["_meta"]?["generation"], .string(captured.uuidString))
            let blocks = try XCTUnwrap(reply["result"]?["content"]?.arrayValue)
            let generationText = try XCTUnwrap(blocks.last?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(generationText.utf8)),
                .object(["generation": .string(captured.uuidString)]))
            let payloadText = try XCTUnwrap(blocks.first?["text"]?.stringValue)
            let payload = try ScriptValue.decode(Data(payloadText.utf8))
            if command == "functions" { XCTAssertEqual(payload.arrayValue?.first?["name"], .string("_main")) }
            else { XCTAssertEqual(payload["function"], .string("_main")) }
            let outcome = MCPMutationOutcome()
            let refused = try await MCPExecutionFence.$outcome.withValue(outcome) {
                try await p2Call(server, "set-comment", .object([
                    "address": .hex(0x1000), "comment": .string("must not apply"),
                    "basedOnGeneration": .string(captured.uuidString)]), asynchronous: true)
            }
            let text = try XCTUnwrap(refused["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), .object([
                "error": .string("staleEvidence"), "basedOnGeneration": .string(captured.uuidString),
                "currentGeneration": .string(current.uuidString)]))
            XCTAssertEqual(outcome.snapshot, .notStarted)
            XCTAssertNil(outcome.batchReceipt)
            XCTAssertNil(store.snapshot.addressOverrides[.primary(0x1000)]?.customComment)
            XCTAssertEqual(store.undoManager.groupingLevel, 0)
        }
    }

    func testVI2GenerationBlockFollowsLegacyPayloadAndDispatchNote() throws {
        let capture = ScriptingGenerationCapture(), generation = UUID()
        let payload: ScriptValue = .object(["type": .string("text"), "text": .string("[]")])
        let note: ScriptValue = .object(["type": .string("text"), "text": .string("{\"note\":{}}")])
        XCTAssertEqual(capture.appendingGeneration(to: [payload, note]), [payload, note])
        capture.record(generation)
        let blocks = capture.appendingGeneration(to: [payload, note])
        XCTAssertEqual(blocks.count, 3)
        XCTAssertEqual(Array(blocks.prefix(2)), [payload, note])
        XCTAssertEqual(blocks[2]["type"], .string("text"))
        let text = try XCTUnwrap(blocks[2]["text"]?.stringValue)
        XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), capture.metadata)
        XCTAssertEqual(MCPServer.protocolVersion, "2024-11-05")
    }

    func testAnnotationGapsCatalogIsReadOnlyAndArgumentFree() throws {
        let (server, _) = makeServer()
        let tools = try XCTUnwrap(server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue)
        let matches = tools.filter { $0["name"] == .string("annotation-gaps") }
        XCTAssertEqual(matches.count, 1)
        let tool = try XCTUnwrap(matches.first)
        XCTAssertEqual(tool["annotations"]?["readOnlyHint"], .bool(true))
        XCTAssertEqual(tool["annotations"]?["destructiveHint"], .bool(false))
        XCTAssertEqual(tool["inputSchema"]?["properties"], .object([:]))
        XCTAssertEqual(tool["inputSchema"]?["additionalProperties"], .bool(false))
        XCTAssertNil(tool["inputSchema"]?["required"])
        let info = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "annotation-gaps" })
        XCTAssertFalse(info.mutates)
        XCTAssertEqual(info.arguments, [])
        XCTAssertTrue(HeadlessAutomationAuthority.availableCommands.contains(info))
    }

    func testAnnotationGapsMCPDispatchMatchesAPIWithoutMutation() async throws {
        let (server, store) = makeServer()
        store.setCustomName(0x1000, in: .primary, name: "needsComment")
        let api = WorkspaceScriptingAPI(store: store)
        let expected = try api.execute("annotation-gaps")
        let before = store.snapshot
        let selection = store.selectedImageAddress
        let undo = store.undoManager.canUndo
        let call = request("tools/call", params: .object([
            "name": .string("annotation-gaps"), "arguments": .object([:]),
        ]))
        let synchronous = try XCTUnwrap(server.handle(call))
        let asyncBytes = try await server.handleMessageAsync(call.jsonData())
        let asynchronous = try ScriptValue.decode(try XCTUnwrap(asyncBytes))
        for envelope in [synchronous, asynchronous] {
            XCTAssertNil(envelope["error"])
            XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), expected)
        }
        XCTAssertEqual(store.snapshot.analysisGenerationID, before.analysisGenerationID)
        XCTAssertEqual(store.snapshot.addressOverrides, before.addressOverrides)
        XCTAssertEqual(store.snapshot.typeDefinitions, before.typeDefinitions)
        XCTAssertEqual(store.selectedImageAddress, selection)
        XCTAssertEqual(store.undoManager.canUndo, undo)
    }

    func testRepresentableBatchRefusalPreservesIDAndConnectionAcrossRoutes() async throws {
        let (_, store) = makeServer()
        let configuration = MCPServer.Configuration(maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8)
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: configuration)
        let id = MacScopeAnalysisCore.Phase2ProductionJSONValue.string(String(repeating: "\\", count: 200))
        let request = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": id, "method": .string("tools/call"),
            "params": .object(["name": .string("set-local-labels"), "arguments": .object([:])])
        ]).canonicalJSONBytes()
        let sync = try XCTUnwrap(server.handleMessage(request))
        let syncFields = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(sync).objectValue
        XCTAssertEqual(syncFields?["id"], id)
        XCTAssertEqual(syncFields?["error"]?.objectValue?["message"], .string("Batch not run; shorten ID."))
        XCTAssertLessThan(sync.count, 512)
        XCTAssertNotNil(server.handleMessage(Data(#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#.utf8)))
        let calls = MCPAsyncTestOutput(), output = MCPAsyncTestOutput()
        let fence = MCPConnectionFence()
        let session = MCPRequestSession(configuration: configuration, mutatingCommands: MCPBatchReceiptBudget.commands,
            execute: { data in await calls.append(data); return nil }, output: { await output.append($0) }, fence: fence)
        await session.receive(request)
        let frames = await output.values
        let callCount = await calls.count
        XCTAssertEqual(callCount, 0)
        XCTAssertEqual(frames.count, 1)
        let fields = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(try XCTUnwrap(frames.first)).objectValue
        XCTAssertEqual(fields?["id"], id)
        XCTAssertEqual(fields?["error"]?.objectValue?["message"], .string("Batch not run; shorten ID."))
        XCTAssertFalse(fence.isFailed)
        await session.finishInput()
    }

    func testBatchSessionRefusalFencesBeforeExecutionWhenIDCannotFit() async throws {
        let calls = MCPAsyncTestOutput(), output = MCPAsyncTestOutput()
        let fence = MCPConnectionFence()
        let session = MCPRequestSession(configuration: .init(maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8),
            mutatingCommands: MCPBatchReceiptBudget.commands, execute: { data in
                await calls.append(data)
                return Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8)
            }, output: { await output.append($0) }, fence: fence)
        let id = MacScopeAnalysisCore.Phase2ProductionJSONValue.string(String(repeating: "\\", count: 256))
        let request = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": id, "method": .string("tools/call"),
            "params": .object(["name": .string("set-local-labels"), "arguments": .object([:])])
        ]).canonicalJSONBytes()
        await session.receive(request)
        let count = await calls.count
        let emitted = await output.count
        XCTAssertEqual(count, 0)
        XCTAssertEqual(emitted, 0)
        XCTAssertTrue(fence.isFailed)
        await session.finishInput()
    }

    func testBatchRefusalFrameKeepsIDWithinLFInclusiveLimit() throws {
        let id = MacScopeAnalysisCore.Phase2ProductionJSONValue.string(String(repeating: "\\", count: 221))
        let frame = try MCPBatchReceiptBudget.refusalFrame(id: id, maximumBytes: 512)
        XCTAssertEqual(frame.count, 511)
        let parsed = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(frame).objectValue
        XCTAssertEqual(parsed?["id"], id)
        XCTAssertEqual(parsed?["error"]?.objectValue?["message"], .string("Not run"))
        XCTAssertThrowsError(try MCPBatchReceiptBudget.refusalFrame(id: id, maximumBytes: 511))
    }

    func testBatchRefusalFencesUnrepresentableOriginalIDBeforeDispatch() async throws {
        let (_, store) = makeServer()
        var identityChecks = 0
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store),
            configuration: .init(maximumInputBytes: 4096, maximumOutputBytes: 512,
                maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8),
            validateWorkspaceIdentity: { identityChecks += 1 })
        let id = MacScopeAnalysisCore.Phase2ProductionJSONValue.string(String(repeating: "\\", count: 256))
        let request = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": id, "method": .string("tools/call"),
            "params": .object(["name": .string("set-local-labels"), "arguments": .object([
                "entries": .array([.object(["address": .string("0x1000"), "label": .string("x")])])
            ])])
        ]).canonicalJSONBytes()
        let before = store.snapshot.addressOverrides
        let response = await server.handleMessageAsync(request)
        XCTAssertNil(response)
        XCTAssertEqual(identityChecks, 0)
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        let next = await server.handleMessageAsync(Data(#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#.utf8))
        XCTAssertNil(next)
    }

    func testDefaultAsyncSearchHandlerPreservesCompleteResultsAndReadOnlyState() async throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let server = MCPServer(api: api)
        let before = store.snapshot
        let selection = store.selectedImageAddress
        for (query, mode) in [("mov", "text"), ("^mov\\b", "regex"), ("e0 03 01 aa", "hex")] {
            let arguments = ScriptValue.object(["query": .string(query), "mode": .string(mode)])
            let expected = try api.execute("search", arguments: arguments)
            let responseData = await server.handleMessageAsync(try request("tools/call", params: .object([
                "name": .string("search"), "arguments": arguments])).jsonData())
            let response = try XCTUnwrap(responseData)
            let envelope = try ScriptValue.decode(response)
            XCTAssertNil(envelope["error"])
            XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let output = try ScriptValue.decode(Data(text.utf8))
            XCTAssertEqual(output["results"], expected["results"])
            XCTAssertEqual(output["total"], expected["total"])
            XCTAssertEqual(output["lowerBound"], expected["total"])
            XCTAssertEqual(output["isTruncated"], .bool(false))
        }
        XCTAssertEqual(store.snapshot.binaries, before.binaries)
        XCTAssertEqual(store.snapshot.instructions, before.instructions)
        XCTAssertEqual(store.snapshot.addressOverrides, before.addressOverrides)
        XCTAssertEqual(store.selectedImageAddress, selection)
    }

    func testDefaultAsyncSearchHandlerReportsTruncatedLowerBound() async throws {
        let (_, store) = makeServer()
        var snapshot = store.snapshot
        snapshot.instructions = (0..<600).map { InstructionRow(address: 0x1000 + UInt64($0 * 4),
            bytes: "00 00 00 00", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil) }
        store.snapshot = snapshot
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let responseData = await server.handleMessageAsync(try request("tools/call", params: .object([
            "name": .string("search"), "arguments": .object(["query": .string("mov")])])).jsonData())
        let response = try XCTUnwrap(responseData)
        let envelope = try ScriptValue.decode(response)
        XCTAssertNil(envelope["error"])
        let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let output = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(output["total"], .null)
        XCTAssertEqual(output["isTruncated"], .bool(true))
        XCTAssertEqual(output["results"]?.arrayValue?.count, 500)
        XCTAssertGreaterThan(output["lowerBound"]?.intValue ?? 0, 500)
        XCTAssertLessThanOrEqual(output["lowerBound"]?.intValue ?? 0, 600)
    }

    func testDefaultSearchRequestSessionSettlesCompletionOrCancellationWithoutCrossSessionEffect() async throws {
        let (_, store) = makeServer()
        var snapshot = store.snapshot
        let operands = String(repeating: "a", count: 4_000)
        snapshot.instructions = (0..<10_000).map { InstructionRow(address: 0x1000 + UInt64($0 * 4),
            bytes: "00 00 00 00", mnemonic: "mov", operands: operands, hasBreakpoint: false, comment: nil) }
        store.snapshot = snapshot
        let selection = store.selectedImageAddress
        let overrides = store.snapshot.addressOverrides
        var identityChecked = false
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), validateWorkspaceIdentity: {
            identityChecked = true
        })
        let cancelledOutput = MCPAsyncTestOutput(), otherOutput = MCPAsyncTestOutput()
        let cancelled = server.makeRequestSession(output: { await cancelledOutput.append($0) })
        let other = server.makeRequestSession(output: { await otherOutput.append($0) })
        await cancelled.receive(try request("tools/call", id: .string("same-id"), params: .object([
            "name": .string("search"), "arguments": .object(["query": .string("never-present"), "mode": .string("regex")])])).jsonData())
        // Identity validation proves default handler admission. The scan may finish before
        // this actor resumes; cancellation cannot replace an already-completed terminal.
        while !identityChecked { await Task.yield() }
        let info = try WorkspaceScriptingAPI(store: store).execute("info")
        XCTAssertEqual(info["instructionCount"], .int(10_000))
        await cancelled.receive(try request("notifications/cancelled", id: nil, params: .object([
            "requestId": .string("same-id")])).jsonData())
        await other.receive(try request("tools/call", id: .string("same-id"), params: .object([
            "name": .string("info")])).jsonData())
        let cancelledResponses = try await asyncResponses(cancelledOutput, count: 1)
        let otherResponses = try await asyncResponses(otherOutput, count: 1)
        let settled = try ScriptValue.decode(cancelledResponses[0])
        if let error = settled["error"] {
            XCTAssertEqual(error["code"], .int(-32800))
            XCTAssertNil(settled["result"])
        } else if settled["result"]?["isError"] == .bool(true) {
            // A scan stopped by its budget with no hits is refused, never a zero-match success.
            let text = try XCTUnwrap(settled["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertTrue(text.contains("Search is incomplete"), text)
        } else {
            let text = try XCTUnwrap(settled["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let output = try ScriptValue.decode(Data(text.utf8))
            if output["error"] == .string("refused") {
                XCTAssertEqual(output["refusal"]?["code"], .string("budgetExceeded"))
                XCTAssertTrue(output["refusal"]?["detail"]?.stringValue?.contains("Search is incomplete") == true)
            } else {
                XCTAssertEqual(output["results"], .array([]))
                XCTAssertEqual(output["lowerBound"], .int(0))
                let truncated = try XCTUnwrap(output["isTruncated"]?.boolValue)
                XCTAssertEqual(output["total"], truncated ? .null : .int(0))
            }
        }
        XCTAssertNil(try ScriptValue.decode(otherResponses[0])["error"])
        XCTAssertEqual(try ScriptValue.decode(otherResponses[0])["result"]?["isError"], .bool(false))
        await cancelled.finishInput()
        await other.finishInput()
        let count = await cancelledOutput.count
        XCTAssertEqual(count, 1, "Completion and cancellation must settle to exactly one terminal")
        let inFlight = await cancelled.inFlightCount
        XCTAssertEqual(inFlight, 0)
        XCTAssertEqual(store.snapshot.instructions, snapshot.instructions)
        XCTAssertEqual(store.snapshot.addressOverrides, overrides)
        XCTAssertEqual(store.selectedImageAddress, selection)
    }

    func testDefaultAsyncHandlerRetainsMCPPrincipalAndPrecancelledSearchResponse() async throws {
        let (server, store) = makeServer()
        let readData = await server.handleMessageAsync(try request("tools/call", params: .object([
            "name": .string("read-evidence"), "arguments": .object(["operation": .string("workspace.summary")])])).jsonData())
        let read = try ScriptValue.decode(XCTUnwrap(readData))
        let text = try XCTUnwrap(read["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let evidence = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(evidence["proposingPrincipal"], .string("mcp"))
        XCTAssertEqual(evidence["authorizingPrincipal"], .string("app"))
        let selection = store.selectedImageAddress
        let requestBytes = try request("tools/call", params: .object([
            "name": .string("search"), "arguments": .object(["query": .string("mov")])])).jsonData()
        let operation = Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            return await server.handleMessageAsync(requestBytes)
        }
        let responseData = await operation.value
        let response = try ScriptValue.decode(XCTUnwrap(responseData))
        XCTAssertEqual(response["error"]?["code"], .int(-32800))
        XCTAssertNil(response["result"])
        XCTAssertEqual(store.selectedImageAddress, selection)
    }

    func testDefaultDecompileRequestSessionCancellationStopsDetachedReadWithOneTerminal() async throws {
        let (_, store) = makeServer()
        // Hold after body extraction, before the MacIR build (checkpoint 2).
        let gate = SnapshotReadCheckpointGate(holdAt: 2)
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store,
            snapshotReadCheckpoint: { gate.checkpoint() }))
        let output = MCPAsyncTestOutput()
        let session = server.makeRequestSession(output: { await output.append($0) })
        let selection = store.selectedImageAddress
        await session.receive(try request("tools/call", id: .string("dec"), params: .object([
            "name": .string("decompile"), "arguments": .object(["function": .string("_main")])])).jsonData())
        try await gate.waitUntilHeld()
        // MainActor stays available while the read is held off it.
        XCTAssertEqual(try WorkspaceScriptingAPI(store: store).execute("info")["functionCount"], .int(1))
        await session.receive(try request("notifications/cancelled", id: nil, params: .object([
            "requestId": .string("dec")])).jsonData())
        gate.open()
        let responses = try await asyncResponses(output, count: 1)
        let terminal = try ScriptValue.decode(responses[0])
        XCTAssertEqual(terminal["error"]?["code"], .int(-32800))
        XCTAssertNil(terminal["result"])
        await session.finishInput()
        let count = await output.count
        XCTAssertEqual(count, 1, "A cancelled read cannot publish a second terminal")
        let inFlight = await session.inFlightCount
        XCTAssertEqual(inFlight, 0, "The detached read acknowledged cancellation and retired")
        XCTAssertEqual(gate.checkpointCount, 2, "No MacIR build or print ran after cancellation")
        XCTAssertEqual(store.selectedImageAddress, selection)
    }

    func testDefaultMutationCancelledBeforeCommitHasNoEffectAndUncancelledCommits() async throws {
        let (server, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let requestBytes = try request("tools/call", params: .object([
            "name": .string("set-comment"),
            "arguments": .object(["address": .string("0x1000"), "comment": .string("must not commit")]),
        ])).jsonData()
        let cancelled = Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            return await server.handleMessageAsync(requestBytes)
        }
        let cancelledData = await cancelled.value
        let cancelledResponse = try ScriptValue.decode(XCTUnwrap(cancelledData))
        XCTAssertEqual(cancelledResponse["error"]?["code"], .int(-32800))
        XCTAssertNil(cancelledResponse["result"])
        let row = try api.execute("instructions", arguments: .object(["address": .string("0x1000"), "count": .int(1)]))
        XCTAssertNil(row.arrayValue?.first?["comment"])

        let committedData = await server.handleMessageAsync(try request("tools/call", params: .object([
            "name": .string("set-comment"),
            "arguments": .object(["address": .string("0x1000"), "comment": .string("committed")]),
        ])).jsonData())
        let committed = try ScriptValue.decode(XCTUnwrap(committedData))
        XCTAssertEqual(committed["result"]?["isError"], .bool(false))
        let after = try api.execute("instructions", arguments: .object(["address": .string("0x1000"), "count": .int(1)]))
        XCTAssertEqual(after.arrayValue?.first?["comment"], .string("committed"))
    }

    func testAsyncSessionCancelsSuspendedReadAndSuppressesItsLateResult() async throws {
        let (_, store) = makeServer()
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), asyncCommandExecutor: { _, _ in
            await gate.suspend()
            return .object(["late": .bool(true)])
        })
        let session = server.makeRequestSession(output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":"read","method":"tools/call","params":{"name":"info"}}"#.utf8))
        await gate.waitUntilStarted()
        await session.receive(Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"read"}}"#.utf8))
        let responses = try await asyncResponses(probe, count: 1)
        XCTAssertEqual(try ScriptValue.decode(responses[0])["error"]?["code"], .int(-32800))
        let observed1 = await session.inFlightCount
        XCTAssertEqual(observed1, 1, "retirement remains bounded until the task returns")
        await gate.release()
        await session.finishInput()
        let observed2 = await probe.count
        XCTAssertEqual(observed2, 1, "late success cannot become a second terminal")
    }

    func testAsyncDeadlineFiresBeforeSuspendedReadCompletes() async throws {
        let (_, store) = makeServer()
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 1_024, maximumOutputBytes: 8_192,
            maximumToolDurationNanoseconds: 20_000_000, maximumRememberedCancellations: 8),
            asyncCommandExecutor: { _, _ in await gate.suspend(); return .null })
        let session = server.makeRequestSession(output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"info"}}"#.utf8))
        let responses = try await asyncResponses(probe, count: 1)
        XCTAssertEqual(try ScriptValue.decode(responses[0])["error"]?["code"], .int(-32001))
        await gate.release()
        await session.finishInput()
        let observed3 = await probe.count
        XCTAssertEqual(observed3, 1)
    }

    func testAsyncRequestIDsPreserveNullStringAndExactNumericIdentity() async throws {
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: [], execute: { _ in
            await gate.suspend()
            return Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8)
        }, output: { await probe.append($0) })
        for id in ["1", "\"1\"", "null"] {
            await session.receive(Data("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"method\":\"ping\"}".utf8))
        }
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1.00e0,"method":"ping"}"#.utf8))
        let duplicates = try await asyncResponses(probe, count: 1)
        let duplicate = try Phase2StrictJSONParser().parse(duplicates[0], limits: .providerEnvelope)
        XCTAssertEqual(duplicate.objectValue?["id"], .number("1.00e0"))
        XCTAssertEqual(duplicate.objectValue?["error"]?.objectValue?["code"], .number("-32600"))
        let observed4 = await session.inFlightCount
        XCTAssertEqual(observed4, 3)
        await session.receive(Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}"#.utf8))
        let cancelled = try await asyncResponses(probe, count: 2)
        XCTAssertEqual(try ScriptValue.decode(cancelled[1])["id"], .null)
        await gate.release()
        _ = try await asyncResponses(probe, count: 4)
        await session.finishInput()
    }

    func testAsyncInFlightLimitAndEOFRetireOwnedReads() async throws {
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let session = MCPRequestSession(configuration: .init(maximumInputBytes: 1_024,
            maximumOutputBytes: 8_192, maximumToolDurationNanoseconds: 1_000_000_000,
            maximumRememberedCancellations: 8, maximumInFlightRequests: 1), mutatingCommands: [],
            execute: { _ in await gate.suspend(); return Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8) },
            output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8))
        await gate.waitUntilStarted()
        await session.receive(Data(#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#.utf8))
        let saturated = try await asyncResponses(probe, count: 1)
        XCTAssertEqual(try ScriptValue.decode(saturated[0])["error"]?["code"], .int(-32000))
        await gate.release()
        await session.finishInput()
        let observed5 = await session.inFlightCount
        XCTAssertEqual(observed5, 0)
        await gate.release()
        await session.receive(Data(#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#.utf8))
        let observed6 = await probe.count
        XCTAssertEqual(observed6, 2)
    }

    func testEOFWaitsForCommittedMutationTerminalWrite() async throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let outputGate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: api)
        let session = server.makeRequestSession(output: { data in
            await outputGate.suspend()
            await probe.append(data)
        })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set-comment","arguments":{"address":"0x1000","comment":"committed before EOF"}}}"#.utf8))
        await outputGate.waitUntilStarted()
        let pending = await session.pendingTerminalWriteCount
        XCTAssertEqual(pending, 1)
        let finished = MCPAsyncTestOutput()
        let eof = Task { await session.finishInput(); await finished.append(Data()) }
        while await session.isAcceptingRequests { await Task.yield() }
        while !(await session.isAwaitingInputDrain), await finished.count == 0 { await Task.yield() }
        let waiting = await session.isAwaitingInputDrain
        XCTAssertTrue(waiting)
        let early = await finished.count
        XCTAssertEqual(early, 0, "EOF must not close the response descriptor while output is suspended")
        await outputGate.release()
        await eof.value
        let responses = await probe.values
        XCTAssertEqual(responses.count, 1)
        XCTAssertEqual(try ScriptValue.decode(responses[0])["result"]?["isError"], .bool(false))
        let comment = try api.execute("instructions", arguments: .object(["address": .string("0x1000"), "count": .int(1)]))
        XCTAssertEqual(comment.arrayValue?.first?["comment"], .string("committed before EOF"))
    }

    func testEOFRetainsCancelledReadUntilCleanupAcknowledgement() async {
        let execution = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
            execute: { _ in await execution.suspend(); return nil }, output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8))
        await execution.waitUntilStarted()
        let finished = MCPAsyncTestOutput()
        let eof = Task { await session.finishInput(); await finished.append(Data()) }
        while await session.isAcceptingRequests { await Task.yield() }
        while !(await session.isAwaitingInputDrain), await finished.count == 0 { await Task.yield() }
        let waiting = await session.isAwaitingInputDrain
        XCTAssertTrue(waiting)
        let retained = await session.inFlightCount
        let early = await finished.count
        XCTAssertEqual(retained, 1)
        XCTAssertEqual(early, 0)
        await execution.release() // Explicit owned-resource cleanup acknowledgment.
        await eof.value
        let retired = await session.inFlightCount
        XCTAssertEqual(retired, 0)
    }

    func testOutputFailureStopsAdmissionBeforeQueuedMutationRuns() async {
        let execution = MCPAsyncTestGate()
        let calls = MCPAsyncTestOutput()
        let outputGate = MCPAsyncTestGate()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: ["set-comment"],
            execute: { data in
                await calls.append(data)
                await execution.suspend()
                return Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8)
            }, output: { _ in await outputGate.markStarted(); throw HeadlessProtocolIOError.writeFailure })
        let request = Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set-comment"}}"#.utf8)
        await session.receive(request)
        await execution.waitUntilStarted()
        await session.receive(Data(#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"set-comment"}}"#.utf8))
        await execution.release()
        await outputGate.waitUntilStarted()
        while await session.isAcceptingRequests { await Task.yield() }
        await session.receive(request)
        await session.finishInput()
        let count = await calls.count
        XCTAssertEqual(count, 1)
    }

    func testAsyncCommittedMutationSurvivesCancellationAndQueuedMutationDoesNotRun() async throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: api, asyncCommandExecutor: { command, arguments in
            let committed = try HeadlessAutomationAuthority.execute(command: command,
                arguments: arguments, api: api, proposingPrincipal: .mcp)
            await gate.suspend()
            return committed
        })
        let session = server.makeRequestSession(output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set-comment","arguments":{"address":"0x1000","comment":"committed"}}}"#.utf8))
        await gate.waitUntilStarted()
        await session.receive(Data(#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"set-comment","arguments":{"address":"0x1000","comment":"must not run"}}}"#.utf8))
        for id in [1, 2] {
            await session.receive(Data("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":\(id)}}".utf8))
        }
        _ = try await asyncResponses(probe, count: 1)
        await gate.release()
        let responses = try await asyncResponses(probe, count: 2)
        let committed = try responses.map(ScriptValue.decode).first { $0["id"] == .int(1) }
        XCTAssertEqual(committed?["result"]?["isError"], .bool(false))
        let comment = try api.execute("instructions", arguments: .object(["address": .string("0x1000"), "count": .int(1)]))
        XCTAssertEqual(comment.arrayValue?.first?["comment"], .string("committed"))
        await session.finishInput()
    }

    func testGotoIsAdvertisedAsWorkspaceMutation() throws {
        let (server, _) = makeServer()
        let tools = server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue ?? []
        let tool = try XCTUnwrap(tools.first { $0["name"]?.stringValue == "goto" })
        XCTAssertEqual(tool["annotations"]?["readOnlyHint"]?.boolValue, false)
    }

    func testQueuedGotoCancelledBehindRunningMutationNeverNavigates() async throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: api, asyncCommandExecutor: { command, arguments in
            let committed = try HeadlessAutomationAuthority.execute(command: command,
                arguments: arguments, api: api, proposingPrincipal: .mcp)
            await gate.suspend()
            return committed
        })
        let selection = store.selectedImageAddress
        let session = server.makeRequestSession(output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set-comment","arguments":{"address":"0x1000","comment":"committed"}}}"#.utf8))
        await gate.waitUntilStarted()
        // goto is a mutation, so it queues behind the running set-comment instead of running now.
        await session.receive(Data(#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"goto","arguments":{"query":"0x1004"}}}"#.utf8))
        await session.receive(Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}"#.utf8))
        let first = try await asyncResponses(probe, count: 1)
        XCTAssertEqual(try ScriptValue.decode(first[0])["id"], .int(2))
        XCTAssertEqual(try ScriptValue.decode(first[0])["error"]?["code"], .int(-32800))
        await gate.release()
        let responses = try await asyncResponses(probe, count: 2)
        let committed = try responses.map(ScriptValue.decode).first { $0["id"] == .int(1) }
        XCTAssertEqual(committed?["result"]?["isError"], .bool(false))
        await session.finishInput()
        XCTAssertEqual(store.selectedImageAddress, selection, "a cancelled queued goto must not navigate")
    }

    func testCommittedGotoReportsReceiptDespiteLateCancellation() async throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: api, asyncCommandExecutor: { command, arguments in
            let committed = try HeadlessAutomationAuthority.execute(command: command,
                arguments: arguments, api: api, proposingPrincipal: .mcp)
            await gate.suspend()
            return committed
        })
        let session = server.makeRequestSession(output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"goto","arguments":{"query":"0x1004"}}}"#.utf8))
        await gate.waitUntilStarted()
        await session.receive(Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#.utf8))
        await gate.release()
        let responses = try await asyncResponses(probe, count: 1)
        let response = try ScriptValue.decode(responses[0])
        XCTAssertEqual(response["result"]?["isError"], .bool(false), "navigation already happened; report it")
        XCTAssertEqual(store.selectedAddress, 0x1004)
        await session.finishInput()
    }

    func testCancellationReachesOwnedAuditProcessWhileMainActorIsBusy() async throws {
        let (_, store) = makeServer()
        let gate = MCPAsyncTestGate()
        let probe = MCPAsyncTestOutput()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), asyncCommandExecutor: { _, _ in
            await gate.markStarted()
            _ = try WorkspaceScriptingAPI.runCallArgumentAuditProcess(
                executableURL: URL(fileURLWithPath: "/bin/sleep"), arguments: ["10"],
                environment: [:], timeout: 10)
            return .null
        })
        let session = server.makeRequestSession(output: { await probe.append($0) })
        let sender = Task.detached {
            await gate.waitUntilStarted()
            try? await Task.sleep(nanoseconds: 100_000_000)
            await session.receive(Data(#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#.utf8))
        }
        let start = DispatchTime.now().uptimeNanoseconds
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"info"}}"#.utf8))
        let responses = try await asyncResponses(probe, count: 1)
        await sender.value
        XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - start, 2_000_000_000)
        XCTAssertEqual(try ScriptValue.decode(responses[0])["error"]?["code"], .int(-32800))
        await session.finishInput()
    }

    private func asyncResponses(_ probe: MCPAsyncTestOutput, count: Int) async throws -> [Data] {
        for _ in 0..<200 {
            let values = await probe.values
            if values.count >= count { return values }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("Timed out waiting for MCP terminal responses")
        throw URLError(.timedOut)
    }

    func testRawHeadlessJSONPreservesIntegralDecimalAndExponentValuesExactly() throws {
        let cases: [(String, Int64)] = [
            ("1.0", 1), ("1e3", 1000), ("1000e-3", 1), ("-0.0e99999999999999999999", 0),
            ("9007199254740993.0", 9_007_199_254_740_993),
            ("9007199254740993e0", 9_007_199_254_740_993),
            ("9223372036854775807.0", Int64.max),
            ("-9223372036854775808.0", Int64.min),
            ("12.000e+0000000000000000000000", 12),
        ]
        for (source, expected) in cases {
            let result = try HeadlessJSON.decode(Data(source.utf8), maximumBytes: 4096)
            XCTAssertEqual(result, .int(expected), source)
        }
    }

    func testFractionalOrOverflowingNumbersNeverBecomeIntegerMutations() throws {
        for source in ["1.9", "1e-1", "1.00000000000000001", "9223372036854775808.0"] {
            let value = try HeadlessJSON.decode(Data(source.utf8), maximumBytes: 4096)
            if case .int = value { XCTFail("Non-Int64 JSON became an integer: \(source)") }
            for (command, key) in [("make-array", "count"), ("make-alignment", "boundary"),
                                   ("rebase-segment", "delta")] {
                var arguments: [String: ScriptValue] = [key: value]
                if command == "rebase-segment" { arguments["section"] = .string("__text") }
                else { arguments["address"] = .string("0x1000") }
                XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(
                    command: command, arguments: .object(arguments)
                ), "\(command): \(source)")
            }
        }
    }

    func testRawTransportAcceptsSchemaIntegralCount() throws {
        let (server, _) = makeServer()
        let json = #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"functions","arguments":{"limit":0e3}}}"#
        let response = try XCTUnwrap(server.handleMessage(Data(json.utf8)))
        let value = try ScriptValue.decode(response)
        XCTAssertEqual(value["result"]?["isError"], .bool(false))
    }

    func testRepeatedTypedReadCallsDoNotRetainExternalEvidenceOrDiscardModelEvidence() throws {
        let (server, store) = makeServer()
        guard case .prepared(let modelRead) = store.preparePhase2Read(
            operation: .workspaceSummary, proposingPrincipal: .model
        ) else { return XCTFail("Expected model preparation") }
        let modelExecution = store.executePhase2Read(modelRead)
        let modelEvidence = try XCTUnwrap(modelExecution.acceptedEvidence)
        let retainedCount = store.phase2EvidenceAcceptor.terminalCount

        for call in 0..<128 {
            let response = server.handle(request("tools/call", id: .int(Int64(call)), params: .object([
                "name": .string("read-evidence"),
                "arguments": .object(["operation": .string("workspace.summary")]),
            ])))
            XCTAssertEqual(response?["result"]?["isError"]?.boolValue, false)
            let text = try XCTUnwrap(response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let output = try ScriptValue.decode(Data(text.utf8))
            XCTAssertEqual(output["status"]?.stringValue, "accepted")
            XCTAssertEqual(output["facts"]?["workspaceName"]?.stringValue, "MCP")
            let invocation = try XCTUnwrap(UUID(uuidString: try XCTUnwrap(output["invocationID"]?.stringValue)))
            XCTAssertNil(store.acceptedPhase2Evidence(invocationID: invocation))
            XCTAssertEqual(store.phase2EvidenceAcceptor.terminalCount, retainedCount)
        }
        XCTAssertEqual(store.acceptedPhase2Evidence(invocationID: modelEvidence.invocationID), modelEvidence)
        XCTAssertEqual(store.executePhase2Read(modelRead).disposition, .duplicate)
    }

    func testTypedReadTransportOutputRejectionDoesNotRetainAcceptance() throws {
        let (_, store) = makeServer()
        guard case .prepared(let modelRead) = store.preparePhase2Read(
            operation: .workspaceSummary, proposingPrincipal: .model
        ) else { return XCTFail("Expected model preparation") }
        let modelEvidence = try XCTUnwrap(store.executePhase2Read(modelRead).acceptedEvidence)
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 1_024, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: .max, maximumRememberedCancellations: 8
        ))
        for call in 0..<16 {
            let response = server.handle(request("tools/call", id: .int(Int64(call)), params: .object([
                "name": .string("read-evidence"),
                "arguments": .object(["operation": .string("workspace.summary")]),
            ])))
            XCTAssertEqual(response?["error"]?["code"]?.intValue, -32603)
            XCTAssertEqual(store.phase2EvidenceAcceptor.terminalCount, 1)
        }
        XCTAssertEqual(store.acceptedPhase2Evidence(invocationID: modelEvidence.invocationID), modelEvidence)
    }


    func testTypedReadToolAdvertisesClosedReadOnlyOperations() throws {
        let (server, _) = makeServer()
        let tools = server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue ?? []
        let tool = try XCTUnwrap(tools.first { $0["name"]?.stringValue == "read-evidence" })
        XCTAssertEqual(tool["annotations"]?["readOnlyHint"]?.boolValue, true)
        XCTAssertEqual(tool["annotations"]?["destructiveHint"]?.boolValue, false)
        XCTAssertEqual(tool["inputSchema"]?["required"]?.arrayValue, [.string("operation")])
        XCTAssertEqual(tool["inputSchema"]?["properties"]?["operation"]?["enum"]?.arrayValue,
                       [.string("workspace.summary"), .string("application.graph.summary"),
                        .string("function.review")])
        XCTAssertEqual(tool["inputSchema"]?["additionalProperties"]?.boolValue, false)
    }

    func testTypedReadCallRecordsMCPProposalAndAppAuthorization() throws {
        let (server, _) = makeServer()
        let response = server.handle(request("tools/call", params: .object([
            "name": .string("read-evidence"),
            "arguments": .object(["operation": .string("workspace.summary")]),
        ])))
        XCTAssertEqual(response?["result"]?["isError"]?.boolValue, false)
        let text = try XCTUnwrap(response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let output = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(output["status"]?.stringValue, "accepted")
        XCTAssertEqual(output["proposingPrincipal"]?.stringValue, "mcp")
        XCTAssertEqual(output["authorizingPrincipal"]?.stringValue, "app")
        XCTAssertEqual(output["facts"]?["workspaceName"]?.stringValue, "MCP")
        for (fields, field) in [
            (["operation": ScriptValue.string("decompiler.native.result")], "operation"),
            (["operation": .string("workspace.summary"), "principal": .string("app")], "principal"),
        ] {
            assertMCPToolArgumentError(server.handle(request("tools/call", params: .object([
                "name": .string("read-evidence"), "arguments": .object(fields),
            ]))), field: field, code: "malformedInput")
        }
    }

    /// F3: `reconstruction-jobs` through the MCP JSON-RPC transport (request bytes in, response
    /// bytes out), not just the scripting function: a durable source job, its lifecycle columns
    /// and the job-not-found argument error.
    func testReconstructionJobsThroughMCPTransportReportsDurableJobAndLifecycle() async throws {
        let databaseFixture = try ReconstructionDatabaseTestFixtures.makeCurrentDatabase()
        let package = try ReconstructionPackageFixture.make(); defer { package.remove() }
        let database = databaseFixture.database, workspaceID = databaseFixture.workspaceUUID
        try database.replaceReconstructionState(workspaceID: workspaceID, state: package.state)
        let project = try XCTUnwrap(package.state.projects.first)
        let occurrence = try XCTUnwrap(package.state.corpusManifests.first?.artifacts.first)
        let initial = try database.commitInitialReconstructionJob(workspaceID: workspaceID,
            mutation: .init(jobID: UUID(), projectID: project.projectID,
                selectedOccurrenceIDs: [occurrence.occurrenceID], objective: "MCP job status transport",
                budget: .init(maxRounds: 2, maxTasks: 20, maxEvidenceRecords: 20, maxEncodedBytes: 1_048_576),
                focus: .artifact(.init(occurrenceID: occurrence.occurrenceID, contentIdentity: occurrence.contentIdentity)),
                sourceProfileID: ReconstructionSourceExecutionTaskContract.profileID))
        let created = try XCTUnwrap(initial.lifecycle.jobs[initial.job.jobID]?.createdAtMilliseconds)

        let (server, store) = makeServer()
        var publication = ReconstructionCommittedCorpus(state: initial.state, attachmentSources: [])
        publication.lifecycle = initial.lifecycle
        store.publishCommittedReconstructionCorpus(publication)
        XCTAssertEqual(store.reconstructionLifecycle, initial.lifecycle)

        let responseData = await server.handleMessageAsync(try request("tools/call", params: .object([
            "name": .string("reconstruction-jobs"),
            "arguments": .object(["job": .string(initial.job.jobID.uuidString)]),
        ])).jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(responseData))
        XCTAssertNil(envelope["error"])
        XCTAssertEqual(envelope["id"]?.intValue, 1)
        XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
        let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let jobs = try XCTUnwrap(try ScriptValue.decode(Data(text.utf8)).arrayValue)
        XCTAssertEqual(jobs.count, 1)
        XCTAssertEqual(jobs[0]["jobID"]?.stringValue, initial.job.jobID.uuidString)
        XCTAssertEqual(jobs[0]["state"]?.stringValue, "created")
        XCTAssertEqual(jobs[0]["lifecycle"]?["createdAtMilliseconds"]?.stringValue, String(created))
        XCTAssertNil(jobs[0]["lifecycle"]?["finishedAtMilliseconds"])
        XCTAssertNil(jobs[0]["elapsedSource"])
        XCTAssertEqual(jobs[0]["failedTasks"]?.arrayValue?.count, 0)
        // Byte-for-byte the same record the scripting function returns.
        XCTAssertEqual(ScriptValue.array(jobs), try WorkspaceScriptingAPI.reconstructionJobsStatus(
            .object(["job": .string(initial.job.jobID.uuidString)]), state: store.reconstructionState,
            lifecycle: store.reconstructionLifecycle))

        // An unknown job is an argument error through the transport, not an empty success.
        let missing = await server.handleMessageAsync(try request("tools/call", id: .int(2), params: .object([
            "name": .string("reconstruction-jobs"),
            "arguments": .object(["job": .string(UUID().uuidString)]),
        ])).jsonData())
        let missingEnvelope = try ScriptValue.decode(try XCTUnwrap(missing))
        XCTAssertEqual(missingEnvelope["id"]?.intValue, 2)
        XCTAssertTrue(missingEnvelope["error"] != nil || missingEnvelope["result"]?["isError"] == .bool(true),
            "\(missingEnvelope)")
    }

    private func makeServer() -> (MCPServer, WorkspaceStore) {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000, kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [],
            hexBytes: Data()
        )
        let store = WorkspaceStore(workspaceName: "MCP", snapshot: snapshot, engine: AnalysisEngine())
        return (MCPServer(api: WorkspaceScriptingAPI(store: store)), store)
    }

    private func request(_ method: String, id: ScriptValue? = .int(1), params: ScriptValue? = nil) -> ScriptValue {
        var object: [String: ScriptValue] = ["jsonrpc": .string("2.0"), "method": .string(method)]
        if let id { object["id"] = id }
        if let params { object["params"] = params }
        return .object(object)
    }

    func testInitialize() {
        let (server, _) = makeServer()
        let response = server.handle(request("initialize"))
        XCTAssertEqual(response?["jsonrpc"]?.stringValue, "2.0")
        XCTAssertEqual(response?["id"]?.intValue, 1)
        XCTAssertEqual(response?["result"]?["protocolVersion"]?.stringValue, MCPServer.protocolVersion)
        XCTAssertEqual(response?["result"]?["serverInfo"]?["name"]?.stringValue, "macscope")
        XCTAssertNotNil(response?["result"]?["capabilities"]?["tools"])
    }

    func testToolsListExposesCommandsAsTools() {
        let (server, _) = makeServer()
        let tools = server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue ?? []
        XCTAssertFalse(tools.isEmpty)
        let rename = tools.first { $0["name"]?.stringValue == "rename" }
        XCTAssertNotNil(rename)
        XCTAssertEqual(rename?["inputSchema"]?["type"]?.stringValue, "object")
        XCTAssertNotNil(rename?["inputSchema"]?["properties"]?["address"])
        XCTAssertTrue(rename?["description"]?.stringValue?.contains("mutates") ?? false)
        XCTAssertTrue(tools.contains { $0["name"]?.stringValue == "functions" })
        XCTAssertFalse(tools.contains { $0["name"]?.stringValue == "save-patched-binary" })
        XCTAssertFalse(tools.contains { $0["name"]?.stringValue == "read-debug-symbols" })
        XCTAssertEqual(rename?["inputSchema"]?["additionalProperties"]?.boolValue, false)
    }

    func testColorSchemaAdvertisesAcceptedValuesAndClearing() throws {
        let (server, _) = makeServer()
        let tools = try XCTUnwrap(server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue)
        let schema = try XCTUnwrap(tools.first { $0["name"]?.stringValue == "set-color" }?["inputSchema"])
        let color = try XCTUnwrap(schema["properties"]?["color"])
        XCTAssertEqual(color["type"], .string("string"))
        XCTAssertEqual(color["enum"], .array(([""] + ColorTag.allCases.map(\.rawValue)).map(ScriptValue.string)))
        XCTAssertTrue(schema["required"]?.arrayValue?.contains(.string("color")) == true)
        XCTAssertNil(color["anyOf"])
    }

    func testOperandFormatSchemasAdvertiseExactlyAcceptedValues() throws {
        let (server, _) = makeServer()
        let tools = try XCTUnwrap(server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue)
        func schema(_ name: String) throws -> ScriptValue {
            try XCTUnwrap(tools.first { $0["name"]?.stringValue == name }?["inputSchema"])
        }
        let expected = ([""] + OperandFormat.allCases.map(\.rawValue)).map(ScriptValue.string)
        let single = try schema("set-operand-format")
        let batch = try schema("set-operand-formats")
        XCTAssertEqual(single["properties"]?["format"]?["enum"]?.arrayValue, expected)
        XCTAssertEqual(batch["properties"]?["entries"]?["items"]?["properties"]?["format"]?["enum"]?.arrayValue, expected)
        let sibling = try schema("set-types")
        XCTAssertNil(sibling["properties"]?["entries"]?["items"]?["properties"]?["type"]?["enum"])
        for format in [""] + OperandFormat.allCases.map(\.rawValue) {
            let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(0x1000), "format": .string(format)])])])
            XCTAssertNoThrow(try HeadlessAutomationAuthority.validateDiagnosed(command: "set-operand-formats", arguments: args))
        }
        let bad: ScriptValue = .object(["entries": .array([.object(["address": .hex(0x1000), "format": .string("bogus")])])])
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: "set-operand-formats", arguments: bad))
    }

    func testToolSchemasDescribeNumericBooleanAndStructuredArguments() throws {
        let (server, _) = makeServer()
        let tools = server.handle(request("tools/list"))?["result"]?["tools"]?.arrayValue ?? []
        func schema(_ name: String) throws -> ScriptValue {
            try XCTUnwrap(tools.first { $0["name"]?.stringValue == name }?["inputSchema"])
        }

        let functions = try schema("functions")
        XCTAssertEqual(functions["properties"]?["limit"]?["type"], .string("integer"))
        XCTAssertEqual(functions["properties"]?["limit"]?["maximum"], .int(10_000))
        let read = try schema("read-bytes")
        XCTAssertEqual(read["properties"]?["count"]?["maximum"], .int(1_048_576))
        XCTAssertEqual(read["required"], .array([.string("address")]))
        XCTAssertEqual(try schema("make-data")["properties"]?["isData"]?["type"], .string("boolean"))

        let signature = try schema("set-signature")
        XCTAssertEqual(signature["properties"]?["args"]?["type"], .array([.string("array"), .string("null")]))
        XCTAssertEqual(signature["properties"]?["args"]?["items"]?["required"], .array([.string("type")]))
        XCTAssertNil(signature["properties"]?["args"]?["items"]?["additionalProperties"])
        XCTAssertEqual(signature["additionalProperties"], .bool(false))
        XCTAssertEqual(signature["properties"]?["returnType"]?["type"], .array([.string("string"), .string("null")]))
        let defineType = try schema("define-type")
        XCTAssertEqual(defineType["properties"]?["fields"]?["type"], .string("array"))
        XCTAssertNil(defineType["properties"]?["fields"]?["items"]?["additionalProperties"])
        XCTAssertEqual(defineType["additionalProperties"], .bool(false))
        XCTAssertEqual(try schema("decompile")["anyOf"], .array([
            .object(["required": .array([.string("function")])]),
            .object(["required": .array([.string("address")])]),
        ]))
        XCTAssertNotNil(try schema("call-argument-audit")["oneOf"])

        // Correcting schemas must never widen the existing external authority.
        XCTAssertFalse(tools.contains { $0["name"]?.stringValue == "save-patched-binary" })
        XCTAssertFalse(tools.contains { $0["name"]?.stringValue == "read-debug-symbols" })
    }

    func testSchemaNumericLimitMatchesExecutionAndRejectsStringifiedCount() throws {
        let (server, _) = makeServer()
        let response = server.handle(request("tools/call", params: .object([
            "name": .string("functions"), "arguments": .object(["limit": .int(0)]),
        ])))
        XCTAssertEqual(response?["result"]?["isError"], .bool(false))
        XCTAssertEqual(response?["result"]?["content"]?.arrayValue?.first?["text"], .string("[]"))
        let invalid = server.handle(request("tools/call", params: .object([
            "name": .string("functions"), "arguments": .object(["limit": .string("0")]),
        ])))
        assertMCPToolArgumentError(invalid, field: "limit", code: "malformedInput")
    }

    func testSchemaBooleanFalseAndSignatureNullRetainTheirExistingMeaning() throws {
        let (server, store) = makeServer()
        let result = server.handle(request("tools/call", params: .object([
            "name": .string("make-data"),
            "arguments": .object(["address": .string("0x1000"), "isData": .bool(false)]),
        ])))
        XCTAssertEqual(result?["result"]?["isError"], .bool(false))
        let payload = try ScriptValue.decode(Data(try XCTUnwrap(
            result?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue
        ).utf8))
        XCTAssertEqual(payload["isData"], .bool(false))

        let authored = server.handle(request("tools/call", params: .object([
            "name": .string("set-signature"),
            "arguments": .object([
                "address": .string("0x1000"), "returnType": .string("int"),
                "variadicState": .string("fixed"),
                "args": .array([.object(["type": .string("int"), "name": .string("value")])]),
            ]),
        ])))
        XCTAssertEqual(authored?["result"]?["isError"], .bool(false))
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.signature?.returnType, "int")
        let cleared = server.handle(request("tools/call", params: .object([
            "name": .string("set-signature"),
            "arguments": .object(["address": .string("0x1000"), "returnType": .null, "args": .null]),
        ])))
        XCTAssertEqual(cleared?["result"]?["isError"], .bool(false))
        let signature = try XCTUnwrap(store.snapshot.addressOverrides[.primary(0x1000)]?.signature)
        XCTAssertNil(signature.returnType)
        XCTAssertEqual(signature.parameterList, .unspecified)
    }

    func testToolsCallReturnsResultContent() {
        let (server, _) = makeServer()
        let response = server.handle(request("tools/call", params: .object(["name": .string("functions")])))
        XCTAssertEqual(response?["result"]?["isError"]?.boolValue, false)
        let text = response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue
        XCTAssertNotNil(text)
        XCTAssertTrue(text?.contains("_main") ?? false) // the JSON listing includes the function
    }

    func testToolsCallSessionMutatesAndReadsBack() throws {
        let (server, store) = makeServer()
        // Call the rename tool, then read it back via name-at — a full session.
        _ = server.handle(request("tools/call", params: .object([
            "name": .string("rename"),
            "arguments": .object(["address": .string("0x1000"), "name": .string("entry")]),
        ])))
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.customName, "entry")

        let readBack = server.handle(request("tools/call", params: .object([
            "name": .string("name-at"),
            "arguments": .object(["address": .string("0x1000")]),
        ])))
        XCTAssertEqual(readBack?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue, "\"entry\"")
    }

    func testSeparateServerInstancesNeverShareWorkspaceMutations() {
        let (first, firstStore) = makeServer()
        let (second, secondStore) = makeServer()
        _ = first.handle(request("tools/call", params: .object([
            "name": .string("rename"),
            "arguments": .object(["address": .string("0x1000"), "name": .string("first-only")]),
        ])))
        XCTAssertEqual(firstStore.snapshot.addressOverrides[.primary(0x1000)]?.customName, "first-only")
        XCTAssertNil(secondStore.snapshot.addressOverrides[.primary(0x1000)]?.customName)
        let secondName = second.handle(request("tools/call", params: .object([
            "name": .string("name-at"),
            "arguments": .object(["address": .string("0x1000")]),
        ])))
        XCTAssertEqual(secondName?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue, "\"_main\"")
    }

    func testToolErrorIsReportedInBand() {
        let (server, _) = makeServer()
        // An unknown tool / bad argument is an MCP tool error (isError), not a protocol error.
        let response = server.handle(request("tools/call", params: .object(["name": .string("does-not-exist")])))
        XCTAssertEqual(response?["result"]?["isError"]?.boolValue, true)
        XCTAssertNil(response?["error"])
    }

    func testFailedToolCallCarriesTheScriptingErrorDescription() {
        let (server, _) = makeServer()
        // A schema-valid call that fails semantically names the reason instead of a bare
        // "Tool call failed.", so an agent can correct the call.
        let response = server.handle(request("tools/call", params: .object([
            "name": .string("rename"),
            "arguments": .object(["address": .string("not-an-address"), "name": .string("x")]),
        ])))
        XCTAssertEqual(response?["result"]?["isError"]?.boolValue, true)
        let text = response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue ?? ""
        XCTAssertTrue(text.hasPrefix("Tool call failed: "), text)
        XCTAssertGreaterThan(text.count, "Tool call failed: ".count)
    }

    func testCommittedMutationIsNotReportedAsADeadlineFailure() {
        let (_, store) = makeServer()
        var now: UInt64 = 0
        // Every clock read advances a minute, so every call "exceeds" the 30 s deadline.
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), monotonicNow: {
            now += 60_000_000_000
            return now
        })
        let rename = server.handle(request("tools/call", params: .object([
            "name": .string("rename"),
            "arguments": .object(["address": .string("0x1000"), "name": .string("applied")]),
        ])))
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.customName, "applied")
        XCTAssertNil(rename?["error"], "the rename committed; reporting -32001 invites a double apply")
        XCTAssertEqual(rename?["result"]?["isError"]?.boolValue, false)
        // A read that overruns still reports the deadline.
        let read = server.handle(request("tools/call", params: .object(["name": .string("functions")])))
        XCTAssertEqual(read?["error"]?["code"]?.intValue, -32001)
    }

    func testRetainedPatchReportsCommitAndDiagnosticDespiteLateCancellationAndDeadline() throws {
        let bytes = Data([0xb8, 1, 0, 0, 0, 0xc3])
        let text = BinarySection(name: ".text", address: 0x1000, size: 6, fileOffset: 0,
                                 isExecutable: true, fileSize: 6)
        let binary = LoadedBinary(name: "mutation-reporting", path: "/mutation-reporting-fixture",
            isBundle: false, cpuType: MachOConstants.cpuTypeX86_64, fileTypeName: "fixture",
            architectureDisplayName: "x86_64", metadata: .empty, bytes: bytes, sliceOffset: 0,
            sliceSize: 6, sections: [text], executableTextSection: text, entryPointAddress: 0x1000,
            symbols: [], imports: [], indirectSymbols: [], exports: [], stringLiterals: [],
            functionStarts: [0x1000], objcSelectors: [:])
        let engine = AnalysisEngine(loader: MutationReportingFixtureLoader(binary: binary))
        let store = WorkspaceStore(workspaceName: "MCP retained edit",
            snapshot: try engine.analyze(url: URL(fileURLWithPath: binary.path)),
            engine: engine, autosaveScheduler: nil)
        var server: MCPServer?
        defer { server = nil }
        var identityChecks = 0
        var now: UInt64 = 0
        server = MCPServer(api: WorkspaceScriptingAPI(store: store), monotonicNow: {
            now += 60_000_000_000
            return now
        }, validateWorkspaceIdentity: {
            identityChecks += 1
            if identityChecks.isMultiple(of: 2) {
                _ = server?.handle(self.request("notifications/cancelled", id: nil, params: .object([
                    "requestId": .int(41),
                ])))
            }
        })
        for _ in 0..<2 {
            let response = server?.handle(request("tools/call", id: .int(41), params: .object([
                "name": .string("patch-bytes"),
                "arguments": .object(["address": .hex(0x1005), "bytes": .string("90 90")]),
            ])))
            XCTAssertNil(response?["error"], "a retained mutation must survive late cancel/deadline reporting")
            XCTAssertEqual(response?["result"]?["isError"], .bool(false))
            let encoded = try XCTUnwrap(response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let output = try ScriptValue.decode(Data(encoded.utf8))
            XCTAssertEqual(output["committed"], .bool(true))
            XCTAssertEqual(output["reanalysisStatus"], .string("failed"))
            XCTAssertTrue(output["reanalysisDiagnostic"]?.stringValue?.contains("unambiguous file-backed mapping") == true)
            XCTAssertEqual(store.snapshot.patches(in: .primary)[0x1005]?.byteText, "90 90")
            XCTAssertTrue(store.isDirty)
        }
    }

    func testProtocolErrors() {
        let (server, _) = makeServer()
        XCTAssertEqual(server.handle(request("nonexistent/method"))?["error"]?["code"]?.intValue, -32601)
        XCTAssertEqual(server.handle(request("tools/call", params: .object([:])))?["error"]?["code"]?.intValue, -32602)
        XCTAssertEqual(server.handle(request("ping"))?["result"], .object([:]))
    }

    func testNotificationsGetNoResponse() {
        let (server, _) = makeServer()
        // No `id` → a notification → no reply.
        XCTAssertNil(server.handle(request("notifications/initialized", id: nil)))
        XCTAssertNil(server.handle(request("initialized", id: nil))) // unknown notification, still no reply
    }

    func testToolCallNotificationExecutesButNeverResponds() {
        let (server, store) = makeServer()
        let notification = request("tools/call", id: nil, params: .object([
            "name": .string("rename"),
            "arguments": .object(["address": .string("0x1000"), "name": .string("notified")]),
        ]))
        XCTAssertNil(server.handle(notification))
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.customName, "notified")
    }

    func testHandleLineTransport() {
        let (server, _) = makeServer()
        let line = #"{"jsonrpc":"2.0","id":7,"method":"ping"}"#
        let response = server.handleLine(line)
        XCTAssertTrue(response?.contains("\"id\":7") ?? false)
        // Malformed JSON yields a JSON-RPC parse error.
        XCTAssertTrue(server.handleLine("{not json")?.contains("-32700") ?? false)
        // A blank line yields nothing.
        XCTAssertNil(server.handleLine("   "))
    }

    func testStrictRequestShapesAndDuplicateKeysFailClosed() throws {
        let (server, _) = makeServer()
        XCTAssertEqual(server.handle(.array([]))?["error"]?["code"]?.intValue, -32600)
        XCTAssertEqual(
            server.handle(.object([
                "jsonrpc": .string("2.0"), "id": .bool(true), "method": .string("ping"),
            ]))?["error"]?["code"]?.intValue,
            -32600
        )
        let explicitNull = server.handle(.object([
            "jsonrpc": .string("2.0"), "id": .null, "method": .string("ping"),
        ]))
        XCTAssertEqual(explicitNull?["id"], ScriptValue.null, "an explicit null id is still a request")
        XCTAssertEqual(
            server.handle(request("ping", params: .array([])))?["error"]?["code"]?.intValue,
            -32602
        )
        XCTAssertEqual(
            server.handle(request("tools/call", params: .object([
                "name": .string("info"), "arguments": .array([]),
            ])))?["error"]?["code"]?.intValue,
            -32602
        )
        let duplicate = #"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#
        let duplicateResponse = try ScriptValue.decode(Data(try XCTUnwrap(
            server.handleLine(duplicate)
        ).utf8))
        XCTAssertEqual(duplicateResponse["error"]?["code"]?.intValue, -32700)
    }

    func testHeadlessAuthorityRejectsFilesystemEscapeAndHostileAmplification() {
        let (server, _) = makeServer()
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("mcp-authority-escape-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destination) }

        let denied = server.handle(request("tools/call", params: .object([
            "name": .string("save-patched-binary"),
            "arguments": .object(["path": .string(destination.path)]),
        ])))
        XCTAssertEqual(denied?["result"]?["isError"]?.boolValue, true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))

        let amplified = server.handle(request("tools/call", params: .object([
            "name": .string("read-bytes"),
            "arguments": .object([
                "address": .string("0x1000"), "count": .int(Int64.max),
            ]),
        ])))
        assertMCPToolArgumentError(amplified, field: "count", code: "outOfBounds")

        let smuggled = server.handle(request("tools/call", params: .object([
            "name": .string("info"),
            "arguments": .object(["path": .string("/etc/passwd")]),
        ])))
        assertMCPToolArgumentError(smuggled, field: "path", code: "malformedInput")

        let commands = server.handle(request("tools/call", params: .object([
            "name": .string("commands"),
        ])))?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue ?? ""
        XCTAssertFalse(commands.contains("save-patched-binary"))
        XCTAssertFalse(commands.contains("read-debug-symbols"))
    }

    func testCancellationIsBoundedToOneServerSession() {
        let (cancelledServer, _) = makeServer()
        let (otherServer, _) = makeServer()
        let cancellation = request("notifications/cancelled", id: nil, params: .object([
            "requestId": .int(41), "reason": .string("test"),
        ]))
        XCTAssertNil(cancelledServer.handle(cancellation))

        let call = request("tools/call", id: .int(41), params: .object([
            "name": .string("info"),
        ]))
        XCTAssertEqual(cancelledServer.handle(call)?["error"]?["code"]?.intValue, -32800)
        XCTAssertEqual(otherServer.handle(call)?["result"]?["isError"]?.boolValue, false)
        XCTAssertEqual(
            cancelledServer.handle(call)?["result"]?["isError"]?.boolValue,
            false,
            "a cancellation is consumed exactly once"
        )
    }

    func testExpiredToolResultIsNotPublished() {
        let (_, store) = makeServer()
        var ticks: [UInt64] = [100, 111]
        let server = MCPServer(
            api: WorkspaceScriptingAPI(store: store),
            configuration: .init(
                maximumInputBytes: 1_024,
                maximumOutputBytes: 8_192,
                maximumToolDurationNanoseconds: 10,
                maximumRememberedCancellations: 8
            ),
            monotonicNow: { ticks.removeFirst() }
        )
        let response = server.handle(request("tools/call", params: .object([
            "name": .string("info"),
        ])))
        XCTAssertEqual(response?["error"]?["code"]?.intValue, -32001)
        XCTAssertNil(response?["result"], "a late result never becomes authoritative")
    }

    func testBoundedTransportDrainsOneOversizedLineAndKeepsFraming() throws {
        let (_, store) = makeServer()
        let server = MCPServer(
            api: WorkspaceScriptingAPI(store: store),
            configuration: .init(
                maximumInputBytes: 64,
                maximumOutputBytes: 8_192,
                maximumToolDurationNanoseconds: 1_000_000_000,
                maximumRememberedCancellations: 8
            )
        )
        let input = Pipe()
        let output = Pipe()
        let bytes = Data((String(repeating: "x", count: 80)
            + "\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n").utf8)
        try input.fileHandleForWriting.write(contentsOf: bytes)
        try input.fileHandleForWriting.close()
        server.runStdioLoop(
            input: input.fileHandleForReading,
            output: output.fileHandleForWriting
        )
        try output.fileHandleForWriting.close()
        let transcript = try XCTUnwrap(try output.fileHandleForReading.readToEnd())
        let lines = String(decoding: transcript, as: UTF8.self)
            .split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 2, "one input line produces at most one response")
        XCTAssertEqual(try ScriptValue.decode(Data(lines[0].utf8))["error"]?["code"]?.intValue, -32700)
        XCTAssertEqual(try ScriptValue.decode(Data(lines[1].utf8))["id"]?.intValue, 9)
    }

    func testOversizedResponseBecomesOneCorrelatedProtocolError() throws {
        let (_, store) = makeServer()
        let server = MCPServer(
            api: WorkspaceScriptingAPI(store: store),
            configuration: .init(
                maximumInputBytes: 1_024,
                maximumOutputBytes: 512,
                maximumToolDurationNanoseconds: 1_000_000_000,
                maximumRememberedCancellations: 8
            )
        )
        let responseData = try XCTUnwrap(server.handleMessage(Data(
            #"{"jsonrpc":"2.0","id":"bounded","method":"tools/list"}"#.utf8
        )))
        XCTAssertLessThanOrEqual(responseData.count, 512)
        let response = try ScriptValue.decode(responseData)
        XCTAssertEqual(response["id"]?.stringValue, "bounded")
        XCTAssertEqual(response["error"]?["code"]?.intValue, -32603)
    }

    func testProtocolDescriptorIsolatesIncidentalOutput() throws {
        var protocolDescriptors: [Int32] = [0, 0]
        var incidentalDescriptors: [Int32] = [0, 0]
        XCTAssertEqual(Darwin.pipe(&protocolDescriptors), 0)
        XCTAssertEqual(Darwin.pipe(&incidentalDescriptors), 0)
        let captured = try HeadlessProtocolIO.isolate(
            outputDescriptor: protocolDescriptors[1],
            replacingWith: incidentalDescriptors[1]
        )
        let incidental = Data("library log with secret\n".utf8)
        _ = incidental.withUnsafeBytes {
            Darwin.write(protocolDescriptors[1], $0.baseAddress, $0.count)
        }
        try HeadlessProtocolIO.writeLine(Data(#"{"jsonrpc":"2.0","id":1,"result":{}}"#.utf8), to: captured)
        try captured.close()
        close(protocolDescriptors[1])
        close(incidentalDescriptors[1])

        let protocolRead = FileHandle(fileDescriptor: protocolDescriptors[0], closeOnDealloc: true)
        let incidentalRead = FileHandle(fileDescriptor: incidentalDescriptors[0], closeOnDealloc: true)
        let protocolData = try XCTUnwrap(try protocolRead.readToEnd())
        let incidentalData = try XCTUnwrap(try incidentalRead.readToEnd())
        XCTAssertFalse(String(decoding: protocolData, as: UTF8.self).contains("secret"))
        XCTAssertEqual(String(decoding: incidentalData, as: UTF8.self), "library log with secret\n")
        XCTAssertNoThrow(try ScriptValue.decode(Data(protocolData.dropLast())))
    }

    private var p2ExpectedInstructions: String {
        """
        MacScope MCP server for one Mach-O binary that is already open; there is no open-file step.
        While analysis runs, tools reply notReady; call info (waitForReadyMs from 0 to 25000 waits) until it reports ready.
        Addresses are hex strings such as "0x100003f20", in arguments and in replies.
        Evidence: each completed workspace read appends a text block {generation: UUID} and returns _meta.generation. The first content block keeps its legacy shape. Pass that UUID as optional basedOnGeneration on a write; staleEvidence names basedOnGeneration and currentGeneration without applying the write. Successful writes return the resulting generation; changed annotations can advance it even without reanalysis, so chain the new reply generation or read again. Navigator staleCursor is unchanged.
        Start with info, then list-image-types (classes, categories, protocols, Swift types) or search (mode text, regex or hex), then decompile a function by name or address.
        Graph: callers, callees and xrefs; callers of an _objc_msgSend$<selector> stub lists that selector's call sites.
        Names: name-at, functions, symbols and strings; demangle renders one Swift mangled name.
        Images: search, callers, callees and xrefs rows carry imageSlot; imageSlot or image selects one loaded image; without it, search reads every loaded image and other tools read the primary image.
        Limits depend on image size: large scans and results stop at a budget and say so (a refusal or isTruncated); narrow with limit, kind, imageSlot or a search cursor and retry; a list-image-types explicit limit is still subject to its byte allowance, so continue a default nextCursor as cursor with page:true, fields:"full", limit:1 and the original image/kind.
        Type Atlas: list-image-types total is the whole-filter total and types.count is the admitted default prefix; an explicit limit is additionally byte-capped, and unnamed vtable slots may be summarized as unnamedVtableSlots with vtableSummaryVersion 1. When isTruncated, pass nextCursor as cursor with page:true, fields:"full", limit:1 and the original image/kind. For browsing use page:true, fields:"names" (kind, name or nameContains narrow it); a full-detail page does not carry the default reply's 180,000-byte bound.
        Tools whose description ends "(mutates the workspace)" change workspace state, for example names, comments, types, code/data markup, xrefs, patches, bookmarks, segments, navigation, undo or the open workspace; every other tool is read-only.
        Groups: reads (info, functions, symbols, strings, sections, search, decompile, instructions, read-bytes), graph (callers, callees, xrefs, open-claim, record-callee-outcome, claim-status), types (list-image-types, list-types), edits (the mutating tools), navigator-* (evidence navigator); commands lists the scripting commands.
        """
    }

    // Session guidance tests use explicit listing policy; no process environment is mutated.
    private func p2Reply(_ server: MCPServer, _ method: String, params: ScriptValue? = nil,
                         asynchronous: Bool) async throws -> ScriptValue {
        let data = try request(method, params: params).jsonData()
        let response: Data?
        if asynchronous { response = await server.handleMessageAsync(data) }
        else { response = server.handleMessage(data) }
        return try ScriptValue.decode(try XCTUnwrap(response))
    }

    private func p2Call(_ server: MCPServer, _ name: String, _ arguments: ScriptValue,
                        asynchronous: Bool) async throws -> ScriptValue {
        try await p2Reply(server, "tools/call",
            params: .object(["name": .string(name), "arguments": arguments]), asynchronous: asynchronous)
    }

    private func p2Tools(_ server: MCPServer, asynchronous: Bool) async throws -> [ScriptValue] {
        let reply = try await p2Reply(server, "tools/list", asynchronous: asynchronous)
        XCTAssertNil(reply["error"])
        return try XCTUnwrap(reply["result"]?["tools"]?.arrayValue)
    }

    private func p2Payload(_ reply: ScriptValue) throws -> ScriptValue {
        XCTAssertNil(reply["error"])
        XCTAssertEqual(reply["result"]?["isError"], .bool(false))
        let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }

    func testP2F1InstructionsOnEveryPlainAndAttachedInitialize() async throws {
        let (_, store) = makeServer()
        for attached in [false, true] {
            let configuration: MCPServer.Configuration = attached ? .attached : .production
            for enabled in [false, true] {
                let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: configuration,
                    allowedCommands: attached ? MCPAttachExecutor.attachCommands : nil, listHarnessTools: enabled)
                for asynchronous in [false, true] {
                    for _ in 0..<2 {
                        let reply = try await p2Reply(server, "initialize", asynchronous: asynchronous)
                        XCTAssertNil(reply["error"])
                        XCTAssertEqual(reply["result"]?["instructions"], .string(p2ExpectedInstructions))
                        XCTAssertEqual(MCPServer.sessionInstructions, p2ExpectedInstructions)
                        XCTAssertEqual(p2ExpectedInstructions.split(separator: "\n", omittingEmptySubsequences: false).count, 12)
                        XCTAssertFalse(p2ExpectedInstructions.isEmpty)
                        XCTAssertNil(reply["result"]?["capabilities"]?["experimental"])
                        XCTAssertEqual(reply["result"]?["protocolVersion"], .string(MCPServer.protocolVersion))
                    }
                }
            }
        }
    }

    func testP2F2StartupInstructionsBeforeAndAfterReadyAndFailure() async throws {
        let (_, store) = makeServer()
        for enabled in [false, true] {
            let gate = MCPStartupGate()
            let server = MCPServer(startup: gate, listHarnessTools: enabled)
            for state in ["analyzing", "ready"] {
                if state == "ready" { gate.install(api: WorkspaceScriptingAPI(store: store), validateIdentity: {}) }
                for asynchronous in [false, true] {
                    let reply = try await p2Reply(server, "initialize", asynchronous: asynchronous)
                    XCTAssertNil(reply["error"])
                    XCTAssertEqual(reply["result"]?["instructions"], .string(p2ExpectedInstructions))
                    XCTAssertEqual(reply["result"]?["capabilities"]?["experimental"]?["macscope/analysis"]?["state"], .string(state))
                }
            }
            let failed = MCPStartupGate()
            failed.fail("fixture failure")
            let failedServer = MCPServer(startup: failed, listHarnessTools: enabled)
            let reply = try await p2Reply(failedServer, "initialize", asynchronous: true)
            XCTAssertEqual(reply["result"]?["instructions"], .string(p2ExpectedInstructions))
            XCTAssertEqual(reply["result"]?["capabilities"]?["experimental"]?["macscope/analysis"]?["state"], .string("failed"))
        }
    }

    func testP2F3PlainListingHidesExactlyTwoWithoutChangingRemainingRows() async throws {
        let (_, store) = makeServer()
        let hidden = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let visible = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: true)
        let harness: Set<String> = ["neon-hitrate", "reconstruction-jobs"]
        for asynchronous in [false, true] {
            let all = try await p2Tools(visible, asynchronous: asynchronous)
            let filtered = try await p2Tools(hidden, asynchronous: asynchronous)
            XCTAssertEqual(all.compactMap { $0["name"]?.stringValue }, HeadlessAutomationAuthority.availableCommands.map(\.name))
            XCTAssertEqual(filtered, all.filter { !harness.contains($0["name"]?.stringValue ?? "") })
            XCTAssertEqual(all.count - filtered.count, 2)
            XCTAssertTrue(Set(NavigatorMCPCommands.catalog.map(\.name)).isSubset(of:
                Set(filtered.compactMap { $0["name"]?.stringValue })))
            XCTAssertTrue(harness.isDisjoint(with: Set(filtered.compactMap { $0["name"]?.stringValue })))
            for tool in filtered {
                let name = try XCTUnwrap(tool["name"]?.stringValue)
                let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == name })
                XCTAssertEqual(tool["description"], .string(info.summary + (info.mutates ? " (mutates the workspace)" : "")))
                XCTAssertEqual(tool["annotations"]?["readOnlyHint"], .bool(!info.mutates))
                XCTAssertEqual(tool["annotations"]?["destructiveHint"], .bool(info.mutates))
            }
        }
    }

    func testP2F4StartupListingUsesSameFilter() async throws {
        let (_, store) = makeServer()
        let plain = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let startup = MCPServer(startup: MCPStartupGate(), listHarnessTools: false)
        let startupVisible = MCPServer(startup: MCPStartupGate(), listHarnessTools: true)
        for asynchronous in [false, true] {
            let expected = try await p2Tools(plain, asynchronous: asynchronous)
            let actual = try await p2Tools(startup, asynchronous: asynchronous)
            XCTAssertEqual(actual, expected)
            XCTAssertFalse(actual.contains { ["neon-hitrate", "reconstruction-jobs"].contains($0["name"]?.stringValue ?? "") })
            let visible = try await p2Tools(startupVisible, asynchronous: asynchronous)
            XCTAssertTrue(visible.contains { $0["name"] == .string("neon-hitrate") })
            XCTAssertTrue(visible.contains { $0["name"] == .string("reconstruction-jobs") })
        }
    }

    func testP2F5AttachedIntersectionKeepsNeonExcluded() async throws {
        let (_, store) = makeServer()
        for enabled in [false, true] {
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .attached,
                allowedCommands: MCPAttachExecutor.attachCommands, listHarnessTools: enabled)
            for asynchronous in [false, true] {
                let tools = try await p2Tools(server, asynchronous: asynchronous)
                let names = tools.compactMap { $0["name"]?.stringValue }
                XCTAssertEqual(names.contains("reconstruction-jobs"), enabled)
                XCTAssertFalse(names.contains("neon-hitrate"))
                let expected = HeadlessAutomationAuthority.availableCommands.map(\.name).filter {
                    MCPAttachExecutor.attachCommands.contains($0) && (enabled || $0 != "reconstruction-jobs")
                }
                XCTAssertEqual(names, expected)
            }
        }
    }

    func testP2F6SearchModeSchemaHasOrderedEnum() async throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        for asynchronous in [false, true] {
            let tools = try await p2Tools(server, asynchronous: asynchronous)
            let search = try XCTUnwrap(tools.first { $0["name"] == .string("search") })
            XCTAssertEqual(search["inputSchema"]?["properties"]?["mode"], .object([
                "type": .string("string"), "enum": .array([.string("text"), .string("regex"), .string("hex")])]))
        }
    }

    func testP2F7ModeValidationRejectsUnknownAndNonStringBeforeKind() async throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let bad: [ScriptValue] = [.string("glob"), .int(1), .string(""), .string("TEXT"), .bool(true), .array([]), .object([:])]
        for asynchronous in [false, true] {
            for mode in bad {
                let reply = try await p2Call(server, "search",
                    .object(["query": .string("aa"), "mode": mode, "kind": .string("bytes")]), asynchronous: asynchronous)
                let refusal = assertMCPToolArgumentError(reply, field: "mode", code: "malformedInput")
                XCTAssertEqual(refusal["detail"], .string("Field 'mode' must be text, regex or hex."))
                XCTAssertEqual(refusal["expected"], .string("string"))
                XCTAssertEqual(refusal["allowed"], .array([.string("hex"), .string("regex"), .string("text")]))
            }
            // Exact W9/W10 arguments, without the extra precedence discriminator.
            for mode in [ScriptValue.string("glob"), .int(1)] {
                let reply = try await p2Call(server, "search", .object(["query": .string("aa"), "mode": mode]),
                    asynchronous: asynchronous)
                _ = assertMCPToolArgumentError(reply, field: "mode", code: "malformedInput")
            }
        }
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(command: "search",
            arguments: .object(["query": .string("aa"), "mode": .string("glob")]))) {
            XCTAssertEqual($0 as? HeadlessAutomationAuthorityError, .invalidArguments)
        }
    }

    func testP2F8BothXRefKindSchemasHaveFiveValuesInOrder() async throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let kinds = ["call", "string", "selref", "classref", "data"]
        for asynchronous in [false, true] {
            let tools = try await p2Tools(server, asynchronous: asynchronous)
            for name in ["add-xref", "suppress-xref"] {
                let tool = try XCTUnwrap(tools.first { $0["name"] == .string(name) })
                XCTAssertEqual(tool["inputSchema"]?["properties"]?["kind"], .object([
                    "type": .string("string"), "enum": .array(kinds.map(ScriptValue.string))]))
            }
        }
    }

    func testP2F9InvalidXRefKindsRefuseBeforeMutation() async throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let before = store.snapshot.manualXRefs
        for asynchronous in [false, true] {
            for name in ["add-xref", "suppress-xref"] {
                for kind in [ScriptValue.string("jump"), .string("reference"), .string(""), .int(1), .bool(true)] {
                    let args = ScriptValue.object(["from": .hex(0x1000), "to": .hex(0x1004), "kind": kind])
                    let reply = try await p2Call(server, name, args, asynchronous: asynchronous)
                    let refusal = assertMCPToolArgumentError(reply, field: "kind", code: "malformedInput")
                    XCTAssertEqual(refusal["detail"], .string("Field 'kind' must be call, string, selref, classref or data."))
                    XCTAssertEqual(refusal["expected"], .string("string"))
                    XCTAssertEqual(refusal["allowed"], .array(["call", "classref", "data", "selref", "string"].map(ScriptValue.string)))
                    XCTAssertEqual(store.snapshot.manualXRefs, before)
                }
            }
        }
    }

    func testP2C1HiddenToolsRemainCallable() async throws {
        let (_, store) = makeServer()
        let hidden = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let visible = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: true)
        for asynchronous in [false, true] {
            for name in ["reconstruction-jobs", "neon-hitrate"] {
                let off = try await p2Call(hidden, name, .object([:]), asynchronous: asynchronous)
                let on = try await p2Call(visible, name, .object([:]), asynchronous: asynchronous)
                XCTAssertEqual(off, on)
                XCTAssertNil(off["error"])
                let text = try XCTUnwrap(off["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                XCTAssertFalse(text.contains("unavailable through headless automation"))
                if name == "reconstruction-jobs" {
                    XCTAssertEqual(off["result"]?["isError"], .bool(false))
                } else {
                    XCTAssertEqual(off["result"]?["isError"], .bool(true))
                    XCTAssertTrue(text.contains("neon-hitrate requires only the authorized arm64 libjpeg.8.dylib image within measurement bounds"))
                }
            }
        }
    }

    func testP2C2AllowedNullAndAbsentSearchModesKeepSuccess() async throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
        let cases: [(ScriptValue?, String)] = [(nil, "mov"), (.null, "mov"), (.string("text"), "mov"),
            (.string("regex"), "^mov"), (.string("hex"), "e0 03 01 aa")]
        for asynchronous in [false, true] {
            for (mode, query) in cases {
                var args: [String: ScriptValue] = ["query": .string(query)]
                if let mode { args["mode"] = mode }
                let reply = try await p2Call(server, "search", .object(args), asynchronous: asynchronous)
                _ = try p2Payload(reply)
            }
        }
    }

    func testP2C3DefaultNullAndAllFiveXRefKindsKeepSuccess() async throws {
        for asynchronous in [false, true] {
            for name in ["add-xref", "suppress-xref"] {
                let kinds: [ScriptValue?] = [nil, .null, .string("call"), .string("string"), .string("selref"), .string("classref"), .string("data")]
                for kind in kinds {
                    let (_, store) = makeServer()
                    let server = MCPServer(api: WorkspaceScriptingAPI(store: store), listHarnessTools: false)
                    var fields: [String: ScriptValue] = ["from": .hex(0x1000), "to": .hex(0x1004)]
                    if let kind { fields["kind"] = kind }
                    let reply = try await p2Call(server, name, .object(fields), asynchronous: asynchronous)
                    let result = try p2Payload(reply)
                    XCTAssertEqual(result["ok"], .bool(true))
                    XCTAssertEqual(result["kind"], .string(kind?.stringValue ?? "call"))
                }
            }
        }
    }

    func testP2C4DirectScriptingUnknownModeIsRejected() throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        // 3fe42ef33 (Reject invalid direct search modes) deliberately rejects unknown modes.
        XCTAssertThrowsError(try api.execute("search", arguments: .object(["query": .string("mov"), "mode": .string("glob")]))) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument("search mode must be text, regex or hex"))
        }
        let omitted = try api.execute("search", arguments: .object(["query": .string("mov")]))
        let text = try api.execute("search", arguments: .object(["query": .string("mov"), "mode": .string("text")]))
        XCTAssertEqual(omitted, text)
    }

    func testP2Q1SmallOutputBoundRefusesRatherThanDroppingInstructions() async throws {
        let (_, store) = makeServer()
        let small = MCPServer.Configuration(maximumInputBytes: 1_048_576, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 1_024)
        let servers = [
            MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: small, listHarnessTools: false),
            MCPServer(startup: MCPStartupGate(), configuration: small, listHarnessTools: false),
        ]
        for server in servers {
            for asynchronous in [false, true] {
                let reply = try await p2Reply(server, "initialize", asynchronous: asynchronous)
                let used = try XCTUnwrap(reply["error"]?["data"]?["refusal"]?["used"]?.intValue)
                XCTAssertGreaterThan(used, 512)
                XCTAssertEqual(reply, .object(["jsonrpc": .string("2.0"), "id": .int(1),
                    "error": .object([
                        "code": .int(-32603), "message": .string("Response exceeds limit"),
                        "data": .object([
                            "error": .string("refused"),
                            "refusal": .object([
                                "code": .string("budgetExceeded"),
                                "detail": .string("Frame limit exceeded."),
                                "retryable": .bool(false),
                                "budget": .object(["unit": .string("bytes"), "limit": .int(512)]),
                                "used": .int(used), "narrowing": .array([])
                            ])
                        ])
                    ])]))
                XCTAssertNil(reply["result"])
            }
        }
    }

    func testFinalFrameCountsLFAndPreservesCorrelatedFallback() throws {
        let id: MacScopeAnalysisCore.Phase2ProductionJSONValue = .string("request")
        let response = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": .integer(0), "result": .string("ok")
        ]).canonicalJSONBytes()
        let encoded = try MCPFrameAdmission.response(response, id: id, maximumBytes: 512)
        XCTAssertTrue(MCPFrameAdmission.fits(encoded, maximumBytes: encoded.count + 1))
        XCTAssertFalse(MCPFrameAdmission.fits(encoded, maximumBytes: encoded.count))
        XCTAssertEqual(try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(encoded, limits: .providerEnvelope).objectValue?["id"], id)

        let large = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": .integer(0), "result": .string(String(repeating: "x", count: 600))
        ]).canonicalJSONBytes()
        let fallback = try MCPFrameAdmission.response(large, id: id, maximumBytes: 512)
        let parsed = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(fallback, limits: .providerEnvelope)
        XCTAssertEqual(parsed.objectValue?["id"], id)
        XCTAssertNotNil(parsed.objectValue?["error"])
        XCTAssertLessThan(fallback.count, 512)
        let malformed = try MCPFrameAdmission.response(Data("{}".utf8), id: id, maximumBytes: 512)
        let malformedReply = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(malformed, limits: .providerEnvelope)
        XCTAssertEqual(malformedReply.objectValue?["id"], id)
        XCTAssertNotNil(malformedReply.objectValue?["error"])
        let deadline = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": .integer(0),
            "error": .object(["code": .integer(-32001), "message": .string(String(repeating: "x", count: 600))])
        ]).canonicalJSONBytes()
        let terminal = try MCPFrameAdmission.response(deadline, id: id, maximumBytes: 512)
        XCTAssertEqual(try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(terminal, limits: .providerEnvelope)
            .objectValue?["error"]?.objectValue?["code"], .integer(-32001))
        let mutation = try MCPFrameAdmission.response(deadline, id: id, maximumBytes: 512,
            failureMessage: "Mutation outcome unknown; do not retry automatically.", compactMessage: "Outcome unknown; no retry")
        let mutationError = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(mutation, limits: .providerEnvelope)
            .objectValue?["error"]?.objectValue
        XCTAssertEqual(mutationError?["code"], .integer(-32603))
        XCTAssertEqual(mutationError?["message"], .string("Mutation outcome unknown; do not retry automatically."))
        XCTAssertThrowsError(try MCPFrameAdmission.response(large,
            id: .string(String(repeating: "\\", count: 256)), maximumBytes: 512))
    }

    func testUnrepresentableFrameClosesSessionBeforeFurtherWork() async throws {
        let output = MCPAsyncTestOutput()
        let session = MCPRequestSession(configuration: .init(maximumInputBytes: 4096,
            maximumOutputBytes: 512, maximumToolDurationNanoseconds: 5_000_000_000,
            maximumRememberedCancellations: 8), mutatingCommands: [],
            execute: { _ in Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8) },
            output: { await output.append($0) })
        let id = String(repeating: "\\", count: 256)
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .string(id), "method": .string("ping")])
        await session.receive(try request.jsonData())
        for _ in 0..<200 {
            if !(await session.isAcceptingRequests) { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let accepting = await session.isAcceptingRequests
        XCTAssertFalse(accepting)
        let before = await output.count
        XCTAssertEqual(before, 0)
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8))
        await session.finishInput()
        let after = await output.count
        XCTAssertEqual(after, 0)
    }

    func testFailedConnectionRejectsNewMutationAndKeepsUnknownOutcome() throws {
        enum Failure: Error { case interrupted }
        let fence = MCPConnectionFence()
        let outcome = MCPMutationOutcome()
        try MCPExecutionFence.$connection.withValue(fence) {
            try MCPExecutionFence.$outcome.withValue(outcome) {
                XCTAssertThrowsError(try MCPExecutionFence.commit { throw Failure.interrupted })
                XCTAssertEqual(outcome.snapshot, .unknown)
                fence.fail()
                var invoked = false
                XCTAssertThrowsError(try MCPExecutionFence.commit { invoked = true })
                XCTAssertFalse(invoked)
            }
        }
    }

    func testSyncTransportRejectsUnrepresentableIDWithoutWritingAFrame() throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8))
        let input = Pipe(), output = Pipe()
        let request = ScriptValue.object(["jsonrpc": .string("2.0"),
            "id": .string(String(repeating: "\\", count: 256)), "method": .string("ping")])
        try input.fileHandleForWriting.write(contentsOf: try request.jsonData() + Data([10]))
        try input.fileHandleForWriting.close()
        server.runStdioLoop(input: input.fileHandleForReading, output: output.fileHandleForWriting)
        try output.fileHandleForWriting.close()
        XCTAssertTrue(try (output.fileHandleForReading.readToEnd() ?? Data()).isEmpty)
        XCTAssertNil(server.handleMessage(Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8)))
    }

    func testUnrepresentableMutationReplyKeepsCommittedEditAndClosesConnection() throws {
        let (_, store) = makeServer()
        let api = WorkspaceScriptingAPI(store: store)
        let server = MCPServer(api: api, configuration: .init(maximumInputBytes: 4096,
            maximumOutputBytes: 512, maximumToolDurationNanoseconds: 5_000_000_000,
            maximumRememberedCancellations: 8))
        let first = request("tools/call", id: .string(String(repeating: "\\", count: 256)), params: .object([
            "name": .string("set-comment"),
            "arguments": .object(["address": .string("0x1000"), "comment": .string("first")])
        ]))
        XCTAssertNil(server.handleMessage(try first.jsonData()))
        let second = request("tools/call", id: .int(2), params: .object([
            "name": .string("set-comment"),
            "arguments": .object(["address": .string("0x1000"), "comment": .string("second")])
        ]))
        XCTAssertNil(server.handleMessage(try second.jsonData()))
        let rows = try api.execute("instructions", arguments: .object(["address": .string("0x1000"), "count": .int(1)]))
        XCTAssertEqual(rows.arrayValue?.first?["comment"], .string("first"))
    }

    func testEncodeBoundedContainsOverdeepWholeResponse() throws {
        let (server, _) = makeServer()
        var deep = ScriptValue.string("leaf")
        for _ in 0..<(ScriptValue.maximumEncodingDepth + 2) { deep = .object(["next": deep]) }
        let response = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(7), "result": deep])
        let data = try XCTUnwrap(server.encodeBounded(response))
        let decoded = try ScriptValue.decode(data)
        XCTAssertEqual(decoded["id"]?.intValue, 7)
        XCTAssertEqual(decoded["error"]?["code"]?.intValue, -32603)
        XCTAssertEqual(decoded["error"]?["message"]?.stringValue, "Response exceeds limit")
        XCTAssertNil(decoded["result"])
        XCTAssertNotNil(server.encodeBounded(.object(["jsonrpc": .string("2.0"), "id": .int(8), "result": .null])))
    }

    func testAsyncTransportStopsReadingAfterUnrepresentableFrame() async throws {
        let (_, store) = makeServer()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8))
        let input = Pipe(), output = Pipe()
        let finished = expectation(description: "transport stops without input EOF")
        let task = Task {
            await server.runStdioLoopAsync(input: input.fileHandleForReading, output: output.fileHandleForWriting)
            finished.fulfill()
        }
        let request = ScriptValue.object(["jsonrpc": .string("2.0"),
            "id": .string(String(repeating: "\\", count: 256)), "method": .string("ping")])
        try input.fileHandleForWriting.write(contentsOf: try request.jsonData() + Data([10]))
        await fulfillment(of: [finished], timeout: 5)
        try input.fileHandleForWriting.close()
        await task.value
        try output.fileHandleForWriting.close()
        XCTAssertTrue(try (output.fileHandleForReading.readToEnd() ?? Data()).isEmpty)
    }
}

private struct MutationReportingFixtureLoader: BinaryLoader {
    let binary: LoadedBinary
    func load(at url: URL) throws -> LoadedBinary { binary }
}

private actor MCPAsyncTestOutput {
    private(set) var values: [Data] = []
    var count: Int { values.count }
    func append(_ data: Data) { values.append(data) }
}

private actor MCPAsyncTestGate {
    private var started = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var blocked: [CheckedContinuation<Void, Never>] = []
    func markStarted() {
        started = true
        let waiters = startWaiters
        startWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
    }
    func suspend() async {
        markStarted()
        if !released { await withCheckedContinuation { blocked.append($0) } }
    }
    func waitUntilStarted() async {
        if !started { await withCheckedContinuation { startWaiters.append($0) } }
    }
    func release() {
        released = true
        let waiters = blocked
        blocked.removeAll()
        for waiter in waiters { waiter.resume() }
    }
}
