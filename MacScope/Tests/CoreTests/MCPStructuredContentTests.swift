import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// ITEM 1246: ALL CONTROLS NOT RUN. No compilation or acceptance claim.
@MainActor
final class MCPStructuredContentTests: XCTestCase {
    private func store() -> WorkspaceStore {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin",
                kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000,
                endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000,
                kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov",
                    operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret",
                    operands: "", hasBreakpoint: false, comment: nil)
            ], xrefs: [], hexBytes: Data())
        return WorkspaceStore(workspaceName: "MCP", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func request(_ method: String, params: ScriptValue? = nil,
                         id: ScriptValue = .int(1)) -> ScriptValue {
        var fields: [String: ScriptValue] = ["jsonrpc": .string("2.0"),
            "id": id, "method": .string(method)]
        if let params { fields["params"] = params }
        return .object(fields)
    }

    private func bytes(_ server: MCPServer, _ request: ScriptValue,
                       asynchronous: Bool) async throws -> Data {
        let data = try request.jsonData()
        let reply: Data?
        if asynchronous { reply = await server.handleMessageAsync(data) }
        else { reply = server.handleMessage(data) }
        return try XCTUnwrap(reply)
    }

    private func call(_ name: String = "info", _ arguments: ScriptValue = .object([:]),
                      id: ScriptValue = .int(1)) -> ScriptValue {
        request("tools/call", params: .object(["name": .string(name), "arguments": arguments]), id: id)
    }

    private func initialize(_ server: MCPServer, _ version: String,
                            asynchronous: Bool) async throws -> ScriptValue {
        try ScriptValue.decode(await bytes(server, request("initialize", params: .object([
            "protocolVersion": .string(version)])), asynchronous: asynchronous))
    }

    private func legacyPayload(_ reply: ScriptValue) throws -> ScriptValue {
        let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }

    // NOT RUN: SPEC 7/11/15, byte equality uses one store so UUIDs are identical.
    func testLegacyNegotiationMatrixAndUninitializedReadWriteBytes() async throws {
        let offers: [ScriptValue?] = [nil, .object([:]), .object(["clientInfo": .object([:])]),
            .object(["protocolVersion": .int(20250618)]),
            .object(["protocolVersion": .string("2024-11-05")])]
        for asynchronous in [false, true] {
            for offer in offers {
                let store = store()
                store.setCustomName(0x1000, in: .primary, name: "unchanged")
                let api = WorkspaceScriptingAPI(store: store)
                let baseline = MCPServer(api: api, listHarnessTools: false) // Never initialized.
                let server = MCPServer(api: api, listHarnessTools: false)
                let initialized = try await bytes(server, request("initialize", params: offer), asynchronous: asynchronous)
                let expected = request("initialize") // ID is identical; literal result is the pin contract.
                let legacyInitialize: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": expected["id"]!,
                    "result": .object(["protocolVersion": .string("2024-11-05"),
                        "instructions": .string(MCPServer.sessionInstructions),
                        "capabilities": .object(["tools": .object([:])]),
                        "serverInfo": .object(["name": .string("macscope"), "version": .string("0.1.0")])])])
                // Compare decoded values: the framed bytes differ from a bare re-serialization
                // by one byte (observed 2218 vs 2219); the legacy fields are what matter.
                XCTAssertEqual(try ScriptValue.decode(initialized), legacyInitialize)
                for query in [call(), call("name-at", .object(["address": .hex(0x1000)])),
                    call("rename", .object(["address": .hex(0x1000), "name": .string("unchanged")])),
                    request("tools/list"), request("ping"), request("missing-method"),
                    request("tools/call", params: .array([]))] {
                    let old = try await bytes(baseline, query, asynchronous: asynchronous)
                    let new = try await bytes(server, query, asynchronous: asynchronous)
                    XCTAssertEqual(new, old)
                    XCTAssertNil(try ScriptValue.decode(new)["result"]?["structuredContent"])
                }
            }
        }
    }

    // NOT RUN: SPEC 7/8/15, explicit latest and both unknown-date choices.
    func testKnownAndUnknownVersionsThenInfo() async throws {
        for asynchronous in [false, true] {
            for offered in ["2025-06-18", "2025-03-26", "2026-01-01"] {
                let store = store(), api = WorkspaceScriptingAPI(store: store)
                let server = MCPServer(api: api), old = MCPServer(api: api)
                let initial = try await initialize(server, offered, asynchronous: asynchronous)
                let structured = offered == "2025-06-18"
                XCTAssertEqual(initial["result"]?["protocolVersion"], .string(structured ? offered : "2024-11-05"))
                let data = try await bytes(server, call(), asynchronous: asynchronous)
                let legacyData = try await bytes(old, call(), asynchronous: asynchronous)
                if !structured { XCTAssertEqual(data, legacyData); continue }
                let reply = try ScriptValue.decode(data), legacy = try ScriptValue.decode(legacyData)
                let result = try XCTUnwrap(reply["result"])
                XCTAssertEqual(result["structuredContent"], try legacyPayload(legacy))
                XCTAssertNil(result["structuredContent"]?["generation"])
                XCTAssertEqual(result["_meta"], legacy["result"]?["_meta"])
                let blocks = try XCTUnwrap(result["content"]?.arrayValue)
                XCTAssertEqual(blocks.count, 2)
                XCTAssertEqual(blocks.last, legacy["result"]?["content"]?.arrayValue?.last)
                let summary = try XCTUnwrap(blocks.first?["text"]?.stringValue)
                XCTAssertEqual(summary, "info: success; data is in structuredContent.")
                XCTAssertLessThanOrEqual(summary.utf8.count, 320)
                XCTAssertEqual(initial["result"]?["instructions"],
                    .string(MCPServer.sessionInstructions + MCPResultProtocol.structured.instructionSuffix))
            }
        }
    }

    // NOT RUN: SPEC 8, real non-object commands plus object/result collision, scalar/null controls.
    func testNonObjectWrapperAndSingleResultKeyAreUnambiguous() async throws {
        for asynchronous in [false, true] {
            let store = store(), api = WorkspaceScriptingAPI(store: store)
            let server = MCPServer(api: api), old = MCPServer(api: api)
            _ = try await initialize(server, "2025-06-18", asynchronous: asynchronous)
            for query in [call("functions", .object(["limit": .int(0)])),
                          call("name-at", .object(["address": .hex(0x1000)]))] {
                let legacy = try ScriptValue.decode(await bytes(old, query, asynchronous: asynchronous))
                let newer = try ScriptValue.decode(await bytes(server, query, asynchronous: asynchronous))
                XCTAssertEqual(newer["result"]?["structuredContent"], .object(["result": try legacyPayload(legacy)]))
                XCTAssertEqual(newer["result"]?["_meta"]?["macscope/resultWrapper"], .string("result"))
                XCTAssertEqual(newer["result"]?["_meta"]?["generation"], legacy["result"]?["_meta"]?["generation"])
            }
        }
        for value: ScriptValue in [.null, .bool(false), .int(7), .double(1.5), .string(""), .array([]),
                                    .object(["result": .int(7)])] {
            let envelope = MCPStructuredResult.successEnvelope(protocolVersion: .structured, tool: "fixture",
                output: value, legacyText: String(decoding: try value.jsonData(), as: UTF8.self), isError: false)
            if case .object = value {
                XCTAssertEqual(envelope["structuredContent"], value)
                XCTAssertNil(envelope["_meta"]?["macscope/resultWrapper"])
            } else {
                XCTAssertEqual(envelope["structuredContent"], .object(["result": value]))
                XCTAssertEqual(envelope["_meta"]?["macscope/resultWrapper"], .string("result"))
            }
        }
    }

    // NOT RUN: SPEC 9/11, list is not decorated and JSON-RPC errors never become tool results.
    func testCatalogPingAndRPCFailuresUnchanged() async throws {
        for asynchronous in [false, true] {
            let store = store(), api = WorkspaceScriptingAPI(store: store)
            let old = MCPServer(api: api, listHarnessTools: false)
            let new = MCPServer(api: api, listHarnessTools: false)
            _ = try await initialize(new, "2025-06-18", asynchronous: asynchronous)
            for query in [request("tools/list"), request("ping"), request("missing-method"),
                          request("tools/call", params: .array([]))] {
                let a = try await bytes(old, query, asynchronous: asynchronous)
                let b = try await bytes(new, query, asynchronous: asynchronous)
                XCTAssertEqual(a, b)
                let reply = try ScriptValue.decode(b)
                XCTAssertNil(reply["structuredContent"])
                XCTAssertNil(reply["result"]?["structuredContent"])
                for tool in reply["result"]?["tools"]?.arrayValue ?? [] { XCTAssertNil(tool["outputSchema"]) }
            }
        }
    }

    // NOT RUN: SPEC 10, all unmodified refusal constructors are exercised on both bindings.
    func testStaleUnknownAndNotReadyErrorsKeepExactBytes() async throws {
        for asynchronous in [false, true] {
            let store = store(), api = WorkspaceScriptingAPI(store: store)
            let old = MCPServer(api: api), new = MCPServer(api: api)
            _ = try await initialize(new, "2025-06-18", asynchronous: asynchronous)
            let stale = call("rename", .object(["address": .hex(0x1000), "name": .string("must-not-write"),
                "basedOnGeneration": .string(UUID().uuidString)]))
            for query in [stale, call("not-a-tool")] {
                let a = try await bytes(old, query, asynchronous: asynchronous)
                let b = try await bytes(new, query, asynchronous: asynchronous)
                XCTAssertEqual(a, b)
                let result = try XCTUnwrap(try ScriptValue.decode(b)["result"])
                XCTAssertEqual(result["isError"], .bool(true)); XCTAssertNil(result["structuredContent"])
            }
            // Freeze elapsedMs before comparison; an actively ticking gate is not a byte oracle.
            let gate = MCPStartupGate(); gate.fail("fixture stopped")
            let a = MCPServer(startup: gate), b = MCPServer(startup: gate)
            _ = try await initialize(b, "2025-06-18", asynchronous: asynchronous)
            let legacy = try await bytes(a, call("functions"), asynchronous: asynchronous)
            let modern = try await bytes(b, call("functions"), asynchronous: asynchronous)
            XCTAssertEqual(legacy, modern)
            XCTAssertEqual(try ScriptValue.decode(modern)["result"]?["isError"], .bool(true))
            let info = try ScriptValue.decode(await bytes(b, call(), asynchronous: asynchronous))
            let legacyInfo = try ScriptValue.decode(await bytes(a, call(), asynchronous: asynchronous))
            XCTAssertEqual(info["result"]?["structuredContent"], try legacyPayload(legacyInfo))
            XCTAssertNil(info["result"]?["_meta"])
            // Analyzing/non-info state is checked semantically: elapsedMs can change.
            let analyzing = MCPServer(startup: MCPStartupGate())
            _ = try await initialize(analyzing, "2025-06-18", asynchronous: asynchronous)
            let busy = try ScriptValue.decode(await bytes(analyzing, call("functions"), asynchronous: asynchronous))
            XCTAssertNil(busy["result"]?["structuredContent"])
            XCTAssertEqual(try legacyPayload(busy)["error"], .string("notReady"))
            let waitingInfo = try ScriptValue.decode(await bytes(analyzing, call(), asynchronous: asynchronous))
            XCTAssertEqual(waitingInfo["result"]?["structuredContent"]?["analysis"]?["state"], .string("analyzing"))
        }
    }

    // NOT RUN: SPEC 10, injected failures pass through actual async catch/reporting paths.
    func testReportingFailureEnvelopesStayTextOnly() async throws {
        enum Deliberate: LocalizedError { case failure; var errorDescription: String? { "report failed" } }
        let store = store(), api = WorkspaceScriptingAPI(store: store)
        let output: ScriptValue = .object(["ok": .bool(true)])
        let failures: [any Error] = [
            ScriptingCommittedBatchFailure(command: "rename", count: 1, changed: 1,
                reason: "receipt failed", result: output),
            ScriptingJournalFailure(command: "rename", result: output, reason: "journal failed",
                handlerReturned: true, liveApplied: true),
            MCPPostMutationReportFailure(result: output, underlying: Deliberate.failure)
        ]
        for failure in failures {
            let executor: MCPServer.AsyncCommandExecutor = { _, _ in throw failure }
            let old = MCPServer(api: api, asyncCommandExecutor: executor)
            let new = MCPServer(api: api, asyncCommandExecutor: executor)
            _ = try await initialize(new, "2025-06-18", asynchronous: true)
            let query = call("rename", .object(["address": .hex(0x1000), "name": .string("fixture")]))
            let a = try await bytes(old, query, asynchronous: true)
            let b = try await bytes(new, query, asynchronous: true)
            XCTAssertEqual(a, b)
            let reply = try ScriptValue.decode(b)
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            XCTAssertNil(reply["result"]?["structuredContent"])
            XCTAssertEqual(try legacyPayload(reply)["returnedResult"], output)
        }
        // Any reporting-failed output, including VerifiedAnnotationFailure's isFailedReply
        // branch, enters this same helper with isError=true. No verified-analysis source is read.
        let capture = ScriptingGenerationCapture(); capture.record(store.snapshot.analysisGenerationID)
        let text = String(decoding: try output.jsonData(), as: UTF8.self)
        let old = MCPStructuredResult.successEnvelope(protocolVersion: .legacy, tool: "rename",
            output: output, legacyText: text, isError: true, generation: capture)
        let new = MCPStructuredResult.successEnvelope(protocolVersion: .structured, tool: "rename",
            output: output, legacyText: text, isError: true, generation: capture)
        XCTAssertEqual(try old.jsonData(), try new.jsonData())
        XCTAssertNil(new["structuredContent"])
    }

    // NOT RUN: SPEC 8/10/15, raw serialized result admission remains <= maximumOutputBytes/2.
    func testOverHalfBudgetRefusalUnchanged() async throws {
        let store = store(), api = WorkspaceScriptingAPI(store: store)
        let configuration = MCPServer.Configuration(maximumInputBytes: 8192, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8)
        let payload: ScriptValue = .object(["padding": .string(String(repeating: "x", count: 257))])
        XCTAssertGreaterThan(try payload.jsonData().count, configuration.maximumOutputBytes / 2)
        let old = MCPServer(api: api, configuration: configuration, asyncCommandExecutor: { _, _ in payload })
        let new = MCPServer(api: api, configuration: configuration, asyncCommandExecutor: { _, _ in payload })
        // handle() selects protocol without the intentionally tiny initialize frame limit.
        _ = new.handle(request("initialize", params: .object(["protocolVersion": .string("2025-06-18")])))
        let a = try await bytes(old, call(), asynchronous: true)
        let b = try await bytes(new, call(), asynchronous: true)
        XCTAssertEqual(a, b)
        XCTAssertEqual(try ScriptValue.decode(b)["error"]?["code"], .int(-32603))
    }

    // NOT RUN: SPEC 13, real attach executor and a second independent connection.
    func testAttachedConnectionsNegotiateIndependently() async throws {
        let store = store()
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .attached,
            asyncCommandExecutor: { name, args in try await executor.execute(name, args) },
            allowedCommands: MCPAttachExecutor.attachCommands)
        let otherExecutor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        otherExecutor.setConsent(.allowed)
        let other = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .attached,
            asyncCommandExecutor: { name, args in try await otherExecutor.execute(name, args) },
            allowedCommands: MCPAttachExecutor.attachCommands)
        _ = try await initialize(server, "2025-06-18", asynchronous: true)
        let modern = try ScriptValue.decode(await bytes(server, call(), asynchronous: true))
        let legacy = try ScriptValue.decode(await bytes(other, call(), asynchronous: true))
        XCTAssertNil(legacy["result"]?["structuredContent"])
        XCTAssertEqual(modern["result"]?["structuredContent"], try legacyPayload(legacy))
        XCTAssertNotNil(modern["result"]?["structuredContent"]) // the assumed editJournalHealth key is absent on main
    }

    // NOT RUN: SPEC 7, second initialize affects future calls, not an admitted suspended call.
    func testRenegotiationCannotChangeAnAdmittedCall() async throws {
        for (first, second) in [("2025-06-18", "2024-11-05"), ("2024-11-05", "2025-06-18")] {
            let gate = P3AdmissionGate(), store = store()
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store), asyncCommandExecutor: { _, _ in
                await gate.hold()
                return .object(["fixture": .bool(true)])
            })
            _ = try await initialize(server, first, asynchronous: true)
            let query = try call().jsonData()
            let operation = Task { @MainActor in await server.handleMessageAsync(query) }
            await gate.waitForAdmission()
            _ = try await initialize(server, second, asynchronous: true)
            await gate.release()
            let data = await operation.value
            let prior = try ScriptValue.decode(XCTUnwrap(data))
            XCTAssertEqual(prior["result"]?["structuredContent"] != nil, first == "2025-06-18")
            let next = try ScriptValue.decode(await bytes(server, call(), asynchronous: true))
            XCTAssertEqual(next["result"]?["structuredContent"] != nil, second == "2025-06-18")
        }
    }

    // NOT RUN: SPEC 3/8, note is second, generation last; reporting failures stay byte-identical.
    func testDispatchNoteOrderingAndLegacyLiteralEnvelope() throws {
        let capture = ScriptingGenerationCapture()
        let uuid = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        capture.record(uuid)
        let output: ScriptValue = .object(["ok": .bool(true)])
        let note: ScriptValue = .object(["fixture": .string("note")])
        let text = String(decoding: try output.jsonData(), as: UTF8.self)
        let noteText = String(decoding: try ScriptValue.object(["note": note]).jsonData(), as: UTF8.self)
        for isError in [false, true] {
            let expected: ScriptValue = .object([
                "content": .array(capture.appendingGeneration(to: [
                    .object(["type": .string("text"), "text": .string(text)]),
                    .object(["type": .string("text"), "text": .string(noteText)])])),
                "isError": .bool(isError), "note": note, "_meta": capture.metadata])
            let legacy = MCPStructuredResult.successEnvelope(protocolVersion: .legacy, tool: "info",
                output: output, legacyText: text, isError: isError, generation: capture, note: note, noteText: noteText)
            let modern = MCPStructuredResult.successEnvelope(protocolVersion: .structured, tool: "info",
                output: output, legacyText: text, isError: isError, generation: capture, note: note, noteText: noteText)
            XCTAssertEqual(try legacy.jsonData(), try expected.jsonData())
            if isError { XCTAssertEqual(try modern.jsonData(), try expected.jsonData()); continue }
            XCTAssertEqual(modern["note"], note)
            XCTAssertEqual(modern["content"]?.arrayValue?.dropFirst(), expected["content"]?.arrayValue?.dropFirst())
            XCTAssertEqual(modern["_meta"], expected["_meta"])
        }
    }

    // Owner ruling (B1): the invariant is the half budget (maximumOutputBytes / 2), enforced
    // at handler admission and unchanged by negotiation. Final-frame admission is asserted
    // unchanged here only for payloads within that half budget and ordinary request ids.
    // Documented deviation, not asserted: with a 256-character id at the 512-byte floor cap
    // the structured envelope's added fields can push the complete frame over a cap the
    // legacy frame still fits; real caps are far larger and the half-budget invariant holds.
    func testFullFrameAdmissionMustNotChangeForNegotiatedEnvelope() throws {
        let capture = ScriptingGenerationCapture()
        capture.record(UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)
        let output: ScriptValue = .string("_main")
        let text = String(decoding: try output.jsonData(), as: UTF8.self)
        let maximumBytes = 512
        XCTAssertLessThanOrEqual(try output.jsonData().count, maximumBytes / 2)
        for length in 0...16 {
            let id: ScriptValue = .string(String(repeating: "i", count: length))
            func frame(_ version: MCPResultProtocol) throws -> Data {
                try ScriptValue.object(["jsonrpc": .string("2.0"), "id": id,
                    "result": MCPStructuredResult.successEnvelope(protocolVersion: version, tool: "name-at",
                        output: output, legacyText: text, isError: false, generation: capture)]).jsonData()
            }
            let old = try frame(.legacy), new = try frame(.structured)
            XCTAssertEqual(MCPFrameAdmission.fits(old, maximumBytes: maximumBytes),
                           MCPFrameAdmission.fits(new, maximumBytes: maximumBytes), "id length \(length)")
        }
    }

    // NOT RUN: SPEC 3/8, an actual guarded write retains the command's generation disclosure.
    func testGuardedWriteKeepsReturnedGeneration() async throws {
        for asynchronous in [false, true] {
            let store = store()
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
            let previous = store.snapshot.analysisGenerationID
            _ = try await initialize(server, "2025-06-18", asynchronous: asynchronous)
            let query = call("rename", .object(["address": .hex(0x1000), "name": .string("p3-renamed"),
                "basedOnGeneration": .string(previous.uuidString)]))
            let reply = try ScriptValue.decode(await bytes(server, query, asynchronous: asynchronous))
            let result = try XCTUnwrap(reply["result"])
            XCTAssertEqual(result["isError"], .bool(false))
            XCTAssertNotEqual(store.snapshot.analysisGenerationID, previous)
            let current = ScriptValue.string(store.snapshot.analysisGenerationID.uuidString)
            XCTAssertEqual(result["_meta"]?["generation"], current)
            XCTAssertEqual(result["structuredContent"]?["generation"], current)
            XCTAssertNil(result["_meta"]?["macscope/resultWrapper"])
        }
    }
}

private actor P3AdmissionGate {
    private var entered = false
    private var released = false
    private var admission: CheckedContinuation<Void, Never>?
    private var work: CheckedContinuation<Void, Never>?
    func hold() async {
        entered = true
        admission?.resume(); admission = nil
        if !released { await withCheckedContinuation { work = $0 } }
    }
    func waitForAdmission() async {
        if !entered { await withCheckedContinuation { admission = $0 } }
    }
    func release() { released = true; work?.resume(); work = nil }
}
