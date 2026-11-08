import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

// Authored, unrun. Invariant/control byte oracles for the public handlers over
// TinyMachO, plus derived fixed-error bytes; not a historical executable capture.
// Only refusal/read paths are exercised; the control encoder assumes notStarted.
@MainActor
final class MCPColdStartEquivalenceTests: XCTestCase {
    private static let code = Data([0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6])

    private func readyAPI() async throws -> WorkspaceScriptingAPI {
        let url = try TinyMachO.make(code: Self.code).write()
        addTeardownBlock { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let snapshot = try await AnalysisEngine().openBinary(
            url: url, selection: .machOSlice(nil), overrides: [:],
            cancellation: .budgeted(progress: { _ in }))
        return WorkspaceScriptingAPI(store: WorkspaceStore(
            workspaceName: "1282-control", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil))
    }

    private func request(_ method: String, id: ScriptValue = .int(1),
                         params: ScriptValue? = nil) throws -> Data {
        var fields: [String: ScriptValue] = [
            "jsonrpc": .string("2.0"), "id": id, "method": .string(method)
        ]
        if let params { fields["params"] = params }
        return try ScriptValue.object(fields).jsonData()
    }

    private func tool(_ name: String, arguments: ScriptValue = .object([:]),
                      id: ScriptValue = .int(1)) throws -> Data {
        try request("tools/call", id: id,
                    params: .object(["name": .string(name), "arguments": arguments]))
    }

    private func validID(_ id: ScriptValue) -> Bool {
        switch id {
        case .null, .int: return true
        case .double(let number): return number.isFinite
        case .string(let text):
            return text.utf8.count <= 256 &&
                !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        default: return false
        }
    }

    // Derived from MCPServer.swift:2190-2229 and :2840-2860.
    // Public handle() remains the same-build semantic oracle; no private helper is called.
    private func legacyControl(_ data: Data, server: MCPServer,
                               configuration: MCPServer.Configuration = .production) throws -> Data? {
        guard !data.allSatisfy({ [0x20, 0x09, 0x0a, 0x0d].contains($0) }) else { return nil }
        let request: ScriptValue
        do {
            request = try HeadlessJSON.decode(data, maximumBytes: configuration.maximumInputBytes)
        } catch {
            return Data(#"{"error":{"code":-32700,"message":"Parse error"},"id":null,"jsonrpc":"2.0"}"#.utf8)
        }
        var original: MacScopeAnalysisCore.Phase2ProductionJSONValue?
        if let id = request["id"], validID(id) {
            original = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(
                data, limits: .init(maximumBytes: configuration.maximumInputBytes, maximumDepth: 16,
                                    maximumTokens: 100_000, maximumMembersAndElements: 50_000)).objectValue?["id"]
        }
        if request["jsonrpc"] == .string("2.0"),
           request["method"] == .string("tools/call"),
           let name = request["params"]?["name"]?.stringValue,
           MCPBatchReceiptBudget.commands.contains(name), let original,
           !MCPBatchReceiptBudget.admits(idBytes: original.canonicalJSONBytes().count,
                                         maximumBytes: configuration.maximumOutputBytes) {
            return try MCPBatchReceiptBudget.refusalFrame(id: original,
                                                          maximumBytes: configuration.maximumOutputBytes)
        }
        guard let response = server.handle(request) else { return nil }
        let encoded = try response.jsonData()
        let idBytes = try (response["id"] ?? .null).jsonData()
        let id = try original ?? MacScopeAnalysisCore.Phase2StrictJSONParser().parse(idBytes, limits: .providerEnvelope)
        return try MCPFrameAdmission.response(encoded, id: id,
                                               maximumBytes: configuration.maximumOutputBytes)
    }

    private func corpus() throws -> [Data] {
        [
            try request("initialize", params: .object([:])),
            try request("tools/list"), try tool("commands"),
            try tool("not-a-tool"), try tool("commands", arguments: .object(["unexpected": .bool(true)])),
            try tool("rename", arguments: .object([:])),
            Data(#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"ping"}"#.utf8),
            Data(repeating: 0x78, count: 1_048_577),
            Data(#"{"jsonrpc":"2.0","id":1.0,"method":"ping"}"#.utf8),
            try request("ping", id: .string(String(repeating: "a", count: 13_000)))
        ]
    }

    // Invariant/control, not red-on-pin. After landing this detects wiring byte drift.
    func testReadyPublicSyncAndAsyncBytesAgainstLegacyControl() async throws {
        let api = try await readyAPI()
        let readOnly = Set(HeadlessAutomationAuthority.availableCommands.filter { !$0.mutates }.map(\.name))
        let sync = MCPServer(api: api, allowedCommands: readOnly, listHarnessTools: false)
        let async = MCPServer(api: api, allowedCommands: readOnly, listHarnessTools: false)
        let control = MCPServer(api: api, allowedCommands: readOnly, listHarnessTools: false)
        let inputs = try corpus()
        XCTAssertEqual(inputs.count, 10)
        for data in inputs {
            let expected = try legacyControl(data, server: control)
            XCTAssertNotNil(expected)
            XCTAssertEqual(sync.handleMessage(data), expected)
            let asynchronous = await async.handleMessageAsync(data)
            XCTAssertEqual(asynchronous, expected)
        }
    }

    // Invariant/control. A failed gate is settled but NOT ready; its frozen elapsed
    // makes full-byte equality deterministic, unlike an actively analyzing gate.
    func testSettledNotReadyBytesAgainstLegacyControl() async throws {
        let gate = MCPStartupGate()
        gate.fail("1282 fixed failure")
        XCTAssertEqual(gate.status.snapshot().state, "failed")
        let sync = MCPServer(startup: gate, listHarnessTools: false)
        let async = MCPServer(startup: gate, listHarnessTools: false)
        let control = MCPServer(startup: gate, listHarnessTools: false)
        for data in try corpus() {
            let expected = try legacyControl(data, server: control)
            XCTAssertEqual(sync.handleMessage(data), expected)
            let asynchronous = await async.handleMessageAsync(data)
            XCTAssertEqual(asynchronous, expected)
        }
    }

    private enum MaskedControlError: Error { case unexpectedShape }

    // MASKED: strict-parse and canonicalize, changing only the named elapsedMs
    // leaf; this intentionally is not raw response-byte equivalence.
    private func maskedAnalyzingReply(_ data: Data, kind: String) throws -> Data {
        let parser = MacScopeAnalysisCore.Phase2StrictJSONParser()
        let limits = MacScopeAnalysisCore.Phase2StrictJSONLimits(
            maximumBytes: max(1, data.count), maximumDepth: 64,
            maximumTokens: max(1, data.count), maximumMembersAndElements: max(1, data.count))
        guard var root = try parser.parse(data, limits: limits).objectValue,
              var result = root["result"]?.objectValue else {
            throw MaskedControlError.unexpectedShape
        }
        if kind == "initialize" {
            guard var capabilities = result["capabilities"]?.objectValue,
                  var experimental = capabilities["experimental"]?.objectValue,
                  var analysis = experimental["macscope/analysis"]?.objectValue,
                  analysis["state"] == .string("analyzing"),
                  case .number? = analysis["elapsedMs"] else {
                throw MaskedControlError.unexpectedShape
            }
            analysis["elapsedMs"] = .number("0")
            experimental["macscope/analysis"] = .object(analysis)
            capabilities["experimental"] = .object(experimental)
            result["capabilities"] = .object(capabilities)
        } else if kind == "commands" {
            // The test negotiates the legacy protocol; do not silently ignore
            // an unexpected second structured copy of the dynamic payload.
            guard result["structuredContent"] == nil,
                  var content = result["content"]?.arrayValue,
                  !content.isEmpty, var first = content[0].objectValue,
                  let text = first["text"]?.stringValue else {
                throw MaskedControlError.unexpectedShape
            }
            let payloadData = Data(text.utf8)
            let payloadLimits = MacScopeAnalysisCore.Phase2StrictJSONLimits(
                maximumBytes: max(1, payloadData.count), maximumDepth: 64,
                maximumTokens: max(1, payloadData.count),
                maximumMembersAndElements: max(1, payloadData.count))
            guard var payload = try parser.parse(payloadData, limits: payloadLimits).objectValue,
                  payload["state"] == .string("analyzing"),
                  payload["error"] == .string("notReady"),
                  case .number? = payload["elapsedMs"] else {
                throw MaskedControlError.unexpectedShape
            }
            payload["elapsedMs"] = .number("0")
            first["text"] = .string(String(
                decoding: MacScopeAnalysisCore.Phase2ProductionJSONValue.object(payload).canonicalJSONBytes(),
                as: UTF8.self))
            content[0] = .object(first)
            result["content"] = .array(content)
        } else {
            throw MaskedControlError.unexpectedShape
        }
        root["result"] = .object(result)
        return MacScopeAnalysisCore.Phase2ProductionJSONValue.object(root).canonicalJSONBytes()
    }

    // MASKED invariant/control: comparing re-encoded replies after masking only
    // elapsedMs does not prove full original bytes or a historical build.
    func testAnalyzingElapsedMsMaskedControl() async throws {
        let gate = MCPStartupGate()
        let syncServer = MCPServer(startup: gate, listHarnessTools: false)
        let asyncServer = MCPServer(startup: gate, listHarnessTools: false)
        let control = MCPServer(startup: gate, listHarnessTools: false)
        let inputs: [(String, Data)] = [
            ("initialize", try request("initialize", params: .object([
                "protocolVersion": .string(MCPServer.protocolVersion)
            ]))),
            ("commands", try tool("commands"))
        ]
        XCTAssertEqual(inputs.count, 2)
        for (kind, data) in inputs {
            let expected = try XCTUnwrap(legacyControl(data, server: control))
            let synchronous = try XCTUnwrap(syncServer.handleMessage(data))
            let asyncData = await asyncServer.handleMessageAsync(data)
            let asynchronous = try XCTUnwrap(asyncData)
            let maskedExpected = try maskedAnalyzingReply(expected, kind: kind)
            XCTAssertEqual(try maskedAnalyzingReply(synchronous, kind: kind), maskedExpected)
            XCTAssertEqual(try maskedAnalyzingReply(asynchronous, kind: kind), maskedExpected)
        }
        XCTAssertEqual(gate.status.snapshot().state, "analyzing")
    }

    // Invariant/control. Only dynamic elapsedMs prevents an independent full-byte
    // oracle in the analyzing state; do not normalize it and claim byte equivalence.
    func testAnalyzingRefusalIsNotAReadyOrFailedReply() async throws {
        let gate = MCPStartupGate()
        let server = MCPServer(startup: gate, listHarnessTools: false)
        let output = await server.handleMessageAsync(try tool("commands"))
        let response = try ScriptValue.decode(XCTUnwrap(output))
        let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let payload = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(payload["error"], .string("notReady"))
        XCTAssertEqual(gate.status.snapshot().state, "analyzing")
    }

    // Invariant/control. DERIVED constant canonical bytes, not captured from a run.
    func testFixedErrorAndOriginalDecimalIDGoldens() async throws {
        let server = MCPServer(api: try await readyAPI(), listHarnessTools: false)
        let parseError = Data(#"{"error":{"code":-32700,"message":"Parse error"},"id":null,"jsonrpc":"2.0"}"#.utf8)
        XCTAssertEqual(server.handleMessage(Data(#"{"x":1,"x":2}"#.utf8)), parseError)
        XCTAssertEqual(server.handleMessage(Data(repeating: 0x78, count: 1_048_577)), parseError)
        let decimal = Data(#"{"jsonrpc":"2.0","id":1.0,"method":"ping"}"#.utf8)
        XCTAssertEqual(server.handleMessage(decimal),
                       Data(#"{"id":1.0,"jsonrpc":"2.0","result":{}}"#.utf8))
        let longID = try request("ping", id: .string(String(repeating: "a", count: 13_000)))
        XCTAssertEqual(server.handleMessage(longID),
                       Data(#"{"error":{"code":-32600,"message":"Invalid Request"},"id":null,"jsonrpc":"2.0"}"#.utf8))
    }

    // Invariant/control: the golden payload bytes come from the authoritative array.
    func testCommandsAndToolsListUseAuthoritativeMetadataBytes() async throws {
        let server = MCPServer(api: try await readyAPI(), listHarnessTools: false)
        let authoritative = HeadlessAutomationAuthority.availableCommands
        let commands: ScriptValue = .array(authoritative.map {
            .object(["name": .string($0.name), "summary": .string($0.summary),
                     "mutates": .bool($0.mutates), "arguments": .array($0.arguments.map(ScriptValue.string))])
        })
        let commandReply = try ScriptValue.decode(XCTUnwrap(server.handleMessage(try tool("commands"))))
        let text = try XCTUnwrap(commandReply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertEqual(Data(text.utf8), try commands.jsonData())
        let expectedTools: ScriptValue = .array(authoritative.filter {
            !HeadlessAutomationAuthority.harnessCommands.contains($0.name)
        }.map { command in
            .object(["name": .string(command.name),
                     "description": .string(command.summary + (command.mutates ? " (mutates the workspace)" : "")),
                     "inputSchema": HeadlessAutomationAuthority.inputSchema(for: command),
                     "annotations": .object(["readOnlyHint": .bool(!command.mutates),
                                             "destructiveHint": .bool(command.mutates)])])
        })
        let listReply = try ScriptValue.decode(XCTUnwrap(server.handleMessage(try request("tools/list"))))
        XCTAssertEqual(try listReply["result"]?["tools"]?.jsonData(), try expectedTools.jsonData())
    }

    // Invariant/control: valid long ID leaves too little receipt space at the small
    // test output cap; the refusal happens before validation or any mutation.
    func testReceiptBudgetRefusalOnReadyAndNotReadyServers() async throws {
        let api = try await readyAPI()
        let gate = MCPStartupGate()
        let configuration = MCPServer.Configuration(
            maximumInputBytes: 1_048_576, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 1_024)
        let id = String(repeating: "a", count: 200)
        let data = try tool("set-tags", id: .string(id))
        let expected = MacScopeAnalysisCore.Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": .string(id),
            "error": .object([
                "code": .integer(-32602), "message": .string(MCPBatchReceiptBudget.refusal),
                "data": .object([
                    "error": .string("refused"),
                    "refusal": .object([
                        "code": .string("outOfBounds"), "detail": .string("Request ID is too long."),
                        "retryable": .bool(false), "field": .string("id"),
                        "expected": .string("shorter ID")
                    ])
                ])
            ])
        ]).canonicalJSONBytes()
        let servers = [
            MCPServer(api: api, configuration: configuration, listHarnessTools: false),
            MCPServer(startup: gate, configuration: configuration, listHarnessTools: false)
        ]
        for server in servers {
            XCTAssertEqual(server.handleMessage(data), expected)
            let asynchronous = await server.handleMessageAsync(data)
            XCTAssertEqual(asynchronous, expected)
        }
    }
}
