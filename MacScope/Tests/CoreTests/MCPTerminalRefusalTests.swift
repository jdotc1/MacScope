import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

private typealias PJ = MacScopeAnalysisCore.Phase2ProductionJSONValue

/// Typed terminal refusals (dot item 1295). Expected bytes are spelled literally and
/// were derived independently of production code. The reply "F" counts payload plus
/// one LF. "Response exceeds limit" is 22 bytes; "Request deadline exceeded" is 25.
@MainActor
final class MCPTerminalRefusalTests: XCTestCase {
    private let limitMessage = "Response exceeds limit"
    private let deadlineMessage = "Request deadline exceeded"

    // MARK: - Literal oracle (never built from MCPServerTerminal)

    private func refusal(_ fields: [String: PJ]) -> PJ {
        .object(["error": .string("refused"), "refusal": .object(fields)])
    }

    private func deadlineData(limit: Int, used: Int?) -> PJ {
        refusal([
            "code": .string("budgetExceeded"), "detail": .string("Deadline exceeded."),
            "retryable": .bool(false),
            "budget": .object(["unit": .string("wallMillis"), "limit": PJ.integer(limit)]),
            "used": used.map { PJ.integer($0) } ?? .null, "narrowing": .array([]),
        ])
    }

    private func bytesData(detail: String, limit: Int, used: Int) -> PJ {
        refusal([
            "code": .string("budgetExceeded"), "detail": .string(detail), "retryable": .bool(false),
            "budget": .object(["unit": .string("bytes"), "limit": PJ.integer(limit)]),
            "used": PJ.integer(used), "narrowing": .array([]),
        ])
    }

    private var encodingData: PJ {
        refusal([
            "code": .string("preconditionFailed"), "detail": .string("Response encoding failed."),
            "retryable": .bool(false),
        ])
    }

    private func scriptDeadlineData(limit: Int64, used: Int64?) -> ScriptValue {
        .object(["error": .string("refused"), "refusal": .object([
            "code": .string("budgetExceeded"), "detail": .string("Deadline exceeded."),
            "retryable": .bool(false),
            "budget": .object(["unit": .string("wallMillis"), "limit": .int(limit)]),
            "used": used.map { ScriptValue.int($0) } ?? .null, "narrowing": .array([]),
        ])])
    }

    private func scriptBytesData(detail: String, limit: Int64, used: Int64) -> ScriptValue {
        .object(["error": .string("refused"), "refusal": .object([
            "code": .string("budgetExceeded"), "detail": .string(detail), "retryable": .bool(false),
            "budget": .object(["unit": .string("bytes"), "limit": .int(limit)]),
            "used": .int(used), "narrowing": .array([]),
        ])])
    }

    private func errorFrame(id: PJ, code: Int, message: String, data: PJ? = nil) -> Data {
        var error: [String: PJ] = ["code": PJ.integer(code), "message": .string(message)]
        if let data { error["data"] = data }
        return PJ.object(["jsonrpc": .string("2.0"), "id": id, "error": .object(error)]).canonicalJSONBytes()
    }

    private func parse(_ data: Data) throws -> PJ {
        try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(data, limits: .providerEnvelope)
    }

    /// Whole-object equality, plus the transport rules: no raw CR/LF, and F = payload + LF.
    private func assertError(_ payload: Data, id: PJ, code: Int, message: String, data: PJ?, frame: Int,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        var error: [String: PJ] = ["code": PJ.integer(code), "message": .string(message)]
        if let data { error["data"] = data }
        XCTAssertEqual(try parse(payload),
            .object(["jsonrpc": .string("2.0"), "id": id, "error": .object(error)]), file: file, line: line)
        XCTAssertEqual(payload.count + 1, frame, file: file, line: line)
        XCTAssertFalse(payload.contains(0x0a) || payload.contains(0x0d), file: file, line: line)
        XCTAssertTrue(MCPFrameAdmission.fits(payload, maximumBytes: 512), file: file, line: line)
    }

    private func backslashes(_ count: Int, suffix: String = "") -> PJ {
        .string(String(repeating: "\\", count: count) + suffix)
    }

    private let small = MCPServer.Configuration(maximumInputBytes: 1_048_576, maximumOutputBytes: 512,
        maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 1_024)

    private func makeStore(functionName: String = "_main") -> WorkspaceStore {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: functionName, startAddress: 0x1000, endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000, kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [],
            hexBytes: Data()
        )
        return WorkspaceStore(workspaceName: "MCP", snapshot: snapshot, engine: AnalysisEngine())
    }

    private func callRequest(id: ScriptValue, name: String, arguments: ScriptValue = .object([:])) throws -> Data {
        try ScriptValue.object(["jsonrpc": .string("2.0"), "id": id, "method": .string("tools/call"),
            "params": .object(["name": .string(name), "arguments": arguments])]).jsonData()
    }

    private func waitForResponses(_ probe: TerminalOutput, count: Int) async throws -> [Data] {
        for _ in 0..<200 {
            let values = await probe.values
            if values.count >= count { return values }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("Timed out waiting for MCP terminal responses")
        throw URLError(.timedOut)
    }

    private func bounded(_ server: MCPServer, _ response: ScriptValue, restoring: PJ? = nil,
                         fence: MCPConnectionFence, outcome: MCPMutationOutcome = MCPMutationOutcome()) -> Data? {
        MCPExecutionFence.$connection.withValue(fence) {
            MCPExecutionFence.$outcome.withValue(outcome) {
                server.encodeBounded(response, restoringID: restoring)
            }
        }
    }

    private func finiteResult(id: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": id,
                 "result": .object(["content": .array([]), "_meta": .object(["bad": .double(.nan)])])])
    }

    // MARK: - T01

    func testT01SessionDeadlineCarriesBudget() async throws {
        let gate = TerminalGate()
        let probe = TerminalOutput()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: .init(
            maximumInputBytes: 1_024, maximumOutputBytes: 8_192,
            maximumToolDurationNanoseconds: 20_000_000, maximumRememberedCancellations: 8),
            asyncCommandExecutor: { _, _ in await gate.suspend(); return .null })
        let session = server.makeRequestSession(output: { await probe.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"info"}}"#.utf8))
        let responses = try await waitForResponses(probe, count: 1)
        let reply = try ScriptValue.decode(responses[0])
        XCTAssertEqual(reply["id"], .int(1))
        XCTAssertEqual(reply["error"]?["code"], .int(-32001))
        XCTAssertEqual(reply["error"]?["message"], .string(deadlineMessage))
        XCTAssertEqual(reply["error"]?["data"], scriptDeadlineData(limit: 20, used: nil))
        XCTAssertNil(reply["result"])
        // D172, J1, M25: F = 69 + 1 + 25 + 172.
        XCTAssertEqual(responses[0].count + 1, 267)
        await gate.release()
        await session.finishInput()
        let observed = await probe.count
        XCTAssertEqual(observed, 1, "a late success is not a second terminal")
    }

    // MARK: - T02

    func testT02ElapsedDeadlineCarriesBudgetOnSyncAndAsyncRoutes() async throws {
        for asynchronous in [false, true] {
            var calls = 0
            let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: .init(
                maximumInputBytes: 1_024, maximumOutputBytes: 8_192,
                maximumToolDurationNanoseconds: 20_000_000, maximumRememberedCancellations: 8),
                monotonicNow: { calls += 1; return calls == 1 ? 0 : 20_000_001 },
                asyncCommandExecutor: { _, _ in .object(["ok": .bool(true)]) })
            let data = try callRequest(id: .int(1), name: "info")
            let response = asynchronous ? await server.handleMessageAsync(data) : server.handleMessage(data)
            let payload = try XCTUnwrap(response)
            let reply = try ScriptValue.decode(payload)
            XCTAssertEqual(reply["error"]?["code"], .int(-32001), "asynchronous=\(asynchronous)")
            XCTAssertEqual(reply["error"]?["message"], .string(deadlineMessage))
            XCTAssertEqual(reply["error"]?["data"], scriptDeadlineData(limit: 20, used: 21))
            XCTAssertNil(reply["result"])
            XCTAssertEqual(payload.count + 1, 265, "D170, J1, M25")
        }
        let cases: [(UInt64, Int64)] = [(1, 1), (999_999, 1), (1_000_000, 1), (1_000_001, 2),
                                        (UInt64.max, 18_446_744_073_710)]
        for (nanoseconds, milliseconds) in cases {
            XCTAssertEqual(MCPServerTerminal.milliseconds(nanoseconds), milliseconds, "\(nanoseconds)")
        }
    }

    // MARK: - T03

    func testT03PayloadAndFrameCapsCarryBytes() async throws {
        // Half cap, async route: 255 x characters encode to exactly 257 bytes.
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small,
            asyncCommandExecutor: { _, _ in .string(String(repeating: "x", count: 255)) })
        let asyncResponse = await server.handleMessageAsync(
            try callRequest(id: .string("a"), name: "functions"))
        let asyncPayload = try XCTUnwrap(asyncResponse)
        try assertError(asyncPayload, id: .string("a"), code: -32603, message: limitMessage,
            data: bytesData(detail: "Output limit exceeded.", limit: 256, used: 257), frame: 265)

        // Half cap, sync route: used is the independently measured command output.
        let longName = String(repeating: "x", count: 512)
        let store = makeStore(functionName: longName)
        let api = WorkspaceScriptingAPI(store: store)
        let measured = try api.execute("functions", arguments: .object([:])).jsonData().count
        XCTAssertGreaterThan(measured, 256)
        let syncServer = MCPServer(api: api, configuration: small)
        let syncPayload = try XCTUnwrap(syncServer.handleMessage(try callRequest(id: .string("a"), name: "functions")))
        let syncReply = try ScriptValue.decode(syncPayload)
        XCTAssertEqual(syncReply["error"]?["code"], .int(-32603))
        XCTAssertEqual(syncReply["error"]?["message"], .string(limitMessage))
        XCTAssertEqual(syncReply["error"]?["data"],
            scriptBytesData(detail: "Output limit exceeded.", limit: 256, used: Int64(measured)))
        XCTAssertNil(syncReply["result"])

        // Whole frame: ID restoration happens before measuring (surrogate 511, restored 513).
        let surrogate = PJ.object(["jsonrpc": .string("2.0"), "id": PJ.integer(0),
            "result": .string(String(repeating: "x", count: 474))]).canonicalJSONBytes()
        XCTAssertEqual(surrogate.count + 1, 511)
        let restored = PJ.object(["jsonrpc": .string("2.0"), "id": .string("a"),
            "result": .string(String(repeating: "x", count: 474))]).canonicalJSONBytes()
        XCTAssertEqual(restored.count + 1, 513)
        let framed = try MCPFrameAdmission.response(surrogate, id: .string("a"), maximumBytes: 512)
        try assertError(framed, id: .string("a"), code: -32603, message: limitMessage,
            data: bytesData(detail: "Frame limit exceeded.", limit: 512, used: 513), frame: 264)

        // Production-size construction vectors, with no multi-megabyte allocation.
        let output = MCPServerTerminal.output(limit: 4_194_304, used: 4_194_305)
        XCTAssertEqual(output.phaseValue, bytesData(detail: "Output limit exceeded.", limit: 4_194_304, used: 4_194_305))
        let frame = MCPServerTerminal.frame(limit: 8_388_608, payloadBytes: 8_388_608)
        XCTAssertEqual(frame.phaseValue, bytesData(detail: "Frame limit exceeded.", limit: 8_388_608, used: 8_388_609))
        for terminal in [output, frame, .encoding, .deadline(limitNanoseconds: 30_000_000_000, usedNanoseconds: nil)] {
            XCTAssertEqual(try ScriptValue.decode(terminal.phaseValue.canonicalJSONBytes()), terminal.scriptValue)
        }
        let outputFrame = output.frame(id: .string("a"), code: -32603, message: limitMessage)
        XCTAssertEqual(try MCPFrameAdmission.response(outputFrame, id: .string("a"), maximumBytes: 8_388_608), outputFrame)
        XCTAssertEqual(outputFrame.count + 1, 273)
        let frameFrame = frame.frame(id: .string("a"), code: -32603, message: limitMessage)
        XCTAssertEqual(try MCPFrameAdmission.response(frameFrame, id: .string("a"), maximumBytes: 8_388_608), frameFrame)
        XCTAssertEqual(frameFrame.count + 1, 272)
    }

    // MARK: - T04

    private func committedOutcome() -> MCPMutationOutcome {
        let outcome = MCPMutationOutcome()
        outcome.committed()
        outcome.recordBatchReceipt(.init(command: "set-tags", count: 1, changed: 1, imageSlot: nil))
        return outcome
    }

    func testT04CommittedReceiptSurvivesTypedTerminal() async throws {
        let outcome = committedOutcome()
        let receipt = try XCTUnwrap(outcome.batchReceipt)
        let summary = "set-tags returned: count=1, changed=1"
        XCTAssertEqual(receipt.summary, summary)

        // Final-envelope path: typed frame data under the receipt message (F = 117 + R + D = 324).
        let fence = MCPConnectionFence()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let big: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
            "result": .string(String(repeating: "x", count: 600))])
        let framed = try XCTUnwrap(bounded(server, big, fence: fence, outcome: outcome))
        try assertError(framed, id: PJ.integer(1), code: -32603,
            message: summary + "; reporting failed. Do not retry automatically.",
            data: bytesData(detail: "Frame limit exceeded.", limit: 512, used: 637), frame: 324)
        XCTAssertFalse(fence.isFailed)

        // A3: receipt-bearing output failures stay tool results (result.isError), never JSON-RPC errors.
        let limitServer = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small,
            asyncCommandExecutor: { _, _ in .string(String(repeating: "x", count: 255)) })
        let limitReply = try await MCPExecutionFence.$connection.withValue(MCPConnectionFence()) {
            try await MCPExecutionFence.$outcome.withValue(outcome) {
                let response = await limitServer.handleMessageAsync(
                    try callRequest(id: .int(1), name: "functions"))
                return try ScriptValue.decode(XCTUnwrap(response))
            }
        }
        XCTAssertNil(limitReply["error"])
        XCTAssertEqual(limitReply["result"]?["isError"], .bool(true))
        XCTAssertEqual(limitReply["result"]?["content"]?.arrayValue?.first?["text"],
            .string(summary + "; response exceeds limit. Do not retry automatically."))

        let nanServer = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small,
            asyncCommandExecutor: { _, _ in .object(["n": .double(.nan)]) })
        let nanReply = try await MCPExecutionFence.$connection.withValue(MCPConnectionFence()) {
            try await MCPExecutionFence.$outcome.withValue(outcome) {
                let response = await nanServer.handleMessageAsync(
                    try callRequest(id: .int(1), name: "functions"))
                return try ScriptValue.decode(XCTUnwrap(response))
            }
        }
        XCTAssertNil(nanReply["error"])
        XCTAssertEqual(nanReply["result"]?["isError"], .bool(true))
        XCTAssertEqual(nanReply["result"]?["content"]?.arrayValue?.first?["text"],
            .string(summary + "; tool output contained a non-finite number at \"/n\". Do not retry automatically."))

        // An incoming typed deadline with a receipt fallback: code and message rewrite, data is carried.
        let fallback = summary + "; reporting failed. Do not retry automatically."
        let deadline = errorFrame(id: PJ.integer(1), code: -32001, message: deadlineMessage,
            data: deadlineData(limit: 30_000, used: nil))
        let rewritten = try MCPFrameAdmission.response(deadline, id: PJ.integer(1), maximumBytes: 512,
            failureMessage: fallback, compactMessage: fallback)
        try assertError(rewritten, id: PJ.integer(1), code: -32603, message: fallback,
            data: deadlineData(limit: 30_000, used: nil), frame: 329)
    }

    // MARK: - T05

    func testT05TypedDeadlineFitsAtExactBoundaryAndFallsBackAdditively() throws {
        let timer = MCPServerTerminal.deadline(limitNanoseconds: 30_000_000_000, usedNanoseconds: nil)
        let data = deadlineData(limit: 30_000, used: nil)
        // 120 backslashes then x: E241, J243, typed F512 fits exactly.
        let fits = backslashes(120, suffix: "x")
        let typedFits = timer.frame(id: fits, code: -32001, message: deadlineMessage)
        XCTAssertEqual(typedFits.count + 1, 512)
        let admitted = try MCPFrameAdmission.response(typedFits, id: fits, maximumBytes: 512)
        try assertError(admitted, id: fits, code: -32001, message: deadlineMessage, data: data, frame: 512)
        // One more byte: typed F513 does not fit. A4: the reply is the untyped deadline (F330).
        let over = backslashes(120, suffix: "xx")
        let typedOver = timer.frame(id: over, code: -32001, message: deadlineMessage)
        XCTAssertEqual(typedOver.count + 1, 513)
        XCTAssertFalse(MCPFrameAdmission.fits(typedOver, maximumBytes: 512))
        let fallback = try MCPFrameAdmission.response(typedOver, id: over, maximumBytes: 512)
        try assertError(fallback, id: over, code: -32001, message: deadlineMessage, data: nil, frame: 330)
    }

    // MARK: - T06 (owner pin) and A4

    func testT06LongEscapedIDKeepsTodaysReplyWithoutData() throws {
        let id = backslashes(200)  // E400, J402
        let timer = MCPServerTerminal.deadline(limitNanoseconds: 30_000_000_000, usedNanoseconds: nil)
        let typed = timer.frame(id: id, code: -32001, message: deadlineMessage)
        XCTAssertEqual(typed.count + 1, 671)
        XCTAssertFalse(MCPFrameAdmission.fits(typed, maximumBytes: 512))
        // A4: today's untyped reply fits (F488), so it is the reply; never a different message.
        let untyped = try MCPFrameAdmission.response(typed, id: id, maximumBytes: 512)
        try assertError(untyped, id: id, code: -32001, message: deadlineMessage, data: nil, frame: 488)
        XCTAssertEqual(untyped, errorFrame(id: id, code: -32001, message: deadlineMessage))

        // Owner pin: the no-data "Response exceeds limit" frame at this ID is 485 bytes
        // (61 + 402 + 22), reached when the oversized typed terminal is a -32603 size refusal.
        let sizeTerminal = MCPServerTerminal.output(limit: 256, used: 257)
            .frame(id: id, code: -32603, message: limitMessage)
        XCTAssertEqual(sizeTerminal.count + 1, 664)
        XCTAssertFalse(MCPFrameAdmission.fits(sizeTerminal, maximumBytes: 512))
        let pinned = try MCPFrameAdmission.response(sizeTerminal, id: id, maximumBytes: 512)
        try assertError(pinned, id: id, code: -32603, message: limitMessage, data: nil, frame: 485)
    }

    func testA4DeadlineBandReturnsTheUntypedDeadlineMessage() throws {
        let timer = MCPServerTerminal.deadline(limitNanoseconds: 30_000_000_000, usedNanoseconds: nil)
        // E300 (150 backslashes): typed F571 does not fit; the bare deadline F388 does.
        let middle = backslashes(150)
        let typedMiddle = timer.frame(id: middle, code: -32001, message: deadlineMessage)
        XCTAssertEqual(typedMiddle.count + 1, 571)
        let middleReply = try MCPFrameAdmission.response(typedMiddle, id: middle, maximumBytes: 512)
        try assertError(middleReply, id: middle, code: -32001, message: deadlineMessage, data: nil, frame: 388)
        // E424: the bare deadline still fits exactly (F512).
        let edge = backslashes(212)
        let edgeReply = try MCPFrameAdmission.response(
            timer.frame(id: edge, code: -32001, message: deadlineMessage), id: edge, maximumBytes: 512)
        try assertError(edgeReply, id: edge, code: -32001, message: deadlineMessage, data: nil, frame: 512)
        // E425: the bare deadline is F513 and does not fit; only then the existing ladder applies (F510).
        let beyond = backslashes(212, suffix: "x")
        let beyondReply = try MCPFrameAdmission.response(
            timer.frame(id: beyond, code: -32001, message: deadlineMessage), id: beyond, maximumBytes: 512)
        try assertError(beyondReply, id: beyond, code: -32001, message: limitMessage, data: nil, frame: 510)
    }

    // MARK: - T07

    func testT07LongEscapedIDCannotFitAnyExistingFallback() async throws {
        let id = backslashes(256)  // E512, J514: even the empty-message no-data frame is F575
        let timer = MCPServerTerminal.deadline(limitNanoseconds: 30_000_000_000, usedNanoseconds: nil)
        XCTAssertThrowsError(try MCPFrameAdmission.response(
            timer.frame(id: id, code: -32001, message: deadlineMessage), id: id, maximumBytes: 512)) {
            XCTAssertEqual($0 as? MCPFrameAdmission.Failure, .unrepresentable)
        }
        let output = TerminalOutput()
        let session = MCPRequestSession(configuration: .init(maximumInputBytes: 4096,
            maximumOutputBytes: 512, maximumToolDurationNanoseconds: 5_000_000_000,
            maximumRememberedCancellations: 8), mutatingCommands: [],
            execute: { _ in Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8) },
            output: { await output.append($0) })
        let request = ScriptValue.object(["jsonrpc": .string("2.0"),
            "id": .string(String(repeating: "\\", count: 256)), "method": .string("ping")])
        await session.receive(try request.jsonData())
        for _ in 0..<200 {
            if !(await session.isAcceptingRequests) { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let accepting = await session.isAcceptingRequests
        XCTAssertFalse(accepting)
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8))
        await session.finishInput()
        let emitted = await output.count
        XCTAssertEqual(emitted, 0, "no frame is emitted and later work is not admitted")
    }

    // MARK: - T08

    func testT08FinalEnvelopeNonFiniteRestoresIDAndRecoversOnce() throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let fence = MCPConnectionFence()
        let restoredID = PJ.number("1e0004")
        let payload = try XCTUnwrap(bounded(server, finiteResult(id: .int(0)), restoring: restoredID, fence: fence))
        try assertError(payload, id: restoredID, code: -32603, message: limitMessage, data: encodingData, frame: 211)
        XCTAssertTrue(String(decoding: payload, as: UTF8.self).contains("\"id\":1e0004"), "lexeme is not normalized")
        XCTAssertFalse(fence.isFailed)

        // Each outcome keeps its existing message; only the rolledBack state may claim a rollback.
        let outcomes: [(String, (MCPMutationOutcome) -> Void, String, Int)] = [
            ("unknown", { $0.started() }, "Mutation outcome unknown; do not retry automatically.", 237),
            ("returned", { $0.started(); $0.returned() }, "Operation returned; do not retry automatically.", 231),
            ("committed", { $0.committed() }, "Mutation committed; do not retry.", 217),
            ("rolledBack", { $0.started(); $0.rolledBack() }, "Write rolled back; read fresh state before retrying.", 236),
        ]
        for (name, prepare, message, frame) in outcomes {
            let outcome = MCPMutationOutcome()
            prepare(outcome)
            let fence = MCPConnectionFence()
            let reply = try XCTUnwrap(bounded(server, finiteResult(id: .int(1)), restoring: PJ.integer(1),
                fence: fence, outcome: outcome), name)
            try assertError(reply, id: PJ.integer(1), code: -32603, message: message, data: encodingData, frame: frame)
            XCTAssertFalse(fence.isFailed, name)
        }
    }

    // MARK: - T09

    func testT09IDFailureStillFailsFence() throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let nonFiniteID: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .double(.nan),
                                                "result": .object([:])])
        for restoring in [nil, PJ.integer(1)] {
            let fence = MCPConnectionFence()
            XCTAssertNil(bounded(server, nonFiniteID, restoring: restoring, fence: fence))
            XCTAssertTrue(fence.isFailed)
        }
        var nested: ScriptValue = .int(0)
        for _ in 0..<20 { nested = .array([nested]) }
        let fence = MCPConnectionFence()
        let deepID: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": nested, "result": .object([:])])
        XCTAssertNil(bounded(server, deepID, fence: fence))
        XCTAssertTrue(fence.isFailed)
    }

    // MARK: - T10

    func testT10D02UnrepresentableStillFailsFence() throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let tooLong = MCPConnectionFence()
        XCTAssertNil(bounded(server, finiteResult(id: .int(0)), restoring: backslashes(256), fence: tooLong))
        XCTAssertTrue(tooLong.isFailed)
        // E400: the typed recovery (F607) does not fit; the existing no-data frame (F485) does.
        let id = backslashes(200)
        let typed = MCPServerTerminal.encoding.frame(id: id, code: -32603, message: limitMessage)
        XCTAssertEqual(typed.count + 1, 607)
        let fence = MCPConnectionFence()
        let payload = try XCTUnwrap(bounded(server, finiteResult(id: .int(0)), restoring: id, fence: fence))
        try assertError(payload, id: id, code: -32603, message: limitMessage, data: nil, frame: 485)
        XCTAssertFalse(fence.isFailed)
    }

    // MARK: - Item 1310 (owner-authorized requests budget unit)

    private func item1310Params(field: String? = nil, expected: String? = nil) -> PJ {
        var fields: [String: PJ] = [
            "code": .string("malformedInput"), "detail": .string("Invalid params"),
            "retryable": .bool(false)
        ]
        if let field { fields["field"] = .string(field) }
        if let expected { fields["expected"] = .string(expected) }
        return refusal(fields)
    }

    private var item1310Receipt: PJ {
        refusal([
            "code": .string("outOfBounds"), "detail": .string("Request ID is too long."),
            "retryable": .bool(false), "field": .string("id"), "expected": .string("shorter ID")
        ])
    }

    private func item1310InFlight(limit: Int, used: Int) -> PJ {
        refusal([
            "code": .string("budgetExceeded"), "detail": .string("In-flight limit exceeded."),
            "retryable": .bool(true),
            "budget": .object(["unit": .string("requests"), "limit": PJ.integer(limit)]),
            "used": PJ.integer(used), "narrowing": .array([])
        ])
    }

    private func item1310Request(id: ScriptValue, method: String, params: ScriptValue) throws -> Data {
        try ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": id, "method": .string(method), "params": params
        ]).jsonData()
    }

    private func item1310SaturatedReply(id: ScriptValue) async throws -> Data {
        let gate = TerminalGate()
        let output = TerminalOutput()
        let session = MCPRequestSession(configuration: .init(
            maximumInputBytes: 1_048_576, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 30_000_000_000,
            maximumRememberedCancellations: 8, maximumInFlightRequests: 1),
            mutatingCommands: [],
            execute: { _ in
                await gate.suspend()
                return Data(#"{"jsonrpc":"2.0","id":0,"result":{}}"#.utf8)
            }, output: { await output.append($0) })
        await session.receive(Data(#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.utf8))
        // The first receive owns its entry before returning; its executor cannot finish yet.
        await session.receive(Data(#"{"jsonrpc":"2.0","method":"ping"}"#.utf8))
        let beforeRejection = await output.count
        XCTAssertEqual(beforeRejection, 0, "an absent ID remains silent at the cap")
        let rejected = try ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": id, "method": .string("ping")
        ]).jsonData()
        await session.receive(rejected)
        let replies = await output.values
        await gate.release()
        await session.finishInput()
        XCTAssertEqual(replies.count, 1)
        return try XCTUnwrap(replies.first)
    }

    func test1310InFlightCapCarriesRequestsBudget() async throws {
        let payload = try await item1310SaturatedReply(id: .int(2))
        // D172, J1, M27: F = 69 + 1 + 27 + 172 = 269.
        try assertError(payload, id: .integer(2), code: -32000, message: "Too many in-flight requests",
            data: item1310InFlight(limit: 1, used: 1), frame: 269)
        let fields = try parse(payload).objectValue?["error"]?.objectValue?["data"]?.objectValue?["refusal"]?.objectValue
        XCTAssertEqual(fields?["budget"]?.objectValue?["unit"], .string("requests"))
        XCTAssertEqual(fields?["budget"]?.objectValue?["limit"], .integer(1))
        XCTAssertEqual(fields?["used"], .integer(1))
        XCTAssertEqual(fields?["retryable"], .bool(true))
    }

    func test1310SyncInvalidParamsCarriesField() throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let request = try item1310Request(id: .int(1), method: "ping", params: .array([]))
        let payload = try XCTUnwrap(server.handleMessage(request))
        try assertError(payload, id: .integer(1), code: -32602, message: "Invalid params",
            data: item1310Params(field: "params", expected: "object"), frame: 220)
    }

    func test1310AsyncInvalidArgumentsCarriesField() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let response = await server.handleMessageAsync(
            try callRequest(id: .int(1), name: "info", arguments: .array([])))
        let payload = try XCTUnwrap(response)
        try assertError(payload, id: .integer(1), code: -32602, message: "Invalid params",
            data: item1310Params(field: "params.arguments", expected: "object or null"), frame: 238)
    }

    func test1310OtherKnownParameterShapesAgreeAcrossRoutes() async throws {
        let cases: [(String, ScriptValue, PJ, Int)] = [
            ("initialize", .bool(true), item1310Params(field: "params", expected: "object"), 220),
            ("tools/list", .array([]), item1310Params(field: "params", expected: "object"), 220),
            ("tools/call", .object([:]), item1310Params(), 183),
            ("tools/call", .object(["name": .string("info"), "_meta": .string("invalid")]),
             item1310Params(field: "params._meta", expected: "object"), 226)
        ]
        for (method, params, data, frame) in cases {
            let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
            let request = try item1310Request(id: .int(1), method: method, params: params)
            let sync = try XCTUnwrap(server.handleMessage(request))
            let response = await server.handleMessageAsync(request)
            let asyncPayload = try XCTUnwrap(response)
            try assertError(sync, id: .integer(1), code: -32602, message: "Invalid params", data: data, frame: frame)
            XCTAssertEqual(asyncPayload, sync)
        }
    }

    func test1310ReceiptRefusalHasIdenticalBytesOnAllWireRoutes() async throws {
        let id = String(repeating: "a", count: 200)
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let request = try callRequest(id: .string(id), name: "set-tags")
        let sync = try XCTUnwrap(server.handleMessage(request))
        let response = await server.handleMessageAsync(request)
        let asyncPayload = try XCTUnwrap(response)
        let output = TerminalOutput()
        let session = server.makeRequestSession(output: { await output.append($0) })
        await session.receive(request)
        let emitted = await output.values
        await session.finishInput()
        let stream = try XCTUnwrap(emitted.first)
        XCTAssertEqual(emitted.count, 1)
        // J202, M64, D142: F = 69 + 202 + 64 + 142 = 477.
        for payload in [sync, asyncPayload, stream] {
            try assertError(payload, id: .string(id), code: -32602, message: MCPBatchReceiptBudget.refusal,
                data: item1310Receipt, frame: 477)
            XCTAssertEqual(payload, errorFrame(id: .string(id), code: -32602,
                message: MCPBatchReceiptBudget.refusal, data: item1310Receipt))
        }
    }

    func test1310ReceiptFallbackBandOnSyncAsyncAndStream() async throws {
        let id = String(repeating: "a", count: 256)
        let request = try callRequest(id: .string(id), name: "set-tags")
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let sync = try XCTUnwrap(server.handleMessage(request))
        let response = await server.handleMessageAsync(request)
        let asyncPayload = try XCTUnwrap(response)
        let output = TerminalOutput()
        let session = server.makeRequestSession(output: { await output.append($0) })
        await session.receive(request)
        let emitted = await output.values
        await session.finishInput()
        let stream = try XCTUnwrap(emitted.first)
        let typed = errorFrame(id: .string(id), code: -32602,
            message: MCPBatchReceiptBudget.refusal, data: item1310Receipt)
        XCTAssertEqual(typed.count + 1, 533)
        XCTAssertFalse(MCPFrameAdmission.fits(typed, maximumBytes: 512))
        for payload in [sync, asyncPayload, stream] {
            try assertError(payload, id: .string(id), code: -32602,
                message: MCPBatchReceiptBudget.refusal, data: nil, frame: 383)
        }
        // The generic admission path must also strip data before its different ladder.
        let admitted = try MCPFrameAdmission.response(typed, id: .string(id), maximumBytes: 512)
        XCTAssertEqual(admitted, sync)
    }

    func test1310InFlightFallbackPreservesOriginalMessage() async throws {
        let id = String(repeating: "a", count: 256)
        let typed = errorFrame(id: .string(id), code: -32000, message: "Too many in-flight requests",
            data: item1310InFlight(limit: 1, used: 1))
        XCTAssertEqual(typed.count + 1, 526)
        XCTAssertFalse(MCPFrameAdmission.fits(typed, maximumBytes: 512))
        let payload = try await item1310SaturatedReply(id: .string(id))
        try assertError(payload, id: .string(id), code: -32000, message: "Too many in-flight requests",
            data: nil, frame: 346)
    }

    func test1310PlainInvalidParamsFallbackPreservesOriginalMessage() throws {
        let id = String(repeating: "a", count: 256)
        let typed = errorFrame(id: .string(id), code: -32602, message: "Invalid params",
            data: item1310Params(field: "params", expected: "object"))
        // wire-unreachable: the typed frame is 477 B, and the configuration minimum is 512 (Configuration precondition)
        XCTAssertEqual(typed.count + 1, 477)
        XCTAssertFalse(MCPFrameAdmission.fits(typed, maximumBytes: 470))
        let payload = try MCPFrameAdmission.response(typed, id: .string(id), maximumBytes: 470)
        try assertError(payload, id: .string(id), code: -32602, message: "Invalid params", data: nil, frame: 333)
    }

    func test1310ReceiptLadderEdgesAtBothCaps() throws {
        let cases: [(Int, Int, String, Bool, Int)] = [
            (512, 127, MCPBatchReceiptBudget.refusal, true, 404),
            (512, 235, MCPBatchReceiptBudget.refusal, true, 512),
            (512, 236, MCPBatchReceiptBudget.refusal, false, 363),
            (512, 385, MCPBatchReceiptBudget.refusal, false, 512),
            (512, 386, "Batch not run; shorten ID.", false, 475),
            (512, 423, "Batch not run; shorten ID.", false, 512),
            (512, 424, "Not run", false, 494),
            (512, 442, "Not run", false, 512),
            (8192, 7807, MCPBatchReceiptBudget.refusal, true, 8084),
            (8192, 7915, MCPBatchReceiptBudget.refusal, true, 8192),
            (8192, 7916, MCPBatchReceiptBudget.refusal, false, 8043),
            (8192, 8065, MCPBatchReceiptBudget.refusal, false, 8192),
            (8192, 8066, "Batch not run; shorten ID.", false, 8155),
            (8192, 8103, "Batch not run; shorten ID.", false, 8192),
            (8192, 8104, "Not run", false, 8174),
            (8192, 8122, "Not run", false, 8192)
        ]
        for (cap, length, message, typed, frame) in cases {
            let id = PJ.string(String(repeating: "a", count: length))
            XCTAssertFalse(MCPBatchReceiptBudget.admits(idBytes: length + 2, maximumBytes: cap))
            let payload = try MCPBatchReceiptBudget.refusalFrame(id: id, maximumBytes: cap)
            XCTAssertEqual(payload, errorFrame(id: id, code: -32602, message: message,
                data: typed ? item1310Receipt : nil))
            XCTAssertEqual(payload.count + 1, frame)
            XCTAssertTrue(MCPFrameAdmission.fits(payload, maximumBytes: cap))
        }
        for (cap, length) in [(512, 443), (8192, 8123)] {
            XCTAssertThrowsError(try MCPBatchReceiptBudget.refusalFrame(
                id: .string(String(repeating: "a", count: length)), maximumBytes: cap)) {
                XCTAssertEqual($0 as? MCPFrameAdmission.Failure, .unrepresentable)
            }
        }
    }

    func test1310TerminalBuildersAgreeAfterCanonicalAdmission() throws {
        let cases: [(MCPServerTerminal, Int, String, PJ)] = [
            (.inFlight(limit: 1, used: 1), -32000, "Too many in-flight requests", item1310InFlight(limit: 1, used: 1)),
            (.inFlight(limit: 1024, used: 1024), -32000, "Too many in-flight requests", item1310InFlight(limit: 1024, used: 1024)),
            (.invalidParams(field: nil, expected: nil), -32602, "Invalid params", item1310Params()),
            (.invalidParams(field: "params", expected: "object"), -32602, "Invalid params", item1310Params(field: "params", expected: "object")),
            (.invalidParams(field: "params._meta", expected: "object"), -32602, "Invalid params", item1310Params(field: "params._meta", expected: "object")),
            (.invalidParams(field: "params.arguments", expected: "object or null"), -32602, "Invalid params", item1310Params(field: "params.arguments", expected: "object or null")),
            (.receiptID, -32602, MCPBatchReceiptBudget.refusal, item1310Receipt)
        ]
        for (terminal, code, message, expected) in cases {
            XCTAssertEqual(terminal.phaseValue, expected)
            XCTAssertEqual(try ScriptValue.decode(expected.canonicalJSONBytes()), terminal.scriptValue)
            let legacy = ScriptValue.object([
                "jsonrpc": .string("2.0"), "id": .int(0),
                "error": .object(["code": .int(Int64(code)), "message": .string(message), "data": terminal.scriptValue])
            ])
            let id = PJ.number("1e0004")
            let admitted = try MCPFrameAdmission.response(legacy.jsonData(), id: id, maximumBytes: 8192)
            XCTAssertEqual(admitted, terminal.frame(id: id, code: code, message: message))
        }
    }
}

private actor TerminalOutput {
    private(set) var values: [Data] = []
    var count: Int { values.count }
    func append(_ data: Data) { values.append(data) }
}

private actor TerminalGate {
    private var released = false
    private var blocked: [CheckedContinuation<Void, Never>] = []
    func suspend() async {
        if !released { await withCheckedContinuation { blocked.append($0) } }
    }
    func release() {
        released = true
        let waiters = blocked
        blocked.removeAll()
        for waiter in waiters { waiter.resume() }
    }
}

// Item 1315: additive receipt typing; existing assertions are untouched.
extension MCPTerminalRefusalTests {
    private var receipt1315: String { "set-tags returned: count=1, changed=1" }
    private var limit1315: String { receipt1315 + "; response exceeds limit. Do not retry automatically." }

    private func frame1315(id: PJ, text: String, refusal: PJ? = nil) -> Data {
        var content: [PJ] = [.object(["type": .string("text"), "text": .string(text)])]
        if let refusal {
            content.append(.object(["type": .string("text"),
                "text": .string(String(decoding: refusal.canonicalJSONBytes(), as: UTF8.self))]))
        }
        return PJ.object(["jsonrpc": .string("2.0"), "id": id,
            "result": .object(["content": .array(content), "isError": .bool(true)])]).canonicalJSONBytes()
    }

    private func run1315(_ server: MCPServer, request: Data, asyncCall: Bool = true) async throws -> Data {
        try await MCPExecutionFence.$connection.withValue(MCPConnectionFence()) {
            try await MCPExecutionFence.$outcome.withValue(committedOutcome()) {
                let response = asyncCall ? await server.handleMessageAsync(request) : server.handleMessage(request)
                return try XCTUnwrap(response)
            }
        }
    }

    func test1315MeasuredReceiptSyncAsyncAndNoReceiptFields() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore(functionName: String(repeating: "x", count: 512)))
        let output = try api.execute("functions", arguments: .object([:]))
        let measured = try output.jsonData().count
        XCTAssertGreaterThan(measured, 256)
        let expected = bytesData(detail: "Output limit exceeded.", limit: 256, used: measured)
        let server = MCPServer(api: api, configuration: small, asyncCommandExecutor: { _, _ in output })
        let request = try callRequest(id: .int(1), name: "functions")
        let sync = try await run1315(server, request: request, asyncCall: false)
        let asyncReply = try await run1315(server, request: request)
        XCTAssertEqual(sync, asyncReply)
        XCTAssertEqual(sync, frame1315(id: .integer(1), text: limit1315, refusal: expected))
        let ordinaryResponse = await server.handleMessageAsync(request)
        let ordinary = try XCTUnwrap(ordinaryResponse)
        XCTAssertEqual(try parse(ordinary).objectValue?["error"]?.objectValue?["data"], expected)
        let longID = String(repeating: "x", count: 120)
        let longRequest = try callRequest(id: .string(longID), name: "functions")
        let syncFallback = try await run1315(server, request: longRequest, asyncCall: false)
        let asyncFallback = try await run1315(server, request: longRequest)
        XCTAssertEqual(syncFallback, asyncFallback)
        XCTAssertEqual(syncFallback, frame1315(id: .string(longID), text: limit1315))
        // Whole-frame equality pins content[0], exactly two blocks, result/no error,
        // isError, the echoed id, and the absence of structuredContent and _meta.
    }

    func test1315NilUsedEncodingAndNonFiniteAreDistinct() async throws {
        var nested: ScriptValue = .null
        for _ in 0...ScriptValue.maximumEncodingDepth { nested = .array([nested]) }
        let deep = nested
        let depthServer = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small,
            asyncCommandExecutor: { _, _ in deep })
        let request = try callRequest(id: .int(1), name: "functions")
        let depth = try await run1315(depthServer, request: request)
        XCTAssertEqual(depth, frame1315(id: .integer(1), text: limit1315, refusal: encodingData))
        let nanServer = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small,
            asyncCommandExecutor: { _, _ in .object(["n": .double(.nan)]) })
        let nan = try await run1315(nanServer, request: request)
        XCTAssertEqual(nan, frame1315(id: .integer(1), text: receipt1315
            + "; tool output contained a non-finite number at \"/n\". Do not retry automatically."))
    }

    func test1315ReceiptAdmissionExactCapsAndBareFallback() throws {
        for cap in [512, 8192] {
            let refusal = bytesData(detail: "Output limit exceeded.", limit: cap / 2, used: cap / 2 + 1)
            let base = frame1315(id: .string(""), text: limit1315, refusal: refusal)
            // F = 178 + J + 225 (512) or 227 (8192); empty string J = 2.
            XCTAssertEqual(base.count + 1, cap == 512 ? 405 : 407)
            let count = cap == 512 ? 107 : 7785
            let id = PJ.string(String(repeating: "x", count: count))
            let typed = frame1315(id: id, text: limit1315, refusal: refusal)
            XCTAssertEqual(typed.count + 1, cap)
            XCTAssertEqual(try MCPFrameAdmission.response(typed, id: id, maximumBytes: cap,
                receiptResultText: limit1315), typed)
            let longer = PJ.string(String(repeating: "x", count: count + 1))
            let oversized = frame1315(id: longer, text: limit1315, refusal: refusal)
            XCTAssertEqual(oversized.count + 1, cap + 1)
            let bare = frame1315(id: longer, text: limit1315)
            XCTAssertEqual(try MCPFrameAdmission.response(oversized, id: longer, maximumBytes: cap,
                receiptResultText: limit1315), bare)
            XCTAssertEqual(try MCPFrameAdmission.response(base, id: longer, maximumBytes: cap,
                receiptResultText: limit1315), bare)
        }
    }

    func test1315FallbackUsesBareMeasurementAndPreservesOtherResults() throws {
        let refusal = bytesData(detail: "Output limit exceeded.", limit: 256, used: 257)
        let text = String(repeating: "x", count: 600)
        let typed = frame1315(id: .integer(1), text: text, refusal: refusal)
        let bare = frame1315(id: .integer(1), text: text)
        let fallback = receipt1315 + "; reporting failed. Do not retry automatically."
        XCTAssertEqual(bare.count + 1, 689) // 88 + J1 + M600.
        let expected = errorFrame(id: .integer(1), code: -32603, message: fallback,
            data: bytesData(detail: "Frame limit exceeded.", limit: 512, used: 689))
        XCTAssertEqual(try MCPFrameAdmission.response(typed, id: .integer(1), maximumBytes: 512,
            failureMessage: fallback, compactMessage: fallback, receiptResultText: text), expected)
        let unrelated = frame1315(id: .integer(1), text: "unrelated", refusal: refusal)
        XCTAssertEqual(try MCPFrameAdmission.response(unrelated, id: .integer(1), maximumBytes: 8192), unrelated)
        XCTAssertEqual(try MCPFrameAdmission.response(unrelated, id: .integer(1), maximumBytes: 8192,
            receiptResultText: limit1315), unrelated)
    }

    func test1315StreamParityAfterRestoredIDFallback() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small,
            asyncCommandExecutor: { _, _ in
                MCPExecutionFence.outcome?.recordBatchReceipt(.init(command: "set-tags", count: 1, changed: 1))
                return .string(String(repeating: "x", count: 255))
            })
        for count in [0, 108] {
            let id = String(repeating: "x", count: count)
            let request = try callRequest(id: .string(id), name: "functions")
            let direct = try await run1315(server, request: request)
            let probe = TerminalOutput()
            let session = server.makeRequestSession(output: { await probe.append($0) })
            await session.receive(request)
            let frames = try await waitForResponses(probe, count: 1)
            await session.finishInput()
            XCTAssertEqual(frames[0], direct)
            let expected = count == 0 ? bytesData(detail: "Output limit exceeded.", limit: 256, used: 257) : nil
            XCTAssertEqual(direct, frame1315(id: .string(id), text: limit1315, refusal: expected))
            let finalCount = await probe.count
            XCTAssertEqual(finalCount, 1)
        }
    }

    func test1315IdentityReceiptsStayUntypedOnBothRoutes() async throws {
        enum Failure: Error { case identity }
        for asyncCall in [false, true] {
            let store = makeStore()
            var checks = 0
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store), validateWorkspaceIdentity: {
                checks += 1
                if checks == 2 { throw Failure.identity }
            })
            let outcome = committedOutcome()
            let request = try callRequest(id: .int(1), name: "set-local-labels", arguments: .object([
                "entries": .array([.object(["address": .hex(0x1000), "label": .string("label")])])]))
            let reply = try await MCPExecutionFence.$outcome.withValue(outcome) {
                let response = asyncCall ? await server.handleMessageAsync(request) : server.handleMessage(request)
                return try XCTUnwrap(response)
            }
            let summary = try XCTUnwrap(outcome.batchReceipt).summary
            XCTAssertEqual(reply, frame1315(id: .integer(1), text: summary
                + "; identity validation failed. Do not retry automatically."))
            XCTAssertEqual(checks, 2)
        }
    }

    func test1315FailureMessageAndAlreadyRefusalKeepLegacyBytes() async throws {
        struct Failure: LocalizedError { var errorDescription: String? { "fixture failed" } }
        let carried = MCPToolRefusal(code: .preconditionFailed, detail: "fixture refused")
        for structured in [false, true] {
            let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()),
                asyncCommandExecutor: { _, _ in
                    if structured { throw ScriptingError.structuredRefusal(carried) }
                    throw Failure()
                })
            let request = try callRequest(id: .int(1), name: "functions")
            let literal = #"{"error":"refused","refusal":{"code":"preconditionFailed","detail":"fixture refused","retryable":false}}"#
            XCTAssertEqual(carried.text, literal)
            let message = structured ? literal : "Tool call failed: fixture failed"
            let receipt = try await run1315(server, request: request)
            XCTAssertEqual(receipt, frame1315(id: .integer(1), text: receipt1315
                + "; " + message + " Do not retry automatically."))
            let ordinaryResponse = await server.handleMessageAsync(request)
            let ordinary = try XCTUnwrap(ordinaryResponse)
            XCTAssertEqual(ordinary, frame1315(id: .integer(1), text: message))
        }
    }

    func test1315ReportingFailureDoesNotAddRefusal() async throws {
        let failure = ScriptingCommittedBatchFailure(command: "set-tags", count: 1, changed: 1,
            reason: "fixture reporting failure", result: .object(["count": .int(1), "changed": .int(1)]))
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()),
            asyncCommandExecutor: { _, _ in throw failure })
        let reply = try await run1315(server, request: callRequest(id: .int(1), name: "functions"))
        let decoded = try ScriptValue.decode(reply)
        XCTAssertEqual(decoded["id"], .int(1))
        XCTAssertEqual(decoded["jsonrpc"], .string("2.0"))
        XCTAssertNil(decoded["error"])
        let result = try XCTUnwrap(decoded["result"])
        XCTAssertEqual(result["isError"], .bool(true))
        XCTAssertNil(result["structuredContent"])
        let content = try XCTUnwrap(result["content"]?.arrayValue)
        XCTAssertEqual(content.first?["type"], .string("text"))
        let text = try XCTUnwrap(content.first?["text"]?.stringValue)
        let literal = #"{"mutationOutcome":"returned","reportingError":"fixture reporting failure","retrySafe":false,"returnedResult":{"changed":1,"count":1}}"#
        XCTAssertEqual(Data(text.utf8), Data(literal.utf8))
        for block in content.dropFirst() {
            XCTAssertFalse(block["text"]?.stringValue?.contains(#""error":"refused""#) ?? false)
        }
        // Supplement API:190-223: this injected throw never records a generation.
        let expected = PJ.object(["jsonrpc": .string("2.0"), "id": .integer(1),
            "result": .object(["_meta": .object([:]), "isError": .bool(true),
                "content": .array([.object(["type": .string("text"), "text": .string(literal)])])])])
        XCTAssertEqual(reply, expected.canonicalJSONBytes())
    }

    func test1315QueuedMutationDeadlineHasOneTerminalAndNeverDispatches() async throws {
        let gate = Receipt1315Gate()
        let calls = TerminalOutput()
        let probe = TerminalOutput()
        let config = MCPServer.Configuration(maximumInputBytes: 1024, maximumOutputBytes: 8192,
            maximumToolDurationNanoseconds: 20_000_000, maximumRememberedCancellations: 8)
        let session = MCPRequestSession(configuration: config, mutatingCommands: ["fixture-mutation"],
            execute: { data in
                await calls.append(data)
                await gate.suspend()
                return Data(#"{"jsonrpc":"2.0","id":0,"result":{"done":true}}"#.utf8)
            }, output: { await probe.append($0) })
        await session.receive(try callRequest(id: .int(1), name: "fixture-mutation"))
        await gate.waitUntilStarted()
        await session.receive(try callRequest(id: .int(2), name: "fixture-mutation"))
        let expired = try await waitForResponses(probe, count: 1)
        XCTAssertEqual(expired.count, 1)
        XCTAssertEqual(expired[0], errorFrame(id: .integer(2), code: -32001,
            message: deadlineMessage, data: deadlineData(limit: 20, used: nil)))
        let before = await calls.count
        XCTAssertEqual(before, 1)
        await gate.release()
        _ = try await waitForResponses(probe, count: 2)
        await session.finishInput()
        let final = await probe.values
        let finalCalls = await calls.count
        let inFlight = await session.inFlightCount
        let pendingWrites = await session.pendingTerminalWriteCount
        XCTAssertEqual(inFlight, 0)
        XCTAssertEqual(pendingWrites, 0)
        XCTAssertEqual(finalCalls, 1)
        XCTAssertEqual(final.count, 2)
        let decoded = try final.map(parse)
        XCTAssertEqual(decoded.filter { $0.objectValue?["id"] == .integer(1) }.count, 1)
        XCTAssertEqual(decoded.filter { $0.objectValue?["id"] == .integer(2) }.count, 1)
        XCTAssertEqual(final[0], expired[0])
        XCTAssertEqual(decoded[1], .object(["jsonrpc": .string("2.0"), "id": .integer(1),
            "result": .object(["done": .bool(true)])]))
        XCTAssertNil(decoded[0].objectValue?["result"])
        // finishInput drains execution and terminal writes; no new sleeps are used.
    }
}

private actor Receipt1315Gate {
    private var started = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var blocked: [CheckedContinuation<Void, Never>] = []
    func suspend() async {
        started = true
        let waiters = startWaiters
        startWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
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

extension MCPTerminalRefusalTests {
    func test1315HistoricalReceiptFailureStaysUntyped() async throws {
        let failure = ScriptingBatchHistoryFailure(receipts: [
            .init(command: "set-tags", count: 1, changed: 1, imageSlot: 7)
        ], omitted: 0, reason: "fixture stopped")
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()),
            asyncCommandExecutor: { _, _ in throw failure })
        let response = await server.handleMessageAsync(try callRequest(id: .int(1), name: "functions"))
        let reply = try XCTUnwrap(response)
        let text = "Tool call failed: Earlier batches returned with changes [set-tags: count=1, changed=1, imageSlot=7]; "
            + "omitted=0. Current state may have changed later. fixture stopped"
        XCTAssertEqual(reply, frame1315(id: .integer(1), text: text))
    }

    func test1315ReceiptFrameLadderUnchangedOnBoundedAndSessionRoutes() async throws {
        let big: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
            "result": .string(String(repeating: "x", count: 600))])
        let raw = try big.jsonData()
        XCTAssertEqual(raw.count + 1, 637)
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()), configuration: small)
        let fence = MCPConnectionFence()
        let sync = try XCTUnwrap(bounded(server, big, fence: fence, outcome: committedOutcome()))
        let probe = TerminalOutput()
        let session = MCPRequestSession(configuration: small, mutatingCommands: [], execute: { _ in
            MCPExecutionFence.outcome?.recordBatchReceipt(.init(command: "set-tags", count: 1, changed: 1))
            return raw
        }, output: { await probe.append($0) })
        await session.receive(try callRequest(id: .int(1), name: "functions"))
        let replies = try await waitForResponses(probe, count: 1)
        await session.finishInput()
        let expected = errorFrame(id: .integer(1), code: -32603,
            message: receipt1315 + "; reporting failed. Do not retry automatically.",
            data: bytesData(detail: "Frame limit exceeded.", limit: 512, used: 637))
        XCTAssertEqual(sync, expected)
        XCTAssertEqual(replies, [expected])
        XCTAssertEqual(sync.count + 1, 324)
        XCTAssertFalse(fence.isFailed)
    }
}

extension MCPTerminalRefusalTests {
    func test1315AdmissionDoesNotStripUnrecognizedOrUnownedBlocks() throws {
        let refusal = bytesData(detail: "Output limit exceeded.", limit: 256, used: 257)
        let id = PJ.string(String(repeating: "x", count: 108))
        let typed = frame1315(id: id, text: limit1315, refusal: refusal)
        XCTAssertEqual(typed.count + 1, 513)
        let ordinaryLadder = try MCPFrameAdmission.response(typed, id: id, maximumBytes: 512)
        XCTAssertEqual(try MCPFrameAdmission.response(typed, id: id, maximumBytes: 512,
            receiptResultText: "different receipt"), ordinaryLadder)
        var fields = try XCTUnwrap(parse(typed).objectValue)
        var result = try XCTUnwrap(fields["result"]?.objectValue)
        result["_meta"] = .object([:])
        fields["result"] = .object(result)
        let extra = PJ.object(fields).canonicalJSONBytes()
        XCTAssertEqual(try MCPFrameAdmission.response(extra, id: id, maximumBytes: 512,
            receiptResultText: limit1315), try MCPFrameAdmission.response(extra, id: id, maximumBytes: 512))
        let unknown = frame1315(id: id, text: limit1315, refusal: deadlineData(limit: 20, used: nil))
        XCTAssertEqual(try MCPFrameAdmission.response(unknown, id: id, maximumBytes: 512,
            receiptResultText: limit1315), try MCPFrameAdmission.response(unknown, id: id, maximumBytes: 512))
    }
}

extension MCPTerminalRefusalTests {
    func test1315EncodingReceiptExactCapsAndFallback() throws {
        for cap in [512, 8192] {
            let count = cap == 512 ? 176 : 7856
            let id = PJ.string(String(repeating: "x", count: count))
            let typed = frame1315(id: id, text: limit1315, refusal: encodingData)
            // F = 178 + J + 156; exact J178 at 512 and J7858 at 8192.
            XCTAssertEqual(typed.count + 1, cap)
            XCTAssertEqual(try MCPFrameAdmission.response(typed, id: id, maximumBytes: cap,
                receiptResultText: limit1315), typed)
            let longer = PJ.string(String(repeating: "x", count: count + 1))
            let oversized = frame1315(id: longer, text: limit1315, refusal: encodingData)
            XCTAssertEqual(oversized.count + 1, cap + 1)
            XCTAssertEqual(try MCPFrameAdmission.response(typed, id: longer, maximumBytes: cap,
                receiptResultText: limit1315), frame1315(id: longer, text: limit1315))
        }
    }
}

extension MCPTerminalRefusalTests {
    func test1315RealAPIFailureMessageKeepsSyncAndAsyncReceiptBytes() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let arguments: ScriptValue = .object(["address": .string("0x1000"), "count": .int(1)])
        // Supplement API:4030-4044: no mapped section in the supplied store fixture.
        // Prove admission and the raw failure separately, rather than using an
        // argument-validation refusal as a substitute for S06's execution catch.
        try HeadlessAutomationAuthority.validateDiagnosed(command: "read-bytes", arguments: arguments)
        XCTAssertThrowsError(try api.execute("read-bytes", arguments: arguments)) { error in
            XCTAssertEqual(error as? ScriptingError,
                .invalidArgument("address 0x1000 is not in any mapped section"))
        }
        let server = MCPServer(api: api)
        let request = try callRequest(id: .int(1), name: "read-bytes", arguments: arguments)
        let message = "Tool call failed: Invalid argument: address 0x1000 is not in any mapped section."
        let sync = try await run1315(server, request: request, asyncCall: false)
        let asyncReply = try await run1315(server, request: request)
        XCTAssertEqual(sync, asyncReply)
        XCTAssertEqual(sync, frame1315(id: .integer(1), text: receipt1315
            + "; " + message + " Do not retry automatically."))
        let plain = try XCTUnwrap(server.handleMessage(request))
        XCTAssertEqual(plain, frame1315(id: .integer(1), text: message))
    }
}
