import Foundation
import XCTest
@testable import MacScope

private final class DeadlineNativeStub: ScriptingNativeDecompiling, @unchecked Sendable {
    private let lock = NSLock()
    private let waits: Bool
    private var entered = false
    private var cancelled = false
    init(waits: Bool) { self.waits = waits }
    var started: Bool { lock.withLock { entered } }
    var sawCancellation: Bool { lock.withLock { cancelled } }
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        lock.withLock { entered = true }
        if waits { try? await Task.sleep(nanoseconds: 10_000_000_000) }
        let observed = Task.isCancelled
        lock.withLock { cancelled = observed }
        return .completed(.init(text: "void f(void) {}", language: "c",
                                isComplete: true, isTruncated: false))
    }
}

private final class DeadlineBlockingProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let seconds: TimeInterval
    private var visits = 0
    init(seconds: TimeInterval) { self.seconds = seconds }
    var count: Int { lock.withLock { visits } }
    func checkpoint() {
        let first = lock.withLock { visits += 1; return visits == 1 }
        if first { Thread.sleep(forTimeInterval: seconds) }
    }
}

/// Decompile deadline: a typed refusal naming its budget, ahead of the MCP request deadline.
@MainActor
final class DecompileDeadlineTests: XCTestCase {
    private let arguments = ScriptValue.object(["function": .string("_main")])
    private let deadlineText = "decompile deadline: no result within 50 ms; the read was cancelled and no partial output is returned"

    // F6: without the race, the ten-second stub outlives this five-second assertion.
    func testDeadlineRefusesWithBudgetValue() async {
        let store = makeStore()
        let stub = DeadlineNativeStub(waits: true)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: stub,
                                       decompileDeadlineNanoseconds: 50_000_000)
        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await api.executeAsync("decompile", arguments: arguments)
            XCTFail("expected deadline refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, deadlineText)
        }
        XCTAssertLessThan(start.duration(to: clock.now), .seconds(5))
    }

    // F7: a task-group or checkpoint-only race cannot finish before the two-second blocking span.
    func testDeadlineDoesNotWaitForUncheckpointedWork() async {
        let store = makeStore()
        let probe = DeadlineBlockingProbe(seconds: 2)
        let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { probe.checkpoint() },
                                       decompileDeadlineNanoseconds: 50_000_000)
        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await api.executeAsync("decompile", arguments: arguments)
            XCTFail("expected deadline refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, deadlineText)
        }
        XCTAssertGreaterThanOrEqual(probe.count, 1, "the blocking span must actually have started")
        XCTAssertLessThan(start.duration(to: clock.now), .seconds(1))
    }

    // F8: a late/omitted inner deadline produces success or a protocol error instead.
    func testMCPDeadlineIsToolResultNotBareError() async throws {
        let store = makeStore()
        let stub = DeadlineNativeStub(waits: true)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: stub,
                                       decompileDeadlineNanoseconds: 50_000_000)
        let server = MCPServer(api: api)
        let request = ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("decompile"), "arguments": arguments]),
        ])
        let bytes = await server.handleMessageAsync(try request.jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        XCTAssertNil(envelope["error"])
        XCTAssertEqual(envelope["result"]?["isError"], .bool(true))
        XCTAssertEqual(envelope["result"]?["content"]?.arrayValue?.first?["text"],
                       .string(MCPToolRefusal(code: .budgetExceeded, detail: deadlineText,
                           budget: .init(unit: .wallMillis, limit: 50), narrowing: []).text))
    }

    // F9: omitting onExpiry leaves the stub asleep and its cancellation flag false.
    func testExpiryCancelsTheRead() async throws {
        let store = makeStore()
        let stub = DeadlineNativeStub(waits: true)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: stub,
                                       decompileDeadlineNanoseconds: 50_000_000)
        do {
            _ = try await api.executeAsync("decompile", arguments: arguments)
            XCTFail("expected deadline refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, deadlineText)
        }
        for _ in 0..<500 {
            if stub.sawCancellation { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertTrue(stub.started)
        XCTAssertTrue(stub.sawCancellation)
    }

    // F10: pins the production value and its nominal margin.
    func testDefaultBudgetIsBelowTheRequestDeadline() {
        let store = makeStore()
        let value = WorkspaceScriptingAPI(store: store).decompileDeadlineNanoseconds
        XCTAssertEqual(value, 27_000_000_000)
        XCTAssertLessThan(value, MCPServer.Configuration.production.maximumToolDurationNanoseconds)
    }

    // C4: positive control with the new init argument removed before FIX.
    func testControlFastReadUnaffected() async throws {
        let store = makeStore()
        let stub = DeadlineNativeStub(waits: false)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: stub,
                                       decompileDeadlineNanoseconds: 5_000_000_000)
        let reply = try await api.executeAsync("decompile", arguments: arguments)
        XCTAssertEqual(reply["backend"], .string("native"))
        XCTAssertTrue(stub.started)
        XCTAssertFalse(stub.sawCancellation)
    }

    // C5: positive control with the new init argument removed before FIX.
    func testControlCallerCancellationIsNotADeadline() async throws {
        let store = makeStore()
        let stub = DeadlineNativeStub(waits: true)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: stub,
                                       decompileDeadlineNanoseconds: 10_000_000_000)
        let args = arguments
        let task = Task { try await api.executeAsync("decompile", arguments: args) }
        defer { task.cancel() }
        for _ in 0..<500 {
            if stub.started { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertTrue(stub.started, "cancel only after the native await has begun")
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
    }

    // C6: positive control with the new init argument removed before FIX.
    func testControlOtherSnapshotReadsHaveNoDeadline() async throws {
        let store = makeStore()
        let probe = DeadlineBlockingProbe(seconds: 0.2)
        let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { probe.checkpoint() },
                                       decompileDeadlineNanoseconds: 50_000_000)
        let result = try await api.executeAsync("basic-blocks", arguments: .object(["address": .hex(0x1000)]))
        XCTAssertEqual(result.arrayValue?.count, 1)
        XCTAssertEqual(result.arrayValue?.first?["start"], .hex(0x1000))
        XCTAssertGreaterThanOrEqual(probe.count, 2)
    }

    private func makeStore() -> WorkspaceStore {
        let id = UUID()
        let snap = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "names", path: "/tmp/names",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: id, name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "helper", startAddress: 0x1008, endAddress: 0x100c, confidence: 1),
            ],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: id, startAddress: 0x1000,
                                           endAddress: 0x1008, instructionCount: 2)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "01 00 00 94", mnemonic: "bl", operands: "helper", hasBreakpoint: false, comment: "call"),
                InstructionRow(address: 0x1008, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [XRef(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            controlFlowEdges: [ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                                      size: 0x200, fileOffset: 0x1000, isExecutable: true)])
        return WorkspaceStore(workspaceName: "small control", snapshot: snap,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}
