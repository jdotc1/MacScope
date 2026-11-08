import Foundation
import XCTest
@testable import MacScope

private final class SizeRefusalCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.withLock { value += 1 } }
    var count: Int { lock.withLock { value } }
}

private final class SizeRefusalNative: ScriptingNativeDecompiling, @unchecked Sendable {
    let calls = SizeRefusalCounter()
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        calls.increment()
        return .completed(.init(text: "void f(void) {}", language: "c",
                                isComplete: true, isTruncated: false))
    }
}

/// Decompile size admission: a typed refusal before any native call or lift, on every route.
@MainActor
final class DecompileSizeRefusalTests: XCTestCase {
    private let address = ScriptValue.object(["address": .hex(0x1000)])
    private let bytesText = "function too large: 262145 bytes, 0 blocks (limits: 262144 bytes, 8192 blocks); refused before lifting"
    private let blocksText = "function too large: 32772 bytes, 8193 blocks (limits: 262144 bytes, 8192 blocks); refused before lifting"

    // F1: fails before: the pin has no typed size refusal.
    func testOversizedBytesRefusedOnInlineBeforeLifting() {
        let store = sizedStore(bytes: 262_145, blocks: 0)
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("decompile", arguments: address)) {
            XCTAssertEqual(($0 as? LocalizedError)?.errorDescription, bytesText)
        }
    }

    // F2: fails before: no block admission before MacIR preparation.
    func testOversizedBlocksRefusedOnAsync() async {
        let store = sizedStore(bytes: 32_772, blocks: 8_193)
        do {
            _ = try await WorkspaceScriptingAPI(store: store).executeAsync("decompile", arguments: address)
            XCTFail("expected size refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, blocksText)
        }
    }

    // F3: fails before: native is called and returns a completed document.
    func testNativeNotCalledForOversizedFunction() async {
        let store = sizedStore(bytes: 262_145, blocks: 0)
        let native = SizeRefusalNative()
        do {
            _ = try await WorkspaceScriptingAPI(store: store, nativeDecompiler: native)
                .executeAsync("decompile", arguments: address)
            XCTFail("expected size refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, bytesText)
        }
        XCTAssertEqual(native.calls.count, 0)
    }

    // F4: fails before: no typed tool failure on the MCP/attached routes.
    func testMCPAndAttachedReturnTypedSizeRefusal() async throws {
        let store = sizedStore(bytes: 262_145, blocks: 0)
        let native = SizeRefusalNative()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store, nativeDecompiler: native))
        let request = ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("decompile"), "arguments": address]),
        ])
        let bytes = await server.handleMessageAsync(try request.jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        XCTAssertNil(envelope["error"])
        XCTAssertEqual(envelope["result"]?["isError"], .bool(true))
        XCTAssertEqual(envelope["result"]?["content"]?.arrayValue?.first?["text"],
                       .string(MCPToolRefusal(code: .budgetExceeded, detail: bytesText,
                           budget: .init(unit: .bytes, limit: 262_144), used: 262_145, narrowing: []).text))
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0, nativeDecompiler: native) })
        attached.setConsent(.allowed)
        do {
            _ = try await attached.execute("decompile", address)
            XCTFail("expected attached size refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, bytesText)
        }
        XCTAssertEqual(native.calls.count, 0)
    }

    // F5: fails before: the pin reaches extraction/build/render checkpoints.
    func testSizeRefusalPrecedesExtractionCheckpoint() async {
        let store = sizedStore(bytes: 32_772, blocks: 8_193)
        let visits = SizeRefusalCounter()
        let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { visits.increment() })
        do {
            _ = try await api.executeAsync("decompile", arguments: address)
            XCTFail("expected size refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, blocksText)
        }
        XCTAssertEqual(visits.count, 10) // entry, eight scan checkpoints, and the scan tail
    }

    func testSizeScanPropagatesCancellationBeforeFinishing() throws {
        let store = sizedStore(bytes: 32_772, blocks: 2_049)
        let snapshot = store.snapshot
        let function = try XCTUnwrap(snapshot.analysis(in: snapshot.primarySlot)?.functions.first)
        var visits = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.decompileSizeCheck(
            function, in: snapshot.primarySlot, snapshot: snapshot, checkpoint: {
                visits += 1
                if visits == 2 { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(visits, 2)
    }

    func testSizeScanCancellationPreventsNativeCall() async {
        let store = sizedStore(bytes: 32_772, blocks: 2_049)
        let visits = SizeRefusalCounter()
        let native = SizeRefusalNative()
        do {
            _ = try await WorkspaceScriptingAPI.decompileNativeFirst(
                address, snapshot: store.snapshot, native: native, checkpoint: {
                    visits.increment()
                    if visits.count == 2 { throw CancellationError() }
                })
            XCTFail("cancelled scan must not return a result")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertEqual(visits.count, 2)
        XCTAssertEqual(native.calls.count, 0)
    }

    // C1: positive control (passes before): equality at both limits is admitted.
    func testControlAtLimitIsNotRefused() async throws {
        let store = sizedStore(bytes: 262_144, blocks: 8_192)
        let native = SizeRefusalNative()
        let result = try await WorkspaceScriptingAPI(store: store, nativeDecompiler: native)
            .executeAsync("decompile", arguments: address)
        XCTAssertEqual(result["backend"], .string("native"))
        XCTAssertEqual(native.calls.count, 1)
    }

    // C2: positive control (passes before): no assumptions about empty-body rendering.
    func testControlZeroWidthFunctionCountsZeroBytes() {
        let store = sizedStore(bytes: 0, blocks: 1)
        do {
            _ = try WorkspaceScriptingAPI(store: store).execute("decompile", arguments: address)
        } catch {
            let detail = (error as? LocalizedError)?.errorDescription ?? ""
            XCTAssertFalse(detail.hasPrefix("function too large"))
            XCTAssertFalse(detail.hasPrefix("decompile deadline"))
        }
    }

    // C3: positive control (passes before): FNR's demonstrated helper rendering.
    func testControlSmallFunctionReplyUnchanged() throws {
        let store = smallStore()
        let result = try WorkspaceScriptingAPI(store: store).execute(
            "decompile", arguments: .object(["function": .string("helper")]))
        XCTAssertEqual(result["backend"], .string("macir"))
        XCTAssertEqual(result["function"], .string("helper"))
        XCTAssertEqual(result["fallbackReason"], .string("native-unavailable"))
    }

    private func sizedStore(bytes: UInt64, blocks: Int) -> WorkspaceStore {
        let id = UUID()
        let snap = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "size", path: "/tmp/size",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: id, name: "big", startAddress: 0x1000, endAddress: 0x1000 + bytes, confidence: 1),
                FunctionSummary(id: UUID(), name: "small", startAddress: 0x900000, endAddress: 0x900004, confidence: 1),
            ],
            basicBlocks: (0..<blocks).map {
                BasicBlockSummary(id: UUID(), functionID: id, startAddress: UInt64(0x1000 + $0 * 4),
                                  endAddress: UInt64(0x1004 + $0 * 4), instructionCount: 1)
            }, instructions: [], xrefs: [], hexBytes: Data())
        return WorkspaceStore(workspaceName: "size refusal", snapshot: snap,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func smallStore() -> WorkspaceStore {
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
