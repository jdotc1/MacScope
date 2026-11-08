import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

@MainActor
final class BatchSlotReceiptTests: XCTestCase {
    private func makeStore() -> WorkspaceStore {
        let primary = ImageSlot(rawValue: 7), sibling = ImageSlot(rawValue: 9)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        let snapshot = WorkspaceSnapshot(binaries: [image(primary), image(sibling)],
            analysisBySlot: [primary: ImageAnalysis(), sibling: ImageAnalysis()])
        let store = WorkspaceStore(workspaceName: "receipt", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
        store.focusImage(sibling)
        return store
    }

    func testCaptureReportsActualPrimaryAndPreservesLegacySuccessKeys() throws {
        for (command, field, text) in [("set-local-labels", "label", "label"), ("set-operand-formats", "format", "hex"), ("set-types", "type", "UnknownType")] {
            let store = makeStore(), capture = ScriptingBatchReceiptCapture()
            let arguments: ScriptValue = .object(["entries": .array([.object(["address": .hex(0x1000), field: .string(text)])])])
            let result = try ScriptingBatchReceiptCapture.$current.withValue(capture) {
                try WorkspaceScriptingAPI(store: store).execute(command, arguments: arguments)
            }
            // Item 1243 / VI1-B: readback is additive for every batch edit tool.
            var legacy = try XCTUnwrap(result.objectValueForReadbackTest)
            do {
                let requested = legacy.removeValue(forKey: "requested")
                let observed = legacy.removeValue(forKey: "observed")
                XCTAssertNotNil(requested)
                XCTAssertEqual(requested, observed)
                XCTAssertEqual(legacy.removeValue(forKey: "verification"), .string("full-state-equal"))
            }
            _ = legacy.removeValue(forKey: "readback") // VI1-B per-item summary, only on the newer tools
            XCTAssertEqual(ScriptValue.object(legacy), .object(["ok": .bool(true), "count": .int(1), "changed": .int(1)]))
            XCTAssertEqual(capture.receipt?.imageSlot, 7)
            XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: ImageSlot(rawValue: 9), address: 0x1000)])
        }
    }

    func testHistoricalReceiptRetainsSlotAfterUndo() throws {
        let store = makeStore()
        let script: ScriptValue = .array([
            .object(["command": .string("set-local-labels"), "arguments": .object(["entries": .array([
                .object(["address": .hex(0x1000), "label": .string("label")])])])]),
            .object(["command": .string("undo-last")]), .object(["command": .string("missing-command")])
        ])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).runScript(script)) { error in
            XCTAssertTrue(error.localizedDescription.contains("imageSlot=7"))
            XCTAssertTrue(error.localizedDescription.contains("Current state may have changed later"))
        }
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testIdentityFailureRetainsCapturedSlotAfterPrimaryChanges() async throws {
        enum Failure: Error { case identity }
        for asyncCall in [false, true] {
            let store = makeStore()
            var checks = 0
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store), validateWorkspaceIdentity: {
                checks += 1
                if checks == 2 { store.snapshot.binaries.reverse(); throw Failure.identity }
            })
            let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                "params": .object(["name": .string("set-local-labels"), "arguments": .object(["entries": .array([
                    .object(["address": .hex(0x1000), "label": .string("label")])])])])])
            let data = try request.jsonData()
            let responseData: Data? = asyncCall ? await server.handleMessageAsync(data) : server.handleMessage(data)
            let response = try ScriptValue.decode(XCTUnwrap(responseData))
            let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertTrue(text.contains("count=1, changed=1, imageSlot=7"), text)
            XCTAssertEqual(store.snapshot.primarySlot, ImageSlot(rawValue: 9))
        }
    }

    func testUnknownExecutorSlotIsNotGuessed() async throws {
        enum Failure: Error { case identity }
        let store = makeStore()
        var checks = 0
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), validateWorkspaceIdentity: {
            checks += 1; if checks == 2 { throw Failure.identity }
        }, asyncCommandExecutor: { _, _ in .object(["count": .int(1), "changed": .int(0)]) })
        let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("set-local-labels"), "arguments": .object(["entries": .array([
                .object(["address": .hex(0x1000), "label": .string("label")])])])])])
        let data = await server.handleMessageAsync(try request.jsonData())
        let response = try ScriptValue.decode(XCTUnwrap(data))
        let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertTrue(text.contains("count=1, changed=0"), text)
        XCTAssertFalse(text.contains("imageSlot"), text)
    }
    func testLargestSlotReceiptFitsWithAdmittedOriginalID() throws {
        let receipt = ScriptingBatchHistoryFailure.Receipt(command: "clear-segment-overrides", count: 1024,
                                                             changed: 1024, imageSlot: Int64.max)
        let id = MacScopeAnalysisCore.Phase2ProductionJSONValue.number("1e" + String(repeating: "0", count: 126))
        XCTAssertTrue(MCPBatchReceiptBudget.admits(idBytes: id.canonicalJSONBytes().count, maximumBytes: 512))
        let message = receipt.summary + "; reporting failed. Do not retry automatically."
        let frame = try MCPFrameAdmission.response(Data(), id: id, maximumBytes: 512,
                                                   failureMessage: message, compactMessage: message)
        XCTAssertLessThan(frame.count, 512)
        let decoded = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(frame, limits: .providerEnvelope)
        XCTAssertEqual(decoded.objectValue?["id"], id)
        XCTAssertEqual(decoded.objectValue?["error"]?.objectValue?["message"], .string(message))
    }

    func testSessionOverflowKeepsReturnedSlotAndOriginalID() async throws {
        let store = makeStore(), api = WorkspaceScriptingAPI(store: store), output = SlotReceiptOutput()
        let server = MCPServer(api: api, configuration: .init(maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8),
            asyncCommandExecutor: { command, arguments in
                let result = try api.execute(command, arguments: arguments)
                return .object(["count": result["count"]!, "changed": result["changed"]!,
                                "padding": .string(String(repeating: "x", count: 1024))])
            })
        let session = server.makeRequestSession(output: { await output.append($0) })
        let id = "1e" + String(repeating: "0", count: 126)
        let body = "{\"jsonrpc\":\"2.0\",\"id\":\(id),\"method\":\"tools/call\",\"params\":{\"name\":\"set-local-labels\",\"arguments\":{\"entries\":[{\"address\":\"0x1000\",\"label\":\"label\"}]}}}"
        await session.receive(Data(body.utf8))
        let frame = await output.first()
        await session.finishInput()
        let frames = await output.values
        XCTAssertEqual(frames.count, 1)
        XCTAssertLessThan(frame.count, 512)
        let value = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(frame, limits: .providerEnvelope)
        XCTAssertEqual(value.objectValue?["id"], .number(id))
        XCTAssertTrue(String(decoding: frame, as: UTF8.self).contains("count=1, changed=1, imageSlot=7"))
    }

}

private extension ScriptValue {
    var objectValueForReadbackTest: [String: ScriptValue]? {
        guard case .object(let fields) = self else { return nil }
        return fields
    }
}


private actor SlotReceiptOutput {
    private(set) var values: [Data] = []
    private var waiter: CheckedContinuation<Data, Never>?
    func append(_ data: Data) {
        values.append(data)
        waiter?.resume(returning: data)
        waiter = nil
    }
    func first() async -> Data {
        if let value = values.first { return value }
        return await withCheckedContinuation { waiter = $0 }
    }
}
