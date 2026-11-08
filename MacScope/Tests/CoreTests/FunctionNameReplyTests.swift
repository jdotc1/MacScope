import Foundation
import XCTest
@testable import MacScope

private struct FunctionNameReplyNativeStub: ScriptingNativeDecompiling {
    let outcome: ScriptingNativeDecompileOutcome
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        outcome
    }
}

@MainActor
final class FunctionNameReplyTests: XCTestCase {
    private func makeStore() -> WorkspaceStore {
        let mainID = UUID()
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "names", path: "/tmp/names",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: mainID, name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "helper", startAddress: 0x1008, endAddress: 0x100c, confidence: 1),
            ],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: mainID, startAddress: 0x1000,
                                           endAddress: 0x1008, instructionCount: 2)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov",
                               operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "01 00 00 94", mnemonic: "bl",
                               operands: "helper", hasBreakpoint: false, comment: "call"),
                InstructionRow(address: 0x1008, bytes: "c0 03 5f d6", mnemonic: "ret",
                               operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [XRef(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            controlFlowEdges: [ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                                     size: 0x200, fileOffset: 0x1000, isExecutable: true)])
        return WorkspaceStore(workspaceName: "Function names", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func renameHelper(_ store: WorkspaceStore) throws {
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
            "address": .hex(0x1008), "name": .string("renamed_helper")
        ]))
    }

    private func request(_ command: String, _ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                 "params": .object(["name": .string(command), "arguments": arguments])])
    }

    // W4: fails before only on function identity; the header already uses renamed_helper.
    func testMacIRReportsDisplayNameForAddressNewNameAndRawName() throws {
        let store = makeStore()
        try renameHelper(store)
        let api = WorkspaceScriptingAPI(store: store)
        for arguments in [
            ScriptValue.object(["address": .hex(0x1008)]),
            .object(["function": .string("renamed_helper")]),
            .object(["function": .string("helper")]),
        ] {
            let reply = try api.execute("decompile", arguments: arguments)
            XCTAssertEqual(reply["function"], .string("renamed_helper"))
            XCTAssertEqual(reply["address"], .hex(0x1008))
            XCTAssertEqual(reply["backend"], .string("macir"))
            XCTAssertTrue(reply["pseudocode"]?.stringValue?.contains("renamed_helper") == true)
        }
    }

    // W4: native completion and all fallback outcomes fail before on function, not text.
    func testAsyncNativeAndFallbackRepliesReportDisplayName() async throws {
        let store = makeStore()
        try renameHelper(store)
        let nativeText = "void renamed_helper(void)\n{\n}"
        let outcomes: [(ScriptingNativeDecompileOutcome, String, String?)] = [
            (.completed(NativeDecompilerWirePseudocodeDocument(text: nativeText, language: "c",
                         isComplete: true, isTruncated: false)), "native", nil),
            (.failed(code: "timed-out"), "macir", "native-failed: timed-out"),
            (.unavailable, "macir", "native-unavailable"),
            (.completed(nil), "macir", "native-empty"),
            (.completed(NativeDecompilerWirePseudocodeDocument(text: " \n", language: "c",
                         isComplete: true, isTruncated: false)), "macir", "native-empty"),
        ]
        for (outcome, backend, fallback) in outcomes {
            let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: FunctionNameReplyNativeStub(outcome: outcome))
            let reply = try await api.executeAsync("decompile", arguments: .object(["address": .hex(0x1008)]))
            XCTAssertEqual(reply["function"], .string("renamed_helper"))
            XCTAssertEqual(reply["backend"], .string(backend))
            XCTAssertEqual(reply["fallbackReason"]?.stringValue, fallback)
            if backend == "native" { XCTAssertEqual(reply["pseudocode"], .string(nativeText)) }
        }
    }

    // W4: MCP authority and attached routes use the same corrected native reply builder.
    func testMCPAndAttachedDecompileReportDisplayName() async throws {
        let store = makeStore()
        try renameHelper(store)
        let outcome = ScriptingNativeDecompileOutcome.completed(NativeDecompilerWirePseudocodeDocument(
            text: "void renamed_helper(void) {}", language: "c", isComplete: true, isTruncated: false))
        let stub = FunctionNameReplyNativeStub(outcome: outcome)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: stub)
        let arguments = ScriptValue.object(["function": .string("renamed_helper")])
        let authority = try await HeadlessAutomationAuthority.executeAsync(
            command: "decompile", arguments: arguments, api: api)
        XCTAssertEqual(authority["function"], .string("renamed_helper"))
        let server = MCPServer(api: api)
        let bytes = await server.handleMessageAsync(try request("decompile", arguments).jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
        let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertEqual(try ScriptValue.decode(Data(text.utf8))["function"], .string("renamed_helper"))
        let attached = MCPAttachExecutor(store: store, api: {
            WorkspaceScriptingAPI(store: $0, nativeDecompiler: stub)
        })
        attached.setConsent(.allowed)
        let reply = try await attached.execute("decompile", arguments)
        XCTAssertEqual(reply["function"], .string("renamed_helper"))
    }

    // W4: colliding addresses must use the selected image's override, not UI focus.
    func testTwoImageNamesStayInTheirSelectedSlots() async throws {
        let sibling = ImageSlot(rawValue: 1)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "image", path: "/tmp/image",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        func analysis(_ name: String) -> ImageAnalysis {
            var value = ImageAnalysis()
            value.functions = [FunctionSummary(id: UUID(), name: name, startAddress: 0x5000,
                                               endAddress: 0x5004, confidence: 1)]
            value.instructions = [InstructionRow(address: 0x5000, bytes: "c0 03 5f d6",
                mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil)]
            return value
        }
        let snapshot = WorkspaceSnapshot(
            binaries: [image(.primary), image(sibling)],
            analysisBySlot: [.primary: analysis("primary_fn"), sibling: analysis("sibling_fn")],
            addressOverrides: [
                ImageAddress(slot: .primary, address: 0x5000): AddressOverride(customName: "AProcedure"),
                ImageAddress(slot: sibling, address: 0x5000): AddressOverride(customName: "BProcedure"),
            ])
        let store = WorkspaceStore(workspaceName: "Two names", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        store.focusImage(sibling)
        let api = WorkspaceScriptingAPI(store: store)
        for (slot, name) in [(0, "AProcedure"), (1, "BProcedure")] {
            let arguments = ScriptValue.object(["address": .hex(0x5000), "image": .int(Int64(slot))])
            let inline = try api.execute("decompile", arguments: arguments)
            let asyncReply = try await api.executeAsync("decompile", arguments: arguments)
            for reply in [inline, asyncReply] {
                XCTAssertEqual(reply["function"], .string(name))
                XCTAssertEqual(reply["imageSlot"], .int(Int64(slot)))
                XCTAssertEqual(reply["address"], .hex(0x5000))
            }
        }
    }

    // Positive W4 controls: no override, undo and parameter audit already have this behavior.
    func testRawNameUndoAndParameterAuditControls() throws {
        let store = makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertEqual(try api.execute("decompile", arguments: .object(["address": .hex(0x1008)]))["function"],
                       .string("helper"))
        try renameHelper(store)
        let audit = try api.execute("parameter-binding-audit",
                                    arguments: .object(["function": .string("renamed_helper")]))
        XCTAssertEqual(audit["function"], .string("renamed_helper"))
        while store.undoManager.canUndo { store.undoManager.undo() }
        XCTAssertEqual(try api.execute("decompile", arguments: .object(["address": .hex(0x1008)]))["function"],
                       .string("helper"))
    }

    // N3-empty regression: passes before and after on every supplied read route.
    func testNameMissesThrowOnEveryReadRoute() async throws {
        let store = makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        let arguments = ScriptValue.object(["function": .string("missing_function")])
        let expected = ScriptingError.invalidArgument("no function named 'missing_function'")
        for command in ["callers", "callees", "basic-blocks", "instructions", "decompile",
                        "register-names", "parameter-binding-audit", "stack-locals", "indirect-call-targets"] {
            XCTAssertThrowsError(try api.execute(command, arguments: arguments)) {
                XCTAssertEqual($0 as? ScriptingError, expected)
            }
            do {
                _ = try await api.executeAsync(command, arguments: arguments)
                XCTFail("name miss returned a value: \(command)")
            } catch { XCTAssertEqual(error as? ScriptingError, expected) }
            do {
                _ = try await HeadlessAutomationAuthority.executeAsync(command: command, arguments: arguments, api: api)
                XCTFail("authority name miss returned a value: \(command)")
            } catch { XCTAssertEqual(error as? ScriptingError, expected) }
            let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
            attached.setConsent(.allowed)
            do {
                _ = try await attached.execute(command, arguments)
                XCTFail("attached name miss returned a value: \(command)")
            } catch { XCTAssertEqual(error as? ScriptingError, expected) }
            let server = MCPServer(api: api)
            let bytes = await server.handleMessageAsync(try request(command, arguments).jsonData())
            let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
            XCTAssertNil(envelope["error"])
            XCTAssertEqual(envelope["result"]?["isError"], .bool(true))
            XCTAssertEqual(envelope["result"]?["content"]?.arrayValue?.first?["text"],
                           .string("Tool call failed: Invalid argument: no function named 'missing_function'."))
        }
    }

    // N3-empty regression: a match with no call edges is legitimately empty.
    func testMatchedNameWithNoCallersIsSuccessfulEmpty() async throws {
        let store = makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        let arguments = ScriptValue.object(["function": .string("_main")])
        XCTAssertEqual(try api.execute("callers", arguments: arguments), .array([]))
        let asyncReply = try await api.executeAsync("callers", arguments: arguments)
        XCTAssertEqual(asyncReply, .array([]))
        let authority = try await HeadlessAutomationAuthority.executeAsync(command: "callers", arguments: arguments, api: api)
        XCTAssertEqual(authority, .array([]))
        let server = MCPServer(api: api)
        let bytes = await server.handleMessageAsync(try request("callers", arguments).jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
        XCTAssertEqual(envelope["result"]?["content"]?.arrayValue?.first?["text"], .string("[]"))
    }

    // N3-empty mutation regression: resolution fails before any override or undo edit.
    func testMissingRegisterRenameLeavesStateAndUndoUnchanged() throws {
        let store = makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        let before = store.snapshot.addressOverrides
        let canUndo = store.undoManager.canUndo
        XCTAssertThrowsError(try api.execute("rename-register", arguments: .object([
            "function": .string("missing_function"), "register": .string("x19"), "name": .string("ctx")
        ]))) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument("no function named 'missing_function'"))
        }
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        XCTAssertEqual(store.undoManager.canUndo, canUndo)
        let renamed = try api.execute("rename", arguments: .object([
            "address": .hex(0x1008), "name": .string("renamed_helper")
        ]))
        XCTAssertEqual(renamed["name"], .string("renamed_helper"))
    }
}
