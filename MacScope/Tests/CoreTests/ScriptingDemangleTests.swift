import Foundation
import XCTest
@testable import MacScope

private struct ScriptingDemangleNativeStub: ScriptingNativeDecompiling {
    let outcome: ScriptingNativeDecompileOutcome
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome { outcome }
}

@MainActor
final class ScriptingDemangleTests: XCTestCase {
    private enum Route: CaseIterable, Equatable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    private let getter = "$s3app5ModelV5countSivg"
    private let getterText = "app.Model.count.getter : Swift.Int"
    private let asynchronous = "_$s10DataViewerAAC12setDirectory_12forSessionIdy10Foundation3URLV_AE4UUIDVtYaF"
    private let asynchronousText = "DataViewer.DataViewer.setDirectory(_: Foundation.URL, forSessionId: Foundation.UUID) async -> ()"
    private let tgpro = "_$s10Foundation10NSNotFoundSivg"
    private let tgproText = "Foundation.NSNotFound.getter : Swift.Int"
    private let staticProperty = "_$s10DataViewerAAC5localABvgZ"
    private let staticPropertyText = "static DataViewer.DataViewer.local.getter : DataViewer.DataViewer"
    private let ghosttyText = "static Ghostty.Ghostty.App.action(_: Swift.UnsafeMutableRawPointer, target: __C.ghostty_target_s, action: __C.ghostty_action_s) -> Swift.Bool"
    private let ghostty = "_$s7GhosttyAAO3AppC6action_6targetAESbSv_So08ghostty_D2_saSo0e1_C2_satFZ"
    private let sibling = ImageSlot(rawValue: 1)
    private var overlong: String { "$s" + String(repeating: "a", count: 8_191) }
    private var depthLimited: String { "$syHX" + String(repeating: "_HX", count: 65) }

    private func makeStoreA() -> WorkspaceStore {
        var analysis = ImageAnalysis()
        let names = [getter, asynchronous, "_main", "_$s", "_ZN3foo3barEv", overlong, ghostty]
        for (index, name) in names.enumerated() {
            let start = UInt64(0x1000 + index * 8)
            analysis.functions.append(FunctionSummary(id: UUID(), name: name, startAddress: start,
                                                       endAddress: start + 8, confidence: 1))
        }
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: tgpro, address: 0x3000, kind: "local", libraryName: nil),
            SymbolSummary(id: UUID(), name: staticProperty, address: 0x3008, kind: "local", libraryName: nil),
            SymbolSummary(id: UUID(), name: "_main", address: 0x1010, kind: "local", libraryName: nil),
        ]
        let image = BinaryImage(id: UUID(), name: "demangle", path: "/fixture",
                                kind: "Mach-O executable", architecture: "arm64")
        return WorkspaceStore(workspaceName: "demangle", snapshot: WorkspaceSnapshot(
            binaries: [image], analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func request(_ command: String, _ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": arguments])])
    }
    private func envelope(_ route: Route, _ api: WorkspaceScriptingAPI,
                          _ command: String, _ arguments: ScriptValue) async throws -> ScriptValue {
        let server = MCPServer(api: api)
        let data = try request(command, arguments).jsonData()
        let response: Data?
        if route == .mcpSync { response = server.handleMessage(data) }
        else { response = await server.handleMessageAsync(data) }
        return try ScriptValue.decode(try XCTUnwrap(response))
    }
    private func read(_ route: Route, _ store: WorkspaceStore,
                      _ command: String, _ arguments: ScriptValue) async throws -> ScriptValue {
        let api = WorkspaceScriptingAPI(store: store)
        switch route {
        case .inline: return try api.execute(command, arguments: arguments)
        case .asynchronous: return try await api.executeAsync(command, arguments: arguments)
        case .attached:
            let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
            executor.setConsent(.allowed)
            return try await executor.execute(command, arguments)
        case .mcpSync, .mcpAsync:
            let reply = try await envelope(route, api, command, arguments)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            return try ScriptValue.decode(Data(text.utf8))
        }
    }
    private func refuses(_ route: Route, _ store: WorkspaceStore, _ arguments: ScriptValue,
                         _ expected: ScriptingError, attachedInvalid: Bool = false,
                         mcpRefusal: MCPToolRefusal? = nil) async throws {
        if route == .mcpSync || route == .mcpAsync {
            let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), "demangle", arguments)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            let refusal = try XCTUnwrap(mcpRefusal ?? MCPToolRefusal.executionRefusal(expected))
            XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string(refusal.text))
        } else {
            do {
                _ = try await read(route, store, "demangle", arguments)
                XCTFail("expected refusal")
            } catch {
                if route == .attached && attachedInvalid {
                    XCTAssertEqual(error as? HeadlessAutomationAuthorityError, .invalidArguments)
                } else { XCTAssertEqual(error as? ScriptingError, expected) }
            }
        }
    }
    private func row(_ rows: [ScriptValue], at address: UInt64) throws -> ScriptValue {
        try XCTUnwrap(rows.first { $0["address"] == .hex(address) })
    }
    private func withoutDemangled(_ row: ScriptValue) throws -> ScriptValue {
        guard case .object(var fields) = row else {
            XCTFail("expected row object")
            return row
        }
        fields.removeValue(forKey: "demangled")
        return .object(fields)
    }
    private func assertJSONEqual(_ actual: ScriptValue, _ expected: ScriptValue,
                                 file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try ScriptValue.decode(actual.jsonData()), try ScriptValue.decode(expected.jsonData()),
                       file: file, line: line)
    }
    private func makeStoreB(_ edit: (inout ImageAnalysis) -> Void = { _ in }) -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "stub-fixture", path: "/fixture",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        func analysis(_ slot: ImageSlot) -> ImageAnalysis {
            var value = ImageAnalysis()
            value.functions = [
                FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "helper", startAddress: 0x1008, endAddress: 0x100c, confidence: 1),
            ]
            let sources: [UInt64] = slot == .primary ? [0x1004] : [0x1000, 0x1004]
            value.xrefs = sources.map { XRef(id: UUID(), from: $0, to: 0x1008, kind: XRefKind.call) }
                + sources.map { XRef(id: UUID(), from: $0, to: 0x2000, kind: XRefKind.call) }
            value.sections = [
                SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                               size: 0x200, fileOffset: 0, isExecutable: true),
                SectionSummary(id: UUID(), name: "__TEXT,__objc_stubs", address: 0x2000,
                               size: 0x40, fileOffset: 0x200, isExecutable: true),
            ]
            value.symbols = [SymbolSummary(id: UUID(), name: "_objc_msgSend$tick", address: 0x2000,
                                          kind: "stub", libraryName: nil)]
            edit(&value)
            return value
        }
        return WorkspaceStore(workspaceName: "stub callers",
            snapshot: WorkspaceSnapshot(binaries: [image(.primary), image(sibling)],
                analysisBySlot: [.primary: analysis(.primary), sibling: analysis(sibling)]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func makeStoreC() -> WorkspaceStore {
        let mainID = UUID()
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "names", path: "/tmp/names",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: mainID, name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: getter, startAddress: 0x1008, endAddress: 0x100c, confidence: 1),
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

    func testF1FunctionPagesUseEmittedNamesOnEveryRoute() async throws {
        for route in Route.allCases {
            let store = makeStoreA()
            let legacy = try await read(route, store, "functions", .object([:]))
            let page = try await read(route, store, "functions", .object(["page": .bool(true), "limit": .int(100)]))
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(rows.count, 7)
            guard case .object(let envelopeFields) = page else { return XCTFail("expected page") }
            XCTAssertEqual(Set(envelopeFields.keys), Set(["rows", "total", "isTruncated", "nextCursor", "sourceComplete"]))
            XCTAssertEqual(page["total"], .int(7))
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["nextCursor"], .null)
            XCTAssertEqual(page["sourceComplete"], .null)
            XCTAssertEqual(try row(rows, at: 0x1000)["demangled"], .string(getterText))
            XCTAssertEqual(try row(rows, at: 0x1008)["demangled"], .string(asynchronousText))
            for address in [UInt64(0x1010), 0x1018, 0x1020, 0x1028] {
                XCTAssertNil(try row(rows, at: address)["demangled"])
            }
            // Item 888 (AA-context demangling) renders the real Ghostty name.
            XCTAssertEqual(try row(rows, at: 0x1030)["name"], .string(ghostty))
            XCTAssertEqual(try row(rows, at: 0x1030)["demangled"], .string(ghosttyText))
            try assertJSONEqual(.array(try rows.map(withoutDemangled)), legacy)
            _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
                "address": .hex(0x1000), "name": .string("count_getter")]))
            let renamed = try await read(route, store, "functions", .object(["page": .bool(true)]))
            let renamedRow = try row(XCTUnwrap(renamed["rows"]?.arrayValue), at: 0x1000)
            XCTAssertEqual(renamedRow["name"], .string("count_getter"))
            XCTAssertNil(renamedRow["demangled"])
        }
    }

    func testF2SymbolPagesPreserveOtherFieldsOnEveryRoute() async throws {
        for route in Route.allCases {
            let store = makeStoreA()
            let legacy = try await read(route, store, "symbols", .object([:]))
            let page = try await read(route, store, "symbols", .object(["page": .bool(true)]))
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(try row(rows, at: 0x3000)["demangled"], .string(tgproText))
            XCTAssertEqual(try row(rows, at: 0x3008)["demangled"], .string(staticPropertyText))
            XCTAssertNil(try row(rows, at: 0x1010)["demangled"])
            try assertJSONEqual(.array(try rows.map(withoutDemangled)), legacy)
        }
    }

    func testF3NameAtConditionalShapeOnEveryRoute() async throws {
        for route in Route.allCases {
            let store = makeStoreA()
            let cases: [(UInt64, ScriptValue)] = [
                (0x1000, .object(["name": .string(getter), "demangled": .string(getterText)])),
                (0x1030, .object(["name": .string(ghostty), "demangled": .string(ghosttyText)])), (0x1010, .string("_main")),
                (0x3000, .object(["name": .string(tgpro), "demangled": .string(tgproText)])),
                (0x5000, .null),
            ]
            for (address, expected) in cases {
                let value = try await read(route, store, "name-at", .object(["address": .hex(address)]))
                XCTAssertEqual(value, expected)
            }
            _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
                "address": .hex(0x1000), "name": .string("count_getter")]))
            let renamed = try await read(route, store, "name-at", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(renamed, .string("count_getter"))
        }
    }

    func testF4StubCallersIncludeOwnerRenderingInBothSlots() async throws {
        let store = makeStoreB { $0.functions[0].name = self.getter }
        for slot in [0, 1] {
            let sources: [UInt64] = slot == 0 ? [0x1004] : [0x1000, 0x1004]
            let expected: ScriptValue = .array(sources.map { source in
                .object(["from": .hex(source), "to": .hex(0x2000), "imageSlot": .int(Int64(slot)),
                         "fromFunction": .hex(0x1000), "fromFunctionName": .string(getter),
                         "fromFunctionDemangled": .string(getterText),
                         "toName": .string("_objc_msgSend$tick"), "selector": .string("tick")])
            })
            for route in Route.allCases {
                let result = try await read(route, store, "callers", .object([
                    "address": .hex(0x2000), "imageSlot": .int(Int64(slot))]))
                XCTAssertEqual(result, expected)
            }
        }
    }

    func testStubCallerPlainRenameSuppressesRenderingOnEveryRoute() async throws {
        let store = makeStoreB { $0.functions[0].name = self.getter }
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
            "address": .hex(0x1000), "name": .string("count_getter")]))
        for route in Route.allCases {
            let reply = try await read(route, store, "callers", .object(["address": .hex(0x2000), "imageSlot": .int(0)]))
            let rows = try XCTUnwrap(reply.arrayValue)
            XCTAssertEqual(rows.count, 1)
            XCTAssertEqual(rows[0]["fromFunctionName"], .string("count_getter"))
            XCTAssertNil(rows[0]["fromFunctionDemangled"])
        }
    }

    func testF5DecompileBothBackendsUseEmittedName() async throws {
        let nativeText = "void fixture(void) {}"
        let outcomes: [(ScriptingNativeDecompileOutcome, String)] = [
            (.completed(NativeDecompilerWirePseudocodeDocument(text: nativeText, language: "c",
                isComplete: true, isTruncated: false)), "native"),
            (.failed(code: "timed-out"), "macir"), (.unavailable, "macir"),
        ]
        for (outcome, backend) in outcomes {
            let store = makeStoreC()
            let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: ScriptingDemangleNativeStub(outcome: outcome))
            let arguments = ScriptValue.object(["address": .hex(0x1008)])
            let inline = try api.execute("decompile", arguments: arguments)
            let asynchronousReply = try await api.executeAsync("decompile", arguments: arguments)
            for reply in [inline, asynchronousReply] {
                XCTAssertEqual(reply["function"], .string(getter))
                XCTAssertEqual(reply["demangled"], .string(getterText))
            }
            XCTAssertEqual(inline["backend"], .string("macir"))
            XCTAssertEqual(asynchronousReply["backend"], .string(backend))
            if backend == "native" { XCTAssertEqual(asynchronousReply["pseudocode"], .string(nativeText)) }
            _ = try api.execute("rename", arguments: .object(["address": .hex(0x1008), "name": .string("renamed_helper")]))
            let renamedInline = try api.execute("decompile", arguments: arguments)
            let renamedAsync = try await api.executeAsync("decompile", arguments: arguments)
            for reply in [renamedInline, renamedAsync] {
                XCTAssertEqual(reply["function"], .string("renamed_helper"))
                XCTAssertNil(reply["demangled"])
            }
        }
    }

    func testF6DemangleSuccessIncludingGhosttyOnEveryRoute() async throws {
        let store = makeStoreA()
        for route in Route.allCases {
            for (name, text) in [(getter, getterText), (asynchronous, asynchronousText), (tgpro, tgproText), (ghostty, ghosttyText)] {
                let reply = try await read(route, store, "demangle", .object(["name": .string(name)]))
                XCTAssertEqual(reply, .object(["name": .string(name), "demangled": .string(text), "language": .string("swift")]))
            }
        }
    }

    func testF7RefusalsOnEveryRouteIncludingShortDepthMarker() async throws {
        let store = makeStoreA()
        XCTAssertEqual(depthLimited.utf8.count, 200)
        // Derived from DemanglerTests.testSwiftPackProtocolConformanceDepthBudget.
        XCTAssertEqual(Demangler.mangledToReadable(depthLimited), SwiftDemangler.tooComplexMarker)
        for route in Route.allCases {
            for name in ["_ZN3foo3barEv", "_Rexample", ""] {
                try await refuses(route, store, .object(["name": .string(name)]), .structuredRefusal(
                    MCPToolRefusal(code: .malformedInput, detail: "name is not a Swift mangled name", field: "name",
                                  expected: "a Swift mangled name ($s, $S, _$s, _$S or _TtC prefix)")))
            }
            try await refuses(route, store, .object(["name": .string("_$s")]), .structuredRefusal(
                MCPToolRefusal(code: .malformedInput, detail: "the in-tree demangler does not cover this Swift name", field: "name")))
            try await refuses(route, store, .object(["name": .string(overlong)]), .structuredRefusal(
                MCPToolRefusal(code: .outOfBounds, detail: "Field 'name' must contain at most 8192 UTF-8 bytes.",
                               field: "name", maximum: 8_192)), attachedInvalid: true)
            try await refuses(route, store, .object(["name": .string(depthLimited)]), .structuredRefusal(
                MCPToolRefusal(code: .budgetExceeded, detail: "name exceeds the demangler's depth, work or output budget", field: "name")))
            try await refuses(route, store, .object([:]), .missingArgument("name"), attachedInvalid: true,
                mcpRefusal: ToolArgumentError(field: "name", detail: "Field 'name' is required.", expected: "string").refusal)
            try await refuses(route, store, .object(["name": .int(7)]), .invalidArgument("name must be a string"), attachedInvalid: true,
                mcpRefusal: ToolArgumentError(field: "name", detail: "Field 'name' must be a string.", expected: "string").refusal)
        }
        for route in [Route.mcpSync, .mcpAsync] {
            let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), "demangle",
                .object(["name": .string(getter), "x": .int(1)]))
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            let expected = ToolArgumentError(field: "x", detail: "Field 'x' is not an allowed argument.", allowed: ["name"]).refusal
            XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string(expected.text))
        }
    }

    func testF8CommandCatalogsAndSchema() throws {
        let info = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "demangle" })
        XCTAssertFalse(info.mutates)
        XCTAssertEqual(info.arguments, ["name"])
        XCTAssertTrue(HeadlessAutomationAuthority.availableCommands.contains { $0.name == "demangle" })
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("demangle"))
        XCTAssertTrue(WorkspaceScriptingAPI.snapshotListCommands.contains("demangle"))
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        XCTAssertEqual(schema["required"], .array([.string("name")]))
        XCTAssertEqual(schema["properties"]?["name"]?["type"], .string("string"))
        XCTAssertEqual(schema["properties"]?["name"]?["maxLength"], .int(8_192))
        XCTAssertEqual(schema["additionalProperties"], .bool(false))
    }

    func testC1bLegacyArraysRemainExactlyThePinRows() async throws {
        let names = [getter, asynchronous, "_main", "_$s", "_ZN3foo3barEv", overlong, ghostty]
        let functions: ScriptValue = .array(names.enumerated().map { index, name in
            let start = UInt64(0x1000 + index * 8)
            return .object(["name": .string(name), "address": .hex(start), "end": .hex(start + 8), "confidence": .double(1)])
        })
        let symbols: ScriptValue = .array([
            .object(["name": .string(tgpro), "address": .hex(0x3000), "kind": .string("local")]),
            .object(["name": .string(staticProperty), "address": .hex(0x3008), "kind": .string("local")]),
            .object(["name": .string("_main"), "address": .hex(0x1010), "kind": .string("local")]),
        ])
        for route in Route.allCases {
            let store = makeStoreA()
            let actualFunctions = try await read(route, store, "functions", .object([:]))
            let actualSymbols = try await read(route, store, "symbols", .object([:]))
            try assertJSONEqual(actualFunctions, functions)
            try assertJSONEqual(actualSymbols, symbols)
            for value in (actualFunctions.arrayValue ?? []) + (actualSymbols.arrayValue ?? []) {
                XCTAssertNil(value["demangled"])
            }
        }
    }
}
