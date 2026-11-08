import Foundation
import XCTest
@testable import MacScope

/// Graph-row contract for the real ObjC name projection.
@MainActor
final class ObjCGraphRowNamingTests: XCTestCase {
    private enum Route: CaseIterable {
        case inline, asynchronous, attached, mcpSync, mcpAsync, mcpAttached
    }

    private func read(_ route: Route, _ store: WorkspaceStore,
                      _ command: String, _ arguments: ScriptValue) async throws -> ScriptValue {
        let api = WorkspaceScriptingAPI(store: store)
        switch route {
        case .inline:
            return try api.execute(command, arguments: arguments)
        case .asynchronous:
            return try await api.executeAsync(command, arguments: arguments)
        case .attached:
            let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
            executor.setConsent(.allowed)
            return try await executor.execute(command, arguments)
        case .mcpSync, .mcpAsync, .mcpAttached:
            let server: MCPServer
            if case .mcpAttached = route {
                let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
                executor.setConsent(.allowed)
                server = MCPServer(api: api, configuration: .attached, asyncCommandExecutor: { command, arguments in
                    try await executor.execute(command, arguments)
                }, allowedCommands: MCPAttachExecutor.attachCommands)
            } else {
                server = MCPServer(api: api)
            }
            let request = try ScriptValue.object([
                "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                "params": .object(["name": .string(command), "arguments": arguments]),
            ]).jsonData()
            let data: Data?
            if case .mcpSync = route { data = server.handleMessage(request) }
            else { data = await server.handleMessageAsync(request) }
            let reply = try ScriptValue.decode(try XCTUnwrap(data))
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            return try ScriptValue.decode(Data(text.utf8))
        }
    }

    private func makeStore(methodMatches: Bool = true) -> WorkspaceStore {
        func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
            FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
        }
        let method = ObjCMethod(selector: "applicationDidFinishLaunching:", typeEncoding: nil,
            isClassMethod: false, implementation: methodMatches ? 0x2000 : 0x8000)
        let owner = ObjCClass(name: "AppDelegate", superclassName: nil, adoptedProtocols: [],
            classMethods: [], instanceMethods: [method], ivars: [], properties: [])
        let projection = AnalysisEngine.projectObjCMethodNames(functions: [
            function("_caller", 0x1000, 0x1010),
            function("sub_0x0000000000002000", 0x2000, 0x2010),
            function("_sink", 0x3000, 0x3010),
            function("_unrelated", 0x4000, 0x4010),
        ], classes: [owner], categories: [], namedAddresses: [], existingNames: ["_puts"])
        XCTAssertEqual(projection.functions.first { $0.startAddress == 0x2000 }?.name,
            methodMatches ? "-[AppDelegate applicationDidFinishLaunching:]" : "sub_0x0000000000002000")
        XCTAssertEqual(projection.symbols.count, methodMatches ? 1 : 0)
        var analysis = ImageAnalysis()
        analysis.functions = projection.functions
        analysis.symbols = projection.symbols + [
            SymbolSummary(id: UUID(), name: "_puts", address: 0x5000, kind: "stub", libraryName: nil),
        ]
        analysis.xrefs = [
            XRef(id: UUID(), from: 0x1004, to: 0x2000, kind: XRefKind.call),
            XRef(id: UUID(), from: 0x2004, to: 0x3000, kind: XRefKind.call),
            XRef(id: UUID(), from: 0x4004, to: 0x5000, kind: XRefKind.call),
        ]
        let image = BinaryImage(id: UUID(), name: "objc-graph-rows", path: "/fixture",
            kind: "Mach-O executable", architecture: "arm64")
        return WorkspaceStore(workspaceName: "objc-graph-rows",
            snapshot: WorkspaceSnapshot(binaries: [image], analysisBySlot: [image.slot: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    // Expected names are caller-supplied literals, never derived from the projection or a row.
    private func row(_ from: UInt64, _ to: UInt64, owner: UInt64,
                     sourceName: String, targetName: String, xref: Bool = false) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "from": .hex(from), "to": .hex(to), "imageSlot": .int(0),
            "fromFunction": .hex(owner), "fromFunctionName": .string(sourceName),
            "toName": .string(targetName),
        ]
        if xref { fields["kind"] = .string("call") }
        return .object(fields)
    }

    private func assertCoreRows(_ store: WorkspaceStore, expectedIMPName: String) async throws {
        let incoming = row(0x1004, 0x2000, owner: 0x1000,
            sourceName: "_caller", targetName: expectedIMPName)
        let outgoing = row(0x2004, 0x3000, owner: 0x2000,
            sourceName: expectedIMPName, targetName: "_sink")
        let incomingXRef = row(0x1004, 0x2000, owner: 0x1000,
            sourceName: "_caller", targetName: expectedIMPName, xref: true)
        let outgoingXRef = row(0x2004, 0x3000, owner: 0x2000,
            sourceName: expectedIMPName, targetName: "_sink", xref: true)
        let requests: [(String, ScriptValue, ScriptValue)] = [
            ("callers", .object(["address": .hex(0x2000)]), incoming),
            ("callers", .object(["function": .string(expectedIMPName)]), incoming),
            ("callers", .object(["address": .hex(0x3000)]), outgoing),
            ("callers", .object(["function": .string("_sink")]), outgoing),
            ("callees", .object(["address": .hex(0x1000)]), incoming),
            ("callees", .object(["function": .string("_caller")]), incoming),
            ("callees", .object(["address": .hex(0x2000)]), outgoing),
            ("callees", .object(["function": .string(expectedIMPName)]), outgoing),
            ("xrefs", .object(["to": .hex(0x2000)]), incomingXRef),
            ("xrefs", .object(["from": .hex(0x1004)]), incomingXRef),
            ("xrefs", .object(["to": .hex(0x3000)]), outgoingXRef),
            ("xrefs", .object(["from": .hex(0x2004)]), outgoingXRef),
        ]
        for route in Route.allCases {
            for (command, arguments, expected) in requests {
                let result = try await read(route, store, command, arguments)
                XCTAssertEqual(result, .array([expected]), "\(route) \(command) \(arguments)")
            }
        }
    }

    func testProjectedObjCNameInBothGraphDirections() async throws {
        let store = makeStore()
        try await assertCoreRows(store, expectedIMPName: "-[AppDelegate applicationDidFinishLaunching:]")
    }

    func testUserRenameWinsInBothGraphDirections() async throws {
        let store = makeStore()
        // Warm the graph-name memo before the authored override, then read the same store.
        try await assertCoreRows(store, expectedIMPName: "-[AppDelegate applicationDidFinishLaunching:]")
        _ = try WorkspaceScriptingAPI(store: store).execute("rename",
            arguments: .object(["address": .hex(0x2000), "name": .string("userName")]))
        try await assertCoreRows(store, expectedIMPName: "userName")
        for route in Route.allCases {
            let symbols = try await read(route, store, "symbols", .object(["kind": .string("objc-method")]))
            XCTAssertEqual(symbols, .array([.object([
                "address": .hex(0x2000), "name": .string("-[AppDelegate applicationDidFinishLaunching:]"),
                "kind": .string("objc-method"),
            ])]))
            // The original raw ObjC name remains a selector after a user rename.
            let callers = try await read(route, store, "callers",
                .object(["function": .string("-[AppDelegate applicationDidFinishLaunching:]")]))
            XCTAssertEqual(callers, .array([row(0x1004, 0x2000, owner: 0x1000,
                sourceName: "_caller", targetName: "userName")]))
            let callees = try await read(route, store, "callees",
                .object(["function": .string("-[AppDelegate applicationDidFinishLaunching:]")]))
            XCTAssertEqual(callees, .array([row(0x2004, 0x3000, owner: 0x2000,
                sourceName: "userName", targetName: "_sink")]))
        }
    }

    func testNoObjCMatchKeepsExactFallbackInBothGraphDirections() async throws {
        let store = makeStore(methodMatches: false)
        try await assertCoreRows(store, expectedIMPName: "sub_0x0000000000002000")
    }

    func testUnrelatedNonObjCRowsRemainExact() async throws {
        let store = makeStore()
        let expected = row(0x4004, 0x5000, owner: 0x4000,
            sourceName: "_unrelated", targetName: "_puts")
        let expectedXRef = row(0x4004, 0x5000, owner: 0x4000,
            sourceName: "_unrelated", targetName: "_puts", xref: true)
        let requests: [(String, ScriptValue, ScriptValue)] = [
            ("callers", .object(["address": .hex(0x5000)]), expected),
            ("callers", .object(["function": .string("_puts")]), expected),
            ("callees", .object(["address": .hex(0x4000)]), expected),
            ("callees", .object(["function": .string("_unrelated")]), expected),
            ("xrefs", .object(["to": .hex(0x5000)]), expectedXRef),
            ("xrefs", .object(["from": .hex(0x4004)]), expectedXRef),
        ]
        for route in Route.allCases {
            for (command, arguments, expectedRow) in requests {
                let result = try await read(route, store, command, arguments)
                XCTAssertEqual(result, .array([expectedRow]), "\(route) \(command) \(arguments)")
            }
        }
    }
}
