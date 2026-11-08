import Foundation
import XCTest
@testable import MacScope

@MainActor
final class StubCallersTests: XCTestCase {
    private enum Route: CaseIterable, Equatable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    private let sibling = ImageSlot(rawValue: 1)

    private func makeStore(_ edit: (inout ImageAnalysis) -> Void = { _ in }) -> WorkspaceStore {
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

    private func refuses(_ route: Route, _ store: WorkspaceStore, _ command: String,
                         _ arguments: ScriptValue, _ expected: ScriptingError) async throws {
        if route == .mcpSync || route == .mcpAsync {
            let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), command, arguments)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            let text: String
            if let refusal = MCPToolRefusal.executionRefusal(expected) { text = refusal.text }
            else { text = "Tool call failed: " + String(try XCTUnwrap(expected.errorDescription).prefix(1_024)) }
            XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string(text))
        } else {
            do {
                _ = try await read(route, store, command, arguments)
                XCTFail("expected refusal")
            } catch { XCTAssertEqual(error as? ScriptingError, expected) }
        }
    }

    private func row(_ from: UInt64, slot: Int, owner: UInt64? = 0x1000, name: String? = "_main") -> ScriptValue {
        .object(["from": .hex(from), "to": .hex(0x2000), "imageSlot": .int(Int64(slot)),
            "fromFunction": owner.map(ScriptValue.hex) ?? .null,
            "fromFunctionName": name.map(ScriptValue.string) ?? .null,
            "toName": .string("_objc_msgSend$tick"), "selector": .string("tick")])
    }

    private func pairs(_ rows: ScriptValue) -> Set<String> {
        Set((rows.arrayValue ?? []).map {
            ($0["from"]?.stringValue ?? "?") + ":" + ($0["to"]?.stringValue ?? "?")
        })
    }

    func testStubAddressReturnsXRefCallSitesOnEveryRoute() async throws {
        let store = makeStore()
        for slot in [0, 1] {
            let args = ScriptValue.object(["address": .hex(0x2000), "imageSlot": .int(Int64(slot))])
            let expected = ScriptValue.array((slot == 0 ? [UInt64(0x1004)] : [0x1000, 0x1004]).map {
                row($0, slot: slot)
            })
            for route in Route.allCases {
                let result = try await read(route, store, "callers", args)
                XCTAssertEqual(result, expected)
            }
        }
    }

    func testStubCallersEqualXRefsCallSitesAndNeverTheNeighbour() async throws {
        let store = makeStore { value in
            value.xrefs.append(XRef(id: UUID(), from: 0x1004, to: 0x2000, kind: XRefKind.call))
            value.xrefs.append(XRef(id: UUID(), from: 0x1008, to: 0x2000, kind: XRefKind.string))
        }
        for slot in [0, 1] {
            for route in Route.allCases {
                let callers = try await read(route, store, "callers",
                    .object(["address": .hex(0x2000), "imageSlot": .int(Int64(slot))]))
                let refs = try await read(route, store, "xrefs",
                    .object(["to": .hex(0x2000), "imageSlot": .int(Int64(slot))]))
                let callRefs = ScriptValue.array((refs.arrayValue ?? []).filter { $0["kind"] == .string(XRefKind.call) })
                XCTAssertEqual(pairs(callers), pairs(callRefs))
                XCTAssertEqual(callers.arrayValue?.count, pairs(callers).count)
                XCTAssertTrue((callers.arrayValue ?? []).allSatisfy { $0["to"] == .hex(0x2000) })
            }
        }
    }

    func testStubNameSelectorReturnsSites() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers",
                .object(["function": .string("_objc_msgSend$tick"), "imageSlot": .int(0)]))
            XCTAssertEqual(result, .array([row(0x1004, slot: 0)]))
        }
    }

    func testStubCallersBudget() async throws {
        let store = makeStore { value in
            value.xrefs = (0..<5_001).map { index -> XRef in
                let source = UInt64(0x10_0000) + UInt64(index)
                return XRef(id: UUID(), from: source, to: 0x2000, kind: XRefKind.call)
            }
        }
        for route in Route.allCases {
            try await refuses(route, store, "callers",
                .object(["address": .hex(0x2000), "imageSlot": .int(0)]),
                .invalidArgument("callers exceeds the snapshot result budget"))
        }
    }

    func testControlZeroSiteStubRefusesUnchanged() async throws {
        let store = makeStore()
        for slot in [0, 1] {
            let expected = ScriptingError.structuredRefusal(MCPToolRefusal(code: .unknownSubject,
                detail: "address 0x2010 is outside every function in image slot \(slot); nearest preceding function helper at 0x1008; section __TEXT,__objc_stubs [0x2000, 0x2040)",
                requestedAddress: 0x2010, imageSlot: slot,
                nearestFunction: MCPRefusalFunction(name: "helper", address: 0x1008),
                section: MCPRefusalSection(name: "__TEXT,__objc_stubs", start: 0x2000, end: 0x2040)))
            for route in Route.allCases {
                try await refuses(route, store, "callers",
                    .object(["address": .hex(0x2010), "imageSlot": .int(Int64(slot))]), expected)
            }
        }
    }

    func testControlResolvedCallersAndCalleesUnchanged() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let callers = try await read(route, store, "callers", .object(["function": .string("helper")]))
            XCTAssertEqual(callers, .array([.object([
                "from": .hex(0x1004), "to": .hex(0x1008), "imageSlot": .int(0),
                "toName": .string("helper"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main"),
            ])]))
            let callees = try await read(route, store, "callees", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(callees, .array([
                .object(["from": .hex(0x1004), "to": .hex(0x1008), "imageSlot": .int(0),
                         "toName": .string("helper"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main")]),
                row(0x1004, slot: 0),
            ]))
            try await refuses(route, store, "callees", .object(["address": .hex(0x2000)]),
                .structuredRefusal(MCPToolRefusal(code: .unknownSubject,
                    detail: "address 0x2000 is outside every function in image slot 0; nearest preceding function helper at 0x1008; section __TEXT,__objc_stubs [0x2000, 0x2040)",
                    requestedAddress: 0x2000, imageSlot: 0,
                    nearestFunction: MCPRefusalFunction(name: "helper", address: 0x1008),
                    section: MCPRefusalSection(name: "__TEXT,__objc_stubs", start: 0x2000, end: 0x2040))))
        }
    }

    func testAmbiguousStubNameRefusal() async throws {
        for count in [2, 17] {
            let store = makeStore { value in
                value.symbols = (0..<count).reversed().map { index -> SymbolSummary in
                    let address = UInt64(0x2000) + UInt64(index * 8)
                    return SymbolSummary(id: UUID(), name: "_objc_msgSend$tick",
                        address: address, kind: "stub", libraryName: nil)
                }
            }
            let expected = ScriptingError.ambiguousFunctionSelector(name: "_objc_msgSend$tick",
                addresses: (0..<min(count, 16)).map { 0x2000 + UInt64($0 * 8) })
            for route in Route.allCases {
                try await refuses(route, store, "callers",
                    .object(["function": .string("_objc_msgSend$tick"), "imageSlot": .int(0)]), expected)
            }
        }
        // Ambiguity is counted before containment, not only among uncovered symbols.
        let mixed = makeStore { value in
            value.symbols.append(SymbolSummary(id: UUID(), name: "_objc_msgSend$tick",
                                               address: 0x1000, kind: "local", libraryName: nil))
        }
        for route in Route.allCases {
            try await refuses(route, mixed, "callers", .object(["function": .string("_objc_msgSend$tick")]),
                .ambiguousFunctionSelector(name: "_objc_msgSend$tick", addresses: [0x1000, 0x2000]))
        }
    }

    func testStubFallbackUsesAuthoredXRefEditsAndKeepsNamePrecedence() async throws {
        let store = makeStore()
        store.snapshot.manualXRefs = [
            ManualXRef(from: 0x1004, to: 0x2000, kind: XRefKind.call, isSuppression: true),
            ManualXRef(from: 0x1008, to: 0x2000, kind: XRefKind.call, isSuppression: false),
        ]
        for route in Route.allCases {
            let result = try await read(route, store, "callers",
                .object(["function": .string("_objc_msgSend$tick"), "address": .hex(0x1008)]))
            XCTAssertEqual(result, .array([row(0x1008, slot: 0, owner: 0x1008, name: "helper")]))
            let refs = try await read(route, store, "xrefs", .object(["to": .hex(0x2000)]))
            XCTAssertEqual(pairs(result), pairs(refs))
        }
    }

    func testContainingFunctionUsesFirstArrayMatchAndHandlesMissingAndMaxAddress() async throws {
        let store = makeStore { value in
            value.functions = [
                FunctionSummary(id: UUID(), name: "first", startAddress: 0x1002, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "earlier-start", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "max", startAddress: UInt64.max, endAddress: UInt64.max, confidence: 1),
            ]
            value.xrefs = [UInt64(0x1004), 0x5000, UInt64.max].map {
                XRef(id: UUID(), from: $0, to: 0x2000, kind: XRefKind.call)
            }
        }
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["address": .hex(0x2000)]))
            XCTAssertEqual(result, .array([
                row(0x1004, slot: 0, owner: 0x1002, name: "first"),
                row(0x5000, slot: 0, owner: nil, name: nil),
                row(UInt64.max, slot: 0, owner: UInt64.max, name: "max"),
            ]))
        }
    }

    func testDuplicateSymbolAddressIsNotAmbiguousAndFunctionMatchesTakePrecedence() async throws {
        let duplicate = makeStore { value in
            value.symbols.append(SymbolSummary(id: UUID(), name: "_objc_msgSend$tick",
                                               address: 0x2000, kind: "stub", libraryName: nil))
        }
        for route in Route.allCases {
            let result = try await read(route, duplicate, "callers",
                .object(["function": .string("_objc_msgSend$tick")]))
            XCTAssertEqual(result, .array([row(0x1004, slot: 0)]))
        }
        let functionMatch = makeStore { value in value.functions[1].name = "_objc_msgSend$tick" }
        for route in Route.allCases {
            let result = try await read(route, functionMatch, "callers",
                .object(["function": .string("_objc_msgSend$tick")]))
            XCTAssertEqual(result, .array([.object([
                "from": .hex(0x1004), "to": .hex(0x1008), "imageSlot": .int(0),
                "toName": .string("_objc_msgSend$tick"), "selector": .string("tick"),
                "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main"),
            ])]))
        }
    }

    func testFallbackCancellationPropagates() throws {
        let snapshot = makeStore().snapshot
        XCTAssertThrowsError(try WorkspaceScriptingAPI.stubCallerRows(
            arguments: .object(["address": .hex(0x2000)]), snapshot: snapshot, view: snapshot,
            filter: nil, scope: .attached, checkpoint: { throw CancellationError() })) {
            XCTAssertTrue($0 is CancellationError)
        }
    }
}
