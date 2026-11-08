import Foundation
import XCTest
@testable import MacScope

@MainActor
final class SelectorQueriesTests: XCTestCase {
    private enum Route: CaseIterable, Equatable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    private let sibling = ImageSlot(rawValue: 1)

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

    private func makeStore(_ change: (inout ImageAnalysis, ImageSlot) -> Void = { _, _ in }) -> WorkspaceStore {
        func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
            FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
        }
        func method(_ selector: String, _ address: UInt64?, classMethod: Bool = false) -> ObjCMethod {
            ObjCMethod(selector: selector, typeEncoding: nil, isClassMethod: classMethod, implementation: address)
        }
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "selectors-\(slot.rawValue)", path: "/fixture",
                kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        func analysis(_ slot: ImageSlot) -> ImageAnalysis {
            var value = ImageAnalysis()
            value.functions = [function("_main", 0x1000, 0x1008), function("helper", 0x1008, 0x1010),
                function("-[Doc save:]", 0x1010, 0x1020), function("+[Doc make]", 0x1020, 0x1028),
                function("-[Other save:]", 0x1030, 0x1038), function("-[Base(Extra) save:]", 0x1040, 0x1048)]
            value.sections = [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                    size: 0x400, fileOffset: 0, isExecutable: true),
                SectionSummary(id: UUID(), name: "__TEXT,__objc_stubs", address: 0x2000,
                    size: 0x40, fileOffset: 0, isExecutable: true),
                SectionSummary(id: UUID(), name: "__DATA,__objc_selrefs", address: 0x3000,
                    size: 0x20, fileOffset: 0, isExecutable: false)]
            value.symbols = [SymbolSummary(id: UUID(), name: "_objc_msgSend$save:", address: 0x2000, kind: "stub", libraryName: nil),
                SymbolSummary(id: UUID(), name: "_objc_msgSend$make", address: 0x2020, kind: "stub", libraryName: nil)]
            value.objcSelectors = [0x3000: "save:", 0x3008: "make"]
            value.xrefs = [edge(0x1004, 0x2000, "call"), edge(0x100c, 0x2000, "call"),
                edge(0x2004, 0x3000, "selref"), edge(0x2024, 0x3008, "selref"),
                edge(0x1024, 0x3000, "selref"), edge(0x1018, 0x2020, "call"), edge(0x1300, 0x3000, "selref")]
            value.objcClasses = [ObjCClass(name: "Doc", superclassName: nil, adoptedProtocols: [],
                classMethods: [method("make", 0x1020, classMethod: true)], instanceMethods: [method("save:", 0x1010)],
                ivars: [], properties: []), ObjCClass(name: "Other", superclassName: nil, adoptedProtocols: [],
                classMethods: [method("make", nil, classMethod: true)], instanceMethods: [method("save:", 0x1030)],
                ivars: [], properties: [])]
            value.objcCategories = [ObjCCategory(name: "Extra", className: "Base", classMethods: [],
                instanceMethods: [method("save:", 0x1040)], adoptedProtocols: [], properties: [])]
            if slot == sibling {
                value.xrefs.append(edge(0x1000, 0x2000, "call"))
                value.objcSelectors[0x3010] = "only:"
                value.xrefs.append(edge(0x1028, 0x3010, "selref"))
                value.symbols.append(SymbolSummary(id: UUID(), name: "_objc_msgSend$side:", address: 0x2030, kind: "stub", libraryName: nil))
                value.xrefs.append(edge(0x1004, 0x2030, "call"))
                value.objcCategories.append(ObjCCategory(name: "Side", className: "Doc", classMethods: [],
                    instanceMethods: [method("only:", 0x1000)], adoptedProtocols: [], properties: []))
            }
            change(&value, slot)
            return value
        }
        return WorkspaceStore(workspaceName: "selectors", snapshot: WorkspaceSnapshot(
            binaries: [image(.primary), image(sibling)], analysisBySlot: [.primary: analysis(.primary), sibling: analysis(sibling)]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func edge(_ from: UInt64, _ to: UInt64, _ kind: String) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }

    private func row(_ from: UInt64, _ to: UInt64, owner: UInt64?, name: String?, target: String?,
                     slot: Int = 0, selector: String? = "save:", via: String? = "stub") -> ScriptValue {
        var fields: [String: ScriptValue] = ["from": .hex(from), "to": .hex(to), "imageSlot": .int(Int64(slot)),
            "toName": target.map(ScriptValue.string) ?? .null, "fromFunction": owner.map(ScriptValue.hex) ?? .null,
            "fromFunctionName": name.map(ScriptValue.string) ?? .null]
        if let selector { fields["selector"] = .string(selector) }
        if let via { fields["via"] = .string(via) }
        return .object(fields)
    }

    private func saveRows(slot: Int = 0) -> [ScriptValue] {
        var rows = [row(0x1004, 0x2000, owner: 0x1000, name: "_main", target: "_objc_msgSend$save:", slot: slot),
            row(0x100c, 0x2000, owner: 0x1008, name: "helper", target: "_objc_msgSend$save:", slot: slot),
            row(0x1024, 0x3000, owner: 0x1020, name: "+[Doc make]", target: nil, slot: slot, via: "selref"),
            row(0x1300, 0x3000, owner: nil, name: nil, target: nil, slot: slot, via: "selref")]
        if slot == 1 { rows.insert(row(0x1000, 0x2000, owner: 0x1000, name: "_main", target: "_objc_msgSend$save:", slot: 1), at: 0) }
        return rows
    }

    private func implementation(_ owner: String, category: String? = nil, classMethod: Bool = false,
                                selector: String = "save:", address: UInt64?, name: String?, slot: Int = 0) -> ScriptValue {
        .object(["class": .string(owner), "category": category.map(ScriptValue.string) ?? .null,
            "isClassMethod": .bool(classMethod), "selector": .string(selector),
            "address": address.map(ScriptValue.hex) ?? .null, "name": name.map(ScriptValue.string) ?? .null,
            "imageSlot": .int(Int64(slot))])
    }

    private func unknown(_ selector: String, slot: Int = 0) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .unknownSubject,
            detail: "No Objective-C selector named '\(selector)' in image slot \(slot): no _objc_msgSend$ stub and no selector reference.",
            field: "selector"))
    }

    private func invalid(_ route: Route, _ store: WorkspaceStore, command: String = "callers",
                         arguments: ScriptValue, direct: ScriptingError, diagnosed: ToolArgumentError) async throws {
        if route == .mcpSync || route == .mcpAsync {
            let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), command, arguments)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string(diagnosed.refusal.text))
        } else if route == .attached {
            do { _ = try await read(route, store, command, arguments); XCTFail("expected attached validation refusal") }
            catch { XCTAssertTrue(error is HeadlessAutomationAuthorityError)
                if case HeadlessAutomationAuthorityError.invalidArguments = error {} else { XCTFail("wrong attached error: \(error)") } }
        } else {
            do { _ = try await read(route, store, command, arguments); XCTFail("expected scripting refusal") }
            catch { XCTAssertEqual(error as? ScriptingError, direct) }
        }
    }

    func testF1SelectorUnionHasExactSortedRows() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["selector": .string("save:")]))
            XCTAssertEqual(result, .array(saveRows()))
        }
    }

    func testF2SymbolOnlyMakeStubAndKnownEmptySelector() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["selector": .string("make")]))
            XCTAssertEqual(result, .array([row(0x1018, 0x2020, owner: 0x1010, name: "-[Doc save:]",
                target: "_objc_msgSend$make", selector: "make")]))
        }
        let empty = makeStore { value, _ in value.xrefs = [] }
        let result = try await read(.inline, empty, "callers", .object(["selector": .string("make")]))
        XCTAssertEqual(result, .array([]))
    }

    func testF3UnknownSelectorRefusesOnEveryRoute() async throws {
        let store = makeStore()
        for route in Route.allCases {
            for name in ["nope:", " save:", "Save:"] {
                try await refuses(route, store, "callers", .object(["selector": .string(name)]), unknown(name))
            }
        }
    }

    func testF4SelectorConflictsAndNullFunction() async throws {
        let store = makeStore()
        for route in Route.allCases {
            for (key, value) in [("function", ScriptValue.string("_main")), ("address", .hex(0x2000))] {
                try await invalid(route, store, arguments: .object(["selector": .string("save:"), key: value]),
                    direct: .invalidArgument("selector cannot be combined with function or address"),
                    diagnosed: ToolArgumentError(field: "selector", detail: "Field 'selector' cannot be combined with 'function' or 'address'."))
            }
            let result = try await read(route, store, "callers", .object(["selector": .string("save:"), "function": .null]))
            XCTAssertEqual(result, .array(saveRows()))
            let legacy = try await read(route, store, "callers", .object(["selector": .null, "address": .hex(0x2000)]))
            XCTAssertEqual(legacy, .array([
                row(0x1004, 0x2000, owner: 0x1000, name: "_main", target: "_objc_msgSend$save:", via: nil),
                row(0x100c, 0x2000, owner: 0x1008, name: "helper", target: "_objc_msgSend$save:", via: nil)]))
        }
    }

    func testF5EmptyWhitespaceAndUTF8LengthRefuse() async throws {
        let store = makeStore()
        let values: [ScriptValue] = [.string(""), .string("  "), .string(String(repeating: "s", count: 1_025)),
            .string(String(repeating: "é", count: 513)), .int(1)]
        for route in Route.allCases {
            for value in values {
                let diagnosed: ToolArgumentError
                if let text = value.stringValue {
                    if text.utf8.count > 1_024 {
                        diagnosed = ToolArgumentError(field: "selector", code: .outOfBounds,
                            detail: "Field 'selector' must contain at most 1024 UTF-8 bytes.", maximum: 1_024)
                    } else {
                        diagnosed = ToolArgumentError(field: "selector", detail: "Field 'selector' must not be empty.", expected: "string")
                    }
                } else { diagnosed = ToolArgumentError(field: "selector", detail: "Field 'selector' must be a string.", expected: "string") }
                try await invalid(route, store, arguments: .object(["selector": value]),
                    direct: .invalidArgument("selector must be a non-empty string of at most 1024 UTF-8 bytes"), diagnosed: diagnosed)
            }
        }
    }

    func testF6SiblingSelrefOnlyAndPrimaryIsolation() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["selector": .string("save:"), "imageSlot": .int(1)]))
            XCTAssertEqual(result, .array(saveRows(slot: 1)))
            let primary = try await read(route, store, "callers", .object(["selector": .string("save:")]))
            XCTAssertEqual(primary, .array(saveRows()))
            let only = try await read(route, store, "callers", .object(["selector": .string("only:"), "imageSlot": .int(1)]))
            XCTAssertEqual(only, .array([row(0x1028, 0x3010, owner: nil, name: nil, target: nil,
                slot: 1, selector: "only:", via: "selref")]))
            try await refuses(route, store, "callers", .object(["selector": .string("only:")]), unknown("only:"))
            let side = try await read(route, store, "callers", .object(["selector": .string("side:"), "imageSlot": .int(1)]))
            XCTAssertEqual(side, .array([row(0x1004, 0x2030, owner: 0x1000, name: "_main", target: "_objc_msgSend$side:",
                slot: 1, selector: "side:")]))
            try await refuses(route, store, "callers", .object(["selector": .string("side:")]), unknown("side:"))
        }
    }

    func testF7ClassCategoryClassMethodAndUnknownImplementations() async throws {
        let store = makeStore()
        let save = [implementation("Base", category: "Extra", address: 0x1040, name: "-[Base(Extra) save:]"),
            implementation("Doc", address: 0x1010, name: "-[Doc save:]"),
            implementation("Other", address: 0x1030, name: "-[Other save:]")]
        let make = [implementation("Doc", classMethod: true, selector: "make", address: 0x1020, name: "+[Doc make]"),
            implementation("Other", classMethod: true, selector: "make", address: nil, name: nil)]
        for route in Route.allCases {
            for (selector, expected) in [("save:", save), ("make", make), ("nope:", [])] {
                let result = try await read(route, store, "implementations", .object(["selector": .string(selector)]))
                XCTAssertEqual(result, .array(expected))
            }
            let sideImplementations = try await read(route, store, "implementations",
                .object(["selector": .string("only:"), "imageSlot": .int(1)]))
            XCTAssertEqual(sideImplementations, .array([implementation("Doc", category: "Side", selector: "only:",
                address: 0x1000, name: "_main", slot: 1)]))
            let primaryImplementations = try await read(route, store, "implementations", .object(["selector": .string("only:")]))
            XCTAssertEqual(primaryImplementations, .array([]))
            for missing in [ScriptValue.object([:]), .object(["selector": .null])] {
                try await invalid(route, store, command: "implementations", arguments: missing,
                    direct: .missingArgument("selector"),
                    diagnosed: ToolArgumentError(field: "selector", detail: "Field 'selector' is required.", expected: "string"))
            }
        }
    }

    func testF8AsyncDispatchNoteNamesSymbolStubAndTrySelector() async throws {
        let store = makeStore()
        let reply = try await envelope(.mcpAsync, WorkspaceScriptingAPI(store: store), "callers",
            .object(["function": .string("-[Doc save:]")]))
        XCTAssertEqual(reply["result"]?["isError"], .bool(false))
        XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string("[]"))
        XCTAssertEqual(reply["result"]?["note"], .object([
            "code": .string("dynamicDispatch"), "selector": .string("save:"), "stubAddress": .hex(0x2000),
            "text": .string("No direct callers of -[Doc save:] were found, but it is an Objective-C method and may be reached by dynamic dispatch through objc_msgSend (selector save:). Try callers with selector save: to list its send sites."),
            "try": .object(["tool": .string("callers"), "arguments": .object(["selector": .string("save:")])])]))
        let lowest = makeStore { value, _ in
            value.functions.append(FunctionSummary(id: UUID(), name: "_objc_msgSend$save:",
                startAddress: 0x1800, endAddress: 0x1810, confidence: 1))
            value.symbols.append(SymbolSummary(id: UUID(), name: "_objc_msgSend$save:", address: 0x1700, kind: "stub", libraryName: nil))
            value.symbols.append(SymbolSummary(id: UUID(), name: "_objc_msgSend$save:", address: nil, kind: "stub", libraryName: nil))
        }
        let lowerReply = try await envelope(.mcpAsync, WorkspaceScriptingAPI(store: lowest), "callers",
            .object(["function": .string("-[Doc save:]")]))
        XCTAssertEqual(lowerReply["result"]?["note"]?["stubAddress"], .hex(0x1700))
    }

    private func checkBudget(_ body: () throws -> ScriptValue, unit: MCPRefusalBudget.Unit,
                             limit: Int64) {
        XCTAssertThrowsError(try body()) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("not a typed refusal") }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget, .init(unit: unit, limit: limit))
            XCTAssertEqual(refusal.narrowing, ["imageSlot"])
        }
    }

    func testF9BothQueriesShareWorkAndRefuseRows() throws {
        let snapshot = makeStore().snapshot
        let args: ScriptValue = .object(["selector": .string("save:")])
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            selectionWorkLimit: 3, checkpoint: {}) }, unit: .workSteps, limit: 3)
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            resultLimit: 2, checkpoint: {}) }, unit: .rows, limit: 2)
        checkBudget({ try WorkspaceScriptingAPI.selectorImplementationRows(args, snapshot: snapshot,
            selectionWorkLimit: 3, checkpoint: {}) }, unit: .workSteps, limit: 3)
        checkBudget({ try WorkspaceScriptingAPI.selectorImplementationRows(args, snapshot: snapshot,
            resultLimit: 2, checkpoint: {}) }, unit: .rows, limit: 2)
        // 2 symbols + 6 functions + 2 slots + (2 stub rows + 1) + (3 selref rows + 1) = 17.
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            selectionWorkLimit: 16, checkpoint: {}) }, unit: .workSteps, limit: 16)
        let exact = try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            selectionWorkLimit: 17, checkpoint: {})
        XCTAssertEqual(exact, .array(saveRows()))
        // Each endpoint fits 3 rows, but their union contains 4 admitted sites.
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            resultLimit: 3, checkpoint: {}) }, unit: .rows, limit: 3)
    }

    func testF10SchemasHaveExactSelectorContracts() throws {
        let commands = HeadlessAutomationAuthority.availableCommands
        let callers = HeadlessAutomationAuthority.inputSchema(for: try XCTUnwrap(commands.first { $0.name == "callers" }))
        let implementations = HeadlessAutomationAuthority.inputSchema(for: try XCTUnwrap(commands.first { $0.name == "implementations" }))
        let expected: ScriptValue = .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024),
            "description": .string("Objective-C selector, exactly as written, e.g. \"setDouble:forKey:\"; callers: use instead of function or address.")])
        XCTAssertEqual(callers["properties"]?["selector"], expected)
        XCTAssertEqual(implementations["properties"]?["selector"], expected)
        XCTAssertEqual(callers["anyOf"], .array([.object(["required": .array([.string("function")])]),
            .object(["required": .array([.string("address")])]), .object(["required": .array([.string("selector")])]),
            .object(["required": .array([.string("selectors")])])]))
        XCTAssertEqual(callers["properties"]?["selectors"], .object(["type": .string("array"), "minItems": .int(1),
            "maxItems": .int(8), "uniqueItems": .bool(true),
            "items": .object(["type": .string("string"), "minLength": .int(1), "maxLength": .int(1_024)]),
            "description": .string("Several Objective-C selectors in one call; returns each selector's send sites, as `selector` would, in one reply. Use instead of repeated selector calls.")]))
        XCTAssertEqual(implementations["required"], .array([.string("selector")]))
        XCTAssertEqual(implementations["additionalProperties"], .bool(false))
        guard case .object(let properties) = try XCTUnwrap(implementations["properties"]) else { return XCTFail("properties") }
        XCTAssertEqual(Set(properties.keys), ["selector", "imageSlot"])
        let decompile = HeadlessAutomationAuthority.inputSchema(for: try XCTUnwrap(commands.first { $0.name == "decompile" }))
        XCTAssertEqual(decompile["anyOf"], .array([.object(["required": .array([.string("function")])]),
            .object(["required": .array([.string("address")])])]))
    }

    // MARK: lane-m3reach: callers {selectors:[...]}

    private func selectorsArgs(_ names: [String], _ extra: [String: ScriptValue] = [:]) -> ScriptValue {
        var fields = extra
        fields["selectors"] = .array(names.map(ScriptValue.string))
        return .object(fields)
    }

    private func sorted(_ rows: [ScriptValue]) -> Bool {
        let keys = rows.map { ($0["from"]?.addressValue ?? 0, $0["to"]?.addressValue ?? 0, $0["selector"]?.stringValue ?? "") }
        return zip(keys, keys.dropFirst()).allSatisfy { $0 < $1 }
    }

    func testS1S2SelectorsReturnEachEntrysRowsSorted() async throws {
        let store = makeStore { value, _ in value.controlFlowEdges = [self.flow(0x1034, 0x2000)] }
        let makeRow = row(0x1018, 0x2020, owner: 0x1010, name: "-[Doc save:]",
            target: "_objc_msgSend$make", selector: "make")
        for route in Route.allCases {
            let reply = try await read(route, store, "callers", selectorsArgs(["save:", "make"]))
            let rows = try XCTUnwrap(reply.arrayValue)
            for name in ["save:", "make"] {
                let single = try await read(route, store, "callers", .object(["selector": .string(name)]))
                XCTAssertEqual(rows.filter { $0["selector"] == .string(name) }, single.arrayValue)
            }
            XCTAssertEqual(rows.filter { $0["selector"] == .string("save:") }, saveRowsWithBranch())
            XCTAssertEqual(rows.filter { $0["selector"] == .string("make") }, [makeRow])
            XCTAssertEqual(rows.count, saveRowsWithBranch().count + 1)
            XCTAssertTrue(sorted(rows), "rows must be sorted by from, to, selector")
        }
    }

    func testS3SelectorsFirstUnknownRefusesOnEveryRoute() async throws {
        let store = makeStore()
        for route in Route.allCases {
            try await refuses(route, store, "callers", selectorsArgs(["save:", "nope:"]), unknown("nope:"))
            try await refuses(route, store, "callers", selectorsArgs(["nope:", "save:"]), unknown("nope:"))
            try await refuses(route, store, "callers", selectorsArgs(["nope2:", "nope:"]), unknown("nope2:"))
        }
    }

    func testS4SelectorsKnownSelectorWithNoSitesAddsNoRows() async throws {
        let store = makeStore { value, _ in value.objcSelectors[0x3018] = "idle:" }
        for route in Route.allCases {
            let reply = try await read(route, store, "callers", selectorsArgs(["idle:", "save:"]))
            XCTAssertEqual(reply, .array(saveRows()))
        }
    }

    func testS5SelectorsInvalidInputsRefuseOnEveryRoute() async throws {
        let store = makeStore()
        let shape = ScriptingError.invalidArgument("selectors must be an array of 1 to 8 distinct non-empty strings of at most 1024 UTF-8 bytes")
        let conflict = ScriptingError.invalidArgument("selectors cannot be combined with selector, function or address")
        func array(_ items: [ScriptValue]) -> ScriptValue { .object(["selectors": .array(items)]) }
        func err(_ detail: String, code: MCPRefusalCode = .malformedInput, expected: String? = nil,
                 minimum: Int64? = nil, maximum: Int64? = nil) -> ToolArgumentError {
            ToolArgumentError(field: "selectors", code: code, detail: detail, expected: expected, minimum: minimum, maximum: maximum)
        }
        let nine = (0..<9).map { ScriptValue.string("s\($0):") }
        let combined: (String, ScriptValue) -> ScriptValue = { key, value in
            .object(["selectors": .array([.string("save:")]), key: value])
        }
        let conflictDiagnosed = err("Field 'selectors' cannot be combined with 'selector', 'function' or 'address'.")
        let cases: [(ScriptValue, ScriptingError, ToolArgumentError)] = [
            (array([]), shape, err("Field 'selectors' must contain 1 to 8 entries.", code: .outOfBounds, minimum: 1, maximum: 8)),
            (array(nine), shape, err("Field 'selectors' must contain 1 to 8 entries.", code: .outOfBounds, minimum: 1, maximum: 8)),
            (.object(["selectors": .string("save:")]), shape, err("Field 'selectors' must be an array of strings.", expected: "array")),
            (array([.int(1)]), shape, err("Field 'selectors' entries must be strings.", expected: "string")),
            (array([.string("")]), shape, err("Field 'selectors' entries must not be empty.", expected: "string")),
            (array([.string("  ")]), shape, err("Field 'selectors' entries must not be empty.", expected: "string")),
            (array([.string(String(repeating: "s", count: 1_025))]), shape,
                err("Field 'selectors' entries must contain at most 1024 UTF-8 bytes.", code: .outOfBounds, maximum: 1_024)),
            (array([.string("save:"), .string("save:")]), shape, err("Field 'selectors' entries must be distinct.")),
            (combined("selector", .string("save:")), conflict, conflictDiagnosed),
            (combined("function", .string("_main")), conflict, conflictDiagnosed),
            (combined("address", .hex(0x2000)), conflict, conflictDiagnosed),
        ]
        for route in Route.allCases {
            for (arguments, direct, diagnosed) in cases {
                try await invalid(route, store, arguments: arguments, direct: direct, diagnosed: diagnosed)
            }
        }
    }

    func testS6SelectorsShareWorkAndRowBudgets() throws {
        let snapshot = makeStore().snapshot
        func args(_ names: [String]) -> ScriptValue { selectorsArgs(names) }
        for name in ["save:", "make"] {
            XCTAssertNoThrow(try WorkspaceScriptingAPI.selectorSendSiteRows(args([name]), snapshot: snapshot,
                resultLimit: 4, checkpoint: {}))
        }
        XCTAssertNoThrow(try WorkspaceScriptingAPI.selectorSendSiteRows(args(["save:"]), snapshot: snapshot,
            selectionWorkLimit: 17, checkpoint: {}))
        XCTAssertNoThrow(try WorkspaceScriptingAPI.selectorSendSiteRows(args(["make"]), snapshot: snapshot,
            selectionWorkLimit: 17, checkpoint: {}))
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args(["save:", "make"]), snapshot: snapshot,
            resultLimit: 4, checkpoint: {}) }, unit: .rows, limit: 4)
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args(["save:", "make"]), snapshot: snapshot,
            selectionWorkLimit: 17, checkpoint: {}) }, unit: .workSteps, limit: 17)
    }

    func testS7SelectorsHonourImageSlot() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let reply = try await read(route, store, "callers", selectorsArgs(["save:", "make"], ["imageSlot": .int(1)]))
            let rows = try XCTUnwrap(reply.arrayValue)
            for name in ["save:", "make"] {
                let single = try await read(route, store, "callers", .object(["selector": .string(name), "imageSlot": .int(1)]))
                XCTAssertEqual(rows.filter { $0["selector"] == .string(name) }, single.arrayValue)
            }
            XCTAssertFalse(rows.isEmpty)
            XCTAssertTrue(rows.allSatisfy { $0["imageSlot"] == .int(1) })
        }
    }

    func testF11CatalogsAndAppleScriptBoundary() {
        XCTAssertTrue(WorkspaceScriptingAPI.snapshotListCommands.contains("implementations"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("implementations"))
        XCTAssertTrue(HeadlessAutomationAuthority.availableCommands.contains { $0.name == "implementations" })
        XCTAssertTrue(MCPAttachExecutor.attachCommands.isSubset(of: Set(HeadlessAutomationAuthority.availableCommands.map(\.name))))
        XCTAssertFalse(AppleScriptCommandTranslator.allowlistedCommandIDs.contains("implementations"))
        XCTAssertTrue(AppleScriptCommandTranslator.allowlistedCommandIDs.contains("callers"))
    }

    func testC1SynchronousAndAttachedEmptyHaveNoNote() async throws {
        let store = makeStore()
        let args: ScriptValue = .object(["function": .string("-[Doc save:]")])
        let reply = try await envelope(.mcpSync, WorkspaceScriptingAPI(store: store), "callers", args)
        XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string("[]"))
        XCTAssertNil(reply["result"]?["note"])
        for route in [Route.inline, .asynchronous, .attached] {
            let result = try await read(route, store, "callers", args)
            XCTAssertEqual(result, .array([]))
        }
    }

    func testC2StubAddressKeepsLegacyRows() async throws {
        let store = makeStore()
        let expected = [row(0x1004, 0x2000, owner: 0x1000, name: "_main", target: "_objc_msgSend$save:", via: nil),
            row(0x100c, 0x2000, owner: 0x1008, name: "helper", target: "_objc_msgSend$save:", via: nil)]
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["address": .hex(0x2000)]))
            XCTAssertEqual(result, .array(expected))
        }
    }

    func testC3CalleesAreNotSelectorQueries() async throws {
        let store = makeStore()
        let expected = [row(0x1004, 0x2000, owner: 0x1000, name: "_main", target: "_objc_msgSend$save:", via: nil)]
        for route in Route.allCases {
            let result = try await read(route, store, "callees", .object(["function": .string("_main")]))
            XCTAssertEqual(result, .array(expected))
            let arguments: ScriptValue = .object(["selector": .string("save:")])
            // 326d0207d (S1: add bounded graph edge continuation) adds paging fields, not selectors.
            if route == .mcpSync || route == .mcpAsync {
                let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), "callees", arguments)
                let refusal = assertMCPToolArgumentError(reply, field: "selector", code: "malformedInput")
                XCTAssertEqual(refusal["detail"], .string("Field 'selector' is not an allowed argument."))
                let allowed = try XCTUnwrap(refusal["allowed"]?.arrayValue)
                XCTAssertFalse(allowed.contains(.string("selector")))
            } else {
                try await invalid(route, store, command: "callees", arguments: arguments,
                    direct: .missingArgument("function or address"),
                    diagnosed: ToolArgumentError(field: "selector", detail: "Field 'selector' is not an allowed argument."))
            }
        }
    }

    func testF12EffectiveEditsDedupAndStubFirstAcrossKinds() async throws {
        let store = makeStore { value, _ in value.xrefs.append(edge(0x1004, 0x2000, "call")) }
        let api = WorkspaceScriptingAPI(store: store)
        _ = try api.execute("suppress-xref", arguments: .object(["from": .hex(0x1004), "to": .hex(0x2000), "kind": .string("call")]))
        _ = try api.execute("add-xref", arguments: .object(["from": .hex(0x1000), "to": .hex(0x2000), "kind": .string("call")]))
        var expected = saveRows()
        expected.removeFirst()
        expected.insert(row(0x1000, 0x2000, owner: 0x1000, name: "_main", target: "_objc_msgSend$save:"), at: 0)
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["selector": .string("save:")]))
            XCTAssertEqual(result, .array(expected))
        }
        let crossing = makeStore { value, _ in
            value.symbols.append(SymbolSummary(id: UUID(), name: "_objc_msgSend$save:", address: 0x3000, kind: "stub", libraryName: nil))
            value.xrefs.append(edge(0x1024, 0x3000, "call"))
            value.xrefs.append(edge(0x1004, 0x2000, "call"))
        }
        expected = saveRows()
        expected[2] = row(0x1024, 0x3000, owner: 0x1020, name: "+[Doc make]", target: "_objc_msgSend$save:")
        expected[3] = row(0x1300, 0x3000, owner: nil, name: nil, target: "_objc_msgSend$save:", via: "selref")
        for route in Route.allCases {
            let result = try await read(route, crossing, "callers", .object(["selector": .string("save:")]))
            XCTAssertEqual(result, .array(expected))
        }
    }

    func testF13FunctionStubsAndNoSectionSelrefAndRawNames() async throws {
        let store = makeStore { value, _ in
            value.symbols = []
            value.functions.append(FunctionSummary(id: UUID(), name: "_objc_msgSend$save:", startAddress: 0x2000, endAddress: 0x2010, confidence: 1))
            value.functions.append(FunctionSummary(id: UUID(), name: "_objc_msgSend$make", startAddress: 0x2020, endAddress: 0x2030, confidence: 1))
            value.xrefs.append(edge(0x4000, 0x3000, "selref"))
            value.xrefs.append(edge(0x1000, 0x2000, "data"))
        }
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object(["address": .hex(0x2000), "name": .string("renamedStub")]))
        let expected = [row(0x1004, 0x2000, owner: 0x1000, name: "_main", target: "renamedStub"),
            row(0x100c, 0x2000, owner: 0x1008, name: "helper", target: "renamedStub"),
            row(0x1024, 0x3000, owner: 0x1020, name: "+[Doc make]", target: nil, via: "selref"),
            row(0x1300, 0x3000, owner: nil, name: nil, target: nil, via: "selref"),
            row(0x4000, 0x3000, owner: nil, name: nil, target: nil, via: "selref")]
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["selector": .string("save:")]))
            XCTAssertEqual(result, .array(expected))
        }
    }

    func testF14ImplementationSortProtocolExclusionAndRename() async throws {
        let store = makeStore { value, _ in
            value.objcClasses = [ObjCClass(name: "Base", superclassName: nil, adoptedProtocols: [], classMethods: [],
                instanceMethods: [ObjCMethod(selector: "save:", typeEncoding: nil, isClassMethod: false, implementation: 0x1030)],
                ivars: [], properties: [])]
            value.objcCategories = [ObjCCategory(name: "Extra", className: "Base",
                classMethods: [ObjCMethod(selector: "save:", typeEncoding: nil, isClassMethod: true, implementation: 0x1020)],
                instanceMethods: [ObjCMethod(selector: "save:", typeEncoding: nil, isClassMethod: false, implementation: 0x1040),
                    ObjCMethod(selector: "save:", typeEncoding: nil, isClassMethod: false, implementation: 0x1010)],
                adoptedProtocols: [], properties: [])]
            value.objcProtocols = [ObjCProtocol(name: "NotAnImplementation", address: 0x5000, adoptedProtocols: [],
                requiredMethods: [ObjCMethod(selector: "save:", typeEncoding: nil, isClassMethod: false, implementation: 0x1030)],
                optionalMethods: [], properties: [])]
        }
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object(["address": .hex(0x1010), "name": .string("renamedMethod")]))
        let expected = [implementation("Base", address: 0x1030, name: "-[Other save:]"),
            implementation("Base", category: "Extra", address: 0x1010, name: "renamedMethod"),
            implementation("Base", category: "Extra", address: 0x1040, name: "-[Base(Extra) save:]"),
            implementation("Base", category: "Extra", classMethod: true, address: 0x1020, name: "+[Doc make]")]
        for route in Route.allCases {
            let result = try await read(route, store, "implementations", .object(["selector": .string("save:")]))
            XCTAssertEqual(result, .array(expected))
        }
    }
}

extension SelectorQueriesTests {
    func testDynamicDispatchRetryPreservesSiblingImage() async throws {
        let store = makeStore()
        let reply = try await envelope(.mcpAsync, WorkspaceScriptingAPI(store: store), "callers",
            .object(["function": .string("-[Doc save:]"), "imageSlot": .int(1)]))
        let retry = try XCTUnwrap(reply["result"]?["note"]?["try"]?["arguments"])
        XCTAssertEqual(retry["selector"], .string("save:"))
        XCTAssertEqual(retry["imageSlot"], .int(1))
        let rows = try await read(.mcpAsync, store, "callers", retry)
        XCTAssertEqual(rows, .array(saveRows(slot: 1)))
    }

    func testEmptyImplementationOwnersConsumeWorkBudget() throws {
        let snapshot = makeStore { value, _ in
            value.objcClasses = (0..<4).map { index in
                ObjCClass(name: "Empty\(index)", superclassName: nil, adoptedProtocols: [],
                    classMethods: [], instanceMethods: [], ivars: [], properties: [])
            }
            value.objcCategories = []
        }.snapshot
        let args: ScriptValue = .object(["selector": .string("missing:")])
        checkBudget({ try WorkspaceScriptingAPI.selectorImplementationRows(args, snapshot: snapshot,
            selectionWorkLimit: 3, checkpoint: {}) }, unit: .workSteps, limit: 3)
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorImplementationRows(args, snapshot: snapshot,
            selectionWorkLimit: 4, checkpoint: {}), .array([]))
    }

    func testSelectorCapCountsOnlyDistinctRelevantSites() throws {
        let store = makeStore { value, _ in
            value.symbols.append(value.symbols[0])
            value.xrefs += [edge(0x1004, 0x2000, "call"), edge(0x100c, 0x2000, "call"),
                edge(0x1000, 0x2000, "data"), edge(0x1010, 0x2000, "selref"),
                edge(0x2004, 0x3000, "selref"), edge(0x1024, 0x3000, "selref")]
        }
        let args: ScriptValue = .object(["selector": .string("save:")])
        let result = try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: store.snapshot,
            resultLimit: 4, checkpoint: {})
        XCTAssertEqual(result, .array(saveRows()))
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: store.snapshot,
            resultLimit: 3, checkpoint: {}) }, unit: .rows, limit: 3)
    }

    func testKnownSelectorWithoutRelevantSitesHonorsZeroCap() throws {
        let snapshot = makeStore { value, _ in
            value.xrefs = [edge(0x1000, 0x2000, "data"), edge(0x1010, 0x2000, "selref"),
                edge(0x2004, 0x3000, "selref"), edge(0x1014, 0x3000, "call")]
        }.snapshot
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorSendSiteRows(
            .object(["selector": .string("save:")]), snapshot: snapshot,
            resultLimit: 0, checkpoint: {}), .array([]))
    }
    func testSuppressedCandidatesConsumeSharedEndpointWork() throws {
        var snapshot = makeStore { value, _ in
            value.symbols = [value.symbols[0]]
            value.functions = []
            value.objcSelectors = [0x3000: "save:"]
            value.xrefs = [edge(0x1004, 0x2000, "call"), edge(0x1024, 0x3000, "selref")]
        }.snapshot
        snapshot.manualXRefs = [
            ManualXRef(from: 0x1004, to: 0x2000, kind: "call", isSuppression: true),
            ManualXRef(from: 0x1024, to: 0x3000, kind: "selref", isSuppression: true)
        ]
        let args: ScriptValue = .object(["selector": .string("save:")])
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            selectionWorkLimit: 9, checkpoint: {}) }, unit: .workSteps, limit: 9)
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorSendSiteRows(args, snapshot: snapshot,
            selectionWorkLimit: 10, checkpoint: {}), .array([]))
    }

    // MARK: - Direct branches to the stub (CALLERS-TAIL)

    private func flow(_ from: UInt64, _ to: UInt64, _ kind: String = "branch") -> ControlFlowEdge {
        ControlFlowEdge(id: UUID(), from: from, to: to, kind: kind)
    }
    private func branchRow() -> ScriptValue {
        row(0x1034, 0x2000, owner: 0x1030, name: "-[Other save:]", target: "_objc_msgSend$save:", via: "stubBranch")
    }
    private func saveRowsWithBranch() -> [ScriptValue] {
        var rows = saveRows()
        rows.insert(branchRow(), at: 3)
        return rows
    }
    private var saveArgs: ScriptValue { .object(["selector": .string("save:")]) }

    func testC1DirectBranchToStubIsASendSiteOnEveryRoute() async throws {
        let store = makeStore { value, _ in value.controlFlowEdges = [self.flow(0x1034, 0x2000)] }
        for route in Route.allCases {
            let result = try await read(route, store, "callers", saveArgs)
            XCTAssertEqual(result, .array(saveRowsWithBranch()))
        }
    }

    func testC2cNonStubNonBranchAndStubInternalEdgesAddNoRows() throws {
        let snapshot = makeStore { value, _ in
            value.controlFlowEdges = [self.flow(0x1034, 0x2000), self.flow(0x2008, 0x2000),
                self.flow(0x1038, 0x1000), self.flow(0x103c, 0x2000, "call")]
        }.snapshot
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorSendSiteRows(saveArgs, snapshot: snapshot, checkpoint: {}),
                       .array(saveRowsWithBranch()))
    }

    func testC3SuppressedBranchEdgeIsAbsentAndOtherKindsDoNotSuppress() throws {
        var snapshot = makeStore { value, _ in value.controlFlowEdges = [self.flow(0x1034, 0x2000)] }.snapshot
        snapshot.manualXRefs = [ManualXRef(from: 0x1034, to: 0x2000, kind: XRefKind.call, isSuppression: true)]
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorSendSiteRows(saveArgs, snapshot: snapshot, checkpoint: {}),
                       .array(saveRows()))
        // C3b: a suppression only matches its own kind.
        snapshot.manualXRefs = [ManualXRef(from: 0x1034, to: 0x2000, kind: "data", isSuppression: true)]
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorSendSiteRows(saveArgs, snapshot: snapshot, checkpoint: {}),
                       .array(saveRowsWithBranch()))
    }

    func testC4EmptyControlFlowEdgesLeaveRowsUnchanged() throws {
        let snapshot = makeStore().snapshot
        XCTAssertEqual(try WorkspaceScriptingAPI.selectorSendSiteRows(saveArgs, snapshot: snapshot, checkpoint: {}),
                       .array(saveRows()))
    }

    func testC7BranchScanHasItsOwnEdgeBudget() throws {
        let snapshot = makeStore { value, _ in
            value.controlFlowEdges = [self.flow(0x1034, 0x2000), self.flow(0x1036, 0x2000), self.flow(0x1038, 0x1000)]
        }.snapshot
        XCTAssertThrowsError(try WorkspaceScriptingAPI.selectorSendSiteRows(saveArgs, snapshot: snapshot,
            branchEdgeScanLimit: 1, checkpoint: {})) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("not a typed refusal") }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget?.limit, 1)
            XCTAssertEqual(refusal.used, 3)
            XCTAssertTrue(refusal.detail.contains("control-flow edge budget"), refusal.detail)
            XCTAssertEqual(refusal.narrowing, ["imageSlot"])
        }
    }

    func testC6BranchRowsCountAgainstTheRowLimit() throws {
        let snapshot = makeStore { value, _ in
            value.controlFlowEdges = [self.flow(0x1034, 0x2000), self.flow(0x1036, 0x2000)]
        }.snapshot
        // 2 stub rows + 2 branch rows exceed a limit of 3.
        checkBudget({ try WorkspaceScriptingAPI.selectorSendSiteRows(self.saveArgs, snapshot: snapshot,
            resultLimit: 3, checkpoint: {}) }, unit: .rows, limit: 3)
    }

}
