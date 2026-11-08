import Foundation
import XCTest
@testable import MacScope

@MainActor
final class ListFilterTests: XCTestCase {
    private enum Route: CaseIterable, Equatable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    private let names = ["-[AppDelegate applicationDidFinishLaunching:]", "AppDelegate.init",
                         "sub_0x0000000000001100", "ViewController.load"]
    private let stale = "staleCursor: the list changed or the cursor belongs to another list; restart without a cursor"

    private func makeStore() -> WorkspaceStore {
        var analysis = ImageAnalysis()
        for (index, name) in names.enumerated() {
            let address = UInt64(0x1000 + index * 0x100)
            let function = FunctionSummary(id: UUID(), name: name, startAddress: address,
                                           endAddress: address + 4, confidence: 0.5)
            analysis.functions.append(function)
        }
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: "AppDelegate.export", address: 0x1000, kind: "export", libraryName: nil),
            SymbolSummary(id: UUID(), name: "external", address: nil, kind: "import", libraryName: "lib"),
            SymbolSummary(id: UUID(), name: "_objc_msgSend$tick", address: 0x2000, kind: "stub", libraryName: nil),
        ]
        return WorkspaceStore(workspaceName: "list-filters",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func request(_ command: String, _ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": arguments])])
    }

    private func envelope(_ route: Route, _ api: WorkspaceScriptingAPI,
                          _ command: String, _ arguments: ScriptValue) async throws -> ScriptValue {
        let server = MCPServer(api: api)
        let request = try request(command, arguments).jsonData()
        let data: Data?
        if route == .mcpSync { data = server.handleMessage(request) }
        else { data = await server.handleMessageAsync(request) }
        return try ScriptValue.decode(try XCTUnwrap(data))
    }

    private func read(_ route: Route, _ store: WorkspaceStore, _ command: String,
                      _ arguments: ScriptValue) async throws -> ScriptValue {
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

    private func executionRefuses(_ route: Route, _ store: WorkspaceStore, _ command: String,
                                 _ arguments: ScriptValue, detail: String) async throws {
        if route == .mcpSync || route == .mcpAsync {
            let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), command, arguments)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"],
                           .string("Tool call failed: Invalid argument: " + detail + "."))
        } else {
            do {
                _ = try await read(route, store, command, arguments)
                XCTFail("expected refusal")
            } catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail)) }
        }
    }

    private func rowNames(_ value: ScriptValue) -> [String] {
        (value.arrayValue ?? value["rows"]?.arrayValue ?? []).compactMap { $0["name"]?.stringValue }
    }

    func testFilteredFunctionsKeepRawOffsetsAndTotalsAcrossRoutes() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let args: ScriptValue = .object(["nameContains": .string("appdelegate"), "page": .bool(true), "limit": .int(1)])
            let first = try await read(route, store, "functions", args)
            XCTAssertEqual(first["total"], .int(2))
            XCTAssertEqual(rowNames(first), [names[0]])
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let second = try await read(route, store, "functions", .object(["nameContains": .string("appdelegate"), "page": .bool(true), "limit": .int(1), "cursor": .string(cursor)]))
            XCTAssertEqual(second["total"], .int(2))
            XCTAssertEqual(rowNames(second), [names[1]])
            XCTAssertEqual(second["nextCursor"], .null)
        }
    }

    func testFilteredFunctionsRefuseOversizedNamesWithoutPartialResults() throws {
        var analysis = ImageAnalysis()
        analysis.functions = [FunctionSummary(id: UUID(), name: "match", startAddress: 0x1000, endAddress: 0x1004, confidence: 1),
                              FunctionSummary(id: UUID(), name: String(repeating: "a", count: 4097), startAddress: 0x2000, endAddress: 0x2004, confidence: 1)]
        let store = WorkspaceStore(workspaceName: "function-filter-bound", snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertThrowsError(try api.execute("functions", arguments: .object(["nameContains": .string("match"), "limit": .int(1)])))
        XCTAssertThrowsError(try api.execute("functions", arguments: .object(["nameContains": .string("match"), "page": .bool(true)])))
        XCTAssertEqual(try api.execute("functions", arguments: .object(["nameContains": .string("match"), "limit": .int(0)])).arrayValue?.count, 0)
        XCTAssertEqual(try api.execute("functions", arguments: .object(["limit": .int(1)])).arrayValue?.count, 1)
    }

    func testRelocationNameFilterAcrossRoutes() async throws {
        var analysis = ImageAnalysis()
        for (index, name) in [nil, "_FirstMatch", "match[2]", "other"].enumerated() {
            analysis.relocations.append(RelocationSummary(id: UUID(), address: UInt64(0x1000 + index * 4), sectionName: "__text", typeCode: 1, typeName: nil, symbolName: name, symbolIndex: nil, addend: nil))
        }
        let store = WorkspaceStore(workspaceName: "relocation-filter", snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        for route in Route.allCases {
            let all = try await read(route, store, "relocations", .object([:]))
            XCTAssertEqual(all.arrayValue?.count, 4)
            let filtered = try await read(route, store, "relocations", .object(["nameContains": .string("MATCH"), "limit": .int(1)]))
            XCTAssertEqual(filtered.arrayValue?.compactMap { $0["symbol"]?.stringValue }, ["_FirstMatch"])
            let literal = try await read(route, store, "relocations", .object(["nameContains": .string("[2]")]))
            XCTAssertEqual(literal.arrayValue?.compactMap { $0["symbol"]?.stringValue }, ["match[2]"])
        }
    }

    func testRelocationFilterRejectsOversizedNamesBeforeReturningPartialResults() throws {
        var analysis = ImageAnalysis()
        for (index, name) in ["match", String(repeating: "a", count: 4097)].enumerated() {
            analysis.relocations.append(RelocationSummary(id: UUID(), address: UInt64(0x1000 + index * 4), sectionName: "__text", typeCode: 1, typeName: nil, symbolName: name, symbolIndex: nil, addend: nil))
        }
        let store = WorkspaceStore(workspaceName: "relocation-bound", snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertThrowsError(try api.execute("relocations", arguments: .object(["nameContains": .string("match")])))
        let limited = try api.execute("relocations", arguments: .object(["nameContains": .string("match"), "limit": .int(1)]))
        XCTAssertEqual(limited.arrayValue?.count, 1)
        XCTAssertThrowsError(try api.execute("relocations", arguments: .object(["nameContains": .string(""), "limit": .int(0)])))
    }

    func testFunctionsNameContainsAndRegexLegacy() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let contains = try await read(route, store, "functions",
                .object(["nameContains": .string("appdelegate")]))
            XCTAssertEqual(rowNames(contains), Array(names.prefix(2)))
            let late = try await read(route, store, "functions",
                .object(["nameContains": .string("ViewController"), "limit": .int(1)]))
            XCTAssertEqual(rowNames(late), [names[3]])
            let conjunction = try await read(route, store, "functions",
                .object(["nameContains": .string("AppDelegate"), "regex": .string("init$")]))
            XCTAssertEqual(rowNames(conjunction), [names[1]])
            let regex = try await read(route, store, "functions",
                .object(["regex": .string("^-\\[AppDelegate ")]))
            XCTAssertEqual(rowNames(regex), [names[0]])
            for key in ["nameContains", "regex"] {
                let pattern = "AppDelegate"
                let limited = try await read(route, store, "functions",
                    .object([key: .string(pattern), "limit": .int(1)]))
                XCTAssertEqual(rowNames(limited), [names[0]])
            }
            for key in ["nameContains", "regex"] {
                try await executionRefuses(route, store, "functions", .object([key: .string("")]),
                    detail: "\(key) must be a non-empty string of at most \(key == "regex" ? 256 : 1024) UTF-8 bytes")
            }
            try await executionRefuses(route, store, "functions", .object(["regex": .string("(")]),
                                      detail: "regex is not a valid regular expression")
        }
    }

    func testSymbolsKindFilter() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let stub = try await read(route, store, "symbols", .object(["kind": .string("stub"), "limit": .int(1)]))
            XCTAssertEqual(rowNames(stub), ["_objc_msgSend$tick"])
            let paged = try await read(route, store, "symbols", .object([
                "page": .bool(true), "kind": .string("stub"), "nameContains": .string("MSGSEND"),
                "regex": .string("tick$"), "limit": .int(1),
            ]))
            XCTAssertEqual(rowNames(paged), ["_objc_msgSend$tick"])
            XCTAssertEqual(paged["total"], .int(1))
            XCTAssertEqual(paged["isTruncated"], .bool(false))
            XCTAssertEqual(paged["nextCursor"], .null)
            let none = try await read(route, store, "symbols", .object(["kind": .string("absolute")]))
            XCTAssertEqual(none, .array([]))
            try await executionRefuses(route, store, "symbols", .object(["kind": .string("nope")]),
                detail: "kind must be one of local|import|export|undefined|absolute|indirect|stub|library-signature|objc-method")
            try await executionRefuses(route, store, "symbols", .object(["kind": .string("")]),
                detail: "kind must be a non-empty string of at most 1024 UTF-8 bytes")
        }
    }

    func testImportExportNameFiltersPreserveRowsAcrossRoutes() async throws {
        var analysis = ImageAnalysis()
        analysis.imports = [
            ImportSummary(id: UUID(), name: "skip", libraryName: nil, libraryOrdinal: nil),
            ImportSummary(id: UUID(), name: "First.Match", libraryName: "libA", libraryOrdinal: 0),
            ImportSummary(id: UUID(), name: "MATCH[2]", libraryName: nil, libraryOrdinal: nil),
        ]
        analysis.exports = [
            ExportSummary(id: UUID(), name: "skip", address: nil, source: ""),
            ExportSummary(id: UUID(), name: "First.Match", address: 0x1000, source: "trie"),
            ExportSummary(id: UUID(), name: "MATCH[2]", address: nil, source: ""),
        ]
        let store = WorkspaceStore(workspaceName: "import-export-filters",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        for route in Route.allCases {
            for command in ["imports", "exports"] {
                let original = try await read(route, store, command, .object([:]))
                XCTAssertEqual(rowNames(original), ["skip", "First.Match", "MATCH[2]"])
                let filtered = try await read(route, store, command,
                    .object(["nameContains": .string("match"), "limit": .int(1)]))
                XCTAssertEqual(rowNames(filtered), ["First.Match"])
                let literal = try await read(route, store, command,
                    .object(["nameContains": .string("[2]")]))
                XCTAssertEqual(rowNames(literal), ["MATCH[2]"])
                let row = try XCTUnwrap(literal.arrayValue?.first)
                if command == "imports" {
                    XCTAssertEqual(row["library"], .null)
                    XCTAssertEqual(row["ordinal"], .null)
                } else {
                    XCTAssertEqual(row["address"], .null)
                    XCTAssertEqual(row["source"], .string(""))
                }
            }
        }
    }

    func testImportExportNameFilterRejectsOversizedNamesBeforeReturningRows() throws {
        var analysis = ImageAnalysis()
        analysis.imports = [ImportSummary(id: UUID(), name: "match", libraryName: nil, libraryOrdinal: nil),
                            ImportSummary(id: UUID(), name: String(repeating: "x", count: 4_097), libraryName: nil, libraryOrdinal: nil)]
        analysis.exports = [ExportSummary(id: UUID(), name: "match", address: nil, source: ""),
                            ExportSummary(id: UUID(), name: String(repeating: "x", count: 4_097), address: nil, source: "")]
        let snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis])
        for command in ["imports", "exports"] {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead(command,
                arguments: .object(["nameContains": .string("match")]), snapshot: snapshot))
            let limited = try WorkspaceScriptingAPI.snapshotListRead(command,
                arguments: .object(["nameContains": .string("match"), "limit": .int(1)]), snapshot: snapshot)
            XCTAssertEqual(rowNames(limited), ["match"])
            XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead(command,
                arguments: .object(["nameContains": .string(""), "limit": .int(0)]), snapshot: snapshot))
        }
    }

    func testImportExportFilterAggregateAndVisitBudgets() throws {
        let longName = String(repeating: "x", count: 4_096)
        var analysis = ImageAnalysis()
        analysis.imports = (0..<257).map { _ in
            ImportSummary(id: UUID(), name: longName, libraryName: nil, libraryOrdinal: nil)
        }
        analysis.exports = (0..<257).map { _ in
            ExportSummary(id: UUID(), name: longName, address: nil, source: "")
        }
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis])
        let arguments: ScriptValue = .object(["nameContains": .string("never matches")])
        for command in ["imports", "exports"] {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead(command, arguments: arguments, snapshot: snapshot)) { error in
                guard case ScriptingError.structuredRefusal(let refusal) = error else {
                    return XCTFail("Expected aggregate budget refusal")
                }
                XCTAssertEqual(refusal.budget?.unit, .bytes)
                XCTAssertEqual(refusal.budget?.limit, 1_048_576)
            }
        }
        analysis.imports = (0..<100_001).map { _ in
            ImportSummary(id: UUID(), name: "", libraryName: nil, libraryOrdinal: nil)
        }
        analysis.exports = (0..<100_001).map { _ in
            ExportSummary(id: UUID(), name: "", address: nil, source: "")
        }
        snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis])
        for command in ["imports", "exports"] {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead(command, arguments: arguments, snapshot: snapshot)) { error in
                guard case ScriptingError.structuredRefusal(let refusal) = error else {
                    return XCTFail("Expected visit budget refusal")
                }
                XCTAssertEqual(refusal.budget?.unit, .workSteps)
                XCTAssertEqual(refusal.budget?.limit, 100_000)
            }
        }
    }

    func testFilteredPageTotalCursorAndTruncation() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let first = try await read(route, store, "functions",
                .object(["page": .bool(true), "limit": .int(1), "nameContains": .string("AppDelegate")]))
            XCTAssertEqual(first["total"], .int(2))
            XCTAssertEqual(first["isTruncated"], .bool(true))
            XCTAssertEqual(rowNames(first), [names[0]])
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let fields = try cursorFields(cursor)
            XCTAssertEqual(fields.count, 6)
            XCTAssertEqual(fields[3], "1")
            let second = try await read(route, store, "functions",
                .object(["page": .bool(true), "limit": .int(1), "nameContains": .string("AppDelegate"),
                         "cursor": .string(cursor)]))
            XCTAssertEqual(rowNames(second), [names[1]])
            XCTAssertEqual(second["total"], .int(2))
            XCTAssertEqual(second["isTruncated"], .bool(false))
            XCTAssertEqual(second["nextCursor"], .null)
            let both = try await read(route, store, "functions",
                .object(["page": .bool(true), "limit": .int(2), "nameContains": .string("AppDelegate")]))
            XCTAssertEqual(rowNames(both), Array(names.prefix(2)))
            XCTAssertEqual(both["isTruncated"], .bool(false))
        }
    }

    private func cursorFields(_ cursor: String) throws -> [String] {
        let data = try XCTUnwrap(Data(base64Encoded: cursor))
        return try XCTUnwrap(String(data: data, encoding: .utf8))
            .split(separator: "|", omittingEmptySubsequences: false).map(String.init)
    }

    func testFilteredCursorOffsetAboveFilteredTotal() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let first = try await read(route, store, "functions", .object([
                "page": .bool(true), "limit": .int(2), "regex": .string("AppDelegate|ViewController"),
            ]))
            XCTAssertEqual(first["total"], .int(3))
            XCTAssertEqual(rowNames(first), Array(names.prefix(2)))
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            XCTAssertEqual(try cursorFields(cursor)[3], "3")
            let second = try await read(route, store, "functions", .object([
                "page": .bool(true), "limit": .int(2), "regex": .string("AppDelegate|ViewController"),
                "cursor": .string(cursor),
            ]))
            XCTAssertEqual(rowNames(second), [names[3]])
            XCTAssertEqual(second["total"], .int(3))
            XCTAssertEqual(second["isTruncated"], .bool(false))
            XCTAssertEqual(second["nextCursor"], .null)
        }
    }

    func testCursorIsBoundToTheFilter() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let first = try await read(route, store, "functions", .object([
                "page": .bool(true), "limit": .int(1), "nameContains": .string("AppDelegate"),
            ]))
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let alternatives: [String?] = [nil, "ViewController"]
            for filter in alternatives {
                var arguments: [String: ScriptValue] = ["page": .bool(true), "cursor": .string(cursor)]
                if let filter { arguments["nameContains"] = .string(filter) }
                try await executionRefuses(route, store, "functions", .object(arguments), detail: stale)
            }
            let folded = try await read(route, store, "functions", .object([
                "page": .bool(true), "cursor": .string(cursor), "nameContains": .string("APPDELEGATE"),
            ]))
            XCTAssertEqual(rowNames(folded), [names[1]])
            let plain = try await read(route, store, "functions",
                .object(["page": .bool(true), "limit": .int(1)]))
            let oldCursor = try XCTUnwrap(plain["nextCursor"]?.stringValue)
            XCTAssertEqual(try cursorFields(oldCursor).count, 5)
            try await executionRefuses(route, store, "functions", .object([
                "page": .bool(true), "cursor": .string(oldCursor), "nameContains": .string("AppDelegate"),
            ]), detail: stale)
            var forged = try cursorFields(cursor)
            forged[3] = "2" // Valid full-array position, but this entry does not match.
            let forgedCursor = Data(forged.joined(separator: "|").utf8).base64EncodedString()
            try await executionRefuses(route, store, "functions", .object([
                "page": .bool(true), "cursor": .string(forgedCursor), "nameContains": .string("AppDelegate"),
            ]), detail: stale)
        }
    }

    func testListFilterSchemas() throws {
        for command in ["functions", "symbols"] {
            let info = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == command })
            let schema = HeadlessAutomationAuthority.inputSchema(for: info)
            for (key, maximum) in [("nameContains", 1_024), ("regex", 256)]
                + (command == "symbols" ? [("kind", 1_024)] : []) {
                XCTAssertEqual(schema["properties"]?[key]?["type"], .string("string"))
                XCTAssertEqual(schema["properties"]?[key]?["minLength"], .int(1))
                XCTAssertEqual(schema["properties"]?[key]?["maxLength"], .int(Int64(maximum)))
                for value in [ScriptValue.null, .string(String(repeating: "x", count: maximum + 1))] {
                    XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(
                        command: command, arguments: .object([key: value]))) {
                        let error = $0 as? ToolArgumentError
                        XCTAssertEqual(error?.refusal.field, key)
                        XCTAssertEqual(error?.refusal.code, value == .null ? .malformedInput : .outOfBounds)
                        XCTAssertEqual(error?.refusal.detail, value == .null
                            ? "Field '\(key)' must be a string."
                            : "Field '\(key)' must contain at most \(maximum) UTF-8 bytes.")
                        XCTAssertEqual(error?.refusal.maximum, value == .null ? nil : Int64(maximum))
                    }
                    XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(
                        command: command, arguments: .object([key: value]))) {
                        XCTAssertEqual($0 as? HeadlessAutomationAuthorityError, .invalidArguments)
                    }
                }
            }
        }
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(
            command: "functions", arguments: .object(["kind": .string("stub")]))) {
            XCTAssertEqual(($0 as? ToolArgumentError)?.refusal.field, "kind")
            XCTAssertEqual(($0 as? ToolArgumentError)?.refusal.code, .malformedInput)
        }
    }

    func testInvalidFilterTypesAndLengthsKeepPerRouteRefusals() async throws {
        let store = makeStore()
        for command in ["functions", "symbols"] {
            for (key, maximum) in [("nameContains", 1_024), ("regex", 256)]
                + (command == "symbols" ? [("kind", 1_024)] : []) {
                for value in [ScriptValue.null, .int(1), .string(String(repeating: "x", count: maximum + 1))] {
                    let tooLong = value.stringValue != nil
                    let detail = "\(key) must be a non-empty string of at most \(maximum) UTF-8 bytes"
                    for paged in [false, true] {
                        let arguments = ScriptValue.object([key: value, "page": .bool(paged)])
                        for route in Route.allCases {
                            switch route {
                            case .inline, .asynchronous:
                                try await executionRefuses(route, store, command, arguments, detail: detail)
                            case .attached:
                                do {
                                    _ = try await read(route, store, command, arguments)
                                    XCTFail("expected direct attached argument refusal")
                                } catch { XCTAssertEqual(error as? HeadlessAutomationAuthorityError, .invalidArguments) }
                            case .mcpSync, .mcpAsync:
                                let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), command, arguments)
                                XCTAssertNil(reply["error"])
                                XCTAssertEqual(reply["result"]?["isError"], .bool(true))
                                let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                                let expected = ToolArgumentError(field: key,
                                    code: tooLong ? .outOfBounds : .malformedInput,
                                    detail: tooLong ? "Field '\(key)' must contain at most \(maximum) UTF-8 bytes."
                                                    : "Field '\(key)' must be a string.",
                                    expected: tooLong ? nil : "string",
                                    maximum: tooLong ? Int64(maximum) : nil)
                                XCTAssertEqual(text, expected.refusal.text)
                            }
                        }
                    }
                }
            }
        }
    }

    func testFilterMatchingNothingIsHonestEmpty() async throws {
        let store = makeStore()
        for route in Route.allCases {
            for (command, filter) in [
                ("functions", ["nameContains": ScriptValue.string("NoSuchName")]),
                ("symbols", ["nameContains": ScriptValue.string("NoSuchName")]),
                ("symbols", ["kind": ScriptValue.string("absolute")]),
            ] {
                let legacy = try await read(route, store, command, .object(filter))
                XCTAssertEqual(legacy, .array([]))
                var arguments = filter
                arguments["page"] = .bool(true)
                let page = try await read(route, store, command, .object(arguments))
                XCTAssertEqual(page["rows"], .array([]))
                XCTAssertEqual(page["total"], .int(0))
                XCTAssertEqual(page["isTruncated"], .bool(false))
                XCTAssertEqual(page["nextCursor"], .null)
                XCTAssertEqual(page["sourceComplete"], .null)
            }
        }
    }

    func testRegexBoundsAndInvalidPattern() async throws {
        let store = makeStore()
        for command in ["functions", "symbols"] {
            for paged in [false, true] {
                for route in Route.allCases {
                    let accepted = try await read(route, store, command, .object([
                        "page": .bool(paged), "regex": .string(String(repeating: "a", count: 256)),
                    ]))
                    XCTAssertEqual(rowNames(accepted), [])
                    try await executionRefuses(route, store, command,
                        .object(["page": .bool(paged), "regex": .string("(")]),
                        detail: "regex is not a valid regular expression")
                    try await executionRefuses(route, store, command,
                        .object(["page": .bool(paged), "regex": .string("")]),
                        detail: "regex must be a non-empty string of at most 256 UTF-8 bytes")
                }
            }
        }
        // The 257-byte cases are exercised through every route by the preceding test.
    }

    func testControlUnfilteredListsUnchanged() async throws {
        let store = makeStore()
        var functionRows: [ScriptValue] = []
        for (index, name) in names.enumerated() {
            let address = UInt64(0x1000 + index * 0x100)
            let fields: [String: ScriptValue] = [
                "name": .string(name), "address": .hex(address),
                "end": .hex(address + 4), "confidence": .double(0.5),
            ]
            functionRows.append(.object(fields))
        }
        let expectedFunctions = ScriptValue.array(functionRows)
        let expectedSymbols = ScriptValue.array([
            .object(["name": .string("AppDelegate.export"), "address": .hex(0x1000), "kind": .string("export")]),
            .object(["name": .string("external"), "address": .null, "kind": .string("import")]),
            .object(["name": .string("_objc_msgSend$tick"), "address": .hex(0x2000), "kind": .string("stub")]),
        ])
        for route in Route.allCases {
            for (command, expected) in [("functions", expectedFunctions), ("symbols", expectedSymbols)] {
                var controls = [ScriptValue.object([:])]
                if command == "functions" || route == .inline || route == .asynchronous {
                    controls += [.object(["page": .bool(false)]), .object(["page": .null, "cursor": .null])]
                }
                for arguments in controls {
                    let value = try await read(route, store, command, arguments)
                    XCTAssertEqual(try value.jsonData(), try expected.jsonData())
                }
            }
            let page = try await read(route, store, "functions", .object(["page": .bool(true)]))
            XCTAssertEqual(page, .object(["rows": expectedFunctions, "total": .int(4),
                "isTruncated": .bool(false), "nextCursor": .null, "sourceComplete": .null]))
        }
    }

    func testPagedSymbolKindIsBoundedWithoutChangingLegacyOrMatching() throws {
        let store = makeStore()
        let value = String(repeating: "\u{1}", count: 300_000)
        let name = String(repeating: "\u{1}", count: 16_384)
        store.snapshot.symbols = [
            SymbolSummary(id: UUID(), name: name, address: nil, kind: value, libraryName: nil),
        ]
        let api = WorkspaceScriptingAPI(store: store)
        let legacy = try api.execute("symbols")
        XCTAssertEqual(legacy.arrayValue?.first?["kind"], .string(value))
        let page = try api.execute("symbols", arguments: .object(["page": .bool(true)]))
        let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
        XCTAssertEqual(row["name"], .string(name))
        XCTAssertEqual(row["kind"], .string(String(repeating: "\u{1}", count: 1_024)))
        XCTAssertEqual(row["kindTruncated"], .bool(true))
        XCTAssertEqual(row["kindByteLength"], .int(300_000))
        XCTAssertEqual(page["total"], .int(1))
        XCTAssertEqual(page["isTruncated"], .bool(false))
        XCTAssertLessThanOrEqual(try page.jsonData().count, 196_608)
        // Even after MCP's nested escaping, both capped fields fit the envelope bound.
        let wireText = String(decoding: try page.jsonData(), as: UTF8.self)
        XCTAssertLessThanOrEqual(try ScriptValue.string(wireText).jsonData().count, 200_000)
    }

    func testFilteredSymbolsKeepRawOffsetPagingAcrossRoutes() async throws {
        let store = makeStore()
        store.snapshot.symbols = ["match-one", "skip", "match-two", "match-three"].map {
            SymbolSummary(id: UUID(), name: $0, address: nil, kind: "export", libraryName: nil)
        }
        for route in Route.allCases {
            let first = try await read(route, store, "symbols", .object([
                "page": .bool(true), "nameContains": .string("match"), "limit": .int(1)
            ]))
            XCTAssertEqual(rowNames(first), ["match-one"])
            XCTAssertEqual(first["total"], .int(3))
            let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
            let second = try await read(route, store, "symbols", .object([
                "page": .bool(true), "nameContains": .string("match"), "limit": .int(1), "cursor": .string(cursor)
            ]))
            XCTAssertEqual(rowNames(second), ["match-two"])
            XCTAssertEqual(second["total"], .int(3))
        }
    }

    func testFilteredSymbolsRefuseOversizedLateCandidateBeforeReturningRows() throws {
        let store = makeStore()
        store.snapshot.symbols = [
            SymbolSummary(id: UUID(), name: "match", address: nil, kind: "export", libraryName: nil),
            SymbolSummary(id: UUID(), name: String(repeating: "x", count: 4_097), address: nil, kind: "export", libraryName: nil),
        ]
        let api = WorkspaceScriptingAPI(store: store)
        for paged in [false, true] {
            XCTAssertThrowsError(try api.execute("symbols", arguments: .object([
                "page": .bool(paged), "nameContains": .string("match"), "limit": .int(1)
            ])))
        }
        XCTAssertEqual(try api.execute("symbols", arguments: .object([
            "nameContains": .string("match"), "limit": .int(0)
        ])), .array([]))
    }

    func testFilteredSymbolSelectionCandidateBoundaryAndCancellation() throws {
        let symbol = SymbolSummary(id: UUID(), name: "x", address: nil, kind: "e", libraryName: nil)
        let maximum = Array(repeating: symbol, count: 100_000)
        XCTAssertEqual(try SymbolFilterSelection.indices(maximum, matching: { _, _, _ in false }, checkpoint: {}).count, 0)
        XCTAssertThrowsError(try SymbolFilterSelection.indices(maximum + [symbol],
            matching: { _, _, _ in false }, checkpoint: {}))
        enum Stop: Error { case cancelled }
        var checkpoints = 0
        XCTAssertThrowsError(try SymbolFilterSelection.indices([symbol], matching: { _, _, _ in true }, checkpoint: {
            checkpoints += 1
            if checkpoints == 2 { throw Stop.cancelled }
        }))
    }

    func testDigestEscapingAndCaseFold() {
        let upper = ListRowFilter(nameContains: "APPDELEGATE", regex: nil, kind: nil)
        let lower = ListRowFilter(nameContains: "appdelegate", regex: nil, kind: nil)
        XCTAssertEqual(upper.digest, lower.digest)
        XCTAssertNotEqual(ListRowFilter(nameContains: "a\0b", regex: nil, kind: nil).digest,
                          ListRowFilter(nameContains: "a\\0b", regex: nil, kind: nil).digest)
        XCTAssertNotEqual(ListRowFilter(nameContains: nil, regex: "A", kind: nil).digest,
                          ListRowFilter(nameContains: nil, regex: "a", kind: nil).digest)
    }
}
