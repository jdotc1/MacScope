import Foundation
import XCTest
@testable import MacScope

@MainActor
final class GraphRowNamesTests: XCTestCase {
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

    private let getter = "$s3app5ModelV5countSivg"
    private let getterText = "app.Model.count.getter : Swift.Int"

    private func makeStore(renamed: Bool = true) throws -> WorkspaceStore {
        func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
            FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
        }
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "graph-\(slot.rawValue)", path: "/fixture",
                kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        let sections = [
            SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                size: 0x500, fileOffset: 0, isExecutable: true),
            SectionSummary(id: UUID(), name: "__TEXT,__objc_stubs", address: 0x2000,
                size: 0x40, fileOffset: 0x500, isExecutable: true),
        ]
        var primary = ImageAnalysis()
        primary.functions = [function("_main", 0x1000, 0x1010), function("helper", 0x1010, 0x1020),
            function("outer", 0x1100, 0x1200), function("inner", 0x1140, 0x1180),
            function("zero", 0x1300, 0x1300), function(getter, 0x1400, 0x1410)]
        primary.sections = sections
        primary.symbols = [SymbolSummary(id: UUID(), name: "_objc_msgSend$isRichText", address: 0x2000,
            kind: "stub", libraryName: nil)]
        primary.stringLiterals = [StringLiteralSummary(id: UUID(), value: "hello", address: 0x2100,
            sourceSection: "__cstring", byteLength: 6)]
        let pairs: [(UInt64, UInt64, String)] = [
            (0x1004, 0x1010, XRefKind.call), (0x1006, 0x2100, XRefKind.string),
            (0x1008, 0x2000, XRefKind.call), (0x100c, 0x1014, XRefKind.call),
            (0x100e, 0x1400, XRefKind.call), (0x1150, 0x1010, XRefKind.call),
            (0x1300, 0x1010, XRefKind.call), (0x1304, 0x1010, XRefKind.call),
            (0x1404, 0x1010, XRefKind.call),
        ]
        primary.xrefs = pairs.map { XRef(id: UUID(), from: $0.0, to: $0.1, kind: $0.2) }
        var other = ImageAnalysis()
        other.functions = [function("sib_fn", 0x1000, 0x1010), function("sib_helper", 0x1010, 0x1020)]
        other.sections = sections
        other.xrefs = [XRef(id: UUID(), from: 0x1004, to: 0x1010, kind: XRefKind.call)]
        let store = WorkspaceStore(workspaceName: "graph names",
            snapshot: WorkspaceSnapshot(binaries: [image(.primary), image(sibling)],
                analysisBySlot: [.primary: primary, sibling: other]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        if renamed {
            _ = try WorkspaceScriptingAPI(store: store).execute("rename",
                arguments: .object(["address": .hex(0x1010), "name": .string("renamedHelper")]))
        }
        return store
    }

    // Explicit expected names, not calls to the production namer or classifier.
    private func row(_ from: UInt64, _ to: UInt64, _ target: String?,
                     owner: UInt64? = 0x1000, name: String? = "_main", slot: Int = 0,
                     kind: String? = nil, selector: String? = nil,
                     toDemangled: String? = nil, fromDemangled: String? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = ["from": .hex(from), "to": .hex(to),
            "imageSlot": .int(Int64(slot)), "toName": target.map(ScriptValue.string) ?? .null,
            "fromFunction": owner.map(ScriptValue.hex) ?? .null,
            "fromFunctionName": name.map(ScriptValue.string) ?? .null]
        if let kind { fields["kind"] = .string(kind) }
        if let selector { fields["selector"] = .string(selector) }
        if let toDemangled { fields["toDemangled"] = .string(toDemangled) }
        if let fromDemangled { fields["fromFunctionDemangled"] = .string(fromDemangled) }
        return .object(fields)
    }

    private func sorted(_ value: ScriptValue) throws -> [ScriptValue] {
        try XCTUnwrap(value.arrayValue).sorted {
            let a = ($0["from"]?.addressValue ?? 0, $0["to"]?.addressValue ?? 0)
            let b = ($1["from"]?.addressValue ?? 0, $1["to"]?.addressValue ?? 0)
            return a < b
        }
    }

    private func expectedCallers(kind: String? = nil) -> [ScriptValue] {
        var rows = [
            row(0x1004, 0x1010, "renamedHelper", kind: kind),
            row(0x1150, 0x1010, "renamedHelper", owner: 0x1100, name: "outer", kind: kind),
            row(0x1300, 0x1010, "renamedHelper", owner: 0x1300, name: "zero", kind: kind),
            row(0x1304, 0x1010, "renamedHelper", owner: nil, name: nil, kind: kind),
            row(0x1404, 0x1010, "renamedHelper", owner: 0x1400, name: getter,
                kind: kind, fromDemangled: getterText),
        ]
        if kind == nil { rows.append(row(0x100c, 0x1014, nil)) }
        return rows
    }

    func testF1CalleesHaveExactTargetNames() async throws {
        let store = try makeStore()
        let expected = ScriptValue.array([
            row(0x1004, 0x1010, "renamedHelper"),
            row(0x1008, 0x2000, "_objc_msgSend$isRichText", selector: "isRichText"),
            row(0x100c, 0x1014, nil),
            row(0x100e, 0x1400, getter, toDemangled: getterText),
        ])
        for route in Route.allCases {
            let result = try await read(route, store, "callees", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(try sorted(result), try sorted(expected))
        }
    }

    func testFinalAddressCallersAndCalleesPreserveRowsAndImageScope() async throws {
        for end: UInt64 in [UInt64.max, 0] {
            func analysis(_ prefix: String) -> ImageAnalysis {
                var result = ImageAnalysis()
                result.functions = [
                    FunctionSummary(id: UUID(), name: prefix + "source", startAddress: 0x1000,
                        endAddress: 0x1010, confidence: 1),
                    FunctionSummary(id: UUID(), name: prefix + "target", startAddress: 0x1010,
                        endAddress: 0x1020, confidence: 1),
                    FunctionSummary(id: UUID(), name: prefix + "final", startAddress: UInt64.max,
                        endAddress: end, confidence: 1),
                ]
                result.xrefs = [
                    XRef(id: UUID(), from: 0x1004, to: UInt64.max, kind: XRefKind.call),
                    XRef(id: UUID(), from: 0x1004, to: UInt64.max, kind: XRefKind.call),
                    XRef(id: UUID(), from: UInt64.max, to: 0x1010, kind: XRefKind.call),
                    XRef(id: UUID(), from: UInt64.max, to: 0x1010, kind: XRefKind.call),
                    XRef(id: UUID(), from: 0x1008, to: UInt64.max, kind: XRefKind.string),
                    XRef(id: UUID(), from: UInt64.max, to: 0x1000, kind: XRefKind.string),
                    XRef(id: UUID(), from: 0x1008, to: UInt64.max - 1, kind: XRefKind.call),
                    XRef(id: UUID(), from: UInt64.max - 1, to: 0x1010, kind: XRefKind.call),
                ]
                return result
            }
            func image(_ slot: ImageSlot) -> BinaryImage {
                BinaryImage(id: UUID(), name: "final-\(slot.rawValue)", path: "/fixture",
                    kind: "Mach-O executable", architecture: "arm64", slot: slot)
            }
            let store = WorkspaceStore(workspaceName: "final address",
                snapshot: WorkspaceSnapshot(binaries: [image(.primary), image(sibling)],
                    analysisBySlot: [.primary: analysis("primary_"), sibling: analysis("sibling_")]),
                engine: AnalysisEngine(), autosaveScheduler: nil)
            for route in Route.allCases {
                for selectedSlot: Int? in [nil, 0, 1] {
                    let slot = selectedSlot ?? 0
                    let prefix = slot == 0 ? "primary_" : "sibling_"
                    for byName in [false, true] {
                        var arguments: [String: ScriptValue] = byName
                            ? ["function": .string(prefix + "final")]
                            : ["address": .hex(UInt64.max)]
                        if let selectedSlot { arguments["imageSlot"] = .int(Int64(selectedSlot)) }
                        let callers = try await read(route, store, "callers", .object(arguments))
                        XCTAssertEqual(callers, .array([
                            row(0x1004, UInt64.max, prefix + "final", name: prefix + "source", slot: slot),
                        ]))
                        let callees = try await read(route, store, "callees", .object(arguments))
                        XCTAssertEqual(callees, .array([
                            row(UInt64.max, 0x1010, prefix + "target", owner: UInt64.max,
                                name: prefix + "final", slot: slot),
                        ]))
                    }
                }
            }
        }
    }

    func testF2CallersFirstContainingOwnerAndNullGap() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["function": .string("renamedHelper")]))
            XCTAssertEqual(try sorted(result), try sorted(.array(expectedCallers())))
        }
    }

    func testF3XRefsIncludeNamesWithoutStringOrInteriorLabels() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let targets = try await read(route, store, "xrefs", .object(["to": .hex(0x1010)]))
            XCTAssertEqual(try sorted(targets), try sorted(.array(expectedCallers(kind: XRefKind.call))))
            let string = try await read(route, store, "xrefs", .object(["from": .hex(0x1006)]))
            XCTAssertEqual(string, .array([row(0x1006, 0x2100, nil, kind: XRefKind.string)]))
        }
    }

    func testF4SiblingNamesDoNotLeakPrimaryRename() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            for command in ["callers", "xrefs"] {
                let args: ScriptValue = .object([command == "callers" ? "address" : "to": .hex(0x1010),
                    "imageSlot": .int(1)])
                let result = try await read(route, store, command, args)
                XCTAssertEqual(result, .array([row(0x1004, 0x1010, "sib_helper", name: "sib_fn", slot: 1,
                    kind: command == "xrefs" ? XRefKind.call : nil)]))
            }
        }
    }

    func testF5StubRowsRetainOwnerAndGainTarget() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["address": .hex(0x2000)]))
            XCTAssertEqual(result, .array([row(0x1008, 0x2000, "_objc_msgSend$isRichText", selector: "isRichText")]))
        }
    }

    private func functionRow(_ target: UInt64, _ start: UInt64, _ end: UInt64, _ name: String,
                             store: WorkspaceStore, slot: Int = 0, demangled: String? = nil) throws -> ScriptValue {
        let binary = try XCTUnwrap(store.snapshot.binary(in: ImageSlot(rawValue: slot)))
        var fields: [String: ScriptValue] = ["name": .string(name), "start": .hex(start), "end": .hex(end),
            "imageSlot": .int(Int64(slot)), "imageOwner": .string(binary.id.uuidString),
            "requestedAddress": .hex(target), "resolvedFunction": .hex(start),
            "resolution": .string(target == start ? "exact" : "containing")]
        if let demangled { fields["demangled"] = .string(demangled) }
        return .object(fields)
    }

    func testF6ContainingFunctionExactInteriorZeroOverlapSwiftAndSibling() async throws {
        let store = try makeStore()
        let cases: [(UInt64, UInt64, UInt64, String, Int, String?)] = [
            (0x1010, 0x1010, 0x1020, "renamedHelper", 0, nil),
            (0x1014, 0x1010, 0x1020, "renamedHelper", 0, nil),
            (0x1300, 0x1300, 0x1300, "zero", 0, nil),
            (0x1150, 0x1100, 0x1200, "outer", 0, nil),
            (0x1404, 0x1400, 0x1410, getter, 0, getterText),
            (0x1014, 0x1010, 0x1020, "sib_helper", 1, nil),
        ]
        for route in Route.allCases {
            for (address, start, end, name, slot, demangled) in cases {
                var arguments: [String: ScriptValue] = ["address": .hex(address)]
                if slot != 0 { arguments["image"] = .int(Int64(slot)) }
                let result = try await read(route, store, "containing-function", .object(arguments))
                XCTAssertEqual(result, try functionRow(address, start, end, name, store: store,
                    slot: slot, demangled: demangled))
            }
        }
    }

    private func uncovered(_ address: UInt64) -> ScriptingError {
        if address == 0x1304 {
            return .structuredRefusal(MCPToolRefusal(code: .unknownSubject,
                detail: "address 0x1304 is outside every function in image slot 0; nearest preceding function zero at 0x1300; section __TEXT,__text [0x1000, 0x1500)",
                requestedAddress: 0x1304, imageSlot: 0,
                nearestFunction: MCPRefusalFunction(name: "zero", address: 0x1300),
                section: MCPRefusalSection(name: "__TEXT,__text", start: 0x1000, end: 0x1500)))
        }
        return .structuredRefusal(MCPToolRefusal(code: .unknownSubject,
            detail: "address 0x2000 is outside every function in image slot 0; nearest preceding function $s3app5ModelV5countSivg at 0x1400; section __TEXT,__objc_stubs [0x2000, 0x2040)",
            requestedAddress: 0x2000, imageSlot: 0,
            nearestFunction: MCPRefusalFunction(name: getter, address: 0x1400),
            section: MCPRefusalSection(name: "__TEXT,__objc_stubs", start: 0x2000, end: 0x2040)))
    }

    func testF7UncoveredUnknownImageAndMissingAddressRefuse() async throws {
        let store = try makeStore(renamed: false)
        for route in Route.allCases {
            for address in [UInt64(0x1304), 0x2000] {
                try await refuses(route, store, "containing-function", .object(["address": .hex(address)]), uncovered(address))
            }
            try await refuses(route, store, "containing-function",
                .object(["address": .hex(0x1014), "image": .int(7)]), .unknownImage(selector: "7", validSlots: [0, 1]))
            // W16 remains the missing-address case, separate from the budget control.
            try await refuses(route, store, "containing-function", .object([:]), .missingArgument("address"))
        }
    }

    func testF7W17RejectsFunctionArgumentAtMCP() async throws {
        let store = try makeStore(renamed: false)
        let expected = ToolArgumentError(field: "function", detail: "Field 'function' is not an allowed argument.",
            allowed: ["address", "image"])
        for route in [Route.mcpSync, .mcpAsync] {
            let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), "containing-function",
                .object(["address": .hex(0x1014), "function": .string("x")]))
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string(expected.refusal.text))
        }
    }

    func testF9GraphOwnerMatchesCompletedContainingSelection() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            for (command, args) in [("callers", ScriptValue.object(["function": .string("renamedHelper")])),
                                    ("xrefs", .object(["to": .hex(0x1010)]))] {
                let graph = try await read(route, store, command, args)
                // Prevent two implementations sharing the same wrong owner rule from agreeing.
                let expected = expectedCallers(kind: command == "xrefs" ? XRefKind.call : nil)
                XCTAssertEqual(try sorted(graph), try sorted(.array(expected)))
                for row in try XCTUnwrap(graph.arrayValue) {
                    let address = try XCTUnwrap(row["from"]?.addressValue)
                    let owner = try XCTUnwrap(row["fromFunction"])
                    if owner == .null {
                        XCTAssertEqual(address, 0x1304)
                        try await refuses(route, store, "containing-function",
                            .object(["address": .hex(address), "image": .int(0)]), uncovered(address))
                    } else {
                        let result = try await read(route, store, "containing-function",
                            .object(["address": .hex(address), "image": .int(0)]))
                        XCTAssertEqual(result["start"], owner)
                        XCTAssertEqual(result["name"], row["fromFunctionName"])
                    }
                }
            }
        }
    }

    func testQ1ActualFunctionBudgetRefusesDespiteNamedGraphOwner() async throws {
        let function = FunctionSummary(id: UUID(), name: "owner", startAddress: 0x1000,
            endAddress: 0x1010, confidence: 1)
        var analysis = ImageAnalysis()
        // Cheap value-array fixture: no store normalization, no fresh production seam.
        analysis.functions = Array(repeating: function, count: 100_001)
        analysis.xrefs = [XRef(id: UUID(), from: 0x1004, to: 0x1000, kind: XRefKind.call)]
        let image = BinaryImage(id: UUID(), name: "budget", path: "/fixture",
            kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        let snapshot = WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("xrefs",
            arguments: .object(["to": .hex(0x1000)]), snapshot: snapshot))
        let graph = try await Task.detached {
            try WorkspaceScriptingAPI.snapshotListRead("xrefs",
                arguments: .object(["to": .hex(0x1000)]), snapshot: snapshot)
        }.value
        XCTAssertEqual(graph.arrayValue?.first?["fromFunction"], .hex(0x1000))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("containing-function",
            arguments: .object(["address": .hex(0x1004)]), snapshot: snapshot)) {
            XCTAssertEqual($0 as? ScriptingError, .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "function selection exceeds the snapshot work budget",
                budget: .init(unit: .workSteps, limit: 100_000), used: 100_001, narrowing: [])))
        }
    }

    func testGraphNameIndexPreservesFirstOwnerLastTargetAndBoundaries() throws {
        func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
            FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
        }
        let functions = [function("outer", 0x1000, 0x1020), function("inner", 0x1008, 0x1010),
                         function("replacement", 0x1000, 0x1000), function("end", UInt64.max, UInt64.max)]
        let symbols = [SymbolSummary(id: UUID(), name: "symbol", address: 0x1000, kind: "symbol", libraryName: nil)]
        let index = try GraphNameIndex.build(functions: functions, symbols: symbols, textLimit: 16 << 20, checkpoint: {})
        XCTAssertEqual(index.rawName(0x1000), "replacement")
        XCTAssertEqual(index.owner(0x1008)?.name, "outer")
        XCTAssertNil(index.owner(0x1020))
        XCTAssertEqual(index.owner(UInt64.max)?.name, "end")
        XCTAssertNil(index.owner(0x0fff))
    }

    func testGraphNameMemoIsGenerationOwnedAndCancellationDoesNotPublish() throws {
        let function = FunctionSummary(id: UUID(), name: "old", startAddress: 0x1000, endAddress: 0x1010, confidence: 1)
        var original = ImageAnalysis(); original.functions = [function]
        let index = try original.graphNames.index(functions: original.functions, symbols: original.symbols, checkpoint: {})
        var changed = original
        changed.functions[0].name = "new"
        XCTAssertEqual(index.rawName(0x1000), "old")
        XCTAssertEqual(try changed.graphNames.index(functions: changed.functions, symbols: changed.symbols, checkpoint: {}).rawName(0x1000), "new")
        let fresh = GraphNameMemo()
        XCTAssertThrowsError(try fresh.index(functions: original.functions, symbols: [], checkpoint: { throw CancellationError() }))
        XCTAssertEqual(try fresh.index(functions: original.functions, symbols: [], checkpoint: {}).rawName(0x1000), "old")
    }

    func testGraphNameIndexRefusesOversizedNameWithoutPartialRows() throws {
        let function = FunctionSummary(id: UUID(), name: String(repeating: "a", count: 8193),
            startAddress: 0x1000, endAddress: 0x1010, confidence: 1)
        var analysis = ImageAnalysis(); analysis.functions = [function]
        let image = BinaryImage(id: UUID(), name: "n", path: "/fixture", kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        let snapshot = WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis])
        let ref = XRef(id: UUID(), from: 0x1004, to: 0x1000, kind: XRefKind.call)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.namedGraphRows([ref], includeKind: false,
            snapshot: snapshot, slot: .primary, checkpoint: {})) { error in
            guard let scripting = error as? ScriptingError, case .structuredRefusal = scripting else {
                return XCTFail("expected structured refusal")
            }
        }
    }

    func testC1ExistingUncoveredRefusalsStayIdentical() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            try await refuses(route, store, "callees", .object(["address": .hex(0x2000)]), uncovered(0x2000))
            try await refuses(route, store, "callers", .object(["address": .hex(0x1304)]), uncovered(0x1304))
        }
    }

    func testC2EmptyCallersStayEmpty() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["function": .string("outer")]))
            XCTAssertEqual(result, .array([]))
        }
    }

    func testC3NameAtStaysExactOnly() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let exact = try await read(route, store, "name-at", .object(["address": .hex(0x1010)]))
            let interior = try await read(route, store, "name-at", .object(["address": .hex(0x1014)]))
            XCTAssertEqual(exact, .string("renamedHelper"))
            XCTAssertEqual(interior, .null)
        }
    }

    func testQ2FullNamesKeepExistingMCPOutputLimitAndXRefPrefixWorkaround() async throws {
        let store = try makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        let longName = String(repeating: "n", count: 700)
        // Exercise read-side output bounds with a pre-existing long annotation; VA1 now
        // bounds new scripting function-entry names to 256 UTF-8 bytes.
        store.setCustomName(0x1010, in: store.snapshot.primarySlot, name: longName)
        let args = ScriptValue.object(["to": .hex(0x1010)])
        let direct = try api.execute("xrefs", arguments: args)
        XCTAssertEqual(direct.arrayValue?.count, 5)
        XCTAssertTrue(try XCTUnwrap(direct.arrayValue).allSatisfy { $0["toName"] == .string(longName) })
        let configuration = MCPServer.Configuration(maximumInputBytes: 1_048_576,
            maximumOutputBytes: 4_096, maximumToolDurationNanoseconds: 30_000_000_000,
            maximumRememberedCancellations: 1_024)
        let server = MCPServer(api: api, configuration: configuration)
        for asynchronous in [false, true] {
            let encoded = try request("xrefs", args).jsonData()
            let data: Data?
            if asynchronous { data = await server.handleMessageAsync(encoded) }
            else { data = server.handleMessage(encoded) }
            let reply = try ScriptValue.decode(try XCTUnwrap(data))
            XCTAssertEqual(reply["error"]?["code"], .int(-32603))
            XCTAssertEqual(reply["error"]?["message"], .string("Response exceeds limit"))
            XCTAssertNil(reply["result"])
            let prefixRequest = try request("xrefs", .object(["to": .hex(0x1010), "limit": .int(1)])).jsonData()
            let prefixData: Data?
            if asynchronous { prefixData = await server.handleMessageAsync(prefixRequest) }
            else { prefixData = server.handleMessage(prefixRequest) }
            let prefix = try ScriptValue.decode(try XCTUnwrap(prefixData))
            XCTAssertNil(prefix["error"])
            let text = try XCTUnwrap(prefix["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let rows = try ScriptValue.decode(Data(text.utf8))
            XCTAssertEqual(rows.arrayValue?.count, 1)
            XCTAssertEqual(rows.arrayValue?.first?["toName"], .string(longName))
        }
    }

    func testF8CatalogSchemaSummaryAndAppleScriptExclusion() async throws {
        XCTAssertTrue(WorkspaceScriptingAPI.snapshotListCommands.contains("containing-function"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("containing-function"))
        XCTAssertFalse(AppleScriptCommandTranslator.allowlistedCommandIDs.contains("containing-function"))
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "containing-function" })
        XCTAssertEqual(info.summary, "The function containing an address: the first function, in list order, whose range [start, end) covers it (a zero-width function covers only its start). Reads the primary image by default; `image` (a slot index or an image-owner ID) selects another loaded image. Returns {name, start, end, imageSlot, imageOwner, resolvedFunction, requestedAddress, resolution}, plus demangled for covered Swift names; resolution is exact at the start, otherwise containing. An address outside every function is refused with code unknownSubject, naming the nearest preceding function and the section; there is no nearest-function fallback.")
        let store = try makeStore()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")])
        for asynchronous in [false, true] {
            let data: Data?
            if asynchronous { data = await server.handleMessageAsync(try request.jsonData()) }
            else { data = server.handleMessage(try request.jsonData()) }
            let reply = try ScriptValue.decode(try XCTUnwrap(data))
            let tool = try XCTUnwrap(reply["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string("containing-function") })
            XCTAssertEqual(tool["inputSchema"]?["required"], .array([.string("address")]))
            guard case .object(let properties) = try XCTUnwrap(tool["inputSchema"]?["properties"]) else {
                return XCTFail("missing properties")
            }
            XCTAssertEqual(Set(properties.keys), ["address", "image"])
        }
    }

    func testTargetFunctionBeatsSymbolAndRenamedStubLosesSelector() async throws {
        let store = try makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x2000), "name": .string("renamedStub")]))
        for route in Route.allCases {
            let result = try await read(route, store, "callers", .object(["address": .hex(0x2000)]))
            XCTAssertEqual(result, .array([row(0x1008, 0x2000, "renamedStub")]))
        }
        var analysis = ImageAnalysis()
        analysis.functions = [FunctionSummary(id: UUID(), name: "functionWins", startAddress: 0x1010,
            endAddress: 0x1020, confidence: 1)]
        analysis.symbols = [SymbolSummary(id: UUID(), name: "symbolLoses", address: 0x1010,
            kind: "defined", libraryName: nil)]
        analysis.xrefs = [XRef(id: UUID(), from: 0x1004, to: 0x1010, kind: XRefKind.call)]
        let image = BinaryImage(id: UUID(), name: "precedence", path: "/fixture",
            kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        let snapshot = WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis])
        let rows = try WorkspaceScriptingAPI.snapshotListRead("xrefs",
            arguments: .object(["to": .hex(0x1010)]), snapshot: snapshot)
        XCTAssertEqual(rows, .array([row(0x1004, 0x1010, "functionWins", owner: nil, name: nil, kind: XRefKind.call)]))
    }

    func testEmptyNamerDoesNotCheckpointAndOwnerGuardPrecedesCheckpoint() throws {
        let snapshot = try makeStore().snapshot
        var count = 0
        let empty = try WorkspaceScriptingAPI.namedGraphRows([], includeKind: true, snapshot: snapshot,
            slot: .primary, checkpoint: { count += 1; throw CancellationError() })
        XCTAssertEqual(empty, [])
        XCTAssertEqual(count, 0)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.graphRowOwners(sources: [0x1004],
            functions: snapshot.functions, guardFunction: { _ in throw CancellationError() },
            checkpoint: { count += 1 })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(count, 0)
        var indices: [Int] = []
        XCTAssertThrowsError(try WorkspaceScriptingAPI.graphRowOwners(sources: [0x1004],
            functions: snapshot.functions, guardFunction: { indices.append($0) },
            checkpoint: { throw CancellationError() })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(indices, [0])
    }
    private func annotationInstructions() -> [InstructionRow] {
        let values: [(UInt64, String, String)] = [
            (0x1000, "adrp", "x3, 0x3000"), (0x1004, "add", "x3, x3, #0x0"),
            (0x1008, "bl", "0x1100"), (0x100c, "bl", "0x2000"), (0x1010, "bl", "0x1200"),
            (0x1014, "bl", "0x1300"), (0x1018, "adrp", "x1, 0x5000"), (0x101c, "ldr", "x1, [x1]"),
            (0x1020, "ldr", "x2, [x1, #0x8]"), (0x1024, "adr", "x0, 0x4000"),
            (0x1028, "adrp", "x8, 0x6000"), (0x102c, "ldr", "x8, [x8]"),
            (0x1030, "adrp", "x9, 0x3000"), (0x1034, "add", "x10, x9, #0x20"),
            (0x1038, "add", "x11, x9, #0x3"), (0x103c, "add", "x12, x9, #0x100"),
            (0x1040, "ret", ""), (0x1044, "bl", "renamedHelper")]
        return values.map { InstructionRow(address: $0.0, bytes: "00 00 00 00", mnemonic: $0.1,
            operands: $0.2, hasBreakpoint: false, comment: nil) }
    }

    private func makeAnnotationStore(selectors: Bool = true, reversed: Bool = false) throws -> WorkspaceStore {
        func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
            FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
        }
        var analysis = ImageAnalysis()
        analysis.functions = [function("_main", 0x1000, 0x1080), function("helper", 0x1100, 0x1110),
            function(getter, 0x1200, 0x1210)]
        analysis.symbols = [SymbolSummary(id: UUID(), name: "_objc_msgSend$isRichText", address: 0x2000, kind: "stub", libraryName: nil),
            SymbolSummary(id: UUID(), name: "_gTable", address: 0x3020, kind: "data", libraryName: nil)]
        let long = String(repeating: "a", count: 255) + "é" + String(repeating: "b", count: 100)
        analysis.stringLiterals = [StringLiteralSummary(id: UUID(), value: "config", address: 0x3000,
            sourceSection: "__TEXT,__cstring", byteLength: 7),
            StringLiteralSummary(id: UUID(), value: long, address: 0x3100, sourceSection: "__TEXT,__cstring", byteLength: 358)]
        analysis.constantStrings = [0x3100: MacIRConstantString(text: long, kind: .cString),
                                   0x4000: MacIRConstantString(text: "Rich", kind: .cfString)]
        analysis.objcSelectors = selectors ? [0x5000: "isRichText"] : [:]
        analysis.objcClassReferences = [0x5008: ObjCClassReferenceTarget(name: "_OBJC_CLASS_$_NSObject", classAddress: nil)]
        analysis.indirectSymbols = [IndirectSymbolSummary(id: UUID(), kind: "pointer", sourceSection: "__DATA,__got",
            address: 0x6000, entrySize: 8, tableIndex: 0, rawSymbolIndex: 0, symbolIndex: nil, symbolName: "_free",
            libraryOrdinal: nil, libraryName: nil, isLocal: false, isAbsolute: false)]
        analysis.instructions = annotationInstructions()
        if reversed { analysis.instructions.reverse() }
        let pairs: [(UInt64, UInt64, String)] = [(0x1004, 0x3000, "string"), (0x1004, 0x3010, "data"),
            (0x1008, 0x1100, "call"), (0x100c, 0x2000, "call"), (0x1010, 0x1200, "call"), (0x1014, 0x1300, "call"),
            (0x101c, 0x5000, "selref"), (0x1020, 0x5008, "classref"), (0x1024, 0x4000, "data"),
            (0x102c, 0x6000, "data"), (0x1034, 0x3020, "data"), (0x1038, 0x3003, "data"),
            (0x103c, 0x3100, "string"), (0x1040, 0x3000, "call"), (0x1044, 0x1100, "call"), (0x1200, 0x3000, "string")]
        analysis.xrefs = pairs.map { XRef(id: UUID(), from: $0.0, to: $0.1, kind: $0.2) }
        let image = BinaryImage(id: UUID(), name: "annotations", path: "/fixture", kind: "Mach-O executable",
            architecture: "arm64", slot: .primary)
        let store = WorkspaceStore(workspaceName: "annotations", snapshot: WorkspaceSnapshot(binaries: [image],
            analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
            "address": .hex(0x1100), "name": .string("renamedHelper")]))
        return store
    }

    // Literal expected pin fields and annotation decisions, independent of the production helper.
    private func annotationPinRows() -> [[String: ScriptValue]] {
        [
            ["address": .hex(0x1000), "bytes": .string("00 00 00 00"), "mnemonic": .string("adrp"), "operands": .string("x3, 0x3000")],
            ["address": .hex(0x1004), "bytes": .string("00 00 00 00"), "mnemonic": .string("add"), "operands": .string("x3, x3, #0x0")],
            ["address": .hex(0x1008), "bytes": .string("00 00 00 00"), "mnemonic": .string("bl"), "operands": .string("0x1100")],
            ["address": .hex(0x100c), "bytes": .string("00 00 00 00"), "mnemonic": .string("bl"), "operands": .string("0x2000")],
            ["address": .hex(0x1010), "bytes": .string("00 00 00 00"), "mnemonic": .string("bl"), "operands": .string("0x1200")],
            ["address": .hex(0x1014), "bytes": .string("00 00 00 00"), "mnemonic": .string("bl"), "operands": .string("0x1300")],
            ["address": .hex(0x1018), "bytes": .string("00 00 00 00"), "mnemonic": .string("adrp"), "operands": .string("x1, 0x5000")],
            ["address": .hex(0x101c), "bytes": .string("00 00 00 00"), "mnemonic": .string("ldr"), "operands": .string("x1, [x1]")],
            ["address": .hex(0x1020), "bytes": .string("00 00 00 00"), "mnemonic": .string("ldr"), "operands": .string("x2, [x1, #0x8]")],
            ["address": .hex(0x1024), "bytes": .string("00 00 00 00"), "mnemonic": .string("adr"), "operands": .string("x0, 0x4000")],
            ["address": .hex(0x1028), "bytes": .string("00 00 00 00"), "mnemonic": .string("adrp"), "operands": .string("x8, 0x6000")],
            ["address": .hex(0x102c), "bytes": .string("00 00 00 00"), "mnemonic": .string("ldr"), "operands": .string("x8, [x8]")],
            ["address": .hex(0x1030), "bytes": .string("00 00 00 00"), "mnemonic": .string("adrp"), "operands": .string("x9, 0x3000")],
            ["address": .hex(0x1034), "bytes": .string("00 00 00 00"), "mnemonic": .string("add"), "operands": .string("x10, x9, #0x20")],
            ["address": .hex(0x1038), "bytes": .string("00 00 00 00"), "mnemonic": .string("add"), "operands": .string("x11, x9, #0x3")],
            ["address": .hex(0x103c), "bytes": .string("00 00 00 00"), "mnemonic": .string("add"), "operands": .string("x12, x9, #0x100")],
            ["address": .hex(0x1040), "bytes": .string("00 00 00 00"), "mnemonic": .string("ret"), "operands": .string("")],
            ["address": .hex(0x1044), "bytes": .string("00 00 00 00"), "mnemonic": .string("bl"), "operands": .string("renamedHelper")],
        ]
    }

    private func expectedAnnotations(selectors: Bool = true) -> [ScriptValue] {
        let additions: [Int: [String: ScriptValue]] = [
            1: ["to": .hex(0x3000), "kind": .string("string"), "targetKind": .string("cString"), "value": .string("config")],
            2: ["to": .hex(0x1100), "kind": .string("call"), "toName": .string("renamedHelper")],
            3: ["to": .hex(0x2000), "kind": .string("call"), "toName": .string("_objc_msgSend$isRichText"), "selector": .string("isRichText")],
            4: ["to": .hex(0x1200), "kind": .string("call"), "toName": .string("$s3app5ModelV5countSivg"), "toDemangled": .string("app.Model.count.getter : Swift.Int")],
            7: ["to": .hex(0x5000), "kind": .string("selref"), "targetKind": .string("selector"), "value": selectors ? .string("isRichText") : .null],
            8: ["to": .hex(0x5008), "kind": .string("classref"), "targetKind": .string("class"), "value": .string("_OBJC_CLASS_$_NSObject")],
            9: ["to": .hex(0x4000), "kind": .string("data"), "targetKind": .string("cfString"), "value": .string("Rich")],
            11: ["to": .hex(0x6000), "kind": .string("data"), "targetKind": .string("import"), "value": .string("_free")],
            13: ["to": .hex(0x3020), "kind": .string("data"), "targetKind": .string("symbol"), "toName": .string("_gTable")],
            14: ["to": .hex(0x3003), "kind": .string("data"), "targetKind": .string("data")],
            15: ["to": .hex(0x3100), "kind": .string("string"), "targetKind": .string("cString"), "value": .string(String(repeating: "a", count: 255)),
                "valueTruncated": .bool(true), "valueByteLength": .int(357)],
        ]
        return annotationPinRows().enumerated().map { index, base in
            .object(base.merging(additions[index] ?? [:]) { _, added in added })
        }
    }

    func testAnnotationF1CompletingRowAndNamedCallAcrossRoutes() async throws {
        let store = try makeAnnotationStore()
        for route in Route.allCases {
            let result = try await read(route, store, "instructions", .object(["address": .hex(0x1000), "count": .int(3), "annotate": .bool(true)]))
            XCTAssertEqual(result, .array(Array(expectedAnnotations().prefix(3))))
        }
    }

    func testAnnotationF2DataTargetVocabulary() async throws {
        let store = try makeAnnotationStore()
        for route in Route.allCases {
            let result = try await read(route, store, "instructions", .object(["address": .hex(0x1018), "count": .int(9), "annotate": .bool(true)]))
            XCTAssertEqual(result, .array(Array(expectedAnnotations()[6...14])))
        }
    }

    func testAnnotationF3StubSwiftUnnamedAndNonHexCalls() async throws {
        let store = try makeAnnotationStore()
        for route in Route.allCases {
            let result = try await read(route, store, "instructions", .object(["function": .string("_main"), "annotate": .bool(true)]))
            XCTAssertEqual(result, .array(expectedAnnotations()))
            let rows = try XCTUnwrap(result.arrayValue)
            XCTAssertEqual(rows[5], .object(annotationPinRows()[5]))
            XCTAssertEqual(rows[17], .object(annotationPinRows()[17]))
        }
    }

    func testAnnotationF4CallNamesEqualCalleesWithoutVacuousPass() async throws {
        let store = try makeAnnotationStore()
        for route in Route.allCases {
            let instructions = try await read(route, store, "instructions", .object(["function": .string("_main"), "annotate": .bool(true)]))
            let graph = try await read(route, store, "callees", .object(["address": .hex(0x1000)]))
            let calls = try XCTUnwrap(instructions.arrayValue).filter { $0["kind"] == .string("call") }
            XCTAssertEqual(calls.compactMap { $0["address"]?.addressValue }, [0x1008, 0x100c, 0x1010])
            for row in calls {
                let edge = try XCTUnwrap(graph.arrayValue?.first { $0["from"] == row["address"] })
                for key in ["to", "toName", "selector", "toDemangled"] { XCTAssertEqual(row[key], edge[key]) }
            }
        }
    }

    func testAnnotationF5ScalarBoundaryPreviewLength() async throws {
        let store = try makeAnnotationStore()
        for route in Route.allCases {
            let result = try await read(route, store, "instructions", .object(["address": .hex(0x103c), "count": .int(1), "annotate": .bool(true)]))
            XCTAssertEqual(result, .array([expectedAnnotations()[15]]))
            let value = try XCTUnwrap(result.arrayValue?.first?["value"]?.stringValue)
            XCTAssertEqual(value.utf8.count, 255)
            XCTAssertFalse(value.contains("�"))
        }
    }

    func testAnnotationF6ReversedOrderAndFirstSourceReference() async throws {
        let store = try makeAnnotationStore(reversed: true)
        let baseline = ScriptValue.array(annotationPinRows().reversed().map(ScriptValue.object))
        for route in Route.allCases {
            let pin = try await read(route, store, "instructions", .object(["function": .string("_main")]))
            XCTAssertEqual(pin, baseline, "fixture must preserve the reversed analysis order")
            let result = try await read(route, store, "instructions", .object(["function": .string("_main"), "annotate": .bool(true)]))
            XCTAssertEqual(result, .array(Array(expectedAnnotations().reversed())))
        }
    }

    func testAnnotationF7EmptyHelperAndCancellation() throws {
        let snapshot = try makeAnnotationStore().snapshot
        var checkpoints = 0
        let empty = try WorkspaceScriptingAPI.annotatedInstructionObjects([], snapshot: snapshot) {
            checkpoints += 1; throw CancellationError()
        }
        XCTAssertEqual(empty, []); XCTAssertEqual(checkpoints, 0)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.annotatedInstructionObjects(snapshot.instructions, snapshot: snapshot) {
            checkpoints += 1; throw CancellationError()
        }) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(checkpoints, 1)
    }

    func testAnnotationF8MissingSelectorStillHasNullValue() async throws {
        let store = try makeAnnotationStore(selectors: false)
        for route in Route.allCases {
            let result = try await read(route, store, "instructions", .object(["address": .hex(0x101c), "count": .int(1), "annotate": .bool(true)]))
            XCTAssertEqual(result, .array([expectedAnnotations(selectors: false)[7]]))
        }
    }

    func testAnnotationF9StrictBooleanValidationOnEveryRoute() async throws {
        let store = try makeAnnotationStore()
        for value in [ScriptValue.string("yes"), .int(1), .null] {
            let args: ScriptValue = .object(["address": .hex(0x1000), "count": .int(3), "annotate": value])
            for route in Route.allCases {
                if route == .attached {
                    do { _ = try await read(route, store, "instructions", args); XCTFail("expected refusal") }
                    catch { XCTAssertEqual(error as? HeadlessAutomationAuthorityError, .invalidArguments) }
                } else if route == .mcpSync || route == .mcpAsync {
                    let reply = try await envelope(route, WorkspaceScriptingAPI(store: store), "instructions", args)
                    XCTAssertEqual(reply["result"]?["isError"], .bool(true))
                    XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"], .string(ToolArgumentError(
                        field: "annotate", detail: "Field 'annotate' must be a boolean.", expected: "boolean").refusal.text))
                } else {
                    try await refuses(route, store, "instructions", args, .invalidArgument("annotate must be a boolean"))
                }
            }
        }
    }

    func testAnnotationC7DefaultAndFalseAreExactPinRows() async throws {
        let store = try makeAnnotationStore()
        for (args, expected) in [(ScriptValue.object(["address": .hex(0x1000), "count": .int(3)]), Array(annotationPinRows().prefix(3))),
                                 (.object(["function": .string("_main")]), annotationPinRows())] {
            guard case .object(var fields) = args else { return XCTFail("fixture") }
            fields["annotate"] = .bool(false)
            let explicit = ScriptValue.object(fields)
            for route in Route.allCases {
                let absent = try await read(route, store, "instructions", args)
                let disabled = try await read(route, store, "instructions", explicit)
                XCTAssertEqual(absent, .array(expected.map(ScriptValue.object)))
                XCTAssertEqual(try absent.jsonData(), try disabled.jsonData())
                if route == .mcpSync || route == .mcpAsync {
                    let a = try await envelope(route, WorkspaceScriptingAPI(store: store), "instructions", args)
                    let b = try await envelope(route, WorkspaceScriptingAPI(store: store), "instructions", explicit)
                    XCTAssertEqual(a["result"]?["content"]?.arrayValue?.first?["text"], b["result"]?["content"]?.arrayValue?.first?["text"])
                }
            }
        }
    }

    func testAnnotationF10OptInTransportLimitAndDefaultIdentity() async throws {
        let store = try makeAnnotationStore()
        let api = WorkspaceScriptingAPI(store: store)
        let base: ScriptValue = .object(["function": .string("_main")])
        let pin = ScriptValue.array(annotationPinRows().map(ScriptValue.object))
        let pinData = try pin.jsonData()
        let bound = 2 * pinData.count
        XCTAssertGreaterThanOrEqual(bound, 512)
        let pinEnvelope: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
            "result": .object(["content": .array([.object(["type": .string("text"),
                "text": .string(String(decoding: pinData, as: UTF8.self))])]), "isError": .bool(false)])])
        XCTAssertLessThanOrEqual(try pinEnvelope.jsonData().count, bound)
        XCTAssertGreaterThan(try ScriptValue.array(expectedAnnotations()).jsonData().count, pinData.count)
        let configuration = MCPServer.Configuration(maximumInputBytes: 65_536, maximumOutputBytes: bound,
            maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 16)
        let annotatedData = try ScriptValue.array(expectedAnnotations()).jsonData()
        let refusal: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1),
            "error": .object([
                "code": .int(-32603), "message": .string("Response exceeds limit"),
                "data": .object([
                    "error": .string("refused"),
                    "refusal": .object([
                        "code": .string("budgetExceeded"),
                        "detail": .string("Output limit exceeded."), "retryable": .bool(false),
                        "budget": .object(["unit": .string("bytes"), "limit": .int(Int64(pinData.count))]),
                        "used": .int(Int64(annotatedData.count)), "narrowing": .array([])
                    ])
                ])
            ])])
        for asynchronous in [false, true] {
            var texts: [ScriptValue?] = []
            let choices: [ScriptValue?] = [nil, .bool(false), .bool(true)]
            for optIn in choices {
                guard case .object(var fields) = base else { return XCTFail("fixture") }
                if let optIn { fields["annotate"] = optIn }
                let server = MCPServer(api: api, configuration: configuration)
                let data = try request("instructions", .object(fields)).jsonData()
                let response: Data?
                if asynchronous { response = await server.handleMessageAsync(data) }
                else { response = server.handleMessage(data) }
                let decoded = try ScriptValue.decode(try XCTUnwrap(response))
                if optIn == .bool(true) { XCTAssertEqual(decoded, refusal) }
                else {
                    XCTAssertNil(decoded["error"])
                    XCTAssertEqual(decoded["result"]?["isError"], .bool(false))
                    let text = decoded["result"]?["content"]?.arrayValue?.first?["text"]
                    XCTAssertEqual(text, .string(String(decoding: pinData, as: UTF8.self)))
                    texts.append(text)
                }
            }
            XCTAssertEqual(texts.count, 2); XCTAssertEqual(texts[0], texts[1])
        }
    }

    func testAnnotationF11StrictCountZeroAndUnchangedSelectionBudget() throws {
        let snapshot = try makeAnnotationStore().snapshot
        let invalid: ScriptValue = .object(["address": .hex(0x1000), "count": .int(0), "annotate": .null])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("instructions", arguments: invalid, snapshot: snapshot)) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument("annotate must be a boolean"))
        }
        var oldCheckpoints = 0
        var newCheckpoints = 0
        let expected = ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "instruction selection exceeds the snapshot work budget",
            budget: .init(unit: .workSteps, limit: 1), used: 2, narrowing: []))
        for annotate in [false, true] {
            let args: ScriptValue = .object(["address": .hex(0x1044), "count": .int(1), "annotate": .bool(annotate)])
            XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("instructions", arguments: args,
                snapshot: snapshot, scope: .attached, selectionWorkLimit: 1, checkpoint: {
                    if annotate { newCheckpoints += 1 } else { oldCheckpoints += 1 }
                })) { XCTAssertEqual($0 as? ScriptingError, expected) }
        }
        XCTAssertEqual(newCheckpoints, oldCheckpoints)
        let zero = try WorkspaceScriptingAPI.snapshotListRead("instructions", arguments: .object([
            "address": .hex(0x1000), "count": .int(0), "annotate": .bool(true)]), snapshot: snapshot)
        XCTAssertEqual(zero, .array([]))
    }

    func testAnnotationF12PrecedenceCommentsAndFullScalarBoundary() throws {
        let store = try makeAnnotationStore()
        _ = try WorkspaceScriptingAPI(store: store).execute("set-comment", arguments: .object([
            "address": .hex(0x1004), "comment": .string("authored comment")]))
        _ = try WorkspaceScriptingAPI(store: store).execute("suppress-xref", arguments: .object([
            "from": .hex(0x1004), "to": .hex(0x3000), "kind": .string("string")]))
        _ = try WorkspaceScriptingAPI(store: store).execute("add-xref", arguments: .object([
            "from": .hex(0x1000), "to": .hex(0x4000), "kind": .string("data")]))
        var snapshot = store.snapshot
        snapshot.constantStrings[0x3000] = MacIRConstantString(text: "stored", kind: .cString)
        snapshot.symbols.append(SymbolSummary(id: UUID(), name: "_pointerName", address: 0x6000, kind: "data", libraryName: nil))
        var later = try XCTUnwrap(snapshot.indirectSymbols.first)
        later.symbolName = "wrongLaterImport"
        snapshot.indirectSymbols.append(later)
        let rows = [snapshot.instructions[0], snapshot.instructions[1], snapshot.instructions[11]]
        let result = try WorkspaceScriptingAPI.annotatedInstructionObjects(rows, snapshot: snapshot, checkpoint: {})
        var added = annotationPinRows()[0]
        added.merge(["to": .hex(0x4000), "kind": .string("data"),
            "targetKind": .string("cfString"), "value": .string("Rich")]) { _, new in new }
        var first = annotationPinRows()[1]
        first.merge(["comment": .string("authored comment"), "to": .hex(0x3010), "kind": .string("data"),
            "targetKind": .string("data")]) { _, new in new }
        var second = annotationPinRows()[11]
        second.merge(["to": .hex(0x6000), "kind": .string("data"), "targetKind": .string("import"),
            "value": .string("_free"), "toName": .string("_pointerName")]) { _, new in new }
        XCTAssertEqual(result, [.object(added), .object(first), .object(second)])
        for (text, expected, fullLength) in [
            (String(repeating: "a", count: 256), String(repeating: "a", count: 256), 256),
            (String(repeating: "a", count: 252) + "😀x", String(repeating: "a", count: 252) + "😀", 257)
        ] {
            snapshot.constantStrings[0x3100] = MacIRConstantString(text: text, kind: .cString)
            let output = try WorkspaceScriptingAPI.annotatedInstructionObjects([snapshot.instructions[15]], snapshot: snapshot, checkpoint: {})
            XCTAssertEqual(output.first?["value"], .string(expected))
            XCTAssertEqual(output.first?["valueTruncated"], fullLength > 256 ? .bool(true) : nil)
            XCTAssertEqual(output.first?["valueByteLength"], fullLength > 256 ? .int(Int64(fullLength)) : nil)
        }
    }

    func testAnnotationF13CallRowsNeverUseDataXRefsAndOnlySelectedSourcesApply() throws {
        var snapshot = try makeAnnotationStore().snapshot
        snapshot.xrefs.insert(XRef(id: UUID(), from: 0x1044, to: 0x3000, kind: "string"), at: 0)
        snapshot.xrefs.insert(XRef(id: UUID(), from: 0x1014, to: 0x3000, kind: "string"), at: 0)
        let rows = [snapshot.instructions[17], snapshot.instructions[5], snapshot.instructions[1]]
        let result = try WorkspaceScriptingAPI.annotatedInstructionObjects(rows, snapshot: snapshot, checkpoint: {})
        XCTAssertEqual(result, [.object(annotationPinRows()[17]), .object(annotationPinRows()[5]), expectedAnnotations()[1]])
    }

    func testAnnotationIndirectBranchesRejectSameSourceDataAcrossRoutes() async throws {
        let spellings: [(String, String)] = [
            ("blr", "x3"), ("BLR", "x3"),
            ("blraa", "x3, x4"), ("blrab", "x3, x4"),
            ("blraaz", "x3"), ("blrabz", "x3"),
            ("br", "x3"), ("braa", "x3, x4"), ("brab", "x3, x4"),
            ("braaz", "x3"), ("brabz", "x3"),
        ]
        let indirectRows = spellings.enumerated().map { index, entry in
            InstructionRow(address: 0x1050 + UInt64(index) * 4, bytes: "00 00 00 00",
                mnemonic: entry.0, operands: entry.1, hasBreakpoint: false, comment: "indirect row")
        }
        let indirectPins = indirectRows.map { row in
            ScriptValue.object(["address": .hex(row.address), "bytes": .string("00 00 00 00"),
                "mnemonic": .string(row.mnemonic), "operands": .string(row.operands),
                "comment": .string("indirect row")])
        }
        let pin = ScriptValue.array([.object(annotationPinRows()[0]), .object(annotationPinRows()[1]),
            .object(annotationPinRows()[3])] + indirectPins)
        let annotated = ScriptValue.array([.object(annotationPinRows()[0]), expectedAnnotations()[1],
            expectedAnnotations()[3]] + indirectPins)
        for manual in [false, true] {
            var snapshot = try makeAnnotationStore().snapshot
            snapshot.instructions = [snapshot.instructions[0], snapshot.instructions[1], snapshot.instructions[3]] + indirectRows
            if !manual {
                for row in indirectRows {
                    // A named data target and a string are eligible, but neither is this branch's target.
                    snapshot.xrefs.append(XRef(id: UUID(), from: row.address, to: 0x3020, kind: "data"))
                    snapshot.xrefs.append(XRef(id: UUID(), from: row.address, to: 0x3000, kind: "string"))
                }
            }
            let store = WorkspaceStore(workspaceName: "indirect annotations", snapshot: snapshot,
                engine: AnalysisEngine(), autosaveScheduler: nil)
            let api = WorkspaceScriptingAPI(store: store)
            if manual {
                for row in indirectRows {
                    for (target, kind) in [(UInt64(0x3020), "data"), (UInt64(0x3000), "string")] {
                        _ = try api.execute("add-xref", arguments: .object([
                            "from": .hex(row.address), "to": .hex(target), "kind": .string(kind)]))
                    }
                }
            }
            let base: ScriptValue = .object(["address": .hex(0x1000), "count": .int(Int64(3 + indirectRows.count))])
            let enabled: ScriptValue = .object(["address": .hex(0x1000), "count": .int(Int64(3 + indirectRows.count)),
                "annotate": .bool(true)])
            let disabled: ScriptValue = .object(["address": .hex(0x1000), "count": .int(Int64(3 + indirectRows.count)),
                "annotate": .bool(false)])
            for route in Route.allCases {
                let actual = try await read(route, store, "instructions", enabled)
                XCTAssertEqual(actual, annotated, "manual=\(manual), route=\(route)")
                let absent = try await read(route, store, "instructions", base)
                let off = try await read(route, store, "instructions", disabled)
                XCTAssertEqual(absent, pin)
                XCTAssertEqual(try absent.jsonData(), try off.jsonData())
            }
            // Exercise headless authority with a CLI principal; frontend routing is reviewed separately.
            let headless = try HeadlessAutomationAuthority.execute(command: "instructions", arguments: enabled,
                api: api, proposingPrincipal: .cli)
            XCTAssertEqual(headless, annotated)
        }
    }

    func testAnnotationF14AdditionalCallSpellingsAndMetadataLiteral() throws {
        var snapshot = try makeAnnotationStore().snapshot
        let callRows = [InstructionRow(address: 0x1050, bytes: "x", mnemonic: "CALLQ", operands: "0X1100",
                hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1054, bytes: "y", mnemonic: "call", operands: "#0x1100", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1058, bytes: "z", mnemonic: "bl", operands: "x0, 0x1100", hasBreakpoint: false, comment: nil)]
        let result = try WorkspaceScriptingAPI.annotatedInstructionObjects(callRows, snapshot: snapshot, checkpoint: {})
        for (index, row) in callRows.enumerated() {
            XCTAssertEqual(result[index], .object(["address": .hex(row.address), "bytes": .string(row.bytes),
                "mnemonic": .string(row.mnemonic), "operands": .string(row.operands), "to": .hex(0x1100),
                "kind": .string("call"), "toName": .string("renamedHelper")]))
        }
        snapshot.stringLiterals.append(StringLiteralSummary(id: UUID(), value: "metadata:", address: 0x7000,
            sourceSection: "__TEXT,__objc_methname", byteLength: 10))
        snapshot.xrefs.append(XRef(id: UUID(), from: 0x1060, to: 0x7000, kind: "string"))
        let load = InstructionRow(address: 0x1060, bytes: "a", mnemonic: "adr", operands: "x0, 0x7000", hasBreakpoint: false, comment: nil)
        let data = try WorkspaceScriptingAPI.annotatedInstructionObjects([load], snapshot: snapshot, checkpoint: {})
        XCTAssertEqual(data, [.object(["address": .hex(0x1060), "bytes": .string("a"), "mnemonic": .string("adr"),
            "operands": .string("x0, 0x7000"), "to": .hex(0x7000), "kind": .string("string"),
            "targetKind": .string("cString"), "value": .string("metadata:")])])
    }

    func testAnnotationF15EveryNewLongPassCheckpoints() throws {
        let base = try makeAnnotationStore().snapshot
        let row = try XCTUnwrap(base.instructions.first { $0.address == 0x1004 })
        func count(_ snapshot: WorkspaceSnapshot, rows: [InstructionRow]) throws -> Int {
            // Build only this synthetic fixture's index before counting the annotation passes.
            _ = try snapshot.xrefCandidates(.from, lower: 0x1004, upperInclusive: 0x1004, in: snapshot.primarySlot, checkpoint: {})
            var count = 0
            _ = try WorkspaceScriptingAPI.annotatedInstructionObjects(rows, snapshot: snapshot) { count += 1 }
            return count
        }
        let baseline = try count(base, rows: [row])
        var literals = base
        literals.stringLiterals += (0..<256).map { StringLiteralSummary(id: UUID(), value: "unused", address: 0x8000 + UInt64($0),
            sourceSection: "__cstring", byteLength: 7) }
        // 622b44847, S1: bound xref selection and prepare indexes by generation,
        // adds cooperative selection passes. Require each long pass's checkpoint
        // growth without forbidding additional checkpoints in other passes.
        XCTAssertGreaterThanOrEqual(try count(literals, rows: [row]), baseline + 1)
        var imports = base
        imports.indirectSymbols += Array(repeating: try XCTUnwrap(base.indirectSymbols.first), count: 256)
        XCTAssertGreaterThanOrEqual(try count(imports, rows: [row]), baseline + 1)
        var refs = base
        refs.xrefs += (0..<256).map { _ in XRef(id: UUID(), from: 0x1004, to: 0x3000, kind: "string") }
        // Candidate materialization and annotation enumeration must both checkpoint.
        XCTAssertGreaterThanOrEqual(try count(refs, rows: [row]), baseline + 2)
        // Both instruction-object construction and annotation application are long passes.
        XCTAssertGreaterThanOrEqual(try count(base, rows: Array(repeating: row, count: 257)), baseline + 2)
    }

    func testSharedDataDescriptionsAndNoEqualTextLinkAcrossRoutes() async throws {
        var snapshot = try makeAnnotationStore().snapshot
        // Dot 1259 / M3-F2: equal text never links a C string to a CFString object, even
        // with a complete inventory (a unique equal-text pair is supplied below).
        snapshot.mutateAnalysis(in: snapshot.primarySlot) { $0.stringLiteralCoverage = .complete }
        snapshot.constantStrings[0x3000] = MacIRConstantString(text: "Rich", kind: .cString)
        let store = WorkspaceStore(workspaceName: "shared descriptions", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        var expected = expectedAnnotations()
        var literal = annotationPinRows()[1]
        literal.merge(["to": .hex(0x3000), "kind": .string("string"),
            "targetKind": .string("cString"), "value": .string("Rich")]) { _, new in new }
        expected[1] = .object(literal)
        for route in Route.allCases {
            let instructions = try await read(route, store, "instructions", .object([
                "function": .string("_main"), "annotate": .bool(true)]))
            XCTAssertEqual(instructions, .array(expected))
            let row = try XCTUnwrap(instructions.arrayValue?[9])
            XCTAssertNil(row["cString"])
            // Annotate stays opt-in with an unchanged row format: no storage field.
            // (InstructionAnnotations.swift passes includeCFStringStorage: false.)
            XCTAssertNil(row["cfStringStorage"])
            let references = try await read(route, store, "function-references", .object([
                "address": .hex(0x1000)]))
            let referenceRows = try XCTUnwrap(references["references"]?.arrayValue)
            for index in [1, 7, 8, 9, 11, 13, 14] {
                let instruction = try XCTUnwrap(instructions.arrayValue?[index])
                let address = try XCTUnwrap(instruction["address"])
                let matched = try XCTUnwrap(referenceRows.first { $0["from"] == address })
                XCTAssertEqual(matched["to"], instruction["to"])
                XCTAssertEqual(matched["kind"], instruction["kind"])
                XCTAssertEqual(matched["targetKind"], instruction["targetKind"])
                XCTAssertEqual(matched["value"], instruction["value"])
                XCTAssertNil(instruction["cString"])
                XCTAssertNil(instruction["cfStringStorage"])
            }
            let reference = try XCTUnwrap(referenceRows.first { $0["from"] == .hex(0x1024) })
            XCTAssertEqual(reference["to"], .hex(0x4000))
            XCTAssertEqual(reference["kind"], .string("data"))
            XCTAssertEqual(reference["targetKind"], row["targetKind"])
            XCTAssertEqual(reference["value"], row["value"])
            // DataReferences.swift describe: a cfString row carries the unavailable
            // storage notice and no cString link, even for a unique equal-text pair.
            XCTAssertNil(reference["cString"])
            XCTAssertEqual(reference["cfStringStorage"], .object([
                "status": .string("unavailable"), "reason": .string("backingAddressNotRetained")]))
        }
    }

    func testSharedDescriptionDuplicatesPrecedenceAndMissingValues() throws {
        let store = try makeAnnotationStore()
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
            "address": .hex(0x6000), "name": .string("renamedImport")]))
        var snapshot = store.snapshot
        snapshot.stringLiterals.append(StringLiteralSummary(id: UUID(), value: "last", address: 0x3000,
            sourceSection: "__cstring", byteLength: 5))
        var empty = try XCTUnwrap(snapshot.indirectSymbols.first)
        empty.symbolName = ""
        var missing = empty
        missing.symbolName = nil
        var later = empty
        later.symbolName = "later"
        snapshot.indirectSymbols = [missing, empty] + snapshot.indirectSymbols + [later]
        let rows = [snapshot.instructions[1], snapshot.instructions[11]]
        var result = try WorkspaceScriptingAPI.annotatedInstructionObjects(rows, snapshot: snapshot, checkpoint: {})
        var literal = annotationPinRows()[1]
        literal.merge(["to": .hex(0x3000), "kind": .string("string"),
            "targetKind": .string("cString"), "value": .string("last")]) { _, new in new }
        var imported = annotationPinRows()[11]
        imported.merge(["to": .hex(0x6000), "kind": .string("data"),
            "targetKind": .string("import"), "value": .string("renamedImport")]) { _, new in new }
        XCTAssertEqual(result, [.object(literal), .object(imported)])
        var originalNames = snapshot
        originalNames.addressOverrides.removeValue(forKey: ImageAddress(slot: snapshot.primarySlot, address: 0x6000))
        let unrenamed = try WorkspaceScriptingAPI.annotatedInstructionObjects([snapshot.instructions[11]],
            snapshot: originalNames, checkpoint: {})
        imported["value"] = .string("_free")
        XCTAssertEqual(unrenamed, [.object(imported)])

        var competingImport = later
        competingImport.address = 0x3000
        snapshot.indirectSymbols.append(competingImport)
        snapshot.constantStrings[0x3000] = MacIRConstantString(text: "", kind: .cfString)
        snapshot.xrefs[0] = XRef(id: UUID(), from: 0x1004, to: 0x3000, kind: XRefKind.selref)
        result = try WorkspaceScriptingAPI.annotatedInstructionObjects([snapshot.instructions[1]], snapshot: snapshot, checkpoint: {})
        literal.merge(["kind": .string("selref"), "targetKind": .string("cfString"), "value": .string("")]) { _, new in new }
        XCTAssertEqual(result, [.object(literal)])
        snapshot.constantStrings[0x3000] = MacIRConstantString(text: "c", kind: .cString)
        snapshot.xrefs[0] = XRef(id: UUID(), from: 0x1004, to: 0x3000, kind: XRefKind.classref)
        result = try WorkspaceScriptingAPI.annotatedInstructionObjects([snapshot.instructions[1]], snapshot: snapshot, checkpoint: {})
        literal.merge(["kind": .string("classref"), "targetKind": .string("cString"), "value": .string("c")]) { _, new in new }
        XCTAssertEqual(result, [.object(literal)])
        let slot = snapshot.primarySlot
        snapshot.mutateAnalysis(in: slot) { $0.objcClassReferences = [:] }
        result = try WorkspaceScriptingAPI.annotatedInstructionObjects([snapshot.instructions[8]], snapshot: snapshot, checkpoint: {})
        var missingClass = annotationPinRows()[8]
        missingClass.merge(["to": .hex(0x5008), "kind": .string("classref"),
            "targetKind": .string("class"), "value": .null]) { _, new in new }
        XCTAssertEqual(result, [.object(missingClass)])
    }

    func testSharedPreviewExactFieldsAndBoundaries() throws {
        var snapshot = try makeAnnotationStore().snapshot
        let inputs: [(String, String, Int)] = [
            ("", "", 0),
            ("short", "short", 5),
            (String(repeating: "a", count: 256), String(repeating: "a", count: 256), 256),
            (String(repeating: "a", count: 252) + "😀x", String(repeating: "a", count: 252) + "😀", 257),
            (String(repeating: "a", count: 255) + "é" + String(repeating: "b", count: 100),
             String(repeating: "a", count: 255), 357)
        ]
        for (text, expected, byteCount) in inputs {
            snapshot.constantStrings[0x3100] = MacIRConstantString(text: text, kind: .cString)
            var fields = annotationPinRows()[15]
            fields.merge(["to": .hex(0x3100), "kind": .string("string"),
                "targetKind": .string("cString"), "value": .string(expected)]) { _, new in new }
            if byteCount > 256 {
                fields["valueTruncated"] = .bool(true)
                fields["valueByteLength"] = .int(Int64(byteCount))
            }
            let result = try WorkspaceScriptingAPI.annotatedInstructionObjects(
                [snapshot.instructions[15]], snapshot: snapshot, checkpoint: {})
            XCTAssertEqual(result, [.object(fields)])
        }
    }

    func testInstructionPrimarySlotIsolation() async throws {
        let base = try makeAnnotationStore().snapshot
        let primary = try XCTUnwrap(base.analysis(in: base.primarySlot))
        var other = primary
        other.stringLiterals[0] = StringLiteralSummary(id: UUID(), value: "sibling", address: 0x3000,
            sourceSection: "__cstring", byteLength: 8)
        let first = BinaryImage(id: UUID(), name: "first", path: "/first", kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        let second = BinaryImage(id: UUID(), name: "second", path: "/second", kind: "Mach-O executable", architecture: "arm64", slot: sibling)
        for (images, value) in [([first, second], "config"), ([second, first], "sibling")] {
            let view = WorkspaceSnapshot(binaries: images, analysisBySlot: [.primary: primary, sibling: other])
            let store = WorkspaceStore(workspaceName: "slots", snapshot: view, engine: AnalysisEngine(), autosaveScheduler: nil)
            for route in Route.allCases {
                let result = try await read(route, store, "instructions", .object([
                    "address": .hex(0x1004), "count": .int(1), "annotate": .bool(true)]))
                var row = annotationPinRows()[1]
                row.merge(["to": .hex(0x3000), "kind": .string("string"),
                    "targetKind": .string("cString"), "value": .string(value)]) { _, new in new }
                XCTAssertEqual(result, .array([.object(row)]))
            }
        }
        let view = WorkspaceSnapshot(binaries: [first, second], analysisBySlot: [.primary: primary, sibling: other])
        let projected = WorkspaceScriptingAPI.imageProjection(of: view, in: sibling)
        XCTAssertEqual(projected.primarySlot, sibling)
        let projectionResult = try WorkspaceScriptingAPI.snapshotListRead("instructions", arguments: .object([
            "address": .hex(0x1004), "count": .int(1), "annotate": .bool(true)]), snapshot: projected)
        var projectedRow = annotationPinRows()[1]
        projectedRow.merge(["to": .hex(0x3000), "kind": .string("string"),
            "targetKind": .string("cString"), "value": .string("sibling")]) { _, new in new }
        XCTAssertEqual(projectionResult, .array([.object(projectedRow)]))
    }

    func testInstructionStorageNoticeGateAndNoEqualityScan() throws {
        var snapshot = try makeAnnotationStore().snapshot
        // Dot 1259 / M3-F2: even a complete inventory with a unique equal-text pair
        // yields no inferred link and no equality-scan checkpoints.
        snapshot.mutateAnalysis(in: snapshot.primarySlot) { $0.stringLiteralCoverage = .complete }
        snapshot.constantStrings = [0x4000: MacIRConstantString(text: "pair", kind: .cfString),
                                    0x3000: MacIRConstantString(text: "pair", kind: .cString)]
        for i in 0..<255 {
            snapshot.constantStrings[0x8000 + UInt64(i)] = MacIRConstantString(text: "other\(i)", kind: .cString)
        }
        let ref = XRef(id: UUID(), from: 0x1024, to: 0x4000, kind: "data")
        var gatedOffCount = 0
        let gatedOff = try DataTargetDescriber(snapshot: snapshot, slot: snapshot.primarySlot,
            targets: [0x4000], includeCFStringStorage: false, checkpoint: { gatedOffCount += 1 })
        var defaultCount = 0
        let gatedOn = try DataTargetDescriber(snapshot: snapshot, slot: snapshot.primarySlot,
            targets: [0x4000], checkpoint: { defaultCount += 1 })
        // DataReferences.swift init: the literal pass, the indirect-symbol pass and the final
        // checkpoint are independent of the gate and of constant-map size.
        XCTAssertEqual(defaultCount, gatedOffCount)
        // DataReferences.swift describe: the annotate gate keeps the legacy two-field row.
        XCTAssertEqual(gatedOff.describe(ref, named: false), ["targetKind": .string("cfString"), "value": .string("pair")])
        XCTAssertEqual(gatedOn.describe(ref, named: false), ["targetKind": .string("cfString"),
            "value": .string("pair"), "cfStringStorage": .object([
                "status": .string("unavailable"), "reason": .string("backingAddressNotRetained")])])

        func count(_ snapshot: WorkspaceSnapshot, _ rows: [InstructionRow]) throws -> Int {
            guard let first = rows.first else {
                var calls = 0
                let result = try WorkspaceScriptingAPI.annotatedInstructionObjects([], snapshot: snapshot) { calls += 1 }
                XCTAssertEqual(result, [])
                return calls
            }
            _ = try snapshot.xrefCandidates(.from, lower: first.address, upperInclusive: first.address,
                in: snapshot.primarySlot, checkpoint: {})
            var calls = 0
            _ = try WorkspaceScriptingAPI.annotatedInstructionObjects(rows, snapshot: snapshot) { calls += 1 }
            return calls
        }
        var larger = snapshot
        for i in 0..<256 {
            larger.constantStrings[0x9000 + UInt64(i)] = MacIRConstantString(text: "extra\(i)", kind: .cString)
        }
        let literal = try XCTUnwrap(larger.stringLiterals.first)
        let indirect = try XCTUnwrap(larger.indirectSymbols.first)
        larger.stringLiterals += Array(repeating: literal, count: 256)
        larger.indirectSymbols += Array(repeating: indirect, count: 256)
        XCTAssertEqual(try count(snapshot, []), 0)
        XCTAssertEqual(try count(larger, []), 0)
        let call = [snapshot.instructions[2]]
        XCTAssertEqual(try count(snapshot, call), try count(larger, call))
        var moreConstants = snapshot
        moreConstants.constantStrings = larger.constantStrings
        let cf = [snapshot.instructions[9]]
        XCTAssertEqual(try count(snapshot, cf), try count(moreConstants, cf))
    }

    func testSharedDescriptionsPropagateCancellation() throws {
        var snapshot = try makeAnnotationStore().snapshot
        for stop in [1, 2] {
            var count = 0
            var result: DataTargetDescriber?
            XCTAssertThrowsError(try { result = try DataTargetDescriber(snapshot: snapshot, slot: snapshot.primarySlot,
                targets: [0x3000], includeCFStringStorage: false, checkpoint: {
                    count += 1
                    if count == stop { throw CancellationError() }
                }) }()) { XCTAssertTrue($0 is CancellationError) }
            XCTAssertNil(result)
            XCTAssertEqual(count, stop)
        }
        let sourceRow = snapshot.instructions[1]
        var noMetadata = snapshot
        noMetadata.stringLiterals = []
        noMetadata.indirectSymbols = []
        _ = try noMetadata.xrefCandidates(.from, lower: sourceRow.address, upperInclusive: sourceRow.address,
            in: noMetadata.primarySlot, checkpoint: {})
        var noMetadataCount = 0
        _ = try WorkspaceScriptingAPI.annotatedInstructionObjects([sourceRow], snapshot: noMetadata) { noMetadataCount += 1 }
        for stop in [noMetadataCount, noMetadataCount + 1] {
            var count = 0
            var output: [ScriptValue]?
            XCTAssertThrowsError(try { output = try WorkspaceScriptingAPI.annotatedInstructionObjects([sourceRow], snapshot: snapshot) {
                count += 1
                if count == stop { throw CancellationError() }
            } }()) { XCTAssertTrue($0 is CancellationError) }
            XCTAssertNil(output)
            XCTAssertEqual(count, stop)
        }
        let row = snapshot.instructions[15]
        snapshot.constantStrings[0x3100] = MacIRConstantString(text: "short", kind: .cString)
        _ = try snapshot.xrefCandidates(.from, lower: row.address, upperInclusive: row.address,
            in: snapshot.primarySlot, checkpoint: {})
        var shortCount = 0
        _ = try WorkspaceScriptingAPI.annotatedInstructionObjects([row], snapshot: snapshot) { shortCount += 1 }
        snapshot.constantStrings[0x3100] = MacIRConstantString(text: String(repeating: "a", count: 257), kind: .cString)
        var longCount = 0
        var output: [ScriptValue]?
        XCTAssertThrowsError(try { output = try WorkspaceScriptingAPI.annotatedInstructionObjects([row], snapshot: snapshot) {
            longCount += 1
            if longCount == shortCount + 1 { throw CancellationError() }
        } }()) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertNil(output)
        XCTAssertEqual(longCount, shortCount + 1)
    }

    func testAnnotationF16SchemaAndSelectionCap() throws {
        let command = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "instructions" })
        XCTAssertTrue(command.arguments.contains("annotate"))
        XCTAssertTrue(command.summary.contains("`annotate` defaults to false"))
        XCTAssertEqual(HeadlessAutomationAuthority.inputSchema(for: command)["properties"]?["annotate"],
            .object(["type": .string("boolean"), "description": .string("Set true to add call-target names and data-target previews to rows; default false.")]))
        var snapshot = try makeAnnotationStore().snapshot
        snapshot.instructions = (0..<2_001).map { InstructionRow(address: 0x1000 + UInt64($0 * 4), bytes: "1f 20 03 d5",
            mnemonic: "nop", operands: "", hasBreakpoint: false, comment: nil) }
        snapshot.xrefs = []
        let args: ScriptValue = .object(["address": .hex(0x1000), "count": .int(2_001), "annotate": .bool(true)])
        let result = try WorkspaceScriptingAPI.snapshotListRead("instructions", arguments: args, snapshot: snapshot, scope: .attached)
        XCTAssertEqual(result.arrayValue?.count, 2_000)
        XCTAssertEqual(result.arrayValue?.last?["address"], .hex(0x1000 + 1_999 * 4))
    }

}
