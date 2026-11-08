import Foundation
import XCTest
@testable import MacScope

@MainActor
final class FunctionReferencesTests: XCTestCase {
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

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func edge(_ from: UInt64, _ to: UInt64, _ kind: String) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }

    private func makeStore(renamed: Bool = true,
                           change: (inout ImageAnalysis) -> Void = { _ in }) throws -> WorkspaceStore {
        func section(_ name: String, _ address: UInt64, _ size: UInt64, _ executable: Bool = false) -> SectionSummary {
            SectionSummary(id: UUID(), name: name, address: address, size: size, fileOffset: 0, isExecutable: executable)
        }
        let sections = [section("__TEXT,__text", 0x1000, 0x100, true),
            section("__TEXT,__cstring", 0x3000, 0x100), section("__DATA_CONST,__cfstring", 0x4000, 0x80),
            section("__DATA_CONST,__got", 0x5000, 0x10), section("__DATA,__data", 0x6000, 0x20),
            section("__DATA,__objc_selrefs", 0x7000, 8), section("__DATA,__objc_classrefs", 0x7100, 8)]
        var primary = ImageAnalysis()
        primary.stringLiteralCoverage = .complete
        primary.functions = [function("_open", 0x1000, 0x1040), function("helper", 0x1040, 0x1050),
                             function("zero", 0x1060, 0x1060)]
        primary.sections = sections
        let literals: [(UInt64, String)] = [(0x3000, "AppleSMC"), (0x3010, "txt"), (0x3020, "dup"),
            (0x3030, "dup"), (0x3040, "config"), (0x3048, "config.ghostty"), (0x3058, "pair")]
        primary.stringLiterals = literals.map { StringLiteralSummary(id: UUID(), value: $0.1,
            address: $0.0, sourceSection: "__TEXT,__cstring", byteLength: $0.1.utf8.count + 1) }
        primary.constantStrings = ImageConstantStringProvider.build(stringLiterals: primary.stringLiterals,
            cfStrings: [0x4000: "txt", 0x4020: "dup", 0x4040: "pair", 0x4060: "pair"])
        primary.indirectSymbols = [IndirectSymbolSummary(id: UUID(), kind: "pointer",
            sourceSection: "__DATA_CONST,__got", address: 0x5000, entrySize: 8, tableIndex: 0,
            rawSymbolIndex: 0, symbolIndex: nil, symbolName: "_UTTypePlainText",
            libraryOrdinal: nil, libraryName: nil, isLocal: false, isAbsolute: false)]
        primary.symbols = [SymbolSummary(id: UUID(), name: "_gConnection", address: 0x6000, kind: "data", libraryName: nil)]
        primary.objcSelectors = [0x7000: "isRichText"]
        primary.objcClassReferences = [0x7100: ObjCClassReferenceTarget(name: "NSString", classAddress: nil)]
        let pairs: [(UInt64, UInt64, String)] = [
            (0x1004, 0x3000, "string"), (0x1004, 0x3000, "string"), (0x1008, 0x4000, "data"),
            (0x100c, 0x4020, "data"), (0x1010, 0x5000, "data"), (0x1014, 0x6000, "data"),
            (0x1018, 0x6010, "data"), (0x101c, 0x7000, "selref"), (0x1020, 0x7100, "classref"),
            (0x1024, 0x1040, "call"), (0x1028, 0x3010, "string"), (0x1044, 0x3040, "string"),
            (0x1048, 0x3048, "string"), (0x104c, 0x4040, "data"), (0x1060, 0x3040, "string"),
            (0x1080, 0x4060, "data")]
        primary.xrefs = pairs.map { edge($0.0, $0.1, $0.2) }
        change(&primary)
        var other = ImageAnalysis()
        other.functions = [function("sib_fn", 0x1000, 0x1040)]
        other.sections = sections
        other.stringLiterals = [StringLiteralSummary(id: UUID(), value: "sibling", address: 0x3000,
            sourceSection: "__TEXT,__cstring", byteLength: 8)]
        other.constantStrings = ImageConstantStringProvider.build(stringLiterals: other.stringLiterals, cfStrings: [:])
        other.xrefs = [edge(0x1004, 0x3000, "string"), edge(0x1044, 0x4000, "data")]
        let images = [ImageSlot.primary, sibling].map { slot in
            BinaryImage(id: UUID(), name: "references-\(slot.rawValue)", path: "/fixture",
                kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        let store = WorkspaceStore(workspaceName: "data references", snapshot: WorkspaceSnapshot(
            binaries: images, analysisBySlot: [.primary: primary, sibling: other]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        if renamed {
            _ = try WorkspaceScriptingAPI(store: store).execute("rename",
                arguments: .object(["address": .hex(0x1000), "name": .string("smcOpen")]))
        }
        return store
    }

    // Expected fields are independent of the production describer and row namer.
    private var storageUnavailable: ScriptValue {
        .object(["status": .string("unavailable"), "reason": .string("backingAddressNotRetained")])
    }

    private func row(_ from: UInt64, _ to: UInt64, _ kind: String,
                     target: String? = nil, owner: UInt64? = 0x1000, name: String? = "smcOpen",
                     slot: Int = 0, targetKind: String? = nil, value: ScriptValue? = nil,
                     storageNotice: Bool = false) -> ScriptValue {
        var fields: [String: ScriptValue] = ["from": .hex(from), "to": .hex(to), "kind": .string(kind),
            "imageSlot": .int(Int64(slot)), "toName": target.map(ScriptValue.string) ?? .null,
            "fromFunction": owner.map(ScriptValue.hex) ?? .null,
            "fromFunctionName": name.map(ScriptValue.string) ?? .null]
        if let targetKind { fields["targetKind"] = .string(targetKind) }
        if let value { fields["value"] = value }
        if storageNotice || targetKind == "cfString" {
            fields["cfStringStorage"] = storageUnavailable
        }
        return .object(fields)
    }

    private func openRows() -> [ScriptValue] {
        [row(0x1004, 0x3000, "string", targetKind: "cString", value: .string("AppleSMC")),
         row(0x1008, 0x4000, "data", targetKind: "cfString", value: .string("txt")),
         row(0x100c, 0x4020, "data", targetKind: "cfString", value: .string("dup")),
         row(0x1010, 0x5000, "data", targetKind: "import", value: .string("_UTTypePlainText")),
         row(0x1014, 0x6000, "data", target: "_gConnection", targetKind: "symbol"),
         row(0x1018, 0x6010, "data", targetKind: "data"),
         row(0x101c, 0x7000, "selref", targetKind: "selector", value: .string("isRichText")),
         row(0x1020, 0x7100, "classref", targetKind: "class", value: .string("NSString")),
         row(0x1028, 0x3010, "string", targetKind: "cString", value: .string("txt"))]
    }

    private func reply(_ store: WorkspaceStore, rows: [ScriptValue], start: UInt64 = 0x1000,
                       end: UInt64 = 0x1040, name: String = "smcOpen", slot: Int = 0,
                       address: UInt64? = 0x1000,
                       coverage: ScriptValue = .object(["status": .string("complete"), "stopReason": .null])) throws -> ScriptValue {
        let image = try XCTUnwrap(store.snapshot.binaries.first { $0.slot.rawValue == slot })
        var fields: [String: ScriptValue] = ["name": .string(name), "start": .hex(start), "end": .hex(end),
            "imageSlot": .int(Int64(slot)), "imageOwner": .string(image.id.uuidString),
            "stringLiteralCoverage": coverage, "cfStringStorage": storageUnavailable,
            "references": .array(rows), "resolvedFunction": .hex(start),
            "resolution": .string(address.map { $0 == start ? "exact" : "containing" } ?? "exact")]
        if let address { fields["requestedAddress"] = .hex(address) }
        return .object(fields)
    }

    func testM1StoredResolverMechanismsFeedReferences() async throws {
        let operations: [(String, String)] = [("adrp", "x0, 0x3000"), ("add", "x0, x0, #0x10"),
            ("adrp", "x1, 0x4000"), ("add", "x1, x1, #0x0"),
            ("adrp", "x2, 0x5000"), ("ldr", "x2, [x2]"),
            ("adrp", "x3, 0x6000"), ("ldr", "w3, [x3, #0x10]"),
            ("adrp", "x4, 0x7000"), ("ldr", "x4, [x4]"),
            ("adrp", "x5, 0x7000"), ("ldr", "x5, [x5, #0x100]")]
        let instructions = operations.enumerated().map { index, operation in
            InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "", mnemonic: operation.0,
                operands: operation.1, hasBreakpoint: false, comment: nil)
        }
        let fixture = try makeStore()
        let refs = DataCrossReferenceResolver().resolve(instructions: instructions,
            stringAddresses: Set(fixture.snapshot.stringLiterals.map(\.address)), selectorSlots: [0x7000], classSlots: [0x7100],
            dataRanges: fixture.snapshot.sections.filter { !$0.isExecutable }.map {
                DataCrossReferenceResolver.DataRange(lowerBound: $0.address, upperBound: $0.address + $0.size)
            })
        let targets: [UInt64] = [0x3010, 0x4000, 0x5000, 0x6010, 0x7000, 0x7100]
        XCTAssertEqual(refs.map(\.to), targets)
        XCTAssertEqual(refs.map(\.from), [0x1004, 0x100c, 0x1014, 0x101c, 0x1024, 0x102c])
        XCTAssertEqual(refs.map(\.kind), ["string", "data", "data", "data", "selref", "classref"])
        let store = try makeStore { $0.xrefs = refs.map { edge($0.from, $0.to, $0.kind) } }
        let expected = [row(0x1004, 0x3010, "string", targetKind: "cString", value: .string("txt")),
            row(0x100c, 0x4000, "data", targetKind: "cfString", value: .string("txt")),
            row(0x1014, 0x5000, "data", targetKind: "import", value: .string("_UTTypePlainText")),
            row(0x101c, 0x6010, "data", targetKind: "data"),
            row(0x1024, 0x7000, "selref", targetKind: "selector", value: .string("isRichText")),
            row(0x102c, 0x7100, "classref", targetKind: "class", value: .string("NSString"))]
        for route in Route.allCases {
            let result = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result, try reply(store, rows: expected))
        }
    }

    func testF1AllKindsNamesDeduplicationAndPrecedence() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result, try reply(store, rows: openRows()))
        }
        let kinds = try makeStore { $0.xrefs.insert(edge(0x1014, 0x6000, "string"), at: 6) }
        var expected = openRows()
        expected.insert(row(0x1014, 0x6000, "string", target: "_gConnection", targetKind: "symbol"), at: 5)
        for route in [Route.inline, .attached] {
            let result = try await read(route, kinds, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result, try reply(kinds, rows: expected))
        }
        let symbols = try makeStore {
            $0.symbols.append(SymbolSummary(id: UUID(), name: "_UTTypePlainText_ptr", address: 0x5000,
                kind: "data", libraryName: nil))
        }
        expected = openRows()
        expected[3] = row(0x1010, 0x5000, "data", target: "_UTTypePlainText_ptr",
            targetKind: "import", value: .string("_UTTypePlainText"))
        let result = try await read(.inline, symbols, "function-references", .object(["address": .hex(0x1000)]))
        XCTAssertEqual(result, try reply(symbols, rows: expected))
    }

    func testF2NamePrefixInteriorAndZeroWidth() async throws {
        let store = try makeStore()
        let helperRows = [row(0x1044, 0x3040, "string", owner: 0x1040, name: "helper", targetKind: "cString", value: .string("config")),
            row(0x1048, 0x3048, "string", owner: 0x1040, name: "helper", targetKind: "cString", value: .string("config.ghostty")),
            row(0x104c, 0x4040, "data", owner: 0x1040, name: "helper", targetKind: "cfString", value: .string("pair"))]
        for route in Route.allCases {
            let prefix = try await read(route, store, "function-references", .object(["function": .string("smcOpen"), "limit": .int(2)]))
            XCTAssertEqual(prefix, try reply(store, rows: Array(openRows().prefix(2)), address: nil))
            let interior = try await read(route, store, "function-references", .object(["address": .hex(0x1048)]))
            XCTAssertEqual(interior, try reply(store, rows: helperRows, start: 0x1040, end: 0x1050, name: "helper", address: 0x1048))
            let zero = try await read(route, store, "function-references", .object(["address": .hex(0x1060)]))
            XCTAssertEqual(zero, try reply(store, rows: [row(0x1060, 0x3040, "string", owner: 0x1060, name: "zero",
                targetKind: "cString", value: .string("config"))], start: 0x1060, end: 0x1060, name: "zero", address: 0x1060))
        }
    }

    func testF3SiblingFactsAndProvenance() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let result = try await read(route, store, "function-references", .object(["address": .hex(0x1004), "imageSlot": .int(1)]))
            XCTAssertEqual(result, try reply(store, rows: [row(0x1004, 0x3000, "string", name: "sib_fn", slot: 1,
                targetKind: "cString", value: .string("sibling"))], name: "sib_fn", slot: 1, address: 0x1004, coverage: .null))
        }
    }

    private func uncovered() -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .unknownSubject,
            detail: "address 0x1070 is outside every function in image slot 0; nearest preceding function zero at 0x1060; section __TEXT,__text [0x1000, 0x1100)",
            requestedAddress: 0x1070, imageSlot: 0,
            nearestFunction: MCPRefusalFunction(name: "zero", address: 0x1060),
            section: MCPRefusalSection(name: "__TEXT,__text", start: 0x1000, end: 0x1100)))
    }

    func testF4SelectionAndArgumentRefusals() async throws {
        let store = try makeStore(renamed: false)
        for route in Route.allCases {
            try await refuses(route, store, "function-references", .object(["address": .hex(0x1070)]), uncovered())
            try await refuses(route, store, "function-references", .object([:]), .missingArgument("function or address"))
            try await refuses(route, store, "function-references", .object(["address": .hex(0x1000), "imageSlot": .int(7)]),
                .unknownImage(selector: "7", validSlots: [0, 1]))
        }
        for route in [Route.mcpSync, .mcpAsync] {
            let result = try await envelope(route, WorkspaceScriptingAPI(store: store), "function-references",
                .object(["address": .hex(0x1000), "image": .int(1)]))
            let expected = ToolArgumentError(field: "image", detail: "Field 'image' is not an allowed argument.",
                allowed: ["address", "function", "imageSlot", "limit"]).refusal
            XCTAssertEqual(result["result"]?["isError"], .bool(true))
            XCTAssertEqual(result["result"]?["content"]?.arrayValue?.first?["text"], .string(expected.text))
        }
    }

    private func budget(work: Bool, used: Int64) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "function-references exceeds the snapshot \(work ? "work" : "result") budget",
            budget: .init(unit: work ? .workSteps : .rows, limit: work ? 100_000 : 5_000), used: used, narrowing: []))
    }

    func testF5ResultWorkAndRequestedLimitBudgets() async throws {
        let rows = try makeStore(renamed: false) { analysis in
            analysis.functions = [function("large", 0x10000, 0x20000)]
            analysis.xrefs = (0..<5_001).map { edge(0x10000 + UInt64($0), 0x6000 + UInt64($0 % 32), "data") }
        }
        let work = try makeStore(renamed: false) { analysis in
            analysis.functions = [function("large", 0x10000, 0x20000)]
            analysis.xrefs = (0..<100_001).map { edge(0x10000 + UInt64($0 % 65_536), 0x1040, "call") }
        }
        for route in [Route.inline, .asynchronous, .attached] {
            try await refuses(route, rows, "function-references", .object(["address": .hex(0x10000)]), budget(work: false, used: 5_001))
            try await refuses(route, work, "function-references", .object(["address": .hex(0x10000)]), budget(work: true, used: 100_001))
            try await refuses(route, makeStore(), "function-references",
                .object(["address": .hex(0x1000), "limit": .int(5_001)]), budget(work: false, used: 5_001))
        }
    }

    func testF6DirectOnlyDisclosureLimitAndSlotControls() async throws {
        let store = try makeStore()
        let direct = row(0x1028, 0x3010, "string", storageNotice: true)
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([direct]))
            let one = try await read(route, store, "xrefs", .object(["to": .hex(0x3010), "limit": .int(1)]))
            XCTAssertEqual(one, .array([direct]))
            let zero = try await read(route, store, "xrefs", .object(["to": .hex(0x3010), "limit": .int(0)]))
            XCTAssertEqual(zero, .array([]))
            let sibling = try await read(route, store, "xrefs", .object(["to": .hex(0x3010), "imageSlot": .int(1)]))
            XCTAssertEqual(sibling, .array([]))
        }
    }

    func testF7CatalogSchemaSummaryAndAppleScriptExclusion() async throws {
        XCTAssertTrue(WorkspaceScriptingAPI.snapshotListCommands.contains("function-references"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("function-references"))
        XCTAssertFalse(MCPAttachExecutor.limitedCommands.contains("function-references"))
        XCTAssertFalse(AppleScriptCommandTranslator.allowlistedCommandIDs.contains("function-references"))
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "function-references" })
        XCTAssertTrue(info.summary.contains("cfStringStorage {status: unavailable, reason: backingAddressNotRetained}"))
        XCTAssertTrue(info.summary.contains("including empty results, zero limit and legacy data"))
        XCTAssertTrue(info.summary.contains("This command is not paged."))
        XCTAssertFalse(info.summary.contains("matched one to one"))
        let xrefs = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "xrefs" })
        XCTAssertTrue(xrefs.summary.contains("Equal text never proves storage identity"))
        XCTAssertTrue(xrefs.summary.contains("every row and every page, including empty partial and final pages"))
        XCTAssertTrue(xrefs.summary.contains("older x1 cursors are refused"))
        XCTAssertFalse(xrefs.summary.contains("matched one to one"))
        let server = MCPServer(api: WorkspaceScriptingAPI(store: try makeStore()))
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")])
        for asynchronous in [false, true] {
            let data: Data?
            if asynchronous { data = await server.handleMessageAsync(try request.jsonData()) }
            else { data = server.handleMessage(try request.jsonData()) }
            let reply = try ScriptValue.decode(try XCTUnwrap(data))
            let tool = try XCTUnwrap(reply["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string("function-references") })
            XCTAssertNil(tool["inputSchema"]?["required"])
            guard case .object(let properties) = try XCTUnwrap(tool["inputSchema"]?["properties"]) else { return XCTFail("missing properties") }
            XCTAssertEqual(Set(properties.keys), ["address", "function", "imageSlot", "limit"])
        }
    }

    func testF8ReloadedSelectorsAndMissingCString() async throws {
        let store = try makeStore { $0.objcSelectors = [:] }
        var expected = openRows()
        expected[6] = row(0x101c, 0x7000, "selref", targetKind: "selector", value: .null)
        let missing = try makeStore { analysis in
            analysis.stringLiterals.removeAll { $0.value == "dup" }
            analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals,
                cfStrings: [0x4000: "txt", 0x4020: "dup", 0x4040: "pair", 0x4060: "pair"])
        }
        for route in Route.allCases {
            let result = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result, try reply(store, rows: expected))
            let missingResult = try await read(route, missing, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(missingResult, try reply(missing, rows: openRows()))
        }
    }

    func testC1UnchainedXRefsStayIdentical() async throws {
        let store = try makeStore()
        let duplicate = row(0x1004, 0x3000, "string", storageNotice: true)
        let cases: [(UInt64, [ScriptValue])] = [(0x3000, [duplicate, duplicate]),
            (0x4000, [row(0x1008, 0x4000, "data")]), (0x6090, [])]
        for route in Route.allCases {
            for (target, expected) in cases {
                let result = try await read(route, store, "xrefs", .object(["to": .hex(target)]))
                XCTAssertEqual(result, .array(expected))
            }
            let from = try await read(route, store, "xrefs", .object(["from": .hex(0x1028)]))
            XCTAssertEqual(from, .array([row(0x1028, 0x3010, "string")]))
        }
    }

    func testC3CalleesStayIdentical() async throws {
        let store = try makeStore()
        let expected: ScriptValue = .array([.object(["from": .hex(0x1024), "to": .hex(0x1040),
            "imageSlot": .int(0), "toName": .string("helper"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("smcOpen")])])
        for route in Route.allCases {
            let result = try await read(route, store, "callees", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result, expected)
        }
    }

    func testC5ContainingFunctionKeepsExactFields() async throws {
        let store = try makeStore()
        let owner = try XCTUnwrap(store.snapshot.binaries.first)
        let expected: ScriptValue = .object(["name": .string("helper"), "start": .hex(0x1040), "end": .hex(0x1050),
            "imageSlot": .int(0), "imageOwner": .string(owner.id.uuidString), "requestedAddress": .hex(0x1048),
            "resolvedFunction": .hex(0x1040), "resolution": .string("containing")])
        for route in Route.allCases {
            let result = try await read(route, store, "containing-function", .object(["address": .hex(0x1048)]))
            XCTAssertEqual(result, expected)
        }
    }

    func testF9OnlyDirectEndpointSpendsRowAndWorkBudget() throws {
        let snapshot = try makeStore().snapshot
        let arguments: ScriptValue = .object(["to": .hex(0x3010)])
        let expected = ScriptValue.array([row(0x1028, 0x3010, "string", storageNotice: true)])
        XCTAssertEqual(try WorkspaceScriptingAPI.snapshotXRefRead(arguments, snapshot: snapshot,
            selectionWorkLimit: 1, resultLimit: 1), expected)
        // Arbitrarily many equal-text object edges cannot spend this endpoint's budget.
        let other = try makeStore { $0.xrefs += (0..<20).map { _ in edge(0x100c, 0x4000, "data") } }.snapshot
        XCTAssertEqual(try WorkspaceScriptingAPI.snapshotXRefRead(arguments, snapshot: other,
            selectionWorkLimit: 1, resultLimit: 1), expected)
    }

    func testF10ZeroLimitStillSelectsAndPrefixStopsBeforeWorkOverflow() async throws {
        let store = try makeStore()
        for route in Route.allCases {
            let empty = try await read(route, store, "function-references",
                .object(["address": .hex(0x1000), "limit": .int(0)]))
            XCTAssertEqual(empty, try reply(store, rows: []))
            try await refuses(route, store, "function-references",
                .object(["address": .hex(0x1070), "limit": .int(0)]), uncovered())
        }
        // All candidates have the same source, so source ordering keeps the first data row first.
        let large = try makeStore(renamed: false) { analysis in
            analysis.functions = [function("large", 0x10000, 0x20000)]
            analysis.xrefs = [edge(0x10000, 0x6010, "data")]
            analysis.xrefs += (0..<100_001).map { _ in edge(0x10001, 0x1040, "call") }
        }
        for route in [Route.inline, .asynchronous, .attached] {
            let prefix = try await read(route, large, "function-references",
                .object(["address": .hex(0x10000), "limit": .int(1)]))
            XCTAssertEqual(prefix, try reply(large, rows: [row(0x10000, 0x6010, "data", owner: 0x10000,
                name: "large", targetKind: "data")], start: 0x10000, end: 0x20000, name: "large", address: 0x10000))
        }
    }

    func testF11MetadataLiteralImportRenameCoverageAndStoredEdges() async throws {
        let store = try makeStore { analysis in
            analysis.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
            analysis.stringLiterals.append(StringLiteralSummary(id: UUID(), value: "method:", address: 0x7200,
                sourceSection: "__TEXT,__objc_methname", byteLength: 8))
            analysis.xrefs.append(edge(0x102c, 0x7200, "string"))
            // build deliberately excludes this metadata literal.
            analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals,
                cfStrings: [0x4000: "txt", 0x4020: "dup", 0x4040: "pair", 0x4060: "pair"])
            var later = analysis.indirectSymbols[0]
            later.symbolName = "wrongLaterImport"
            analysis.indirectSymbols.append(later)
        }
        let api = WorkspaceScriptingAPI(store: store)
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x5000), "name": .string("customImport")]))
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x6000), "name": .string("customGlobal")]))
        _ = try api.execute("suppress-xref", arguments: .object(["from": .hex(0x1004), "to": .hex(0x3000), "kind": .string("string")]))
        var expected = openRows()
        expected[1] = row(0x1008, 0x4000, "data", targetKind: "cfString", value: .string("txt"))
        expected[3] = row(0x1010, 0x5000, "data", targetKind: "import", value: .string("customImport"))
        expected[4] = row(0x1014, 0x6000, "data", target: "customGlobal", targetKind: "symbol")
        expected.removeFirst() // The user's suppression applies to both duplicate stored edges.
        expected.append(row(0x102c, 0x7200, "string", targetKind: "cString", value: .string("method:")))
        for route in Route.allCases {
            let result = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result, try reply(store, rows: expected,
                coverage: .object(["status": .string("incomplete"), "stopReason": .string("stringCountLimitReached")])))
        }
        // Before the rename, first nonempty indirect name wins even with a later duplicate.
        let imports = try makeStore { analysis in
            var later = analysis.indirectSymbols[0]
            later.symbolName = "wrongLaterImport"
            analysis.indirectSymbols.append(later)
        }
        let result = try await read(.inline, imports, "function-references", .object(["address": .hex(0x1000)]))
        XCTAssertEqual(result, try reply(imports, rows: openRows()))
    }

    func testEffectiveReferencesHonorEditsAndImageScope() async throws {
        let store = try makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        _ = try api.execute("suppress-xref", arguments: .object([
            "from": .hex(0x1004), "to": .hex(0x3000), "kind": .string("string")]))
        _ = try api.execute("add-xref", arguments: .object([
            "from": .hex(0x1030), "to": .hex(0x6018), "kind": .string("data")]))
        for route in Route.allCases {
            let primary = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
            let rows = try XCTUnwrap(primary["references"]?.arrayValue)
            XCTAssertFalse(rows.contains { $0["from"] == .hex(0x1004) && $0["to"] == .hex(0x3000) })
            XCTAssertTrue(rows.contains { $0["from"] == .hex(0x1030) && $0["to"] == .hex(0x6018) })
            let sibling = try await read(route, store, "function-references", .object([
                "address": .hex(0x1000), "imageSlot": .int(1)]))
            let otherRows = try XCTUnwrap(sibling["references"]?.arrayValue)
            XCTAssertTrue(otherRows.contains { $0["from"] == .hex(0x1004) && $0["to"] == .hex(0x3000) })
            XCTAssertFalse(otherRows.contains { $0["to"] == .hex(0x6018) })
        }
    }

    func testF12DescriptionCancellationAndEmptyFastPaths() throws {
        let snapshot = try makeStore().snapshot
        var count = 0
        _ = try DataTargetDescriber(snapshot: snapshot, slot: .primary, targets: []) {
            count += 1; throw CancellationError()
        }
        XCTAssertEqual(count, 0)
        XCTAssertThrowsError(try DataTargetDescriber(snapshot: snapshot, slot: .primary, targets: [0x4000],
            checkpoint: { throw CancellationError() })) { XCTAssertTrue($0 is CancellationError) }
        // Isolate retained literal/import passes; the removed equality scan must never run.
        for pass in 0..<2 {
            var analysis = ImageAnalysis()
            analysis.stringLiteralCoverage = .complete
            if pass == 0 {
                analysis.stringLiterals = (0..<257).map { StringLiteralSummary(id: UUID(), value: "v",
                    address: UInt64($0), sourceSection: "__cstring", byteLength: 2) }
            } else if pass == 1 {
                let sample = try XCTUnwrap(snapshot.analysis(in: .primary)?.indirectSymbols.first)
                analysis.indirectSymbols = Array(repeating: sample, count: 257)
            } else {
                analysis.constantStrings = Dictionary(uniqueKeysWithValues: (0..<257).map {
                    (UInt64($0), MacIRConstantString(text: "v", kind: .cfString))
                })
            }
            let input = WorkspaceSnapshot(binaries: snapshot.binaries, analysisBySlot: [.primary: analysis])
            var checkpoints = 0
            // The constant pass follows a one-target pass; the other two precede it.
            let stop = pass == 2 ? 3 : 2
            XCTAssertThrowsError(try DataTargetDescriber(snapshot: input, slot: .primary, targets: [0], checkpoint: {
                checkpoints += 1
                if checkpoints == stop { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
            XCTAssertEqual(checkpoints, stop)
        }
    }

    func testPartialStringInventoryDoesNotInferCFStringLinks() throws {
        let coverages: [StringLiteralCoverage?] = [nil, .notAttempted, .complete,
            .incomplete(.stringCountLimitReached), .incomplete(.unterminatedField)]
        for coverage in coverages {
            let snapshot = try makeStore(change: { $0.stringLiteralCoverage = coverage }).snapshot
            let description = try DataTargetDescriber(snapshot: snapshot, slot: .primary,
                targets: [0x4000], checkpoint: {}).describe(edge(0x1008, 0x4000, "data"), named: false)
            XCTAssertEqual(description["targetKind"], .string("cfString"))
            XCTAssertEqual(description["value"], .string("txt"))
            XCTAssertNil(description["cString"])
            XCTAssertEqual(description["cfStringStorage"], storageUnavailable)
        }
    }

    func testFunctionReferencesCheckpointCancellationNeverReturnsPartialReply() throws {
        let args: ScriptValue = .object(["address": .hex(0x1000)])
        // 189dcae60, N5: Bound graph name enrichment with image-owned index.
        // Each probe needs the same memo state as its measured run. Cover both
        // cold index construction and warm reads without pinning either count.
        func fixture(warm: Bool) throws -> WorkspaceSnapshot {
            let snapshot = try makeStore().snapshot
            if warm {
                _ = try WorkspaceScriptingAPI.attachedSnapshotRead("function-references", arguments: args,
                    snapshot: snapshot, checkpoint: {})
            }
            return snapshot
        }
        for warm in [false, true] {
            let measured = try fixture(warm: warm)
            var total = 0
            _ = try WorkspaceScriptingAPI.attachedSnapshotRead("function-references", arguments: args,
                snapshot: measured, checkpoint: { total += 1 })
            XCTAssertGreaterThan(total, 0)
            guard total > 0 else { continue }
            for stop in 1...total {
                let snapshot = try fixture(warm: warm)
                var calls = 0
                var output: ScriptValue?
                XCTAssertThrowsError(try { output = try WorkspaceScriptingAPI.attachedSnapshotRead(
                    "function-references", arguments: args, snapshot: snapshot, checkpoint: {
                        calls += 1
                        if calls == stop { throw CancellationError() }
                    }) }()) { XCTAssertTrue($0 is CancellationError) }
                XCTAssertNil(output)
                XCTAssertEqual(calls, stop)
            }
        }
    }

    func testF13ZeroWidthAtLastAddressDoesNotWrapRange() async throws {
        let store = try makeStore(renamed: false) { analysis in
            analysis.functions = [function("last", UInt64.max, UInt64.max)]
            analysis.xrefs = [edge(UInt64.max, 0x3000, "string"), edge(UInt64.max - 1, 0x3000, "string")]
        }
        // Nonzero ranges store an end address, not a length to add: max is a valid exclusive end.
        let nonzero = try makeStore(renamed: false) { analysis in
            analysis.functions = [function("nearLast", UInt64.max - 4, UInt64.max)]
            analysis.xrefs = [edge(UInt64.max - 1, 0x3000, "string"), edge(UInt64.max, 0x3000, "string")]
        }
        for route in Route.allCases {
            let interior = try await read(route, nonzero, "function-references", .object(["address": .hex(UInt64.max - 1)]))
            XCTAssertEqual(interior, try reply(nonzero, rows: [row(UInt64.max - 1, 0x3000, "string",
                owner: UInt64.max - 4, name: "nearLast", targetKind: "cString", value: .string("AppleSMC"))],
                start: UInt64.max - 4, end: UInt64.max, name: "nearLast", address: UInt64.max - 1))
            let result = try await read(route, store, "function-references", .object(["address": .hex(UInt64.max)]))
            XCTAssertEqual(result, try reply(store, rows: [row(UInt64.max, 0x3000, "string", owner: UInt64.max,
                name: "last", targetKind: "cString", value: .string("AppleSMC"))], start: UInt64.max,
                end: UInt64.max, name: "last", address: UInt64.max))
        }
    }

    // Storage-authority controls.
    private var storageRefusal: ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
            detail: "xrefs found no direct references to this address; references through CFString backing storage are unavailable because backing addresses were not retained",
            narrowing: []))
    }

    func testStorageAuthorityAllRoutesActualReaderWorlds() async throws {
        for world in [(true, false), (false, false), (false, true)] {
            let snapshot = ImageConstantStringProviderTests.storageAuthoritySnapshot(shared: world.0, utf16: world.1)
            let store = WorkspaceStore(workspaceName: "storage authority", snapshot: snapshot,
                engine: AnalysisEngine(), autosaveScheduler: nil)
            for route in Route.allCases {
                let refs = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
                XCTAssertEqual(refs["cfStringStorage"], storageUnavailable)
                let rows = try XCTUnwrap(refs["references"]?.arrayValue)
                XCTAssertEqual(rows.count, 2)
                XCTAssertEqual(rows[1]["targetKind"], .string("cfString"))
                XCTAssertEqual(rows[1]["value"], .string("txt"))
                XCTAssertEqual(rows[1]["cfStringStorage"], storageUnavailable)
                XCTAssertNil(rows[1]["cString"])
                let direct = try await read(route, store, "xrefs", .object(["to": .hex(0x2000)]))
                let directRows = try XCTUnwrap(direct.arrayValue)
                XCTAssertEqual(directRows.count, 1)
                XCTAssertEqual(directRows[0]["from"], .hex(0x1000))
                XCTAssertEqual(directRows[0]["to"], .hex(0x2000))
                XCTAssertEqual(directRows[0]["cfStringStorage"], storageUnavailable)
                XCTAssertNil(directRows[0]["via"])
                XCTAssertNil(directRows[0]["cString"])
            }
        }
    }

    func testStorageAuthorityEveryCoverageAndEmptyFunctionEnvelope() async throws {
        let coverages: [StringLiteralCoverage?] = [nil, .notAttempted, .complete,
            .incomplete(.stringCountLimitReached), .incomplete(.unterminatedField)]
        for coverage in coverages {
            for empty in [false, true] {
                let store = try makeStore {
                    $0.stringLiteralCoverage = coverage
                    if empty { $0.xrefs = []; $0.constantStrings = [:] }
                }
                for route in Route.allCases {
                    for limit in [0, 1] {
                        let result = try await read(route, store, "function-references",
                            .object(["address": .hex(0x1000), "limit": .int(Int64(limit))]))
                        XCTAssertEqual(result["cfStringStorage"], storageUnavailable)
                        XCTAssertEqual(result["references"]?.arrayValue?.count, empty ? 0 : limit)
                    }
                }
            }
        }
    }

    func testStorageAuthorityMapAbsentMetadataAndSuppressedEmptyRefusalAllRoutes() async throws {
        for metadata in [false, true] {
            let store = try makeStore { analysis in
                analysis.constantStrings = [:]
                analysis.stringLiteralCoverage = nil
                analysis.stringLiterals = [StringLiteralSummary(id: UUID(), value: "txt", address: 0x3010,
                    sourceSection: metadata ? "__TEXT,__objc_methname" : "__TEXT,__cstring", byteLength: 4)]
            }
            for route in Route.allCases {
                let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
                XCTAssertEqual(result, .array([row(0x1028, 0x3010, "string", storageNotice: true)]))
            }
            _ = try WorkspaceScriptingAPI(store: store).execute("suppress-xref", arguments: .object([
                "from": .hex(0x1028), "to": .hex(0x3010), "kind": .string("string")]))
            for route in Route.allCases {
                try await refuses(route, store, "xrefs", .object(["to": .hex(0x3010)]), storageRefusal)
                let zero = try await read(route, store, "xrefs", .object(["to": .hex(0x3010), "limit": .int(0)]))
                XCTAssertEqual(zero, .array([]))
            }
        }
        let store = try makeStore()
        for route in Route.allCases {
            for address in [UInt64(0x3020), UInt64(0x3058)] {
                try await refuses(route, store, "xrefs", .object(["to": .hex(address)]), storageRefusal)
            }
        }
    }

    func testStorageAuthorityAuthoredOnlyAndSiblingIsolationAllRoutes() async throws {
        let store = try makeStore { $0.xrefs.removeAll { $0.to == 0x3010 } }
        _ = try WorkspaceScriptingAPI(store: store).execute("add-xref", arguments: .object([
            "from": .hex(0x1030), "to": .hex(0x3010), "kind": .string("string")]))
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([row(0x1030, 0x3010, "string", storageNotice: true)]))
            let other = try await read(route, store, "xrefs", .object(["to": .hex(0x3010), "imageSlot": .int(1)]))
            XCTAssertEqual(other, .array([]))
            let sameAddress = try await read(route, store, "xrefs", .object(["to": .hex(0x3000), "imageSlot": .int(1)]))
            XCTAssertEqual(sameAddress, .array([row(0x1004, 0x3000, "string", name: "sib_fn", slot: 1, storageNotice: true)]))
        }
    }

    func testStorageClassificationBoundCancellationAndMapPriority() throws {
        let literals = (0..<257).map { StringLiteralSummary(id: UUID(), value: "txt", address: UInt64($0),
            sourceSection: "__TEXT,__cstring", byteLength: 4) }
        func classify(_ target: UInt64, _ work: Int, constants: [UInt64: MacIRConstantString] = [:],
                      checkpoint: () throws -> Void = {}) throws -> Bool {
            try WorkspaceScriptingAPI.requiresCFStringStorageNotice(target: target, constants: constants,
                literals: literals, maximumWork: work, checkpoint: checkpoint)
        }
        XCTAssertTrue(try classify(256, 257))
        XCTAssertTrue(try classify(256, 256)) // Exhaustion is uncertainty, never absence.
        XCTAssertTrue(try classify(900, 0))
        XCTAssertFalse(try classify(900, 257))
        XCTAssertFalse(try classify(0, 257, constants: [0: MacIRConstantString(text: "txt", kind: .cfString)]))
        XCTAssertTrue(try classify(900, 0, constants: [900: MacIRConstantString(text: "txt", kind: .cString)]))
        var total = 0
        _ = try classify(900, 257, checkpoint: { total += 1 })
        XCTAssertGreaterThan(total, 0)
        for stop in 1...total {
            var calls = 0
            XCTAssertThrowsError(try classify(900, 257, checkpoint: {
                calls += 1
                if calls == stop { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
            XCTAssertEqual(calls, stop)
        }
    }

    // MARK: - Retained CFString backing table (CFSTR-XREF)

    private var retainedStorage: ScriptValue { .object(["status": .string("retained")]) }
    private var partialStorage: ScriptValue {
        .object(["status": .string("partial"), "reason": .string("cfStringWalkIncomplete")])
    }
    private var partialRefusal: ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
            detail: "xrefs found no references to this address; CFString backing storage was only partly retained because the CFString walk was capped or could not resolve every data pointer",
            narrowing: []))
    }

    private func backingTable(_ pairs: [UInt64: UInt64],
                              complete: Bool = true) -> ImageConstantStringProvider.CFStringBackingTable {
        ImageConstantStringProvider.CFStringBackingTable(complete: complete, backings: pairs)
    }

    /// The fixture without its direct 0x1028 -> 0x3010 edge, so only the CFString object reaches 0x3010.
    private func chainStore(_ table: ImageConstantStringProvider.CFStringBackingTable?,
                            keepDirect: Bool = false,
                            change: (inout ImageAnalysis) -> Void = { _ in }) throws -> WorkspaceStore {
        try makeStore {
            if !keepDirect { $0.xrefs.removeAll { $0.from == 0x1028 && $0.to == 0x3010 } }
            $0.cfStringBackings = table
            change(&$0)
        }
    }

    private func chainedRow(_ from: UInt64, _ to: UInt64, object: UInt64, kind: String = "data",
                            storage: ScriptValue? = nil, owner: UInt64? = 0x1000,
                            name: String? = "smcOpen") -> ScriptValue {
        guard case .object(var fields) = row(from, to, kind, owner: owner, name: name) else { return .null }
        fields["via"] = .string("cfString")
        fields["cfString"] = .hex(object)
        fields["cfStringStorage"] = storage ?? retainedStorage
        return .object(fields)
    }

    private func directRow(_ from: UInt64, _ to: UInt64, kind: String,
                           storage: ScriptValue? = nil) -> ScriptValue {
        guard case .object(var fields) = row(from, to, kind) else { return .null }
        fields["cfStringStorage"] = storage ?? retainedStorage
        return .object(fields)
    }

    /// Local copy of the seven-key edge projection; XRefReadBudgetTests' helper is private.
    private func edgeKeys(_ row: ScriptValue) -> ScriptValue {
        var fields: [String: ScriptValue] = [:]
        for key in ["from", "to", "kind", "imageSlot", "cfStringStorage", "via", "cfString"] {
            if let value = row[key] { fields[key] = value }
        }
        return .object(fields)
    }

    /// Follows nextCursor to the end. Returns every page in order.
    private func pagedXRefs(_ store: WorkspaceStore, to target: UInt64, limit: Int? = nil) throws -> [ScriptValue] {
        var cursor: ScriptValue = .null
        var pages: [ScriptValue] = []
        for _ in 0..<40 {
            var arguments: [String: ScriptValue] = ["to": .hex(target), "page": .bool(true),
                "detail": .string("edges"), "cursor": cursor]
            if let limit { arguments["limit"] = .int(Int64(limit)) }
            // A refusal must propagate as the thrown error, not as an XCTUnwrap failure.
            guard let page = try WorkspaceScriptingAPI.snapshotGraphPage("xrefs",
                arguments: .object(arguments), snapshot: store.snapshot,
                context: store.graphPageContext, checkpoint: {}) else {
                XCTFail("paged read returned no page")
                return pages
            }
            pages.append(page)
            cursor = try XCTUnwrap(page["nextCursor"])
            if cursor == .null { return pages }
        }
        XCTFail("paging did not finish")
        return pages
    }

    private func flatXRefs(_ store: WorkspaceStore, _ arguments: [String: ScriptValue]) throws -> [ScriptValue] {
        try XCTUnwrap(WorkspaceScriptingAPI.snapshotXRefRead(.object(arguments),
            snapshot: store.snapshot).arrayValue)
    }

    func testX1ChainedRowReachesBackingThroughCFStringAllRoutes() async throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]))
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([chainedRow(0x1008, 0x3010, object: 0x4000)]))
        }
    }

    func testX2PagedMatchesFlatAndCountsChainedRowsInTotal() throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]))
        let flat = try flatXRefs(store, ["to": .hex(0x3010)])
        let pages = try pagedXRefs(store, to: 0x3010)
        XCTAssertEqual(pages.count, 1)
        let page = try XCTUnwrap(pages.first)
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.map(edgeKeys), flat.map(edgeKeys))
        XCTAssertEqual(rows.map(edgeKeys), [.object(["from": .hex(0x1008), "to": .hex(0x3010),
            "kind": .string("data"), "imageSlot": .int(0), "cfStringStorage": retainedStorage,
            "via": .string("cfString"), "cfString": .hex(0x4000)])])
        XCTAssertEqual(page["cfStringStorage"], retainedStorage)
        XCTAssertEqual(page["total"], .int(1))
        XCTAssertEqual(page["coverage"], .string("complete"))
    }

    func testX3DirectRowsPrecedeChainedRows() async throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]), keepDirect: true)
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([directRow(0x1028, 0x3010, kind: "string"),
                                           chainedRow(0x1008, 0x3010, object: 0x4000)]))
        }
    }

    func testX4CompleteTableWithNoObjectGivesHonestEmptyResult() async throws {
        let store = try chainStore(backingTable([0x4000: 0x3020]))
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([]))
        }
        let pages = try pagedXRefs(store, to: 0x3010)
        XCTAssertEqual(pages.count, 1)
        XCTAssertEqual(pages[0]["rows"], .array([]))
        XCTAssertEqual(pages[0]["total"], .int(0))
        XCTAssertEqual(pages[0]["coverage"], .string("complete"))
        XCTAssertEqual(pages[0]["cfStringStorage"], retainedStorage)
    }

    func testX5NilTableKeepsTodaysRefusalAndDisclosure() async throws {
        let store = try chainStore(nil)
        for route in Route.allCases {
            try await refuses(route, store, "xrefs", .object(["to": .hex(0x3010)]), storageRefusal)
        }
        XCTAssertThrowsError(try pagedXRefs(store, to: 0x3010)) { XCTAssertEqual($0 as? ScriptingError, storageRefusal) }
        let direct = try await read(.inline, try chainStore(nil, keepDirect: true), "xrefs", .object(["to": .hex(0x3010)]))
        XCTAssertEqual(direct, .array([row(0x1028, 0x3010, "string", storageNotice: true)]))
    }

    func testX6PartialTableRefusesEmptyResultAndMarksRowsPartial() async throws {
        let empty = try chainStore(backingTable([0x4000: 0x3020], complete: false))
        for route in Route.allCases {
            try await refuses(route, empty, "xrefs", .object(["to": .hex(0x3010)]), partialRefusal)
        }
        XCTAssertThrowsError(try pagedXRefs(empty, to: 0x3010)) { XCTAssertEqual($0 as? ScriptingError, partialRefusal) }
        // X6c: the explicit zero prefix is never refused and carries no disclosure.
        for route in Route.allCases {
            let zero = try await read(route, empty, "xrefs", .object(["to": .hex(0x3010), "limit": .int(0)]))
            XCTAssertEqual(zero, .array([]))
        }
        // X6b: with a chained row the disclosure is partial.
        let chained = try chainStore(backingTable([0x4000: 0x3010], complete: false))
        for route in Route.allCases {
            let result = try await read(route, chained, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([chainedRow(0x1008, 0x3010, object: 0x4000, storage: partialStorage)]))
        }
        let pages = try pagedXRefs(chained, to: 0x3010)
        XCTAssertEqual(pages.last?["cfStringStorage"], partialStorage)
        XCTAssertEqual(pages.last?["rows"]?.arrayValue?.first?["cfStringStorage"], partialStorage)
    }

    func testX7ObjectSuppressionRemovesChainedRowWithoutRefusal() async throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]))
        _ = try WorkspaceScriptingAPI(store: store).execute("suppress-xref", arguments: .object([
            "from": .hex(0x1008), "to": .hex(0x4000), "kind": .string("data")]))
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([]))
        }
        let pages = try pagedXRefs(store, to: 0x3010)
        XCTAssertEqual(pages.count, 1)
        XCTAssertEqual(pages[0]["rows"], .array([]))
        XCTAssertEqual(pages[0]["cfStringStorage"], retainedStorage)
        XCTAssertEqual(pages[0]["total"], .int(0))
    }

    func testX7bBackingSuppressionRemovesChainedRow() async throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]))
        _ = try WorkspaceScriptingAPI(store: store).execute("suppress-xref", arguments: .object([
            "from": .hex(0x1008), "to": .hex(0x3010), "kind": .string("data")]))
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3010)]))
            XCTAssertEqual(result, .array([]))
        }
        let pages = try pagedXRefs(store, to: 0x3010)
        XCTAssertEqual(pages.last?["rows"], .array([]))
        XCTAssertEqual(pages.last?["total"], .int(0))
    }

    func testX8bFlatChainedQueryChargesSharedWorkBudget() throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]))
        let expected = ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "xrefs exceeds the snapshot work budget",
            budget: .init(unit: .workSteps, limit: 0), narrowing: ["imageSlot"]))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(0x3010)]),
            snapshot: store.snapshot, selectionWorkLimit: 0)) { XCTAssertEqual($0 as? ScriptingError, expected) }
        // X8c positive control: a bound that covers the object query answers.
        let positive = try WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(0x3010)]),
            snapshot: store.snapshot, selectionWorkLimit: 1)
        XCTAssertEqual(positive.arrayValue?.map { $0["from"] ?? .null }, [.hex(0x1008)])
    }

    func testX8cBackingTableScanIsNotChargedToTheWorkBudget() throws {
        var pairs: [UInt64: UInt64] = [0x4000: 0x3010]
        for index in 0..<96 { pairs[0x9000 + UInt64(index) * 0x20] = 0xA000 + UInt64(index) * 0x20 }
        let store = try chainStore(backingTable(pairs))
        let result = try WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(0x3010)]),
            snapshot: store.snapshot, selectionWorkLimit: 2)
        XCTAssertEqual(result, .array([chainedRow(0x1008, 0x3010, object: 0x4000)]))
    }

    private func x9Store() throws -> WorkspaceStore {
        try makeStore {
            $0.cfStringBackings = ImageConstantStringProvider.CFStringBackingTable(
                complete: true, backings: [0x4040: 0x3058, 0x4060: 0x3058])
            $0.xrefs.append(XRef(id: UUID(), from: 0x1030, to: 0x4040, kind: "data"))
        }
    }

    func testX9ChainedRowsFollowObjectOrderThenEachObjectsOwnOrder() async throws {
        let store = try x9Store()
        for route in Route.allCases {
            let result = try await read(route, store, "xrefs", .object(["to": .hex(0x3058)]))
            let rows = try XCTUnwrap(result.arrayValue)
            XCTAssertEqual(rows.map { $0["from"] ?? .null }, [.hex(0x104c), .hex(0x1030), .hex(0x1080)])
            XCTAssertEqual(rows.map { $0["cfString"] ?? .null }, [.hex(0x4040), .hex(0x4040), .hex(0x4060)])
            XCTAssertTrue(rows.allSatisfy { $0["to"] == ScriptValue.hex(0x3058) && $0["via"] == ScriptValue.string("cfString") })
        }
        let first = try await read(.inline, store, "xrefs", .object(["to": .hex(0x4040)]))
        let second = try await read(.inline, store, "xrefs", .object(["to": .hex(0x4060)]))
        let joined = try XCTUnwrap(first.arrayValue) + XCTUnwrap(second.arrayValue)
        let combined = try await read(.inline, store, "xrefs", .object(["to": .hex(0x3058)]))
        let chained = try XCTUnwrap(combined.arrayValue)
        XCTAssertEqual(chained.map { $0["from"] ?? .null }, joined.map { $0["from"] ?? .null })
    }

    func testX9bPagedLimitOneWalksChainedRowsWithoutRepeats() throws {
        let store = try x9Store()
        let pages = try pagedXRefs(store, to: 0x3058, limit: 1)
        XCTAssertEqual(pages.count, 4)
        let froms = pages.prefix(3).map { $0["rows"]?.arrayValue?.first?["from"] ?? .null }
        XCTAssertEqual(froms, [.hex(0x104c), .hex(0x1030), .hex(0x1080)])
        for page in pages.prefix(3) {
            XCTAssertEqual(page["rows"]?.arrayValue?.count, 1)
            XCTAssertEqual(page["total"], .null)
            XCTAssertNotEqual(page["nextCursor"], .null)
        }
        XCTAssertEqual(pages[3]["rows"], .array([]))
        XCTAssertEqual(pages[3]["total"], .int(3))
        XCTAssertEqual(pages[3]["lowerBound"], .int(3))
        XCTAssertEqual(pages[3]["nextCursor"], .null)
        // X3 paged with limit 1: the direct row first, then the chained row.
        let mixed = try pagedXRefs(try chainStore(backingTable([0x4000: 0x3010]), keepDirect: true),
                                   to: 0x3010, limit: 1)
        let mixedRows = mixed.compactMap { $0["rows"]?.arrayValue?.first }
        XCTAssertEqual(mixedRows.map { $0["from"] ?? .null }, [.hex(0x1028), .hex(0x1008)])
        XCTAssertNil(mixedRows.first?["via"])
        XCTAssertEqual(mixedRows.last?["via"], .string("cfString"))
        XCTAssertEqual(mixed.last?["total"], .int(2))
    }

    func testR1DescribeReportsBackingForCFStringObjects() throws {
        let row = XRef(id: UUID(), from: 0x1008, to: 0x4000, kind: "data")
        func storage(_ table: ImageConstantStringProvider.CFStringBackingTable?) throws -> ScriptValue? {
            let store = try chainStore(table)
            let describer = try DataTargetDescriber(snapshot: store.snapshot, slot: .primary,
                targets: [0x4000], checkpoint: {})
            return describer.describe(row, named: false)["cfStringStorage"]
        }
        XCTAssertEqual(try storage(backingTable([0x4000: 0x3010])),
                       .object(["status": .string("retained"), "backing": .hex(0x3010)]))
        XCTAssertEqual(try storage(backingTable([0x4020: 0x3010])), storageUnavailable)   // R1b
        XCTAssertEqual(try storage(backingTable([:], complete: false)), partialStorage)     // R1c
        XCTAssertEqual(try storage(nil), storageUnavailable)
    }

    func testA1AttachedFunctionReferencesDisclosureFollowsTable() async throws {
        let store = try chainStore(backingTable([0x4000: 0x3010]))
        let nilStore = try chainStore(nil)
        let partial = try chainStore(backingTable([:], complete: false))
        for route in Route.allCases {
            let result = try await read(route, store, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(result["cfStringStorage"], retainedStorage)
            let cfRow = try XCTUnwrap(result["references"]?.arrayValue?.first { $0["to"] == .hex(0x4000) })
            XCTAssertEqual(cfRow["cfStringStorage"],
                           .object(["status": .string("retained"), "backing": .hex(0x3010)]))
            let legacy = try await read(route, nilStore, "function-references", .object(["address": .hex(0x1000)]))
            XCTAssertEqual(legacy["cfStringStorage"], storageUnavailable)
            let incomplete = try await read(route, partial, "function-references",
                                            .object(["address": .hex(0x1000), "limit": .int(0)]))
            XCTAssertEqual(incomplete["cfStringStorage"], partialStorage)
        }
    }

}
