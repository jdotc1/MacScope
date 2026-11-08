import Foundation
import XCTest
@testable import MacScope

private struct ObjCCategorySelectorNativeStub: ScriptingNativeDecompiling {
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        .completed(NativeDecompilerWirePseudocodeDocument(text: "void selected(void) {}",
            language: "c", isComplete: true, isTruncated: false))
    }
}

@MainActor
final class ObjCCategorySelectorTests: XCTestCase {
    private enum Route: CaseIterable, Equatable { case sync, asynchronous, authority, attached, mcp }

    private func function(_ name: String, _ start: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: start + 0x10, confidence: 1)
    }

    private func method(_ name: String, _ start: UInt64?, classSide: Bool = false) -> ObjCMethod {
        ObjCMethod(selector: name, typeEncoding: nil, isClassMethod: classSide, implementation: start)
    }

    private func binary() -> BinaryImage {
        BinaryImage(id: UUID(), name: "cats", path: "/tmp/cats", kind: "Mach-O executable", architecture: "arm64")
    }

    private func makeStore(extra: [(String, UInt64)] = [], extraMethods: [ObjCMethod] = [],
                           symbols: [SymbolSummary] = [], extraXRefs: [XRef] = []) -> WorkspaceStore {
        let definitions: [(String, UInt64)] = [
            ("-[Doc(Over) save:]", 0x1000), ("-[Doc isRich]", 0x1010),
            ("-[Doc(A) dup]", 0x1020), ("-[Doc(B) dup]", 0x1030),
            ("-[Doc both]", 0x1040), ("-[Doc(C) both]", 0x1050),
            ("+[Doc(Over) make]", 0x1060), ("-[DocX(Over) save:]", 0x1070),
            ("_caller", 0x1080), ("-[NSString(Ext) shout]", 0x10a0),
        ] + extra
        let functions = definitions.map { function($0.0, $0.1) }
        let blocks = functions.map { BasicBlockSummary(id: UUID(), functionID: $0.id,
            startAddress: $0.startAddress, endAddress: $0.endAddress, instructionCount: 1) }
        var instructions = functions.map { InstructionRow(address: $0.startAddress, bytes: "c0 03 5f d6",
            mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil) }
        instructions.append(InstructionRow(address: 0x1084, bytes: "df ff ff 97", mnemonic: "bl",
            operands: "0x1000", hasBreakpoint: false, comment: "call"))
        let doc = ObjCClass(name: "Doc", superclassName: "NSObject", adoptedProtocols: [],
            classMethods: [method("make", 0x1060, classSide: true)], instanceMethods: [
                method("save:", 0x1000), method("isRich", 0x1010), method("dup", 0x1020),
                method("dup", 0x1030), method("both", 0x1040), method("both", 0x1050),
            ] + extraMethods, ivars: [], properties: [], address: 0x7000)
        let docX = ObjCClass(name: "DocX", superclassName: "NSObject", adoptedProtocols: [],
            classMethods: [], instanceMethods: [method("save:", 0x1070)], ivars: [], properties: [], address: 0x7100)
        let category = ObjCCategory(name: "Ext", className: "NSString", classMethods: [],
            instanceMethods: [method("shout", 0x10a0)], adoptedProtocols: [], properties: [], address: 0x7200)
        let snapshot = WorkspaceSnapshot(binaries: [binary()], functions: functions, symbols: symbols,
            basicBlocks: blocks, instructions: instructions,
            xrefs: [XRef(id: UUID(), from: 0x1084, to: 0x1000, kind: "call")] + extraXRefs,
            controlFlowEdges: [ControlFlowEdge(id: UUID(), from: 0x1084, to: 0x1000, kind: "call")],
            hexBytes: Data(), objcClasses: [doc, docX], objcCategories: [category],
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                size: 0x1000, fileOffset: 0, isExecutable: true)])
        return WorkspaceStore(workspaceName: "Categories", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func api(_ store: WorkspaceStore) -> WorkspaceScriptingAPI {
        WorkspaceScriptingAPI(store: store, nativeDecompiler: ObjCCategorySelectorNativeStub())
    }

    private func args(_ name: String) -> ScriptValue { .object(["function": .string(name)]) }

    private func request(_ command: String, _ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": arguments])])
    }

    private func mcp(_ command: String, _ arguments: ScriptValue, store: WorkspaceStore) async throws -> ScriptValue {
        let server = MCPServer(api: api(store))
        let bytes = await server.handleMessageAsync(try request(command, arguments).jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        XCTAssertNil(envelope["error"])
        return try XCTUnwrap(envelope["result"])
    }

    private func read(_ route: Route, _ command: String, _ arguments: ScriptValue,
                      store: WorkspaceStore) async throws -> ScriptValue {
        let api = api(store)
        let result: ScriptValue
        switch route {
        case .sync: result = try api.execute(command, arguments: arguments)
        case .asynchronous: result = try await api.executeAsync(command, arguments: arguments)
        case .authority:
            result = try await HeadlessAutomationAuthority.executeAsync(command: command, arguments: arguments, api: api)
        case .attached:
            let executor = MCPAttachExecutor(store: store, api: {
                WorkspaceScriptingAPI(store: $0, nativeDecompiler: ObjCCategorySelectorNativeStub())
            })
            executor.setConsent(.allowed)
            result = try await executor.execute(command, arguments)
        case .mcp:
            let response = try await mcp(command, arguments, store: store)
            XCTAssertEqual(response["isError"], .bool(false))
            let text = try XCTUnwrap(response["content"]?.arrayValue?.first?["text"]?.stringValue)
            result = try ScriptValue.decode(Data(text.utf8))
        }
        // Compare both in-process and wire rows through the same numeric representation.
        return try ScriptValue.decode(result.jsonData())
    }

    private func refusal(_ route: Route, _ command: String, _ name: String, _ expected: String,
                         store: WorkspaceStore) async throws {
        if route == .mcp {
            let response = try await mcp(command, args(name), store: store)
            XCTAssertEqual(response["isError"], .bool(true))
            XCTAssertEqual(response["content"]?.arrayValue?.first?["text"], .string("Tool call failed: " + expected))
        } else {
            do { _ = try await read(route, command, args(name), store: store); XCTFail("Expected refusal: \(name)") }
            catch { XCTAssertEqual((error as? LocalizedError)?.errorDescription, expected) }
        }
    }

    func testF1UniqueFallbackOnFiveRoutes() async throws {
        let store = makeStore()
        let reply = try api(store).execute("decompile", arguments: args("-[Doc save:]"))
        XCTAssertEqual(reply["address"], .hex(0x1000))
        XCTAssertEqual(reply["function"], .string("-[Doc(Over) save:]"))
        for route in Route.allCases {
            let plain = try await read(route, "callers", args("-[Doc save:]"), store: store)
            let qualified = try await read(route, "callers", args("-[Doc(Over) save:]"), store: store)
            XCTAssertEqual(plain, qualified)
            XCTAssertEqual(plain.arrayValue?.count, 1)
            XCTAssertEqual(plain.arrayValue?.first?["from"], .hex(0x1084))
        }
    }

    func testF2NineCommandsReachSelectedFunction() async throws {
        let store = makeStore()
        for command in ["callers", "callees", "basic-blocks", "instructions", "decompile",
                        "register-names", "parameter-binding-audit", "stack-locals", "indirect-call-targets"] {
            for route in [Route.sync, .asynchronous] {
                do { _ = try await read(route, command, args("-[Doc save:]"), store: store) }
                catch {
                    XCTAssertTrue(["parameter-binding-audit", "stack-locals", "indirect-call-targets"].contains(command),
                        "Unexpected failure in a non-lifting read: \(command): \(error)")
                    XCTAssertNotEqual((error as? LocalizedError)?.errorDescription,
                        "Invalid argument: no function named '-[Doc save:]'.", command)
                }
            }
        }
    }

    func testF3ClassSideAndOppositeSide() async throws {
        let store = makeStore()
        XCTAssertEqual(try api(store).execute("decompile", arguments: args("+[Doc make]"))["address"], .hex(0x1060))
        try await refusal(.sync, "decompile", "-[Doc make]",
            "Invalid argument: no function named '-[Doc make]'.", store: store)
        let plain = try await mcp("callers", args("+[Doc make]"), store: store)
        let qualified = try await mcp("callers", args("+[Doc(Over) make]"), store: store)
        XCTAssertEqual(plain["isError"], .bool(false)); XCTAssertEqual(plain, qualified)
        try await refusal(.mcp, "callers", "-[Doc make]",
            "Invalid argument: no function named '-[Doc make]'.", store: store)
    }

    func testF4TwoCategoriesRefuseInAnalysisOrder() async throws {
        let store = makeStore()
        let expected = "Ambiguous Objective-C method '-[Doc dup]': 2 implementations match (-[Doc(A) dup] at 0x1020, -[Doc(B) dup] at 0x1030); select by a category-qualified name or by `address`."
        for route in [Route.sync, .asynchronous] { try await refusal(route, "decompile", "-[Doc dup]", expected, store: store) }
        try await refusal(.mcp, "callers", "-[Doc dup]", expected, store: store)
    }

    func testF5ExactClassDoesNotOutrankCategory() async throws {
        try await refusal(.sync, "decompile", "-[Doc both]",
            "Ambiguous Objective-C method '-[Doc both]': 2 implementations match (-[Doc both] at 0x1040, -[Doc(C) both] at 0x1050); select by a category-qualified name or by `address`.", store: makeStore())
    }

    private var expectedDocMethods: ScriptValue {
        .array([
            .object(["name": .string("save:"), "implementation": .hex(0x1000), "isClassMethod": .bool(false), "selectorUsers": .array([]), "category": .string("Over")]),
            .object(["name": .string("isRich"), "implementation": .hex(0x1010), "isClassMethod": .bool(false), "selectorUsers": .array([])]),
            .object(["name": .string("dup"), "implementation": .hex(0x1020), "isClassMethod": .bool(false), "selectorUsers": .array([]), "category": .string("A")]),
            .object(["name": .string("dup"), "implementation": .hex(0x1030), "isClassMethod": .bool(false), "selectorUsers": .array([]), "category": .string("B")]),
            .object(["name": .string("both"), "implementation": .hex(0x1040), "isClassMethod": .bool(false), "selectorUsers": .array([])]),
            .object(["name": .string("both"), "implementation": .hex(0x1050), "isClassMethod": .bool(false), "selectorUsers": .array([]), "category": .string("C")]),
            .object(["name": .string("make"), "implementation": .hex(0x1060), "isClassMethod": .bool(true), "selectorUsers": .array([]), "category": .string("Over")]),
        ])
    }

    func testF6FullMethodsAndF7PageMethods() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let full = try await read(route, "list-image-types", .object(["kind": .string("objcClass")]), store: store)
            let rows = try XCTUnwrap(full["types"]?.arrayValue)
            XCTAssertEqual(rows.first { $0["name"] == .string("Doc") }?["methods"], expectedDocMethods)
            XCTAssertEqual(rows.first { $0["name"] == .string("DocX") }?["methods"], .array([
                .object(["name": .string("save:"), "implementation": .hex(0x1070), "isClassMethod": .bool(false), "selectorUsers": .array([]), "category": .string("Over")]),
            ]))
            let page = try await read(route, "list-image-types", .object(["page": .bool(true), "kind": .string("objcClass")]), store: store)
            XCTAssertEqual(page["rows"], .array(rows))
        }
    }

    func testF8FallbackBeforeExactKeepsAnalysisOrder() async throws {
        let store = makeStore(extra: [("-[Doc(D) late]", 0x10c0), ("-[Doc late]", 0x10d0)])
        let expected = "Ambiguous Objective-C method '-[Doc late]': 2 implementations match (-[Doc(D) late] at 0x10c0, -[Doc late] at 0x10d0); select by a category-qualified name or by `address`."
        for route in [Route.sync, .asynchronous] { try await refusal(route, "decompile", "-[Doc late]", expected, store: store) }
        try await refusal(.mcp, "callers", "-[Doc late]", expected, store: store)
    }

    func testF9RawAndDisplayFallbackArms() async throws {
        let store = makeStore(extra: [("sub_10e0", 0x10e0), ("-[Doc(S) raw2]", 0x10f0)])
        let api = api(store)
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x10e0), "name": .string("-[Doc(R) late2]")]))
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x10f0), "name": .string("plain_raw2")]))
        let display = try api.execute("decompile", arguments: args("-[Doc late2]"))
        XCTAssertEqual(display["address"], .hex(0x10e0)); XCTAssertEqual(display["function"], .string("-[Doc(R) late2]"))
        XCTAssertEqual(try api.execute("decompile", arguments: args("-[Doc raw2]"))["address"], .hex(0x10f0))
        for pair in [("-[Doc late2]", "-[Doc(R) late2]"), ("-[Doc raw2]", "plain_raw2")] {
            let plain = try await mcp("callers", args(pair.0), store: store)
            let exact = try await mcp("callers", args(pair.1), store: store)
            XCTAssertEqual(plain["isError"], .bool(false)); XCTAssertEqual(plain, exact)
        }
    }

    func testF10ReadTimeAnnotationDoesNotAlterStoredCatalog() throws {
        var analysis = ImageAnalysis()
        analysis.objcClasses = [ObjCClass(name: "Doc", superclassName: nil, adoptedProtocols: [], classMethods: [],
            instanceMethods: [method("save:", 0x1000)], ivars: [], properties: [], address: 0x7000)]
        analysis.refreshTypeCatalog()
        analysis.functions = [function("-[Doc(Over) save:]", 0x1000)]
        let snapshot = WorkspaceSnapshot(binaries: [binary()], analysisBySlot: [.primary: analysis])
        let readEntry = try XCTUnwrap(snapshot.typeCatalog(in: .primary).entries.first { $0.name == "Doc" })
        let storedEntry = try XCTUnwrap(snapshot.analysisBySlot[.primary]?.typeCatalog?.entries.first { $0.name == "Doc" })
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(readEntry)["methods"]?.arrayValue?.first?["category"], .string("Over"))
        XCTAssertNil(WorkspaceScriptingAPI.typeAtlasEntryValue(storedEntry)["methods"]?.arrayValue?.first?["category"])
    }

    func testC1ExactNamesAndMissesAndC2ClassEquality() async throws {
        let store = makeStore()
        for (name, address) in [("-[Doc(Over) save:]", UInt64(0x1000)), ("-[Doc isRich]", 0x1010),
            ("-[Doc(A) dup]", 0x1020), ("-[Doc(B) dup]", 0x1030), ("-[Doc(C) both]", 0x1050),
            ("+[Doc(Over) make]", 0x1060), ("-[DocX(Over) save:]", 0x1070), ("-[NSString(Ext) shout]", 0x10a0)] {
            XCTAssertEqual(try api(store).execute("decompile", arguments: args(name))["address"], .hex(address))
        }
        for name in ["-[Doc(Over) dup]", "-[Doc(Wrong) save:]", "-[DocX save]"] {
            let expected = "Invalid argument: no function named '\(name)'."
            try await refusal(.sync, "decompile", name, expected, store: store)
            try await refusal(.mcp, "callers", name, expected, store: store)
        }
        XCTAssertEqual(try api(store).execute("decompile", arguments: args("-[DocX save:]"))["address"], .hex(0x1070))
    }

    func testC3HonestEmptyAllFiveRoutesAndC4RawOnlyAudit() async throws {
        let store = makeStore()
        for command in ["callers", "callees", "basic-blocks", "instructions", "decompile",
                        "register-names", "parameter-binding-audit", "stack-locals", "indirect-call-targets"] {
            for route in Route.allCases {
                try await refusal(route, command, "missing_function",
                    "Invalid argument: no function named 'missing_function'.", store: store)
            }
        }
        try await refusal(.sync, "call-argument-audit", "-[Doc save:]",
            "Invalid argument: no function named '-[Doc save:]'.", store: store)
    }

    func testC5NonObjCAmbiguityUnchanged() async throws {
        let store = makeStore(extra: [("helper", 0x1100), ("helper", 0x1110)])
        let expected = "Ambiguous function selector 'helper': 2 functions match (0x1100, 0x1110); select by `address` instead."
        try await refusal(.sync, "decompile", "helper", expected, store: store)
        try await refusal(.asynchronous, "callers", "helper", expected, store: store)
        try await refusal(.mcp, "callers", "helper", expected, store: store)
    }

    func testC6CategoryRowUnchanged() throws {
        let reply = try api(makeStore()).execute("list-image-types", arguments: .object(["kind": .string("objcCategory")]))
        XCTAssertEqual(reply["types"]?.arrayValue?.first?["name"], .string("NSString (Ext)"))
        XCTAssertEqual(reply["types"]?.arrayValue?.first?["methods"], .array([
            .object(["name": .string("shout"), "implementation": .hex(0x10a0), "isClassMethod": .bool(false), "selectorUsers": .array([])]),
        ]))
    }

    func testC7DuplicateStartAndRawOnlyAnnotationAbstentions() throws {
        let store = makeStore(extra: [("-[Doc(Over) twin]", 0x1090), ("sub_1090", 0x1090)],
            extraMethods: [method("twin", 0x1090), method("save:", 0x1070), method("alias", 0x1000), method("make", 0x1060)])
        let api = api(store)
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x1010), "name": .string("-[Doc(Zed) isRich]")]))
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x1000), "name": .string("plainSave")]))
        XCTAssertEqual(try api.execute("decompile", arguments: args("-[Doc twin]"))["address"], .hex(0x1090))
        XCTAssertEqual(try api.execute("decompile", arguments: args("-[Doc(Zed) isRich]"))["address"], .hex(0x1010))
        let reply = try api.execute("list-image-types", arguments: .object(["kind": .string("objcClass")]))
        let rows = try XCTUnwrap(reply["types"]?.arrayValue?.first { $0["name"] == .string("Doc") }?["methods"]?.arrayValue)
        XCTAssertEqual(rows[0]["category"], .string("Over"))
        for index in [1, 6, 7, 8, 9] { XCTAssertNil(rows[index]["category"]) }
        XCTAssertEqual(rows[10]["category"], .string("Over"))
    }

    func testC6NoCategoryFunctionKeepsLiteralClassReply() async throws {
        let primaryOwner = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
        let siblingOwner = UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!
        var primary = ImageAnalysis()
        primary.swiftTypes = [SwiftTypeDescriptor(kind: .struct, name: "P",
            fields: [SwiftField(name: "v", typeName: "Int")], descriptorAddress: 0x8000)]
        var sibling = ImageAnalysis()
        sibling.objcClasses = [ObjCClass(name: "S", superclassName: "NSObject", adoptedProtocols: ["NSCopying"],
            classMethods: [], instanceMethods: [method("go", 0x9100)],
            ivars: [ObjCIvar(name: "_n", typeEncoding: "i", offset: 8, size: 4)], properties: [],
            address: 0x7100, instanceSize: 12)]
        let snapshot = WorkspaceSnapshot(binaries: [
            BinaryImage(id: primaryOwner, name: "p", path: "/tmp/p", kind: "Mach-O", architecture: "arm64", slot: .primary),
            BinaryImage(id: siblingOwner, name: "s", path: "/tmp/s", kind: "Mach-O", architecture: "arm64", slot: ImageSlot(rawValue: 1)),
        ], analysisBySlot: [.primary: primary, ImageSlot(rawValue: 1): sibling])
        let store = WorkspaceStore(workspaceName: "Unchanged", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
        let expected: ScriptValue = .object([
            "imageSlot": .int(1), "imageOwner": .string("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"), "total": .int(1),
            "types": .array([.object([
                "id": .object(["slot": .int(1), "kind": .string("objcClass"), "address": .hex(0x7100)]),
                "imageSlot": .int(1), "kind": .string("objcClass"), "name": .string("S"), "superclass": .string("NSObject"),
                "members": .array([.object(["name": .string("_n"), "type": .string("int"), "offset": .int(8), "evidence": .string("descriptor"), "size": .int(4)])]),
                "conformances": .array([.string("NSCopying")]),
                "methods": .array([.object(["name": .string("go"), "implementation": .hex(0x9100), "isClassMethod": .bool(false), "selectorUsers": .array([])])]),
                "users": .array([]), "evidence": .string("descriptor"), "instanceSize": .int(12),
            ])]),
        ])
        for route in Route.allCases {
            let reply = try await read(route, "list-image-types", .object(["image": .int(1), "kind": .string("objcClass")]), store: store)
            XCTAssertEqual(reply["types"], expected["types"])
            XCTAssertEqual(reply["imageSlot"], .int(1))
            XCTAssertEqual(reply["imageOwner"], .string("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"))
            XCTAssertEqual(reply["total"], .int(1))
        }
    }

    func testMalformedNamesAndSelectorPrefixDoNotBecomeFallbacks() throws {
        let misses: [(String, String)] = [
            ("-[Doc() x]", "-[Doc x]"), ("-[(Cat) x]", "-[ x]"),
            ("-[Doc(A)(B) x]", "-[Doc x]"), ("-[Doc(A)x y]", "-[Doc y]"),
            ("-[Doc(A) x y]", "-[Doc x y]"), ("-[Doc(A) ]", "-[Doc ]"),
            ("-[Doc(A)]", "-[Doc]"), ("[Doc(A) x]", "[Doc x]"),
            ("_objc_msgSend$x", "-[Doc x]"), ("-[Doc(A) x", "-[Doc x"),
            ("-[Doc(A) x\ty]", "-[Doc x\ty]"), ("-[Doc(A) x:y:]", "-[Doc x:]"),
        ]
        for (raw, requested) in misses {
            let functions = [function(raw, 0x1000)]
            XCTAssertThrowsError(try WorkspaceScriptingAPI.resolveFunctionName(requested, in: functions, displayName: { $0.name })) {
                XCTAssertEqual(($0 as? LocalizedError)?.errorDescription, "Invalid argument: no function named '\(requested)'.")
            }
        }
    }

    func testNewCategoryTextConsumesExistingTypeBudget() throws {
        let category = String(repeating: "C", count: 2_049)
        var analysis = ImageAnalysis()
        analysis.objcClasses = [ObjCClass(name: "Doc", superclassName: nil, adoptedProtocols: [], classMethods: [],
            instanceMethods: [method("save:", 0x1000)], ivars: [], properties: [], address: 0x7000)]
        analysis.refreshTypeCatalog()
        analysis.functions = [function("-[Doc(\(category)) save:]", 0x1000)]
        let snapshot = WorkspaceSnapshot(binaries: [binary()], analysisBySlot: [.primary: analysis])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types", arguments: .object([:]), snapshot: snapshot)) {
            guard case ScriptingError.structuredRefusal(let refusal) = $0 else { return XCTFail("Expected type-budget refusal") }
            XCTAssertEqual(refusal.code, .budgetExceeded)
        }
    }

    func testQ1AmbiguityCannotFallThroughToSameNamedSymbol() async throws {
        let store = makeStore(symbols: [SymbolSummary(id: UUID(), name: "-[Doc dup]", address: 0x3000,
            kind: "stub", libraryName: nil)], extraXRefs: [XRef(id: UUID(), from: 0x1084, to: 0x3000, kind: "call")])
        let expected = "Ambiguous Objective-C method '-[Doc dup]': 2 implementations match (-[Doc(A) dup] at 0x1020, -[Doc(B) dup] at 0x1030); select by a category-qualified name or by `address`."
        for route in Route.allCases { try await refusal(route, "callers", "-[Doc dup]", expected, store: store) }
    }
}
