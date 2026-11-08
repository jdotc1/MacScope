import Foundation
import XCTest
@testable import MacScope

final class ObjCMethodNamingTests: XCTestCase {
    private typealias Counts = AnalysisEngine.ObjCMethodNameAbstentions
    private typealias Projection = AnalysisEngine.ObjCMethodNameProjection

    private func method(_ selector: String, _ imp: UInt64?, classMethod: Bool = false) -> ObjCMethod {
        ObjCMethod(selector: selector, typeEncoding: nil, isClassMethod: classMethod, implementation: imp)
    }
    private func cls(_ name: String, instance: [ObjCMethod] = [], classMethods: [ObjCMethod] = []) -> ObjCClass {
        ObjCClass(name: name, superclassName: nil, adoptedProtocols: [], classMethods: classMethods,
                  instanceMethods: instance, ivars: [], properties: [])
    }
    private func category(_ name: String, owner: String, instance: [ObjCMethod] = [],
                          classMethods: [ObjCMethod] = []) -> ObjCCategory {
        ObjCCategory(name: name, className: owner, classMethods: classMethods,
                     instanceMethods: instance, adoptedProtocols: [], properties: [])
    }
    private func function(_ start: UInt64, _ end: UInt64, _ name: String) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }
    private func project(_ functions: [FunctionSummary], _ classes: [ObjCClass],
                         categories: [ObjCCategory] = [], named: Set<UInt64> = [],
                         existing: [String] = []) -> Projection {
        AnalysisEngine.projectObjCMethodNames(functions: functions, classes: classes,
            categories: categories, namedAddresses: named, existingNames: existing)
    }
    private func check(_ result: Projection, names: [String], symbols: [(UInt64, String)], counts: Counts,
                       file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(result.functions.map(\.name), names, file: file, line: line)
        XCTAssertEqual(result.symbols.count, symbols.count, file: file, line: line)
        for (actual, expected) in zip(result.symbols, symbols) {
            XCTAssertEqual(actual.address, expected.0, file: file, line: line)
            XCTAssertEqual(actual.name, expected.1, file: file, line: line)
            XCTAssertEqual(actual.kind, "objc-method", file: file, line: line)
            XCTAssertNil(actual.libraryName, file: file, line: line)
            XCTAssertNil(actual.rawLinkageName, file: file, line: line)
        }
        XCTAssertEqual(result.abstentions, counts, file: file, line: line)
    }

    func testT1InstanceMethodPreservesEveryOtherFunctionField() {
        var input = function(0x1000, 0x1010, "sub_0x0000000000001000")
        input.noReturnProvenance = .catalog
        let result = project([input], [cls("Widget", instance: [method("draw", 0x1000)])])
        check(result, names: ["-[Widget draw]"], symbols: [(0x1000, "-[Widget draw]")],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
        var expected = input
        expected.name = "-[Widget draw]"
        XCTAssertEqual(result.functions, [expected])
    }

    func testT2ClassMethod() {
        let input = function(0x2000, 0x2010, "sub_0x0000000000002000")
        let result = project([input], [cls("Widget", classMethods: [method("shared", 0x2000, classMethod: true)])])
        check(result, names: ["+[Widget shared]"], symbols: [(0x2000, "+[Widget shared]")],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
    }

    func testT3CategoryAndPreexistingAddress() {
        let functions = [function(0x1000, 0x1010, "sub_0x0000000000001000"),
                         function(0x2000, 0x2010, "sub_0x0000000000002000"),
                         function(0x3000, 0x3010, "sub_0x0000000000003000"),
                         function(0x4000, 0x4010, "sub_0x0000000000004000")]
        var classes = [cls("Widget", instance: [method("draw", 0x1000), method("named", 0x3000), method("external", nil)],
                           classMethods: [method("shared", 0x2000, classMethod: true)])]
        classes[0].superclassName = "NSObject"
        let categories = [category("Extras", owner: "NSString", instance: [method("shout", 0x4000)])]
        let result = project(functions, classes, categories: categories, named: [0x3000])
        check(result, names: ["-[Widget draw]", "+[Widget shared]", "sub_0x0000000000003000", "-[NSString(Extras) shout]"],
            symbols: [(0x1000, "-[Widget draw]"), (0x2000, "+[Widget shared]"), (0x4000, "-[NSString(Extras) shout]")],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 1,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
        let comments = AnalysisEngine.objcImplementationComments(classes: classes, categories: categories, namedAddresses: [0x3000])
        for symbol in result.symbols {
            XCTAssertEqual(comments[symbol.address!], "Objective C implementation of " + symbol.name)
        }
    }

    func testT4AllPrecedenceSteps() {
        let functions = [function(0x1000, 0x1010, "_draw"),
                         function(0x2000, 0x2010, "sub_0x0000000000002000"),
                         function(0x3000, 0x3010, "_entry"), function(0x4000, 0x4010, "__text"),
                         function(0x5000, 0x5010, "signatureName"),
                         function(0x6000, 0x6010, "sub_0x0000000000006000")]
        let classes = [cls("Widget", instance: [method("draw", 0x1000), method("stub", 0x2000),
            method("entry", 0x3000), method("text", 0x4000), method("signature", 0x5000), method("plain", 0x6000)])]
        let result = project(functions, classes, named: [0x1000, 0x2000])
        check(result, names: ["_draw", "sub_0x0000000000002000", "_entry", "__text", "signatureName", "-[Widget plain]"],
            symbols: [(0x6000, "-[Widget plain]")],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 4, alreadyNamed: 1,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
    }

    func testT5DistinctTextsShareAnImplementation() {
        let input = function(0x3000, 0x3010, "sub_0x0000000000003000")
        let classes = [cls("A", instance: [method("x", 0x3000)]), cls("B", instance: [method("y", 0x3000)])]
        let result = project([input], classes)
        check(result, names: ["sub_0x0000000000003000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 1, textNotUnique: 0, existingNameCollision: 0))
        XCTAssertEqual(result.functions, [input])
        XCTAssertEqual(AnalysisEngine.objcImplementationComments(classes: classes, categories: [], namedAddresses: [])[0x3000],
                       "Objective C implementation of -[A x], -[B y]")
    }

    func testT6IdenticalDuplicatesAreNotSharedTexts() {
        let result = project([function(0x1000, 0x1010, "sub_0x0000000000001000")],
            [cls("Widget", instance: [method("draw", 0x1000), method("draw", 0x1000)])])
        check(result, names: ["-[Widget draw]"], symbols: [(0x1000, "-[Widget draw]")],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
    }

    func testT7OneTextAtTwoStartsAbstainsAtBoth() {
        let result = project([function(0x5000, 0x5010, "sub_0x0000000000005000"), function(0x6000, 0x6010, "sub_0x0000000000006000")],
            [cls("Dup", instance: [method("run", 0x5000)]), cls("Dup", instance: [method("run", 0x6000)])])
        check(result, names: ["sub_0x0000000000005000", "sub_0x0000000000006000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 2, existingNameCollision: 0))
    }

    func testT8InteriorIMPIsOutsideTheNamingPopulation() {
        let result = project([function(0x1000, 0x1010, "sub_0x0000000000001000")],
                             [cls("Widget", instance: [method("inside", 0x1004)])])
        check(result, names: ["sub_0x0000000000001000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
    }

    func testT9NilZeroAndOutsideIMPsAreNotCandidates() {
        let result = project([function(0x1000, 0x1010, "sub_0x0000000000001000")],
                             [cls("Widget", instance: [method("nil", nil), method("zero", 0), method("outside", 0x3000)])])
        check(result, names: ["sub_0x0000000000001000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
    }

    func testT10SwiftExposedClassKeepsRuntimeSpelling() {
        let result = project([function(0x10002ce24, 0x10002ce34, "sub_0x000000010002ce24")],
            [cls("_TtC5Mints11AppDelegate", instance: [method("applicationDidFinishLaunching:", 0x10002ce24)])])
        check(result, names: ["-[_TtC5Mints11AppDelegate applicationDidFinishLaunching:]"],
            symbols: [(0x10002ce24, "-[_TtC5Mints11AppDelegate applicationDidFinishLaunching:]")],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
    }

    func testT11ReversalPreservesStartNameMapAndSymbolValues() {
        let functions = [function(0x1000, 0x1010, "sub_0x0000000000001000"),
                         function(0x3000, 0x3010, "sub_0x0000000000003000"),
                         function(0x5000, 0x5010, "sub_0x0000000000005000"),
                         function(0x6000, 0x6010, "sub_0x0000000000006000")]
        let classes = [cls("Widget", instance: [method("draw", 0x1000)]),
                       cls("A", instance: [method("x", 0x3000)]), cls("B", instance: [method("y", 0x3000)]),
                       cls("Dup", instance: [method("run", 0x5000)]), cls("Dup", instance: [method("run", 0x6000)])]
        let first = project(functions, classes)
        let second = project(Array(functions.reversed()), Array(classes.reversed()))
        let expected: [UInt64: String] = [0x1000: "-[Widget draw]", 0x3000: "sub_0x0000000000003000",
                                        0x5000: "sub_0x0000000000005000", 0x6000: "sub_0x0000000000006000"]
        for result in [first, second] {
            XCTAssertEqual(Dictionary(uniqueKeysWithValues: result.functions.map { ($0.startAddress, $0.name) }), expected)
            XCTAssertEqual(result.symbols.map(\.address), [0x1000])
            XCTAssertEqual(result.symbols.map(\.name), ["-[Widget draw]"])
            XCTAssertEqual(result.symbols.map(\.kind), ["objc-method"])
            XCTAssertTrue(result.symbols.allSatisfy { $0.libraryName == nil && $0.rawLinkageName == nil })
            XCTAssertEqual(result.abstentions, .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                                                   sharedImplementation: 1, textNotUnique: 2, existingNameCollision: 0))
        }
    }

    func testT16CaseCollisionAtDifferentStarts() {
        let result = project([function(0x5000, 0x5010, "sub_0x0000000000005000"), function(0x6000, 0x6010, "sub_0x0000000000006000")],
            [cls("Dup", instance: [method("run", 0x5000)]), cls("dup", instance: [method("run", 0x6000)])])
        check(result, names: ["sub_0x0000000000005000", "sub_0x0000000000006000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 2, existingNameCollision: 0))
    }

    func testT17ExistingFunctionOrUnderscoredSymbolNameCollision() {
        let input = function(0x1000, 0x1010, "sub_0x0000000000001000")
        let classes = [cls("Widget", instance: [method("draw", 0x1000)])]
        let a = project([input, function(0x9000, 0x9010, "-[widget draw]")], classes, named: [0x9000])
        check(a, names: ["sub_0x0000000000001000", "-[widget draw]"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 1))
        let b = project([input], classes, existing: ["_-[WIDGET DRAW]"])
        check(b, names: ["sub_0x0000000000001000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 1))
    }

    func testT18DuplicateFunctionStartCountsBothRowsBeforeOtherRules() {
        let functions = [function(0x7000, 0x7010, "sub_0x0000000000007000"),
                         function(0x7000, 0x7020, "sub_0x0000000000007000")]
        let result = project(functions, [cls("Widget", instance: [method("go", 0x7000)])])
        check(result, names: ["sub_0x0000000000007000", "sub_0x0000000000007000"], symbols: [],
            counts: .init(duplicateFunctionStart: 2, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
        XCTAssertEqual(result.functions, functions)
    }

    func testEmptyMethodListPreservesInput() {
        let input = function(0x1000, 0x1010, "sub_0x0000000000001000")
        let result = project([input], [])
        check(result, names: ["sub_0x0000000000001000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 0, textNotUnique: 0, existingNameCollision: 0))
        XCTAssertEqual(result.functions, [input])
    }

    func testSharedIMPTextAlsoBlocksAnotherCandidateName() {
        let result = project([function(0x1000, 0x1010, "sub_0x0000000000001000"),
                              function(0x2000, 0x2010, "sub_0x0000000000002000")],
            [cls("Widget", instance: [method("draw", 0x1000), method("draw", 0x2000)]),
             cls("Other", instance: [method("alternate", 0x2000)])])
        check(result, names: ["sub_0x0000000000001000", "sub_0x0000000000002000"], symbols: [],
            counts: .init(duplicateFunctionStart: 0, notFallbackName: 0, alreadyNamed: 0,
                          sharedImplementation: 1, textNotUnique: 1, existingNameCollision: 0))
    }

    private func analyzedFixture() throws -> (snapshot: WorkspaceSnapshot, base: UInt64) {
        let fixture = MachOFixture.makeExecutableWithCategoryOnlyRelativeIMPs()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("objc-naming-\(UUID().uuidString)")
        try fixture.bytes.write(to: url)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return (try AnalysisEngine().analyze(url: url), fixture.baseAddress)
    }

    func testT13CategoryRelativeIMPsAreNamedWithoutChangingCommentsOrEntry() throws {
        let (snapshot, base) = try analyzedFixture()
        XCTAssertEqual(snapshot.functions.first { $0.startAddress == base }?.name, "_entry")
        XCTAssertEqual(snapshot.functions.first { $0.startAddress == base + 0x20 }?.name, "-[Owner(Extra) first]")
        XCTAssertEqual(snapshot.functions.first { $0.startAddress == base + 0x30 }?.name, "+[Owner(Extra) second]")
        let symbols = snapshot.symbols.filter { $0.kind == "objc-method" }
        XCTAssertEqual(symbols.map(\.address), [base + 0x20, base + 0x30])
        XCTAssertEqual(symbols.map(\.name), ["-[Owner(Extra) first]", "+[Owner(Extra) second]"])
        XCTAssertTrue(symbols.allSatisfy { $0.rawLinkageName == nil && $0.libraryName == nil })
        XCTAssertTrue(snapshot.instructions.first { $0.address == base + 0x20 }?.comment?
            .contains("Objective C implementation of -[Owner(Extra) first]") == true)
        XCTAssertTrue(snapshot.instructions.first { $0.address == base + 0x30 }?.comment?
            .contains("Objective C implementation of +[Owner(Extra) second]") == true)
    }

    private enum Route: CaseIterable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    @MainActor
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
            let server = MCPServer(api: api)
            let request = try ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
                "method": .string("tools/call"), "params": .object(["name": .string(command), "arguments": arguments])]).jsonData()
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

    @MainActor
    func testT14ViewsAgreeAndUserRenameWinsOnAnalyzedStore() async throws {
        let (snapshot, base) = try analyzedFixture()
        let store = WorkspaceStore(workspaceName: "objc-naming", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let target = base + 0x20
        for route in Route.allCases {
            let name = try await read(route, store, "name-at", .object(["address": .hex(target)]))
            XCTAssertEqual(name, .string("-[Owner(Extra) first]"))
            let functions = try await read(route, store, "functions", .object([:]))
            XCTAssertEqual(functions.arrayValue?.first { $0["address"] == .hex(target) }?["name"], .string("-[Owner(Extra) first]"))
            let symbols = try await read(route, store, "symbols", .object(["kind": .string("objc-method")]))
            XCTAssertEqual(symbols.arrayValue?.first { $0["address"] == .hex(target) }?["name"], .string("-[Owner(Extra) first]"))
        }
        XCTAssertEqual(store.snapshot.address(forSymbolName: "-[Owner(Extra) first]", in: .primary), target)
        _ = try WorkspaceScriptingAPI(store: store).execute("rename",
            arguments: .object(["address": .hex(target), "name": .string("userName")]))
        for route in Route.allCases {
            let name = try await read(route, store, "name-at", .object(["address": .hex(target)]))
            XCTAssertEqual(name, .string("userName"))
            let functions = try await read(route, store, "functions", .object([:]))
            XCTAssertEqual(functions.arrayValue?.first { $0["address"] == .hex(target) }?["name"], .string("userName"))
            let symbols = try await read(route, store, "symbols", .object(["kind": .string("objc-method")]))
            XCTAssertEqual(symbols.arrayValue?.first { $0["address"] == .hex(target) }?["name"], .string("-[Owner(Extra) first]"))
        }
    }

    @MainActor
    func testT15ObjCMethodKindFiltersOnEveryReadRoute() async throws {
        let (snapshot, base) = try analyzedFixture()
        let store = WorkspaceStore(workspaceName: "objc-kind", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        for route in Route.allCases {
            let rows = try await read(route, store, "symbols", .object(["kind": .string("objc-method")]))
            XCTAssertEqual(rows.arrayValue?.compactMap { $0["name"]?.stringValue },
                           ["-[Owner(Extra) first]", "+[Owner(Extra) second]"])
            XCTAssertEqual(rows.arrayValue?.map { $0["address"] }, [.hex(base + 0x20), .hex(base + 0x30)])
            XCTAssertTrue(rows.arrayValue?.allSatisfy { $0["kind"] == .string("objc-method") } == true)
        }
    }
}
