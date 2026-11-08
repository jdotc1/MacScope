import Foundation
import XCTest
@testable import MacScope

// Authored from packet 1316 at d5c9adf92727acd63621c7895c4c747e340a7ca8.
// Unrun. Requires all WIRING rows and the variant-F diagnostic helper.
@MainActor
final class SyncTypeListBudgetTests: XCTestCase {
    private static let owner = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    private static let detail = "Type read exceeds the finite preparation or nested-result budget; narrow the workspace type catalog."

    private func api(definitions: [TypeDefinition] = [], entries: [TypeAtlasEntry] = []) -> WorkspaceScriptingAPI {
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: Self.owner, name: "types", path: "/unused/types",
                                  kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: analysis], typeDefinitions: definitions)
        let store = WorkspaceStore(workspaceName: "Sync type budget", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        return WorkspaceScriptingAPI(store: store)
    }

    private func definition(_ fieldCount: Int) -> TypeDefinition {
        TypeDefinition(kind: .struct, name: "U",
                       fields: (0..<fieldCount).map { _ in FieldDef(name: "x", type: "int") })
    }

    private func small(_ index: Int) -> TypeAtlasEntry {
        TypeAtlasEntry(id: .init(slot: .primary, kind: .objcClass,
                                key: .address(UInt64(4096 + index * 16))),
                       kind: .objcClass, name: "C\(index)", superclass: nil,
                       members: [], conformances: [], methods: [], users: [], evidence: .descriptor)
    }

    private func synchronousError(_ api: WorkspaceScriptingAPI, _ command: String,
                                  _ arguments: ScriptValue = .object([:])) throws -> Error {
        do {
            _ = try api.execute(command, arguments: arguments)
        } catch { return error }
        XCTFail("Expected a refusal from \(command)")
        throw ScriptingError.invalidArgument("test expected refusal")
    }

    private func asynchronousError(_ api: WorkspaceScriptingAPI, _ command: String,
                                   _ arguments: ScriptValue = .object([:])) async throws -> Error {
        do {
            _ = try await api.executeAsync(command, arguments: arguments)
        } catch { return error }
        XCTFail("Expected an asynchronous refusal from \(command)")
        throw ScriptingError.invalidArgument("test expected refusal")
    }

    private func assertRefusalParity(_ api: WorkspaceScriptingAPI, _ command: String,
                                     arguments: ScriptValue = .object([:]),
                                     unit: MCPRefusalBudget.Unit, limit: Int64, used: Int64,
                                     detail: String? = nil,
                                     narrowing: [String] = []) async throws {
        let sync = try XCTUnwrap(MCPToolRefusal.executionRefusal(synchronousError(api, command, arguments)))
        let asyncError = try await asynchronousError(api, command, arguments)
        let asynchronous = try XCTUnwrap(MCPToolRefusal.executionRefusal(asyncError))
        let expected = MCPToolRefusal(code: .budgetExceeded, detail: detail ?? Self.detail,
            budget: .init(unit: unit, limit: limit), used: used, narrowing: narrowing)
        XCTAssertEqual(sync, expected)
        XCTAssertEqual(asynchronous, expected)
        XCTAssertEqual(sync.value, asynchronous.value)
        XCTAssertEqual(try sync.value.jsonData(), try asynchronous.value.jsonData())
        XCTAssertEqual(sync.value["refusal"]?["code"], .string("budgetExceeded"))
        XCTAssertEqual(sync.value["refusal"]?["budget"],
                       .object(["unit": .string(unit.rawValue), "limit": .int(limit)]))
        XCTAssertEqual(sync.value["refusal"]?["used"], .int(used))
        XCTAssertEqual(sync.value["refusal"]?["narrowing"], .array(narrowing.map { .string($0) }))
    }

    // SYNC-LIST-TYPES-IDENTICAL: the literal is hand-derived from the old SY1 closure.
    func testListTypesMatchesLiteralOldSyncAndAsyncBytes() async throws {
        let api = api(definitions: [definition(1)])
        let expected: ScriptValue = .array([.object([
            "name": .string("U"), "kind": .string("struct"),
            "fields": .array([.object(["name": .string("x"), "type": .string("int")])])
        ])])
        let sync = try api.execute("list-types")
        let asynchronous = try await api.executeAsync("list-types", arguments: .object([:]))
        XCTAssertEqual(sync, expected)
        XCTAssertEqual(asynchronous, expected)
        XCTAssertEqual(try sync.jsonData(), try expected.jsonData())
        XCTAssertEqual(try sync.jsonData(), try asynchronous.jsonData())
    }

    // SYNC-LIST-IMAGE-TYPES-IDENTICAL. Literal old projection, including array order.
    // Supplement: TypeAtlas.swift:9-52,81-84; ImageSelector.swift:124-131.
    func testImageTypesMatchesLiteralOldSyncAndAsyncBytes() async throws {
        let api = api(entries: [small(1), small(0)])
        let expected: ScriptValue = .object([
            "imageSlot": .int(0),
            "imageOwner": .string("11111111-2222-3333-4444-555555555555"),
            "total": .int(2),
            "types": .array([
                .object([
                    "id": .object(["slot": .int(0), "kind": .string("objcClass"), "address": .hex(0x1010)]),
                    "imageSlot": .int(0), "kind": .string("objcClass"), "name": .string("C1"),
                    "superclass": .null, "members": .array([]), "conformances": .array([]),
                    "methods": .array([]), "users": .array([]), "evidence": .string("descriptor")
                ]),
                .object([
                    "id": .object(["slot": .int(0), "kind": .string("objcClass"), "address": .hex(0x1000)]),
                    "imageSlot": .int(0), "kind": .string("objcClass"), "name": .string("C0"),
                    "superclass": .null, "members": .array([]), "conformances": .array([]),
                    "methods": .array([]), "users": .array([]), "evidence": .string("descriptor")
                ])
            ])
        ])
        let sync = try api.execute("list-image-types")
        let asynchronous = try await api.executeAsync("list-image-types", arguments: .object([:]))
        XCTAssertEqual(sync, expected)
        XCTAssertEqual(asynchronous, expected)
        XCTAssertEqual(try sync.jsonData(), try expected.jsonData())
        XCTAssertEqual(try sync.jsonData(), try asynchronous.jsonData())
    }

    // SYNC-LIST-TYPES-REFUSAL-P1, SYNC-LIST-IMAGE-TYPES-REFUSAL-P1,
    // SYNC-ASYNC-REFUSAL-PARITY. One definition + 5001 fields = 5002 nodes.
    func testOversizedUserFieldsRefuseOnBothCommandsWithP1Parity() async throws {
        let api = api(definitions: [definition(5_001)])
        for command in ["list-types", "list-image-types"] {
            try await assertRefusalParity(api, command, unit: .nodes, limit: 4_096, used: 5_002)
        }
    }

    // Cached catalog preflight fails inside the page-advice conversion, not at definitions.
    func testCachedCatalogRefusalPreservesPageAdviceAndMeasuredNodes() async throws {
        let api = api(entries: (0..<4_096).map(small))
        try await assertRefusalParity(api, "list-image-types", unit: .nodes, limit: 4_096, used: 4_097,
            detail: Self.detail + " " + WorkspaceScriptingAPI.typeAtlasPageHint, narrowing: ["page"])
    }

    // SYNC-BUDGET-EDGE: exactly 4096 nodes, then one additional field.
    func testNodeBoundaryAndOneNodeMore() async throws {
        let fit = api(definitions: [definition(4_095)])
        let sync = try fit.execute("list-types")
        let asynchronous = try await fit.executeAsync("list-types", arguments: .object([:]))
        XCTAssertEqual(sync, asynchronous)
        XCTAssertEqual(sync.arrayValue?.first?["fields"]?.arrayValue?.count, 4_095)
        try await assertRefusalParity(api(definitions: [definition(4_096)]), "list-types",
                                     unit: .nodes, limit: 4_096, used: 4_097)
    }

    // 128 names * 2048 ASCII bytes = 262144; one extra one-byte name crosses only bytes.
    func testAggregateByteBoundaryAndOneByteMore() async throws {
        let name = String(repeating: "a", count: 2_048)
        let definitions = (0..<128).map { _ in TypeDefinition(kind: .struct, name: name, fields: []) }
        let fit = api(definitions: definitions)
        let sync = try fit.execute("list-types")
        let asynchronous = try await fit.executeAsync("list-types", arguments: .object([:]))
        XCTAssertEqual(sync, asynchronous)
        XCTAssertEqual(sync.arrayValue?.count, 128)
        let over = definitions + [TypeDefinition(kind: .struct, name: "a", fields: [])]
        try await assertRefusalParity(api(definitions: over), "list-types",
                                     unit: .bytes, limit: 262_144, used: 262_145)
    }

    // Each name alone remains subject to the existing 2048-byte text bound.
    func testSingleStringBoundaryAndOneByteMore() async throws {
        let fit = api(definitions: [TypeDefinition(kind: .struct,
            name: String(repeating: "a", count: 2_048), fields: [])])
        XCTAssertEqual(try fit.execute("list-types").arrayValue?.count, 1)
        let over = api(definitions: [TypeDefinition(kind: .struct,
            name: String(repeating: "a", count: 2_049), fields: [])])
        try await assertRefusalParity(over, "list-types", unit: .bytes, limit: 2_048, used: 2_049)
    }

    // With N unrelated one-field definitions, layout consumes N + N*(N-1) = N*N.
    func testWorkBoundaryAndFirstRefusedStep() async throws {
        func definitions(_ count: Int) -> [TypeDefinition] {
            (0..<count).map { index in
                TypeDefinition(kind: .struct, name: "D\(index)",
                               fields: [FieldDef(name: "x", type: "int")])
            }
        }
        var budget = AttachedTypeReadBudget()
        try budget.definitions(definitions(1_000), includeLayout: true, checkpoint: {})
        XCTAssertThrowsError(try budget.charge(1)) { error in
            XCTAssertEqual(error as? ScriptingError, AttachedTypeReadBudget.refused)
        }
        try await assertRefusalParity(api(definitions: definitions(1_001)), "list-image-types",
                                     unit: .workSteps, limit: 1_000_000, used: 1_000_001)
    }

    func testUnrepresentableWorkKeepsSentinelAndReportsExplicitNullUsed() throws {
        var budget = AttachedTypeReadBudget()
        let thrown = budget.recordRefusal(unit: .workSteps, limit: 1_000_000, used: nil)
        XCTAssertEqual(thrown, AttachedTypeReadBudget.refused)
        let reported = budget.reportingRefusal(thrown)
        let refusal = try XCTUnwrap(MCPToolRefusal.executionRefusal(reported))
        XCTAssertEqual(refusal.code, .budgetExceeded)
        XCTAssertEqual(refusal.detail, Self.detail)
        XCTAssertEqual(refusal.narrowing, [])
        XCTAssertEqual(refusal.value["refusal"]?["budget"],
                       .object(["unit": .string("workSteps"), "limit": .int(1_000_000)]))
        XCTAssertEqual(refusal.value["refusal"]?["used"], .null)
    }

    // SYNC-PAGE-PATH: a cursor obtained on the synchronous route is valid on both routes.
    func testFirstAndCursorPagesAgree() async throws {
        let api = api(entries: [small(0), small(1)])
        let firstArgs: ScriptValue = .object(["page": .bool(true), "fields": .string("names"), "limit": .int(1)])
        let syncFirst = try api.execute("list-image-types", arguments: firstArgs)
        let asyncFirst = try await api.executeAsync("list-image-types", arguments: firstArgs)
        XCTAssertEqual(syncFirst, asyncFirst)
        XCTAssertEqual(try syncFirst.jsonData(), try asyncFirst.jsonData())
        XCTAssertEqual(syncFirst["rows"]?.arrayValue?.count, 1)
        XCTAssertEqual(syncFirst["isTruncated"], .bool(true))
        let cursor = try XCTUnwrap(syncFirst["nextCursor"]?.stringValue)
        let nextArgs: ScriptValue = .object(["page": .bool(true), "fields": .string("names"),
                                             "limit": .int(1), "cursor": .string(cursor)])
        let syncNext = try api.execute("list-image-types", arguments: nextArgs)
        let asyncNext = try await api.executeAsync("list-image-types", arguments: nextArgs)
        XCTAssertEqual(syncNext, asyncNext)
        XCTAssertEqual(try syncNext.jsonData(), try asyncNext.jsonData())
        XCTAssertEqual(syncNext["rows"]?.arrayValue?.count, 1)
        XCTAssertEqual(syncNext["isTruncated"], .bool(false))
        XCTAssertEqual(syncNext["nextCursor"], .null)
        XCTAssertNotEqual(syncFirst["rows"], syncNext["rows"])
    }

    // SYNC-LIMIT-DEFAULT: a cap above the catalog cardinality cannot change its reply.
    func testOmittedAndAboveFiveThousandLimitsPreserveSmallCatalog() async throws {
        let api = api(entries: [small(0), small(1)])
        let baseline = try api.execute("list-image-types")
        let arguments: [ScriptValue] = [.object([:]), .object(["limit": .int(5_001)]),
                                       .object(["limit": .int(10_000)])]
        for args in arguments {
            let sync = try api.execute("list-image-types", arguments: args)
            let asynchronous = try await api.executeAsync("list-image-types", arguments: args)
            XCTAssertEqual(sync, baseline)
            XCTAssertEqual(asynchronous, baseline)
            XCTAssertEqual(try sync.jsonData(), try baseline.jsonData())
        }
    }

    // SYNC-VALIDATION-ORDER: the chosen async ordering rejects definitions before kind.
    func testDefinitionBudgetPrecedesBadKindButPageValidationStaysFirst() async throws {
        let over = api(definitions: [definition(5_001)])
        let badKinds: [ScriptValue] = [.int(1), .string("not-a-kind")]
        for kind in badKinds {
            try await assertRefusalParity(over, "list-image-types", arguments: .object(["kind": kind]),
                                         unit: .nodes, limit: 4_096, used: 5_002)
        }
        let badPage: ScriptValue = .object(["page": .string("invalid"), "kind": .int(1)])
        let sync = try synchronousError(over, "list-image-types", badPage)
        let asynchronous = try await asynchronousError(over, "list-image-types", badPage)
        XCTAssertEqual(sync as? ScriptingError, .invalidArgument("page must be a boolean"))
        XCTAssertEqual(asynchronous as? ScriptingError, .invalidArgument("page must be a boolean"))
        let small = api()
        let badKind: ScriptValue = .object(["kind": .int(1)])
        let syncKind = try synchronousError(small, "list-image-types", badKind)
        let asyncKind = try await asynchronousError(small, "list-image-types", badKind)
        XCTAssertEqual(syncKind as? ScriptingError, .invalidArgument("kind must be a string"))
        XCTAssertEqual(asyncKind as? ScriptingError, .invalidArgument("kind must be a string"))
    }

    // Supplement ImageSelector.swift:31-66,134-143 fixes the exact selector/valid-slot value.
    func testDefinitionsPrecedeUnknownImageAndUnknownImagePrecedesKind() async throws {
        let args: ScriptValue = .object(["image": .int(99), "kind": .int(1)])
        let small = api()
        let sync = try synchronousError(small, "list-image-types", args)
        let asynchronous = try await asynchronousError(small, "list-image-types", args)
        let expected = ScriptingError.unknownImage(selector: "99", validSlots: [0])
        XCTAssertEqual(sync as? ScriptingError, expected)
        XCTAssertEqual(asynchronous as? ScriptingError, expected)
        try await assertRefusalParity(api(definitions: [definition(5_001)]), "list-image-types",
                                     arguments: args, unit: .nodes, limit: 4_096, used: 5_002)
    }

    // SYNC-LIST-TYPES-IGNORES-ARGS: not even malformed atlas-only arguments affect SY1.
    func testListTypesIgnoresArbitraryArguments() async throws {
        let api = api(definitions: [definition(1)])
        let baseline = try api.execute("list-types")
        let args: ScriptValue = .object(["limit": .double(1.5), "kind": .int(7),
            "image": .string("not-an-image"), "page": .string("invalid"),
            "cursor": .bool(true), "fields": .string("not-fields"), "extra": .array([.null])])
        let sync = try api.execute("list-types", arguments: args)
        let asynchronous = try await api.executeAsync("list-types", arguments: args)
        XCTAssertEqual(sync, baseline)
        XCTAssertEqual(asynchronous, baseline)
        XCTAssertEqual(try sync.jsonData(), try baseline.jsonData())
    }
}
