import Foundation
import XCTest
@testable import MacScope

/// `endpoint-references`: static candidates for where a network endpoint string appears.
/// Fixture: a synthetic WorkspaceStore built in this file (no app or Mints binary); every
/// expected value below is written out here, independent of the production matcher.
@MainActor
final class EndpointReferencesTests: XCTestCase {
    private enum Route: CaseIterable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    private let command = "endpoint-references"
    private let sibling = ImageSlot(rawValue: 1)

    private func request(_ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": arguments])])
    }

    private func envelope(_ route: Route, _ store: WorkspaceStore, _ arguments: ScriptValue) async throws -> ScriptValue {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let data = try request(arguments).jsonData()
        let response: Data?
        if route == .mcpSync { response = server.handleMessage(data) }
        else { response = await server.handleMessageAsync(data) }
        return try ScriptValue.decode(try XCTUnwrap(response))
    }

    private func read(_ route: Route, _ store: WorkspaceStore, _ arguments: ScriptValue) async throws -> ScriptValue {
        let api = WorkspaceScriptingAPI(store: store)
        switch route {
        case .inline: return try api.execute(command, arguments: arguments)
        case .asynchronous: return try await api.executeAsync(command, arguments: arguments)
        case .attached:
            let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
            executor.setConsent(.allowed)
            return try await executor.execute(command, arguments)
        case .mcpSync, .mcpAsync:
            let reply = try await envelope(route, store, arguments)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            return try ScriptValue.decode(Data(text.utf8))
        }
    }

    /// The reply as the wire would carry it, for inline and MCP routes alike.
    private func wire(_ value: ScriptValue) throws -> String {
        String(decoding: try value.jsonData(), as: UTF8.self)
    }

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func makeStore() -> WorkspaceStore {
        func section(_ name: String, _ address: UInt64, _ size: UInt64, _ executable: Bool = false) -> SectionSummary {
            SectionSummary(id: UUID(), name: name, address: address, size: size, fileOffset: 0, isExecutable: executable)
        }
        let sections = [section("__TEXT,__text", 0x1000, 0x100, true), section("__TEXT,__cstring", 0x3000, 0x200),
                        section("__DATA_CONST,__cfstring", 0x4000, 0x80)]
        var primary = ImageAnalysis()
        primary.stringLiteralCoverage = .complete
        primary.functions = [function("fetchItems", 0x1000, 0x1040), function("helper", 0x1040, 0x1080)]
        primary.sections = sections
        let literals: [(UInt64, String)] = [
            (0x3000, "https://api.example.com/v1/items?token=BINSECRET"),
            (0x3040, "api.example.com"),
            (0x3060, "https://api.example.com/v1/users/%@/profile"),
            (0x30a0, "/v1/items"),
            (0x30c0, "https://other.example.org/v1/items"),
            (0x30e0, "https://API.EXAMPLE.COM/v2/ping"),
            (0x3100, "https://x.api.example.com/v1/items"),
            (0x3140, "https://api.example.com/v3/orphan"),
            (0x3160, "GET https://api.example.com/v1/items"),
            (0x3200, "unrelated text"),
        ]
        primary.stringLiterals = literals.map { StringLiteralSummary(id: UUID(), value: $0.1,
            address: $0.0, sourceSection: "__TEXT,__cstring", byteLength: $0.1.utf8.count + 1) }
        primary.constantStrings = ImageConstantStringProvider.build(stringLiterals: primary.stringLiterals,
            cfStrings: [0x4000: "api.example.com"])
        primary.cfStringBackings = .init(complete: true, backings: [0x4000: 0x3040])
        let pairs: [(UInt64, UInt64, String)] = [
            (0x1004, 0x3000, "string"), (0x1008, 0x3000, "string"), (0x1044, 0x3040, "string"),
            (0x1010, 0x4000, "data"), (0x1014, 0x3060, "string"), (0x1018, 0x30a0, "string"),
            (0x101c, 0x30c0, "string"), (0x1020, 0x30e0, "string"), (0x1024, 0x3100, "string"),
            (0x1028, 0x3160, "string"), (0x102c, 0x3200, "string"),
        ]
        primary.xrefs = pairs.map { XRef(id: UUID(), from: $0.0, to: $0.1, kind: $0.2) }
        var other = ImageAnalysis()
        other.stringLiteralCoverage = .complete
        other.functions = [function("sibFetch", 0x1000, 0x1040)]
        other.sections = sections
        other.stringLiterals = [StringLiteralSummary(id: UUID(), value: "https://api.example.com/sibling",
            address: 0x3000, sourceSection: "__TEXT,__cstring", byteLength: 32)]
        other.constantStrings = ImageConstantStringProvider.build(stringLiterals: other.stringLiterals, cfStrings: [:])
        other.xrefs = [XRef(id: UUID(), from: 0x1004, to: 0x3000, kind: "string")]
        let images = [ImageSlot.primary, sibling].map { slot in
            BinaryImage(id: UUID(), name: "endpoint-\(slot.rawValue)", path: "/fixture",
                kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        return WorkspaceStore(workspaceName: "endpoint references", snapshot: WorkspaceSnapshot(
            binaries: images, analysisBySlot: [.primary: primary, sibling: other]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func args(_ host: String, path: String? = nil, method: String? = nil, image: ScriptValue? = nil,
                      limit: Int64? = nil, cursor: String? = nil) -> ScriptValue {
        var fields: [String: ScriptValue] = ["host": .string(host)]
        if let path { fields["path"] = .string(path) }
        if let method { fields["method"] = .string(method) }
        if let image { fields["image"] = image }
        if let limit { fields["limit"] = .int(limit) }
        if let cursor { fields["cursor"] = .string(cursor) }
        return .object(fields)
    }

    /// (matchKind, stringAddress, cfStringAddress, from, fromFunction, fromFunctionName) per row.
    private struct Expected: Equatable {
        let kind: String, string: String, cf: String?, from: String?, function: String?, name: String?
    }

    private func summary(_ reply: ScriptValue) throws -> [Expected] {
        try XCTUnwrap(reply["rows"]?.arrayValue).map { row in
            XCTAssertEqual(row["evidence"], .string("staticCandidate"))
            return Expected(kind: row["matchKind"]?.stringValue ?? "?", string: row["stringAddress"]?.stringValue ?? "?",
                cf: row["cfStringAddress"]?.stringValue, from: row["from"]?.stringValue,
                function: row["fromFunction"]?.stringValue, name: row["fromFunctionName"]?.stringValue)
        }
    }

    private func site(_ kind: String, _ string: String, from: String?, cf: String? = nil) -> Expected {
        let isHelper = from == "0x1044"
        return Expected(kind: kind, string: string, cf: cf, from: from,
            function: from == nil ? nil : (isHelper ? "0x1040" : "0x1000"),
            name: from == nil ? nil : (isHelper ? "helper" : "fetchItems"))
    }

    private var hostOnlyRows: [Expected] {
        [site("hostOnly", "0x3000", from: "0x1004"), site("hostOnly", "0x3000", from: "0x1008"),
         site("hostOnly", "0x3040", from: "0x1044"), site("hostOnly", "0x3040", from: "0x1010", cf: "0x4000"),
         site("hostOnly", "0x3060", from: "0x1014"), site("hostOnly", "0x30e0", from: "0x1020"),
         site("hostOnly", "0x3140", from: nil), site("hostOnly", "0x3160", from: "0x1028")]
    }

    // Acceptance 1: a present host returns its string address and containing function on every route.
    func testHostStringReturnsAddressesAndContainingFunctionOnEveryRoute() async throws {
        let store = makeStore()
        let inline = try await read(.inline, store, args("api.example.com"))
        XCTAssertEqual(try summary(inline), hostOnlyRows)
        XCTAssertEqual(inline["total"], .int(8))
        XCTAssertEqual(inline["isTruncated"], .bool(false))
        XCTAssertEqual(inline["nextCursor"], .null)
        XCTAssertEqual(inline["sourceComplete"], .bool(true))
        XCTAssertEqual(inline["totalIsExact"], .bool(true))
        XCTAssertEqual(inline["evidence"], .string("staticCandidate"))
        let reference = try ScriptValue.decode(try inline.jsonData())
        for route in Route.allCases where route != .inline {
            let other = try await read(route, store, args("api.example.com"))
            XCTAssertEqual(other, reference, "\(route)")
        }
        // The host compare is case-insensitive and exact: upper-case input matches the same rows,
        // other.example.org and x.api.example.com never do.
        let upper = try await read(.inline, store, args("API.Example.COM"))
        XCTAssertEqual(try summary(upper), hostOnlyRows)
    }

    func testMatchKindsForPathQueries() async throws {
        let store = makeStore()
        let exact = try await read(.inline, store, args("api.example.com", path: "/v1/items"))
        XCTAssertEqual(try summary(exact), [
            site("exactURL", "0x3000", from: "0x1004"), site("exactURL", "0x3000", from: "0x1008"),
            site("pathComponent", "0x30a0", from: "0x1018"), site("exactURL", "0x3160", from: "0x1028")])
        let template = try await read(.inline, store, args("api.example.com", path: "/v1/users/42/profile"))
        XCTAssertEqual(try summary(template), [site("pathTemplate", "0x3060", from: "0x1014")])
        XCTAssertEqual(try XCTUnwrap(template["rows"]?.arrayValue?.first?["path"]), .string("/v1/users/:param/profile"))
        // A method filters only strings that carry one; the plain-URL strings stay.
        let post = try await read(.inline, store, args("api.example.com", path: "/v1/items", method: "post"))
        XCTAssertEqual(try summary(post).map(\.string), ["0x3000", "0x3000", "0x30a0"])
        let get = try await read(.inline, store, args("api.example.com", path: "/v1/items", method: "GET"))
        XCTAssertEqual(try summary(get).count, 4)
    }

    // Acceptance 2.
    func testAbsentHostIsAnEmptyCompletePage() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let reply = try await read(route, store, args("absent.example.net"))
            XCTAssertEqual(reply["total"], .int(0), "\(route)")
            XCTAssertEqual(reply["isTruncated"], .bool(false))
            XCTAssertEqual(reply["rows"], .array([]))
            XCTAssertEqual(reply["nextCursor"], .null)
        }
    }

    // Acceptance 3: query values, user-info and fragments never reach any reply or error.
    func testQuerySecretsAreNeverEchoed() async throws {
        let store = makeStore()
        let secretHost = "https://user:PASSWD99@api.example.com:8443/v1/items?token=SECRET123#frag-SECRET123"
        for route in Route.allCases {
            let reply = try await read(route, store, args(secretHost, path: "/v1/items?session=SECRET123#SECRET123"))
            let text = try wire(reply)
            for secret in ["SECRET123", "PASSWD99", "BINSECRET", "frag-", "user:"] {
                XCTAssertFalse(text.contains(secret), "\(route) leaked \(secret)")
            }
            XCTAssertEqual(reply["total"], .int(4), "\(route)")
        }
        let inlineReply = try await read(.inline, store, args("https://api.example.com/v1/items?token=SECRET123"))
        XCTAssertFalse(try wire(inlineReply).contains("SECRET123"))
        // Refusals use fixed text.
        for bad in [args("ftp://api.example.com/?token=SECRET123"), args("api.example.com", path: "v1?token=SECRET123"),
                    args("api.example.com", method: "SECRET123")] {
            do {
                _ = try await read(.inline, store, bad)
                XCTFail("expected a refusal")
            } catch {
                XCTAssertFalse(String(describing: error).contains("SECRET123"))
                XCTAssertFalse((error.localizedDescription).contains("SECRET123"))
            }
            let reply = try await envelope(.mcpSync, store, bad)
            XCTAssertFalse(try wire(reply).contains("SECRET123"))
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
        }
    }

    // Acceptance 4: limit and cursor behave like the sibling pages.
    func testCursorPagingMatchesTheSiblingEnvelope() async throws {
        let store = makeStore()
        let full = try await read(.inline, store, args("api.example.com"))
        var collected: [ScriptValue] = []
        var cursor: String?
        var pages = 0
        repeat {
            let page = try await read(pages.isMultiple(of: 2) ? .inline : .mcpAsync, store,
                                      args("api.example.com", limit: 3, cursor: cursor))
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertLessThanOrEqual(rows.count, 3)
            XCTAssertEqual(page["total"], .int(8))
            collected += rows
            cursor = page["nextCursor"]?.stringValue
            XCTAssertEqual(page["isTruncated"], .bool(cursor != nil))
            pages += 1
        } while cursor != nil && pages < 10
        XCTAssertEqual(pages, 3)
        XCTAssertEqual(collected, try XCTUnwrap(full["rows"]?.arrayValue))

        let first = try await read(.inline, store, args("api.example.com", limit: 3))
        let next = try XCTUnwrap(first["nextCursor"]?.stringValue)
        for (bad, text) in [("bogus", "malformed cursor"), (String(repeating: "A", count: 2_000), "malformed cursor")] {
            do { _ = try await read(.inline, store, args("api.example.com", limit: 3, cursor: bad)); XCTFail() }
            catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(text)) }
        }
        // A cursor belongs to its query and image.
        for other in [args("other.example.org", limit: 3, cursor: next),
                      args("api.example.com", path: "/v1/items", limit: 3, cursor: next),
                      args("api.example.com", image: .int(1), limit: 3, cursor: next)] {
            do { _ = try await read(.inline, store, other); XCTFail("expected stale cursor") }
            catch { XCTAssertTrue((error as? ScriptingError)?.errorDescription?.contains("staleCursor") == true) }
        }
        for limit in [Int64(0), 1_001, -1] {
            do { _ = try await read(.inline, store, args("api.example.com", limit: limit)); XCTFail() }
            catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument("limit must be an integer from 1 to 1000")) }
        }
    }

    func testImageSelectionReadsOneImage() async throws {
        let store = makeStore()
        let reply = try await read(.inline, store, args("api.example.com", image: .int(1)))
        XCTAssertEqual(reply["imageSlot"], .int(1))
        let row = try XCTUnwrap(reply["rows"]?.arrayValue?.first)
        XCTAssertEqual(reply["total"], .int(1))
        XCTAssertEqual(row["fromFunctionName"], .string("sibFetch"))
        XCTAssertEqual(row["imageSlot"], .int(1))
        do { _ = try await read(.inline, store, args("api.example.com", image: .int(9))); XCTFail() }
        catch { XCTAssertTrue(error is ScriptingError) }
    }

    func testRowsDisclosePrivacyMinimizedFieldsOnly() async throws {
        let store = makeStore()
        let reply = try await read(.inline, store, args("api.example.com", path: "/v1/items"))
        let row = try XCTUnwrap(reply["rows"]?.arrayValue?.first)
        XCTAssertEqual(row["scheme"], .string("https"))
        XCTAssertEqual(row["host"], .string("api.example.com"))
        XCTAssertEqual(row["path"], .string("/v1/items"))
        XCTAssertNil(row["value"], "the binary string itself is never echoed")
        XCTAssertEqual(reply["query"]?["host"], .string("api.example.com"))
    }

    func testToolIsRegisteredAsAReadOnlyListedTool() throws {
        let store = makeStore()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let list: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")])
        let tools = try XCTUnwrap(server.handle(list)?["result"]?["tools"]?.arrayValue)
        let tool = try XCTUnwrap(tools.first { $0["name"] == .string(command) })
        XCTAssertEqual(tool["annotations"]?["readOnlyHint"], .bool(true))
        XCTAssertEqual(tool["inputSchema"]?["required"], .array([.string("host")]))
        guard case .object(let properties)? = tool["inputSchema"]?["properties"] else {
            return XCTFail("inputSchema.properties is not an object")
        }
        XCTAssertEqual(Set(properties.keys), ["host", "path", "method", "image", "limit", "cursor"])
    }
}
