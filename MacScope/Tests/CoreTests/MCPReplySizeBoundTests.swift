// Authored, unrun.
import Foundation
import XCTest
@testable import MacScope

@MainActor
final class MCPReplySizeBoundTests: XCTestCase {
    private let cap = 196_608

    private func bound(_ output: ScriptValue, tool: String, bytes: Int,
                       structuredBytes: Int? = nil,
                       strict: Bool = false, label: String,
                       file: StaticString = #filePath, line: UInt = #line) throws {
        for version in [MCPResultProtocol.legacy, .structured] {
            let wire = try mcpToolReplyJSONByteCount(output: output, tool: tool,
                generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(1)) + 1
            let context = "\(label), \(version.rawValue), frame+LF=\(wire)"
            let limit = version == .structured ? (structuredBytes ?? bytes) : bytes
            if strict { XCTAssertLessThan(wire, limit, context, file: file, line: line) }
            else { XCTAssertLessThanOrEqual(wire, limit, context, file: file, line: line) }
        }
    }

    private func serverBound(_ api: WorkspaceScriptingAPI, tool: String,
                             args: ScriptValue, bytes: Int,
                             file: StaticString = #filePath, line: UInt = #line) throws {
        let configuration = MCPServer.Configuration(maximumInputBytes: 65_536,
            maximumOutputBytes: 8 * 1_024 * 1_024,
            maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 16)
        let server = MCPServer(api: api, configuration: configuration)
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
            "method": .string("tools/call"),
            "params": .object(["name": .string(tool), "arguments": args])])
        // No initialize: this is the legacy server route, independent of the oracle.
        let data = try XCTUnwrap(server.handleMessage(try request.jsonData()), file: file, line: line)
        let frame = try ScriptValue.decode(data)
        XCTAssertNil(frame["error"], file: file, line: line)
        XCTAssertEqual(frame["result"]?["isError"], .bool(false), file: file, line: line)
        guard frame["error"] == nil, frame["result"]?["isError"] == .bool(false) else { return }
        let text = try XCTUnwrap(frame["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue,
                                 file: file, line: line)
        let payload = try ScriptValue.decode(Data(text.utf8))
        XCTAssertNotNil(payload[tool == "function-facts" ? "calls" : "rows"], file: file, line: line)
        XCTAssertLessThanOrEqual(data.count + 1, bytes,
            "\(tool) server frame+LF=\(data.count + 1)", file: file, line: line)
    }

    func testT3WalkReaches18884RowsIn19BoundedPages() throws {
        // Ghostty-shaped count only. Names are assumed to be 24 ASCII bytes;
        // addresses and names are synthetic, not measurements of the real app.
        let store = MCPReplySizeBoundFixtures.functions(count: 18_884) {
            MCPReplySizeBoundFixtures.asciiName(24, ordinal: $0)
        }
        let api = WorkspaceScriptingAPI(store: store)
        let expected = try XCTUnwrap(try api.execute("functions").arrayValue)
        XCTAssertEqual(expected.count, 18_884)
        var collected: [ScriptValue] = [], cursor: String?
        var visited = Set<String>()
        for pageNumber in 0..<19 {
            var args: [String: ScriptValue] = ["page": .bool(true), "limit": .int(1_000)]
            if let cursor { args["cursor"] = .string(cursor) }
            let page = try api.execute("functions", arguments: .object(args))
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(rows.count, pageNumber == 18 ? 884 : 1_000)
            XCTAssertEqual(page["total"], .int(18_884))
            try bound(page, tool: "functions", bytes: 200_000, label: "T3-A page \(pageNumber + 1)")
            collected.append(contentsOf: rows)
            if pageNumber == 18 {
                XCTAssertEqual(page["nextCursor"], .null)
                XCTAssertEqual(page["isTruncated"], .bool(false))
            } else {
                let next = try XCTUnwrap(page["nextCursor"]?.stringValue)
                XCTAssertTrue(visited.insert(next).inserted, "cursor must advance")
                XCTAssertEqual(page["isTruncated"], .bool(true))
                cursor = next
            }
        }
        XCTAssertEqual(collected, expected)
    }

    private func capFill(name: String, count: Int, expectedRows: Int,
                         filtered: Bool = false, crossCheck: Bool = false, label: String) throws {
        let store = MCPReplySizeBoundFixtures.functions(count: count) { _ in name }
        let api = WorkspaceScriptingAPI(store: store)
        var args: [String: ScriptValue] = ["page": .bool(true), "limit": .int(1_000)]
        if filtered { args["nameContains"] = .string("Q") }
        let firstArgs = ScriptValue.object(args)
        let page = try api.execute("functions", arguments: firstArgs)
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.count, expectedRows, label)
        XCTAssertFalse(rows.isEmpty, label)
        XCTAssertLessThan(rows.count, 1_000, label)
        XCTAssertEqual(page["total"], .int(Int64(count)), label)
        XCTAssertEqual(page["isTruncated"], .bool(true), label)
        let cursor = try XCTUnwrap(page["nextCursor"]?.stringValue)
        let charge = try rows.reduce(0) { try $0 + WorkspaceScriptingAPI.listPageWireBytes($1) + 1 }
        XCTAssertLessThanOrEqual(charge, cap, label)
        try bound(page, tool: "functions", bytes: 200_000, label: label + " first")
        args["cursor"] = .string(cursor)
        let tail = try api.execute("functions", arguments: .object(args))
        let remaining = try XCTUnwrap(tail["rows"]?.arrayValue)
        XCTAssertEqual(remaining.count, 1, "one omitted candidate, not a larger fixture")
        let nextRow = try XCTUnwrap(remaining.first)
        XCTAssertGreaterThan(charge + (try WorkspaceScriptingAPI.listPageWireBytes(nextRow)) + 1,
                             cap, "\(label): next matching row must fail byte admission")
        XCTAssertEqual(nextRow["name"], .string(name))
        XCTAssertEqual(tail["nextCursor"], .null)
        XCTAssertEqual(tail["total"], .int(Int64(count)))
        try bound(tail, tool: "functions", bytes: 200_000, label: label + " tail")
        if crossCheck { try serverBound(api, tool: "functions", args: firstArgs, bytes: 200_000) }
    }

    func testT3QuoteAndBackslashCapFillAndLegacyServer() throws {
        try capFill(name: String(repeating: "\"\\", count: 128) + "Q",
                    count: 177, expectedRows: 176, crossCheck: true, label: "T3-B(i)")
    }

    func testT3ControlCharacterCapFill() throws {
        try capFill(name: String(repeating: "\u{0001}", count: 256),
                    count: 105, expectedRows: 104, label: "T3-B(ii)")
    }

    func testT3SlashCapFill() throws {
        try capFill(name: String(repeating: "/", count: 512),
                    count: 93, expectedRows: 92, label: "T3-B(iii)")
    }

    func testT3FirstRowAt16384ControlCharacterCap() throws {
        try capFill(name: String(repeating: "\u{0001}", count: 16_384),
                    count: 2, expectedRows: 1, label: "T3-B(iv)")
    }

    func testT3FilteredQuoteAndBackslashCapFill() throws {
        try capFill(name: String(repeating: "\"\\", count: 128) + "Q",
                    count: 177, expectedRows: 176, filtered: true, label: "T3-C")
    }

    func testT5TGProShapedNamesAtDefaultAnd1000Limits() async throws {
        // TG Pro-shaped count only: 400 ObjC classes and 50 protocols.
        // Assumption: every class has a 128-byte ASCII name. No real app data.
        let entries = MCPReplySizeBoundFixtures.types()
        let harness = TypeAtlasReplyTestHarness(entries)
        let expected = Set(entries.filter { $0.kind == .objcClass }.map(\.name))
        XCTAssertEqual(expected.count, 400)
        XCTAssertEqual(entries.filter { $0.kind != .objcClass }.count, 50)
        for explicitLimit in [false, true] {
            let pages = explicitLimit ? 2 : 4
            var cursor: String?, visited = Set<String>(), names: [String] = []
            for pageNumber in 0..<pages {
                var args: [String: ScriptValue] = ["page": .bool(true),
                    "kind": .string("objcClass"), "fields": .string("names")]
                if explicitLimit { args["limit"] = .int(1_000) }
                if let cursor { args["cursor"] = .string(cursor) }
                let page = try await harness.read(.inline, .object(args))
                let rows = try XCTUnwrap(page["rows"]?.arrayValue)
                XCTAssertEqual(rows.count, explicitLimit ? (pageNumber == 0 ? 374 : 26) : 100)
                XCTAssertEqual(page["total"], .int(400))
                for row in rows {
                    XCTAssertEqual(row["kind"], .string("objcClass"))
                    names.append(try XCTUnwrap(row["name"]?.stringValue))
                }
                if explicitLimit {
                    for version in [MCPResultProtocol.legacy, .structured] {
                        let wire = try mcpToolReplyJSONByteCount(output: page, tool: "list-image-types",
                            generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(1)) + 1
                        print("MEASURED TG explicit page \(pageNumber + 1) rows=\(rows.count) \(version.rawValue) frame+LF=\(wire)")
                    }
                }
                try bound(page, tool: "list-image-types", bytes: 100_000, strict: true,
                    label: "T5-A \(explicitLimit ? "1000" : "default") page \(pageNumber + 1)")
                if pageNumber + 1 == pages {
                    XCTAssertEqual(page["nextCursor"], .null)
                    XCTAssertEqual(page["isTruncated"], .bool(false))
                } else {
                    let next = try XCTUnwrap(page["nextCursor"]?.stringValue)
                    XCTAssertTrue(visited.insert(next).inserted)
                    XCTAssertEqual(page["isTruncated"], .bool(true))
                    cursor = next
                }
            }
            XCTAssertEqual(names.count, 400)
            XCTAssertEqual(Set(names), expected)
        }
    }

    func testT5MintsShapedNamesOnAllRoutesAndLegacyServer() async throws {
        // The supplied anonymous 53-row shape is reused without modification.
        // It models lengths and links, not names or measurements of the real app.
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let args = ScriptValue.object(["page": .bool(true), "fields": .string("names")])
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let page = try await harness.read(route, args)
            XCTAssertEqual(try XCTUnwrap(page["rows"]?.arrayValue).count, 53)
            XCTAssertEqual(page["total"], .int(53))
            XCTAssertEqual(page["nextCursor"], .null)
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["swiftObjCLinks"]?["linked"], .int(19), "synthetic link-shape premise")
            XCTAssertEqual(page["swiftObjCLinks"]?["abstained"]?["runtimeNameUndecodable"], .int(1))
            // Owner ruling O1: 12,576 B legacy and 11,145 B structured at the measured 53-row figures.
            try bound(page, tool: "list-image-types", bytes: 12_576, structuredBytes: 11_145,
                label: "T5-B \(route)")
            for version in [MCPResultProtocol.legacy, .structured] {
                let wire = try mcpToolReplyJSONByteCount(output: page, tool: "list-image-types",
                    generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(1)) + 1
                print("MEASURED Mints names \(route) \(version.rawValue) frame+LF=\(wire)")
            }
        }
        try serverBound(harness.api, tool: "list-image-types", args: args, bytes: 12_576)
    }

    func testF4RoadmapFiveCallShape() throws {
        // TextEdit-shaped five-call fixture, copied from the supplied test pattern.
        // This is synthetic stored analysis, not a real TextEdit measurement.
        let api = WorkspaceScriptingAPI(store: MCPReplySizeBoundFixtures.facts(nearCap: false))
        let output = try api.execute("function-facts", arguments: MCPReplySizeBoundFixtures.factsArgs)
        XCTAssertEqual(output["calls"]?["total"], .int(5))
        try bound(output, tool: "function-facts", bytes: 8_000, label: "F4-A")
    }

    func testF4NearInnerCapAndLegacyServer() throws {
        // All three row-bearing sections start with eight rows (24 total).
        // 32 is the shared admission ceiling, not four output sections.
        let store = MCPReplySizeBoundFixtures.facts(nearCap: true)
        let api = WorkspaceScriptingAPI(store: store)
        let args = MCPReplySizeBoundFixtures.factsArgs
        let output = try api.execute("function-facts", arguments: args)
        for section in ["calls", "references", "size"] {
            XCTAssertEqual(output[section]?["total"], .int(8))
        }
        let calls = try XCTUnwrap(output["calls"]?["rows"]?.arrayValue)
        XCTAssertEqual(calls.count, 2, "static near-cap construction must retain two calls")
        XCTAssertEqual(output["references"]?["rows"], .array([]))
        XCTAssertEqual(output["size"]?["blocks"], .array([]))
        XCTAssertEqual(output["calls"]?["omitted"], .int(6))
        XCTAssertEqual(output["calls"]?["truncated"], .bool(true))
        XCTAssertEqual(output["name"]?.stringValue?.utf8.count, 256)
        for call in calls { XCTAssertEqual(call["toName"]?.stringValue?.utf8.count, 256) }
        let inner = try output.jsonData().count
        XCTAssertGreaterThanOrEqual(inner, 2_700, "F4-B must approach the inner cap")
        XCTAssertLessThanOrEqual(inner, 3_000)
        try bound(output, tool: "function-facts", bytes: 8_000, label: "F4-B")
        try serverBound(api, tool: "function-facts", args: args, bytes: 8_000)
    }
}
