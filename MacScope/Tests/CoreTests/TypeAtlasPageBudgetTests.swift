// dot item 1294: Type Atlas page wire budget. Locally rederived from the 1294-v1 vectors.
import Foundation
import XCTest
@testable import MacScope

@MainActor
final class TypeAtlasPageBudgetTests: XCTestCase {
    private typealias API = WorkspaceScriptingAPI

    // MARK: helpers

    private func frame(_ output: ScriptValue, _ version: MCPResultProtocol) throws -> Int {
        try mcpToolReplyJSONByteCount(output: output, tool: "list-image-types",
            generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(1)) + 1
    }

    private func record(_ label: String, _ output: ScriptValue) throws {
        let legacy = try frame(output, .legacy), structured = try frame(output, .structured)
        print("MEASURED \(label) legacy=\(legacy) structured=\(structured)")
    }

    private func addressEntries(count: Int, kind: TypeAtlasKind = .objcClass,
                                name: (Int) -> String) -> [TypeAtlasEntry] {
        (0..<count).map { index in
            TypeAtlasEntry(id: .init(slot: .primary, kind: kind,
                key: .address(0x700000000 + UInt64(index * 16))), kind: kind,
                name: name(index), superclass: nil, members: [], conformances: [],
                methods: [], users: [], evidence: .descriptor)
        }
    }

    private func idKey(_ row: ScriptValue) throws -> String {
        let id = try XCTUnwrap(row["id"])
        return try String(decoding: id.jsonData(), as: UTF8.self)
    }

    /// Walks every page. Requires success shape, a constant total, advancing cursors.
    private func walk(_ harness: TypeAtlasReplyTestHarness, _ base: [String: ScriptValue],
                      label: String, namesFrameLimit: Int? = 100_000,
                      start: String? = nil) async throws -> [ScriptValue] {
        var pages: [ScriptValue] = [], cursor = start, visited = Set<String>()
        while true {
            var args = base
            if let cursor { args["cursor"] = .string(cursor) }
            let page = try await harness.read(.inline, .object(args))
            XCTAssertNotNil(page[base["format"] != nil ? "text" : "rows"], label)
            pages.append(page)
            for version in [MCPResultProtocol.legacy, .structured] {
                let wire = try frame(page, version)
                XCTAssertLessThanOrEqual(wire, 200_000, "\(label) page \(pages.count)")
                if let namesFrameLimit {
                    XCTAssertLessThan(wire, namesFrameLimit, "\(label) page \(pages.count) \(version.rawValue)")
                }
            }
            try record("\(label) page \(pages.count)", page)
            guard let next = page["nextCursor"]?.stringValue else {
                XCTAssertEqual(page["nextCursor"], .null)
                XCTAssertEqual(page["isTruncated"], .bool(false))
                return pages
            }
            XCTAssertEqual(page["isTruncated"], .bool(true))
            XCTAssertTrue(visited.insert(next).inserted, "\(label): cursor repeated")
            cursor = next
            if pages.count > 50 { XCTFail("\(label): runaway walk"); return pages }
        }
    }

    private func assertWalk(_ entries: [TypeAtlasEntry], rows expected: [Int],
                            args: [String: ScriptValue], label: String) async throws {
        let harness = TypeAtlasReplyTestHarness(entries)
        let pages = try await walk(harness, args, label: label)
        XCTAssertEqual(try pages.map { try XCTUnwrap($0["rows"]?.arrayValue).count }, expected, label)
        var seen: [ScriptValue] = []
        for page in pages {
            XCTAssertEqual(page["total"], .int(Int64(entries.count)), label)
            seen += try XCTUnwrap(page["rows"]?.arrayValue)
        }
        XCTAssertEqual(try seen.map(idKey).count, entries.count, label)
        XCTAssertEqual(Set(try seen.map(idKey)).count, entries.count, "\(label): each id exactly once")
        XCTAssertEqual(seen.compactMap { $0["name"]?.stringValue }, entries.map(\.name), "\(label): original order and names")
    }

    private func refusal(_ body: () async throws -> Void) async -> MCPToolRefusal? {
        do { try await body() } catch ScriptingError.structuredRefusal(let refusal) { return refusal } catch {}
        return nil
    }

    // MARK: T1, T6a escaping walks

    private let namesArgs: [String: ScriptValue] = ["page": .bool(true), "fields": .string("names"), "limit": .int(1_000)]

    func testT1BackslashWitnessCompleteWalk() async throws {
        try await assertWalk(addressEntries(count: 319) { _ in String(repeating: "\\", count: 256) },
            rows: [82, 82, 82, 73], args: namesArgs, label: "T1")
    }

    func testT6aQuoteSlashAndControlEscaping() async throws {
        try await assertWalk(addressEntries(count: 319) { _ in String(repeating: "\"", count: 256) },
            rows: [82, 82, 82, 73], args: namesArgs, label: "T6a quote")
        try await assertWalk(addressEntries(count: 319) { _ in String(repeating: "/", count: 256) },
            rows: [82, 82, 82, 73], args: namesArgs, label: "T6a slash")
        try await assertWalk(addressEntries(count: 50) { _ in String(repeating: "\u{0001}", count: 256) },
            rows: [49, 1], args: namesArgs, label: "T6a control")
    }

    // MARK: T2, T3

    func testT2TGExplicitLimitWalkIs374Plus26() async throws {
        let entries = MCPReplySizeBoundFixtures.types()
        let classes = entries.filter { $0.kind == .objcClass }
        var args = namesArgs; args["kind"] = .string("objcClass")
        let pages = try await walk(TypeAtlasReplyTestHarness(entries), args, label: "T2")
        XCTAssertEqual(try pages.map { try XCTUnwrap($0["rows"]?.arrayValue).count }, [374, 26])
        let rows = try pages.flatMap { try XCTUnwrap($0["rows"]?.arrayValue) }
        XCTAssertEqual(rows.compactMap { $0["name"]?.stringValue }, classes.map(\.name))
        XCTAssertEqual(Set(try rows.map(idKey)).count, 400)
        XCTAssertTrue(rows.allSatisfy { $0["kind"] == .string("objcClass") })
        XCTAssertTrue(pages.allSatisfy { $0["total"] == .int(400) })
    }

    func testT3CrossingPair123And124() async throws {
        for (width, expected) in [(123, [381, 19]), (124, [379, 21])] {
            let entries = (0..<450).map { index -> TypeAtlasEntry in
                let kind: TypeAtlasKind = index < 400 ? .objcClass : .objcProtocol
                return TypeAtlasEntry(id: .init(slot: .primary, kind: kind,
                    key: .address(0x700000000 + UInt64(index * 16))), kind: kind,
                    name: MCPReplySizeBoundFixtures.asciiName(width, ordinal: index), superclass: nil,
                    members: [], conformances: [], methods: [], users: [], evidence: .descriptor)
            }
            var args = namesArgs; args["kind"] = .string("objcClass")
            let pages = try await walk(TypeAtlasReplyTestHarness(entries), args, label: "T3 width \(width)")
            XCTAssertEqual(try pages.map { try XCTUnwrap($0["rows"]?.arrayValue).count }, expected, "width \(width)")
            let rows = try pages.flatMap { try XCTUnwrap($0["rows"]?.arrayValue) }
            XCTAssertEqual(rows.compactMap { $0["name"]?.stringValue },
                           entries.prefix(400).map(\.name))
            XCTAssertTrue(pages.allSatisfy { $0["total"] == .int(400) })
        }
    }

    // MARK: T4 (the 1291 Mints cell lives in MCPReplySizeBoundTests)

    func testT4MintsNamesPageIsWithinOrdinaryWireBound() async throws {
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let page = try await harness.read(route, .object(["page": .bool(true), "fields": .string("names")]))
            XCTAssertEqual(try XCTUnwrap(page["rows"]?.arrayValue).count, 53)
            XCTAssertEqual(page["total"], .int(53))
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["swiftObjCLinks"]?["linked"], .int(19))
            XCTAssertEqual(page["swiftObjCLinks"]?["abstained"]?["runtimeNameUndecodable"], .int(1))
            for version in [MCPResultProtocol.legacy, .structured] {
                XCTAssertLessThan(try frame(page, version), 100_000)
            }
            try record("T4 Mints names \(route)", page)
        }
    }

    // MARK: T5 cursors

    func testT5OldFormatCursorAcceptedAcrossChangedBoundary() async throws {
        let entries = MCPReplySizeBoundFixtures.types()
        let harness = TypeAtlasReplyTestHarness(entries)
        var first = namesArgs; first["kind"] = .string("objcClass"); first["limit"] = .int(100)
        let seed = try await harness.read(.inline, .object(first))
        let cursor = try XCTUnwrap(seed["nextCursor"]?.stringValue)
        XCTAssertEqual(String(decoding: try XCTUnwrap(Data(base64Encoded: cursor)), as: UTF8.self)
            .split(separator: "|")[3], "100")
        var args = namesArgs; args["kind"] = .string("objcClass"); args["cursor"] = .string(cursor)
        let page = try await harness.read(.inline, .object(args))
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.count, 300)
        XCTAssertEqual(page["total"], .int(400))
        XCTAssertEqual(page["nextCursor"], .null)
        XCTAssertEqual(rows.compactMap { $0["name"]?.stringValue },
                       entries.filter { $0.kind == .objcClass }.dropFirst(100).map(\.name))
        try record("T5 suffix", page)
        // Filter and field mismatches still reject the cursor.
        for change in [("kind", "objcProtocol"), ("nameContains", "Q"), ("name", "Q"), ("fields", "full")] {
            var bad = args; bad[change.0] = .string(change.1)
            do {
                _ = try await harness.read(.inline, .object(bad))
                XCTFail("cursor accepted with changed \(change.0)")
            } catch {}
        }
    }

    // MARK: T6 projections

    private func entryWithName(_ name: String, key: TypeAtlasEntryID.Key = .address(0x1000),
                               members: [TypeAtlasMember] = []) -> TypeAtlasEntry {
        TypeAtlasEntry(id: .init(slot: .primary, kind: .objcClass, key: key), kind: .objcClass,
            name: name, superclass: nil, members: members, conformances: [], methods: [],
            users: [], evidence: .descriptor)
    }

    func testT6bNodeFallbackReportsReason() async throws {
        let members = (0..<5_000).map { _ in TypeAtlasMember(name: "m", type: nil, offset: nil, evidence: .descriptor) }
        let harness = TypeAtlasReplyTestHarness([entryWithName("C0", members: members)])
        let page = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("full"), "limit": .int(1)]))
        let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
        XCTAssertEqual(row["fullRowOmitted"], .bool(true))
        XCTAssertEqual(row["fullRowReason"], .string("nodes"))
        XCTAssertNil(row["members"])
        XCTAssertEqual(row["name"], .string("C0"))
        XCTAssertEqual(page["nextCursor"], .null)
        try record("T6b", page)
    }

    func testT6cBytesFallbackKeepsExistingPrefix() async throws {
        let name = String(repeating: "\u{0001}", count: 32_768)
        let harness = TypeAtlasReplyTestHarness([entryWithName(name)])
        let page = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("full"), "limit": .int(1)]))
        let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
        XCTAssertEqual(row["fullRowOmitted"], .bool(true))
        XCTAssertEqual(row["fullRowReason"], .string("bytes"))
        XCTAssertEqual(row["nameTruncated"], .bool(true))
        XCTAssertEqual(row["nameByteLength"], .int(32_768))
        XCTAssertEqual(row["name"]?.stringValue, String(name.unicodeScalars.prefix(8_192)))
        try record("T6c", page)
    }

    func testT6dImpossibleNamesProjectionRefusesTyped() async throws {
        let name = String(repeating: "\u{0001}", count: 8_192)
        let harness = TypeAtlasReplyTestHarness([entryWithName(name, key: .name(name))])
        let refused = await refusal {
            _ = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("names")]))
        }
        let value = try XCTUnwrap(refused, "typed refusal expected")
        XCTAssertEqual(value.code, .budgetExceeded)
        XCTAssertEqual(value.budget?.unit, .bytes)
        XCTAssertEqual(value.budget?.limit, 94_999)
        XCTAssertGreaterThan(try XCTUnwrap(value.used), 94_999)
        XCTAssertFalse(value.detail.contains("\u{0001}"))
    }

    func testT6ePrefixThenRefusalDoesNotRepeat() async throws {
        let name = String(repeating: "\u{0001}", count: 8_192)
        let entries = [TypeAtlasReplyTestHarness.small(0), entryWithName(name, key: .name(name))]
        let harness = TypeAtlasReplyTestHarness(entries)
        let args: [String: ScriptValue] = ["page": .bool(true), "fields": .string("names")]
        let first = try await harness.read(.inline, .object(args))
        XCTAssertEqual(try XCTUnwrap(first["rows"]?.arrayValue).count, 1)
        XCTAssertEqual(first["total"], .int(2))
        XCTAssertEqual(first["isTruncated"], .bool(true))
        try record("T6e first", first)
        var next = args; next["cursor"] = first["nextCursor"]
        let refused = await refusal { _ = try await harness.read(.inline, .object(next)) }
        XCTAssertEqual(try XCTUnwrap(refused).code, .budgetExceeded)
    }

    func testT6fOrdinaryFullRowsAreUnmarked() async throws {
        let harness = TypeAtlasReplyTestHarness([TypeAtlasReplyTestHarness.small(0), TypeAtlasReplyTestHarness.small(1)])
        let page = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("full")]))
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.allSatisfy { $0["fullRowOmitted"] == nil })
        XCTAssertEqual(rows, try harness.entries.enumerated().map { index, entry in
            let links = try API.makeTypeAtlasSwiftObjCLinks(harness.entries, checkpoint: {})
            return try API.applyingTypeAtlasLink(API.typeAtlasEntryValue(entry), link: links.byIndex[index], checkpoint: {})
        })
        for version in [MCPResultProtocol.legacy, .structured] { XCTAssertLessThanOrEqual(try frame(page, version), 200_000) }
        try record("T6f", page)
    }

    // MARK: T7 / T9e envelopes

    private func worstEnvelope() throws -> [String: ScriptValue] {
        let harness = TypeAtlasReplyTestHarness([TypeAtlasReplyTestHarness.small(0)])
        guard case .object(var fields) = try harness.original() else { throw NSError(domain: "TypeAtlasPageBudgetTests", code: 1) }
        fields.removeValue(forKey: "types")
        fields["rows"] = .array([]); fields["total"] = .int(Int64.max)
        fields["imageSlot"] = .int(Int64.min)
        fields["isTruncated"] = .bool(true); fields["sourceComplete"] = .null
        fields["nextCursor"] = .string(String(repeating: "/", count: 1_024))
        fields["swiftObjCLinks"] = API.typeAtlasLinkCountsValue(.init(
            linked: Int.max, membersNotMerged: Int.max, runtimeNameUndecodable: Int.max,
            noSwiftRow: Int.max, ambiguous: Int.max, privateOrLocal: Int.max, generic: Int.max))
        return fields
    }

    func testT7WorstEnvelopeFitsReserve() throws {
        let envelope = ScriptValue.object(try worstEnvelope())
        try record("T7 envelope", envelope)
        for version in [MCPResultProtocol.legacy, .structured] {
            XCTAssertLessThanOrEqual(try frame(envelope, version), API.typeAtlasPageFrameReserve)
        }
    }

    func testT9eDeclarationWorstEnvelopeFitsReserve() throws {
        var fields = try worstEnvelope()
        fields.removeValue(forKey: "rows")
        fields["format"] = .string("declarations-v1")
        fields["text"] = .string(try API.typeAtlasDeclarationText([], checkpoint: {}))
        let envelope = ScriptValue.object(fields)
        try record("T9e envelope", envelope)
        for version in [MCPResultProtocol.legacy, .structured] {
            XCTAssertLessThanOrEqual(try frame(envelope, version), API.typeAtlasPageFrameReserve)
        }
    }

    // MARK: T9 declarations

    private func expectedText(_ rows: [ScriptValue]) throws -> String {
        try API.typeAtlasDeclarationText(rows, checkpoint: {})
    }

    func testT9aSmallNamesAllRoutes() async throws {
        let harness = TypeAtlasReplyTestHarness([TypeAtlasReplyTestHarness.small(0)])
        let ordinary = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("names")]))
        let rows = try XCTUnwrap(ordinary["rows"]?.arrayValue)
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let page = try await harness.read(route, .object(["format": .string("declarations-v1"),
                "fields": .string("names"), "page": .bool(true)]))
            XCTAssertEqual(page["format"], .string("declarations-v1"))
            XCTAssertNil(page["rows"])
            XCTAssertEqual(page["text"]?.stringValue, try expectedText(rows))
            XCTAssertEqual(page["total"], .int(1))
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["nextCursor"], .null)
            try record("T9a \(route)", page)
        }
    }

    func testT9bTGDeclarationWalkStopsOnRenderedBytes() async throws {
        let entries = MCPReplySizeBoundFixtures.types()
        let harness = TypeAtlasReplyTestHarness(entries)
        var args = namesArgs; args["kind"] = .string("objcClass")
        let ordinaryRows = try await walk(harness, args, label: "T9b ordinary")
            .flatMap { try XCTUnwrap($0["rows"]?.arrayValue) }
        XCTAssertEqual(ordinaryRows.count, 400)
        args["format"] = .string("declarations-v1")
        let pages = try await walk(harness, args, label: "T9b declarations")
        XCTAssertGreaterThan(pages.count, 1, "first page must stop on bytes before 1,000 rows")
        XCTAssertTrue(pages.allSatisfy { $0["total"] == .int(400) && $0["rows"] == nil })
        let header = try expectedText([])
        let text = try pages.map { try XCTUnwrap($0["text"]?.stringValue) }
            .map { String($0.dropFirst(header.count)) }.joined()
        XCTAssertEqual(header + text, try expectedText(ordinaryRows))
        // Declaration pages are no larger than the ordinary pages in row count.
        print("MEASURED T9b declaration pages=\(pages.count)")
    }

    func testT9cCursorNamespaces() async throws {
        let entries = MCPReplySizeBoundFixtures.types()
        let harness = TypeAtlasReplyTestHarness(entries)
        var seedArgs = namesArgs; seedArgs["kind"] = .string("objcClass"); seedArgs["limit"] = .int(100)
        let seed = try await harness.read(.inline, .object(seedArgs))
        let ordinaryCursor = try XCTUnwrap(seed["nextCursor"]?.stringValue)
        let mapped = try XCTUnwrap(try API.typeAtlasDeclarationCursor(.string(ordinaryCursor)).stringValue)
        var args = namesArgs; args["kind"] = .string("objcClass"); args["format"] = .string("declarations-v1")
        let pages = try await walk(harness, args, label: "T9c", start: mapped)
        XCTAssertGreaterThan(pages.count, 1)
        XCTAssertTrue(pages.allSatisfy { $0["total"] == .int(400) })
        // An unmapped ordinary cursor on the declaration route, and the reverse, stay stale.
        var wrong = args; wrong["cursor"] = .string(ordinaryCursor)
        do { _ = try await harness.read(.inline, .object(wrong)); XCTFail("unmapped cursor accepted") } catch {}
        var reverse = namesArgs; reverse["kind"] = .string("objcClass"); reverse["cursor"] = .string(mapped)
        do { _ = try await harness.read(.inline, .object(reverse)); XCTFail("declaration cursor accepted by ordinary route") } catch {}
    }

    func testT9dFallbackProjectionsRenderUnchanged() async throws {
        let members = (0..<5_000).map { _ in TypeAtlasMember(name: "m", type: nil, offset: nil, evidence: .descriptor) }
        let longName = String(repeating: "\u{0001}", count: 32_768)
        for (label, entry) in [("nodes", entryWithName("C0", members: members)), ("bytes", entryWithName(longName))] {
            let harness = TypeAtlasReplyTestHarness([entry])
            let ordinary = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("full"), "limit": .int(1)]))
            let rows = try XCTUnwrap(ordinary["rows"]?.arrayValue)
            let args: [String: ScriptValue] = ["format": .string("declarations-v1"), "fields": .string("full"), "limit": .int(1)]
            do {
                let page = try await harness.read(.inline, .object(args))
                XCTAssertEqual(page["text"]?.stringValue, try expectedText(rows), label)
                try record("T9d \(label)", page)
            } catch ScriptingError.structuredRefusal(let refused) {
                // The renderer's own per-string refusals stay typed; record, never a vacuous size pass.
                XCTAssertEqual(refused.code, .budgetExceeded, label)
                print("MEASURED T9d \(label) typed renderer refusal: \(refused.detail)")
            }
        }
    }

    func testT9fMintsDeclarationsRecordOnly() async throws {
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let ordinary = try await harness.read(.inline, .object(["page": .bool(true), "fields": .string("names")]))
        let rows = try XCTUnwrap(ordinary["rows"]?.arrayValue)
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let page = try await harness.read(route, .object(["format": .string("declarations-v1"),
                "fields": .string("names"), "page": .bool(true)]))
            XCTAssertNil(page["rows"])
            XCTAssertEqual(page["total"], .int(53))
            XCTAssertEqual(page["swiftObjCLinks"]?["linked"], .int(19))
            XCTAssertEqual(page["swiftObjCLinks"]?["abstained"]?["runtimeNameUndecodable"], .int(1))
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["nextCursor"], .null)
            XCTAssertEqual(page["text"]?.stringValue, try expectedText(rows))
            for version in [MCPResultProtocol.legacy, .structured] { XCTAssertLessThan(try frame(page, version), 100_000) }
            try record("T9f Mints declarations \(route) (record-only)", page)
        }
    }
}
