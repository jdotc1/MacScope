import Foundation
import XCTest
@testable import MacScope

@MainActor
final class TypeAtlasPageTests: XCTestCase {
    private let command = "list-image-types"
    private let stale = "staleCursor: the list changed or the cursor belongs to another list; restart without a cursor"
    private let preparation = "Type Atlas preparation exceeds 4194304 derived user entries for this image (the image catalog is not cached); no argument narrows it"

    func testMalformedKindIsRejectedWithoutChangingNullOrValidFilters() async throws {
        let store = makeStore(["A", "B"])
        let api = WorkspaceScriptingAPI(store: store)
        let snapshot = store.snapshot
        let malformed: [ScriptValue] = [.int(1), .bool(false), .array([]), .object([:])]
        for paged in [false, true] {
            for value in malformed {
                let args: ScriptValue = .object(["page": .bool(paged), "kind": value])
                assertInvalid("kind must be a string") { try api.execute(command, arguments: args) }
                assertInvalid("kind must be a string") { try direct(snapshot, args) }
                do {
                    _ = try await api.executeAsync(command, arguments: args)
                    XCTFail("non-string kind should be rejected")
                } catch {
                    XCTAssertEqual(error as? ScriptingError, .invalidArgument("kind must be a string"))
                }
            }
            let omitted = ScriptValue.object(["page": .bool(paged)])
            let explicitNull = ScriptValue.object(["page": .bool(paged), "kind": .null])
            XCTAssertEqual(try api.execute(command, arguments: omitted),
                           try api.execute(command, arguments: explicitNull))
            let filtered = try api.execute(command, arguments: .object([
                "page": .bool(paged), "kind": .string("objcClass"),
            ]))
            XCTAssertEqual(filtered["total"], .int(2))
        }
    }

    // F1: fails before: no rows envelope (or attached unknown-key refusal).
    func testPageEnvelopeShapeOnEveryRoute() async throws {
        for route in Route.allCases {
            let store = makeStore(["A", "B", "C"])
            let api = WorkspaceScriptingAPI(store: store)
            let executor = attachedExecutor(store)
            let expected = store.snapshot.typeCatalog(in: store.snapshot.primarySlot).entries
                .map(WorkspaceScriptingAPI.typeAtlasEntryValue)
            let page = try await read(route, .object(["page": .bool(true)]), api, executor)
            guard case .object(let fields) = page else { return XCTFail("expected object") }
            XCTAssertEqual(Set(fields.keys), Set([
                "rows", "total", "isTruncated", "nextCursor", "sourceComplete", "imageSlot", "imageOwner",
            ]))
            XCTAssertEqual(page["rows"], .array(expected))
            XCTAssertEqual(page["total"], .int(3))
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["nextCursor"], .null)
            XCTAssertEqual(page["sourceComplete"], .null)
            XCTAssertEqual(page["imageSlot"], .int(Int64(store.snapshot.primarySlot.rawValue)))
        }
    }

    // F2: fails before: no names pages/continuation on any route.
    func testNamesPagesByLimitOnEveryRoute() async throws {
        let names = (0..<2_501).map { String(format: "C%04d", $0) }
        for route in Route.allCases {
            let store = makeStore(names)
            let api = WorkspaceScriptingAPI(store: store)
            let executor = attachedExecutor(store)
            var cursor: String?
            var collected: [String] = []
            var pageIndex = 0
            repeat {
                var args: [String: ScriptValue] = [
                    "page": .bool(true), "fields": .string("names"), "limit": .int(1_000),
                ]
                if let cursor { args["cursor"] = .string(cursor) }
                let page = try await read(route, .object(args), api, executor)
                let rows = try XCTUnwrap(page["rows"]?.arrayValue)
                // 1294 pages names at 94,999 escaped bytes: a page holds fewer rows than the limit.
                XCTAssertFalse(rows.isEmpty)
                XCTAssertLessThanOrEqual(rows.count, 1_000)
                if pageIndex == 0 { XCTAssertEqual(rows.count, 753) }
                XCTAssertEqual(page["total"], .int(2_501))
                XCTAssertLessThan(try page.jsonData().count, 100_000)
                for row in rows {
                    guard case .object(let fields) = row else { return XCTFail("expected names row") }
                    XCTAssertEqual(Set(fields.keys), Set(["id", "imageSlot", "kind", "name"]))
                    collected.append(try XCTUnwrap(row["name"]?.stringValue))
                }
                if let next = page["nextCursor"]?.stringValue {
                    XCTAssertEqual(page["isTruncated"], .bool(true))
                    XCTAssertNotEqual(cursor, next)
                    cursor = next
                } else {
                    XCTAssertEqual(page["nextCursor"], .null)
                    XCTAssertEqual(page["isTruncated"], .bool(false))
                    cursor = nil
                }
                pageIndex += 1
                XCTAssertLessThanOrEqual(pageIndex, 10, "cursor walk must terminate")
            } while cursor != nil && pageIndex <= 10
            XCTAssertEqual(collected, names)
        }
    }

    // F3: fails before: old refusal lacks page:true; page mode still refuses.
    func testCachedCatalogAboveNodeBudgetPagesAndLegacyHintNamesPage() throws {
        let entries = (0..<5_000).map { entry("C\($0)", address: UInt64(0x1000 + $0 * 16)) }
        let snap = cached(entries)
        XCTAssertThrowsError(try direct(snap, .object([:]))) {
            guard case ScriptingError.structuredRefusal(let refusal) = $0 else { return XCTFail("wrong refusal") }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertTrue(refusal.detail.contains("finite preparation or nested-result budget"))
            XCTAssertTrue(refusal.detail.contains("page:true"))
            XCTAssertEqual(refusal.narrowing, ["page"])
        }
        let page = try direct(snap, .object([
            "page": .bool(true), "fields": .string("names"),
            "kind": .string("objcClass"), "limit": .int(1_000),
        ]))
        // 1294: names pages hold 760 of these rows (94,999-byte allowance), not the 1,000 limit.
        let count = try XCTUnwrap(page["rows"]?.arrayValue?.count)
        XCTAssertEqual(count, 760)
        XCTAssertLessThanOrEqual(count, 1_000)
        XCTAssertLessThan(try page.jsonData().count, 100_000)
        XCTAssertEqual(page["total"], .int(5_000))
        XCTAssertNotNil(page["nextCursor"]?.stringValue)
    }

    // F4: fails before: legacy preparation charges every call xref into the cross product.
    func testUncachedCrossProductPagesInPageMode() throws {
        var analysis = classAnalysis((0..<10).map { "C\($0)" })
        analysis.xrefs = (0..<1_000).map {
            XRef(id: UUID(), from: UInt64(0x100000 + $0 * 4), to: 0x9000, kind: XRefKind.call)
        }
        let snap = snapshot(analysis)
        XCTAssertNil(snap.analysis(in: snap.primarySlot)?.typeCatalog)
        XCTAssertThrowsError(try direct(snap, .object([:])))
        let args = ScriptValue.object(["page": .bool(true)])
        let page = try direct(snap, args)
        let attached = try WorkspaceScriptingAPI.snapshotListRead(
            command, arguments: args, snapshot: snap, scope: .attached)
        XCTAssertEqual(page["rows"]?.arrayValue?.count, 10)
        XCTAssertEqual(page["total"], .int(10))
        XCTAssertEqual(attached, page)
    }

    // F5: fails before: old preparation refusal, not the derived-entry cap detail.
    func testPreparationCapRefusesAndSaysNoArgumentNarrows() async throws {
        var analysis = classAnalysis(["A"])
        analysis.objcClasses[0].instanceMethods = (0..<2_049).map { _ in
            ObjCMethod(selector: "m", typeEncoding: nil, isClassMethod: false)
        }
        analysis.objcSelectors = [0x9000: "m"]
        analysis.xrefs = (0..<2_049).map {
            XRef(id: UUID(), from: UInt64(0x100000 + $0 * 4), to: 0x9000, kind: XRefKind.selref)
        }
        let snap = snapshot(analysis)
        let args = ScriptValue.object(["page": .bool(true), "fields": .string("names")])
        XCTAssertThrowsError(try direct(snap, args)) { assertPreparation900($0) }
        let store = makeStore(snap)
        XCTAssertNil(store.snapshot.analysis(in: store.snapshot.primarySlot)?.typeCatalog)
        do {
            _ = try await WorkspaceScriptingAPI(store: store).executeAsync(command, arguments: args)
            XCTFail("expected preparation cap")
        } catch {
            assertPreparation900(error)
        }
    }

    // F6: fails before: filters and rows envelope are absent.
    func testNameAndNameContainsFilters() async throws {
        let store = makeStore(["Alpha", "alphabet", "Beta"])
        let api = WorkspaceScriptingAPI(store: store)
        let executor = attachedExecutor(store)
        let cases: [([String: ScriptValue], [String])] = [
            (["name": .string("Alpha")], ["Alpha"]),
            (["name": .string("alpha")], []),
            (["nameContains": .string("ALPHA")], ["Alpha", "alphabet"]),
            (["kind": .string("objcClass"), "nameContains": .string("a")], ["Alpha", "alphabet", "Beta"]),
        ]
        for route in [Route.inline, .asynchronous] {
            for (filters, expected) in cases {
                var fields = filters
                fields["page"] = .bool(true)
                let page = try await read(route, .object(fields), api, executor)
                let rows = try XCTUnwrap(page["rows"]?.arrayValue)
                XCTAssertEqual(rows.compactMap { $0["name"]?.stringValue }, expected)
                XCTAssertEqual(page["total"], .int(Int64(expected.count)))
                XCTAssertEqual(page["nextCursor"], .null)
            }
        }
        var point = entry("Point", kind: .swiftStruct)
        point.qualifiedName = "Geo.Point"
        let snap = cached([point])
        for filters in [
            ["name": ScriptValue.string("Geo.Point"), "fields": .string("names")],
            ["nameContains": .string("geo."), "fields": .string("names")],
        ] {
            var fields = filters
            fields["page"] = .bool(true)
            let page = try direct(snap, .object(fields))
            let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
            XCTAssertEqual(page["total"], .int(1))
            XCTAssertEqual(row["name"], .string("Point"))
            XCTAssertEqual(row["qualifiedName"], .string("Geo.Point"))
        }
    }

    // F7: fails before: full row is not replaced with a flagged names row.
    func testFullRowOmittedKeepsPaging() throws {
        var analysis = classAnalysis(["A", "B", "C"])
        analysis.objcClasses[0].address = 0xA000
        analysis.objcClasses[1].address = 0xB000
        analysis.objcClasses[2].address = 0xC000
        analysis.xrefs = (0..<110_000).map {
            XRef(id: UUID(), from: UInt64(0x100000 + $0 * 4),
                 to: $0 < 40_000 ? 0xA000 : 0xB000, kind: XRefKind.data)
        }
        let snap = snapshot(analysis)
        let store = makeStore(snap)
        let args = ScriptValue.object(["page": .bool(true), "limit": .int(3)])
        let inline = try WorkspaceScriptingAPI(store: store).execute(command, arguments: args)
        let exact = try direct(snap, args)
        for page in [inline, exact] {
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(rows.count, 3)
            guard rows.count == 3 else { return }
            XCTAssertEqual(rows[0]["name"], .string("A"))
            XCTAssertEqual(rows[0]["fullRowOmitted"], .bool(true))
            XCTAssertEqual(rows[0]["fullRowReason"], .string("bytes"))
            XCTAssertEqual(rows[1]["name"], .string("B"))
            XCTAssertEqual(rows[1]["fullRowOmitted"], .bool(true))
            XCTAssertEqual(rows[1]["fullRowReason"], .string("nodes"))
            let c = try XCTUnwrap(snap.typeCatalog(in: snap.primarySlot).entries.first { $0.name == "C" })
            XCTAssertEqual(rows[2], WorkspaceScriptingAPI.typeAtlasEntryValue(c))
            XCTAssertEqual(page["nextCursor"], .null)
            XCTAssertLessThanOrEqual(try page.jsonData().count, 200_000)
        }
        // The row's +1 separator charge also applies at the exact byte boundary.
        var boundary = entry("", address: 0xD000)
        let framing = try WorkspaceScriptingAPI.typeAtlasEntryValue(boundary).jsonData().count
        boundary.name = String(repeating: "a", count: 196_608 - framing)
        XCTAssertEqual(try WorkspaceScriptingAPI.typeAtlasEntryValue(boundary).jsonData().count, 196_608)
        let boundaryPage = try direct(cached([boundary]), .object(["page": .bool(true)]))
        XCTAssertEqual(boundaryPage["rows"]?.arrayValue?.first?["fullRowReason"], .string("bytes"))
        XCTAssertLessThanOrEqual(try boundaryPage.jsonData().count, 200_000)
    }

    // F8: fails before: no cursor; all controls below use existing APIs only.
    func testCursorRefusalsAndStaleness() throws {
        let store = makeStore((0..<5).map { "Aa\($0)" })
        let api = WorkspaceScriptingAPI(store: store)
        let first = try api.execute(command, arguments: .object(["page": .bool(true), "limit": .int(2)]))
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let parts = try cursorParts(cursor)
        XCTAssertEqual(parts.count, 6)
        guard parts.count == 6 else { return }
        XCTAssertEqual(parts[3], "2")
        let slot = try XCTUnwrap(Int(parts[2]))
        func reencoded(_ parts: [String]) -> String { Data(parts.joined(separator: "|").utf8).base64EncodedString() }
        func changed(_ field: Int, _ value: String) -> String {
            var copy = parts
            copy[field] = value
            return reencoded(copy)
        }
        func args(_ token: String, extra: [String: ScriptValue] = [:]) -> ScriptValue {
            var result: [String: ScriptValue] = ["page": .bool(true), "limit": .int(2), "cursor": .string(token)]
            result.merge(extra) { _, newer in newer }
            return .object(result)
        }
        XCTAssertEqual(reencoded(parts), cursor)
        let continuation = try api.execute(command, arguments: args(cursor))
        XCTAssertEqual(continuation["rows"]?.arrayValue?.compactMap { $0["name"]?.stringValue }, ["Aa2", "Aa3"])
        XCTAssertEqual(try api.execute(command, arguments: args(reencoded(parts))), continuation)
        let last = try api.execute(command, arguments: args(changed(3, "4")))
        XCTAssertEqual(last["rows"]?.arrayValue?.compactMap { $0["name"]?.stringValue }, ["Aa4"])
        XCTAssertEqual(last["nextCursor"], .null)

        assertInvalid(stale) {
            try api.execute(command, arguments: args(cursor, extra: ["nameContains": .string("a")]))
        }
        assertInvalid(stale) { try api.execute(command, arguments: args(changed(2, String(slot + 1)))) }
        assertInvalid("malformed cursor") { try api.execute(command, arguments: args(changed(3, "0"))) }
        assertInvalid(stale) { try api.execute(command, arguments: args(changed(3, "5"))) }
        let protocolFilter = fnv("k=1objcProtocol\0n=0\0c=0\0f=full")
        assertInvalid(stale) {
            try api.execute(command, arguments: args(changed(5, protocolFilter), extra: ["kind": .string("objcProtocol")]))
        }
        assertInvalid("malformed cursor") { try api.execute(command, arguments: args(reencoded(parts + ["x"]))) }
        let five = ["l1", "list-image-types", parts[2], "2", parts[4]]
        assertInvalid("malformed cursor") { try api.execute(command, arguments: args(reencoded(five))) }
        assertInvalid("malformed cursor") { try api.execute(command, arguments: args("%%%")) }
        // Leading zero offsets are accepted; this one differs only by exceeding the byte ceiling.
        let overlong = changed(3, String(repeating: "0", count: 900) + "2")
        XCTAssertGreaterThan(overlong.utf8.count, 1_024)
        XCTAssertNotNil(Data(base64Encoded: overlong))
        assertInvalid("malformed cursor") { try api.execute(command, arguments: args(overlong)) }
        let zeroPadded = try api.execute(command, arguments: args(changed(3, "002")))
        XCTAssertEqual(zeroPadded, continuation)

        _ = try api.execute("define-type", arguments: .object([
            "name": .string("NewType"), "kind": .string("struct"),
            "fields": .array([.object(["name": .string("x"), "type": .string("int")])]),
        ]))
        assertInvalid(stale) { try api.execute(command, arguments: args(cursor)) }
    }

    // F9: fails before: inline ignores the new options instead of validating them.
    func testValidationRefusals() throws {
        let store = makeStore(["A"])
        let api = WorkspaceScriptingAPI(store: store)
        let cases: [(ScriptValue, String)] = [
            (.object(["page": .string("yes")]), "page must be a boolean"),
            (.object(["cursor": .string("x")]), "cursor requires page:true"),
            (.object(["page": .bool(false), "fields": .string("names")]), "name, nameContains and fields require page:true"),
            (.object(["page": .bool(true), "limit": .int(0)]), "limit must be an integer from 1 to 1000 when page is true"),
            (.object(["page": .bool(true), "limit": .int(1_001)]), "limit must be an integer from 1 to 1000 when page is true"),
            (.object(["page": .bool(true), "limit": .double(5)]), "limit must be an integer from 1 to 1000 when page is true"),
            (.object(["page": .bool(true), "name": .string("")]), "name must be a non-empty string of at most 1024 UTF-8 bytes"),
            (.object(["page": .bool(true), "name": .string(String(repeating: "a", count: 1_025))]), "name must be a non-empty string of at most 1024 UTF-8 bytes"),
            (.object(["page": .bool(true), "nameContains": .int(1)]), "nameContains must be a non-empty string of at most 1024 UTF-8 bytes"),
            (.object(["page": .bool(true), "fields": .string("x")]), "fields must be full or names"),
        ]
        for (args, detail) in cases { assertInvalid(detail) { try api.execute(command, arguments: args) } }
    }

    // F10: fails before: properties absent and closed-set admission refuses page/cursor/filter keys.
    func testMCPSchemaAndAdmission() throws {
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == command })
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        XCTAssertEqual(schema["properties"]?["page"]?["type"], .string("boolean"))
        XCTAssertEqual(schema["properties"]?["cursor"]?["type"], .string("string"))
        XCTAssertEqual(schema["properties"]?["cursor"]?["maxLength"], .int(1_024))
        for name in ["name", "nameContains"] {
            XCTAssertEqual(schema["properties"]?[name]?["type"], .string("string"))
            XCTAssertEqual(schema["properties"]?[name]?["minLength"], .int(1))
            XCTAssertEqual(schema["properties"]?[name]?["maxLength"], .int(1_024))
        }
        XCTAssertEqual(schema["properties"]?["fields"]?["type"], .string("string"))
        XCTAssertEqual(schema["properties"]?["fields"]?["enum"], .array([.string("full"), .string("names")]))
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(command: command, arguments: .object([
            "page": .bool(true), "cursor": .string("x"), "name": .string("A"),
            "nameContains": .string("a"), "fields": .string("names"),
        ])))
    }

    // Additional Q1 regression: fails before; three escaped names must not defeat page admission.
    func testEscapedNamesRowFitsAndAdvances() throws {
        // Charge arithmetic (1294): a U+0001 is 6 bytes in the row JSON and 7 once listPageWireBytes
        // re-escapes it, and name, qualifiedName and id.name each carry it: 3 * 7 * 4,000 = 84,000,
        // plus under 400 bytes of keys, which is under the 94,999 names allowance. Below the
        // 8,192-byte field cap, so nothing is truncated. (20,000 chars charged 172,383 and is refused.)
        let text = String(repeating: "\u{0001}", count: 4_000)
        var large = entry(text, kind: .swiftStruct)
        large.qualifiedName = text
        let snap = cached([large, entry("tail", address: 0x8000)])
        let page = try direct(snap, .object(["page": .bool(true), "fields": .string("names"), "limit": .int(1)]))
        let row = try XCTUnwrap(page["rows"]?.arrayValue?.first)
        for key in ["name", "qualifiedName"] {
            XCTAssertEqual(row[key]?.stringValue?.utf8.count, 4_000)
            XCTAssertNil(row[key + "Truncated"])
        }
        XCTAssertEqual(row["id"]?["name"]?.stringValue?.utf8.count, 4_000)
        XCTAssertNil(row["idNameTruncated"])
        XCTAssertLessThan(try page.jsonData().count, 100_000)
        let cursor = try XCTUnwrap(page["nextCursor"]?.stringValue)
        let next = try direct(snap, .object(["page": .bool(true), "fields": .string("names"), "cursor": .string(cursor)]))
        XCTAssertEqual(next["rows"]?.arrayValue?.first?["name"], .string("tail"))
        XCTAssertEqual(next["nextCursor"], .null)
    }

    // Additional Q3 regression: fails before; delimiter injection must not produce identical bindings.
    func testFilterDigestEscapesEmbeddedDelimiters() throws {
        var a = entry("x\0c=1y", kind: .swiftStruct)
        a.qualifiedName = "z"
        var b = entry("x", kind: .swiftStruct)
        b.qualifiedName = "y\0c=1z"
        let snap = cached([a, b, a, b])
        let first = try direct(snap, .object([
            "page": .bool(true), "limit": .int(1), "name": .string("x\0c=1y"), "nameContains": .string("z"),
        ]))
        let second = try direct(snap, .object([
            "page": .bool(true), "limit": .int(1), "name": .string("x"), "nameContains": .string("y\0c=1z"),
        ]))
        let firstParts = try cursorParts(try XCTUnwrap(first["nextCursor"]?.stringValue))
        let secondParts = try cursorParts(try XCTUnwrap(second["nextCursor"]?.stringValue))
        XCTAssertEqual(firstParts.count, 6)
        XCTAssertEqual(secondParts.count, 6)
        guard firstParts.count == 6, secondParts.count == 6 else { return }
        XCTAssertNotEqual(firstParts[5], secondParts[5])
    }

    // C1: positive control (passes before): hand-built legacy object and original full rows.
    func testControlLegacyInlineReplyUnchanged() throws {
        let store = makeStore(["A", "B", "C"])
        let api = WorkspaceScriptingAPI(store: store)
        let slot = store.snapshot.primarySlot
        let entries = store.snapshot.typeCatalog(in: slot).entries
        for args in [ScriptValue.object([:]), .object(["kind": .string("objcClass")]), .object(["limit": .int(1)])] {
            let rows = args["limit"] == .int(1) ? Array(entries.prefix(1)) : entries
            let expected = ScriptValue.object([
                "imageSlot": .int(Int64(slot.rawValue)),
                "imageOwner": store.snapshot.binary(in: slot).map { .string($0.id.uuidString) } ?? .null,
                "total": .int(3), "types": .array(rows.map(WorkspaceScriptingAPI.typeAtlasEntryValue)),
            ])
            XCTAssertEqual(try api.execute(command, arguments: args), expected)
        }
    }

    // C2: positive control (passes before): false/null page options retain the legacy object.
    func testControlPageFalseAndNullCursorAreLegacy() throws {
        let store = makeStore(["A", "B", "C"])
        let api = WorkspaceScriptingAPI(store: store)
        let inline = try api.execute(command)
        let snap = store.snapshot
        let exact = try direct(snap, .object([:]))
        for args in [ScriptValue.object(["page": .bool(false)]),
                     .object(["page": .bool(false), "cursor": .null]), .object(["page": .null])] {
            XCTAssertEqual(try api.execute(command, arguments: args), inline)
            XCTAssertEqual(try direct(snap, args), exact)
        }
    }

    // C3: positive control (passes before): attached default limit remains 1,000.
    func testControlAttachedLegacyClampUnchanged() async throws {
        let store = makeStore((0..<1_200).map { "C\($0)" })
        let executor = attachedExecutor(store)
        let result = try await executor.execute(command, .object([:]))
        let prefix = try XCTUnwrap(result["types"]?.arrayValue)
        XCTAssertFalse(prefix.isEmpty)
        XCTAssertLessThanOrEqual(prefix.count, 1_000)
        XCTAssertEqual(result["total"], .int(1_200))
        XCTAssertNil(result["rows"])
        XCTAssertEqual(result["isTruncated"], .bool(true))
        XCTAssertEqual(MCPAttachExecutor.boundedArguments(command, .object([:]))["limit"], .int(1_000))
        let cursor = try XCTUnwrap(result["nextCursor"]?.stringValue)
        let page = try direct(store.snapshot, .object(["page": .bool(true), "fields": .string("full"),
            "limit": .int(1), "cursor": .string(cursor)]))
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.count, 1)
        let entries = store.snapshot.typeCatalog(in: .primary).entries
        XCTAssertEqual(rows[0], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[prefix.count]))
        XCTAssertNotEqual(page["nextCursor"], result["nextCursor"])
    }

    // C4: positive control (passes before): first checkpoint cancellation still escapes.
    func testControlPageModeObservesFirstCheckpoint() throws {
        let snap = snapshot(classAnalysis(["A"]))
        var visits = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotTypeListRead(command,
            arguments: .object(["page": .bool(true)]), snapshot: snap, checkpoint: {
                visits += 1
                throw CancellationError()
            })) {
            XCTAssertTrue($0 is CancellationError)
        }
        XCTAssertEqual(visits, 1)
    }

    func test900F1ImpliedNamesPagesAndCrossModeCursorsOnEveryRoute() async throws {
        let names = (0..<2_501).map { String(format: "C%04d", $0) }
        for route in Route.allCases {
            let store = makeStore(names)
            let api = WorkspaceScriptingAPI(store: store)
            let executor = rateSafeExecutor900(store)
            var cursor: String?
            var collected: [String] = []
            for pageIndex in 0..<26 {
                var args: [String: ScriptValue] = ["fields": .string("names")]
                if let cursor { args["cursor"] = .string(cursor) }
                let page = try await read(route, .object(args), api, executor)
                let rows = try XCTUnwrap(page["rows"]?.arrayValue)
                XCTAssertEqual(rows.count, pageIndex == 25 ? 1 : 100)
                XCTAssertEqual(page["total"], .int(2_501))
                collected += try rows.map { try XCTUnwrap($0["name"]?.stringValue) }
                if pageIndex == 1 {
                    args["page"] = .bool(true)
                    let explicit = try await read(route, .object(args), api, executor)
                    XCTAssertEqual(try explicit.jsonData(), try page.jsonData())
                }
                cursor = page["nextCursor"]?.stringValue
                XCTAssertEqual(page["isTruncated"], .bool(pageIndex != 25))
                if pageIndex < 25 { XCTAssertNotNil(cursor) } else { XCTAssertNil(cursor) }
            }
            XCTAssertEqual(collected, names)
            let explicit = try await read(route, .object(["page": .bool(true), "fields": .string("names")]), api, executor)
            let explicitCursor = try XCTUnwrap(explicit["nextCursor"]?.stringValue)
            let implied = try await read(route, .object(["fields": .string("names"), "cursor": .string(explicitCursor)]), api, executor)
            XCTAssertEqual(implied["rows"]?.arrayValue?.first?["name"], .string("C0100"))
            do {
                _ = try await read(route, .object(["fields": .string("names"), "nameContains": .string("C0"),
                    "cursor": .string(explicitCursor)]), api, executor)
                XCTFail("cursor accepted for changed filters")
            } catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(stale)) }
        }
    }

    func test900F2ImpliedExactAndSubstringFiltersWithLinkEnvelope() async throws {
        let target = "_TtC6TG_Pro14SMCKeyRegistry"
        for route in Route.allCases {
            let store = makeStore(["Alpha", "alphabet", "Beta", target, target + "X"])
            let api = WorkspaceScriptingAPI(store: store)
            let executor = rateSafeExecutor900(store)
            for (args, names) in [(ScriptValue.object(["name": .string("Alpha")]), ["Alpha"]),
                (.object(["nameContains": .string("ALPHA")]), ["Alpha", "alphabet"]),
                (.object(["name": .string(target)]), [target])] {
                let value = try await read(route, args, api, executor)
                guard case .object(let fields) = value else { return XCTFail("expected page") }
                XCTAssertEqual(Set(fields.keys), ["rows", "total", "isTruncated", "nextCursor", "sourceComplete",
                                                       "imageSlot", "imageOwner", "swiftObjCLinks"])
                XCTAssertEqual(value["rows"]?.arrayValue?.compactMap { $0["name"]?.stringValue }, names)
                XCTAssertEqual(value["total"], .int(Int64(names.count)))
                XCTAssertEqual(value["nextCursor"], .null)
                if names == [target] {
                    XCTAssertNil(value["rows"]?.arrayValue?.first?["qualifiedName"])
                    XCTAssertNil(value["rows"]?.arrayValue?.first?["swiftName"])
                }
            }
        }
    }

    private func request900(_ args: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": args])])
    }

    private func response900(_ server: MCPServer, args: ScriptValue, asynchronous: Bool) async throws -> ScriptValue {
        let data: Data?
        let request = try request900(args).jsonData()
        if asynchronous { data = await server.handleMessageAsync(request) }
        else { data = server.handleMessage(request) }
        return try ScriptValue.decode(try XCTUnwrap(data))
    }

    private func payload900(_ response: ScriptValue) throws -> ScriptValue {
        let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }

    func test900F3MCPAcceptanceCallOnBothTransports() async throws {
        let store = makeStore((0..<2_501).map { String(format: "C%04d", $0) })
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        for asynchronous in [false, true] {
            let response = try await response900(server, args: .object(["kind": .string("objcClass"),
                "fields": .string("names")]), asynchronous: asynchronous)
            XCTAssertEqual(response["result"]?["isError"], .bool(false))
            let value = try payload900(response)
            XCTAssertEqual(value["rows"]?.arrayValue?.count, 100)
            XCTAssertEqual(value["total"], .int(2_501))
            guard case .object(let fields) = value else { return XCTFail("expected page") }
            XCTAssertEqual(Set(fields.keys), ["rows", "total", "isTruncated", "nextCursor", "sourceComplete", "imageSlot", "imageOwner"])
        }
    }

    private func fanout900() -> ImageAnalysis {
        var analysis = classAnalysis(["A"])
        analysis.objcClasses[0].instanceMethods = (0..<2_049).map { _ in
            ObjCMethod(selector: "m", typeEncoding: nil, isClassMethod: false)
        }
        analysis.objcSelectors = [0x9000: "m"]
        analysis.xrefs = (0..<2_049).map {
            XRef(id: UUID(), from: UInt64(0x100000 + $0 * 4), to: 0x9000, kind: XRefKind.selref)
        }
        return analysis
    }

    private func assertPreparation900(_ error: any Error, file: StaticString = #filePath, line: UInt = #line) {
        guard case ScriptingError.structuredRefusal(let refusal) = error else {
            return XCTFail("expected typed preparation refusal, got \(error)", file: file, line: line)
        }
        XCTAssertEqual(refusal.code, .budgetExceeded, file: file, line: line)
        XCTAssertEqual(refusal.detail, preparation, file: file, line: line)
        XCTAssertEqual(refusal.budget, .init(unit: .workSteps, limit: 4_194_304), file: file, line: line)
        XCTAssertEqual(refusal.used, 4_196_352, file: file, line: line)
        XCTAssertEqual(refusal.narrowing, [], file: file, line: line)
        XCTAssertFalse(refusal.retryable, file: file, line: line)
    }

    func test900F4TypedPreparationForExplicitAndImpliedOnEveryRoute() async throws {
        let snap = snapshot(fanout900())
        let store = makeStore(snap)
        let api = WorkspaceScriptingAPI(store: store)
        let executor = rateSafeExecutor900(store)
        for args in [ScriptValue.object(["page": .bool(true), "fields": .string("names")]),
                     .object(["fields": .string("names")])] {
            XCTAssertThrowsError(try direct(snap, args)) { assertPreparation900($0) }
            for route in Route.allCases {
                do { _ = try await read(route, args, api, executor); XCTFail("expected preparation refusal") }
                catch { assertPreparation900(error) }
            }
        }
    }

    func test900F5MCPPreparationIsStructuredOnBothTransports() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore(snapshot(fanout900()))))
        for asynchronous in [false, true] {
            for args in [ScriptValue.object(["page": .bool(true), "fields": .string("names")]),
                         .object(["fields": .string("names")])] {
                let response = try await response900(server, args: args, asynchronous: asynchronous)
                XCTAssertNil(response["error"])
                XCTAssertEqual(response["result"]?["isError"], .bool(true))
                let value = try payload900(response)
                XCTAssertEqual(value, .object(["error": .string("refused"), "refusal": .object([
                    "code": .string("budgetExceeded"), "detail": .string(preparation), "retryable": .bool(false),
                    "budget": .object(["unit": .string("workSteps"), "limit": .int(4_194_304)]),
                    "used": .int(4_196_352), "narrowing": .array([]),
                ])]))
            }
        }
    }

    private let noPage900 = "Type read exceeds the finite preparation or nested-result budget, and page mode cannot prepare this image either: its catalog is not cached and its derived user entries exceed 4194304; no argument narrows it."

    private func legacyRefusal900(_ snap: WorkspaceSnapshot, page: Bool,
                                  file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try direct(snap, .object([:])), file: file, line: line) { error in
            guard case ScriptingError.structuredRefusal(let value) = error else { return XCTFail("\(error)", file: file, line: line) }
            XCTAssertEqual(value.code, .budgetExceeded, file: file, line: line)
            XCTAssertEqual(value.narrowing, page ? ["page"] : [], file: file, line: line)
            let expected = page ? "Type read exceeds the finite preparation or nested-result budget; narrow the workspace type catalog. " + WorkspaceScriptingAPI.typeAtlasPageHint : noPage900
            XCTAssertEqual(value.detail, expected, file: file, line: line)
            XCTAssertTrue(value.detail.contains("finite preparation or nested-result budget"), file: file, line: line)
            XCTAssertEqual(value.detail.contains("page:true"), page, file: file, line: line)
        }
    }

    func test900F6LegacyHintAndFourthCheckpointCancellation() throws {
        let snap = snapshot(fanout900())
        legacyRefusal900(snap, page: false)
        var visits = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotTypeListRead(command, arguments: .object([:]),
            snapshot: snap, checkpoint: {
                visits += 1
                if visits == 4 { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(visits, 4)
    }

    func test900CheckpointEqualPreparationRefusalPropagates() throws {
        let snap = snapshot(fanout900())
        var visits = 0
        let expected = WorkspaceScriptingAPI.typeAtlasPreparationRefusal
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotTypeListRead(command, arguments: .object([:]),
            snapshot: snap, checkpoint: {
                visits += 1
                if visits == 4 { throw expected }
            })) { XCTAssertEqual($0 as? ScriptingError, expected) }
        XCTAssertEqual(visits, 4)
    }

    func test900C1NullFiltersKeepLegacyBytesAndC2RefusalsStay() throws {
        let store = makeStore(["A", "B", "C"])
        let api = WorkspaceScriptingAPI(store: store)
        let snap = store.snapshot
        let inline = try api.execute(command).jsonData()
        let bounded = try direct(snap, .object([:])).jsonData()
        for key in ["name", "nameContains", "fields"] {
            let args = ScriptValue.object([key: .null])
            XCTAssertEqual(try api.execute(command, arguments: args).jsonData(), inline)
            XCTAssertEqual(try direct(snap, args).jsonData(), bounded)
        }
        for (args, text) in [(ScriptValue.object(["page": .bool(false), "fields": .string("names")]),
                             "name, nameContains and fields require page:true"),
                            (.object(["cursor": .string("x")]), "cursor requires page:true")] {
            assertInvalid(text) { try api.execute(command, arguments: args) }
            assertInvalid(text) { try direct(snap, args) }
        }
    }

    func test900C3KindOnlyStillGetsAttachedLegacyClamp() async throws {
        let store = makeStore((0..<1_200).map { "C\($0)" })
        let value = try await rateSafeExecutor900(store).execute(command, .object(["kind": .string("objcClass")]))
        let prefix = try XCTUnwrap(value["types"]?.arrayValue)
        XCTAssertFalse(prefix.isEmpty)
        XCTAssertLessThanOrEqual(prefix.count, 1_000)
        XCTAssertEqual(value["total"], .int(1_200))
        XCTAssertNil(value["rows"])
        XCTAssertEqual(value["isTruncated"], .bool(true))
        XCTAssertEqual(MCPAttachExecutor.boundedArguments(command, .object(["kind": .string("objcClass")]))["limit"], .int(1_000))
        let cursor = try XCTUnwrap(value["nextCursor"]?.stringValue)
        let page = try direct(store.snapshot, .object(["page": .bool(true), "fields": .string("full"),
            "kind": .string("objcClass"), "limit": .int(1), "cursor": .string(cursor)]))
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.count, 1)
        let entries = store.snapshot.typeCatalog(in: .primary).entries
        XCTAssertEqual(rows[0], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[prefix.count]))
        XCTAssertNotEqual(page["nextCursor"], value["nextCursor"])
    }

    func test900C4HelpfulHintForPassingUncachedAndCachedFanout() throws {
        var calls = classAnalysis((0..<10).map { "C\($0)" })
        calls.xrefs = (0..<1_000).map { XRef(id: UUID(), from: UInt64(0x100000 + $0 * 4), to: 0x9000, kind: XRefKind.call) }
        let uncached = snapshot(calls)
        legacyRefusal900(uncached, page: true)
        XCTAssertEqual(try direct(uncached, .object(["page": .bool(true)]))["rows"]?.arrayValue?.count, 10)
        var fanout = fanout900()
        fanout.typeCatalog = .init(slot: .primary, entries: (0..<5_000).map { entry("C\($0)", address: UInt64(0x1000 + $0 * 16)) })
        let cachedFanout = snapshot(fanout)
        legacyRefusal900(cachedFanout, page: true)
        let fanoutPage = try direct(cachedFanout, .object(["page": .bool(true), "fields": .string("names"),
            "limit": .int(1_000)]))
        // 1294: names pages hold 760 of these rows (94,999-byte allowance), not the 1,000 limit.
        let fanoutCount = try XCTUnwrap(fanoutPage["rows"]?.arrayValue?.count)
        XCTAssertEqual(fanoutCount, 760)
        XCTAssertLessThanOrEqual(fanoutCount, 1_000)
        XCTAssertLessThan(try fanoutPage.jsonData().count, 100_000)
    }

    func test900C4bOverrideHintDependsOnPagePreparation() throws {
        for cached in [false, true] {
            var analysis = fanout900()
            if cached { analysis.typeCatalog = .init(slot: .primary, entries: [entry("A")]) }
            let base = snapshot(analysis)
            let snap = WorkspaceSnapshot(binaries: base.binaries, analysisBySlot: [.primary: analysis],
                addressOverrides: [ImageAddress(slot: .primary, address: 0x2000):
                    AddressOverride(appliedTypeName: String(repeating: "T", count: 2_049))])
            legacyRefusal900(snap, page: cached)
        }
    }

    func test900C5ExactClassInputShapeRemainsLegacy() throws {
        let snap = snapshot(classAnalysis(["A", "B"]))
        let value = try direct(snap, .object(["image": .int(0), "limit": .int(5_000)]))
        XCTAssertEqual(value["types"]?.arrayValue?.count, 2)
        XCTAssertEqual(value["total"], .int(2))
        XCTAssertNil(value["rows"])
    }

    func test900F7NullPageFullFieldsAndCallerLimitMatchExplicitPages() async throws {
        for route in Route.allCases {
            let store = makeStore(["Alpha", "Beta", "Gamma"])
            let api = WorkspaceScriptingAPI(store: store)
            let executor = rateSafeExecutor900(store)
            for key in ["name", "nameContains", "fields"] {
                let filter: ScriptValue = .string(key == "fields" ? "full" : "Alpha")
                let modes: [ScriptValue?] = [nil, .null]
                for page in modes {
                    var args: [String: ScriptValue] = [key: filter, "limit": .int(1)]
                    if let page { args["page"] = page }
                    let implied = try await read(route, .object(args), api, executor)
                    args["page"] = .bool(true)
                    let explicit = try await read(route, .object(args), api, executor)
                    XCTAssertEqual(try implied.jsonData(), try explicit.jsonData())
                    XCTAssertEqual(implied["rows"]?.arrayValue?.count, 1)
                }
            }
            for (args, detail) in [
                (ScriptValue.object(["name": .string("")]), "name must be a non-empty string of at most 1024 UTF-8 bytes"),
                (.object(["fields": .string("x")]), "fields must be full or names"),
                (.object(["name": .string("Alpha"), "limit": .int(5_000)]), "limit must be an integer from 1 to 1000 when page is true"),
            ] {
                do { _ = try await read(route, args, api, executor); XCTFail("invalid implied page succeeded") }
                catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail)) }
            }
        }
    }

    private func rateSafeExecutor900(_ store: WorkspaceStore) -> MCPAttachExecutor {
        var clock: UInt64 = 0
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) }, now: {
            clock += 1_000_000_000
            return clock
        })
        executor.setConsent(.allowed)
        return executor
    }

    private enum Route: CaseIterable { case inline, asynchronous, attached }

    private func read(_ route: Route, _ args: ScriptValue, _ api: WorkspaceScriptingAPI,
                      _ executor: MCPAttachExecutor) async throws -> ScriptValue {
        switch route {
        case .inline: return try api.execute(command, arguments: args)
        case .asynchronous: return try await api.executeAsync(command, arguments: args)
        case .attached: return try await executor.execute(command, args)
        }
    }

    private func direct(_ snap: WorkspaceSnapshot, _ args: ScriptValue) throws -> ScriptValue {
        try WorkspaceScriptingAPI.snapshotTypeListRead(command, arguments: args, snapshot: snap)
    }

    private func assertInvalid(_ detail: String, file: StaticString = #filePath, line: UInt = #line,
                               _ body: () throws -> ScriptValue) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument(detail), file: file, line: line)
        }
    }

    private func cursorParts(_ text: String) throws -> [String] {
        let data = try XCTUnwrap(Data(base64Encoded: text))
        let decoded = try XCTUnwrap(String(data: data, encoding: .utf8))
        return decoded.components(separatedBy: "|")
    }

    private func fnv(_ text: String) -> String {
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in text.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
        let digits = String(hash, radix: 16)
        return String(repeating: "0", count: 16 - digits.count) + digits
    }

    private func entry(_ name: String, kind: TypeAtlasKind = .objcClass,
                       address: UInt64? = nil) -> TypeAtlasEntry {
        TypeAtlasEntry(id: .init(slot: .primary, kind: kind, key: address.map { .address($0) } ?? .name(name)),
            kind: kind, name: name, superclass: nil, members: [], conformances: [],
            methods: [], users: [], evidence: .descriptor)
    }

    private func classAnalysis(_ names: [String]) -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.objcClasses = names.enumerated().map { index, name in
            ObjCClass(name: name, superclassName: nil, adoptedProtocols: [], classMethods: [],
                instanceMethods: [], ivars: [], properties: [], address: UInt64(0x1000 + index * 16))
        }
        return analysis
    }

    private func snapshot(_ analysis: ImageAnalysis) -> WorkspaceSnapshot {
        WorkspaceSnapshot(binaries: [
            BinaryImage(id: UUID(), name: "type-pages", path: "/type-pages", kind: "Mach-O", architecture: "arm64"),
        ], analysisBySlot: [.primary: analysis])
    }

    private func cached(_ entries: [TypeAtlasEntry]) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        return snapshot(analysis)
    }

    private func makeStore(_ names: [String]) -> WorkspaceStore { makeStore(snapshot(classAnalysis(names))) }

    private func makeStore(_ snap: WorkspaceSnapshot) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "873 Type Atlas pages", snapshot: snap,
                       engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func attachedExecutor(_ store: WorkspaceStore) -> MCPAttachExecutor {
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        return executor
    }
}
