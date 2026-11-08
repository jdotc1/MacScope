import Foundation
import XCTest
@testable import MacScope

@MainActor
final class ScriptingListPageTests: XCTestCase {
    private let commands = ["functions", "strings"]
    private let stale = "staleCursor: the list changed or the cursor belongs to another list; restart without a cursor"
    private let badLimit = "limit must be an integer from 1 to 1000 when page is true"

    // F1: fails before the fix: a bare array has no envelope keys.
    func testPageEnvelopeShapeForFunctionsAndStrings() throws {
        let store = makeListStore(count: 250)
        let api = WorkspaceScriptingAPI(store: store)
        for command in commands {
            let legacy = try XCTUnwrap(try api.execute(command).arrayValue)
            let page = try api.execute(command, arguments: .object(["page": .bool(true), "limit": .int(100)]))
            guard case .object(let fields) = page else { return XCTFail("expected page object") }
            var expectedKeys = Set(["rows", "total", "isTruncated", "nextCursor", "sourceComplete"])
            if command == "strings" { expectedKeys.formUnion(["totalLowerBound", "totalIsExact", "source"]) }
            XCTAssertEqual(Set(fields.keys), expectedKeys)
            XCTAssertEqual(page["rows"]?.arrayValue, Array(legacy.prefix(100)))
            XCTAssertEqual(page["total"], command == "strings" ? .null : .int(250))
            XCTAssertEqual(page["isTruncated"], .bool(true))
            XCTAssertNotNil(page["nextCursor"]?.stringValue)
            XCTAssertEqual(page["sourceComplete"], .null)
            for defaults in [ScriptValue.object(["page": .bool(true)]),
                             .object(["page": .bool(true), "limit": .null])] {
                let defaultPage = try api.execute(command, arguments: defaults)
                XCTAssertEqual(defaultPage["rows"]?.arrayValue?.count, 100)
            }
        }
    }

    // F2: fails before the fix on inline/async shape and attached argument admission.
    func testCursorSequenceReachesEveryRowOnEveryRoute() async throws {
        for command in commands {
            for route in Route.allCases {
                let store = makeListStore(count: 2_501)
                let api = WorkspaceScriptingAPI(store: store)
                let executor = attachedExecutor(store)
                let expected = try XCTUnwrap(try api.execute(command).arrayValue)
                var collected: [ScriptValue] = []
                var cursor: String?
                for (pageNumber, expectedCount) in [1_000, 1_000, 501].enumerated() {
                    var fields: [String: ScriptValue] = ["page": .bool(true), "limit": .int(1_000)]
                    if let cursor { fields["cursor"] = .string(cursor) }
                    let page = try await read(route, command: command, arguments: .object(fields),
                                              api: api, executor: executor)
                    let rows = try XCTUnwrap(page["rows"]?.arrayValue)
                    XCTAssertEqual(rows.count, expectedCount)
                    XCTAssertEqual(page["total"], command == "strings" ? .null : .int(2_501))
                    collected.append(contentsOf: rows)
                    if pageNumber == 2 {
                        XCTAssertEqual(page["nextCursor"], .null)
                        XCTAssertEqual(page["isTruncated"], .bool(false))
                    } else {
                        let next = try XCTUnwrap(page["nextCursor"]?.stringValue)
                        XCTAssertNotEqual(next, cursor)
                        cursor = next
                        XCTAssertEqual(page["isTruncated"], .bool(true))
                    }
                }
                XCTAssertEqual(collected, expected, "\(command), \(route)")
            }
        }
    }

    // F3: fails before the fix: sourceComplete is absent.
    func testStringsSourceCompleteFollowsCoverage() throws {
        let cases: [(StringLiteralCoverage?, ScriptValue)] = [
            (.complete, .bool(true)),
            (.incomplete(.stringCountLimitReached), .bool(false)),
            (.notAttempted, .bool(false)),
            (nil, .null),
        ]
        for (coverage, expected) in cases {
            let store = makeListStore(count: 1, coverage: coverage)
            let page = try WorkspaceScriptingAPI(store: store).execute(
                "strings", arguments: .object(["page": .bool(true)]))
            XCTAssertEqual(page["sourceComplete"], expected)
        }
        let emptyStore = makeListStore(count: 0, coverage: .complete)
        let empty = try WorkspaceScriptingAPI(store: emptyStore).execute(
            "strings", arguments: .object(["page": .bool(true)]))
        XCTAssertEqual(empty["rows"], .array([]))
        XCTAssertEqual(empty["total"], .int(0))
        XCTAssertEqual(empty["isTruncated"], .bool(false))
        XCTAssertEqual(empty["nextCursor"], .null)
        XCTAssertEqual(empty["sourceComplete"], .bool(true))
    }

    // F4: fails before the fix at cursor extraction; the pin also ignores a supplied cursor.
    func testCursorIsRefusedAfterMutationOrOnAnotherList() throws {
        let store = makeListStore(count: 25)
        let api = WorkspaceScriptingAPI(store: store)
        let first = try api.execute("functions", arguments: .object(["page": .bool(true), "limit": .int(10)]))
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let args = ScriptValue.object(["page": .bool(true), "cursor": .string(cursor), "limit": .int(10)])
        assertInvalid(stale) { try api.execute("strings", arguments: args) }
        let data = try XCTUnwrap(Data(base64Encoded: cursor))
        let decoded = try XCTUnwrap(String(data: data, encoding: .utf8))
        var fields = decoded.components(separatedBy: "|")
        fields[2] = "1"
        let wrongSlot = Data(fields.joined(separator: "|").utf8).base64EncodedString()
        assertInvalid(stale) {
            try api.execute("functions", arguments: .object(["page": .bool(true), "cursor": .string(wrongSlot)]))
        }
        fields = decoded.components(separatedBy: "|")
        fields[3] = "25"
        let pastEnd = Data(fields.joined(separator: "|").utf8).base64EncodedString()
        assertInvalid(stale) {
            try api.execute("functions", arguments: .object(["page": .bool(true), "cursor": .string(pastEnd)]))
        }
        store.snapshot.functions.append(FunctionSummary(
            id: UUID(), name: "new", startAddress: 0x9000, endAddress: 0x9004, confidence: 1))
        assertInvalid(stale) { try api.execute("functions", arguments: args) }
    }

    // F5: fails before the fix: no page object, byte cap or field flags.
    func testPageBytesStayBelowCeilingAndLongValuesAreCut() throws {
        let store = makeListStore(count: 100, value: { _ in String(repeating: "a", count: 4_000) })
        let api = WorkspaceScriptingAPI(store: store)
        let expected = try XCTUnwrap(try api.execute("strings").arrayValue)
        var collected: [ScriptValue] = []
        var cursor: String?
        for _ in 0..<100 {
            var fields: [String: ScriptValue] = ["page": .bool(true), "limit": .int(100)]
            if let cursor { fields["cursor"] = .string(cursor) }
            let page = try api.execute("strings", arguments: .object(fields))
            XCTAssertLessThanOrEqual(try page.jsonData().count, 200_000)
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertFalse(rows.isEmpty)
            XCTAssertEqual(page["total"], .null)
            for row in rows { XCTAssertNil(row["valueTruncated"]); XCTAssertNil(row["valueByteLength"]) }
            collected.append(contentsOf: rows)
            if page["nextCursor"] == .null {
                XCTAssertEqual(page["isTruncated"], .bool(false))
                break
            }
            let next = try XCTUnwrap(page["nextCursor"]?.stringValue)
            XCTAssertNotEqual(next, cursor)
            cursor = next
            XCTAssertEqual(page["isTruncated"], .bool(true))
        }
        XCTAssertEqual(collected, expected)

        let long = String(repeating: "x", count: 300_000)
        let longStore = makeListStore(count: 1, value: { _ in long })
        let longPage = try WorkspaceScriptingAPI(store: longStore).execute(
            "strings", arguments: .object(["page": .bool(true)]))
        let longRow = try XCTUnwrap(longPage["rows"]?.arrayValue?.first)
        let cut = try XCTUnwrap(longRow["value"]?.stringValue)
        XCTAssertLessThanOrEqual(cut.utf8.count, 16_384)
        XCTAssertTrue(long.hasPrefix(cut))
        XCTAssertEqual(longRow["valueTruncated"], .bool(true))
        XCTAssertEqual(longRow["valueByteLength"], .int(300_000))
        XCTAssertLessThanOrEqual(try longPage.jsonData().count, 200_000)

        let euro = String(repeating: "\u{20ac}", count: 6_000)
        let euroStore = makeListStore(count: 1, value: { _ in euro })
        let euroPage = try WorkspaceScriptingAPI(store: euroStore).execute(
            "strings", arguments: .object(["page": .bool(true)]))
        let euroRow = try XCTUnwrap(euroPage["rows"]?.arrayValue?.first)
        XCTAssertEqual(euroRow["value"]?.stringValue?.utf8.count, 16_383)
        XCTAssertEqual(euroRow["valueTruncated"], .bool(true))
        XCTAssertEqual(euroRow["valueByteLength"], .int(18_000))

        let escaped = String(repeating: "\u{0001}", count: 20_000)
        let names = makeListStore(count: 3)
        names.snapshot.functions = names.snapshot.functions.map {
            var function = $0
            function.name = escaped
            return function
        }
        let namePage = try WorkspaceScriptingAPI(store: names).execute(
            "functions", arguments: .object(["page": .bool(true)]))
        let nameRow = try XCTUnwrap(namePage["rows"]?.arrayValue?.first)
        XCTAssertEqual(nameRow["nameTruncated"], .bool(true))
        XCTAssertEqual(nameRow["nameByteLength"], .int(20_000))
        XCTAssertEqual(nameRow["name"]?.stringValue?.utf8.count, 16_384)
        XCTAssertLessThanOrEqual(try namePage.jsonData().count, 200_000)
    }

    // F6: fails before the fix: inline ignores page/cursor and accepts or clamps these limits.
    func testPageArgumentValidationRefusals() async throws {
        let store = makeListStore(count: 25)
        let api = WorkspaceScriptingAPI(store: store)
        assertInvalid("cursor requires page:true") {
            try api.execute("functions", arguments: .object(["cursor": .string("anything")]))
        }
        for page in [ScriptValue.string("yes"), .int(1)] {
            assertInvalid("page must be a boolean") {
                try api.execute("functions", arguments: .object(["page": page]))
            }
        }
        for limit in [ScriptValue.int(0), .int(1_001), .int(-1), .double(5), .string("5"), .int(10_001)] {
            assertInvalid(badLimit) {
                try api.execute("functions", arguments: .object(["page": .bool(true), "limit": limit]))
            }
        }
        let uuid = "00000000-0000-0000-0000-000000000001"
        let malformedBodies = [
            "l1|functions|0|0|\(uuid)", "l1|functions|0|-1|\(uuid)",
            "l1|functions|0|x|\(uuid)", "l1|functions|0|999999999999999999999999|\(uuid)",
            "l2|functions|0|1|\(uuid)",
            "l1|functions|x|1|\(uuid)", "l1|functions|0|1|bad",
            "l1|functions|0|1|\(uuid)|extra",
        ]
        var cursors: [ScriptValue] = [.int(1), .string("!!"), .string(String(repeating: "A", count: 1_025))]
        cursors += malformedBodies.map { .string(Data($0.utf8).base64EncodedString()) }
        cursors.append(.string(Data([0xff]).base64EncodedString()))
        for cursor in cursors {
            assertInvalid("malformed cursor") {
                try api.execute("functions", arguments: .object(["page": .bool(true), "cursor": cursor]))
            }
        }
        let symbolsCursor = Data("l1|symbols|0|1|\(uuid)".utf8).base64EncodedString()
        assertInvalid(stale) {
            try api.execute("functions", arguments: .object(["page": .bool(true), "cursor": .string(symbolsCursor)]))
        }
        let executor = attachedExecutor(store)
        for limit in [ScriptValue.null, .int(-1)] {
            do {
                _ = try await executor.execute("functions", .object(["page": .bool(true), "limit": limit]))
                XCTFail("attached authority must refuse the limit")
            } catch {
                XCTAssertEqual(error as? HeadlessAutomationAuthorityError, .invalidArguments)
            }
        }
        do {
            _ = try await executor.execute("functions", .object(["page": .bool(true), "limit": .int(0)]))
            XCTFail("page validation must refuse zero")
        } catch {
            XCTAssertEqual(error as? ScriptingError, .invalidArgument(badLimit))
        }
    }

    // F7: fails before the fix: schema fields are absent and authority rejects page.
    func testMCPAdvertisesAndAdmitsPageArguments() async throws {
        for command in commands {
            let info = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == command })
            let schema = HeadlessAutomationAuthority.inputSchema(for: info)
            XCTAssertEqual(schema["properties"]?["page"]?["type"], .string("boolean"))
            XCTAssertEqual(schema["properties"]?["cursor"]?["type"], .string("string"))
            XCTAssertEqual(schema["properties"]?["cursor"]?["maxLength"], .int(1_024))
            XCTAssertEqual(schema["properties"]?["limit"]?["minimum"], .int(0))
            XCTAssertEqual(schema["properties"]?["limit"]?["maximum"], .int(10_000))
        }
        let symbols = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "symbols" })
        let schema = HeadlessAutomationAuthority.inputSchema(for: symbols)
        XCTAssertEqual(schema["properties"]?["page"]?["type"], .string("boolean"))
        XCTAssertEqual(schema["properties"]?["cursor"]?["type"], .string("string"))
        XCTAssertEqual(schema["properties"]?["cursor"]?["maxLength"], .int(1_024))
        let store = makeListStore(count: 25)
        let result = try await HeadlessAutomationAuthority.executeAsync(
            command: "functions", arguments: .object(["page": .bool(true), "limit": .int(5)]),
            api: WorkspaceScriptingAPI(store: store))
        XCTAssertEqual(result["rows"]?.arrayValue?.count, 5)
        XCTAssertEqual(result["total"], .int(25))
    }

    // F8: fails before the fix: attached authority rejects the unknown page key.
    func testAttachedPageDefaultIsOneHundred() async throws {
        let store = makeListStore(count: 250)
        let executor = attachedExecutor(store)
        let page = try await executor.execute("functions", .object(["page": .bool(true)]))
        XCTAssertEqual(page["rows"]?.arrayValue?.count, 100)
        XCTAssertEqual(page["total"], .int(250))
    }

    // C1: positive control (passes before): absent/null nonattached limits remain unlimited.
    func testControlLegacyOmittedAndNullLimitReturnAllRows() async throws {
        let store = makeListStore(count: 5_001)
        let api = WorkspaceScriptingAPI(store: store)
        for command in commands {
            for arguments in [ScriptValue.object([:]), .object(["limit": .null])] {
                let inline = try api.execute(command, arguments: arguments)
                let asynchronous = try await api.executeAsync(command, arguments: arguments)
                XCTAssertEqual(inline.arrayValue?.count, 5_001)
                XCTAssertEqual(asynchronous, inline)
            }
        }
    }

    // C2: positive control (passes before): no true page and no non-null cursor.
    func testControlPageFalseAndNullCursorKeepBareArray() async throws {
        let store = makeListStore(count: 25)
        let api = WorkspaceScriptingAPI(store: store)
        let cases: [(ScriptValue, Int)] = [
            (.object(["page": .bool(false)]), 25),
            (.object(["page": .bool(false), "limit": .int(17)]), 17),
            (.object(["cursor": .null]), 25),
            (.object(["page": .null, "cursor": .null]), 25),
        ]
        for command in commands {
            for (arguments, count) in cases {
                let inline = try api.execute(command, arguments: arguments)
                let asynchronous = try await api.executeAsync(command, arguments: arguments)
                XCTAssertEqual(inline.arrayValue?.count, count)
                XCTAssertEqual(asynchronous, inline)
            }
        }
    }

    // C3: positive control (passes before): attached legacy clamp remains 1,000/5,000.
    func testControlAttachedLegacyClampUnchanged() async throws {
        for command in commands {
            let store = makeListStore(count: 5_001)
            let executor = attachedExecutor(store)
            let first = try await executor.execute(command, .object([:]))
            let second = try await executor.execute(command, .object(["limit": .int(5_001)]))
            XCTAssertEqual(first.arrayValue?.count, 1_000)
            XCTAssertEqual(second.arrayValue?.count, 5_000)
        }
    }

    // C4: positive control (passes before): legacy text is never cut.
    func testControlLegacyRowsKeepLongValuesWhole() throws {
        let text = String(repeating: "x", count: 300_000)
        let store = makeListStore(count: 1, value: { _ in text })
        let result = try WorkspaceScriptingAPI(store: store).execute("strings")
        let row = try XCTUnwrap(result.arrayValue?.first)
        XCTAssertEqual(row["value"], .string(text))
        XCTAssertNil(row["valueTruncated"])
        XCTAssertNil(row["valueByteLength"])
    }

    // Symbols now join the opt-in page contract.
    func testSymbolsPageMode() throws {
        let store = makeListStore(count: 25)
        let result = try WorkspaceScriptingAPI(store: store).execute(
            "symbols", arguments: .object(["page": .bool(true), "limit": .int(17)]))
        XCTAssertEqual(result["rows"]?.arrayValue?.count, 17)
        XCTAssertEqual(result["total"], .int(25))
        XCTAssertEqual(result["isTruncated"], .bool(true))
        XCTAssertNotNil(result["nextCursor"]?.stringValue)
        XCTAssertEqual(result["sourceComplete"], .null)
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(
            command: "symbols", arguments: .object(["page": .bool(true)])))
    }

    private enum Route: CaseIterable { case inline, asynchronous, attached }

    private func read(_ route: Route, command: String, arguments: ScriptValue,
                      api: WorkspaceScriptingAPI, executor: MCPAttachExecutor) async throws -> ScriptValue {
        switch route {
        case .inline: return try api.execute(command, arguments: arguments)
        case .asynchronous: return try await api.executeAsync(command, arguments: arguments)
        case .attached: return try await executor.execute(command, arguments)
        }
    }

    private func assertInvalid(_ detail: String, file: StaticString = #filePath, line: UInt = #line,
                               _ body: () throws -> ScriptValue) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument(detail), file: file, line: line)
        }
    }

    private func attachedExecutor(_ store: WorkspaceStore) -> MCPAttachExecutor {
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        return executor
    }

    private func makeListStore(count: Int, coverage: StringLiteralCoverage? = nil,
                               value: (Int) -> String = { "row\($0)" }) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.stringLiteralCoverage = coverage
        for index in 0..<count {
            let name = "row\(index)"
            let address = UInt64(0x1000 + index * 4)
            analysis.functions.append(FunctionSummary(id: UUID(), name: name, startAddress: address,
                                                       endAddress: address + 4, confidence: 1))
            analysis.symbols.append(SymbolSummary(id: UUID(), name: name, address: address,
                                                   kind: "local", libraryName: nil))
            let text = value(index)
            analysis.stringLiterals.append(StringLiteralSummary(id: UUID(), value: text, address: address,
                sourceSection: "__cstring", byteLength: text.utf8.count))
        }
        return WorkspaceStore(workspaceName: "871 retained-list pages",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}
