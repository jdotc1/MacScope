import Foundation
import XCTest
@testable import MacScope

private final class Search880CreationThenExpiredClock: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private let freshReads: Int
    init(freshReads: Int = 1) { self.freshReads = freshReads }
    func now() -> Date {
        lock.lock(); defer { lock.unlock() }
        calls += 1
        return Date(timeIntervalSince1970: calls <= freshReads ? 0 : 3)
    }
}

@MainActor
final class SearchBudgetCoverageTests: XCTestCase {
    private func instruction(_ index: Int, _ mnemonic: String = "nop") -> InstructionRow {
        InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "1f 20 03 d5",
                       mnemonic: mnemonic, operands: "", hasBreakpoint: false, comment: nil)
    }
    private func literal(_ value: String, _ address: UInt64) -> StringLiteralSummary {
        .init(id: UUID(), value: value, address: address, sourceSection: "__cstring", byteLength: value.utf8.count)
    }
    private func symbol(_ value: String, _ address: UInt64) -> SymbolSummary {
        .init(id: UUID(), name: value, address: address, kind: "local", libraryName: nil)
    }
    private func function(_ value: String, _ address: UInt64) -> FunctionSummary {
        .init(id: UUID(), name: value, startAddress: address, endAddress: address + 4, confidence: 1)
    }
    private func snapshot(_ analysis: ImageAnalysis, sibling: ImageAnalysis? = nil) -> WorkspaceSnapshot {
        var result = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        for (index, bucket) in ([analysis] + (sibling.map { [$0] } ?? [])).enumerated() {
            let slot = ImageSlot(rawValue: index)
            result.insertImage(binary: BinaryImage(id: UUID(), name: "880-\(index)", path: "/fixture-880-\(index)",
                kind: "Mach-O", architecture: "arm64", slot: slot), analysis: bucket)
        }
        return result
    }
    private func store(_ snapshot: WorkspaceSnapshot) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "880 search", snapshot: snapshot,
                       engine: AnalysisEngine(), autosaveScheduler: nil)
    }
    private func metadataFixture(instructions: Int = 250_000) -> ImageAnalysis {
        var analysis = ImageAnalysis()
        analysis.instructions = (0..<instructions).map { instruction($0) }
        analysis.stringLiterals = [literal("needle", 0x200000)]
        analysis.symbols = [symbol("needle", 0x300000)]
        analysis.functions = [function("needle", 0x400000)]
        return analysis
    }
    private func fixedSearch(_ snapshot: WorkspaceSnapshot, resume: BinarySearchService.SearchResumePoint? = nil,
                             limit: Int = 500) -> BinarySearchService.BoundedOutcome {
        BinarySearchService().searchBounded(query: "needle", mode: .text, in: snapshot,
            limit: limit, resume: resume, clock: { Date(timeIntervalSince1970: 0) })
    }
    private func cursor(_ reply: ScriptValue) -> ScriptValue? {
        let value = reply["nextCursor"] ?? reply["refusal"]?["nextCursor"]
        return value == .null ? nil : value
    }
    private func chain(_ api: WorkspaceScriptingAPI, arguments: [String: ScriptValue],
                       maximumPages: Int = 40) async throws -> (rows: [ScriptValue], final: ScriptValue) {
        var arguments = arguments
        var rows: [ScriptValue] = []
        for _ in 0..<maximumPages {
            let reply = try await api.executeAsync("search", arguments: .object(arguments))
            if let page = reply["results"]?.arrayValue { rows += page }
            if let next = cursor(reply) { arguments["cursor"] = next }
            else { return (rows, reply) }
        }
        XCTFail("cursor chain did not finish within fixture bound")
        throw ScriptingError.invalidArgument("fixture page bound")
    }
    private func mcp(_ server: MCPServer, name: String, arguments: [String: ScriptValue], id: Int = 1)
        async throws -> (envelope: ScriptValue, value: ScriptValue) {
        let request = ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(Int64(id)), "method": .string("tools/call"),
            "params": .object(["name": .string(name), "arguments": .object(arguments)]),
        ])
        let response = await server.handleMessageAsync(try request.jsonData())
        let data = try XCTUnwrap(response)
        let envelope = try ScriptValue.decode(data)
        let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return (envelope, try ScriptValue.decode(Data(text.utf8)))
    }

    func testGhosttyStringBehindInstructionsIsFound() async throws {
        var analysis = metadataFixture()
        analysis.stringLiterals = (0..<4_999).map { literal("literal\($0)", 0x200000 + UInt64($0 * 16)) }
        analysis.stringLiterals.append(literal("XDG_CONFIG_HOME", 0x100973f57))
        let reply = try await WorkspaceScriptingAPI(store: store(snapshot(analysis))).executeAsync("search",
            arguments: .object(["mode": .string("text"), "query": .string("XDG_CONFIG_HOME")]))
        XCTAssertTrue(reply["results"]?.arrayValue?.contains {
            $0["kind"] == .string("string") && $0["address"] == .hex(0x100973f57)
        } == true)
    }

    func testTGProDefaultModeFindsString() async throws {
        var analysis = metadataFixture()
        analysis.stringLiterals = (0..<4_999).map { literal("literal\($0)", 0x200000 + UInt64($0 * 16)) }
        analysis.stringLiterals.append(literal("AppleSMC", 0x10050ca52))
        let reply = try await WorkspaceScriptingAPI(store: store(snapshot(analysis))).executeAsync("search",
            arguments: .object(["query": .string("AppleSMC")]))
        XCTAssertTrue(reply["results"]?.arrayValue?.contains {
            $0["kind"] == .string("string") && $0["address"] == .hex(0x10050ca52)
        } == true)
    }

    func testCursorChainReachesLateInstruction() async throws {
        var analysis = metadataFixture()
        analysis.instructions[240_000] = instruction(240_000, "needle")
        let snap = snapshot(analysis)
        let first = fixedSearch(snap)
        XCTAssertEqual(first.visits, 200_000)
        XCTAssertEqual(first.results.count, 3)
        XCTAssertEqual(first.stoppedBy, .workSteps)
        XCTAssertEqual(first.resumePoint?.phase, .instructions)
        XCTAssertEqual(first.resumePoint?.row, 199_997)
        XCTAssertEqual(first.kindsCovered, [.function, .string, .symbol])
        XCTAssertEqual(first.kindsPending, [.instruction])
        let second = fixedSearch(snap, resume: try XCTUnwrap(first.resumePoint))
        XCTAssertEqual(second.visits, 50_003)
        XCTAssertEqual(second.results.map(\.kind), [.instruction])
        XCTAssertEqual(second.results.first?.address, analysis.instructions[240_000].address)
        XCTAssertNil(second.resumePoint)
        XCTAssertNil(second.stoppedBy)
        XCTAssertEqual(second.kindsCovered, [.function, .string, .symbol, .instruction])
        let result = try await chain(WorkspaceScriptingAPI(store: store(snap)), arguments: ["query": .string("needle")])
        XCTAssertEqual(result.rows.count, 4)
        XCTAssertEqual(result.final["total"], .int(4))
        XCTAssertEqual(Set(result.rows.compactMap { $0["kind"]?.stringValue }), ["function", "string", "symbol", "instruction"])
    }

    func testMetadataQuantumDoesNotStarveNextKind() async throws {
        var analysis = metadataFixture(instructions: 0)
        analysis.symbols = (0..<250_000).map { symbol($0 == 240_000 ? "needle" : "symbol\($0)", 0x300000 + UInt64($0 * 4)) }
        let snap = snapshot(analysis)
        let first = fixedSearch(snap)
        XCTAssertEqual(first.visits, 200_000)
        XCTAssertEqual(Set(first.results.map(\.kind)), [.function, .string])
        XCTAssertEqual(first.kindsPending, [.symbol])
        XCTAssertEqual(first.resumePoint?.phase, .metadataRest)
        XCTAssertEqual(first.resumePoint?.kindIndex, 0)
        XCTAssertEqual(first.resumePoint?.row, 199_998)
        let second = fixedSearch(snap, resume: try XCTUnwrap(first.resumePoint))
        XCTAssertEqual(second.visits, 50_002)
        XCTAssertEqual(second.results.map(\.kind), [.symbol])
        XCTAssertNil(second.resumePoint)
        let result = try await chain(WorkspaceScriptingAPI(store: store(snap)), arguments: ["query": .string("needle")])
        XCTAssertEqual(result.rows.count, 3)
        XCTAssertEqual(result.final["total"], .int(3))
    }

    func testSecondImageMetadataIsReached() async throws {
        var first = ImageAnalysis()
        first.instructions = (0..<250_000).map { instruction($0) }
        var second = ImageAnalysis()
        second.symbols = [symbol("needle", 0x7000)]
        let reply = try await WorkspaceScriptingAPI(store: store(snapshot(first, sibling: second))).executeAsync("search",
            arguments: .object(["query": .string("needle")]))
        XCTAssertTrue(reply["results"]?.arrayValue?.contains {
            $0["kind"] == .string("symbol") && $0["imageSlot"] == .int(1) && $0["address"] == .hex(0x7000)
        } == true)
    }

    func testMatchCapBoundaryIsRetriedWithoutSkipping() throws {
        var analysis = ImageAnalysis()
        analysis.instructions = (0..<4).map { instruction($0, "needle") }
        let snap = snapshot(analysis)
        let first = fixedSearch(snap, limit: 2)
        XCTAssertEqual(first.results.map(\.address), [0x1000, 0x1004])
        XCTAssertEqual(first.lowerBound, 3)
        XCTAssertEqual(first.visits, 3)
        XCTAssertEqual(first.resumePoint?.row, 2)
        let second = fixedSearch(snap, resume: try XCTUnwrap(first.resumePoint), limit: 2)
        XCTAssertEqual(second.results.map(\.address), [0x1008, 0x100c])
        XCTAssertEqual(second.visits, 2)
        XCTAssertNil(second.resumePoint)
    }

    func testDuplicateLookaheadDoesNotInflateLowerBound() throws {
        var analysis = ImageAnalysis()
        analysis.instructions = [instruction(0, "needle"), instruction(1, "needle"), instruction(0, "needle")]
        let snap = snapshot(analysis)
        let first = fixedSearch(snap, limit: 2)
        XCTAssertEqual(first.results.count, 2)
        XCTAssertEqual(first.lowerBound, 2)
        XCTAssertEqual(first.resumePoint?.row, 2)
        let second = fixedSearch(snap, resume: try XCTUnwrap(first.resumePoint), limit: 2)
        XCTAssertEqual(second.results.map(\.address), [0x1000])
        XCTAssertNil(second.resumePoint)
    }

    func testControlEqualAddressCompleteReplyKeepsLegacyKindOrder() async throws {
        var analysis = ImageAnalysis()
        analysis.instructions = [instruction(0, "needle")]
        analysis.stringLiterals = [literal("needle", 0x1000)]
        analysis.symbols = [symbol("needle", 0x1000)]
        analysis.functions = [function("needle", 0x1000)]
        let api = WorkspaceScriptingAPI(store: store(snapshot(analysis)))
        let reply = try await api.executeAsync("search", arguments: .object(["query": .string("needle")]))
        XCTAssertEqual(reply["results"]?.arrayValue?.compactMap { $0["kind"]?.stringValue },
                       ["instruction", "string", "symbol", "function"])
        XCTAssertEqual(reply["total"], .int(4))
    }

    func testReplayedQueriesNeverEmptyTruncated() async throws {
        var analysis = metadataFixture()
        analysis.stringLiterals = [literal("AppleSMC", 0x10050ca52), literal("isAtMaxRPM", 0x200100)]
        analysis.symbols = []
        analysis.functions = [function("_GhosttyShowWindowSafely", 0x400000)]
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store(snapshot(analysis))))
        var calls: [[String: ScriptValue]] = [
            ["mode": .string("text"), "query": .string("XDG_CONFIG_HOME")],
            ["mode": .string("text"), "query": .string("config.ghostty")],
            ["mode": .string("text"), "query": .string("XDG")],
            ["mode": .string("text"), "query": .string("Application Support")],
            ["mode": .string("regex"), "query": .string("ghostty/config")],
            ["mode": .string("text"), "query": .string("Reload Configuration")],
            ["mode": .string("text"), "query": .string("keybind")],
            ["mode": .string("text"), "query": .string("Reload Configuration"), "imageSlot": .int(0)],
            ["mode": .string("hex"), "query": .string("5265 6c6f 6164 2043")],
            ["mode": .string("regex"), "query": .string("^Reload Conf")],
            ["mode": .string("text"), "query": .string("_GhosttyShowWindowSafely")],
        ]
        let tg: [(String, String)] = [
            ("text", "AppleSMC"), ("text", "IOServiceOpen"), ("text", "SMC"),
            ("text", "TC0P"), ("text", "Tp09"), ("text", "isAtMaxRPM"),
            ("text", "kIOMainPortDefault"), ("regex", "IOService"), ("hex", "4170706c65534d43"),
        ]
        for (mode, query) in tg {
            calls.append(["mode": .string(mode), "query": .string(query)])
            calls.append(["mode": .string(mode), "query": .string(query), "imageSlot": .int(0)])
        }
        XCTAssertEqual(calls.count, 29)
        for (id, arguments) in calls.enumerated() {
            let reply = try await mcp(server, name: "search", arguments: arguments, id: id + 1)
            XCTAssertEqual(reply.envelope["result"]?["isError"], .bool(false), "\(arguments)")
            if reply.value["error"] == .string("refused") {
                XCTAssertTrue(["budgetExceeded", "preconditionFailed"].contains(reply.value["refusal"]?["code"]?.stringValue ?? ""))
                XCTAssertNil(reply.value["results"])
            } else {
                XCTAssertFalse(try XCTUnwrap(reply.value["results"]?.arrayValue).isEmpty)
            }
        }
    }

    func testCappedStringKindIsNotHonestEmpty() async throws {
        var analysis = metadataFixture(instructions: 10)
        analysis.stringLiterals = (0..<10).map { literal("literal\($0)", 0x200000 + UInt64($0 * 16)) }
        analysis.symbols = (0..<10).map { symbol("symbol\($0)", 0x300000 + UInt64($0 * 4)) }
        analysis.functions = (0..<10).map { function("function\($0)", 0x400000 + UInt64($0 * 4)) }
        analysis.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        let reply = try await mcp(MCPServer(api: WorkspaceScriptingAPI(store: store(snapshot(analysis)))),
                                  name: "search", arguments: ["query": .string("absent880")])
        XCTAssertEqual(reply.envelope["result"]?["isError"], .bool(false))
        XCTAssertEqual(reply.value["error"], .string("refused"))
        XCTAssertEqual(reply.value["refusal"]?["code"], .string("preconditionFailed"))
        XCTAssertEqual(reply.value["refusal"]?["retryable"], .bool(false))
        XCTAssertEqual(reply.value["refusal"]?["sourceIncomplete"]?["string"], .string("stringCountLimitReached"))
        XCTAssertEqual(reply.value["refusal"]?["kindsCovered"], .array(["function", "instruction", "symbol"].map(ScriptValue.string)))
        XCTAssertNil(reply.value["results"])
    }

    func testHexCursorResumesPastWindow() async throws {
        let offset = 2_621_440
        var bytes = Data(repeating: 0, count: 3 * 1_048_576)
        bytes.replaceSubrange(offset..<(offset + 4), with: [0xde, 0xad, 0xbe, 0xef])
        let snap = WorkspaceSnapshot(binaries: [], functions: [], symbols: [], stringLiterals: [],
            instructions: [], xrefs: [], hexBytes: Data(),
            sections: [.init(id: UUID(), name: "__data", address: 0x1000, size: UInt64(bytes.count),
                             fileOffset: 0, isExecutable: false)], imageBytes: bytes)
        let result = try await chain(WorkspaceScriptingAPI(store: store(snap)),
            arguments: ["mode": .string("hex"), "query": .string("deadbeef")], maximumPages: 40)
        XCTAssertEqual(result.rows.count, 1)
        XCTAssertEqual(result.rows.first?["address"], .hex(0x1000 + UInt64(offset)))
        XCTAssertEqual(result.final["kindsCovered"], .array([.string("bytes")]))
        XCTAssertEqual(result.final["isTruncated"], .bool(false))
        XCTAssertEqual(result.final["total"], .int(1))
    }

    func testStaleOrForeignCursorRefused() async throws {
        let owner = store(snapshot(metadataFixture(), sibling: ImageAnalysis()))
        let api = WorkspaceScriptingAPI(store: owner)
        let snap = owner.snapshot
        let point = try XCTUnwrap(fixedSearch(snap).resumePoint)
        let token = WorkspaceScriptingAPI.encodeSearchCursor(point, cumulative: 3, query: "needle",
            mode: .text, kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
        let foreign: [[String: ScriptValue]] = [
            ["query": .string("other"), "cursor": .string(token)],
            ["query": .string("needle"), "kind": .string("symbol"), "cursor": .string(token)],
            ["query": .string("needle"), "imageSlot": .int(1), "cursor": .string(token)],
        ]
        for args in foreign {
            do { _ = try await api.executeAsync("search", arguments: .object(args)); XCTFail("foreign cursor accepted") }
            catch ScriptingError.invalidArgument(let detail) { XCTAssertTrue(detail.hasPrefix("staleCursor:")) }
            XCTAssertEqual(owner.snapshot.analysisGenerationID, snap.analysisGenerationID)
        }
        for bad in ["!!", String(repeating: "A", count: 1_025)] {
            do {
                _ = try await api.executeAsync("search", arguments: .object(["query": .string("needle"), "cursor": .string(bad)]))
                XCTFail("malformed cursor accepted")
            } catch ScriptingError.invalidArgument(let detail) { XCTAssertEqual(detail, "malformed cursor") }
            XCTAssertEqual(owner.snapshot.analysisGenerationID, snap.analysisGenerationID)
        }
        var changed = owner.snapshot
        var override = AddressOverride()
        override.customName = "renamed"
        changed.addressOverrides[.primary(0x1000)] = override
        owner.snapshot = changed
        let generation = owner.snapshot.analysisGenerationID
        XCTAssertNotEqual(generation, snap.analysisGenerationID)
        do {
            _ = try await api.executeAsync("search", arguments: .object(["query": .string("needle"), "cursor": .string(token)]))
            XCTFail("stale cursor accepted")
        } catch ScriptingError.invalidArgument(let detail) { XCTAssertTrue(detail.hasPrefix("staleCursor:")) }
        XCTAssertEqual(owner.snapshot.analysisGenerationID, generation)
    }

    func testMCPCursorSchemaAndValidation() async throws {
        let api = WorkspaceScriptingAPI(store: store(snapshot(metadataFixture(instructions: 1))))
        let server = MCPServer(api: api)
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
            "method": .string("tools/list"), "params": .object([:])])
        let response = await server.handleMessageAsync(try request.jsonData())
        let listing = try ScriptValue.decode(XCTUnwrap(response))
        let tool = try XCTUnwrap(listing["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string("search") })
        XCTAssertEqual(tool["inputSchema"]?["properties"]?["cursor"]?["type"], .string("string"))
        XCTAssertEqual(tool["inputSchema"]?["properties"]?["cursor"]?["maxLength"], .int(1_024))
        let invalid = try await mcp(server, name: "search",
            arguments: ["query": .string("needle"), "cursor": .int(5)], id: 2)
        XCTAssertEqual(invalid.envelope["result"]?["isError"], .bool(true))
        XCTAssertEqual(invalid.value["refusal"]?["field"], .string("cursor"))
        XCTAssertThrowsError(try api.execute("search", arguments: .object(["query": .string("needle"), "cursor": .string("x")]))) {
            guard case ScriptingError.invalidArgument(let detail) = $0 else { return XCTFail("wrong error") }
            XCTAssertEqual(detail, "cursor is accepted only by the bounded search")
        }
    }

    func testStopBeforeAnyCandidateReturnsStartCursor() async throws {
        var analysis = ImageAnalysis()
        analysis.instructions = [instruction(0, "needle")]
        let snap = snapshot(analysis, sibling: analysis)
        let clock = Search880CreationThenExpiredClock()
        let deadline = BinarySearchService().searchBounded(query: "needle", mode: .text, in: snap,
            preparationCheckpointInterval: 1, clock: { clock.now() })
        let probe = BinarySearchService().searchBounded(query: "needle", mode: .text, in: snap,
            preparationCheckpointInterval: 1, preparationCheckpoint: { _ in true })
        XCTAssertEqual(deadline.stoppedBy, .deadline)
        XCTAssertEqual(deadline.visits, 0)
        XCTAssertEqual(deadline.elapsedMillis, 3_000)
        XCTAssertEqual(probe.stoppedBy, .preparation)
        for outcome in [deadline, probe] {
            let point = try XCTUnwrap(outcome.resumePoint)
            XCTAssertEqual(point, BinarySearchService.SearchResumePoint())
            XCTAssertTrue(outcome.results.isEmpty)
            let token = WorkspaceScriptingAPI.encodeSearchCursor(point, cumulative: 0, query: "needle",
                mode: .text, kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
            let reply = WorkspaceScriptingAPI.searchIncompleteReply(outcome, nextCursor: .string(token), cumulative: 0)
            XCTAssertEqual(reply["error"], .string("refused"))
            XCTAssertNil(reply["results"])
            XCTAssertEqual(reply["refusal"]?["code"], .string("budgetExceeded"))
            XCTAssertEqual(reply["refusal"]?["retryable"], .bool(true))
            let decoded = try WorkspaceScriptingAPI.decodeSearchCursor(.string(token), query: "needle",
                mode: .text, kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
            XCTAssertEqual(decoded.point, point)
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store(snap)),
                asyncCommandExecutor: { _, _ in reply })
            let transport = try await mcp(server, name: "search", arguments: ["query": .string("needle")])
            XCTAssertEqual(transport.envelope["result"]?["isError"], .bool(false))
            XCTAssertEqual(transport.value, reply)
            if outcome.stoppedBy == .deadline {
                XCTAssertEqual(reply["refusal"]?["budget"]?["unit"], .string("wallMillis"))
                XCTAssertEqual(reply["refusal"]?["budget"]?["limit"], .int(2_000))
                XCTAssertEqual(reply["refusal"]?["used"], .int(3_000))
            } else {
                XCTAssertNil(reply["refusal"]?["budget"])
                XCTAssertNil(reply["refusal"]?["used"])
            }
            XCTAssertEqual(fixedSearch(snap, resume: point).results.count, 2)
        }
    }

    func testZeroRowTruncatedPageOnTrailingEmptyImageRefuses() async throws {
        var matching = ImageAnalysis()
        matching.symbols = [symbol("needle", 0x7000)]
        let snap = snapshot(matching, sibling: ImageAnalysis())
        let kinds = Set(BinarySearchResult.Kind.allCases)
        let clock = Search880CreationThenExpiredClock(freshReads: 4)
        let first = BinarySearchService().searchBounded(query: "needle", mode: .text, in: snap,
            clock: { clock.now() })
        XCTAssertEqual(first.results.map(\.address), [0x7000])
        XCTAssertEqual(first.stoppedBy, .deadline)
        XCTAssertEqual(first.resumePoint?.slot, ImageSlot(rawValue: 1))
        let firstReply = WorkspaceScriptingAPI.searchPageReply(first, cumulative: 0, query: "needle",
            mode: .text, kinds: kinds, slotFilter: nil, snapshot: snap)
        XCTAssertEqual(firstReply["results"]?.arrayValue?.count, 1)
        let token = try XCTUnwrap(cursor(firstReply))
        let decoded = try WorkspaceScriptingAPI.decodeSearchCursor(token, query: "needle", mode: .text,
            kinds: kinds, slotFilter: nil, snapshot: snap)
        let expired = Search880CreationThenExpiredClock(freshReads: 1)
        let second = BinarySearchService().searchBounded(query: "needle", mode: .text, in: snap,
            resume: decoded.point, clock: { expired.now() })
        XCTAssertTrue(second.results.isEmpty)
        XCTAssertTrue(second.isTruncated || second.resumePoint != nil)
        let reply = WorkspaceScriptingAPI.searchPageReply(second, cumulative: decoded.cumulative, query: "needle",
            mode: .text, kinds: kinds, slotFilter: nil, snapshot: snap)
        XCTAssertNil(reply["results"])
        XCTAssertEqual(reply["error"], .string("refused"))
        XCTAssertEqual(reply["refusal"]?["code"], .string("budgetExceeded"))
    }

    func testContinuationPreparationStopPreservesPositionAndCount() throws {
        let snap = snapshot(metadataFixture())
        let first = fixedSearch(snap)
        let position = try XCTUnwrap(first.resumePoint)
        let stopped = BinarySearchService().searchBounded(query: "needle", mode: .text, in: snap,
            preparationCheckpointInterval: 1, preparationCheckpoint: { _ in true }, resume: position)
        XCTAssertEqual(stopped.visits, 0)
        XCTAssertEqual(stopped.resumePoint, position)
        let reply = WorkspaceScriptingAPI.searchPageReply(stopped, cumulative: first.results.count,
            query: "needle", mode: .text, kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
        let token = try XCTUnwrap(reply["refusal"]?["nextCursor"])
        let decoded = try WorkspaceScriptingAPI.decodeSearchCursor(token, query: "needle", mode: .text,
            kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
        XCTAssertEqual(decoded.point, position)
        XCTAssertEqual(decoded.cumulative, 3)
        XCTAssertEqual(fixedSearch(snap, resume: decoded.point).visits, 50_003)
    }

    func testControlCompleteSearchReplyUnchanged() async throws {
        let analysis = metadataFixture(instructions: 2)
        let snap = snapshot(analysis)
        let expected = BinarySearchService().searchWithCount(query: "needle", mode: .text, in: snap)
        let value = try await WorkspaceScriptingAPI(store: store(snap)).executeAsync("search",
            arguments: .object(["query": .string("needle")]))
        XCTAssertEqual(value["total"], .int(Int64(expected.total)))
        XCTAssertEqual(value["lowerBound"], .int(Int64(expected.total)))
        XCTAssertEqual(value["isTruncated"], .bool(false))
        // The async route returned unquoted string previews at the pin (searchBounded); searchWithCount quotes them for the synchronous route.
        let unquoted = expected.results.map { row -> BinarySearchResult in
            var row = row
            if row.kind == .string, row.preview.count >= 2, row.preview.hasPrefix("\""), row.preview.hasSuffix("\"") {
                row.preview = String(row.preview.dropFirst().dropLast())
            }
            return row
        }
        XCTAssertEqual(value["results"], .array(unquoted.map(WorkspaceScriptingAPI.searchRow)))
    }

    func testControlSynchronousSearchUnchanged() throws {
        let snap = snapshot(metadataFixture(instructions: 2))
        let api = WorkspaceScriptingAPI(store: store(snap))
        let value = try api.execute("search", arguments: .object(["query": .string("needle"), "kind": .string("symbol")]))
        XCTAssertEqual(value["total"], .int(1))
        XCTAssertEqual(value["results"], .array([WorkspaceScriptingAPI.searchRow(
            BinarySearchResult(address: 0x300000, kind: .symbol, preview: "needle", imageSlot: .primary))]))
    }

    func testPrefixMissRemainsUncoveredAcrossPages() throws {
        var analysis = metadataFixture()
        analysis.stringLiterals = [literal(String(repeating: "x", count: 4_096) + "needle", 0x200000)]
        let snap = snapshot(analysis)
        let first = fixedSearch(snap)
        XCTAssertEqual(first.sourceIncomplete[.string], "prefixLimited")
        let next = try XCTUnwrap(first.resumePoint)
        XCTAssertTrue(next.prefixLimited.contains(.string))
        let second = fixedSearch(snap, resume: next)
        XCTAssertNil(second.resumePoint)
        XCTAssertEqual(second.kindsPending, [.string])
        XCTAssertFalse(second.kindsCovered.contains(.string))
        let reply = WorkspaceScriptingAPI.searchPageReply(second, cumulative: first.results.count,
            query: "needle", mode: .text, kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
        XCTAssertEqual(reply["refusal"]?["code"], .string("preconditionFailed"))
        XCTAssertEqual(reply["refusal"]?["retryable"], .bool(false))
        XCTAssertNil(reply["results"])
    }

    func testMatchedPrefixKeepsLegacyTruncationWithoutIncompleteCoverage() throws {
        var analysis = ImageAnalysis()
        analysis.stringLiterals = [literal("needle" + String(repeating: "x", count: 4_096), 0x200000)]
        let snap = snapshot(analysis)
        let outcome = fixedSearch(snap)
        XCTAssertTrue(outcome.isTruncated)
        XCTAssertTrue(outcome.kindsPending.isEmpty)
        XCTAssertTrue(outcome.kindsCovered.contains(.string))
        let reply = WorkspaceScriptingAPI.searchPageReply(outcome, cumulative: 0,
            query: "needle", mode: .text, kinds: Set(BinarySearchResult.Kind.allCases), slotFilter: nil, snapshot: snap)
        XCTAssertEqual(reply["total"], .null)
        XCTAssertEqual(reply["isTruncated"], .bool(true))
        XCTAssertEqual(reply["results"]?.arrayValue?.count, 1)
        XCTAssertEqual(reply["nextCursor"], .null)
        XCTAssertNil(reply["incomplete"])
    }

    func testRefusedAppendRetriesLastWorkBudgetCandidate() throws {
        var analysis = ImageAnalysis()
        analysis.instructions = (0..<200_000).map { instruction($0, $0 == 199_999 ? "needle" : "nop") }
        let snap = snapshot(analysis)
        let first = fixedSearch(snap)
        XCTAssertTrue(first.results.isEmpty)
        XCTAssertEqual(first.visits, 200_000)
        XCTAssertEqual(first.stoppedBy, .workSteps)
        XCTAssertEqual(first.resumePoint?.row, 199_999)
        let second = fixedSearch(snap, resume: try XCTUnwrap(first.resumePoint))
        XCTAssertEqual(second.visits, 1)
        XCTAssertEqual(second.results.map(\.address), [analysis.instructions[199_999].address])
        XCTAssertNil(second.resumePoint)
    }

    func testInterruptedRegexRetriesCurrentCandidate() throws {
        var analysis = ImageAnalysis()
        analysis.instructions = [instruction(0, "needle")]
        let snap = snapshot(analysis)
        let clock = Search880CreationThenExpiredClock(freshReads: 3)
        let first = BinarySearchService().searchBounded(query: "needle", mode: .regex, in: snap,
            clock: { clock.now() })
        XCTAssertTrue(first.results.isEmpty)
        XCTAssertEqual(first.visits, 1)
        XCTAssertEqual(first.stoppedBy, .deadline)
        XCTAssertEqual(first.resumePoint?.row, 0)
        let second = BinarySearchService().searchBounded(query: "needle", mode: .regex, in: snap,
            resume: try XCTUnwrap(first.resumePoint), clock: { Date(timeIntervalSince1970: 0) })
        XCTAssertEqual(second.results.map(\.address), [0x1000])
        XCTAssertNil(second.resumePoint)
    }
}
