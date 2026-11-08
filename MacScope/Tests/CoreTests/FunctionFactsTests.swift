import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// All controls in this file are AUTHORED, NOT RUN for packet 1245.
@MainActor
final class FunctionFactsTests: XCTestCase {
    private enum Route: CaseIterable, Equatable { case inline, asynchronous, attached, mcpSync, mcpAsync }
    private let start: UInt64 = 0x1000065d0
    private var arguments: ScriptValue { .object(["address": .hex(start)]) }

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func edge(_ from: UInt64, _ to: UInt64, _ kind: String = "call") -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }

    private func makeStore(_ change: (inout ImageAnalysis) -> Void = { _ in }) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.functions = [function("fixture", start, start + 0x40), function("zero", start + 0x80, start + 0x80)]
        let names = ["_objc_opt_class", "_objc_msgSend$writableTypes", "_objc_msgSend$mutableCopy",
                     "_objc_msgSend$isRichText", "_objc_msgSend$removeObject:"]
        analysis.symbols = names.enumerated().map {
            SymbolSummary(id: UUID(), name: $0.element, address: 0x2000 + UInt64($0.offset * 4),
                          kind: "import", libraryName: nil)
        }
        analysis.xrefs = names.indices.reversed().map { edge(start + UInt64($0 * 4), 0x2000 + UInt64($0 * 4)) }
        analysis.xrefs.append(edge(start, 0x2000)) // endpoint duplicate is one call
        analysis.xrefs.append(edge(start + 0x20, 0x3000, "string"))
        analysis.stringLiteralCoverage = .complete
        analysis.stringLiterals = [StringLiteralSummary(id: UUID(), value: "hello", address: 0x3000,
            sourceSection: "__TEXT,__cstring", byteLength: 6)]
        analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals, cfStrings: [:])
        analysis.basicBlocks = [BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start,
            endAddress: start + 0x40, instructionCount: 16)]
        analysis.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: start + 4, to: start + 0x30, kind: "branch"),
            ControlFlowEdge(id: UUID(), from: start + 8, to: start + 0x30, kind: "switch"),
            ControlFlowEdge(id: UUID(), from: start + 12, to: 0x2000, kind: "call"),
            ControlFlowEdge(id: UUID(), from: start + 16, to: start + 20, kind: "fallthrough")]
        change(&analysis)
        let image = BinaryImage(id: UUID(), name: "facts", path: "/fixture", kind: "Mach-O executable", architecture: "arm64")
        return WorkspaceStore(workspaceName: "facts", snapshot: WorkspaceSnapshot(binaries: [image],
            analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func request(_ command: String, _ arguments: ScriptValue, id: ScriptValue = .int(1)) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": id, "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": arguments])])
    }

    private func envelope(_ route: Route, _ api: WorkspaceScriptingAPI, _ command: String,
                          _ arguments: ScriptValue, cap: Int = 8 * 1_024 * 1_024,
                          id: ScriptValue = .int(1)) async throws -> Data {
        let configuration = MCPServer.Configuration(maximumInputBytes: 65_536, maximumOutputBytes: cap,
            maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 16)
        let server = MCPServer(api: api, configuration: configuration)
        let input = try request(command, arguments, id: id).jsonData()
        let result: Data?
        if route == .mcpSync { result = server.handleMessage(input) }
        else { result = await server.handleMessageAsync(input) }
        return try XCTUnwrap(result)
    }

    private func read(_ route: Route, _ store: WorkspaceStore, _ command: String = "function-facts",
                      _ args: ScriptValue? = nil, api supplied: WorkspaceScriptingAPI? = nil) async throws -> ScriptValue {
        let args = args ?? arguments
        let api = supplied ?? WorkspaceScriptingAPI(store: store)
        switch route {
        case .inline: return try api.execute(command, arguments: args)
        case .asynchronous: return try await api.executeAsync(command, arguments: args)
        case .attached:
            let executor = MCPAttachExecutor(store: store, api: { _ in api })
            executor.setConsent(.allowed)
            return try await executor.execute(command, args)
        case .mcpSync, .mcpAsync:
            let reply = try ScriptValue.decode(try await envelope(route, api, command, args))
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            return try ScriptValue.decode(Data(try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue).utf8))
        }
    }

    private func failure(_ route: Route, _ store: WorkspaceStore, _ args: ScriptValue) async throws -> ScriptValue {
        if route == .mcpSync || route == .mcpAsync {
            let reply = try ScriptValue.decode(try await envelope(route, WorkspaceScriptingAPI(store: store), "function-facts", args))
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            return try ScriptValue.decode(Data(try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue).utf8))
        }
        do { _ = try await read(route, store, "function-facts", args); XCTFail("expected refusal"); return .null }
        catch { return try XCTUnwrap(MCPToolRefusal.executionRefusal(error)).value }
    }

    // NOT RUN. The roadmap acceptance text is deliberately unchanged:
    // TextEdit: `function-facts 0x1000065d0` lists, in order, `objc_opt_class`,
    // `writableTypes`, `mutableCopy`, `isRichText`, `removeObject:` with addresses, and is ≤ 8 KB.
    func testSyntheticRoadmapOrderAddressesAndComplete8192ByteFrame() async throws {
        let store = makeStore()
        for route in Route.allCases {
            let result = try await read(route, store)
            let calls = try XCTUnwrap(result["calls"]?["rows"]?.arrayValue)
            let tokens = try calls.map { row -> String in
                if let selector = row["selector"]?.stringValue { return selector }
                let name = try XCTUnwrap(row["toName"]?.stringValue)
                return name.hasPrefix("_") ? String(name.dropFirst()) : name
            }
            XCTAssertEqual(tokens, ["objc_opt_class", "writableTypes", "mutableCopy", "isRichText", "removeObject:"])
            XCTAssertEqual(calls.compactMap { $0["from"]?.addressValue }, (0..<5).map { start + UInt64($0 * 4) })
            for row in calls + (result["references"]?["rows"]?.arrayValue ?? []) {
                XCTAssertNotNil(row["from"]?.addressValue)
                XCTAssertNotNil(row["to"]?.addressValue)
            }
            XCTAssertEqual(result["branches"]?["branchCount"], .int(2))
            XCTAssertEqual(result["branches"]?["branch"], .int(1))
            XCTAssertEqual(result["branches"]?["switch"], .int(1))
            XCTAssertEqual(result["backend"]?["status"], .string("unavailable"))
            XCTAssertLessThanOrEqual(try result.jsonData().count, 3_000)
            // Non-MCP routes are checked in the same complete envelope with the
            // capture's real generation, rather than treating inner length as wire length.
            let wire: Data
            if route == .mcpSync || route == .mcpAsync {
                wire = try await envelope(route, WorkspaceScriptingAPI(store: store), "function-facts", arguments)
            } else { wire = try frame(result, generation: store.snapshot.analysisGenerationID).jsonData() }
            XCTAssertLessThanOrEqual(wire.count + 1, 8_192) // LF is included
        }
    }

    // R2 DELTA, NOT RUN. Each independently overfull section returns its ordered
    // prefix, not a whole-reply refusal. The duplicated omitted endpoint is not
    // a tenth observation, and the omitted ninth block contributes to aggregates.
    func testNinthCallReferenceAndBlockRetainEightOnEveryRoute() async throws {
        let calls = makeStore { analysis in
            analysis.xrefs = (0..<9).reversed().map { edge(start + UInt64($0 * 4), 0x2000) }
            analysis.xrefs.append(edge(start + 32, 0x2000)) // already omitted from the prefix
            analysis.basicBlocks = []
        }
        let references = makeStore { analysis in
            analysis.xrefs = (0..<9).reversed().map {
                edge(start + UInt64($0 * 4), 0x8000 + UInt64($0 * 4), "data")
            }
            analysis.xrefs.append(edge(start + 32, 0x8020, "data")) // already omitted from the prefix
            analysis.basicBlocks = []
        }
        let blocks = makeStore { analysis in
            analysis.xrefs = []
            analysis.basicBlocks = (0..<9).reversed().map { index in
                BasicBlockSummary(id: UUID(), functionID: UUID(),
                    startAddress: start + UInt64(index * 4),
                    endAddress: start + UInt64(index == 8 ? 0x44 : (index + 1) * 4),
                    instructionCount: index + 1)
            }
        }
        for (section, store) in [("calls", calls), ("references", references), ("size", blocks)] {
            for route in Route.allCases {
                let result = try await read(route, store)
                let category = try XCTUnwrap(result[section])
                let rows = try XCTUnwrap(category[section == "size" ? "blocks" : "rows"]?.arrayValue)
                XCTAssertEqual(rows.count, 8, "\(section), \(route)")
                XCTAssertEqual(category["total"], .int(9), "\(section), \(route)")
                XCTAssertEqual(category["omitted"], .int(1), "\(section), \(route)")
                XCTAssertEqual(category["truncated"], .bool(true), "\(section), \(route)")
                XCTAssertEqual(rows.compactMap { $0[section == "size" ? "start" : "from"]?.addressValue },
                    (0..<8).map { start + UInt64($0 * 4) })
                if section == "size" {
                    XCTAssertEqual(category["blockCount"], .int(9))
                    XCTAssertEqual(category["instructionCount"], .int(45))
                    XCTAssertEqual(category["straddlingBlockCount"], .int(1))
                    XCTAssertEqual(rows.compactMap { $0["instructionCount"]?.intValue }.reduce(0, +), 36)
                } else {
                    XCTAssertEqual(category["enumerationComplete"], .bool(true))
                }
                XCTAssertLessThanOrEqual(try result.jsonData().count, 3_000)
                let wire: Data
                if route == .mcpSync || route == .mcpAsync {
                    wire = try await envelope(route, WorkspaceScriptingAPI(store: store), "function-facts",
                        arguments, cap: 8_192)
                } else {
                    let framed = try frame(result, generation: store.snapshot.analysisGenerationID).jsonData()
                    wire = try MCPFrameAdmission.response(framed, id: .integer(1), maximumBytes: 8_192)
                }
                let reply = try ScriptValue.decode(wire)
                XCTAssertNil(reply["error"])
                XCTAssertEqual(reply["result"]?["isError"], .bool(false))
                let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), result) // capped frame preserves the sheet
                XCTAssertLessThanOrEqual(wire.count + 1, 8_192) // complete frame including LF
            }
        }
    }

    // NOT RUN.
    func testCatalogSchemaAllowlistAndShortSummary() async throws {
        XCTAssertTrue(WorkspaceScriptingAPI.snapshotListCommands.contains("function-facts"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("function-facts"))
        XCTAssertFalse(WorkspaceScriptingAPI.liftingSnapshotCommands.contains("function-facts"))
        XCTAssertFalse(MCPAttachExecutor.limitedCommands.contains("function-facts"))
        XCTAssertFalse(AppleScriptCommandTranslator.allowlistedCommandIDs.contains("function-facts"))
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "function-facts" })
        XCTAssertFalse(info.mutates)
        XCTAssertEqual(info.summary, "Stored function facts: ordered calls, references, branches, size and backend availability.")
        XCTAssertEqual(info.summary.utf8.count, 90)
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        guard case .object(let properties) = try XCTUnwrap(schema["properties"]) else { return XCTFail("properties") }
        XCTAssertEqual(Set(properties.keys), ["function", "address", "imageSlot"])
        XCTAssertNil(schema["required"])
        XCTAssertEqual(schema["anyOf"]?.arrayValue?.count, 2)
        for route in Route.allCases {
            let commands = try await read(route, makeStore(), "commands", .object([:]))
            XCTAssertTrue(commands.arrayValue?.contains { $0["name"] == .string("function-facts") } == true)
        }
        for route in [Route.mcpSync, .mcpAsync] {
            let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()))
            let input = try ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")]).jsonData()
            let data: Data?
            if route == .mcpSync { data = server.handleMessage(input) } else { data = await server.handleMessageAsync(input) }
            let reply = try ScriptValue.decode(try XCTUnwrap(data))
            let tool = try XCTUnwrap(reply["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string("function-facts") })
            XCTAssertEqual(tool["annotations"]?["readOnlyHint"], .bool(true))
        }
    }

    // NOT RUN. 1272 FD3 makes function-facts address selection order-independent.
    // Exact start wins, then the smallest start/end/name tuple; name selection stays unchanged.
    func testMembershipSameStartInteriorUnknownExtentAndUncovered() async throws {
        for reverse in [false, true] {
            let store = makeStore { analysis in
                let a = function("A", start, start + 8), b = function("B", start, start + 0x40)
                analysis.functions = reverse ? [b, a] : [a, b]
            }
            for route in Route.allCases {
                let first = try await read(route, store)
                XCTAssertEqual(first["name"], .string("A"))
                let interior = try await read(route, store, "function-facts", .object(["address": .hex(start + 0x10)]))
                XCTAssertEqual(interior["name"], .string("B"))
                XCTAssertEqual(interior["resolution"], .string("containing"))
                let named = try await read(route, store, "function-facts", .object(["function": .string("A")]))
                XCTAssertEqual(named["end"], .hex(start + 8))
            }
        }
        let zero = makeStore { $0.xrefs = [edge(start + 0x80, 0x3000, "string"), edge(start + 0x81, 0x3000, "string")] }
        let last = makeStore { analysis in
            analysis.functions = [function("last", UInt64.max, UInt64.max)]
            analysis.xrefs = [edge(UInt64.max, 0x3000, "string"), edge(UInt64.max - 1, 0x3000, "string")]
            analysis.basicBlocks = []
        }
        for route in Route.allCases {
            let result = try await read(route, zero, "function-facts", .object(["address": .hex(start + 0x80)]))
            XCTAssertEqual(result["extent"], .string("exactStartOnly"))
            XCTAssertEqual(result["size"]?["sizeKnown"], .bool(false))
            XCTAssertEqual(result["size"]?["bytes"], .null)
            XCTAssertEqual(result["references"]?["rows"]?.arrayValue?.count, 1)
            let final = try await read(route, last, "function-facts", .object(["address": .hex(UInt64.max)]))
            XCTAssertEqual(final["references"]?["rows"]?.arrayValue?.count, 1)
            let refusal = try await failure(route, zero, .object(["address": .hex(start + 0x81)]))
            XCTAssertEqual(refusal["refusal"]?["code"], .string("unknownSubject"))
            XCTAssertEqual(refusal["refusal"]?["resolution"], .string("refused"))
        }
    }

    // NOT RUN. The straddling block is counted whole even with a foreign functionID.
    func testBlockStartMembershipWholeCountsAndDistinctCallSites() async throws {
        let store = makeStore { analysis in
            analysis.basicBlocks = [
                BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start - 4, endAddress: start + 4, instructionCount: 77),
                BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start + 4, endAddress: start + 0x44, instructionCount: 17)]
            analysis.xrefs = [edge(start, 0x2000), edge(start + 4, 0x2000), edge(start, 0x2000)]
        }
        for route in Route.allCases {
            let result = try await read(route, store)
            XCTAssertEqual(result["calls"]?["rows"]?.arrayValue?.count, 2)
            XCTAssertEqual(result["size"]?["blockCount"], .int(1))
            XCTAssertEqual(result["size"]?["instructionCount"], .int(17))
            XCTAssertEqual(result["size"]?["straddlingBlockCount"], .int(1))
            XCTAssertEqual(result["size"]?["blocks"]?.arrayValue?.first?["end"], .hex(start + 0x44))
        }
    }

    // NOT RUN. Compare existing-command replies before and after the facts read,
    // including their exact JSON bytes, on every binding.
    func testReadOnlyDeterministicAndLegacyRepliesUnchanged() async throws {
        for route in Route.allCases {
            let store = makeStore()
            let snapshot = store.snapshot
            let undo = (store.undoManager.canUndo, store.undoManager.undoActionName, store.undoManager.groupingLevel)
            let sequence = store.editJournal?.sequence
            var legacy: [String: Data] = [:]
            for command in ["function-references", "callees", "basic-blocks"] {
                legacy[command] = try await read(route, store, command).jsonData()
            }
            let first = try await read(route, store), second = try await read(route, store)
            XCTAssertEqual(try first.jsonData(), try second.jsonData())
            for command in ["function-references", "callees", "basic-blocks"] {
                let after = try await read(route, store, command)
                XCTAssertEqual(try after.jsonData(), legacy[command])
            }
            XCTAssertEqual(store.snapshot.analysisGenerationID, snapshot.analysisGenerationID)
            XCTAssertEqual(store.snapshot.functions, snapshot.functions)
            XCTAssertEqual(store.snapshot.symbols, snapshot.symbols)
            XCTAssertEqual(store.snapshot.xrefs, snapshot.xrefs)
            XCTAssertEqual(store.snapshot.basicBlocks, snapshot.basicBlocks)
            XCTAssertEqual(store.snapshot.controlFlowEdges, snapshot.controlFlowEdges)
            XCTAssertEqual(store.snapshot.addressOverrides, snapshot.addressOverrides)
            XCTAssertEqual(store.snapshot.typeDefinitions, snapshot.typeDefinitions)
            XCTAssertEqual(store.snapshot.manualXRefs, snapshot.manualXRefs)
            XCTAssertEqual(store.editJournal?.sequence, sequence)
            XCTAssertEqual(store.undoManager.canUndo, undo.0)
            XCTAssertEqual(store.undoManager.undoActionName, undo.1)
            XCTAssertEqual(store.undoManager.groupingLevel, undo.2)
        }
    }

    private func frame(_ payload: ScriptValue, generation: UUID,
                       id: ScriptValue = .int(1), note: ScriptValue? = nil, isError: Bool = false) throws -> ScriptValue {
        let capture = ScriptingGenerationCapture()
        capture.record(generation)
        var content: [ScriptValue] = [.object(["type": .string("text"),
            "text": .string(String(decoding: try payload.jsonData(), as: UTF8.self))])]
        if let note { content.append(.object(["type": .string("text"),
            "text": .string(String(decoding: try ScriptValue.object(["note": note]).jsonData(), as: UTF8.self))])) }
        var result: [String: ScriptValue] = ["content": .array(capture.appendingGeneration(to: content)),
            "isError": .bool(isError), "_meta": capture.metadata]
        if let note { result["note"] = note }
        return .object(["jsonrpc": .string("2.0"), "id": id, "result": .object(result)])
    }

    // G5-1 and G5-3, NOT RUN. Actual transport boundaries include LF. A complete
    // frame exactly at cap succeeds; one fewer allowed byte gives a fallback.
    func testEscapedFinalFrameExactAndOneOverAndInnerFitsButOuterDoesNot() async throws {
        let store = makeStore { analysis in
            analysis.functions[0].name = "quotes\"\\\t雪"
            analysis.symbols[1].name = "_objc_msgSend$a\"\\雪"
            analysis.stringLiterals[0].value = "v\"\\\n雪"
            analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals, cfStrings: [:])
        }
        let id = ScriptValue.string(String(repeating: "\\", count: 256))
        for route in Route.allCases {
            let result = try await read(route, store)
            let inner = try result.jsonData()
            XCTAssertLessThanOrEqual(inner.count, 3_000)
            let full = try frame(result, generation: store.snapshot.analysisGenerationID, id: id).jsonData()
            let original: MacScopeAnalysisCore.Phase2ProductionJSONValue = .string(String(repeating: "\\", count: 256))
            // Measure the final canonical/restored form, not Foundation's
            // potentially different spelling of the same JSON strings.
            let canonical = try MCPFrameAdmission.response(full, id: original, maximumBytes: 8_192)
            XCTAssertNotNil(try ScriptValue.decode(canonical)["result"])
            let exact = try MCPFrameAdmission.response(full, id: original, maximumBytes: canonical.count + 1)
            XCTAssertEqual(try ScriptValue.decode(exact)["result"]?["isError"], .bool(false))
            XCTAssertEqual(exact.count + 1, canonical.count + 1)
            let oneOver = try MCPFrameAdmission.response(full, id: original, maximumBytes: canonical.count)
            XCTAssertEqual(try ScriptValue.decode(oneOver)["error"]?["message"], .string("Response exceeds limit"))
            XCTAssertLessThan(oneOver.count, canonical.count)
            XCTAssertGreaterThan(full.count + 1, inner.count)
            // This discriminates outer escaping from inner admission without
            // relying on the server's earlier inner <= cap/2 check.
            XCTAssertLessThanOrEqual(inner.count, full.count)
        }
        for route in [Route.mcpSync, .mcpAsync] {
            let full = try await envelope(route, WorkspaceScriptingAPI(store: store), "function-facts", arguments, id: id)
            let response = try ScriptValue.decode(full)
            let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let cap = max(2 * text.utf8.count, full.count + 1)
            let admitted = try await envelope(route, WorkspaceScriptingAPI(store: store), "function-facts", arguments,
                cap: cap, id: id)
            XCTAssertNotNil(try ScriptValue.decode(admitted)["result"])
            let tiny = try await envelope(route, WorkspaceScriptingAPI(store: store), "function-facts", arguments,
                cap: 1_024, id: .int(1))
            XCTAssertNotNil(try ScriptValue.decode(tiny)["error"])
        }
    }

    // G5-2, NOT RUN. Exercise success, tool refusal, protocol error/cancellation,
    // fallback, generation/_meta and the existing optional dispatch-note frame.
    // F4 itself never creates a dispatch note (the production sink is callers-only).
    func testEveryAdmittedEnvelopeBranchAndOriginalNumericID() async throws {
        let id: MacScopeAnalysisCore.Phase2ProductionJSONValue = .number("1" + String(repeating: "0", count: 255))
        let store = makeStore()
        for route in Route.allCases {
            let payload = try await read(route, store)
            let refusal = MCPToolRefusal(code: .budgetExceeded, detail: "bounded", budget: .init(unit: .bytes, limit: 3_000),
                used: 3_001, narrowing: ["address"]).value
            for candidate in [try frame(payload, generation: store.snapshot.analysisGenerationID),
                              try frame(refusal, generation: store.snapshot.analysisGenerationID, isError: true),
                              try frame(payload, generation: store.snapshot.analysisGenerationID, note: .string("a\"\\\n雪")),
                              .object(["jsonrpc": .string("2.0"), "id": .int(0),
                                  "error": .object(["code": .int(-32800), "message": .string("Request cancelled")])]),
                              .object(["jsonrpc": .string("2.0"), "id": .int(0),
                                  "error": .object(["code": .int(-32602), "message": .string("Invalid params")])])] {
                let bytes = try MCPFrameAdmission.response(candidate.jsonData(), id: id, maximumBytes: 8_192)
                XCTAssertLessThanOrEqual(bytes.count + 1, 8_192)
                XCTAssertEqual(try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(bytes, limits: .providerEnvelope).objectValue?["id"], id)
            }
            let oversized = try frame(.string(String(repeating: "x", count: 4_000)), generation: store.snapshot.analysisGenerationID)
            let fallback = try MCPFrameAdmission.response(oversized.jsonData(), id: .integer(1), maximumBytes: 512)
            XCTAssertNotNil(try ScriptValue.decode(fallback)["error"])
            XCTAssertThrowsError(try MCPFrameAdmission.response(oversized.jsonData(),
                id: .string(String(repeating: "\\", count: 256)), maximumBytes: 512))
        }
    }

    // G5-4, NOT RUN. Cancel every cooperative boundary, covering collection,
    // candidate/tree construction and the checks on both sides of final encoding.
    func testCancellationAtEverySharedBuilderBoundaryPublishesNoPrefix() throws {
        for warm in [false, true] {
            func snapshot() throws -> WorkspaceSnapshot {
                let value = makeStore().snapshot
                if warm { _ = try WorkspaceScriptingAPI.functionFacts(arguments, snapshot: value, checkpoint: {}) }
                return value
            }
            var total = 0
            _ = try WorkspaceScriptingAPI.functionFacts(arguments, snapshot: snapshot(), checkpoint: { total += 1 })
            for stop in 1...total {
                var visits = 0, output: ScriptValue?
                XCTAssertThrowsError(try { output = try WorkspaceScriptingAPI.functionFacts(arguments, snapshot: snapshot(), checkpoint: {
                    visits += 1
                    if visits == stop { throw CancellationError() }
                }) }()) { XCTAssertTrue($0 is CancellationError) }
                XCTAssertNil(output)
                XCTAssertEqual(visits, stop)
            }
        }
    }

    // G5-4 adapters, NOT RUN. Each binding owns the task being cancelled.
    func testFiveRoutesCheckTaskCancellationBeforePublication() async throws {
        for route in Route.allCases {
            let store = makeStore()
            let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: {
                withUnsafeCurrentTask { $0?.cancel() }
            })
            let operation = Task { @MainActor () -> Bool in
                do {
                    if route == .mcpSync || route == .mcpAsync {
                        let response = try ScriptValue.decode(try await envelope(route, api, "function-facts", arguments))
                        return response["result"] == nil && response["error"]?["code"] == .int(-32800)
                    }
                    _ = try await read(route, store, api: api)
                    return false
                } catch { return error is CancellationError }
            }
            let cancelled = await operation.value
            XCTAssertTrue(cancelled)
        }
    }

    private final class Gate: @unchecked Sendable {
        private let condition = NSCondition()
        private let stop: Int
        private var count = 0, held = false, opened = false
        init(_ stop: Int = 1) { self.stop = stop }
        func checkpoint() {
            condition.lock(); defer { condition.unlock() }
            count += 1
            guard count == stop else { return }
            held = true
            condition.broadcast()
            while !opened { condition.wait() }
        }
        func open() { condition.lock(); opened = true; condition.broadcast(); condition.unlock() }
        private var isHeld: Bool { condition.lock(); defer { condition.unlock() }; return held }
        func waitUntilHeld() async throws {
            for _ in 0..<5_000 {
                if isHeld { return }
                try await Task.sleep(nanoseconds: 1_000_000)
            }
            XCTFail("NOT RUN control timed out before the requested checkpoint")
            throw CancellationError()
        }
    }

    // G5-5, NOT RUN. Suspensible routes publish the original capture when only
    // slot/owner/analysis/authored data changes. There is no new freshness guard.
    // Inline and synchronous MCP cannot interleave a MainActor edit in this span.
    func testCapturedOwnerSlotGenerationAndRenameAreDisclosedRatherThanRestamped() async throws {
        for route in [Route.asynchronous, .attached, .mcpAsync] {
            for change in ["owner", "slot", "generation", "rename"] {
                let store = makeStore(), gate = Gate(), capture = ScriptingGenerationCapture()
                let original = store.snapshot
                let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { gate.checkpoint() })
                let operation = Task { @MainActor in
                    if route == .mcpAsync {
                        return try ScriptValue.decode(try await envelope(route, api, "function-facts", arguments))
                    }
                    return try await ScriptingGenerationCapture.$current.withValue(capture) {
                        try await read(route, store, api: api)
                    }
                }
                defer { gate.open() }
                try await gate.waitUntilHeld()
                if change == "rename" {
                    store.setCustomName(start, in: .primary, name: "live-name")
                } else {
                    var live = store.snapshot
                    if change == "generation" { live.functions.append(function("new", 0x9000, 0x9004)) }
                    else {
                        let slot = change == "slot" ? ImageSlot(rawValue: 1) : ImageSlot.primary
                        live.binaries = [BinaryImage(id: UUID(), name: "replacement", path: "/fixture",
                            kind: "Mach-O executable", architecture: "arm64", slot: slot)]
                    }
                    store.snapshot = live
                }
                XCTAssertNotEqual(store.snapshot.analysisGenerationID, original.analysisGenerationID)
                gate.open()
                let returned = try await operation.value
                let result: ScriptValue
                if route == .mcpAsync {
                    XCTAssertEqual(returned["result"]?["_meta"]?["generation"], .string(original.analysisGenerationID.uuidString))
                    let text = try XCTUnwrap(returned["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                    result = try ScriptValue.decode(Data(text.utf8))
                } else {
                    result = returned
                    XCTAssertEqual(capture.generation, original.analysisGenerationID)
                    XCTAssertEqual(capture.disclosing(result)["generation"], .string(original.analysisGenerationID.uuidString))
                }
                XCTAssertEqual(result["name"], .string("fixture"))
                XCTAssertEqual(result["imageSlot"], .int(0))
                XCTAssertEqual(result["imageOwner"], .string(try XCTUnwrap(original.binaries.first).id.uuidString))
            }
        }
    }

    // G5-5, NOT RUN. The existing attach authority check is a different fence
    // from generation freshness and refuses late reads after document/grant loss.
    func testAttachedDocumentChangeAndRevokedConsentNeverReleaseRead() async throws {
        for revoked in [false, true] {
            let store = makeStore(), gate = Gate()
            var documentMatches = true
            let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { gate.checkpoint() })
            let executor = MCPAttachExecutor(store: store, api: { _ in api })
            executor.setConsent(.allowed)
            executor.authorize = { documentMatches }
            let operation = Task { @MainActor in try await executor.execute("function-facts", arguments) }
            defer { gate.open() }
            try await gate.waitUntilHeld()
            if revoked { executor.setConsent(.revoked) } else { documentMatches = false }
            gate.open()
            do { _ = try await operation.value; XCTFail("late attached read was released") }
            catch {
                if !revoked { XCTAssertEqual(error as? MCPAttachExecutor.Failure, .notAuthorized) }
                else { XCTAssertTrue(error is CancellationError || error as? MCPAttachExecutor.Failure == .notAuthorized) }
            }
        }
    }

    // G5-4 final encoding, NOT RUN. Count the complete snapshot route's checkpoints, then
    // stop the actual detached MCP encoder immediately before/after jsonData().
    func testParentCancellationDuringFinalMCPEncodingNeverPublishesSuccess() async throws {
        for afterEncoding in [false, true] {
            let store = makeStore()
            _ = try WorkspaceScriptingAPI.functionFacts(arguments, snapshot: store.snapshot, checkpoint: {})
            var total = 0
            _ = try WorkspaceScriptingAPI.snapshotListRead("function-facts", arguments: arguments,
                snapshot: store.snapshot, checkpoint: { total += 1 })
            let gate = Gate(total + (afterEncoding ? 2 : 1))
            let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { gate.checkpoint() })
            let server = MCPServer(api: api)
            let input = try request("function-facts", arguments).jsonData()
            let operation = Task { @MainActor in await server.handleMessageAsync(input) }
            defer { gate.open() }
            try await gate.waitUntilHeld()
            operation.cancel()
            gate.open()
            let returned = await operation.value
            let result = try ScriptValue.decode(try XCTUnwrap(returned))
            XCTAssertNil(result["result"])
            XCTAssertEqual(result["error"]?["code"], .int(-32800))
        }
    }

    private actor Output {
        private var values: [Data] = []
        func append(_ value: Data) { values.append(value) }
        var first: Data? { values.first }
    }

    // G5-2 original-ID restoration, NOT RUN. This exercises the real request
    // session, which checks a 256-byte numeric lexeme before replacing it by 0.
    func testProductionSessionRestoresMaximumNumericID() async throws {
        let store = makeStore(), output = Output()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 65_536, maximumOutputBytes: 8_192,
            maximumToolDurationNanoseconds: 30_000_000_000, maximumRememberedCancellations: 16))
        let session = server.makeRequestSession(output: { await output.append($0) })
        let numericID = "1" + String(repeating: "0", count: 255)
        let input = Data("{\"jsonrpc\":\"2.0\",\"id\":\(numericID),\"method\":\"tools/call\",\"params\":{\"name\":\"function-facts\",\"arguments\":{\"address\":\"0x1000065d0\"}}}".utf8)
        await session.receive(input)
        var response: Data?
        for _ in 0..<5_000 {
            response = await output.first
            if response != nil { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        let bytes = try XCTUnwrap(response)
        XCTAssertLessThanOrEqual(bytes.count + 1, 8_192)
        let parsed = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(bytes, limits: .providerEnvelope)
        XCTAssertEqual(parsed.objectValue?["id"], .number(numericID))
        XCTAssertNotNil(parsed.objectValue?["result"])
        await session.finishInput()
    }

    // Realistic 8+8+8 ObjC-style function that used to be refused for size (budgetExceeded, 3001).
    // Rows are shed blocks first, then references, then calls, and the section omitted counts follow.
    func testFullRowCapsWithLongSelectorsShedRowsInsteadOfRefusing() async throws {
        let selectors = (0..<8).map { "_objc_msgSend$setAttributedStringValueForTextStorageRange\($0):withOptions:" }
        let store = makeStore { analysis in
            analysis.symbols = selectors.enumerated().map {
                SymbolSummary(id: UUID(), name: $0.element, address: 0x2000 + UInt64($0.offset * 4),
                              kind: "import", libraryName: nil)
            }
            analysis.xrefs = selectors.indices.map { edge(start + UInt64($0 * 4), 0x2000 + UInt64($0 * 4)) }
                + (0..<8).map { edge(start + 0x20 + UInt64($0 * 2), 0x3000 + UInt64($0 * 0x40), "string") }
            analysis.stringLiterals = (0..<8).map {
                StringLiteralSummary(id: UUID(), value: String(repeating: "NSAttributedString-\($0)-", count: 4),
                    address: 0x3000 + UInt64($0 * 0x40), sourceSection: "__TEXT,__cstring", byteLength: 80)
            }
            analysis.constantStrings = ImageConstantStringProvider.build(
                stringLiterals: analysis.stringLiterals, cfStrings: [:])
            analysis.basicBlocks = (0..<8).map {
                BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start + UInt64($0 * 8),
                    endAddress: start + UInt64($0 * 8 + 8), instructionCount: 2)
            }
        }
        for route in Route.allCases {
            let result = try await read(route, store)
            XCTAssertLessThanOrEqual(try result.jsonData().count, 3_000)
            let calls = try XCTUnwrap(result["calls"]?["rows"]?.arrayValue)
            let references = try XCTUnwrap(result["references"]?["rows"]?.arrayValue)
            let blocks = try XCTUnwrap(result["size"]?["blocks"]?.arrayValue)
            XCTAssertEqual(result["calls"]?["total"], .int(8))
            XCTAssertEqual(result["references"]?["total"], .int(8))
            XCTAssertEqual(result["size"]?["total"], .int(8))
            // Overflow happened: the last section (blocks) lost rows, and nothing earlier was cut first.
            XCTAssertLessThan(blocks.count + references.count + calls.count, 24)
            if references.count < 8 { XCTAssertTrue(blocks.isEmpty) }
            if calls.count < 8 { XCTAssertTrue(references.isEmpty && blocks.isEmpty) }
            // Omitted counts and truncation flags follow the retained rows; rows are kept from the front.
            XCTAssertEqual(result["calls"]?["omitted"], .int(Int64(8 - calls.count)))
            XCTAssertEqual(result["references"]?["omitted"], .int(Int64(8 - references.count)))
            XCTAssertEqual(result["size"]?["omitted"], .int(Int64(8 - blocks.count)))
            XCTAssertEqual(result["size"]?["truncated"], .bool(blocks.count < 8))
            XCTAssertEqual(calls.compactMap { $0["from"]?.addressValue },
                (0..<calls.count).map { start + UInt64($0 * 4) })
        }
    }

    // The pre-count refusal reports the real count it reached, not limit+1.
    func testPreCountRefusalReportsRealUsed() throws {
        let admission = FunctionFactsAdmission(checkpoint: {})
        try admission.output(2_990)
        XCTAssertThrowsError(try admission.output(25)) {
            XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.used, 3_015)
            XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.budget?.limit, 3_000)
        }
    }

    // G5-6, NOT RUN. Nonmatching candidates still spend the same allowance.
    func testSharedWorkOversizedFieldAndColdEnrichmentBudgets() async throws {
        let functions = makeStore { analysis in
            analysis.functions += (0..<100_001).map { function("", 0x4000 + UInt64($0 * 4), 0x4004 + UInt64($0 * 4)) }
        }
        let nonmatching = makeStore { analysis in
            analysis.xrefs = (0..<100_001).map { edge(0x4000 + UInt64($0 * 4), 0x2000) }
        }
        let name = makeStore { $0.symbols[0].name = String(repeating: "x", count: 100_000) }
        let enrichment = makeStore { analysis in
            analysis.indirectSymbols = (0..<100_001).map { IndirectSymbolSummary(id: UUID(), kind: "pointer",
                sourceSection: "__DATA,__got", address: 0x5000 + UInt64($0 * 8), entrySize: 8, tableIndex: $0,
                rawSymbolIndex: 0, symbolIndex: nil, symbolName: "outside", libraryOrdinal: nil, libraryName: nil,
                isLocal: false, isAbsolute: false) }
        }
        for route in Route.allCases {
            for (store, unit) in [(functions, "workSteps"), (nonmatching, "workSteps"),
                                  (name, "bytes"), (enrichment, "workSteps")] {
                let refusal = try await failure(route, store, arguments)
                XCTAssertEqual(refusal["refusal"]?["code"], .string("budgetExceeded"))
                XCTAssertEqual(refusal["refusal"]?["budget"]?["unit"], .string(unit))
                XCTAssertNotNil(refusal["refusal"]?["used"])
                XCTAssertFalse(refusal["refusal"]?["narrowing"]?.arrayValue?.isEmpty ?? true)
            }
            // Small cold enrichment succeeds and the second same-capture reply is identical.
            let cold = makeStore()
            let first = try await read(route, cold), second = try await read(route, cold)
            XCTAssertEqual(try first.jsonData(), try second.jsonData())
        }
    }

    // NOT RUN. The admission object is one counter set, not a fresh allowance
    // per producer. Exact remaining capacity is accepted, then cap+1 refuses.
    func testAdmissionExactCapsAndSharedRemainingCapacity() throws {
        // NOT RUN. Direct selectors must be admitted before trim/lowercase/UUID
        // parsing, not merely bounded later by the MCP argument validator.
        for key in ["address", "imageSlot"] {
            let args: ScriptValue = .object(["function": .string("fixture"),
                key: .string(String(repeating: " ", count: 100_000))])
            XCTAssertThrowsError(try WorkspaceScriptingAPI.functionFacts(args,
                snapshot: makeStore().snapshot, checkpoint: {})) {
                XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.budget?.unit, .bytes)
                XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.used, 257)
            }
        }
        let admission = FunctionFactsAdmission(checkpoint: {})
        try admission.visit(99_000)
        try admission.visit(1_000)
        XCTAssertThrowsError(try admission.visit()) {
            XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.budget?.unit, .workSteps)
        }
        let bytes = FunctionFactsAdmission(checkpoint: {})
        try bytes.output(3_000)
        XCTAssertThrowsError(try bytes.output(1)) {
            XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.used, 3_001)
        }
        XCTAssertThrowsError(try bytes.output(-1))
        let rows = FunctionFactsAdmission(checkpoint: {})
        for _ in 0..<32 { try rows.row() }
        XCTAssertThrowsError(try rows.row()) {
            XCTAssertEqual(MCPToolRefusal.executionRefusal($0)?.budget?.unit, .rows)
        }
    }

    // NOT RUN. Reuse F2's CFString interpretation and unique text link. Preview
    // truncation preserves scalar boundaries and reports the original byte count.
    func testF2DescriptionsPreviewCoverageAndUnavailableBuckets() async throws {
        let text = String(repeating: "x", count: 255) + "雪-tail"
        let preview = makeStore { analysis in
            analysis.xrefs = [edge(start, 0x3000, "string"), edge(start + 4, 0x7000, "selref")]
            analysis.stringLiterals[0].value = text
            analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals, cfStrings: [:])
            analysis.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        }
        let cfString = makeStore { analysis in
            analysis.xrefs = [edge(start, 0x4000, "data")]
            analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals,
                cfStrings: [0x4000: "hello"])
        }
        let empty = makeStore { analysis in
            analysis.xrefs = []; analysis.basicBlocks = []; analysis.controlFlowEdges = []
            analysis.stringLiteralCoverage = nil
        }
        for route in Route.allCases {
            let result = try await read(route, preview)
            let rows = try XCTUnwrap(result["references"]?["rows"]?.arrayValue)
            XCTAssertEqual(rows[0]["value"], .string(String(repeating: "x", count: 255)))
            XCTAssertEqual(rows[0]["valueTruncated"], .bool(true))
            XCTAssertEqual(rows[0]["valueByteLength"], .int(Int64(text.utf8.count)))
            XCTAssertEqual(rows[1]["valueStatus"], .string("unavailable"))
            XCTAssertNotNil(result["stringLiteralCoverage"]?["stopReason"]?.stringValue)
            let linked = try await read(route, cfString)
            XCTAssertEqual(linked["references"]?["rows"]?.arrayValue?.first?["targetKind"], .string("cfString"))
            XCTAssertNil(linked["references"]?["rows"]?.arrayValue?.first?["cString"]) // describer no longer infers a C-string link from equal text (DataReferences.swift describe)
            let unavailable = try await read(route, empty)
            XCTAssertEqual(unavailable["calls"]?["reason"], .string("noStoredXRefs"))
            XCTAssertEqual(unavailable["branches"]?["status"], .string("unavailable"))
            XCTAssertEqual(unavailable["size"]?["blockStatus"], .string("unavailable"))
            XCTAssertEqual(unavailable["stringLiteralCoverage"]?["status"], .string("unavailable"))
        }
    }
}
