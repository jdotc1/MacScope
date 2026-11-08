import Foundation
import XCTest
@testable import MacScope

@MainActor
final class StructuredRefusalTests: XCTestCase {
    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func store(_ analysis: ImageAnalysis) -> WorkspaceStore {
        let image = BinaryImage(id: UUID(), name: "refusal-fixture", path: "/tmp/refusal-fixture",
                                kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        return WorkspaceStore(workspaceName: "structured-refusals",
            snapshot: WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func bytesStore() -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.sections = [SectionSummary(id: UUID(), name: "__TEXT,__data", address: 0x1000,
            size: 0x30000, fileOffset: 0, isExecutable: false)]
        analysis.imageBytes = Data(repeating: 0xab, count: 0x30000)
        return store(analysis)
    }

    private func request(_ command: String, _ arguments: ScriptValue, id: Int64 = 1) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(id), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": arguments])])
    }

    private func call(_ server: MCPServer, _ command: String, _ arguments: ScriptValue,
                      id: Int64 = 1) async throws -> ScriptValue {
        let bytes = await server.handleMessageAsync(try request(command, arguments, id: id).jsonData())
        return try ScriptValue.decode(try XCTUnwrap(bytes))
    }

    private func refusal(_ reply: ScriptValue) throws -> ScriptValue {
        XCTAssertNil(reply["error"])
        XCTAssertEqual(reply["result"]?["isError"], .bool(true))
        let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let value = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(value["error"], .string("refused"))
        return try XCTUnwrap(value["refusal"])
    }

    private func caught(_ body: () throws -> ScriptValue,
                        file: StaticString = #filePath, line: UInt = #line) throws -> ScriptingError {
        do {
            _ = try body()
            XCTFail("expected refusal", file: file, line: line)
            throw ScriptingError.invalidArgument("test did not refuse")
        } catch let error as ScriptingError {
            return error
        }
    }

    private func assertBudget(_ error: ScriptingError, detail: String, unit: MCPRefusalBudget.Unit,
                              limit: Int64, used: Int64?, narrowing: [String],
                              file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(error, .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: detail,
            budget: .init(unit: unit, limit: limit), used: used, narrowing: narrowing)), file: file, line: line)
        // Independent literal prose oracle for the unchanged in-process surface.
        XCTAssertEqual(error.errorDescription, "Invalid argument: " + detail + ".", file: file, line: line)
    }

    func testReadBytesOverBudgetIsTypedRefusal() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: bytesStore()))
        let fields = try refusal(await call(server, "read-bytes",
            .object(["address": .hex(0x1000), "count": .int(704_736)])))
        XCTAssertEqual(fields["code"], .string("budgetExceeded"))
        XCTAssertEqual(fields["budget"], .object(["unit": .string("bytes"), "limit": .int(100_000)]))
        XCTAssertEqual(fields["used"], .int(196_608))
        XCTAssertEqual(fields["narrowing"], .array([.string("count")]))
        XCTAssertEqual(fields["retryable"], .bool(false))
    }

    func testReadBytesAtTheStatedLimitSucceeds() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: bytesStore()))
        let reply = try await call(server, "read-bytes",
            .object(["address": .hex(0x1000), "count": .int(100_000)]))
        XCTAssertNil(reply["error"])
        XCTAssertEqual(reply["result"]?["isError"], .bool(false))
        let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let output = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(output["length"], .int(100_000))
        XCTAssertEqual(output["hex"]?.stringValue?.count, 200_000)
        let fields = try refusal(await call(server, "read-bytes",
            .object(["address": .hex(0x1000), "count": .int(100_001)]), id: 2))
        XCTAssertEqual(fields["used"], .int(100_001))
        XCTAssertEqual(fields["budget"]?["limit"], .int(100_000))
    }

    func testSnapshotBudgetRefusalsAreTyped() throws {
        var analysis = ImageAnalysis()
        analysis.functions = [function("target", 0x2000, 0x2004)]
        analysis.xrefs = (0..<3).map {
            XRef(id: UUID(), from: UInt64($0 + 1), to: 0x2000, kind: XRefKind.call)
        }
        var snapshot = store(analysis).snapshot
        let arguments = ScriptValue.object(["to": .hex(0x2000)])
        let work = try caught {
            try WorkspaceScriptingAPI.snapshotXRefRead(arguments, snapshot: snapshot, selectionWorkLimit: 1)
        }
        assertBudget(work, detail: "xrefs exceeds the snapshot work budget", unit: .workSteps,
                     limit: 1, used: nil, narrowing: ["imageSlot"])
        let rows = try caught {
            try WorkspaceScriptingAPI.snapshotXRefRead(arguments, snapshot: snapshot, resultLimit: 2)
        }
        assertBudget(rows, detail: "xrefs exceeds the snapshot result budget; request a smaller limit",
                     unit: .rows, limit: 2, used: nil, narrowing: ["limit", "imageSlot"])
        let mapped = try XCTUnwrap(MCPToolRefusal.executionRefusal(work))
        XCTAssertEqual(mapped.value["refusal"]?["used"], .null)

        analysis.xrefs = (0..<5_001).map {
            XRef(id: UUID(), from: UInt64($0 + 1), to: 0x2000, kind: XRefKind.call)
        }
        snapshot = store(analysis).snapshot
        let callers = try caught {
            try WorkspaceScriptingAPI.snapshotListRead("callers",
                arguments: .object(["address": .hex(0x2000)]), snapshot: snapshot)
        }
        assertBudget(callers, detail: "callers exceeds the snapshot result budget",
                     unit: .rows, limit: 5_000, used: 5_001, narrowing: [])
        analysis.instructions = (0..<3).map {
            InstructionRow(address: UInt64(0x1000 + $0 * 4), bytes: "1f 20 03 d5", mnemonic: "nop",
                           operands: "", hasBreakpoint: false, comment: nil)
        }
        snapshot = store(analysis).snapshot
        let instructions = try caught {
            try WorkspaceScriptingAPI.snapshotListRead("instructions",
                arguments: .object(["address": .hex(0x1008), "count": .int(1)]),
                snapshot: snapshot, scope: .attached, selectionWorkLimit: 1)
        }
        assertBudget(instructions, detail: "instruction selection exceeds the snapshot work budget",
                     unit: .workSteps, limit: 1, used: 2, narrowing: [])
    }

    func testTypeAndAnalysisBudgetRefusalsAreTyped() throws {
        for error in [AttachedTypeReadBudget.refused, SnapshotAnalysisReadBudget.refused] {
            let mapped = try XCTUnwrap(MCPToolRefusal.executionRefusal(error))
            XCTAssertEqual(mapped.code, .budgetExceeded)
            XCTAssertEqual(mapped.narrowing, [])
            XCTAssertNil(mapped.value["refusal"]?["budget"])
            XCTAssertNil(mapped.value["refusal"]?["used"])
            XCTAssertTrue(error.errorDescription?.hasSuffix(".") == true)
            XCTAssertFalse(error.errorDescription?.hasSuffix("..") == true)
        }
    }

    private func addressStore() -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.functions = [function("_main", 0x1000, 0x1008), function("helper", 0x1008, 0x100c)]
        analysis.sections = [
            SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                           size: 0x200, fileOffset: 0x1000, isExecutable: true),
            SectionSummary(id: UUID(), name: "__TEXT,__stubs", address: 0x1200,
                           size: 0x20, fileOffset: 0x1200, isExecutable: true),
            SectionSummary(id: UUID(), name: "__TEXT,__cstring", address: 0x2000,
                           size: 0x40, fileOffset: 0x2000, isExecutable: false),
        ]
        return store(analysis)
    }

    func testOutsideEveryFunctionRefusalCarriesFields() async throws {
        let api = WorkspaceScriptingAPI(store: addressStore())
        let server = MCPServer(api: api)
        for (index, address) in [UInt64(0x1204), 0x2010, 0x800].enumerated() {
            let fields = try refusal(await call(server, "callers",
                .object(["address": .hex(address)]), id: Int64(index + 1)))
            XCTAssertEqual(fields["code"], .string("unknownSubject"))
            XCTAssertEqual(fields["requestedAddress"], .hex(address))
            XCTAssertEqual(fields["imageSlot"], .int(0))
            XCTAssertEqual(fields["resolution"], .string("refused"))
            XCTAssertEqual(fields["nearestFunction"], address == 0x800 ? .null :
                .object(["name": .string("helper"), "address": .hex(0x1008)]))
            let expected: ScriptValue = address == 0x1204
                ? .object(["name": .string("__TEXT,__stubs"), "start": .hex(0x1200), "end": .hex(0x1220)])
                : address == 0x2010
                    ? .object(["name": .string("__TEXT,__cstring"), "start": .hex(0x2000), "end": .hex(0x2040)])
                    : .null
            XCTAssertEqual(fields["section"], expected)
        }
        let error = try caught { try api.execute("callers", arguments: .object(["address": .hex(0x1204)])) }
        XCTAssertEqual(error.errorDescription,
            "Invalid argument: address 0x1204 is outside every function in image slot 0; nearest preceding function helper at 0x1008; section __TEXT,__stubs [0x1200, 0x1220).")
    }

    func testDecompileBudgetRefusalsAreTyped() throws {
        let values: [(DecompileBudgetRefusal, MCPRefusalBudget.Unit, Int64, Int64?)] = [
            (.tooLarge(bytes: 262_145, blocks: 0), .bytes, 262_144, 262_145),
            (.tooLarge(bytes: 32_772, blocks: 8_193), .nodes, 8_192, 8_193),
            (.deadline(milliseconds: 50), .wallMillis, 50, nil),
            (.tooLarge(bytes: UInt64.max, blocks: 0), .bytes, 262_144, Int64.max),
        ]
        for (error, unit, limit, used) in values {
            let mapped = try XCTUnwrap(MCPToolRefusal.executionRefusal(error))
            XCTAssertEqual(mapped.code, .budgetExceeded)
            XCTAssertEqual(mapped.budget, MCPRefusalBudget(unit: unit, limit: limit))
            XCTAssertEqual(mapped.used, used)
            XCTAssertEqual(mapped.detail, error.errorDescription)
            XCTAssertEqual(mapped.narrowing, [])
            XCTAssertFalse(mapped.retryable)
        }
        XCTAssertNil(MCPToolRefusal.executionRefusal(ScriptingError.invalidArgument("x")))
    }

    func testFunctionPagesFitTwoHundredKilobytesOnTheWire() async throws {
        var analysis = ImageAnalysis()
        analysis.functions = (0..<2_000).map { (index: Int) -> FunctionSummary in
            let start = UInt64(0x1000) + UInt64(index) * 4
            return function(String(repeating: "\"", count: 200) + String(index), start, start + 4)
        }
        let api = WorkspaceScriptingAPI(store: store(analysis))
        // Rows come back through wire JSON, which reads 1.0 as an int; compare like with like.
        let expected = try XCTUnwrap(try ScriptValue.decode(try api.execute("functions").jsonData()).arrayValue)
        let server = MCPServer(api: api)
        var cursor: String?
        var seen = Set<String>()
        var collected: [ScriptValue] = []
        for pageNumber in 1...2_001 {
            var arguments: [String: ScriptValue] = ["page": .bool(true), "limit": .int(1_000)]
            if let cursor { arguments["cursor"] = .string(cursor) }
            let data = await server.handleMessageAsync(
                try request("functions", .object(arguments), id: Int64(pageNumber)).jsonData())
            let bytes = try XCTUnwrap(data)
            XCTAssertLessThanOrEqual(bytes.count, 200_000)
            let reply = try ScriptValue.decode(bytes)
            XCTAssertNil(reply["error"])
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let page = try ScriptValue.decode(Data(text.utf8))
            XCTAssertEqual(page["total"], .int(2_000))
            let rows = try XCTUnwrap(page["rows"]?.arrayValue)
            collected += rows
            cursor = page["nextCursor"]?.stringValue
            if let cursor {
                XCTAssertTrue(seen.insert(cursor).inserted)
                XCTAssertFalse(rows.isEmpty)
                XCTAssertEqual(page["isTruncated"], .bool(true))
            } else {
                XCTAssertEqual(page["isTruncated"], .bool(false))
                break
            }
        }
        XCTAssertNil(cursor)
        XCTAssertEqual(collected, expected)
    }

    private func objcStore(stubs: [UInt64] = [0x3000], directCaller: Bool = false,
                           selector: String = "isRichText") -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.functions = [
            function("-[Document " + selector + "]", 0x2000, 0x2004),
            function("_main", 0x1000, 0x1004),
        ] + stubs.map { function("_objc_msgSend$" + selector, $0, $0 + 4) }
        if directCaller {
            analysis.xrefs = [XRef(id: UUID(), from: 0x1000, to: 0x2000, kind: XRefKind.call)]
        }
        return store(analysis)
    }

    // Dot 1281 / dot 1246: the generation capture appends a trailing {"generation":...} text
    // block to MCP content (see MCPServerTests.testVI2GenerationBlockFollowsLegacyPayloadAndDispatchNote).
    // These tests select payload and note blocks by content, so the trailing block is dropped here.
    private func withoutGenerationBlock(_ content: [ScriptValue]) -> [ScriptValue] {
        content.filter { block in
            guard let text = block["text"]?.stringValue,
                  let value = try? ScriptValue.decode(Data(text.utf8)),
                  case .object(let fields) = value else { return true }
            return Set(fields.keys) != ["generation"]
        }
    }

    private func assertBareEmpty(_ reply: ScriptValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(reply["error"], file: file, line: line)
        XCTAssertEqual(reply["result"]?["isError"], .bool(false), file: file, line: line)
        XCTAssertEqual(withoutGenerationBlock(reply["result"]?["content"]?.arrayValue ?? []),
            [.object(["type": .string("text"), "text": .string("[]")])], file: file, line: line)
        XCTAssertNil(reply["result"]?["note"], file: file, line: line)
    }

    func testCallersEmptyObjcMethodCarriesDispatchNote() async throws {
        let arguments = ScriptValue.object(["function": .string("-[Document isRichText]")])
        let fixture = objcStore(stubs: [0x4000, 0x3000])
        let api = WorkspaceScriptingAPI(store: fixture)
        let server = MCPServer(api: api)
        let reply = try await call(server, "callers", arguments)
        let note = ScriptValue.object([
            "code": .string("dynamicDispatch"), "selector": .string("isRichText"),
            "stubAddress": .hex(0x3000),
            "text": .string("No direct callers of -[Document isRichText] were found, but it is an Objective-C method and may be reached by dynamic dispatch through objc_msgSend (selector isRichText). Try callers with selector isRichText to list its send sites."),
            "try": .object(["tool": .string("callers"), "arguments": .object(["selector": .string("isRichText")])]),
        ])
        XCTAssertEqual(reply["result"]?["isError"], .bool(false))
        XCTAssertEqual(reply["result"]?["note"], note)
        let content = withoutGenerationBlock(try XCTUnwrap(reply["result"]?["content"]?.arrayValue))
        XCTAssertEqual(content.count, 2)
        XCTAssertEqual(content.first?["text"], .string("[]"))
        XCTAssertEqual(content.last?["type"], .string("text"))
        let text = try XCTUnwrap(content.last?["text"]?.stringValue)
        XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), .object(["note": note]))
        let sync = try ScriptValue.decode(try XCTUnwrap(server.handleMessage(try request("callers", arguments).jsonData())))
        assertBareEmpty(sync)
        let direct = try await api.executeAsync("callers", arguments: arguments)
        XCTAssertEqual(direct, .array([]))
        XCTAssertEqual(try WorkspaceScriptingAPI.snapshotListRead("callers", arguments: arguments,
            snapshot: fixture.snapshot), .array([]))
        let attached = MCPAttachExecutor(store: fixture, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        let attachedServer = MCPServer(api: api, configuration: .attached,
            asyncCommandExecutor: { command, arguments in try await attached.execute(command, arguments) },
            allowedCommands: MCPAttachExecutor.attachCommands)
        assertBareEmpty(try await call(attachedServer, "callers", arguments))
        assertBareEmpty(try await call(server, "callees", arguments, id: 2))
        assertBareEmpty(try await call(server, "callers", .object(["function": .string("_main")]), id: 3))

        let noStub = try await call(MCPServer(api: WorkspaceScriptingAPI(store: objcStore(stubs: []))),
                                   "callers", arguments)
        XCTAssertEqual(noStub["result"]?["note"]?["selector"], .string("isRichText"))
        XCTAssertNil(noStub["result"]?["note"]?["stubAddress"])
        let withCaller = try await call(MCPServer(api: WorkspaceScriptingAPI(store: objcStore(directCaller: true))),
                                       "callers", arguments)
        XCTAssertNil(withCaller["result"]?["note"])
        let callerText = try XCTUnwrap(withCaller["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertEqual(try ScriptValue.decode(Data(callerText.utf8)).arrayValue?.count, 1)
    }

    func testDispatchLookupSharesWorkBudgetAndPropagatesCancellation() throws {
        var analysis = ImageAnalysis()
        analysis.functions = [function("-[Document isRichText]", 0x2000, 0x2004)]
        analysis.functions += (0..<99_999).map { (index: Int) -> FunctionSummary in
            let start = UInt64(0x10000) + UInt64(index) * 4
            return function("other\(index)", start, start + 4)
        }
        analysis.xrefs = [XRef(id: UUID(), from: 0x1000, to: 0x2000, kind: XRefKind.string)]
        let fixture = store(analysis)
        let sink = DispatchNoteSink()
        let result = try WorkspaceScriptingAPI.attachedSnapshotRead("callers",
            arguments: .object(["address": .hex(0x2000)]), snapshot: fixture.snapshot,
            checkpoint: {}, dispatchNote: sink)
        XCTAssertEqual(result, .array([]))
        XCTAssertEqual(sink.read()?["selector"], .string("isRichText"))
        XCTAssertNil(sink.read()?["stubAddress"])
        var baselineCheckpoints = 0
        _ = try WorkspaceScriptingAPI.attachedSnapshotRead("callers",
            arguments: .object(["address": .hex(0x2000)]), snapshot: fixture.snapshot,
            checkpoint: { baselineCheckpoints += 1 })
        let cancelled = DispatchNoteSink()
        var checkpoints = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.attachedSnapshotRead("callers",
            arguments: .object(["address": .hex(0x2000)]), snapshot: fixture.snapshot,
            checkpoint: {
                checkpoints += 1
                if checkpoints == baselineCheckpoints + 1 { throw CancellationError() }
            }, dispatchNote: cancelled)) {
            XCTAssertTrue($0 is CancellationError)
        }
        XCTAssertNil(cancelled.read())
    }

    func testOversizedOptionalDispatchNoteKeepsSuccessfulEmpty() async throws {
        let configuration = MCPServer.Configuration(maximumInputBytes: 1_048_576,
            maximumOutputBytes: 4_096, maximumToolDurationNanoseconds: 30_000_000_000,
            maximumRememberedCancellations: 1_024)
        let server = MCPServer(api: WorkspaceScriptingAPI(store:
            objcStore(stubs: [], selector: String(repeating: "s", count: 8_000))), configuration: configuration)
        assertBareEmpty(try await call(server, "callers", .object(["address": .hex(0x2000)])))
    }

    func testNameSelectorHonestEmptyControl() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: objcStore()))
        let missing = try await call(server, "callers", .object(["function": .string("missing")]))
        XCTAssertEqual(missing["result"]?["isError"], .bool(true))
        XCTAssertEqual(missing["result"]?["content"]?.arrayValue?.first?["text"],
                       .string("Tool call failed: Invalid argument: no function named 'missing'."))
        assertBareEmpty(try await call(server, "callers", .object(["function": .string("_main")]), id: 2))
    }

    func testValidationRefusalUnchanged() async throws {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: addressStore()))
        let reply = try await call(server, "callers", .object(["address": .hex(0x1000), "limit": .int(5)]))
        // 326d0207d (S1: add bounded graph edge continuation) requires page:true for limit.
        XCTAssertEqual(reply["result"]?["content"]?.arrayValue?.first?["text"],
            .string(#"{"error":"refused","refusal":{"code":"malformedInput","detail":"Invalid argument: limit requires page:true for callers and callees.","field":"page","retryable":false}}"#))
        let bad = try await call(server, "rename",
            .object(["address": .string("not-an-address"), "name": .string("x")]), id: 2)
        XCTAssertEqual(bad["result"]?["isError"], .bool(true))
        XCTAssertTrue(bad["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue?
            .hasPrefix("Tool call failed: ") == true)
    }
    func testLegacyProseUnchanged() throws {
        var analysis = ImageAnalysis()
        analysis.functions = [function("target", 0x2000, 0x2004)]
        analysis.xrefs = (0..<3).map {
            XRef(id: UUID(), from: UInt64($0 + 1), to: 0x2000, kind: XRefKind.call)
        }
        let snapshot = store(analysis).snapshot
        let arguments = ScriptValue.object(["to": .hex(0x2000)])
        let work = try caught {
            try WorkspaceScriptingAPI.snapshotXRefRead(arguments, snapshot: snapshot, selectionWorkLimit: 1)
        }
        XCTAssertEqual(work.errorDescription, "Invalid argument: xrefs exceeds the snapshot work budget.")
        let result = try caught {
            try WorkspaceScriptingAPI.snapshotXRefRead(arguments, snapshot: snapshot, resultLimit: 2)
        }
        XCTAssertEqual(result.errorDescription,
            "Invalid argument: xrefs exceeds the snapshot result budget; request a smaller limit.")
        let api = WorkspaceScriptingAPI(store: addressStore())
        let outside = try caught {
            try api.execute("callers", arguments: .object(["address": .hex(0x1204)]))
        }
        XCTAssertEqual(outside.errorDescription,
            "Invalid argument: address 0x1204 is outside every function in image slot 0; nearest preceding function helper at 0x1008; section __TEXT,__stubs [0x1200, 0x1220).")
    }

    func testMaximumEscapedFirstFieldStillFitsWireBudget() async throws {
        var analysis = ImageAnalysis()
        let value = String(repeating: "\u{1}", count: 16_384)
        analysis.functions = [function(value, 0x1000, 0x1004)]
        analysis.stringLiterals = [StringLiteralSummary(id: UUID(), value: value, address: 0x2000,
            sourceSection: "__TEXT,__cstring", byteLength: value.utf8.count)]
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store(analysis)))
        for (index, command) in ["functions", "strings"].enumerated() {
            let bytes = await server.handleMessageAsync(try request(command,
                .object(["page": .bool(true), "limit": .int(1)]), id: Int64(index + 1)).jsonData())
            let data = try XCTUnwrap(bytes)
            XCTAssertLessThanOrEqual(data.count, 200_000)
            let reply = try ScriptValue.decode(data)
            XCTAssertEqual(reply["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let page = try ScriptValue.decode(Data(text.utf8))
            XCTAssertEqual(page["rows"]?.arrayValue?.count, 1)
            XCTAssertEqual(page["rows"]?.arrayValue?.first?[command == "functions" ? "name" : "value"], .string(value))
            XCTAssertEqual(page["isTruncated"], .bool(false))
            XCTAssertEqual(page["nextCursor"], .null)
        }
    }

}
