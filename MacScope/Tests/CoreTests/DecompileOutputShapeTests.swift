import Foundation
import XCTest
@testable import MacScope

private struct ShapeNativeStub: ScriptingNativeDecompiling {
    let text: String
    var truncated = false
    var complete = true
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        .completed(.init(text: text, language: "c", isComplete: complete, isTruncated: truncated))
    }
}

private final class ShapeCheckpointProbe: @unchecked Sendable {
    private let condition = NSCondition()
    private let holdAt: Int?
    private var visits = 0
    private var held = false
    private var released = false
    init(holdAt: Int? = nil) { self.holdAt = holdAt }
    var count: Int { condition.lock(); defer { condition.unlock() }; return visits }
    func checkpoint() {
        condition.lock(); defer { condition.unlock() }
        visits += 1
        if let holdAt, visits == holdAt { held = true; while !released { condition.wait() } }
    }
    func open() { condition.lock(); released = true; condition.broadcast(); condition.unlock() }
    private var isHeld: Bool { condition.lock(); defer { condition.unlock() }; return held }
    func waitUntilHeld() async throws {
        for _ in 0..<3_000 {
            if isHeld { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        throw NSError(domain: "ShapeCheckpointProbe", code: 1)
    }
}

private actor ShapeOutput {
    private var values: [Data] = []
    func append(_ value: Data) { values.append(value) }
    func snapshot() -> [Data] { values }
}

@MainActor
final class DecompileOutputShapeTests: XCTestCase {
    private func makeStore() -> WorkspaceStore {
        let mainID = UUID()
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "names", path: "/tmp/names",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: mainID, name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "helper", startAddress: 0x1008, endAddress: 0x100c, confidence: 1),
            ],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: mainID, startAddress: 0x1000,
                                           endAddress: 0x1008, instructionCount: 2)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov",
                               operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "01 00 00 94", mnemonic: "bl",
                               operands: "helper", hasBreakpoint: false, comment: "call"),
                InstructionRow(address: 0x1008, bytes: "c0 03 5f d6", mnemonic: "ret",
                               operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [XRef(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            controlFlowEdges: [ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                                     size: 0x200, fileOffset: 0x1000, isExecutable: true)])
        return WorkspaceStore(workspaceName: "Function names", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func renameHelper(_ store: WorkspaceStore) throws {
        _ = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: .object([
            "address": .hex(0x1008), "name": .string("renamed_helper")
        ]))
    }

    private func api(_ store: WorkspaceStore, text: String = "a\nb\nc\nd\ne", truncated: Bool = false,
                     complete: Bool = true) -> WorkspaceScriptingAPI {
        WorkspaceScriptingAPI(store: store, nativeDecompiler: ShapeNativeStub(text: text, truncated: truncated, complete: complete))
    }
    private func args(_ extra: [String: ScriptValue] = [:]) -> ScriptValue {
        .object(["function": .string("_main")].merging(extra) { _, new in new })
    }
    private func request(_ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("decompile"), "arguments": arguments])])
    }
    private func mcp(_ server: MCPServer, _ arguments: ScriptValue, sync: Bool = false) async throws -> ScriptValue {
        let bytes: Data?
        if sync { bytes = server.handleMessage(try request(arguments).jsonData()) }
        else { bytes = await server.handleMessageAsync(try request(arguments).jsonData()) }
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        XCTAssertNil(envelope["error"])
        return try XCTUnwrap(envelope["result"])
    }
    private func payload(_ response: ScriptValue) throws -> ScriptValue {
        XCTAssertEqual(response["isError"], .bool(false))
        let text = try XCTUnwrap(response["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }
    private func native(_ api: WorkspaceScriptingAPI, _ extra: [String: ScriptValue]) async throws -> ScriptValue {
        try await api.executeAsync("decompile", arguments: args(extra))
    }
    func testNativeUnshapedResponseCompletenessReflectsDocumentFlags() async throws {
        for complete in [false, true] {
            for truncated in [false, true] {
                let reply = try await native(api(makeStore(), truncated: truncated, complete: complete), [:])
                XCTAssertEqual(reply["complete"], .bool(complete))
                XCTAssertEqual(reply["truncated"], .bool(truncated))
                XCTAssertEqual(reply["responseComplete"], .bool(complete && !truncated))
                XCTAssertNil(reply["nextCursor"])
            }
        }
    }
    func testNativePageDistinguishesDocumentAndResponseCompleteness() async throws {
        let service = api(makeStore())
        let full = try await native(service, ["format": .string("text")])
        XCTAssertEqual(full["complete"], .bool(true))
        XCTAssertEqual(full["responseComplete"], .bool(true))
        let page = try await native(service, ["format": .string("text"), "lineRange": .string("2-3")])
        XCTAssertEqual(page["complete"], .bool(true))
        XCTAssertEqual(page["responseComplete"], .bool(false))
        let suffix = try await native(service, ["format": .string("text"), "lineRange": .string("4-5")])
        XCTAssertEqual(suffix["responseComplete"], .bool(false))
        XCTAssertEqual(suffix["nextCursor"], .null)
        let truncated = try await native(api(makeStore(), truncated: true), ["format": .string("text")])
        XCTAssertEqual(truncated["responseComplete"], .bool(false))
    }

    func testNativeCompletenessFlagsAcrossDirectAuthorityAttachedAndMCP() async throws {
        for complete in [false, true] {
            for truncated in [false, true] {
                let store = makeStore()
                let service = api(store, truncated: truncated, complete: complete)
                let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0,
                    nativeDecompiler: ShapeNativeStub(text: "a\nb\nc\nd\ne", truncated: truncated, complete: complete)) })
                attached.setConsent(.allowed)
                let headlessServer = MCPServer(api: service)
                let attachedServer = MCPServer(api: service, asyncCommandExecutor: { command, arguments in
                    try await attached.execute(command, arguments)
                })
                let authority = try await HeadlessAutomationAuthority.executeAsync(
                    command: "decompile", arguments: args(), api: service)
                let directAttached = try await attached.execute("decompile", args())
                for reply in [authority, directAttached] {
                    XCTAssertEqual(reply["complete"], .bool(complete))
                    XCTAssertEqual(reply["truncated"], .bool(truncated))
                    XCTAssertEqual(reply["responseComplete"], .bool(complete && !truncated))
                    XCTAssertNil(reply["nextCursor"])
                    XCTAssertNotNil(reply["pseudocode"])
                    XCTAssertNotNil(reply["lines"])
                }
                for format in ["text", "lines"] {
                    let extra: [String: ScriptValue] = ["format": .string(format)]
                    let direct = try await native(service, extra)
                    let headless = try payload(await mcp(headlessServer, args(extra)))
                    let attachedReply = try payload(await mcp(attachedServer, args(extra)))
                    for reply in [direct, headless, attachedReply] {
                        XCTAssertEqual(reply["complete"], .bool(complete))
                        XCTAssertEqual(reply["documentTruncated"], .bool(truncated))
                        XCTAssertEqual(reply["truncated"], .bool(truncated))
                        XCTAssertEqual(reply["responseComplete"], .bool(complete && !truncated))
                        XCTAssertEqual(reply["firstLine"], .int(1))
                        XCTAssertEqual(reply["lastLine"], .int(5))
                        XCTAssertEqual(reply["nextCursor"], .null)
                        XCTAssertNil(reply[format == "text" ? "lines" : "pseudocode"])
                    }
                }
            }
        }
    }

    func testNativeMCPContinuationNeverClaimsTheWholeDocument() async throws {
        for format in ["text", "lines"] {
            let store = makeStore()
            let service = api(store)
            let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0,
                nativeDecompiler: ShapeNativeStub(text: "a\nb\nc\nd\ne")) })
            attached.setConsent(.allowed)
            let attachedServer = MCPServer(api: service, asyncCommandExecutor: { command, arguments in
                try await attached.execute(command, arguments)
            })
            for server in [MCPServer(api: service), attachedServer] {
                let first = try payload(await mcp(server, args([
                    "format": .string(format), "lineRange": .string("1-2")
                ])))
                XCTAssertEqual(first["complete"], .bool(true))
                XCTAssertEqual(first["responseComplete"], .bool(false))
                let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
                let suffix = try payload(await mcp(server, args([
                    "format": .string(format), "cursor": .string(cursor)
                ])))
                XCTAssertEqual(suffix["complete"], .bool(true))
                XCTAssertEqual(suffix["responseComplete"], .bool(false))
                XCTAssertEqual(suffix["firstLine"], .int(3))
                XCTAssertEqual(suffix["lastLine"], .int(5))
                XCTAssertEqual(suffix["truncated"], .bool(false))
                XCTAssertEqual(suffix["nextCursor"], .null)
                let whole = try payload(await mcp(server, args([
                    "format": .string(format), "lineRange": .string("1-9")
                ])))
                XCTAssertEqual(whole["responseComplete"], .bool(true))
                XCTAssertEqual(whole["firstLine"], .int(1))
                XCTAssertEqual(whole["lastLine"], .int(5))
                XCTAssertEqual(whole["nextCursor"], .null)
            }
        }
    }

    private func assertDefault(_ reply: ScriptValue) {
        XCTAssertEqual(reply["pseudocode"], .string("a\nb\nc\nd\ne")); XCTAssertNil(reply["lines"])
        XCTAssertEqual(reply["lineCount"], .int(5)); XCTAssertEqual(reply["firstLine"], .int(1))
        XCTAssertEqual(reply["lastLine"], .int(5)); XCTAssertEqual(reply["truncated"], .bool(false))
        XCTAssertEqual(reply["documentTruncated"], .bool(false)); XCTAssertEqual(reply["nextCursor"], .null)
        XCTAssertEqual(reply["responseComplete"], .bool(true))
        XCTAssertEqual(reply["backend"], .string("native")); XCTAssertEqual(reply["function"], .string("_main"))
    }
    private func refuses(_ api: WorkspaceScriptingAPI, _ extra: [String: ScriptValue], _ detail: String) async throws {
        do { _ = try await native(api, extra); XCTFail("Expected refusal") }
        catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail)) }
        let response = try await mcp(MCPServer(api: api), args(extra))
        XCTAssertEqual(response["isError"], .bool(true))
        let text = try XCTUnwrap(response["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertTrue(text.contains(detail), text)
    }

    func testF1HeadlessAndF2AttachedMCPDefaults() async throws {
        let store = makeStore(); let api = api(store)
        let headless = try payload(await mcp(MCPServer(api: api), args()))
        assertDefault(headless)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0,
            nativeDecompiler: ShapeNativeStub(text: "a\nb\nc\nd\ne")) })
        attached.setConsent(.allowed)
        let server = MCPServer(api: api, asyncCommandExecutor: { command, arguments in
            try await attached.execute(command, arguments)
        })
        let reply = try payload(await mcp(server, args()))
        assertDefault(reply)
    }

    func testF1sSyncMCPDefaultAndF3MacIRLines() async throws {
        let store = makeStore(); let api = api(store)
        let legacy = try api.execute("decompile", arguments: args())
        let lines = try XCTUnwrap(legacy["lines"]?.arrayValue)
        let sync = try payload(await mcp(MCPServer(api: api), args(), sync: true))
        XCTAssertNil(sync["lines"]); XCTAssertEqual(sync["pseudocode"], legacy["pseudocode"])
        XCTAssertEqual(sync["lineCount"], .int(Int64(lines.count))); XCTAssertEqual(sync["backend"], .string("macir"))
        let shaped = try api.execute("decompile", arguments: args(["format": .string("lines")]))
        XCTAssertNil(shaped["pseudocode"]); XCTAssertEqual(shaped["lines"], legacy["lines"])
        XCTAssertEqual(shaped["lineCount"], .int(Int64(lines.count)))
        XCTAssertEqual(shaped["firstLine"], .int(1)); XCTAssertEqual(shaped["lastLine"], .int(Int64(lines.count)))
        XCTAssertEqual(shaped["truncated"], .bool(false)); XCTAssertEqual(shaped["nextCursor"], .null)
        for reply in [legacy, sync, shaped] {
            XCTAssertNil(reply["complete"])
            XCTAssertNil(reply["responseComplete"])
            XCTAssertNil(reply["documentTruncated"])
        }
    }

    func testF4RangeContinuationAndF5Clamp() async throws {
        let api = api(makeStore())
        let first = try await native(api, ["lineRange": .string("2-3")])
        XCTAssertEqual(first["pseudocode"], .string("b\nc")); XCTAssertEqual(first["firstLine"], .int(2))
        XCTAssertEqual(first["lastLine"], .int(3)); XCTAssertEqual(first["truncated"], .bool(true))
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let second = try await native(api, ["cursor": .string(cursor)])
        XCTAssertEqual(second["pseudocode"], .string("d\ne")); XCTAssertEqual(second["firstLine"], .int(4))
        XCTAssertEqual(second["lastLine"], .int(5)); XCTAssertEqual(second["truncated"], .bool(false))
        XCTAssertEqual(second["nextCursor"], .null)
        XCTAssertEqual([first["pseudocode"]!.stringValue!, second["pseudocode"]!.stringValue!].joined(separator: "\n"), "b\nc\nd\ne")
        let clamped = try await native(api, ["format": .string("lines"), "lineRange": .string("4-9")])
        XCTAssertEqual(clamped["lines"], .array([
            .object(["n": .int(4), "text": .string("d")]), .object(["n": .int(5), "text": .string("e")]),
        ])); XCTAssertEqual(clamped["lastLine"], .int(5)); XCTAssertEqual(clamped["nextCursor"], .null)
        let last = try await native(api, ["lineRange": .string("5-5")])
        XCTAssertEqual(last["pseudocode"], .string("e")); XCTAssertEqual(last["firstLine"], .int(5))
        XCTAssertEqual(last["lastLine"], .int(5)); XCTAssertEqual(last["nextCursor"], .null)
    }

    func testF5ExactRefusalTextsOnBothSurfaces() async throws {
        let api = api(makeStore())
        for range in [ScriptValue.string("3-2"), .string("0-2"), .string("2"), .int(2)] {
            try await refuses(api, ["lineRange": range], "lineRange must be \"a-b\" with 1 <= a <= b")
        }
        try await refuses(api, ["lineRange": .string("6-7")], "lineRange starts past the end: the function has 5 lines")
        try await refuses(api, ["format": .string("html")], "format must be \"text\" or \"lines\"")
        try await refuses(api, ["lineRange": .string("1-2"), "cursor": .string("x")], "lineRange cannot be combined with cursor")
    }

    // Item 1286: authored-unrun controls; all expected sizes are hand-derived.
    // Synthetic native text only. These controls do not accept the real TG Pro row.
    private func e3NumberedSource(count: Int, width: Int = 80) -> [String] {
        precondition((1...9_999).contains(count) && width >= 13)
        return (1...count).map { index in
            "    r" + String(format: "%04d", index) + " = "
                + String(repeating: "k", count: width - 13) + ";"
        }
    }

    private func e3Reply(_ service: WorkspaceScriptingAPI, server: MCPServer,
                         viaMCP: Bool, extra: [String: ScriptValue]) async throws -> ScriptValue {
        if viaMCP { return try payload(await mcp(server, args(extra))) }
        return try await native(service, extra)
    }

    private func e3AssertPage(_ reply: ScriptValue, total: Int, first: Int, last: Int) throws {
        XCTAssertEqual(reply["lineCount"], .int(Int64(total)))
        XCTAssertEqual(reply["firstLine"], .int(Int64(first)))
        XCTAssertEqual(reply["lastLine"], .int(Int64(last)))
        XCTAssertEqual(reply["complete"], .bool(true))
        XCTAssertEqual(reply["documentTruncated"], .bool(false))
        XCTAssertEqual(reply["backend"], .string("native"))
        XCTAssertEqual(reply["truncated"], .bool(last < total))
        XCTAssertEqual(reply["responseComplete"], .bool(first == 1 && last == total))
        if last < total {
            XCTAssertFalse(try XCTUnwrap(reply["nextCursor"]?.stringValue).isEmpty)
        } else {
            XCTAssertEqual(reply["nextCursor"], .null)
        }
    }

    private func e3AssertText(_ reply: ScriptValue, source: [String], first: Int, last: Int) throws -> String {
        let text = try XCTUnwrap(reply["pseudocode"]?.stringValue)
        XCTAssertEqual(text, source[(first - 1)..<last].joined(separator: "\n"))
        XCTAssertEqual(text.split(separator: "\n", omittingEmptySubsequences: false).count, last - first + 1)
        XCTAssertNil(reply["lines"])
        return text
    }

    private func e3AssertRows(_ reply: ScriptValue, source: [String], first: Int, last: Int) throws -> [ScriptValue] {
        let rows = try XCTUnwrap(reply["lines"]?.arrayValue)
        let expected: [ScriptValue] = (first...last).map { number in
            .object(["n": .int(Int64(number)), "text": .string(source[number - 1])])
        }
        XCTAssertEqual(rows.count, last - first + 1)
        XCTAssertEqual(rows, expected) // Exact objects also reject extra row keys.
        XCTAssertNil(reply["pseudocode"])
        return rows
    }

    private func e3AssertCursor(_ cursor: String, next: Int, generation: UUID) throws {
        XCTAssertFalse(cursor.isEmpty)
        let parts = try cursorParts(cursor)
        XCTAssertEqual(parts.count, 6)
        guard parts.count == 6 else { return }
        XCTAssertEqual(parts[0], "d1")
        XCTAssertEqual(parts[1], "0")
        XCTAssertEqual(parts[2], "4096")
        XCTAssertEqual(parts[3], String(next))
        XCTAssertEqual(parts[4], generation.uuidString)
        XCTAssertEqual(parts[5].count, 16)
    }

    func testE3NumberedSourceFixtureShape() {
        // Dedicated self-check covers every count/width used by the new tests.
        let cases = [(1_000, 80), (199, 80), (200, 80), (201, 80), (400, 1_000), (1_546, 80)]
        for (count, width) in cases {
            let source = e3NumberedSource(count: count, width: width)
            XCTAssertEqual(source.count, count)
            XCTAssertEqual(Set(source).count, count)
            for (offset, line) in source.enumerated() {
                XCTAssertEqual(line.utf8.count, width)
                XCTAssertTrue(line.hasPrefix("    r" + String(format: "%04d", offset + 1) + " = "))
                XCTAssertTrue(line.hasSuffix(";"))
                XCTAssertTrue(line.utf8.allSatisfy {
                    $0 == 32 || $0 == 59 || $0 == 61 || $0 == 107 || $0 == 114 || (48...57).contains($0)
                })
            }
        }
    }

    func testE3TwoHundredLinePageAndContinuationOnBothSurfaces() async throws {
        let source = e3NumberedSource(count: 1_000)
        let fullText = source.joined(separator: "\n")
        for viaMCP in [false, true] {
            let store = makeStore()
            let service = api(store, text: fullText)
            let server = MCPServer(api: service)
            for format in ["text", "lines"] {
                var extra: [String: ScriptValue] = ["lineRange": .string("1-200")]
                if format == "lines" { extra["format"] = .string("lines") }
                let page = try await e3Reply(service, server: server, viaMCP: viaMCP, extra: extra)
                try e3AssertPage(page, total: 1_000, first: 1, last: 200)
                if format == "text" {
                    _ = try e3AssertText(page, source: source, first: 1, last: 200)
                } else {
                    _ = try e3AssertRows(page, source: source, first: 1, last: 200)
                }
                let cursor = try XCTUnwrap(page["nextCursor"]?.stringValue)
                try e3AssertCursor(cursor, next: 201, generation: store.snapshot.analysisGenerationID)

                // hand-derived: cursor-only defaults to text, including from a lines page.
                // Shape.swift:23-30, :98, :112; cursor does not preserve the old range/format.
                let suffix = try await e3Reply(service, server: server, viaMCP: viaMCP,
                                               extra: ["cursor": .string(cursor)])
                try e3AssertPage(suffix, total: 1_000, first: 201, last: 1_000)
                let suffixText = try e3AssertText(suffix, source: source, first: 201, last: 1_000)
                XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(.string(suffixText)), 196_608)
                if format == "text" {
                    let pageText = try XCTUnwrap(page["pseudocode"]?.stringValue)
                    XCTAssertEqual([pageText, suffixText].joined(separator: "\n"), fullText)
                    XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(.string(pageText)), 196_608)
                }

                // Explicit lines also exercises text-cursor -> lines format switching.
                let linesSuffix = try await e3Reply(service, server: server, viaMCP: viaMCP,
                    extra: ["format": .string("lines"), "cursor": .string(cursor)])
                try e3AssertPage(linesSuffix, total: 1_000, first: 201, last: 1_000)
                let suffixRows = try e3AssertRows(linesSuffix, source: source, first: 201, last: 1_000)
                if format == "lines" {
                    let pageRows = try XCTUnwrap(page["lines"]?.arrayValue)
                    let wholeRows: [ScriptValue] = source.enumerated().map {
                        .object(["n": .int(Int64($0.offset + 1)), "text": .string($0.element)])
                    }
                    XCTAssertEqual(pageRows + suffixRows, wholeRows)
                }
                try await refuses(service, ["lineRange": .string("1-200"), "cursor": .string(cursor)],
                                  "lineRange cannot be combined with cursor")
            }
        }
    }

    func testE3WindowWalkClampAndPastEndOnBothSurfaces() async throws {
        let source = e3NumberedSource(count: 1_000)
        let fullText = source.joined(separator: "\n")
        for viaMCP in [false, true] {
            let store = makeStore()
            let service = api(store, text: fullText)
            let server = MCPServer(api: service)
            var pages: [String] = []
            for window in 0..<5 {
                let first = window * 200 + 1
                let last = (window + 1) * 200
                let reply = try await e3Reply(service, server: server, viaMCP: viaMCP,
                    extra: ["lineRange": .string("\(first)-\(last)")])
                try e3AssertPage(reply, total: 1_000, first: first, last: last)
                pages.append(try e3AssertText(reply, source: source, first: first, last: last))
                XCTAssertEqual(reply["responseComplete"], .bool(false))
                if last < 1_000 {
                    let cursor = try XCTUnwrap(reply["nextCursor"]?.stringValue)
                    try e3AssertCursor(cursor, next: last + 1, generation: store.snapshot.analysisGenerationID)
                }
            }
            XCTAssertEqual(pages.joined(separator: "\n"), fullText)
            let clamped = try await e3Reply(service, server: server, viaMCP: viaMCP,
                                            extra: ["lineRange": .string("901-1100")])
            try e3AssertPage(clamped, total: 1_000, first: 901, last: 1_000)
            _ = try e3AssertText(clamped, source: source, first: 901, last: 1_000)
            let last = try await e3Reply(service, server: server, viaMCP: viaMCP,
                                         extra: ["lineRange": .string("1000-1000")])
            try e3AssertPage(last, total: 1_000, first: 1_000, last: 1_000)
            _ = try e3AssertText(last, source: source, first: 1_000, last: 1_000)
            try await refuses(service, ["lineRange": .string("1001-1200")],
                              "lineRange starts past the end: the function has 1000 lines")
        }
    }

    func testE3Boundary199200201OnBothSurfaces() async throws {
        for count in [199, 200, 201] {
            let source = e3NumberedSource(count: count)
            for viaMCP in [false, true] {
                let store = makeStore()
                let service = api(store, text: source.joined(separator: "\n"))
                let server = MCPServer(api: service)
                let page = try await e3Reply(service, server: server, viaMCP: viaMCP,
                                             extra: ["lineRange": .string("1-200")])
                let last = min(count, 200)
                try e3AssertPage(page, total: count, first: 1, last: last)
                _ = try e3AssertText(page, source: source, first: 1, last: last)
                if count == 201 {
                    let cursor = try XCTUnwrap(page["nextCursor"]?.stringValue)
                    try e3AssertCursor(cursor, next: 201, generation: store.snapshot.analysisGenerationID)
                    let suffix = try await e3Reply(service, server: server, viaMCP: viaMCP,
                                                   extra: ["cursor": .string(cursor)])
                    try e3AssertPage(suffix, total: 201, first: 201, last: 201)
                    _ = try e3AssertText(suffix, source: source, first: 201, last: 201)
                    XCTAssertEqual(suffix["responseComplete"], .bool(false))
                }
            }
        }
    }

    func testE3ByteCapBeatsTwoHundredLineRange() async throws {
        let source = e3NumberedSource(count: 400, width: 1_000)
        let fullText = source.joined(separator: "\n")
        let store = makeStore()
        let server = MCPServer(api: api(store, text: fullText))
        var extra: [String: ScriptValue] = ["lineRange": .string("1-200")]
        var previousLast = 0
        var pageCount = 0
        var pieces: [String] = []
        while true {
            pageCount += 1
            XCTAssertLessThanOrEqual(pageCount, source.count)
            guard pageCount <= source.count else { return }
            let page = try payload(await mcp(server, args(extra)))
            let first = Int(try XCTUnwrap(page["firstLine"]?.intValue))
            let last = Int(try XCTUnwrap(page["lastLine"]?.intValue))
            XCTAssertEqual(first, previousLast + 1)
            XCTAssertGreaterThanOrEqual(last, first)
            XCTAssertLessThanOrEqual(last, source.count)
            guard first == previousLast + 1, first >= 1, last >= first, last <= source.count else { return }
            try e3AssertPage(page, total: 400, first: first, last: last)
            XCTAssertEqual(page["responseComplete"], .bool(false))
            let text = try e3AssertText(page, source: source, first: first, last: last)
            XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(.string(text)), 196_608)
            pieces.append(text)
            if pageCount == 1 {
                XCTAssertEqual(first, 1)
                XCTAssertGreaterThanOrEqual(last, 1) // A first line is always kept.
                XCTAssertLessThan(last, 200) // No exact-196 assumption.
                XCTAssertEqual(page["truncated"], .bool(true))
                XCTAssertFalse(try XCTUnwrap(page["nextCursor"]?.stringValue).isEmpty)
            }
            previousLast = last
            guard let cursor = page["nextCursor"]?.stringValue else {
                XCTAssertEqual(page["nextCursor"], .null)
                XCTAssertEqual(page["truncated"], .bool(false))
                break
            }
            try e3AssertCursor(cursor, next: last + 1, generation: store.snapshot.analysisGenerationID)
            extra = ["cursor": .string(cursor)] // Drop lineRange; all later requests are cursor-only.
        }
        XCTAssertGreaterThan(pageCount, 1)
        XCTAssertEqual(previousLast, source.count)
        XCTAssertEqual(pieces.joined(separator: "\n"), fullText)
    }

    func testE3SyntheticTGProSizeOracle() async throws {
        // Authored-unrun proxy: 1,546 lines, 80 B per line; not TG Pro output.
        // If L misses the baseline locally, only a larger width is permitted,
        // recorded by the owner; do not weaken thresholds or replay a success.
        let width = 80
        let source = e3NumberedSource(count: 1_546, width: width)
        for line in source { XCTAssertEqual(line.utf8.count, width) }
        let fullText = source.joined(separator: "\n")
        let service = api(makeStore(), text: fullText)
        let legacy = try await native(service, [:])
        let textReply = try await native(service, ["format": .string("text")])
        let server = MCPServer(api: service)
        let maybeEnvelope = await server.handleMessageAsync(try request(args()).jsonData())
        let envelopeBytes = try XCTUnwrap(maybeEnvelope)
        let envelope = try ScriptValue.decode(envelopeBytes)
        XCTAssertNil(envelope["error"])
        let mcpReply = try payload(XCTUnwrap(envelope["result"]))

        // Count the full legacy/direct JSON objects and the entire MCP envelope.
        // These are future local measurements, not measurements made in this packet.
        let L = try legacy.jsonData().count
        let T = try textReply.jsonData().count
        let M = envelopeBytes.count
        let legacyRows = try XCTUnwrap(legacy["lines"]?.arrayValue)
        let expectedRows: [ScriptValue] = source.enumerated().map {
            .object(["n": .int(Int64($0.offset + 1)), "text": .string($0.element)])
        }
        XCTAssertEqual(legacy["pseudocode"], .string(fullText))
        XCTAssertEqual(legacyRows, expectedRows)
        for key in ["firstLine", "lastLine", "nextCursor"] { XCTAssertNil(legacy[key]) }
        let legacyLinesBytes = try ScriptValue.array(legacyRows).jsonData().count

        // hand-derived thresholds from BRIEF SPEC 8; integer arithmetic only.
        XCTAssertGreaterThanOrEqual(L, 271_447)
        XCTAssertLessThanOrEqual(T * 100, L * 55)
        XCTAssertLessThanOrEqual(T, 149_295)
        XCTAssertLessThanOrEqual(M, 149_295)
        XCTAssertLessThanOrEqual(M * 100, L * 55)
        XCTAssertLessThan(T, L)
        XCTAssertGreaterThanOrEqual((L - T) * 100, legacyLinesBytes * 90)
        for reply in [textReply, mcpReply] {
            try e3AssertPage(reply, total: 1_546, first: 1, last: 1_546)
            let text = try e3AssertText(reply, source: source, first: 1, last: 1_546)
            XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(.string(text)), 196_608)
        }
    }


    private func capPages(format: String) async throws {
        let line = "x" + String(repeating: "\"", count: 95)
        let source = Array(repeating: line, count: 2_500)
        let server = MCPServer(api: api(makeStore(), text: source.joined(separator: "\n")))
        var extra: [String: ScriptValue] = ["format": .string(format)]
        var previousLast = 0; var texts: [String] = []; var pages = 0
        while true {
            pages += 1; XCTAssertLessThanOrEqual(pages, 2_500)
            guard pages <= 2_500 else { return }
            let reply = try payload(await mcp(server, args(extra)))
            let first = Int(try XCTUnwrap(reply["firstLine"]?.intValue))
            let last = Int(try XCTUnwrap(reply["lastLine"]?.intValue))
            XCTAssertEqual(first, previousLast + 1); XCTAssertGreaterThanOrEqual(last, first)
            XCTAssertEqual(reply["lineCount"], .int(2_500))
            XCTAssertEqual(reply["complete"], .bool(true))
            XCTAssertEqual(reply["documentTruncated"], .bool(false))
            XCTAssertEqual(reply["responseComplete"], .bool(false))
            if format == "text" {
                let text = try XCTUnwrap(reply["pseudocode"]?.stringValue)
                XCTAssertNil(reply["lines"])
                XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(.string(text)), 196_608)
                texts += text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            } else {
                let lines = try XCTUnwrap(reply["lines"]?.arrayValue)
                XCTAssertNil(reply["pseudocode"])
                XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(.array(lines)), 196_608)
                XCTAssertEqual(lines.map { $0["n"]?.intValue }, (first...last).map { Optional(Int64($0)) })
                texts += try lines.map { try XCTUnwrap($0["text"]?.stringValue) }
            }
            if pages == 1 { XCTAssertLessThan(last, 2_500); XCTAssertEqual(reply["truncated"], .bool(true)) }
            previousLast = last
            guard let cursor = reply["nextCursor"]?.stringValue else {
                XCTAssertEqual(reply["nextCursor"], .null); XCTAssertEqual(reply["truncated"], .bool(false)); break
            }
            extra["cursor"] = .string(cursor)
        }
        XCTAssertGreaterThan(pages, 1); XCTAssertEqual(previousLast, 2_500); XCTAssertEqual(texts, source)
    }
    func testF6TextWireCap() async throws { try await capPages(format: "text") }
    func testF6bLinesWireCap() async throws { try await capPages(format: "lines") }

    func testF6cOversizedFirstLineIsWhole() async throws {
        let large = String(repeating: "x", count: 200_000)
        let server = MCPServer(api: api(makeStore(), text: large + "\nb"))
        let first = try payload(await mcp(server, args()))
        XCTAssertEqual(first["pseudocode"], .string(large)); XCTAssertEqual(first["firstLine"], .int(1))
        XCTAssertEqual(first["lastLine"], .int(1)); XCTAssertEqual(first["truncated"], .bool(true))
        XCTAssertEqual(first["responseComplete"], .bool(false))
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let second = try payload(await mcp(server, args(["cursor": .string(cursor)])))
        XCTAssertEqual(second["pseudocode"], .string("b")); XCTAssertEqual(second["firstLine"], .int(2))
        XCTAssertEqual(second["lastLine"], .int(2)); XCTAssertEqual(second["nextCursor"], .null)
        XCTAssertEqual(second["responseComplete"], .bool(false))
    }

    private func cursorParts(_ cursor: String) throws -> [String] {
        let data = try XCTUnwrap(Data(base64Encoded: cursor))
        return try XCTUnwrap(String(data: data, encoding: .utf8)).components(separatedBy: "|")
    }
    private func changedCursor(_ cursor: String, _ index: Int, _ value: String) throws -> String {
        var parts = try cursorParts(cursor); parts[index] = value
        return Data(parts.joined(separator: "|").utf8).base64EncodedString()
    }
    private let stale = "staleCursor: the decompile changed or the cursor belongs to another function; restart without a cursor"

    func testF7CursorBindingMalformedAndFormatChange() async throws {
        let store = makeStore(); let api = api(store)
        let first = try await native(api, ["lineRange": .string("2-3")])
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let parts = try cursorParts(cursor)
        XCTAssertEqual(parts.count, 6); XCTAssertEqual(parts[0], "d1"); XCTAssertEqual(parts[1], "0")
        XCTAssertEqual(parts[2], "4096"); XCTAssertEqual(parts[3], "4")
        XCTAssertEqual(parts[4], store.snapshot.analysisGenerationID.uuidString); XCTAssertEqual(parts[5].count, 16)
        let lines = try await native(api, ["format": .string("lines"), "cursor": .string(cursor)])
        XCTAssertEqual(lines["lines"], .array([.object(["n": .int(4), "text": .string("d")]), .object(["n": .int(5), "text": .string("e")])]))
        for changed in [try changedCursor(cursor, 1, "1"), try changedCursor(cursor, 3, "6")] {
            try await refuses(api, ["cursor": .string(changed)], stale)
        }
        try await refuses(api, ["function": .string("helper"), "cursor": .string(cursor)], stale)
        let otherText = self.api(store, text: "a\nb\nc\nd\nX")
        try await refuses(otherText, ["cursor": .string(cursor)], stale)
        var short = parts; short.removeLast()
        let malformed = [try changedCursor(cursor, 0, "d2"), Data(short.joined(separator: "|").utf8).base64EncodedString(),
            try changedCursor(cursor, 3, "1"), try changedCursor(cursor, 3, "x"), try changedCursor(cursor, 4, "bad"),
            try changedCursor(cursor, 5, "000000000000000"), cursor + "\n", String(repeating: "x", count: 1_025),
            try changedCursor(cursor, 3, "04"), try changedCursor(cursor, 2, "04096"), try changedCursor(cursor, 5, "AAAAAAAAAAAAAAAA")]
        for value in malformed { try await refuses(api, ["cursor": .string(value)], "malformed cursor") }
        try await refuses(api, ["cursor": .int(1)], "malformed cursor")
        try renameHelper(store)
        try await refuses(api, ["cursor": .string(cursor)], stale)
    }

    func testF8Schema() throws {
        let server = MCPServer(api: api(makeStore()))
        let response = server.handle(.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")]))
        let tool = try XCTUnwrap(response?["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string("decompile") })
        let schema = try XCTUnwrap(tool["inputSchema"])
        XCTAssertEqual(schema["properties"]?["format"]?["enum"], .array([.string("text"), .string("lines")]))
        let formatDescription = try XCTUnwrap(schema["properties"]?["format"]?["description"]?.stringValue)
        XCTAssertTrue(formatDescription.contains("responseComplete"))
        XCTAssertTrue(formatDescription.contains("a terminal suffix is not complete"))
        XCTAssertEqual(schema["properties"]?["lineRange"]?["maxLength"], .int(32))
        XCTAssertEqual(schema["properties"]?["lineRange"]?["pattern"], .string("^[1-9][0-9]{0,8}-[1-9][0-9]{0,8}$"))
        XCTAssertEqual(schema["properties"]?["cursor"]?["maxLength"], .int(1_024))
        XCTAssertEqual(schema["anyOf"], .array([.object(["required": .array([.string("function")])]), .object(["required": .array([.string("address")])])]))
        XCTAssertNil(schema["required"])
    }

    func testF9CheckpointCountsAndHeldCancellation() async throws {
        do { try HeadlessAutomationAuthority.validateDiagnosed(command: "decompile", arguments: args(["lineRange": .string("1-1")])) }
        catch { XCTFail("validateDiagnosed refused lineRange: \(error)"); return }
        let store = makeStore(); let legacyProbe = ShapeCheckpointProbe(); let shapeProbe = ShapeCheckpointProbe()
        _ = try await WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { legacyProbe.checkpoint() })
            .executeAsync("decompile", arguments: args())
        _ = try await WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { shapeProbe.checkpoint() })
            .executeAsync("decompile", arguments: args(["lineRange": .string("1-1")]))
        XCTAssertGreaterThanOrEqual(legacyProbe.count, 2); XCTAssertEqual(shapeProbe.count, legacyProbe.count)
        let gate = ShapeCheckpointProbe(holdAt: 2); defer { gate.open() }
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { gate.checkpoint() }))
        let output = ShapeOutput(); let session = server.makeRequestSession(output: { await output.append($0) })
        await session.receive(try request(args(["lineRange": .string("1-1")])).jsonData())
        try await gate.waitUntilHeld()
        await session.receive(try ScriptValue.object(["jsonrpc": .string("2.0"), "method": .string("notifications/cancelled"),
            "params": .object(["requestId": .int(1)])]).jsonData())
        gate.open()
        var responses: [Data] = []
        for _ in 0..<3_000 {
            responses = await output.snapshot(); if !responses.isEmpty { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(responses.count, 1)
        let terminal = try ScriptValue.decode(XCTUnwrap(responses.first))
        XCTAssertEqual(terminal["error"]?["code"], .int(-32800)); XCTAssertNil(terminal["result"])
        await session.finishInput()
        let final = await output.snapshot(); XCTAssertEqual(final.count, 1)
        XCTAssertEqual(gate.count, 2)
    }

    func testF10MacIRRangeRegionsAndBackendBinding() async throws {
        let store = makeStore(); let api = api(store)
        let legacy = try api.execute("decompile", arguments: args())
        let pinLines = try XCTUnwrap(legacy["lines"]?.arrayValue)
        guard pinLines.count >= 2, let regions = legacy["regions"] else {
            throw XCTSkip("NOT APPLICABLE: supplied fixture did not produce two MacIR lines and regions")
        }
        let first = try api.execute("decompile", arguments: args(["format": .string("lines"), "lineRange": .string("1-1")]))
        XCTAssertEqual(first["lines"], .array([pinLines[0]])); XCTAssertEqual(pinLines[0]["n"], .int(1))
        XCTAssertEqual(first["regions"], regions)
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let rest = try api.execute("decompile", arguments: args(["format": .string("lines"), "cursor": .string(cursor)]))
        XCTAssertEqual(rest["lines"], .array(Array(pinLines.dropFirst()))); XCTAssertNil(rest["regions"])

    }

    func testF10NativeCursorIsStaleOnMacIR() async throws {
        let store = makeStore(); let api = api(store)
        let legacy = try api.execute("decompile", arguments: args())
        let text = try XCTUnwrap(legacy["pseudocode"]?.stringValue)
        guard (legacy["lines"]?.arrayValue?.count ?? 0) >= 2 else {
            throw XCTSkip("NOT APPLICABLE: fixture has fewer than two MacIR lines")
        }
        // Identical full text, function, slot and generation: only the backend differs.
        let sameTextNative = self.api(store, text: text)
        let nativePage = try await native(sameTextNative, ["lineRange": .string("1-1")])
        let nativeCursor = try XCTUnwrap(nativePage["nextCursor"]?.stringValue)
        XCTAssertThrowsError(try api.execute("decompile", arguments: args(["cursor": .string(nativeCursor)]))) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument(self.stale))
        }
    }

    func testF11EmptyLinesF12TruncatedDocumentF13Nulls() async throws {
        let store = makeStore(); let api = api(store, text: "a\n\nb\n")
        let full = try await native(api, ["format": .string("text")])
        XCTAssertEqual(full["lineCount"], .int(4)); XCTAssertEqual(full["pseudocode"], .string("a\n\nb\n"))
        let ranged = try await native(api, ["lineRange": .string("2-4")])
        XCTAssertEqual(ranged["pseudocode"], .string("\nb\n"))
        let lines = try await native(api, ["format": .string("lines"), "lineRange": .string("2-4")])
        XCTAssertEqual(lines["lines"], .array([.object(["n": .int(2), "text": .string("")]),
            .object(["n": .int(3), "text": .string("b")]), .object(["n": .int(4), "text": .string("")])]))
        let cut = try await native(self.api(store, text: "a\nb", truncated: true), ["format": .string("text")])
        XCTAssertEqual(cut["documentTruncated"], .bool(true)); XCTAssertEqual(cut["truncated"], .bool(true))
        XCTAssertEqual(cut["nextCursor"], .null); XCTAssertEqual(cut["lineCount"], .int(2))
        let legacy = try api.execute("decompile", arguments: args())
        let nulls = try api.execute("decompile", arguments: args(["format": .null, "lineRange": .null, "cursor": .null]))
        XCTAssertEqual(nulls, legacy)
        let mcpNull = try payload(await mcp(MCPServer(api: api), args(["lineRange": .null])))
        XCTAssertNil(mcpNull["lines"]); XCTAssertEqual(mcpNull["lineCount"], .int(4))
    }

    func testC1LegacyInlineAndAuthority() throws {
        let api = api(makeStore())
        for reply in [try api.execute("decompile", arguments: args()),
                      try HeadlessAutomationAuthority.execute(command: "decompile", arguments: args(), api: api)] {
            let text = try XCTUnwrap(reply["pseudocode"]?.stringValue)
            let lines = try XCTUnwrap(reply["lines"]?.arrayValue)
            XCTAssertEqual(lines.count, text.split(separator: "\n", omittingEmptySubsequences: false).count)
            XCTAssertEqual(lines.map { $0["n"]?.intValue }, lines.indices.map { Optional(Int64($0 + 1)) })
            XCTAssertEqual(try lines.map { try XCTUnwrap($0["text"]?.stringValue) }.joined(separator: "\n"), text)
            for key in ["lineCount", "firstLine", "lastLine", "nextCursor", "documentTruncated", "truncated", "complete", "responseComplete"] { XCTAssertNil(reply[key]) }
        }
    }

    func testC2LegacyNativeAuthorityAndAttached() async throws {
        let store = makeStore(); let api = api(store)
        let authority = try await HeadlessAutomationAuthority.executeAsync(command: "decompile", arguments: args(), api: api)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0,
            nativeDecompiler: ShapeNativeStub(text: "a\nb\nc\nd\ne")) })
        attached.setConsent(.allowed)
        let reply = try await attached.execute("decompile", args())
        for result in [authority, reply] {
            guard case .object(let fields) = result else { return XCTFail("Expected object") }
            XCTAssertEqual(Set(fields.keys), Set(["function", "address", "pseudocode", "structured", "lines", "backend", "language",
                "complete", "truncated", "responseComplete", "imageSlot", "imageOwner", "resolvedFunction", "resolution"]))
        }
    }

    func testC3OtherFieldsAndDemangledPreserved() async throws {
        let store = makeStore(); let api = api(store)
        func stripped(_ value: ScriptValue) -> ScriptValue {
            guard case .object(var fields) = value else { return value }
            for key in ["pseudocode", "lines", "regions", "lineCount", "firstLine", "lastLine", "nextCursor", "truncated", "documentTruncated"] { fields.removeValue(forKey: key) }
            return .object(fields)
        }
        let address: ScriptValue = .object(["address": .hex(0x1004)])
        let shaped: ScriptValue = .object(["address": .hex(0x1004), "format": .string("text")])
        XCTAssertEqual(stripped(try api.execute("decompile", arguments: address)), stripped(try api.execute("decompile", arguments: shaped)))
        let oldNative = try await api.executeAsync("decompile", arguments: address)
        let newNative = try await api.executeAsync("decompile", arguments: shaped)
        XCTAssertEqual(stripped(oldNative), stripped(newNative))
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x1000), "name": .string("$s3app5ModelV5countSivg")]))
        let oldSwift = try await api.executeAsync("decompile", arguments: address)
        let newSwift = try await api.executeAsync("decompile", arguments: shaped)
        XCTAssertEqual(oldSwift["demangled"], .string("app.Model.count.getter : Swift.Int"))
        XCTAssertEqual(newSwift["demangled"], oldSwift["demangled"]); XCTAssertEqual(stripped(oldSwift), stripped(newSwift))
    }

    func testC4ExistingSummaryPhrases() throws {
        let command = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "decompile" })
        for text in ["primary image by default", "`imageSlot`", "`imageOwner`", "`backend`", "`fallbackReason`", "native-failed: <code>"] {
            XCTAssertTrue(command.summary.contains(text), text)
        }
    }
}
