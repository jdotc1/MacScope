// Authored, unrun.
import Foundation
import XCTest
@testable import MacScope

private struct BoundNativeStub: ScriptingNativeDecompiling {
    let text: String
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        .completed(.init(text: text, language: "c", isComplete: true, isTruncated: false))
    }
}

private struct BoundFailedNativeStub: ScriptingNativeDecompiling {
    let code: String
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        .failed(code: code)
    }
}

private enum BoundFixtureError: Error { case expectedObject }

@MainActor
final class DecompileReplyBoundTests: XCTestCase {
    private func makeStore(name: String = "_main") -> WorkspaceStore {
        let mainID = UUID()
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "names", path: "/tmp/names",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: mainID, name: name, startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
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
    private func object(_ value: ScriptValue) throws -> [String: ScriptValue] {
        guard case .object(let fields) = value else { throw BoundFixtureError.expectedObject }
        return fields
    }
    private func args(_ extra: [String: ScriptValue] = [:]) -> ScriptValue {
        .object(["address": .hex(0x1000)].merging(extra) { _, new in new })
    }
    private func source(_ lines: [String]) -> DecompileReplySource {
        .init(text: lines.joined(separator: "\n"), lines: lines)
    }
    private func frameBytes(_ output: ScriptValue, _ protocolVersion: MCPResultProtocol = .legacy) throws -> Int {
        try mcpToolReplyJSONByteCount(output: output, tool: "decompile",
            generation: syntheticTypeAtlasGeneration(), protocolVersion: protocolVersion, id: .int(1)) + 1
    }
    private func assertBound(_ output: ScriptValue, file: StaticString = #filePath, line: UInt = #line) throws {
        for version in [MCPResultProtocol.legacy, .structured] {
            XCTAssertLessThanOrEqual(try frameBytes(output, version), 200_000, file: file, line: line)
        }
    }
    private func page(_ store: WorkspaceStore, _ lines: [String], backend: String = "native",
                      extra: [String: ScriptValue] = [:], format: String = "text",
                      range: String? = nil, cursor: String? = nil, fold: String? = nil) throws -> ScriptValue {
        var shapeArguments: [String: ScriptValue] = ["format": .string(format)]
        if let range { shapeArguments["lineRange"] = .string(range) }
        if let cursor { shapeArguments["cursor"] = .string(cursor) }
        let shape = try XCTUnwrap(WorkspaceScriptingAPI.decompileShape(.object(shapeArguments)))
        var fields: [String: ScriptValue] = [
            "function": .string("_main"), "address": .hex(0x1000), "backend": .string(backend),
            "structured": .bool(false), "resolvedFunction": .hex(0x1000), "resolution": .string("exact"),
            "imageSlot": .int(0), "imageOwner": .string("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
        ]
        if backend == "native" { fields["complete"] = .bool(true); fields["language"] = .string("c") }
        fields.merge(extra) { _, new in new }
        return .object(try WorkspaceScriptingAPI.shapedDecompileFields(fields, shape: shape,
            slot: store.snapshot.primarySlot, functionStart: 0x1000, snapshot: store.snapshot,
            backend: backend, fullText: lines.joined(separator: "\n"), lineCount: lines.count,
            textAt: { lines[$0] },
            lineAt: { .object(["n": .int(Int64($0 + 1)), "text": .string(lines[$0])]) },
            nativeDocumentTruncated: backend == "native" ? false : nil, foldMode: fold, checkpoint: {}))
    }
    private func bounded(_ reply: ScriptValue, _ store: WorkspaceStore,
                         sources: [String: DecompileReplySource], fold: String? = nil,
                         refresh: (inout [String: ScriptValue]) -> Void = { _ in }) throws -> ScriptValue {
        try WorkspaceScriptingAPI.boundedDecompileReply(reply,
            shape: DecompileShape(format: .text, lineRange: nil, cursor: nil),
            slot: store.snapshot.primarySlot, functionStart: 0x1000, snapshot: store.snapshot,
            sources: sources, foldMode: fold, refreshPage: refresh)
    }
    private func paired(_ native: ScriptValue, _ macir: ScriptValue) throws -> ScriptValue {
        var n = try object(native), m = try object(macir)
        var result: [String: ScriptValue] = ["backend": .string("both")]
        for key in ["function", "address", "demangled", "imageSlot", "imageOwner",
                    "resolvedFunction", "resolution", "requestedAddress"] {
            if let value = m.removeValue(forKey: key) { result[key] = value }
            n.removeValue(forKey: key)
        }
        for key in ["fallbackReason", "fallbackCause", "fallbackDetail"] { m.removeValue(forKey: key) }
        n.removeValue(forKey: "backendRequested")
        result["native"] = .object(n); result["macir"] = .object(m)
        return .object(result)
    }
    private func mcpFrame(_ server: MCPServer, _ arguments: ScriptValue) async throws -> ScriptValue {
        let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
            "method": .string("tools/call"), "params": .object([
                "name": .string("decompile"), "arguments": arguments])])
        let data = await server.handleMessageAsync(try request.jsonData())
        let bytes = try XCTUnwrap(data)
        XCTAssertLessThanOrEqual(bytes.count + 1, 200_000) // Actual serialized frame, not only a re-encode.
        let frame = try ScriptValue.decode(bytes)
        XCTAssertNil(frame["error"]); XCTAssertNotNil(frame["result"])
        return frame
    }
    private func payload(_ frame: ScriptValue) throws -> ScriptValue {
        let text = try XCTUnwrap(frame["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }
    private func nearCapLines() -> [String] {
        (1...200).map { index in
            let prefix = String(index) + ":"
            return prefix + String(repeating: "x", count: 980 - prefix.utf8.count)
        }
    }

    func testWrapperArithmeticAndFitAboveConservativeReserve() throws {
        let store = makeStore(), lines = [String(repeating: "x", count: 98_000), String(repeating: "y", count: 98_000)]
        let original = try page(store, lines, extra: ["cache": .string(String(repeating: "c", count: 2_000))])
        XCTAssertGreaterThan(try WorkspaceScriptingAPI.listPageWireBytes(original), 196_608)
        try assertBound(original)
        XCTAssertEqual(try frameBytes(original), try WorkspaceScriptingAPI.listPageWireBytes(original) + 235)
        XCTAssertEqual(try frameBytes(original, .structured), try original.jsonData().count + 305)
        let result = try bounded(original, store, sources: ["native": source(lines)])
        XCTAssertEqual(try result.jsonData(), try original.jsonData()); XCTAssertNil(result["omittedFields"])
    }

    func testPagesCodeBeforeOmittingOpaqueRegionsInBothFormats() throws {
        let store = makeStore(), lines = [String(repeating: "x", count: 98_000), String(repeating: "y", count: 98_000)]
        let regions = ScriptValue.object(["opaque": .string(String(repeating: "r", count: 4_000))])
        for format in ["text", "lines"] {
            let original = try page(store, lines, extra: ["regions": regions], format: format)
            XCTAssertGreaterThan(try frameBytes(original), 200_000)
            let result = try bounded(original, store, sources: ["native": source(lines)])
            try assertBound(result); XCTAssertEqual(result["regions"], regions)
            XCTAssertNil(result["omittedFields"]); XCTAssertEqual(result["lastLine"], .int(1))
            XCTAssertEqual(result["truncated"], .bool(true)); XCTAssertEqual(result["responseComplete"], .bool(false))
            let cursor = try XCTUnwrap(result["nextCursor"]?.stringValue)
            let next = try page(store, lines, format: format, cursor: cursor)
            XCTAssertEqual(next["firstLine"], .int(2)); XCTAssertEqual(next["nextCursor"], .null)
            if format == "text" { XCTAssertEqual(next["pseudocode"], .string(lines[1])) }
            else { XCTAssertEqual(next["lines"]?.arrayValue?.first?["text"], .string(lines[1])) }
        }
    }

    func testLateProvenanceAloneCrossesTheFinishedFrameBoundary() throws {
        let store = makeStore(), lines = nearCapLines()
        let finished = try page(store, lines, extra: [
            "function": .string(String(repeating: "f", count: 2_800)), "requestedAddress": .hex(0x1000)])
        var beforeLateFields = try object(finished)
        for key in ["imageSlot", "imageOwner", "resolvedFunction", "resolution", "requestedAddress"] {
            beforeLateFields.removeValue(forKey: key)
        }
        XCTAssertEqual(try frameBytes(.object(beforeLateFields)), 199_920)
        XCTAssertEqual(try frameBytes(finished), 200_081)
        let bounded = try bounded(finished, store, sources: ["native": source(lines)])
        try assertBound(bounded); XCTAssertNil(bounded["omittedFields"])
        XCTAssertEqual(bounded["function"], finished["function"])
        XCTAssertLessThan(try XCTUnwrap(bounded["lastLine"]?.intValue), 200)
    }

    func testWholeOptionalFieldsAreNamedAndNeverSliced() throws {
        let store = makeStore(), lines = ["one", "two"]
        let large = String(repeating: "x", count: 200_000)
        let cases: [(String, ScriptValue)] = [
            ("regions", .object(["opaque": .string(large)])),
            ("unplacedComments", .array([.object(["text": .string(large)])])),
            ("foldedEvents", .array([.object(["comment": .string(large)])])),
            ("language", .string(large)),
        ]
        for (key, value) in cases {
            let original = try page(store, lines, extra: [key: value])
            XCTAssertGreaterThan(try frameBytes(original), 200_000)
            let result = try bounded(original, store, sources: ["native": source(lines)])
            try assertBound(result); XCTAssertEqual(result["lastLine"], .int(1))
            XCTAssertNil(result[key]); XCTAssertEqual(result["omittedFields"], .array([.string(key)]))
            XCTAssertEqual(result["responseComplete"], .bool(false))
            XCTAssertNotNil(result["nextCursor"]?.stringValue)
        }
        let regions = ScriptValue.string(String(repeating: "r", count: 100_100))
        let events = ScriptValue.array([.string(String(repeating: "e", count: 100_000))])
        let original = try page(store, ["one"], extra: ["regions": regions, "foldedEvents": events])
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        let result = try bounded(original, store, sources: ["native": source(["one"])])
        try assertBound(result); XCTAssertEqual(result["omittedFields"], .array([.string("regions")]))
        XCTAssertEqual(result["foldedEvents"], events) // The surviving array is byte-for-byte whole.
    }

    func testOneBudgetForPairAndQualifiedOmissionNames() throws {
        let store = makeStore(), n = Array(repeating: String(repeating: "n", count: 25_000), count: 4)
        let m = Array(repeating: String(repeating: "m", count: 25_000), count: 4)
        let native = try page(store, n), macir = try page(store, m, backend: "macir")
        let original = try paired(native, macir)
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        let result = try bounded(original, store, sources: ["native": source(n), "macir": source(m)])
        try assertBound(result); XCTAssertLessThan(try XCTUnwrap(result["native"]?["lastLine"]?.intValue), 4)
        XCTAssertEqual(result["macir"], original["macir"]); XCTAssertNil(result["omittedFields"])
        let big = ScriptValue.array([.string(String(repeating: "r", count: 200_000))])
        let smallNative = try page(store, ["n"])
        let smallMacir = try page(store, ["m"], backend: "macir", extra: ["regions": big])
        let oversized = try paired(smallNative, smallMacir)
        XCTAssertGreaterThan(try frameBytes(oversized), 200_000)
        let omitted = try bounded(oversized, store, sources: ["native": source(["n"]), "macir": source(["m"])])
        try assertBound(omitted); XCTAssertNil(omitted["macir"]?["regions"])
        XCTAssertEqual(omitted["omittedFields"], .array([.string("macir.regions")]))
        XCTAssertEqual(omitted["responseComplete"], .bool(false))
    }

    func testNativeMCPWalksEveryLineAfterFinalBounding() async throws {
        let lines = nearCapLines(), text = lines.joined(separator: "\n")
        XCTAssertEqual(try WorkspaceScriptingAPI.listPageWireBytes(.string(text)), 196_601)
        let name = "f" + String(repeating: "x", count: 4_095), store = makeStore(name: "f" + String(repeating: "x", count: 4_095))
        let old = try page(store, lines, extra: ["function": .string(name)])
        XCTAssertGreaterThan(try frameBytes(old), 200_000)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: BoundNativeStub(text: text))
        let server = MCPServer(api: api)
        var extra: [String: ScriptValue] = [:], collected: [String] = [], pages = 0
        var previousLast: Int64 = 0
        while pages < lines.count {
            let frame = try await mcpFrame(server, args(extra)), value = try payload(frame)
            XCTAssertEqual(frame["result"]?["isError"], .bool(false))
            XCTAssertLessThanOrEqual(try frame.jsonData().count + 1, 200_000); try assertBound(value)
            XCTAssertEqual(value["firstLine"], .int(previousLast + 1))
            let last = try XCTUnwrap(value["lastLine"]?.intValue)
            XCTAssertGreaterThan(last, previousLast); previousLast = last; pages += 1
            collected += try XCTUnwrap(value["pseudocode"]?.stringValue).split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            guard let cursor = value["nextCursor"]?.stringValue else {
                XCTAssertEqual(value["nextCursor"], .null); break
            }
            extra = ["cursor": .string(cursor)]
        }
        XCTAssertGreaterThan(pages, 1); XCTAssertEqual(previousLast, 200); XCTAssertEqual(collected, lines)
        XCTAssertEqual(collected.joined(separator: "\n"), text)
    }

    func testBothMCPBudgetAndExistingCursorRefusal() async throws {
        let lines = nearCapLines(), name = "f" + String(repeating: "x", count: 4_095)
        let store = makeStore(name: name)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: BoundNativeStub(text: lines.joined(separator: "\n")))
        let original = try paired(page(store, lines, extra: ["function": .string(name)]),
            page(store, ["m"], backend: "macir", extra: ["function": .string(name)]))
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        let server = MCPServer(api: api), frame = try await mcpFrame(server, args(["backend": .string("both")]))
        let value = try payload(frame)
        XCTAssertEqual(frame["result"]?["isError"], .bool(false))
        XCTAssertLessThanOrEqual(try frame.jsonData().count + 1, 200_000); try assertBound(value)
        XCTAssertEqual(value["backend"], .string("both")); XCTAssertNotNil(value["macir"])
        XCTAssertLessThan(try XCTUnwrap(value["native"]?["lastLine"]?.intValue), 200)
        let cursor = try XCTUnwrap(value["native"]?["nextCursor"]?.stringValue)
        do {
            _ = try await api.executeAsync("decompile", arguments: args(["backend": .string("both"), "cursor": .string(cursor)]))
            XCTFail("Expected existing both/cursor refusal")
        } catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument("backend both cannot accompany cursor")) }
        let refused = try await mcpFrame(server, args(["backend": .string("both"), "cursor": .string(cursor)]))
        XCTAssertEqual(refused["result"]?["isError"], .bool(true))
        let refusalText = try XCTUnwrap(refused["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertTrue(refusalText.contains("backend both cannot accompany cursor"))
        let suffix = try payload(await mcpFrame(server, args(["backend": .string("native"), "cursor": .string(cursor)])))
        XCTAssertEqual(suffix["firstLine"]?.intValue, value["native"]?["lastLine"]?.intValue.map { $0 + 1 })
    }

    func testRequiredFieldsRefuseThroughAPIAndMCPWithoutRPCError() async throws {
        let name = "f" + String(repeating: "x", count: 199_999), lines = ["one"]
        let store = makeStore(name: name), old = try page(makeStore(), lines, extra: ["function": .string(name)])
        XCTAssertGreaterThan(try frameBytes(old), 200_000)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: BoundNativeStub(text: "one"))
        do {
            _ = try await api.executeAsync("decompile", arguments: args(["format": .string("text")]))
            XCTFail("Expected typed required-field refusal")
        } catch {
            guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("Wrong refusal: \(error)") }
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget, MCPRefusalBudget(unit: .bytes, limit: 200_000))
            XCTAssertGreaterThan(try XCTUnwrap(refusal.used), 200_000)
            XCTAssertFalse(try XCTUnwrap(refusal.narrowing).isEmpty)
        }
        let frame = try await mcpFrame(MCPServer(api: api), args()), result = try payload(frame)
        XCTAssertNil(frame["error"]); XCTAssertEqual(result["error"], .string("refused"))
        XCTAssertEqual(result["refusal"]?["code"], .string("budgetExceeded"))
        XCTAssertEqual(result["refusal"]?["budget"], .object(["unit": .string("bytes"), "limit": .int(200_000)]))
        XCTAssertGreaterThan(try XCTUnwrap(result["refusal"]?["used"]?.intValue), 200_000)
        XCTAssertFalse(try XCTUnwrap(result["refusal"]?["narrowing"]?.arrayValue).isEmpty)
        XCTAssertLessThanOrEqual(try frame.jsonData().count + 1, 200_000)
    }

    func testFallbackPairCannotBypassFinalBudget() async throws {
        let store = makeStore(), code = String(repeating: "f", count: 100_000)
        // The default disclosure copies the failed code into both reason and detail.
        // MacIR requested:true does not itself contain those native fallback fields.
        let failure = ScriptValue.object(["fallbackReason": .string("native-failed: " + code),
            "fallbackCause": .string("error"), "fallbackDetail": .string(code)])
        let original = try paired(failure, page(store, ["m"], backend: "macir"))
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: BoundFailedNativeStub(code: code))
        let frame = try await mcpFrame(MCPServer(api: api), args(["backend": .string("both")]))
        let result = try payload(frame)
        XCTAssertEqual(result["error"], .string("refused"))
        XCTAssertEqual(result["refusal"]?["code"], .string("budgetExceeded"))
        XCTAssertGreaterThan(try XCTUnwrap(result["refusal"]?["used"]?.intValue), 200_000)
    }

    func testOversizedSingleLineKeepsWholeCodeAndOmitsAllOptionalFields() throws {
        let store = makeStore(), lines = [String(repeating: "x", count: 200_000), "b"]
        let original = try page(store, lines, extra: ["regions": .array([.string("r")]), "cache": .string("hit")])
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        let result = try bounded(original, store, sources: ["native": source(lines)])
        XCTAssertEqual(result["pseudocode"], .string(lines[0])); XCTAssertEqual(result["firstLine"], .int(1))
        XCTAssertEqual(result["lastLine"], .int(1)); XCTAssertEqual(result["truncated"], .bool(true))
        XCTAssertEqual(result["responseComplete"], .bool(false))
        XCTAssertGreaterThan(try frameBytes(result), 200_000) // Explicit D2 exception, not a bound assertion.
        let names = Set(try XCTUnwrap(result["omittedFields"]?.arrayValue).compactMap(\.stringValue))
        XCTAssertEqual(names, Set(["regions", "cache", "structured", "language"]))
        for key in names { XCTAssertNil(result[key]) }
        let cursor = try XCTUnwrap(result["nextCursor"]?.stringValue)
        let suffix = try page(store, lines, cursor: cursor)
        XCTAssertEqual(suffix["pseudocode"], .string("b")); XCTAssertEqual(suffix["nextCursor"], .null)
    }

    func testPairDoesNotMultiplySingleLineExceptionAndNilShapeIsUnchanged() throws {
        let store = makeStore(), lines = [String(repeating: "x", count: 200_000)]
        let native = try page(store, lines), macir = try page(store, ["m"], backend: "macir")
        let original = try paired(native, macir)
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        XCTAssertThrowsError(try bounded(original, store, sources: ["native": source(lines), "macir": source(["m"])])) {
            guard case ScriptingError.structuredRefusal(let refusal) = $0 else { return XCTFail("Expected typed refusal") }
            XCTAssertEqual(refusal.code, .budgetExceeded)
        }
        let unshaped = try WorkspaceScriptingAPI.boundedDecompileReply(original, shape: nil,
            slot: store.snapshot.primarySlot, functionStart: 0x1000, snapshot: store.snapshot, sources: [:])
        XCTAssertEqual(unshaped, original)
    }

    func testSingleLineExceptionUsesExplicitCodeContributionThresholds() throws {
        let store = makeStore()
        for width in [199_693, 199_694] {
            let lines = [String(repeating: "x", count: width)], code = ScriptValue.string(lines[0])
            // A quoted plain ASCII code value has J = width + 2. The structured
            // payload allowance is 200000 - 305 = 199695; equality is not an exception.
            XCTAssertEqual(try code.jsonData().count, width + 2)
            let original = try page(store, lines)
            XCTAssertGreaterThan(try frameBytes(original), 200_000)
            if width == 199_693 {
                XCTAssertThrowsError(try bounded(original, store, sources: ["native": source(lines)])) {
                    guard case ScriptingError.structuredRefusal(let refusal) = $0 else { return XCTFail("Expected typed refusal") }
                    XCTAssertEqual(refusal.code, .budgetExceeded)
                }
            } else {
                let result = try bounded(original, store, sources: ["native": source(lines)])
                XCTAssertEqual(result["pseudocode"], code); XCTAssertEqual(result["nextCursor"], .null)
                XCTAssertNotNil(result["omittedFields"]); XCTAssertNil(result["language"])
                XCTAssertNil(result["structured"])
            }
        }
    }

    func testLogicalLinesAndFoldCursorAreNotReconstructedFromNewlines() throws {
        let store = makeStore()
        let lines = [String(repeating: "x", count: 97_999) + "\n", String(repeating: "y", count: 98_000)]
        let original = try page(store, lines, backend: "macir",
            extra: ["regions": .string(String(repeating: "r", count: 4_000))], fold: "arc")
        XCTAssertGreaterThan(try frameBytes(original), 200_000)
        let result = try bounded(original, store, sources: ["macir": source(lines)], fold: "arc") { fields in
            fields["foldedEvents"] = .array([.object(["beforeLine": fields["lastLine"] ?? .null])])
        }
        try assertBound(result); XCTAssertEqual(result["lastLine"], .int(1))
        XCTAssertEqual(result["pseudocode"], .string(lines[0]))
        XCTAssertEqual(result["foldedEvents"], .array([.object(["beforeLine": .int(1)])]))
        let cursor = try XCTUnwrap(result["nextCursor"]?.stringValue)
        let body = String(decoding: try XCTUnwrap(Data(base64Encoded: cursor)), as: UTF8.self)
        XCTAssertTrue(body.hasPrefix("d2|0|4096|2|")); XCTAssertTrue(body.hasSuffix("|arc"))
        let suffix = try page(store, lines, backend: "macir", cursor: cursor, fold: "arc")
        XCTAssertEqual(suffix["firstLine"], .int(2)); XCTAssertEqual(suffix["pseudocode"], .string(lines[1]))
    }

    func testDefaultFitNativeAndMacIRKeepPinKeysAndBytes() async throws {
        let store = makeStore(), api = WorkspaceScriptingAPI(store: makeStore(), nativeDecompiler: BoundNativeStub(text: "a\nb\nc\nd\ne"))
        let named = ScriptValue.object(["function": .string("_main")])
        let shaped = ScriptValue.object(["function": .string("_main"), "format": .string("text")])
        let native = try await api.executeAsync("decompile", arguments: shaped)
        XCTAssertEqual(Set(try object(native).keys), Set([
            "function", "address", "pseudocode", "structured", "backend", "language", "complete",
            "truncated", "responseComplete", "imageSlot", "imageOwner", "resolvedFunction", "resolution",
            "lineCount", "firstLine", "lastLine", "nextCursor", "documentTruncated",
        ]))
        let macirAPI = WorkspaceScriptingAPI(store: store)
        let legacyMacIR = try macirAPI.execute("decompile", arguments: named)
        let macir = try macirAPI.execute("decompile", arguments: shaped)
        var macirKeys = Set([
            "function", "address", "pseudocode", "structured", "backend", "fallbackReason", "fallbackCause",
            "fallbackDetail", "imageSlot", "imageOwner", "resolvedFunction", "resolution",
            "lineCount", "firstLine", "lastLine", "nextCursor", "truncated",
        ])
        // These three pin branches depend on renderer output absent from this packet.
        // Use the independent, unchanged unshaped route as the branch oracle, never the reply under test.
        for key in ["regions", "structureFallback", "callTargetNames"] where legacyMacIR[key] != nil { macirKeys.insert(key) }
        XCTAssertEqual(Set(try object(macir).keys), macirKeys)
        let legacyNative = try await api.executeAsync("decompile", arguments: named)
        for (legacy, actual, isNative) in [(legacyNative, native, true), (legacyMacIR, macir, false)] {
            var expected = try object(legacy)
            let rows = try XCTUnwrap(expected["lines"]?.arrayValue), count = rows.count
            expected["pseudocode"] = .string(try rows.map { try XCTUnwrap($0["text"]?.stringValue) }.joined(separator: "\n"))
            expected.removeValue(forKey: "lines")
            expected["lineCount"] = .int(Int64(count)); expected["firstLine"] = count == 0 ? .null : .int(1)
            expected["lastLine"] = count == 0 ? .null : .int(Int64(count)); expected["nextCursor"] = .null
            expected["truncated"] = .bool(false)
            if isNative { expected["documentTruncated"] = .bool(false) }
            try assertBound(actual); XCTAssertNil(actual["omittedFields"])
            XCTAssertEqual(try actual.jsonData(), try ScriptValue.object(expected).jsonData())
        }
    }
}
