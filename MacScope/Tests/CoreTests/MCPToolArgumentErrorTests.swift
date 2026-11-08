import Foundation
import XCTest
@testable import MacScope

@MainActor
@discardableResult
func assertMCPToolArgumentError(
    _ response: ScriptValue?, field: String, code: String,
    file: StaticString = #filePath, line: UInt = #line
) -> ScriptValue {
    XCTAssertNil(response?["error"], file: file, line: line)
    XCTAssertEqual(response?["result"]?["isError"], .bool(true), file: file, line: line)
    XCTAssertEqual(response?["result"]?["content"]?.arrayValue?.count, 1, file: file, line: line)
    do {
        let text = try XCTUnwrap(response?["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue,
                                 file: file, line: line)
        let payload = try ScriptValue.decode(Data(text.utf8))
        XCTAssertEqual(payload["error"], .string("refused"), file: file, line: line)
        XCTAssertEqual(payload["refusal"]?["field"], .string(field), file: file, line: line)
        XCTAssertEqual(payload["refusal"]?["code"], .string(code), file: file, line: line)
        XCTAssertEqual(payload["refusal"]?["retryable"], .bool(false), file: file, line: line)
        return payload["refusal"] ?? .null
    } catch {
        XCTFail("Missing structured refusal: \(error)", file: file, line: line)
        return .null
    }
}

@MainActor
final class MCPToolArgumentErrorTests: XCTestCase {
    private func makeServer() -> MCPServer {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000,
                                        endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000,
                                    kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov",
                               operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret",
                               operands: "", hasBreakpoint: false, comment: nil),
            ], xrefs: [], hexBytes: Data())
        let store = WorkspaceStore(workspaceName: "MCP", snapshot: snapshot, engine: AnalysisEngine())
        return MCPServer(api: WorkspaceScriptingAPI(store: store))
    }

    private func request(_ command: String, _ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                 "params": .object(["name": .string(command), "arguments": arguments])])
    }

    // Before: every case is a protocol -32602 with no result on both paths.
    func testSixAcceptanceCasesOnBothDeciders() async throws {
        let cases: [(String, ScriptValue, String, String, ScriptValue)] = [
            ("list-image-types", .object(["kind": .string("class")]), "kind", "malformedInput",
             .object(["allowed": .array(["importedType", "objcCategory", "objcClass", "objcProtocol",
                                        "swiftClass", "swiftEnum", "swiftStruct", "userType"].map { .string($0) })])),
            // 326d0207d (S1: add bounded graph edge continuation) admits limit only with page:true.
            ("callers", .object(["address": .hex(0x1000), "limit": .int(5)]), "page", "malformedInput",
             .object(["detail": .string("Invalid argument: limit requires page:true for callers and callees.")])),
            ("functions", .object(["limit": .int(50_000)]), "limit", "outOfBounds",
             .object(["minimum": .int(0), "maximum": .int(10_000)])),
            ("functions", .object(["limit": .string("0")]), "limit", "malformedInput",
             .object(["expected": .string("integer")])),
            ("navigator-facts", .object([:]), "imageSlot", "malformedInput",
             .object(["expected": .string("integer or string")])),
            ("read-bytes", .object(["address": .hex(0x1000), "count": .int(Int64.max)]), "count", "outOfBounds",
             .object(["minimum": .int(0), "maximum": .int(1_048_576)])),
        ]
        for (command, arguments, field, code, extra) in cases {
            let server = makeServer()
            let input = request(command, arguments)
            let inline = server.handle(input)
            let bytes = await server.handleMessageAsync(try input.jsonData())
            let asyncReply = try ScriptValue.decode(try XCTUnwrap(bytes))
            for response in [inline, Optional(asyncReply)] {
                let record = assertMCPToolArgumentError(response, field: field, code: code)
                guard case .object(let expected) = extra else { return XCTFail("bad fixture") }
                for (key, value) in expected { XCTAssertEqual(record[key], value, command) }
                if expected["detail"] == nil {
                    XCTAssertTrue(record["detail"]?.stringValue?.contains("'\(field)'") == true)
                }
                XCTAssertNil(record["budget"])
                XCTAssertNil(record["used"])
                XCTAssertNil(record["narrowing"])
            }
            XCTAssertEqual(inline, asyncReply)
        }
    }

    // Before: bad operation, extra key and bad search kind all lose their detail in -32602.
    func testMappedScriptingErrorsAndUnknownKeyRemainDistinct() {
        let server = makeServer()
        let badOperation = assertMCPToolArgumentError(server.handle(request("read-evidence",
            .object(["operation": .string("decompiler.native.result")]))), field: "operation", code: "malformedInput")
        XCTAssertEqual(badOperation["allowed"], .array([
            .string("application.graph.summary"), .string("function.review"), .string("workspace.summary")]))
        assertMCPToolArgumentError(server.handle(request("read-evidence",
            .object(["operation": .string("workspace.summary"), "principal": .string("app")]))),
            field: "principal", code: "malformedInput")
        let missing = assertMCPToolArgumentError(server.handle(request("read-evidence", .object([:]))),
                                                 field: "operation", code: "malformedInput")
        XCTAssertEqual(missing["allowed"], badOperation["allowed"])
        for (mode, kind, allowed) in [
            ("hex", "function", ["bytes"]),
            ("text", "bytes", ["function", "instruction", "string", "symbol"]),
        ] {
            let record = assertMCPToolArgumentError(server.handle(request("search", .object([
                "query": .string("aa"), "mode": .string(mode), "kind": .string(kind)
            ]))), field: "kind", code: "malformedInput")
            XCTAssertEqual(record["allowed"], .array(allowed.map { .string($0) }))
        }
    }

    // Before: protocol -32602; the diagnostic must select a deterministic bounded key.
    func testUnknownKeySortingAndScalarSafeTruncation() {
        let key = String(repeating: "é", count: 40)
        let record = assertMCPToolArgumentError(makeServer().handle(request("info", .object([
            key: .int(1), "zz": .int(2)
        ]))), field: "zz", code: "malformedInput")
        XCTAssertNotNil(record["allowed"])
        let clipped = String(repeating: "é", count: 32)
        let long = assertMCPToolArgumentError(makeServer().handle(request("info", .object([
            key: .int(1)
        ]))), field: clipped, code: "malformedInput")
        XCTAssertEqual(long["field"]?.stringValue?.utf8.count, 64)
        XCTAssertEqual(long["detail"], .string("Field '\(clipped)' is not an allowed argument."))
    }

    // Before: protocol -32602; nested failures name their top-level argument.
    func testNestedAndCompoundValidationFields() {
        let server = makeServer()
        let cases: [(String, ScriptValue, String, String)] = [
            ("rename", .object(["address": .hex(0x1000), "name": .object(["": .int(1)])]), "name", "malformedInput"),
            ("rename", .object(["address": .hex(0x1000), "name": .object([String(repeating: "k", count: 257): .int(1)])]), "name", "outOfBounds"),
            ("read-bytes", .object(["image": .bool(true)]), "image", "malformedInput"),
            ("read-bytes", .object(["image": .int(-1)]), "image", "outOfBounds"),
            ("read-bytes", .object(["image": .string(String(repeating: "x", count: 65))]), "image", "outOfBounds"),
            ("accept-struct-candidate", .object(["candidate": .int(1), "name": .int(1)]), "candidate", "malformedInput"),
            ("accept-struct-candidate", .object(["candidate": .string("c"), "name": .string("T"),
                                               "choices": .array([.object(["offset": .int(0)])])]), "choices", "malformedInput"),
            ("set-stack-local", .object(["local": .string("-8:0")]), "name", "malformedInput"),
            ("set-stack-local", .object(["local": .string("-8:0"), "name": .string(String(repeating: "a", count: 1_025))]), "name", "outOfBounds"),
        ]
        for (command, args, field, code) in cases {
            assertMCPToolArgumentError(server.handle(request(command, args)), field: field, code: code)
        }
    }

    // Before: protocol -32602, including required navigator fields and page limits.
    func testNavigatorDiagnostics() {
        let server = makeServer()
        for (command, arguments, field, code) in [
            ("navigator-facts", ScriptValue.object(["imageSlot": .int(0), "limit": .int(257)]), "limit", "outOfBounds"),
            ("navigator-facts", .object(["imageSlot": .int(0), "cursor": .string("bad")]), "cursor", "malformedInput"),
            ("navigator-dependents", .object(["imageSlot": .int(0)]), "id", "malformedInput"),
            ("navigator-revert", .object(["imageSlot": .int(0), "id": .string("fact")]), "session", "malformedInput"),
            ("navigator-accept", .object(["imageSlot": .int(0), "annotation": .string("x")]), "annotation", "malformedInput"),
        ] {
            assertMCPToolArgumentError(server.handle(request(command, arguments)), field: field, code: code)
        }
    }

    // Positive controls: envelope -32602, execution text, and legacy validation types stay.
    func testEnvelopeExecutionAndDirectValidationControls() throws {
        let server = makeServer()
        let envelope = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
            "method": .string("tools/call"), "params": .object([:])])
        XCTAssertEqual(server.handle(envelope)?["error"]?["code"], .int(-32602))
        let execution = server.handle(request("rename", .object(["address": .hex(0x1000)])))
        XCTAssertEqual(execution?["result"]?["isError"], .bool(true))
        // 2e64a5ce3 (Bound correlated MCP response frames) marks thrown mutation handlers unknown.
        XCTAssertEqual(execution?["result"]?["content"]?.arrayValue?.first?["text"],
                       .string("Tool call failed: Missing required argument 'name'. Mutation outcome unknown; do not retry automatically."))
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(command: "functions",
            arguments: .object(["limit": .int(50_000)]))) {
            XCTAssertEqual($0 as? HeadlessAutomationAuthorityError, .invalidArguments)
        }
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(command: "read-evidence",
            arguments: .object(["operation": .string("bad")]))) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument("read-evidence requires one supported operation"))
        }
        XCTAssertThrowsError(try NavigatorMCPCommands.validate(command: "navigator-facts", fields: [:])) {
            XCTAssertEqual($0 as? HeadlessAutomationAuthorityError, .invalidArguments)
        }
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(command: "functions",
            arguments: .object(["limit": .int(0)])))
    }

    // New types do not compile before FIX; before-FIX validation produced only -32602.
    func testTypedDiagnosticPreservesUnderlyingError() throws {
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: "read-evidence",
            arguments: .object(["operation": .string("bad")]))) {
            let error = $0 as? ToolArgumentError
            XCTAssertEqual(error?.underlying, .scripting(.invalidArgument("read-evidence requires one supported operation")))
            XCTAssertEqual(error?.refusal.field, "operation")
        }
    }

    // New encoder type does not exist before FIX; no budget record was emitted at the pin.
    func testBudgetEncoderKnownAndUnknownUse() throws {
        var record = MCPToolRefusal(code: .budgetExceeded, detail: "Snapshot work limit exceeded.",
            budget: MCPRefusalBudget(unit: .workSteps, limit: 100_000),
            used: 100_001, narrowing: [])
        let known = try ScriptValue.decode(Data(record.text.utf8))
        XCTAssertEqual(known["refusal"]?["budget"],
                       .object(["unit": .string("workSteps"), "limit": .int(100_000)]))
        XCTAssertEqual(known["refusal"]?["used"], .int(100_001))
        XCTAssertEqual(known["refusal"]?["narrowing"], .array([]))
        XCTAssertEqual(record.text, String(decoding: try record.value.jsonData(), as: UTF8.self))
        record.used = nil
        XCTAssertEqual(try ScriptValue.decode(Data(record.text.utf8))["refusal"]?["used"], .null)
        record.budget = nil
        XCTAssertNil(try ScriptValue.decode(Data(record.text.utf8))["refusal"]?["used"])
    }
}
