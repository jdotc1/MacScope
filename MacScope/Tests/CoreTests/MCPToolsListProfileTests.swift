import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// ITEM 1283: authored, unrun. Intended to prove membership, copy-only exact compaction,
/// unchanged authority/validation controls, launch parsing and instruction budgets.
/// Same-build controls are not historical bytes, stderr-descriptor or client evidence.
@MainActor
final class MCPToolsListProfileTests: XCTestCase {
    private static let core: Set<String> = [
        "info", "list-image-types", "search", "decompile", "functions", "symbols", "strings",
        "sections", "instructions", "read-bytes", "callers", "callees", "xrefs", "name-at",
        "containing-function", "demangle", "function-facts", "function-references", "call-path",
        "imports", "exports", "basic-blocks", "resolve-symbol", "commands",
        "rename", "set-names", "set-comment", "set-comments",
    ]
    private static let writes = ["rename", "set-names", "set-comment", "set-comments"]
    private static let harness: Set<String> = ["neon-hitrate", "reconstruction-jobs"]
    private static let marker = " (mutates the workspace)"
    // Independent source literals: MCPServer.swift:826,1065,1086,1094 (part2of4)
    // (the Navigator-only description is not in core). No production constant supplies expectations.
    private static let descriptions = [
        "Optional analysis generation from the reply's generation text block (also result._meta.generation); null or omission retains legacy unconditional writes. A mismatch is staleEvidence with basedOnGeneration and currentGeneration.",
        "Unsigned address. Exact-address tools use the address itself. Function-selector tools require a containing function (or the exact start of a zero-width function) and refuse uncovered addresses; a supplied function name takes precedence. Prefer a hexadecimal string to preserve all 64 bits.",
        "Restrict the rows to one loaded image: a slot index or an image-owner ID (UUID). Omit to search every image (search) or read the primary image (callers, callees, xrefs, function-references). Every row reports the `imageSlot` that produced it.",
        "Image to read: a slot index (0 is the primary image) or an image-owner ID (UUID). Omit for the primary image.",
    ]
    private static let appendage = " Optional basedOnGeneration is an analysis-generation UUID from prior evidence; a mismatch refuses the write with staleEvidence and both generations. MCP write replies disclose the resulting generation; guarded object replies also include generation."

    // Redeclared fixture, not another test class's private helper (SizeTests:40-57).
    private func makeAPI() -> WorkspaceScriptingAPI {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000, kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
            ], xrefs: [], hexBytes: Data())
        return WorkspaceScriptingAPI(store: WorkspaceStore(workspaceName: "MCP", snapshot: snapshot, engine: AnalysisEngine()))
    }
    private func server(_ profile: MCPToolListingProfile? = nil, harness: Bool = false,
                        allowed: Set<String>? = nil, api: WorkspaceScriptingAPI? = nil,
                        configuration: MCPServer.Configuration = .production,
                        executor: MCPServer.AsyncCommandExecutor? = nil) -> MCPServer {
        MCPServer(api: api ?? makeAPI(), configuration: configuration.listing(profile: profile),
                  asyncCommandExecutor: executor, allowedCommands: allowed, listHarnessTools: harness)
    }
    private func request(_ method: String = "tools/list", params: ScriptValue? = nil) throws -> Data {
        var fields: [String: ScriptValue] = ["jsonrpc": .string("2.0"), "id": .int(1), "method": .string(method)]
        if let params { fields["params"] = params }
        return try ScriptValue.object(fields).jsonData()
    }
    private func reply(_ server: MCPServer, _ data: Data) throws -> Data {
        try XCTUnwrap(server.handleMessage(data))
    }
    private func tools(_ data: Data) throws -> [ScriptValue] {
        let response = try ScriptValue.decode(data)
        XCTAssertEqual(response["jsonrpc"], .string("2.0"))
        XCTAssertEqual(response["id"], .int(1))
        XCTAssertNil(response["error"])
        return try XCTUnwrap(response["result"]?["tools"]?.arrayValue)
    }
    private func names(_ entries: [ScriptValue]) throws -> [String] {
        try entries.map { try XCTUnwrap($0["name"]?.stringValue) }
    }
    private func object(_ value: ScriptValue?) throws -> [String: ScriptValue] {
        guard case .object(let fields)? = value else { throw NSError(domain: "ExpectedObject", code: 1) }
        return fields
    }
    private func expected(_ original: ScriptValue) throws -> ScriptValue {
        var fields = try object(original)
        var schema = try object(fields["inputSchema"])
        var properties = try object(schema["properties"])
        for (key, property) in properties {
            guard case .object(var members) = property else { continue }
            if let text = members["description"]?.stringValue, Self.descriptions.contains(text) {
                members.removeValue(forKey: "description")
            }
            properties[key] = .object(members)
        }
        schema["properties"] = .object(properties)
        fields["inputSchema"] = .object(schema)
        if let name = fields["name"]?.stringValue, Self.writes.contains(name),
           let text = fields["description"]?.stringValue, text.hasSuffix(Self.appendage + Self.marker) {
            fields["description"] = .string(String(text.dropLast((Self.appendage + Self.marker).count)) + Self.marker)
        }
        return .object(fields)
    }
    private func record(_ text: String) {
        let attachment = XCTAttachment(string: text)
        attachment.name = "1283 authored-unrun owner measurement"
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    func testProfileTypeAndStrictParser() {
        XCTAssertEqual(MCPToolListingProfile.coreNames, Self.core)
        XCTAssertEqual(Self.appendage, ScriptingCommandInfo(name: "", summary: "", mutates: true, arguments: []).withEvidencePrecondition.summary)
        let cases: [(String?, MCPToolListingProfile, Bool)] = [
            (nil, .core, false), ("core", .core, false), ("full", .full, false),
            ("", .full, true), ("Core", .full, true), ("CORE", .full, true),
            (" core", .full, true), ("full ", .full, true), ("other", .full, true),
        ]
        for (input, profile, warns) in cases {
            let parsed = MCPToolListingProfile.resolve(input)
            XCTAssertEqual(parsed.profile, profile)
            XCTAssertEqual(parsed.warning, warns ? "Unknown MACSCOPE_MCP_LIST_PROFILE; using full." : nil)
            var warnings: [String] = []
            let environment = input.map { ["MACSCOPE_MCP_LIST_PROFILE": $0] } ?? [:]
            let config = MCPToolListingProfile.launchConfiguration(environment: environment, warn: { warnings.append($0) })
            XCTAssertEqual(config.listingProfile, profile)
            XCTAssertEqual(warnings, warns ? ["Unknown MACSCOPE_MCP_LIST_PROFILE; using full."] : [])
        }
    }
    func testConfigurationCopyInvariantControl() {
        XCTAssertNil(MCPServer.Configuration.production.listingProfile)
        let base = MCPServer.Configuration(maximumInputBytes: 2_048, maximumOutputBytes: 1_024,
            maximumToolDurationNanoseconds: 2_000_000_000, maximumRememberedCancellations: 17, maximumInFlightRequests: 3)
        for profile in [MCPToolListingProfile.core, .full] {
            let copied = base.listing(profile: profile)
            XCTAssertEqual(copied.listingProfile, profile)
            XCTAssertEqual(copied.maximumInputBytes, base.maximumInputBytes)
            XCTAssertEqual(copied.maximumOutputBytes, base.maximumOutputBytes)
            XCTAssertEqual(copied.maximumToolDurationNanoseconds, base.maximumToolDurationNanoseconds)
            XCTAssertEqual(copied.maximumRememberedCancellations, base.maximumRememberedCancellations)
            XCTAssertEqual(copied.maximumInFlightRequests, base.maximumInFlightRequests)
            XCTAssertNil(copied.listing(profile: nil).listingProfile)
        }
    }
    func testCoreLaunchDefaultNamesOrderAndWireGate() throws {
        let config = MCPToolListingProfile.launchConfiguration(environment: [:], warn: { _ in XCTFail("Unexpected warning") })
        let bytes = try reply(MCPServer(api: makeAPI(), configuration: config, listHarnessTools: false), request())
        let actual = try names(tools(bytes))
        XCTAssertEqual(actual.count, 28)
        XCTAssertEqual(Set(actual), Self.core)
        XCTAssertEqual(actual, HeadlessAutomationAuthority.availableCommands.filter { Self.core.contains($0.name) }.map(\.name))
        for name in Self.writes { XCTAssertTrue(actual.contains(name)) }
        let wire = bytes.count + 1 // HeadlessProtocolIO appends exactly one LF.
        XCTAssertLessThanOrEqual(wire, 40_000)
        XCTAssertGreaterThanOrEqual(45_000 - wire, 5_000)
        print("1283 MEASURED core payload=\(bytes.count) wire=\(wire)")
        record("core payload=\(bytes.count) wire=\(wire) headroom=\(45_000 - wire)")
    }
    func testUnprofiledAndFullBytesInvariantControl() throws {
        let input = try request()
        let originalShape = MCPServer(api: makeAPI(), listHarnessTools: false)
        let baseline = try reply(originalShape, input)
        XCTAssertEqual(try reply(server(), input), baseline)
        XCTAssertEqual(try reply(server(.full), input), baseline)
        let catalog = HeadlessAutomationAuthority.availableCommands.filter { !Self.harness.contains($0.name) }
        let entries = catalog.map { command in ScriptValue.object([
            "name": .string(command.name),
            "description": .string(command.summary + (command.mutates ? Self.marker : "")),
            "inputSchema": HeadlessAutomationAuthority.inputSchema(for: command),
            "annotations": .object(["readOnlyHint": .bool(!command.mutates), "destructiveHint": .bool(command.mutates)]),
        ]) }
        XCTAssertEqual(try tools(baseline), entries)
        record("full payload=\(baseline.count) wire=\(baseline.count + 1); recording only")
        print("1283 MEASURED full payload=\(baseline.count) wire=\(baseline.count + 1)")
    }
    func testCompactionSchemaAndRegistryInvariantControl() throws {
        let api = makeAPI()
        let unprofiled = server(api: api)
        let input = try request()
        let before = try reply(unprofiled, input)
        let registry = WorkspaceScriptingAPI.availableCommands
        let authority = HeadlessAutomationAuthority.availableCommands
        let commandRequest = try request("tools/call", params: .object(["name": .string("commands")]))
        let commandsBefore = try reply(unprofiled, commandRequest)
        let full = try tools(before)
        let core = try tools(reply(server(.core, api: api), input))
        for compact in core {
            let name = try XCTUnwrap(compact["name"]?.stringValue)
            let original = try XCTUnwrap(full.first { $0["name"]?.stringValue == name })
            XCTAssertEqual(compact, try expected(original), name)
            if Self.writes.contains(name) {
                XCTAssertTrue(try XCTUnwrap(compact["description"]?.stringValue).hasSuffix(Self.marker))
                XCTAssertEqual(compact["annotations"]?["readOnlyHint"], .bool(false))
                XCTAssertEqual(compact["annotations"]?["destructiveHint"], .bool(true))
            }
        }
        let search = try XCTUnwrap(core.first { $0["name"] == .string("search") })
        XCTAssertEqual(search["inputSchema"]?["properties"]?["mode"]?["enum"], .array(["text", "regex", "hex"].map(ScriptValue.string)))
        XCTAssertEqual(WorkspaceScriptingAPI.availableCommands, registry)
        XCTAssertEqual(HeadlessAutomationAuthority.availableCommands, authority)
        XCTAssertEqual(try reply(unprofiled, input), before)
        XCTAssertEqual(try reply(server(.full, api: api), input), before)
        XCTAssertEqual(try reply(unprofiled, commandRequest), commandsBefore)
    }
    func testExactAndUnmatchedCompactionBoundaries() throws {
        for literal in Self.descriptions {
            let property: ScriptValue = .object(["type": .string("string"), "description": .string(literal)])
            let nested: ScriptValue = .object(["description": .string(literal), "properties": .object(["child": property])])
            let entry: ScriptValue = .object([
                "name": .string("rename"), "description": .string("Keep prior period." + Self.appendage + Self.marker),
                "inputSchema": .object(["description": .string(literal), "properties": .object([
                    "match": property, "near": .object(["description": .string(literal + " ")]),
                    "nested": .object(["items": nested]), "opaque": .string(literal),
                ]), "required": .array([.string("match")]), "additionalProperties": .bool(false)]),
                "annotations": .object(["readOnlyHint": .bool(false), "destructiveHint": .bool(true)]),
            ])
            let compact = MCPToolsListCompaction.entry(entry, profile: .core)
            XCTAssertEqual(compact, try expected(entry))
            XCTAssertEqual(compact["description"], .string("Keep prior period." + Self.marker))
            XCTAssertEqual(MCPToolsListCompaction.entry(entry, profile: nil), entry)
            XCTAssertEqual(MCPToolsListCompaction.entry(entry, profile: .full), entry)
            for name in ["info", "add-bookmark"] {
                var other = try object(entry)
                other["name"] = .string(name)
                XCTAssertEqual(MCPToolsListCompaction.entry(.object(other), profile: .core)["description"], entry["description"])
            }
            for text in ["Unmatched" + Self.marker, "Keep." + Self.appendage + Self.marker + " ", "Keep." + Self.appendage] {
                var altered = try object(entry)
                altered["description"] = .string(text)
                XCTAssertEqual(MCPToolsListCompaction.entry(.object(altered), profile: .core)["description"], .string(text))
            }
        }
    }
    func testHarnessAndAllowedCommandsMatrix() throws {
        let restricted: Set<String> = ["info", "rename", "bookmarks", "neon-hitrate", "not-a-tool"]
        let restrictions: [Set<String>?] = [nil, restricted]
        for profile in [MCPToolListingProfile.core, .full] {
            for visible in [false, true] {
                for allowed in restrictions {
                    let actual = try names(tools(reply(server(profile, harness: visible, allowed: allowed), request())))
                    let expected = HeadlessAutomationAuthority.availableCommands.filter { command in
                        (allowed?.contains(command.name) ?? true) && (visible || !Self.harness.contains(command.name)) &&
                        (profile == .full || Self.core.contains(command.name) || Self.harness.contains(command.name))
                    }.map(\.name)
                    XCTAssertEqual(actual, expected)
                    XCTAssertEqual(Set(actual).count, actual.count)
                }
            }
        }
    }
    func testListParamsCannotSelectProfileInvariantControl() throws {
        let core = server(.core)
        let baseline = try reply(core, request())
        let objects: [ScriptValue] = [.object([:]), .object(["profile": .string("full")]), .object(["cursor": .string("x")])]
        for params in objects {
            XCTAssertEqual(try reply(core, request(params: params)), baseline)
        }
        let invalid: [ScriptValue] = [.null, .string("full"), .array([]), .bool(true), .int(1)]
        for params in invalid {
            let result = try ScriptValue.decode(reply(core, request(params: params)))
            XCTAssertEqual(result["id"], .int(1))
            XCTAssertEqual(result["error"]?["code"], .int(-32602))
            XCTAssertNil(result["result"])
        }
    }
    func testAuthorityErrorsInvariantControl() throws {
        let core = server(.core)
        let unprofiled = server()
        XCTAssertFalse(Self.core.contains("bookmarks"))
        XCTAssertTrue(HeadlessAutomationAuthority.availableCommands.contains { $0.name == "bookmarks" })
        for name in ["bookmarks", "info", "no-such-tool"] {
            let input = try request("tools/call", params: .object([
                "name": .string(name), "arguments": .object(["unknown1283": .bool(true)]),
            ]))
            let actual = try reply(core, input)
            XCTAssertEqual(actual, try reply(unprofiled, input))
            let decoded = try ScriptValue.decode(actual)
            let message: String
            if name == "no-such-tool" {
                message = "Tool is unavailable through headless automation."
            } else {
                let command = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == name })
                message = ToolArgumentError(field: "unknown1283", detail: "Field 'unknown1283' is not an allowed argument.", allowed: command.arguments.sorted()).refusal.text
            }
            XCTAssertEqual(decoded, .object([
                "jsonrpc": .string("2.0"), "id": .int(1),
                "result": .object(["content": .array([.object(["type": .string("text"), "text": .string(message)])]), "isError": .bool(true)]),
            ]))
        }
    }
    @MainActor private final class Calls {
        var values: [(String, ScriptValue)] = []
    }
    func testValidCallsReachAsyncExecutorInvariantControl() async throws {
        let profiles: [MCPToolListingProfile?] = [nil, .core]
        for profile in profiles {
            let calls = Calls()
            let target = server(profile, executor: { name, arguments in
                calls.values.append((name, arguments))
                return .object(["sentinel1283": .bool(true)])
            })
            let inputs: [(String, ScriptValue)] = [
                ("info", .object([:])), ("rename", .object(["address": .string("0x1000"), "name": .string("renamed")])),
            ]
            for (name, arguments) in inputs {
                let response = await target.handleMessageAsync(try request("tools/call", params: .object(["name": .string(name), "arguments": arguments])))
                let decoded = try ScriptValue.decode(XCTUnwrap(response))
                XCTAssertNil(decoded["error"])
                XCTAssertEqual(decoded["result"]?["isError"], .bool(false))
                XCTAssertEqual(decoded["id"], .int(1))
                let content = try XCTUnwrap(decoded["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(content.utf8)), .object(["sentinel1283": .bool(true)]))
            }
            XCTAssertEqual(calls.values.map { $0.0 }, inputs.map { $0.0 })
            XCTAssertEqual(calls.values.map { $0.1 }, inputs.map { $0.1 })
        }
    }
    func testSyncAsyncListBytesInvariantControl() async throws {
        let profiles: [MCPToolListingProfile?] = [nil, .core, .full]
        for profile in profiles {
            let target = server(profile)
            let input = try request()
            let sync = try reply(target, input)
            let asynchronous = await target.handleMessageAsync(input)
            XCTAssertEqual(try XCTUnwrap(asynchronous), sync)
        }
    }
    func testOutputBoundRefusesInsteadOfShortSuccessInvariantControl() throws {
        let bounded = MCPServer.Configuration(maximumInputBytes: 1_024, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 1_000_000_000, maximumRememberedCancellations: 8)
        let input = Data(#"{"jsonrpc":"2.0","id":"bounded","method":"tools/list"}"#.utf8)
        for profile in [MCPToolListingProfile.core, .full] {
            let bytes = try reply(server(profile, configuration: bounded), input)
            XCTAssertLessThanOrEqual(bytes.count + 1, 512) // Include the transport LF.
            let decoded = try ScriptValue.decode(bytes)
            XCTAssertEqual(decoded["id"], .string("bounded"))
            XCTAssertEqual(decoded["error"]?["code"], .int(-32603))
            XCTAssertNil(decoded["result"])
        }
    }
    func testInitializeInstructionsAndEncodedBudgets() throws {
        for version in [MCPResultProtocol.legacy, .structured] {
            let input = try request("initialize", params: .object(["protocolVersion": .string(version.rawValue)]))
            let base = MCPServer.sessionInstructions + version.instructionSuffix
            let unprofiled = try ScriptValue.decode(reply(server(), input))
            XCTAssertEqual(unprofiled["result"]?["instructions"], .string(base))
            for profile in [MCPToolListingProfile.core, .full] {
                let response = try ScriptValue.decode(reply(server(profile), input))
                XCTAssertNil(response["error"])
                let text = try XCTUnwrap(response["result"]?["instructions"]?.stringValue)
                let supplement = MCPToolsListCompaction.instructionSupplement(for: profile)
                XCTAssertEqual(text, MCPServer.sessionInstructions + supplement + version.instructionSuffix)
                XCTAssertTrue(text.hasPrefix(MCPServer.sessionInstructions))
                XCTAssertTrue(text.hasSuffix(version.instructionSuffix))
                for tool in Self.writes { XCTAssertTrue(supplement.contains(tool)) }
                let profilePhrase = profile == .core ? "MACSCOPE_MCP_LIST_PROFILE=full" : "MACSCOPE_MCP_LIST_PROFILE=core"
                for phrase in [profilePhrase, "reconnect", "Request parameters never select a profile", "commands", "MACSCOPE_MCP_HARNESS_TOOLS=1"] {
                    XCTAssertTrue(supplement.contains(phrase), phrase)
                }
                if profile == .core {
                    let lines = supplement.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
                    for literal in Self.descriptions + [Self.appendage] {
                        XCTAssertTrue(lines.contains(literal), "Canonical text must occupy its own exact line")
                    }
                } else {
                    XCTAssertTrue(supplement.hasPrefix("\ntools/list is using full."))
                    XCTAssertFalse(supplement.contains("MACSCOPE_MCP_LIST_PROFILE=full"))
                }
                let delta = try ScriptValue.string(text).jsonData().count - ScriptValue.string(base).jsonData().count
                XCTAssertLessThanOrEqual(delta, profile == .core ? 2_200 : 800)
                XCTAssertGreaterThan(delta, 0)
                print("1283 MEASURED initialize profile=\(profile) version=\(version.rawValue) encodedDelta=\(delta)")
                record("initialize profile=\(profile) version=\(version.rawValue) encodedDelta=\(delta)")
            }
        }
        XCTAssertEqual(MCPToolsListCompaction.instructionSupplement(for: nil), "")
    }
}
