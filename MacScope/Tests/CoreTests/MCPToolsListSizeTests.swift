import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// ITEM 1254, a2b52e69c. RECORDING witness, not P2 acceptance.
/// PROPOSAL (not decided): measure the full handleMessage response, including id:1,
/// without the transport LF, and separately reserialize result with ScriptValue.
/// Record BOTH 45,000 bytes and 46,080 bytes side by side. Neither is selected or gated.
/// Unit choice and any future headroom/description changes belong to the owner at M5.
/// This one-function fixture exposes the live full registry, not a loaded-app witness.
@MainActor
final class MCPToolsListSizeTests: XCTestCase {
    // D2 is deliberately literal, independent of the live D1 registry. Pin sources:
    // MCPServer.swift:697-720; MCPServer+Navigator.swift:116-129,136-182.
    private static let allowedNamesAtPin: Set<String> = [
        "call-graph", "call-path", "unwind-audit", "swift-error-flow",
        "add-bookmark", "add-bookmarks", "add-xref", "add-xrefs", "annotation-gaps", "basic-blocks", "bookmarks", "bundle-info", "callees", "callers",
        "call-argument-audit", "clear-local-label", "clear-patch", "clear-register-name",
        "clear-segment-override", "clear-segment-overrides", "commands", "containing-function", "decompile", "demangle", "define-type",
        "define-types-from-c", "exports", "functions", "function-references", "endpoint-references", "function-facts", "implementations", "goto", "imports", "info",
        "instructions", "list-image-types", "list-types", "local-labels", "make-alignment", "make-array",
        "make-arrays", "make-alignments", "make-data", "make-procedure", "make-string", "make-strings", "make-undefined", "manual-xrefs",
        "name-at", "neon-hitrate", "open-workspace", "parameter-binding-audit", "patch-bytes", "read-bytes", "read-evidence",
        "rebase-segment", "rebase-segments", "reconstruction-jobs", "register-names", "relocations", "remove-bookmark", "remove-bookmarks", "rename", "rename-register", "rename-registers", "clear-register-names", "set-stack-locals",
        "rename-segment", "rename-segments", "resolve-symbol", "save-workspace", "search", "sections", "segment-overrides",
        "set-color", "set-colors", "set-comment", "set-local-label", "set-operand-format", "set-signature", "set-signatures",
        "set-data", "set-procedures", "set-tag", "set-tags", "set-type", "set-undefined", "slices", "strings", "suppress-xref", "suppress-xrefs", "symbols", "xrefs",
        "set-stack-local", "stack-locals", "recover-struct-candidate", "accept-struct-candidate",
        "indirect-call-targets", "verified-checkpoint", "verified-commit", "verified-checkpoint-isolated", "verified-call-path", "open-claim", "record-callee-outcome", "claim-status",
        "set-names", "set-comments", "set-local-labels", "set-operand-formats", "set-types", "undo-last",
    ]
    private static let navigatorNamesAtPin: Set<String> = [
        "navigator-facts", "navigator-frontier", "navigator-dependents", "navigator-primitives",
        "navigator-preview-revert", "navigator-revert", "navigator-accept",
        "navigator-toolchain", "navigator-resolve-provenance",
    ]
    private static let harnessNamesAtPin: Set<String> = ["neon-hitrate", "reconstruction-jobs"]

    private func makeServer(listHarnessTools: Bool = false) -> MCPServer {
        // Copied fixture shape: MCPServerTests.swift:1005-1018.
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000, kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [],
            hexBytes: Data()
        )
        let store = WorkspaceStore(workspaceName: "MCP", snapshot: snapshot, engine: AnalysisEngine())
        return MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .production,
                         listHarnessTools: listHarnessTools)
    }

    private func listRequest() throws -> Data {
        try ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list"),
        ]).jsonData()
    }

    private func decodeTools(_ data: Data) throws -> (result: ScriptValue, tools: [ScriptValue]) {
        let response = try ScriptValue.decode(data)
        XCTAssertEqual(response["jsonrpc"], .string("2.0"))
        XCTAssertEqual(response["id"], .int(1))
        XCTAssertNil(response["error"])
        let result = try XCTUnwrap(response["result"])
        return (result, try XCTUnwrap(result["tools"]?.arrayValue))
    }

    private func toolNames(_ tools: [ScriptValue]) throws -> [String] {
        try tools.map { try XCTUnwrap($0["name"]?.stringValue) }
    }

    private func report(_ lines: [String], name: String) {
        let text = lines.joined(separator: "\n") + "\n"
        print(text, terminator: "")
        let attachment = XCTAttachment(string: text)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    // T1: correctness, not a size target. No registry-derived expectation is used for D2.
    func testT1FullHiddenRegistryNames() throws {
        var lines: [String] = []
        defer { report(lines, name: "TOOLSLIST-NAMES") }
        let data = try XCTUnwrap(makeServer().handleMessage(try listRequest()))
        let responseNames = try toolNames(decodeTools(data).tools)
        let d1Names = HeadlessAutomationAuthority.availableCommands
            .filter { !HeadlessAutomationAuthority.harnessCommands.contains($0.name) }.map(\.name)
        let d1 = Set(d1Names)
        let d2 = Self.allowedNamesAtPin.union(Self.navigatorNamesAtPin).subtracting(Self.harnessNamesAtPin)
        let responseSet = Set(responseNames)
        for name in d1.subtracting(d2).sorted() {
            lines.append("TOOLSLIST-NAMEDIFF side=D1only name=\(name)")
        }
        for name in d2.subtracting(d1).sorted() {
            lines.append("TOOLSLIST-NAMEDIFF side=D2only name=\(name)")
        }
        for name in responseSet.subtracting(d1).sorted() {
            lines.append("TOOLSLIST-NAMEDIFF side=responseonly name=\(name)")
        }
        for name in d1.subtracting(responseSet).sorted() {
            lines.append("TOOLSLIST-NAMEDIFF side=D1only name=\(name) context=missing-from-response")
        }
        for (origin, names) in [("D1", d1Names), ("response", responseNames)] {
            let counts = Dictionary(grouping: names, by: { $0 }).mapValues(\.count)
            for name in counts.keys.sorted() where counts[name, default: 0] > 1 {
                lines.append("TOOLSLIST-NAMEDIFF side=duplicate name=\(name) origin=\(origin) count=\(counts[name, default: 0])")
            }
        }
        for name in Set(WorkspaceScriptingAPI.availableCommands.map(\.name)).subtracting(d2).sorted() {
            lines.append("TOOLSLIST-REGISTERED-NOT-LISTED name=\(name)")
        }
        lines.append("TOOLSLIST-NAMES response=\(responseNames.count) D1=\(d1Names.count) D2=\(d2.count)")
        XCTAssertEqual(d1, d2)
        XCTAssertEqual(d1Names.count, d1.count, "D1 must contain each registered name once")
        XCTAssertEqual(responseNames.sorted(), d1.sorted(), "Missing, duplicate or extra response name")
        let required: Set<String> = [
            "set-names", "set-comments", "set-local-labels", "set-operand-formats", "set-types",
            "open-workspace", "save-workspace", "open-claim", "record-callee-outcome", "claim-status",
            "undo-last", "list-image-types", "navigator-facts", "navigator-frontier",
            "navigator-dependents", "navigator-primitives", "navigator-preview-revert", "navigator-revert",
            "navigator-accept", "navigator-toolchain", "navigator-resolve-provenance",
        ]
        for name in required.sorted() { XCTAssertTrue(responseSet.contains(name), "Missing \(name)") }
    }

    // T2: only records sizes. Component shares use the full wire count as denominator;
    // ScriptValue components are approximate contributions to the different canonical encoder.
    func testT2RecordEncodedToolsList() throws {
        var lines: [String] = []
        defer { report(lines, name: "TOOLSLIST-SIZE-AND-BREAKDOWN") }
        let data = try XCTUnwrap(makeServer().handleMessage(try listRequest()))
        let decoded = try decodeTools(data)
        let resultBytes = try decoded.result.jsonData().count
        lines.append("TOOLSLIST-SIZE total=\(data.count) result=\(resultBytes) tools=\(decoded.tools.count) over45000=\(data.count - 45_000) over46080=\(data.count - 46_080)")
        var unsorted: [(name: String, bytes: Int)] = []
        for tool in decoded.tools {
            let toolName: String = try XCTUnwrap(tool["name"]?.stringValue)
            let toolBytes: Int = try tool.jsonData().count
            unsorted.append((name: toolName, bytes: toolBytes))
        }
        let entries = unsorted.sorted { (a: (name: String, bytes: Int), b: (name: String, bytes: Int)) -> Bool in
            if a.bytes == b.bytes { return a.name < b.name }
            return a.bytes > b.bytes
        }
        for (index, entry) in entries.prefix(10).enumerated() {
            lines.append("TOOLSLIST-TOP10 rank=\(index + 1) name=\(entry.name) bytes=\(entry.bytes)")
        }
        lines.append("TOOLSLIST-ENTRY-SUM bytes=\(entries.reduce(0) { $0 + $1.bytes }) encoding=ScriptValue approximation=true")
        // Source-derived at run time: WorkspaceScriptingAPI.swift:171-185.
        let probe = ScriptingCommandInfo(name: "size-witness", summary: "", mutates: true, arguments: [])
        let suffix = probe.withEvidencePrecondition.summary
        let suffixTools = suffix.isEmpty ? 0 : decoded.tools.filter {
            $0["description"]?.stringValue?.hasSuffix(suffix + " (mutates the workspace)") == true
        }.count
        let suffixBytes = suffixTools * suffix.utf8.count
        let denominator = Double(max(1, data.count))
        lines.append("TOOLSLIST-PRECONDITION-SUFFIX tools=\(suffixTools) bytes=\(suffixBytes) share=\(Double(suffixBytes) / denominator) byteBasis=UTF8 approximation=true")
        let generationSchemas = decoded.tools.compactMap { $0["inputSchema"]?["properties"]?["basedOnGeneration"] }
        let generationBytes = try generationSchemas.reduce(0) { try $0 + $1.jsonData().count }
        lines.append("TOOLSLIST-BASEDONGEN-SCHEMA tools=\(generationSchemas.count) bytes=\(generationBytes) share=\(Double(generationBytes) / denominator) excludesPropertyKey=true approximation=true")
    }

    // T3: equality of the actual returned encoded bytes, with the same request id.
    func testT3AsyncEqualsSyncBytes() async throws {
        let server = makeServer()
        let request = try listRequest()
        let sync = try XCTUnwrap(server.handleMessage(request))
        let asynchronous = await server.handleMessageAsync(request)
        let asyncBytes = try XCTUnwrap(asynchronous)
        XCTAssertEqual(asyncBytes, sync)
    }

    // T4/T5: flag controls for the recording boundary. Relative growth is a flag
    // correctness control required by SPEC 4, never an absolute size/headroom gate.
    // P2F3 owns unchanged remaining rows, ordering and annotations; do not copy it.
    func testT4T5HarnessFlagRecordingControls() throws {
        let request = try listRequest()
        let hidden = try XCTUnwrap(makeServer(listHarnessTools: false).handleMessage(request))
        let visible = try XCTUnwrap(makeServer(listHarnessTools: true).handleMessage(request))
        let hiddenNames = Set(try toolNames(decodeTools(hidden).tools))
        let visibleNames = Set(try toolNames(decodeTools(visible).tools))
        XCTAssertTrue(Self.harnessNamesAtPin.isDisjoint(with: hiddenNames))
        XCTAssertTrue(Self.harnessNamesAtPin.isSubset(of: visibleNames))
        XCTAssertEqual(visibleNames.subtracting(hiddenNames), Self.harnessNamesAtPin)
        XCTAssertTrue(hiddenNames.isSubset(of: visibleNames))
        XCTAssertGreaterThan(visible.count, hidden.count, "Harness flag must add its encoded entries")
        report(["TOOLSLIST-HARNESS hidden=\(hidden.count) visible=\(visible.count) growth=\(visible.count - hidden.count)"],
               name: "TOOLSLIST-HARNESS")
    }

    // T6: stored JSON re-anchored to main 8d0a269e1 (includes the 1251 format argument), not the live
    // schema builder. Owner updates this expectation when the entry changes; size is still recorded only.
    // Summary: WorkspaceScriptingAPI.swift:5087-5088, copied exactly as JSON text.
    // Schemas: MCPServer.swift:690,738-775,814,894-895,932-954,1055-1063,2243-2247.
    // Kind values: ImageTypeCatalog.swift:17-29 (including importedType).
    // Image key: sole supplement, WorkspaceScriptingAPI+ImageSelector.swift:18.
    private static let listImageTypesAtMainJSON = #"""
    {
      "name": "list-image-types",
      "description": "RX-02a Type Atlas (read-only): the types of one image — Objective-C classes, categories and protocols (name only), Swift classes/structs/enums, and the workspace user types — with members (offset + evidence: descriptor|staticEvaluation|authored|unknown; an unknown layout has a null offset), conformances, methods (selector, IMP, selref users) and users (classref xref sources, or addresses a user type is applied to). Reads the primary image by default; `image` (a slot index or an image-owner ID) selects another loaded image. Optional `kind` filters (swiftClass|swiftStruct|swiftEnum|objcClass|objcCategory|objcProtocol|userType); optional `limit` caps the rows. The default reply (including an explicit `limit` and `page: false`) is a bounded prefix of full rows with a byte allowance C = 166,000: `total` is the whole-filter total and `types.count` the admitted prefix; unnamed positional Swift vtable slots may be replaced by `unnamedVtableSlots` {count, first, last} with `vtableSummaryVersion: 1`; when rows are omitted the reply carries `isTruncated: true` and `nextCursor`, which is continued as `cursor` with `page: true`, `fields: \"full\"`, `limit: 1` and the original image/kind. The complete frame is guaranteed within 180,000 bytes only for an encoded JSON request-id length I <= 13,000, since C + I + 1,000 <= 180,000; larger IDs are not clipped and have no such guarantee. Small replies keep their original shape. For Swift rows, `hasUnassignedSwiftConformanceRecords` reports whether recovered records in the image lack a unique local owner; false does not certify extraction completeness. The result carries `imageSlot`, `imageOwner`, `total` and `types`. `page: true` returns {rows, total, isTruncated, nextCursor, sourceComplete, imageSlot, imageOwner}; `cursor` continues from `nextCursor`, `name` / `nameContains` filter by name, and `fields: \"names\"` returns names-only rows. A non-null `name`, `nameContains` or `fields` without `page` also returns a page.",
      "inputSchema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "image": {
            "anyOf": [{"type":"integer","minimum":0,"maximum":2147483647},{"type":"string"}],
            "description": "Image to read: a slot index (0 is the primary image) or an image-owner ID (UUID). Omit for the primary image."
          },
          "kind": {"type":"string","enum":["swiftClass","swiftStruct","swiftEnum","objcClass","objcCategory","objcProtocol","userType","importedType"]},
          "limit": {"type":"integer","minimum":0,"maximum":10000},
          "page": {"type":"boolean","description":"Opt in to a bounded Type Atlas page with filters and continuation; name, nameContains or fields without page also page."},
          "cursor": {"type":"string","maxLength":1024,"description":"Continue from nextCursor; restart if stale. A nextCursor from a default reply needs page:true, fields:\"full\", limit:1 and the original image/kind; page cursors keep their own filters and fields."},
          "name": {"type":"string","minLength":1,"maxLength":1024},
          "nameContains": {"type":"string","minLength":1,"maxLength":1024},
          "fields": {"type":"string","enum":["full","names"]},
          "format": {"type":["string","null"],"enum":["declarations-v1",null]}
        }
      },
      "annotations": {"readOnlyHint":true,"destructiveHint":false}
    }
    """#

    func testT6ListImageTypesStoredEntry() throws {
        let data = try XCTUnwrap(makeServer().handleMessage(try listRequest()))
        let matches = try decodeTools(data).tools.filter { $0["name"]?.stringValue == "list-image-types" }
        XCTAssertEqual(matches.count, 1)
        let actualEntry = try XCTUnwrap(matches.first)
        let expected = try ScriptValue.decode(Data(Self.listImageTypesAtMainJSON.utf8))
        let actual = try ScriptValue.decode(actualEntry.jsonData())
        XCTAssertEqual(try actual.jsonData(), try expected.jsonData(),
                       "Pin entry changed. The owner must update this expectation when 1251 lands.")
    }

    // T7 is optional and omitted. No .attached configuration is used.
}
