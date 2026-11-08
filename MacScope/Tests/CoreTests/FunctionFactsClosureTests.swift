import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

// 1272-v1-r1-20261106. FD1/FD2/FD3/FD4 are landing prerequisites (FD4 canonicalizes F4 target-function aliases).
// Helpers are local copies of the supplied fixture/transport idioms, not calls
// to the private helpers of FunctionFactsTests. No real-app acceptance is claimed.
@MainActor
final class FunctionFactsClosureTests: XCTestCase {
    private enum Route: CaseIterable { case inline, mcpSync }
    private let start: UInt64 = 0x1000
    private let owner = UUID(uuidString: "00000000-0000-0000-0000-000000001272")!
    private let permutations = [
        [0, 1, 2, 3], [3, 2, 1, 0], [1, 0, 3, 2],
        [2, 3, 0, 1], [1, 3, 0, 2], [2, 0, 3, 1],
    ]

    private func function(_ name: String, _ begin: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: begin, endAddress: end, confidence: 1)
    }

    private func edge(_ from: UInt64, _ to: UInt64, _ kind: String = "call") -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }

    private func analysis() -> ImageAnalysis {
        var value = ImageAnalysis()
        // A real tie: choosing the first same-start function makes the reply differ.
        value.functions = [function("f", start, 0x1040), function("z", start, 0x1080),
                           function("a", 0x2000, 0x2004), function("b", 0x2004, 0x2008)]
        value.xrefs = [edge(start, start), edge(start, 0x2000),
                       edge(0x1004, 0x3000, "data"), edge(start, 0x2000)]
        value.basicBlocks = [
            BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start, endAddress: 0x1008, instructionCount: 2),
            BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start, endAddress: 0x1008, instructionCount: 1),
            BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: 0x1008, endAddress: 0x1010, instructionCount: 2),
            BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: 0x1008, endAddress: 0x1010, instructionCount: 2),
        ]
        value.controlFlowEdges = [
            ControlFlowEdge(id: UUID(), from: start, to: 0x1008, kind: "branch"),
            ControlFlowEdge(id: UUID(), from: start, to: 0x1008, kind: "switch"),
            ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x2000, kind: "call"),
            ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x1008, kind: "fallthrough"),
        ]
        return value
    }

    private func store(_ analysis: ImageAnalysis) -> WorkspaceStore {
        let image = BinaryImage(id: owner, name: "facts", path: "/fixture", kind: "Mach-O executable", architecture: "arm64")
        return WorkspaceStore(workspaceName: "facts", snapshot: WorkspaceSnapshot(binaries: [image],
            analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func bytes(_ route: Route, _ store: WorkspaceStore,
                       arguments: ScriptValue? = nil) throws -> Data {
        let args = arguments ?? .object(["address": .hex(start)])
        let api = WorkspaceScriptingAPI(store: store)
        switch route {
        case .inline:
            return try api.execute("function-facts", arguments: args).jsonData()
        case .mcpSync:
            let server = MCPServer(api: api)
            let request = ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
                "method": .string("tools/call"), "params": .object([
                    "name": .string("function-facts"), "arguments": args])])
            let frame = try ScriptValue.decode(try XCTUnwrap(server.handleMessage(request.jsonData())))
            XCTAssertNil(frame["error"])
            XCTAssertEqual(frame["result"]?["isError"], .bool(false))
            let text = try XCTUnwrap(frame["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            return Data(text.utf8) // Compare the actual wire text, not a re-encoded copy.
        }
    }

    func testSixFixedPermutationsIncludingTiesOnInlineAndMCP() throws {
        let original = analysis() // Row UUIDs and image identity stay the same in all six worlds.
        XCTAssertEqual(Set(permutations.map { $0.map(String.init).joined() }).count, 6)
        for order in permutations { XCTAssertEqual(order.sorted(), [0, 1, 2, 3]) }
        var baseline: Data?
        for order in permutations {
            var changed = original
            changed.xrefs = order.map { original.xrefs[$0] }
            changed.basicBlocks = order.map { original.basicBlocks[$0] }
            changed.controlFlowEdges = order.map { original.controlFlowEdges[$0] }
            changed.functions = order.map { original.functions[$0] }
            let world = store(changed)
            for route in Route.allCases {
                let actual = try bytes(route, world)
                if let expected = baseline { XCTAssertEqual(actual, expected, "order \(order), route \(route)") }
                else { baseline = actual }
                let sheet = try ScriptValue.decode(actual)
                XCTAssertEqual(sheet["name"], .string("f"))
                XCTAssertEqual(sheet["end"], .hex(0x1040))
                XCTAssertEqual(sheet["calls"]?["total"], .int(2))
                XCTAssertEqual(sheet["calls"]?["rows"]?.arrayValue?.compactMap { $0["to"]?.addressValue }, [0x1000, 0x2000])
                // Self-call target alias: f and z share the start; the canonical alias must not follow list order.
                let rows = try XCTUnwrap(sheet["calls"]?["rows"]?.arrayValue)
                XCTAssertEqual(rows.first?["toName"]?.stringValue.map { Data($0.utf8) }, Data("f".utf8), "order \(order), route \(route)")
                XCTAssertEqual(sheet["size"]?["blocks"]?.arrayValue?.compactMap { $0["instructionCount"]?.intValue }, [1, 2, 2, 2])
                XCTAssertEqual(sheet["branches"]?["branchCount"], .int(2))
            }
        }
    }

    private func isHex(_ value: ScriptValue?) -> Bool {
        guard let text = value?.stringValue, text.hasPrefix("0x"),
              (1...16).contains(text.dropFirst(2).count) else { return false }
        return text.dropFirst(2).utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) } && UInt64(text.dropFirst(2), radix: 16) != nil
    }

    private func addressProblems(_ value: ScriptValue, path: String = "$", root: Bool = true) -> [String] {
        var problems: [String] = []
        switch value {
        case .object(let fields):
            // A category is a direct object of the sheet or a nested disclosure.
            if !root && (fields["status"] != nil || fields["blockStatus"] != nil || fields["rows"] != nil || fields["blocks"] != nil) {
                if !isHex(fields["address"]) { problems.append(path + ".address") }
            }
            for (key, child) in fields {
                let next = path + "." + key
                if root, case .object = child, !isHex(child["address"]) { problems.append(next + ".address") }
                if key == "rows" || key == "blocks" {
                    if let rows = child.arrayValue {
                        for (index, row) in rows.enumerated() {
                            let keys = key == "rows" ? ["from", "to"] : ["start", "end"]
                            for addressKey in keys where !isHex(row[addressKey]) {
                                problems.append(next + "[\(index)]." + addressKey)
                            }
                        }
                    } else { problems.append(next + ": not an array") }
                }
                problems += addressProblems(child, path: next, root: false)
            }
        case .array(let values):
            for (index, child) in values.enumerated() { problems += addressProblems(child, path: path + "[\(index)]", root: false) }
        default: break
        }
        return problems
    }

    func testEveryRowAndCategoryHasHexAddresses() throws {
        for route in Route.allCases {
            let sheet = try ScriptValue.decode(bytes(route, store(analysis())))
            for key in ["calls", "references", "constants", "branches", "size", "backend", "stringLiteralCoverage"] {
                guard case .object? = sheet[key] else { XCTFail("missing category \(key)"); continue }
            }
            XCTAssertEqual(sheet["calls"]?["rows"]?.arrayValue?.count, 2)
            XCTAssertEqual(sheet["references"]?["rows"]?.arrayValue?.count, 1)
            XCTAssertEqual(sheet["size"]?["blocks"]?.arrayValue?.count, 4)
            XCTAssertEqual(addressProblems(sheet), []) // Includes stringLiteralCoverage; requires FD1.
        }
        // Negative controls exercise nested traversal without executing a mutation.
        let nested: ScriptValue = .object(["extra": .object(["address": .hex(start),
            "nested": .object(["address": .hex(start), "rows": .array([.object(["from": .hex(start)])]),
                               "blocks": .array([.object(["start": .hex(start), "end": .string("0x+1")])])])])])
        XCTAssertTrue(addressProblems(nested).contains("$.extra.nested.rows[0].to"))
        XCTAssertTrue(addressProblems(nested).contains("$.extra.nested.blocks[0].end"))
    }

    private let nameFields: Set<String> = ["name", "toName", "selector", "toDemangled", "cString", "value", "imageOwner", "kind"]
    // Closed literal vocabulary, INCLUDING the finite hex values of these fixtures.
    // No exemption for arbitrary hex strings, unknown keys, arrays or nested objects.
    private let vocabulary: Set<String> = [
        "partial", "unavailable", "complete", "incomplete",
        "storedDirectCallXRefs", "storedNonCallXRefs", "storedRowsOnly", "noStoredXRefs",
        "noStoredTargetValue", "dataAndStringTargetsInReferences;numericImmediatesNotIncluded",
        "storedEdgesOnly;conditionalityNotStored", "wholeStoredBlocksByStart", "noStoredFunctionBackend",
        "noStoredStringCoverage", "storedCoverage", "stringCountLimitReached",
        "notAttempted", "unterminatedField", "malformedSection",
        "storedRange", "exactStartOnly", "exact", "containing",
        "cString", "cfString", "selector", "class", "import", "symbol", "data",
        "0x1000", "0x1004", "0x1008", "0x1010", "0x1040", "0x40", "0x0",
        "0x2000", "0x2004", "0x3000",
    ]

    private func vocabularyProblems(_ value: ScriptValue, key: String = "", path: String = "$") -> [String] {
        switch value {
        case .string(let text):
            return nameFields.contains(key) || vocabulary.contains(text) ? [] : [path + "=" + text]
        case .array(let values):
            // A name-field exemption applies only to a direct string, not a container.
            return values.enumerated().flatMap { vocabularyProblems($0.element, path: path + "[\($0.offset)]") }
        case .object(let fields):
            return fields.flatMap { vocabularyProblems($0.value, key: $0.key, path: path + "." + $0.key) }
        default: return []
        }
    }

    func testClosedVocabularyAcrossPresentAbsentAndIncompleteCategories() throws {
        let ordinary = analysis()
        var empty = ordinary
        empty.xrefs = []; empty.basicBlocks = []; empty.controlFlowEdges = []
        var complete = ordinary
        complete.stringLiteralCoverage = .complete
        var incomplete = ordinary
        incomplete.stringLiteralCoverage = .incomplete(.stringCountLimitReached)
        var unavailableValue = ordinary
        unavailableValue.xrefs = [edge(start, 0x3000, "selref")]
        var unknownExtent = ordinary
        unknownExtent.functions = [function("zero", start, start)]
        unknownExtent.xrefs = []; unknownExtent.basicBlocks = []; unknownExtent.controlFlowEdges = []
        for value in [ordinary, empty, complete, incomplete, unavailableValue, unknownExtent] {
            for route in Route.allCases {
                let sheet = try ScriptValue.decode(bytes(route, store(value)))
                XCTAssertNotNil(sheet["name"]?.stringValue)
                XCTAssertNotNil(sheet["constants"]?["reason"]?.stringValue)
                XCTAssertNotNil(sheet["stringLiteralCoverage"]?["status"]?.stringValue)
                XCTAssertEqual(vocabularyProblems(sheet), [])
            }
        }
        for route in Route.allCases {
            let interior = try ScriptValue.decode(bytes(route, store(ordinary), arguments: .object(["address": .hex(0x1004)])))
            XCTAssertEqual(vocabularyProblems(interior), [])
        }
        XCTAssertFalse(vocabularyProblems(.object(["explanation": .string("a novel sentence")])).isEmpty)
        XCTAssertFalse(vocabularyProblems(.object(["name": .array([.string("a novel sentence")])])).isEmpty)
        XCTAssertFalse(vocabularyProblems(.object(["extra": .string("0xdeadbeef")])).isEmpty)
        XCTAssertEqual(vocabularyProblems(.object(["name": .string("stored free text")])), [])
    }

    func testFourteenCallSitesRetainFirstEightAndOmitNamedNinth() throws {
        var value = ImageAnalysis()
        value.functions = [function("f", start, 0x1040)]
        value.symbols = [SymbolSummary(id: UUID(), name: "late", address: 0x2000, kind: "import", libraryName: nil)]
        value.xrefs = (0..<14).reversed().map { index in
            edge(start + UInt64(index * 4), index == 8 ? 0x2000 : 0x3000)
        }
        for route in Route.allCases {
            let data = try bytes(route, store(value))
            let sheet = try ScriptValue.decode(data)
            let rows = try XCTUnwrap(sheet["calls"]?["rows"]?.arrayValue)
            XCTAssertEqual(rows.count, 8)
            XCTAssertEqual(rows.compactMap { $0["from"]?.addressValue }, (0..<8).map { start + UInt64($0 * 4) })
            XCTAssertEqual(sheet["calls"]?["total"], .int(14))
            XCTAssertEqual(sheet["calls"]?["omitted"], .int(6))
            XCTAssertEqual(sheet["calls"]?["truncated"], .bool(true))
            XCTAssertFalse(rows.contains { $0["toName"] == .string("late") })
            XCTAssertFalse(rows.contains { $0["from"] == .hex(0x1020) })
            XCTAssertEqual(sheet["references"]?["rows"]?.arrayValue?.count, 0)
            XCTAssertEqual(sheet["size"]?["blocks"]?.arrayValue?.count, 0)
            XCTAssertLessThanOrEqual(data.count, 3_000)
        }
    }

    func testUnicodeAliasTiesUseUTF8OrderForRootAndSelfCall() throws {
        let composed = "\u{00e9}", decomposed = "e\u{0301}"
        let functions = [function(composed, start, 0x1040), function(decomposed, start, 0x1040)]
        let refs = [edge(start, start)]
        var baseline: Data?
        for order in [[0, 1], [1, 0]] {
            var value = ImageAnalysis()
            value.functions = order.map { functions[$0] }
            value.xrefs = refs
            for route in Route.allCases {
                let data = try bytes(route, store(value))
                if let expected = baseline { XCTAssertEqual(data, expected) }
                else { baseline = data }
                let sheet = try ScriptValue.decode(data)
                let name = try XCTUnwrap(sheet["name"]?.stringValue)
                let target = try XCTUnwrap(sheet["calls"]?["rows"]?.arrayValue?.first?["toName"]?.stringValue)
                // String equality alone would hide canonically equivalent encodings.
                XCTAssertEqual(Data(name.utf8), Data(decomposed.utf8))
                XCTAssertEqual(Data(target.utf8), Data(decomposed.utf8))
            }
        }
    }
}
