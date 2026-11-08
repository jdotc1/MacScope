import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// `function` accepts a strict 0x-hex address when no function has that name.
@MainActor
final class FunctionHexSelectorTests: XCTestCase {
    private let start: UInt64 = 0x1000065d0

    private func function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func makeAPI(extra: [FunctionSummary] = []) -> WorkspaceScriptingAPI {
        var analysis = ImageAnalysis()
        analysis.functions = [function("fixture", start, start + 0x40)] + extra
        let image = BinaryImage(id: UUID(), name: "hex", path: "/fixture", kind: "Mach-O executable", architecture: "arm64")
        let store = WorkspaceStore(workspaceName: "hex", snapshot: WorkspaceSnapshot(binaries: [image],
            analysisBySlot: [.primary: analysis]), engine: AnalysisEngine(), autosaveScheduler: nil)
        return WorkspaceScriptingAPI(store: store)
    }

    private func facts(_ api: WorkspaceScriptingAPI, function: String) throws -> ScriptValue {
        try api.execute("function-facts", arguments: .object(["function": .string(function)]))
    }

    private func facts(_ api: WorkspaceScriptingAPI, address: String) throws -> ScriptValue {
        try api.execute("function-facts", arguments: .object(["address": .string(address)]))
    }

    func testHexFunctionEqualsAddressByteForByte() throws {
        let api = makeAPI()
        let byName = try facts(api, function: "0x1000065d0")
        let byAddress = try facts(api, address: "0x1000065d0")
        XCTAssertEqual(try byName.jsonData(), try byAddress.jsonData())
    }

    func testInteriorHexAddressResolvesContainingFunction() throws {
        let api = makeAPI()
        let byName = try facts(api, function: "0x1000065f4")
        let byAddress = try facts(api, address: "0x1000065f4")
        XCTAssertEqual(try byName.jsonData(), try byAddress.jsonData())
    }

    func testFunctionNamedLikeHexWinsOverAddress() throws {
        let api = makeAPI(extra: [function("0x2000", 0x5000, 0x5040), function("covers2000", 0x2000, 0x2040)])
        let byName = try facts(api, function: "0x2000")
        let covering = try facts(api, address: "0x2000")
        XCTAssertEqual(byName["resolvedFunction"], .string("0x5000"))
        XCTAssertNil(byName["requestedAddress"])
        XCTAssertEqual(byName["resolution"], .string("exact"))
        XCTAssertEqual(covering["resolvedFunction"], .string("0x2000"))
        XCTAssertNotEqual(try byName.jsonData(), try covering.jsonData())
    }

    func testMalformedHexStaysNoFunctionNamed() {
        let api = makeAPI()
        for text in ["0x+1", "0X", "0x", "0x" + String(repeating: "1", count: 17), " 0x10", "0x10 ", "0X10", "0x-1"] {
            XCTAssertThrowsError(try facts(api, function: text), text) {
                XCTAssertEqual($0 as? ScriptingError, .invalidArgument("no function named '\(text)'"), text)
            }
        }
    }

    func testUncoveredHexAddressGivesSameRefusalAsAddress() throws {
        let api = makeAPI()
        var viaAddress: ScriptValue?
        XCTAssertThrowsError(try facts(api, address: "0x9000")) { viaAddress = MCPToolRefusal.executionRefusal($0)?.value }
        var viaName: ScriptValue?
        XCTAssertThrowsError(try facts(api, function: "0x9000")) { viaName = MCPToolRefusal.executionRefusal($0)?.value }
        XCTAssertNotNil(viaAddress)
        XCTAssertEqual(viaName, viaAddress)
    }

    func testSchemaDescriptionPin() throws {
        let api = makeAPI()
        let server = MCPServer(api: api)
        let input = try ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")]).jsonData()
        let reply = try ScriptValue.decode(try XCTUnwrap(server.handleMessage(input)))
        let tools = try XCTUnwrap(reply["result"]?["tools"]?.arrayValue)
        let tool = try XCTUnwrap(tools.first { $0["name"]?.stringValue == "function-facts" })
        XCTAssertEqual(tool["inputSchema"]?["properties"]?["function"]?["description"],
                       .string("Raw or display name, or a 0x-hex address used when no name matches; at most 256 UTF-8 bytes."))
    }
}
