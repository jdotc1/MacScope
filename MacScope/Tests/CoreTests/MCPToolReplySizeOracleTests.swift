import Foundation
import XCTest
@testable import MacScope

// Authored, unrun. All tests in this suite are invariant/controls, not red claims.
final class MCPToolReplySizeOracleTests: XCTestCase {
    func testInvariantAdapterShapesEscapingAndNilID() throws {
        for output in [ScriptValue.null, .int(7), .array([.string("é\n\\\"")]),
                       .object(["text": .string("\u{0001}/雪")])] {
            for version in [MCPResultProtocol.legacy, .structured] {
                let frame = try mcpToolReplyOracleFrame(output: output, tool: "list-image-types",
                    generation: nil, protocolVersion: version, id: nil)
                XCTAssertEqual(frame["id"], .null)
                let expected = MCPStructuredResult.successEnvelope(protocolVersion: version,
                    tool: "list-image-types", output: output,
                    legacyText: String(data: try output.jsonData(), encoding: .utf8)!, isError: false)
                XCTAssertEqual(frame["result"], expected)
                XCTAssertEqual(try mcpToolReplyJSONByteCount(output: output, tool: "list-image-types",
                    generation: nil, protocolVersion: version, id: nil), try frame.jsonData().count)
            }
        }
    }

    func testInvariantNullGenerationIsAbsentAndRealBridgeMatchesFrozenFragment() throws {
        let capture = ScriptingGenerationCapture()
        capture.record(UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!)
        let frozen = try syntheticTypeAtlasGeneration()
        XCTAssertEqual(frozen["metadata"], capture.metadata)
        XCTAssertEqual(frozen["contentSuffix"], .array(capture.appendingGeneration(to: [])))
        for output in [ScriptValue.object(["value": .int(7)]), .array([.int(7)]), .null] {
            for version in [MCPResultProtocol.legacy, .structured] {
                let nilFrame = try mcpToolReplyOracleFrame(output: output, tool: "list-image-types",
                    generation: nil, protocolVersion: version, id: .int(5))
                XCTAssertEqual(try mcpToolReplyOracleFrame(output: output, tool: "list-image-types",
                    generation: .null, protocolVersion: version, id: .int(5)), nilFrame)
                let frame = try mcpToolReplyOracleFrame(output: output, tool: "list-image-types",
                    generation: frozen, protocolVersion: version, id: .int(5))
                let real = MCPStructuredResult.successEnvelope(protocolVersion: version,
                    tool: "list-image-types", output: output,
                    legacyText: String(data: try output.jsonData(), encoding: .utf8)!,
                    isError: false, generation: capture)
                XCTAssertEqual(frame["result"], real)
            }
        }
    }

    func testInvariantFrozenGenerationPreservesWrapperMarker() throws {
        let fragment = ScriptValue.object([
            "metadata": .object([MCPStructuredResult.wrapperMarker: .string("wrong")]),
            "contentSuffix": .array([.object(["type": .string("text"), "text": .string("frozen")])])])
        let frame = try mcpToolReplyOracleFrame(output: .array([]), tool: "list-image-types",
            generation: fragment, protocolVersion: .structured, id: .int(5))
        XCTAssertEqual(frame["result"]?["_meta"]?[MCPStructuredResult.wrapperMarker], .string("result"))
        XCTAssertEqual(frame["result"]?["content"]?.arrayValue?.count, 2)
        XCTAssertEqual(frame["result"]?["structuredContent"], .object(["result": .array([])]))
    }

    func testInvariantMalformedFragmentsAndNonJSONValuesThrow() throws {
        for fragment in [ScriptValue.object([:]),
                         .object(["metadata": .array([]), "contentSuffix": .array([])]),
                         .object(["metadata": .object([:]), "contentSuffix": .array([.null])])] {
            XCTAssertThrowsError(try mcpToolReplyJSONByteCount(output: .null, tool: "list-image-types",
                generation: fragment, protocolVersion: .legacy, id: nil))
        }
        XCTAssertThrowsError(try mcpToolReplyJSONByteCount(output: .double(.infinity), tool: "list-image-types",
            generation: nil, protocolVersion: .legacy, id: nil))
    }

    func testInvariantEncodedIDBoundaryOracleOnly() throws {
        // Oracle-only: MCPServer validResponseID and scheduler key reject this string.
        // No server admission or guarantee outside I <= 13,000 is claimed.
        let inside = ScriptValue.string(String(repeating: "x", count: 12_998))
        let outside = ScriptValue.string(String(repeating: "x", count: 12_999))
        XCTAssertEqual(try inside.jsonData().count, 13_000)
        XCTAssertEqual(try outside.jsonData().count, 13_001)
        XCTAssertEqual(166_000 + 13_000 + 1_000, 180_000)
        XCTAssertGreaterThan(166_000 + 13_001 + 1_000, 180_000)
        for version in [MCPResultProtocol.legacy, .structured] {
            let base = try mcpToolReplyJSONByteCount(output: .object([:]), tool: "list-image-types",
                generation: nil, protocolVersion: version, id: .int(0))
            let boundary = try mcpToolReplyJSONByteCount(output: .object([:]), tool: "list-image-types",
                generation: nil, protocolVersion: version, id: inside)
            XCTAssertEqual(boundary - base, 12_999)
            let extra = try mcpToolReplyJSONByteCount(output: .object([:]), tool: "list-image-types",
                generation: nil, protocolVersion: version, id: outside)
            XCTAssertEqual(extra, boundary + 1)
            let escaped = ScriptValue.string("\"\\\n")
            XCTAssertEqual(try mcpToolReplyJSONByteCount(output: .object([:]), tool: "list-image-types",
                generation: nil, protocolVersion: version, id: escaped) - base,
                try escaped.jsonData().count - 1)
        }
    }
}
