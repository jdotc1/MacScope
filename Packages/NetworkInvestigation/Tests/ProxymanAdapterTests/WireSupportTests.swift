import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

@Suite struct WireSupportTests {
    @Test func identifierAndVersionHelpersKeepStrictWireGrammarAndBounds() {
        #expect(ProxymanMinimizer.identifier(.string("flow-1_A")) == "flow-1_A")
        #expect(ProxymanMinimizer.identifier(.int(5)) == "5")
        let invalidIdentifiers: [MCPJSONValue?] = [.int(-1), .double(5), .string("a b"), .string(""), nil]
        for value in invalidIdentifiers {
            #expect(ProxymanMinimizer.identifier(value) == nil)
        }
        let longestIdentifier = String(repeating: "a", count: 128)
        #expect(ProxymanMinimizer.identifier(.string(longestIdentifier)) == longestIdentifier)
        #expect(ProxymanMinimizer.identifier(.string(String(repeating: "a", count: 129))) == nil)
        #expect(ProxymanMinimizer.version(.string("26.4.0")) == "26.4.0")
        #expect(ProxymanMinimizer.version(.int(26)) == "26")
        #expect(ProxymanMinimizer.version(.string("26.4.0+beta_1-x")) == "26.4.0+beta_1-x")
        let invalidVersions: [MCPJSONValue] = [.string("26 4"), .string(""), .bool(true)]
        for value in invalidVersions {
            #expect(ProxymanMinimizer.version(value) == nil)
        }
        let longestVersion = String(repeating: "1", count: 64)
        #expect(ProxymanMinimizer.version(.string(longestVersion)) == longestVersion)
        #expect(ProxymanMinimizer.version(.string(String(repeating: "1", count: 65))) == nil)
    }

    @Test func digestUsesSortedKeysAndUnescapedSlashes() throws {
        let first = try ProxymanDigest.json(.object(["b": .int(1), "a": .string("x/y")]))
        let second = try ProxymanDigest.json(.object(["a": .string("x/y"), "b": .int(1)]))
        let expected = "0acee55b8e12ac14a243a8be247ca94cba02af907fcb0ed2e6f23ee33ed2ea11"
        #expect(first == expected)
        #expect(second == expected)
        for digest in [first, second] {
            #expect(digest.count == 64)
            #expect(digest.allSatisfy { "0123456789abcdef".contains($0) })
        }
    }

    @Test func typedAccessorsAndFirstNonNullValueRemainStrict() {
        #expect(MCPJSONValue.double(3.0).pInt == 3)
        #expect(MCPJSONValue.double(3.5).pInt == nil)
        #expect(MCPJSONValue.string("1").pInt == nil)
        #expect(MCPJSONValue.int(7).pNumber == 7.0)
        #expect(MCPJSONValue.double(.infinity).pNumber == nil)
        #expect(MCPJSONValue.bool(true).pBool == true)
        #expect(MCPJSONValue.string("x").pString == "x")
        #expect(MCPJSONValue.array([]).pArray == [])
        #expect(MCPJSONValue.object([:]).pObject == [:])
        let nullable: [String: MCPJSONValue] = ["a": .null, "b": .int(1)]
        let onlyNull: [String: MCPJSONValue] = ["a": .null]
        let ordered: [String: MCPJSONValue] = ["a": .int(1), "b": .int(2)]
        #expect(nullable.first(["a", "b"]) == .int(1))
        #expect(onlyNull.first(["a"]) == nil)
        #expect(ordered.first(["b", "a"]) == .int(2))
    }
}
