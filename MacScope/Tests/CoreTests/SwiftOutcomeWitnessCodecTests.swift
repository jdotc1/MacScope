import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeWitnessCodecTests: XCTestCase {
    private let minimal: SwiftOutcomeJSON = .object(["model_version": .string("swift-outcome-witness-v2"), "status": .string("unresolved"), "eligible": .bool(false)])
    private func code(_ expected: String, _ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: expected), file: file, line: line) }
    }
    func testJM01Defaults() {
        let v = BroadWitnessLimits()
        let expected: [Int] = [512, 512, 2048, 65536, 32, 64, 512, 16384, 2048, 262144, 16777216, 16]
        XCTAssertEqual([v.maxInstructions, v.maxBlocks, v.maxEdges, v.maxWork, v.maxDepth, v.maxStateEntries, v.maxProvenanceNodes, v.maxContainerItems, v.maxString, v.maxBytes, v.maxAggregateBytes, v.postCallWindow], expected)
    }
    func testJM02DepthCaps() throws {
        code("invalid_broad_witness_limit:max_depth") { _ = try BroadWitnessLimits(maxDepth: 65) }
        XCTAssertEqual(try BroadWitnessLimits(maxDepth: 64).maxDepth, Int(64))
        XCTAssertEqual(try BroadWitnessLimits(maxDepth: 0).maxDepth, Int(0))
    }
    func testJM03OrderedValidation() {
        code("invalid_broad_witness_limit:max_instructions") { _ = try BroadWitnessLimits(maxInstructions: -1, maxDepth: 65) }
        code("invalid_broad_witness_limit:max_instructions") { _ = try BroadWitnessLimits(maxInstructions: 4097) }
    }
    func testJM04EscapedCanonicalBytes() {
        let value: SwiftOutcomeJSON = .object(["b": .integer(1), "a": .array([.bool(true), .null, .string("\u{e9}\u{7f}\u{1f600}")])])
        let expected: Data = Data(#"{"a":[true,null,"\u00e9\u007f\ud83d\ude00"],"b":1}"#.utf8)
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(value), expected)
    }
    func testJM05ControlEscapes() {
        let expected: Data = Data(#""a\"b\\c\n\r\t\b\f\u0001""#.utf8)
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(.string("a\"b\\c\n\r\t\u{8}\u{c}\u{1}")), expected)
    }
    func testJM06ScalarKeyOrder() {
        let value: SwiftOutcomeJSON = .object(["B": .integer(0), "a": .integer(0), "_": .integer(0), "10": .integer(0), "9": .integer(0)])
        let expected: Data = Data(#"{"10":0,"9":0,"B":0,"_":0,"a":0}"#.utf8)
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(value), expected)
        let astralExpected: Data = Data(#"{"\uff5e":0,"\ud83d\ude00":0}"#.utf8)
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(.object(["\u{1f600}": .integer(0), "\u{ff5e}": .integer(0)])), astralExpected)
    }
    func testJM07IntegerBytes() {
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(.integer(-1)), Data("-1".utf8))
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(.integer(18446744073709551615)), Data("18446744073709551615".utf8))
    }
    func testJM08PreflightCount() throws {
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.preflight(.object(["a": .array([.integer(1), .integer(2), .integer(3)])])), Int(5))
    }
    func testJM09PreflightDepth() throws {
        let limits = try BroadWitnessLimits(maxDepth: 2)
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.preflight(.array([.array([.integer(1)])]), limits: limits), Int(3))
        code("witness_structure_limit") { _ = try SwiftOutcomeWitnessCodec.preflight(.array([.array([.array([.integer(1)])])]), limits: limits) }
    }
    func testJM10StringBeforeByteBudget() {
        code("witness_byte_limit") { _ = try SwiftOutcomeWitnessCodec.preflight(.string("abc"), limits: BroadWitnessLimits(maxBytes: 10)) }
        code("witness_string_limit") { _ = try SwiftOutcomeWitnessCodec.preflight(.string("abc"), limits: BroadWitnessLimits(maxString: 2)) }
    }
    func testJM11KeyLimit() {
        code("witness_key_limit") { _ = try SwiftOutcomeWitnessCodec.preflight(.object(["abc": .null]), limits: BroadWitnessLimits(maxString: 2)) }
    }
    func testJM12SignedMagnitudeRange() throws {
        code("witness_integer_limit") { _ = try SwiftOutcomeWitnessCodec.preflight(.integer(Int128(1) << 64)) }
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.preflight(.integer(-(Int128(1) << 64))), Int(1))
        code("witness_integer_limit") { _ = try SwiftOutcomeWitnessCodec.preflight(.integer(-(Int128(1) << 64) - 1)) }
    }
    func testJM13CandidateOnlyContract() throws {
        let expected: Data = Data(#"{"eligible":false,"model_version":"swift-outcome-witness-v2","status":"unresolved"}"#.utf8)
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.encode(minimal), expected)
        var status = minimal; status["status"] = .string("eligible_structural_only")
        var eligible = minimal; eligible["eligible"] = .bool(true)
        var model = minimal; model["model_version"] = .string("swift-outcome-witness-v1")
        for value in [status, eligible, model, .array([])] { code("candidate_only_contract") { _ = try SwiftOutcomeWitnessCodec.encode(value) } }
    }
    func testJM14ConservativeByteBudget() {
        code("witness_byte_limit") { _ = try SwiftOutcomeWitnessCodec.encode(minimal, limits: BroadWitnessLimits(maxBytes: 100)) }
    }
    func testJM15PublicRecordSkipsBinding() throws {
        let value: SwiftOutcomeJSON = .object(["abi": .object(["binding": .array([.integer(1)]), "x_binding": .null, "keep": .integer(2), "bindingx": .integer(4), "nested": .object(["binding": .integer(3), "ok": .string("y")])])])
        let expected: SwiftOutcomeJSON = .object(["abi": .object(["keep": .integer(2), "bindingx": .integer(4), "nested": .object(["ok": .string("y")])])])
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.publicRecord(value), expected)
    }
    func testJM16StrictParse() throws {
        let expected: SwiftOutcomeJSON = .object(["a": .array([.integer(1), .integer(0), .string("x")]), "b": .null])
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":[1,-0,"x"],"b":null}"#.utf8)), expected)
    }
    func testJM17MalformedAndNonInteger() {
        code("duplicate_json_key") { _ = try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":1,"a":2}"#.utf8)) }
        let nonIntegers: [String] = [#"{"a":1.5}"#, #"{"a":1e2}"#, #"{"a":NaN}"#, #"{"a":Infinity}"#, #"{"a":-Infinity}"#]
        for text in nonIntegers { code("non_integer_json_number") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8)) } }
        code("witness_object_required") { _ = try SwiftOutcomeWitnessCodec.parse(Data("[1]".utf8)) }
        let malformed: [Data] = [Data(#"{"a":1,}"#.utf8), Data(), Data(#"{"a":01}"#.utf8), Data([0xff])]
        for data in malformed { code("malformed_witness_json") { _ = try SwiftOutcomeWitnessCodec.parse(data) } }
    }
    func testJM18ParsedIntegerRange() throws {
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":18446744073709551615}"#.utf8))["a"], SwiftOutcomeJSON.integer(18446744073709551615))
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":-18446744073709551616}"#.utf8))["a"], SwiftOutcomeJSON.integer(-18446744073709551616))
        for text in [#"{"a":18446744073709551616}"#, #"{"a":1234567890123456789012}"#] { code("witness_integer_limit") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8)) } }
    }
    func testJM19ScanPrecedesGrammar() throws {
        let limits = try BroadWitnessLimits(maxDepth: 2)
        for text in [#"{"a":{"b":{"c":1}}}"#, "[[[["] { code("witness_structure_limit") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8), limits: limits) } }
        let expected: SwiftOutcomeJSON = .object(["a": .string("[[[[[")])
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":"[[[[["}"#.utf8), limits: limits), expected)
        code("witness_byte_limit") { _ = try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":1}"#.utf8), limits: BroadWitnessLimits(maxBytes: 5)) }
    }
    func testCodecSurrogateAndControlRefusals() {
        let malformed: [String] = [#"{"a":"\ud800"}"#, #"{"a":"\udc00"}"#, #"{"a":"\ud800\u0041"}"#, "{\"a\":\"\u{1}\"}"]
        for text in malformed { code("malformed_witness_json") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8)) } }
    }
    func testCodecDuplicateHookWaitsForCompleteObject() {
        code("non_integer_json_number") { _ = try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":1,"a":2,"b":1.5}"#.utf8)) }
        code("malformed_witness_json") { _ = try SwiftOutcomeWitnessCodec.parse(Data(#"{"a":1,"a":2,}"#.utf8)) }
    }
    func testPublicRecordReverseArrayWalkPreservesOrder() throws {
        let value: SwiftOutcomeJSON = .array([.array([.integer(1)]), .integer(2)])
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.publicRecord(value), value)
        // Donor LIFO visits 2 first, leaving enough pending budget for [1].
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.publicRecord(value, limits: BroadWitnessLimits(maxContainerItems: 4)), value)
        let orderSensitive: SwiftOutcomeJSON = .array([.object(["binding": .null]), .array([.integer(2)])])
        code("witness_structure_limit") { _ = try SwiftOutcomeWitnessCodec.publicRecord(orderSensitive, limits: BroadWitnessLimits(maxContainerItems: 4)) }
    }
    func testNumberHookUsesLongestValidToken() {
        let floatingPrefixes: [String] = [#"{"x":1.2e}"#, #"{"x":1.2e+}"#, #"{"x":1.2.}"#, #"{"x":1e2e}"#]
        for text in floatingPrefixes { code("non_integer_json_number") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8)) } }
        let oversizedPrefixes: [String] = [#"{"x":18446744073709551616.}"#, #"{"x":18446744073709551616e+}"#]
        for text in oversizedPrefixes { code("witness_integer_limit") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8)) } }
        let malformed: [String] = [#"{"x":1.}"#, #"{"x":1e}"#, #"{"x":1e+}"#]
        for text in malformed { code("malformed_witness_json") { _ = try SwiftOutcomeWitnessCodec.parse(Data(text.utf8)) } }
    }

}
#endif
