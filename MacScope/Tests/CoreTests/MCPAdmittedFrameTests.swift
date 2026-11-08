import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

// Authored, unrun. Proves strict-parser/legacy-conversion parity, explicit boundary
// outcomes and raw ID lexemes; raw IDs do not authorize protocol restoration.
final class MCPAdmittedFrameTests: XCTestCase {
    private struct Case {
        let name: String
        let data: Data
        let maximumBytes: Int
        let succeeds: Bool
        init(_ name: String, _ json: String, maximumBytes: Int = 1_048_576,
             succeeds: Bool = true) {
            self.name = name
            data = Data(json.utf8)
            self.maximumBytes = maximumBytes
            self.succeeds = succeeds
        }
        init(_ name: String, bytes: [UInt8], succeeds: Bool) {
            self.name = name
            data = Data(bytes)
            maximumBytes = 1_048_576
            self.succeeds = succeeds
        }
    }

    // Type-presence: absent at the pin; expected not to compile there.
    func testNewFrameTypePresenceAndLimits() throws {
        let frame = try MCPAdmittedFrame.admit(Data("{}".utf8), maximumBytes: 2)
        XCTAssertEqual(frame.byteCount, 2)
        XCTAssertEqual(frame.value, .object([:]))
        XCTAssertNil(frame.originalID)
        XCTAssertEqual(MCPAdmittedFrame.limits(maximumBytes: 123),
                       MacScopeAnalysisCore.Phase2StrictJSONLimits(maximumBytes: 123, maximumDepth: 16,
                                              maximumTokens: 100_000,
                                              maximumMembersAndElements: 50_000))
    }

    private func corpus() -> [Case] {
        // DERIVED from parser :252-279: n scalar array items cost 2*n+1 tokens;
        // replacing one scalar by [] adds one token without adding a member.
        let atTokens = "[" + (["[]"] + Array(repeating: "0", count: 49_998)).joined(separator: ",") + "]"
        let atMembers = "[" + Array(repeating: "0", count: 50_000).joined(separator: ",") + "]"
        let overMembers = "[" + Array(repeating: "0", count: 50_001).joined(separator: ",") + "]"
        return [
            Case("duplicate-top", #"{"a":1,"a":2}"#, succeeds: false),
            Case("duplicate-nested", #"{"x":{"a":1,"a":2}}"#, succeeds: false),
            Case("lone-high", #""\uD800""#, succeeds: false),
            Case("lone-low", #""\uDC00""#, succeeds: false),
            Case("paired-surrogates", #""\uD83D\uDE00""#),
            Case("invalid-UTF8", bytes: [0x22, 0xff, 0x22], succeeds: false),
            Case("above-2pow53", "9007199254740993"),
            Case("decimal", "1.0"), Case("exponent", "1e3"), Case("negative-zero", "-0"),
            Case("leading-zero", "01", succeeds: false),
            Case("depth-at", String(repeating: "[", count: 16) + "0" + String(repeating: "]", count: 16)),
            Case("depth-over", String(repeating: "[", count: 17) + "0" + String(repeating: "]", count: 17), succeeds: false),
            Case("tokens-at-100000", atTokens),
            Case("tokens-over-100001-members-at-50000", atMembers, succeeds: false),
            Case("members-over-50001", overMembers, succeeds: false),
            Case("bytes-at", "{}", maximumBytes: 2),
            Case("bytes-over", "{} ", maximumBytes: 2, succeeds: false),
            Case("trailing", "{}x", succeeds: false),
            Case("empty-object", "{}"), Case("bare-scalar", "true"),
            Case("empty-input", "", succeeds: false),
            Case("whitespace", " \t\r\n", succeeds: false),
            Case("non-finite-conversion", "1e9999", succeeds: false),
            Case("id-int", #"{"id":1}"#), Case("id-decimal", #"{"id":1.0}"#),
            Case("id-string", #"{"id":"a"}"#), Case("id-null", #"{"id":null}"#),
            Case("id-absent", #"{"method":"ping"}"#),
            Case("id-long", "{\"id\":\"" + String(repeating: "a", count: 13_000) + "\"}")
        ]
    }

    // Invariant/control: old decode and the new admission+conversion have equal values/errors.
    func testCorpusMatchesLegacyAndExplicitExpectedOutcome() {
        let inputs = corpus()
        XCTAssertEqual(inputs.count, 30)
        for input in inputs {
            let legacy = Result { try HeadlessJSON.decode(input.data, maximumBytes: input.maximumBytes) }
            let admitted = Result {
                try MCPAdmittedFrame.admit(input.data, maximumBytes: input.maximumBytes).legacyValue()
            }
            switch (legacy, admitted) {
            case (.success(let old), .success(let new)):
                XCTAssertTrue(input.succeeds, input.name)
                XCTAssertEqual(old, new, input.name)
            case (.failure(let old), .failure(let new)):
                XCTAssertFalse(input.succeeds, input.name)
                guard case HeadlessJSONError.invalid = old,
                      case HeadlessJSONError.invalid = new else {
                    XCTFail("Wrong failure class: " + input.name)
                    continue
                }
            default: XCTFail("Admission/legacy disagreement: " + input.name)
            }
        }
    }

    // Invariant/control: exact values, not just mutual agreement between two paths.
    func testNumberConversionAndSurrogateExpectedValues() throws {
        let values: [(String, ScriptValue)] = [
            ("9007199254740993", .int(9_007_199_254_740_993)),
            ("1.0", .int(1)), ("1e3", .int(1_000)), ("-0", .int(0)),
            (#""\uD83D\uDE00""#, .string("😀"))
        ]
        for (json, expected) in values {
            XCTAssertEqual(try MCPAdmittedFrame.admit(Data(json.utf8), maximumBytes: 100).legacyValue(),
                           expected)
        }
    }

    // Invariant/control. The fixed token cap masks the production member boundary.
    // This control raises ONLY the parser's token cap to isolate the member limit.
    func testMemberBoundaryIsolationExplainsMaskedProductionCases() throws {
        let at = Data(("[" + Array(repeating: "0", count: 50_000).joined(separator: ",") + "]").utf8)
        let over = Data(("[" + Array(repeating: "0", count: 50_001).joined(separator: ",") + "]").utf8)
        let isolated = MacScopeAnalysisCore.Phase2StrictJSONLimits(maximumBytes: 1_048_576, maximumDepth: 16,
                                             maximumTokens: 100_003,
                                             maximumMembersAndElements: 50_000)
        XCTAssertEqual(try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(at, limits: isolated).arrayValue?.count, 50_000)
        XCTAssertThrowsError(try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(over, limits: isolated)) {
            XCTAssertEqual($0 as? MacScopeAnalysisCore.Phase2StrictJSONError, .memberLimitExceeded)
        }
        for data in [at, over] {
            XCTAssertThrowsError(try MCPAdmittedFrame.admit(data, maximumBytes: 1_048_576))
        }
    }

    // Invariant/control: originalID's parser oracle is public; its private method is not called.
    func testOriginalIDLexemeAndAbsenceAgainstFreshStrictParse() throws {
        let lexemes = ["1", "1.0", "\"a\"", "null", "\"" + String(repeating: "a", count: 13_000) + "\""]
        for lexeme in lexemes {
            let data = Data(("{\"id\":" + lexeme + "}").utf8)
            let frame = try MCPAdmittedFrame.admit(data, maximumBytes: 1_048_576)
            let oracle = try MacScopeAnalysisCore.Phase2StrictJSONParser().parse(
                data, limits: MCPAdmittedFrame.limits(maximumBytes: 1_048_576)).objectValue?["id"]
            XCTAssertEqual(frame.originalID, oracle)
            XCTAssertEqual(frame.originalID?.canonicalJSONBytes(), Data(lexeme.utf8))
            XCTAssertEqual(frame.byteCount, data.count)
        }
        let absent = try MCPAdmittedFrame.admit(Data("{}".utf8), maximumBytes: 2)
        XCTAssertNil(absent.originalID)
        let explicitNull = try MCPAdmittedFrame.admit(Data("{\"id\":null}".utf8), maximumBytes: 100)
        XCTAssertEqual(explicitNull.originalID, .null)
    }
}
