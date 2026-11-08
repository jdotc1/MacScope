// Authored, unrun.
// Pure fixtures only. No stack-overflow-sized input and no intentional crash.
import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

@MainActor
final class ScriptValueOutputDepthTests: XCTestCase {
    private func chain(_ depth: Int, object: Bool, leaf: ScriptValue = .int(7)) -> ScriptValue {
        var value = leaf
        for _ in 0..<depth {
            value = object ? .object(["child": value]) : .array([value])
        }
        return value
    }

    private func assertNestingRefusal(
        _ value: ScriptValue, maximumDepth: Int = ScriptValue.maximumEncodingDepth,
        limit: Int = ScriptValue.maximumEncodingDepth, prettyPrinted: Bool = false,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try value.jsonData(prettyPrinted: prettyPrinted, maximumDepth: maximumDepth),
            file: file, line: line
        ) { error in
            XCTAssertEqual(error as? ScriptValueNestingError, ScriptValueNestingError(limit: limit),
                           file: file, line: line)
        }
    }

    private func assertNonFinite(
        _ value: ScriptValue, path: String, truncated: Bool = false, prettyPrinted: Bool,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertThrowsError(try value.jsonData(prettyPrinted: prettyPrinted), file: file, line: line) { error in
            guard let refusal = error as? ScriptValueEncodingError else {
                XCTFail("Expected the existing non-finite error type", file: file, line: line)
                return
            }
            switch refusal {
            case let .nonFiniteNumber(actualPath, actualTruncated):
                XCTAssertEqual(actualPath, path, file: file, line: line)
                XCTAssertEqual(actualTruncated, truncated, file: file, line: line)
            }
        }
    }

    private func response(_ output: ScriptValue, protocolVersion: MCPResultProtocol = .structured,
                          isError: Bool = false, note: ScriptValue? = nil) throws -> ScriptValue {
        let limit = MCPStructuredResult.maximumOutputDepth(
            protocolVersion: protocolVersion, isError: isError, output: output)
        let text = String(decoding: try output.jsonData(maximumDepth: limit), as: UTF8.self)
        return .object([
            "jsonrpc": .string("2.0"), "id": .int(7),
            "result": MCPStructuredResult.successEnvelope(
                protocolVersion: protocolVersion, tool: "info", output: output,
                legacyText: text, isError: isError, note: note, noteText: note == nil ? nil : "note")
        ])
    }

    func testDeepOutputRefusesBeforeFoundationBridge() {
        for object in [false, true] {
            let value = chain(129, object: object)
            for pretty in [false, true] {
                assertNestingRefusal(value, prettyPrinted: pretty)
            }
        }
    }

    func testAtLimitEncodesIdentically() throws {
        XCTAssertEqual(ScriptValue.maximumEncodingDepth, 128)
        for object in [false, true] {
            let value = chain(128, object: object)
            for pretty in [false, true] {
                var options: JSONSerialization.WritingOptions = [.fragmentsAllowed, .sortedKeys]
                if pretty { options.insert(.prettyPrinted) }
                let expected = try JSONSerialization.data(withJSONObject: value.foundationObject, options: options)
                XCTAssertEqual(try value.jsonData(prettyPrinted: pretty), expected)
            }
        }
    }

    func testExplicitLimitIsClampedAndStricterOnly() throws {
        for pretty in [false, true] {
            for object in [false, true] {
                assertNestingRefusal(chain(129, object: object), maximumDepth: 1_000, prettyPrinted: pretty)
                assertNestingRefusal(chain(3, object: object), maximumDepth: 2, limit: 2, prettyPrinted: pretty)
                let shallow = chain(2, object: object)
                XCTAssertEqual(try shallow.jsonData(prettyPrinted: pretty, maximumDepth: 2),
                               try shallow.jsonData(prettyPrinted: pretty))
            }
            for root in [ScriptValue.array([]), .object([:]), .array([.int(1)]), .object(["x": .int(1)])] {
                assertNestingRefusal(root, maximumDepth: -1, limit: 0, prettyPrinted: pretty)
                assertNestingRefusal(root, maximumDepth: 0, limit: 0, prettyPrinted: pretty)
            }
            for scalar in [ScriptValue.null, .bool(true), .int(7), .double(2.5), .string("fragment")] {
                XCTAssertEqual(try scalar.jsonData(prettyPrinted: pretty, maximumDepth: -1),
                               try scalar.jsonData(prettyPrinted: pretty))
            }
        }
    }

    func testNonFiniteBeatsDepth() {
        let deepNaN = chain(300, object: false, leaf: .double(.nan))
        let finiteBranch = chain(129, object: false)
        // Array index zero is visited first, so the deep branch precedes the shallow NaN.
        let siblingNaN: ScriptValue = .array([finiteBranch, .double(.nan)])
        let finiteSiblings: ScriptValue = .array([finiteBranch, .int(0)])
        for pretty in [false, true] {
            assertNonFinite(deepNaN, path: String(repeating: "/0", count: 128),
                            truncated: true, prettyPrinted: pretty)
            assertNonFinite(siblingNaN, path: "/1", prettyPrinted: pretty)
            assertNestingRefusal(finiteSiblings, prettyPrinted: pretty)
        }
    }

    func testStructuredOutputLimitMatchesFrameAdmission() throws {
        XCTAssertEqual(MCPStructuredResult.responseFrameDepth, 64)
        for (object, limit) in [(true, 62), (false, 61)] {
            let output = chain(limit, object: object)
            XCTAssertEqual(MCPStructuredResult.maximumOutputDepth(
                protocolVersion: .structured, isError: false, output: output), limit)
            for note in [Optional<ScriptValue>.none, .some(.object(["message": .string("bounded note")]))] {
                let frame = try response(output, note: note)
                let data = try frame.jsonData()
                let admitted = try MCPFrameAdmission.response(data, id: .integer(7), maximumBytes: 1_000_000)
                let decoded = try ScriptValue.decode(admitted)
                XCTAssertNil(decoded["error"])
                XCTAssertNotNil(decoded["result"])
                let embedded = object ? decoded["result"]?["structuredContent"]
                    : decoded["result"]?["structuredContent"]?["result"]
                XCTAssertEqual(embedded, output)
            }
            let tooDeep = chain(limit + 1, object: object)
            let selectedLimit = MCPStructuredResult.maximumOutputDepth(
                protocolVersion: .structured, isError: false, output: tooDeep)
            for pretty in [false, true] {
                assertNestingRefusal(tooDeep, maximumDepth: selectedLimit, limit: limit, prettyPrinted: pretty)
            }
            // Independently demonstrate the actual frame-admission boundary, without
            // the output preflight helper: depth 65 must not be admitted as a result.
            let overFrame: ScriptValue = .object([
                "jsonrpc": .string("2.0"), "id": .int(7),
                "result": MCPStructuredResult.successEnvelope(
                    protocolVersion: .structured, tool: "info", output: tooDeep,
                    legacyText: "unused", isError: false)
            ])
            let refused = try MCPFrameAdmission.response(
                overFrame.jsonData(), id: .integer(7), maximumBytes: 1_000_000)
            let decoded = try ScriptValue.decode(refused)
            XCTAssertNil(decoded["result"])
            XCTAssertEqual(decoded["error"]?["code"], .int(-32603))
            XCTAssertEqual(decoded["error"]?["message"], .string("Invalid response"))
        }
        for output in [chain(128, object: true), chain(128, object: false), .int(7)] {
            for version in [MCPResultProtocol.legacy, .structured] {
                for isError in [false, true] where version == .legacy || isError {
                    XCTAssertEqual(MCPStructuredResult.maximumOutputDepth(
                        protocolVersion: version, isError: isError, output: output), 128)
                    let frame = try response(output, protocolVersion: version, isError: isError)
                    let admitted = try MCPFrameAdmission.response(
                        frame.jsonData(), id: .integer(7), maximumBytes: 1_000_000)
                    XCTAssertNotNil(try ScriptValue.decode(admitted)["result"])
                }
            }
        }
    }

    func testAppleScriptRunCommandDeepRefusesWithFixedError() {
        for object in [false, true] {
            XCTAssertThrowsError(try AppleScriptArgumentBridge.cocoaReply(
                from: chain(129, object: object), command: "run command")) { error in
                let cocoa = error as NSError
                XCTAssertEqual(cocoa.domain, "MacScope.Scripting")
                XCTAssertEqual(cocoa.code, -1750)
                XCTAssertEqual(cocoa.localizedDescription,
                               "Scripting reply contains a value that cannot be encoded as JSON.")
            }
        }
    }

    func testAppleScriptRunCommandFiniteUnchanged() throws {
        let object: ScriptValue = .object([
            "ok": .bool(true), "stubCount": .int(3), "name": .string("Quoted \"name\" — λ"),
            "items": .array([.null, .double(2.5)])
        ])
        let values: [ScriptValue] = [object, .string("scalar"), .int(7), .bool(false), .null,
                                    chain(128, object: false), chain(128, object: true)]
        for value in values {
            let text = try XCTUnwrap(AppleScriptArgumentBridge.cocoaReply(
                from: value, command: "run command") as? String)
            XCTAssertEqual(Data(text.utf8), try value.jsonData())
            XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), value)
        }
    }

    func testNestingDescriptionIsFixed() {
        let value = chain(128, object: false, leaf: .object(["private-key": .int(7)]))
        XCTAssertThrowsError(try value.jsonData()) { error in
            XCTAssertEqual(error.localizedDescription,
                           "JSON encoding refused output nested deeper than 128 levels.")
            XCTAssertFalse(error.localizedDescription.contains("private-key"))
        }
        XCTAssertEqual(ScriptValueNestingError(limit: 2).errorDescription,
                       "JSON encoding refused output nested deeper than 2 levels.")
    }
}
