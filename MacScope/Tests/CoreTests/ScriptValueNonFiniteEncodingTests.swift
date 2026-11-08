// Authored, unrun.
// Outcome A: refuse before Foundation. Never run these non-finite cases at the pin.
import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

@MainActor
final class ScriptValueNonFiniteEncodingTests: XCTestCase {
    private func assertRefusal(
        _ value: ScriptValue, path: String, truncated: Bool = false,
        prettyPrinted: Bool = false, file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertThrowsError(try value.jsonData(prettyPrinted: prettyPrinted), file: file, line: line) { error in
            guard let typed = error as? ScriptValueEncodingError else {
                XCTFail("Expected the typed non-finite refusal, got \(error)", file: file, line: line)
                return
            }
            switch typed {
            case let .nonFiniteNumber(actualPath, actualTruncated):
                XCTAssertEqual(actualPath, path, file: file, line: line)
                XCTAssertEqual(actualTruncated, truncated, file: file, line: line)
                XCTAssertLessThanOrEqual(actualPath.unicodeScalars.count, 256, file: file, line: line)
                XCTAssertLessThanOrEqual(actualPath.utf8.count, 1_024, file: file, line: line)
            }
        }
    }

    private var finiteVectors: [(String, ScriptValue)] {
        [
            ("positive zero fragment", .double(0.0)),
            ("negative zero fragment", .double(-0.0)),
            ("fraction fragment", .double(0.1)),
            ("large exponent fragment", .double(1e21)),
            ("least positive subnormal fragment", .double(Double.leastNonzeroMagnitude)),
            ("greatest finite fragment", .double(Double.greatestFiniteMagnitude)),
            ("UInt64 maximum count", .count(UInt64.max)),
            ("object-array-object depth three", .object([
                "items": .array([.object(["confidence": .double(0.1)])])
            ])),
            ("mixed siblings", .object([
                "number": .double(-0.0), "integer": .int(-7), "boolean": .bool(true),
                "text": .string("line\n雪/~"), "nothing": .null
            ])),
            ("empty object", .object([:])),
            ("empty array", .array([])),
            ("bare null", .null),
            ("bare bool", .bool(false)),
            ("bare int", .int(Int64.max)),
            ("bare string", .string("fragment"))
        ]
    }

    private func assertFiniteIdentity(
        prettyPrinted: Bool, file: StaticString = #filePath, line: UInt = #line
    ) throws {
        var options: JSONSerialization.WritingOptions = [.fragmentsAllowed, .sortedKeys]
        if prettyPrinted { options.insert(.prettyPrinted) }
        for (name, value) in finiteVectors {
            // Exact pin expression on the same finite value, never a hand-typed JSON string.
            let expected = try JSONSerialization.data(withJSONObject: value.foundationObject, options: options)
            let actual = try value.jsonData(prettyPrinted: prettyPrinted)
            XCTAssertEqual(actual, expected, name, file: file, line: line)
        }
    }

    // T1: the root path is the empty JSON Pointer, not "/".
    func testT1RefuseTopLevelNaN() {
        assertRefusal(.double(.nan), path: "")
    }

    // T2: objects are traversed as well as arrays.
    func testT2RefusePositiveInfinityInObject() {
        assertRefusal(.object(["confidence": .double(.infinity)]), path: "/confidence")
    }

    // T3: an ordinary finite leaf before the bad one must not end validation.
    func testT3RefuseNegativeInfinityInArrayInsideObject() {
        assertRefusal(
            .object(["items": .array([.int(1), .double(-.infinity)])]),
            path: "/items/1"
        )
    }

    // T4 and T5 pass at the pin by construction. The non-finite tests do not.
    func testT4RefusalPolicyPreservesCompactFiniteBytes() throws {
        try assertFiniteIdentity(prettyPrinted: false)
    }

    func testT5RefusalPolicyPreservesPrettyFiniteBytes() throws {
        try assertFiniteIdentity(prettyPrinted: true)
    }

    // T6: pretty printing cannot bypass the preflight.
    func testT6RefusePrettyPrintedTopLevelNaN() {
        assertRefusal(.double(.nan), path: "", prettyPrinted: true)
    }

    // T7: the same shape as T3, with an explicit typed path assertion in both modes.
    func testT7RefusalCarriesNestedArrayPath() {
        let value: ScriptValue = .object(["items": .array([.int(1), .double(-.infinity)])])
        for prettyPrinted in [false, true] {
            assertRefusal(value, path: "/items/1", prettyPrinted: prettyPrinted)
        }
    }

    // T8: object children are pushed in Dictionary order and popped in reverse.
    // Replacing an existing value does not insert/remove a key. Assert the actual
    // order after replacement so this test never silently assumes sorted keys.
    func testT8RefuseLastVisitedLeafOfWideObject() throws {
        var fields = Dictionary(uniqueKeysWithValues: (0..<128).map { ("leaf\($0)", ScriptValue.int(Int64($0))) })
        let lastVisitedKey = try XCTUnwrap(fields.first?.key)
        fields[lastVisitedKey] = .double(.nan)
        XCTAssertEqual(fields.first?.key, lastVisitedKey, "The bad leaf must be last in the LIFO walk.")
        for prettyPrinted in [false, true] {
            assertRefusal(.object(fields), path: "/" + lastVisitedKey, prettyPrinted: prettyPrinted)
        }

        // Also reject a mutant that checks only Dictionary.first directly.
        fields[lastVisitedKey] = .int(0)
        let oppositeKey = try XCTUnwrap(Array(fields.keys).last)
        XCTAssertNotEqual(oppositeKey, lastVisitedKey)
        fields[oppositeKey] = .double(.nan)
        for prettyPrinted in [false, true] {
            assertRefusal(.object(fields), path: "/" + oppositeKey, prettyPrinted: prettyPrinted)
        }
    }

    func testRefusalEscapesJSONPointerKeyAndPreservesEmptyKey() {
        assertRefusal(.object(["a~/b": .double(.nan)]), path: "/a~0~1b")
        assertRefusal(.object(["": .double(.nan)]), path: "/")
    }

    func testRefusalBoundsLongUnicodeKeyAndMarksTruncation() {
        let key = String(repeating: "é", count: 300)
        assertRefusal(
            .object([key: .double(.nan)]),
            path: "/" + String(repeating: "é", count: 255), truncated: true
        )
    }

    func testRefusalDoesNotSplitJSONPointerEscapeAtBound() {
        let key = String(repeating: "k", count: 254) + "/"
        assertRefusal(
            .object([key: .double(.nan)]),
            path: "/" + String(repeating: "k", count: 254), truncated: true
        )
    }

    func testRefusalDistinguishesExactBoundFromTruncatedDescendant() {
        let key = String(repeating: "k", count: 255)
        assertRefusal(.object([key: .double(.nan)]), path: "/" + key)
        assertRefusal(.object([key: .array([.double(.nan)])]), path: "/" + key, truncated: true)
    }

    func testRefusalUsesIterativeWalkForDeepNonFiniteLeaf() {
        var value: ScriptValue = .double(-.infinity)
        for _ in 0..<300 { value = .array([value]) }
        assertRefusal(value, path: String(repeating: "/0", count: 128), truncated: true)
    }

    func testRefusalDescriptionDoesNotRenderOffendingNumber() {
        let expected = "JSON encoding refused a non-finite number at \"\"."
        for number in [Double.nan, Double.infinity, -Double.infinity] {
            XCTAssertThrowsError(try ScriptValue.double(number).jsonData()) { error in
                XCTAssertEqual(error.localizedDescription, expected)
            }
        }
    }

    // D01: a NaN in a tool result is reported as a non-finite number, not as an oversize reply.
    func testMCPToolResultWithNaNReportsNonFiniteNotResponseExceedsLimit() async throws {
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: "/tmp/test.bin", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: .nan)],
            symbols: [], instructions: [], xrefs: [], hexBytes: Data())
        let store = WorkspaceStore(workspaceName: "MCP", snapshot: snapshot, engine: AnalysisEngine())
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let request = try ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(7), "method": .string("tools/call"),
            "params": .object(["name": .string("functions"), "arguments": .object([:])])
        ]).jsonData()
        for asynchronous in [false, true] {
            let data = asynchronous ? await server.handleMessageAsync(request) : server.handleMessage(request)
            let reply = try ScriptValue.decode(try XCTUnwrap(data))
            let message = try XCTUnwrap(reply["error"]?["message"]?.stringValue, "asynchronous=\(asynchronous)")
            XCTAssertTrue(message.contains("non-finite number"), message)
            XCTAssertFalse(message.contains("exceeds limit"), message)
            XCTAssertFalse(message.lowercased().contains("nan"), message)
        }
    }
}
