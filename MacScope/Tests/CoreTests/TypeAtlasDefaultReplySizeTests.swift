import Foundation
import XCTest
@testable import MacScope

// Authored, unrun. Each red prediction names an assertion, not an observed run.
@MainActor
final class TypeAtlasDefaultReplySizeTests: XCTestCase {
    func testInvariantSyntheticFullProjectionByteModel() throws {
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let output = try harness.original()
        XCTAssertEqual(harness.entries.count, 53)
        XCTAssertEqual(harness.entries.filter { $0.kind == .objcClass }.count, 20)
        XCTAssertEqual(harness.entries.filter { $0.kind == .objcProtocol }.count, 7)
        XCTAssertEqual(harness.entries.filter { $0.kind == .swiftClass }.count, 21)
        XCTAssertEqual(harness.entries.filter { $0.kind == .swiftStruct }.count, 5)
        XCTAssertEqual(harness.entries.reduce(0) { $0 + $1.methods.count }, 1_288)
        XCTAssertEqual(harness.entries.reduce(0) { $0 + $1.methods.filter { $0.swiftMetadata != nil }.count }, 600)
        XCTAssertEqual(harness.entries.reduce(0) { $0 + $1.methods.reduce(0) { $0 + $1.selectorUsers.count } }, 550)
        XCTAssertEqual(harness.entries.reduce(0) { $0 + ($1.declaredProperties?.count ?? 0) }, 54)
        XCTAssertEqual(try output.jsonData().count, 287_660)
        let generation = try syntheticTypeAtlasGeneration()
        let legacy = try mcpToolReplyJSONByteCount(output: output, tool: "list-image-types",
            generation: generation, protocolVersion: .legacy, id: .int(5))
        XCTAssertEqual(legacy, 322_714)
        XCTAssertEqual(legacy + 1, 322_715)
        XCTAssertEqual(try mcpToolReplyJSONByteCount(output: output, tool: "list-image-types",
            generation: generation, protocolVersion: .structured, id: .int(5)), 287_971)
        // Exact byte model only. Synthetic content cannot prove real names or real-app acceptance.
    }

    func testDefaultAllRoutesAndProtocolsUseVCompleteFixture() async throws {
        // RED prediction: inline has no version marker and legacy frame exceeds 180,000.
        // Bounded pin outcomes are not inferred from captured inline output.
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let full = try harness.original()
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let reply = try await harness.read(route)
            let rows = try XCTUnwrap(reply["types"]?.arrayValue) // refusals cannot satisfy success
            XCTAssertEqual(reply["total"], .int(53))
            XCTAssertEqual(rows.count, 53)
            XCTAssertEqual(reply["vtableSummaryVersion"], .int(1))
            XCTAssertNil(reply["isTruncated"])
            XCTAssertNil(reply["nextCursor"])
            XCTAssertEqual(reply["swiftObjCLinks"], full["swiftObjCLinks"])
            XCTAssertEqual(rows[0]["swiftId"], full["types"]?.arrayValue?[0]["swiftId"])
            XCTAssertEqual(rows[0]["swiftName"], full["types"]?.arrayValue?[0]["swiftName"])
            let charge = try rows.reduce(0) { try $0 + WorkspaceScriptingAPI.listPageWireBytes($1) + 1 }
            XCTAssertLessThanOrEqual(charge, defaultTypeAtlasEscapedRowCap) // fixture invariant
            for version in [MCPResultProtocol.legacy, .structured] {
                XCTAssertLessThanOrEqual(try mcpToolReplyJSONByteCount(output: reply, tool: "list-image-types",
                    generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(5)) + 1, 180_000)
            }
        }
    }

    func testExplicitLimitAndPageFalseCannotBypassCapAt1200Rows() async throws {
        // RED prediction: pin returns 1,200 inline/async rows, 1,000 attached default;
        // isTruncated and nextCursor are absent. After fix every path returns 703.
        let harness = TypeAtlasReplyTestHarness((0..<1_200).map(TypeAtlasReplyTestHarness.small))
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            for args in [ScriptValue.object([:]), .object(["limit": .int(5_000), "page": .bool(false)])] {
                let reply = try await harness.read(route, args)
                XCTAssertEqual(reply["total"], .int(1_200))
                XCTAssertEqual(try XCTUnwrap(reply["types"]?.arrayValue).count, 703)
                XCTAssertEqual(reply["isTruncated"], .bool(true))
                XCTAssertNotNil(reply["nextCursor"]?.stringValue)
                XCTAssertNil(reply["vtableSummaryVersion"])
                for version in [MCPResultProtocol.legacy, .structured] {
                    XCTAssertLessThanOrEqual(try mcpToolReplyJSONByteCount(output: reply, tool: "list-image-types",
                        generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(5)) + 1, 180_000)
                }
            }
        }
    }

    func testInvariantSmallRepliesAndPageFalseStayByteIdentical() async throws {
        let harness = TypeAtlasReplyTestHarness((0..<3).map(TypeAtlasReplyTestHarness.small))
        let original = try harness.original()
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            for args in [ScriptValue.object([:]), .object(["page": .bool(false)]),
                         .object(["limit": .int(3)])] {
                let reply = try await harness.read(route, args)
                XCTAssertEqual(reply, original)
            }
        }
    }

    func testInvariantSmallVtableDoesNotTriggerSummary() async throws {
        var entry = TypeAtlasReplyTestHarness.small(0)
        entry.kind = .swiftClass; entry.id.kind = .swiftClass
        entry.methods = (0..<3).map { index in
            let metadata = SwiftMetadataMethod(source: .vtable, index: UInt64(index),
                descriptorAddress: UInt64(8_000 + index), implementation: nil, flags: 16)
            return TypeAtlasMethod(name: metadata.name, implementation: nil, swiftMetadata: metadata)
        }
        let harness = TypeAtlasReplyTestHarness([entry])
        let original = try harness.original()
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let reply = try await harness.read(route)
            XCTAssertEqual(reply, original)
            XCTAssertNil(reply["vtableSummaryVersion"])
            XCTAssertNil(reply["types"]?.arrayValue?.first?["unnamedVtableSlots"])
            XCTAssertEqual(reply["types"]?.arrayValue?.first?["methods"]?.arrayValue?.count, 3)
        }
    }

    func testFirstRowIsJudgedAfterVOnEveryRoute() async throws {
        // RED prediction: the pin lacks the version and retains 700 positional methods.
        var entry = TypeAtlasReplyTestHarness.small(0)
        entry.kind = .swiftClass; entry.id.kind = .swiftClass
        entry.methods = (0..<700).map { index in
            let metadata = SwiftMetadataMethod(source: .vtable, index: UInt64(index),
                descriptorAddress: UInt64(80_000 + index), implementation: nil, flags: 16)
            return TypeAtlasMethod(name: metadata.name, implementation: nil, swiftMetadata: metadata)
        }
        let harness = TypeAtlasReplyTestHarness([entry])
        for route in TypeAtlasReplyTestHarness.Route.allCases {
            let reply = try await harness.read(route)
            let rows = try XCTUnwrap(reply["types"]?.arrayValue)
            XCTAssertEqual(reply["total"], .int(1))
            XCTAssertEqual(rows.count, 1)
            XCTAssertEqual(reply["vtableSummaryVersion"], .int(1))
            XCTAssertEqual(rows[0]["methods"], .array([]))
            XCTAssertEqual(rows[0]["unnamedVtableSlots"], .object([
                "count": .int(700), "first": .int(0), "last": .int(699)]))
            XCTAssertNil(reply["isTruncated"])
        }
    }

    func testOracleOnlyFixtureReplyAtEncodedIDBoundary() async throws {
        // New-policy envelope invariant; server itself rejects this oversized ID string.
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let reply = try await harness.read(.inline)
        XCTAssertEqual(try XCTUnwrap(reply["types"]?.arrayValue).count, 53)
        let id = ScriptValue.string(String(repeating: "x", count: 12_998))
        XCTAssertEqual(try id.jsonData().count, 13_000)
        for version in [MCPResultProtocol.legacy, .structured] {
            XCTAssertLessThanOrEqual(try mcpToolReplyJSONByteCount(output: reply, tool: "list-image-types",
                generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: id) + 1, 180_000)
        }
    }

    func testWorkLedgerExhaustionInPassTwoEndsWithContinuationCursor() throws {
        // Calls the reply builder directly: 60 Swift rows of 700 positional vtable slots cost
        // about 39,000 work units each, and the summary leaves almost no output bytes.
        let entries: [TypeAtlasEntry] = (0..<60).map { row in
            var entry = TypeAtlasReplyTestHarness.small(row)
            entry.kind = .swiftClass; entry.id.kind = .swiftClass
            entry.methods = (0..<700).map { index in
                let metadata = SwiftMetadataMethod(source: .vtable, index: UInt64(index),
                    descriptorAddress: UInt64(80_000 + index), implementation: nil, flags: 16)
                return TypeAtlasMethod(name: metadata.name, implementation: nil, swiftMetadata: metadata)
            }
            return entry
        }
        let harness = TypeAtlasReplyTestHarness(entries)
        let reply = try WorkspaceScriptingAPI.typeAtlasUnpagedReply(entries,
            links: WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks(), slot: .primary, snapshot: harness.snapshot,
            kind: nil, limit: 5_000)
        let rows = try XCTUnwrap(reply["types"]?.arrayValue)
        XCTAssertFalse(rows.isEmpty)
        XCTAssertLessThan(rows.count, 60)
        XCTAssertEqual(reply["total"], .int(60))
        XCTAssertEqual(reply["isTruncated"], .bool(true))
        XCTAssertEqual(reply["vtableSummaryVersion"], .int(1))
        XCTAssertNotNil(reply["nextCursor"]?.stringValue)
    }

    func testInvariantWorstShapeReserveWithFrozenGeneration() throws {
        let harness = TypeAtlasReplyTestHarness([TypeAtlasReplyTestHarness.small(0)])
        guard case .object(var fields) = try harness.original() else { return XCTFail("object expected") }
        fields["types"] = .array([]); fields["total"] = .int(Int64.max)
        fields["imageSlot"] = .int(Int64.max)
        fields["isTruncated"] = .bool(true)
        fields["nextCursor"] = .string(String(repeating: "A", count: 152))
        fields["vtableSummaryVersion"] = .int(1)
        fields["swiftObjCLinks"] = WorkspaceScriptingAPI.typeAtlasLinkCountsValue(.init(
            linked: Int.max, membersNotMerged: Int.max, runtimeNameUndecodable: Int.max,
            noSwiftRow: Int.max, ambiguous: Int.max, privateOrLocal: Int.max, generic: Int.max))
        let framed = try mcpToolReplyJSONByteCount(output: .object(fields), tool: "list-image-types",
            generation: syntheticTypeAtlasGeneration(), protocolVersion: .legacy, id: .int(0)) + 1
        // I=0 means subtract the serialized ID token, not omit the JSON-RPC id field.
        XCTAssertLessThanOrEqual(framed - 1, 1_000)
    }
}

