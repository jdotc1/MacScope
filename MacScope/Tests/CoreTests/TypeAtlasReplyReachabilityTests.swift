import Foundation
import XCTest
@testable import MacScope

// Authored, unrun. Add as MacScope/Tests/CoreTests/TypeAtlasReplyReachabilityTests.swift.
@MainActor
final class TypeAtlasReplyReachabilityTests: XCTestCase {
    func testPrefixContinuationUsesOriginalFilteredIndices() async throws {
        // RED prediction: pin lacks nextCursor; alternating kinds catch renumbered offsets.
        var entries = (0..<1_200).map(TypeAtlasReplyTestHarness.small)
        for i in stride(from: 1, to: entries.count, by: 2) {
            entries[i].kind = .objcProtocol; entries[i].id.kind = .objcProtocol
        }
        // Larger names force a prefix even though only 600 rows match the kind.
        for i in entries.indices { entries[i].name += String(repeating: "x", count: 100) }
        let harness = TypeAtlasReplyTestHarness(entries)
        let first = try await harness.read(.inline, .object(["kind": .string("objcClass")]))
        var rows = try XCTUnwrap(first["types"]?.arrayValue)
        var cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        var seen = Set<String>()
        while true {
            guard seen.insert(cursor).inserted else {
                return XCTFail("cursor must advance")
            }
            let page = try await harness.read(.inline, .object([
                "kind": .string("objcClass"), "page": .bool(true),
                "fields": .string("full"), "limit": .int(1), "cursor": .string(cursor)]))
            let next = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(next.count, 1)
            XCTAssertNil(page["vtableSummaryVersion"])
            XCTAssertNil(next[0]["unnamedVtableSlots"])
            rows.append(contentsOf: next)
            guard rows.count <= 600 else {
                return XCTFail("filtered continuation exceeded its whole-filter total")
            }
            if page["nextCursor"] == .null { break }
            cursor = try XCTUnwrap(page["nextCursor"]?.stringValue)
        }
        XCTAssertEqual(rows, entries.filter { $0.kind == .objcClass }.map(WorkspaceScriptingAPI.typeAtlasEntryValue))
    }

    func testSymbolProtected53RowVariantContinuesWithoutGaps() async throws {
        // Variant, not the ordinary V-complete fixture. Symbol evidence protects even
        // a name identical to the positional label. RED prediction: pin has no cursor.
        var entries = try SyntheticTypeAtlasReplyFixture.entries()
        for row in entries.indices {
            for method in entries[row].methods.indices {
                guard var metadata = entries[row].methods[method].swiftMetadata else { continue }
                metadata.implementationSymbol = .init(rawLinkageName: "synthetic_\(row)_\(method)",
                    name: entries[row].methods[method].name)
                entries[row].methods[method].swiftMetadata = metadata
            }
        }
        let harness = TypeAtlasReplyTestHarness(entries)
        let expected = try XCTUnwrap(harness.original()["types"]?.arrayValue)
        let first = try await harness.read(.inline)
        var rows = try XCTUnwrap(first["types"]?.arrayValue)
        XCTAssertFalse(rows.isEmpty)
        XCTAssertLessThan(rows.count, 53)
        XCTAssertEqual(first["isTruncated"], .bool(true))
        XCTAssertNil(first["vtableSummaryVersion"])
        var cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        var cursors = Set<String>()
        while true {
            guard cursors.insert(cursor).inserted else {
                return XCTFail("cursor must advance")
            }
            let page = try await harness.read(.inline, .object([
                "page": .bool(true), "fields": .string("full"), "limit": .int(1), "cursor": .string(cursor)]))
            let next = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(next.count, 1)
            rows.append(contentsOf: next)
            guard rows.count <= 53 else {
                return XCTFail("continuation returned more than 53 rows")
            }
            if page["nextCursor"] == .null { break }
            cursor = try XCTUnwrap(page["nextCursor"]?.stringValue)
        }
        XCTAssertEqual(rows, expected)
        XCTAssertEqual(rows.count, 53)
    }

    func testInvariantFullFixturePagesRecoverEveryRowAndPair() async throws {
        // Invariant/control. V-complete default has no cursor, so full recovery starts page:true.
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let original = try harness.original()
        let expected = try XCTUnwrap(original["types"]?.arrayValue)
        var rows: [ScriptValue] = []
        var cursor: String? = nil
        repeat {
            var args: [String: ScriptValue] = ["page": .bool(true), "fields": .string("full"), "limit": .int(1)]
            if let cursor { args["cursor"] = .string(cursor) }
            let page = try await harness.read(.inline, .object(args))
            let pageRows = try XCTUnwrap(page["rows"]?.arrayValue)
            XCTAssertEqual(pageRows.count, 1)
            XCTAssertNil(pageRows[0]["unnamedVtableSlots"])
            XCTAssertNil(page["vtableSummaryVersion"])
            XCTAssertNil(pageRows[0]["fullRowOmitted"])
            rows.append(contentsOf: pageRows)
            guard rows.count <= 53 else {
                return XCTFail("full-page stream returned more than 53 rows")
            }
            cursor = page["nextCursor"]?.stringValue
            for version in [MCPResultProtocol.legacy, .structured] {
                XCTAssertLessThanOrEqual(try mcpToolReplyJSONByteCount(output: page, tool: "list-image-types",
                    generation: syntheticTypeAtlasGeneration(), protocolVersion: version, id: .int(5)) + 1, 180_000)
            }
        } while cursor != nil
        XCTAssertEqual(rows, expected)
        XCTAssertEqual(rows.count, 53)
        XCTAssertEqual(rows[0]["members"]?.arrayValue?.count, 83)
        XCTAssertEqual(rows[27]["members"], .array([]))
        XCTAssertEqual(rows[27]["membersListedOn"], rows[0]["id"])
        XCTAssertEqual(rows[27]["objcId"], rows[0]["id"])
        XCTAssertEqual(original["swiftObjCLinks"]?["linked"], .int(19))
        XCTAssertEqual(original["swiftObjCLinks"]?["membersNotMerged"], .int(0))
    }

    func testInvariantEachSyntheticKindAndExactNameRecoversFullRow() async throws {
        let harness = TypeAtlasReplyTestHarness(try SyntheticTypeAtlasReplyFixture.entries())
        let expected = try XCTUnwrap(harness.original()["types"]?.arrayValue)
        for (index, entry) in harness.entries.enumerated() {
            let page = try await harness.read(.inline, .object([
                "page": .bool(true), "fields": .string("full"), "limit": .int(1),
                "kind": .string(entry.kind.rawValue), "name": .string(entry.name)]))
            XCTAssertEqual(page["rows"], .array([expected[index]]))
            XCTAssertNil(page["rows"]?.arrayValue?.first?["fullRowOmitted"])
        }
    }

    func testInternalCompleteRetainsLateExactIdentity() throws {
        // Invariant/control on pin. Guards against accidentally routing exact reads through prefix.
        let entries = (0..<1_200).map(TypeAtlasReplyTestHarness.small)
        let harness = TypeAtlasReplyTestHarness(entries)
        let selector = ExactClassReadSelector(owner: .init(slot: .primary,
            binaryID: TypeAtlasReplyTestHarness.owner, architecture: "arm64", sliceIndex: nil,
            ownerGeneration: 0), entryID: entries[1_199].id)
        let value = try WorkspaceScriptingAPI.exactClassRead(selector: selector, snapshot: harness.snapshot)
        XCTAssertEqual(value["status"], .string("found"))
        XCTAssertEqual(value["class"], WorkspaceScriptingAPI.typeAtlasEntryValue(entries[1_199]))
        let complete = try WorkspaceScriptingAPI.snapshotTypeListRead("list-image-types",
            arguments: .object(["limit": .int(5_000)]), snapshot: harness.snapshot,
            swiftObjCLinks: false, mode: .internalComplete)
        XCTAssertEqual(complete["types"]?.arrayValue?.count, 1_200)
        XCTAssertNil(complete["isTruncated"])
    }

    func testVClassifierContiguityNamedMethodsAndFallback() throws {
        // Invariant specification for the new pure classifier; absent API is not a red assertion.
        func method(_ index: UInt64, named: Bool = false) -> TypeAtlasMethod {
            var metadata = SwiftMetadataMethod(source: .vtable, index: index,
                descriptorAddress: 8_000, implementation: nil, flags: 16)
            if named { metadata.implementationSymbol = .init(rawLinkageName: "synthetic_symbol", name: "kept") }
            return .init(name: metadata.name, implementation: nil, swiftMetadata: metadata)
        }
        var entry = TypeAtlasReplyTestHarness.small(0)
        entry.kind = .swiftClass; entry.id.kind = .swiftClass
        entry.methods = [method(0), method(1), method(2, named: true)]
        let summary = try TypeAtlasDefaultReplyPolicy.summarized(entry, checkpoint: {})
        XCTAssertEqual(summary.slots, 2)
        XCTAssertEqual(summary.entry.methods, [entry.methods[2]])
        XCTAssertEqual(WorkspaceScriptingAPI.typeAtlasEntryValue(summary.entry)["methods"],
            .array([WorkspaceScriptingAPI.typeAtlasEntryValue(entry)["methods"]!.arrayValue![2]]))
        let invalidSets: [[UInt64]] = [[1], [0, 2], [0, 0], [0, 1, 4], [UInt64.max]]
        for indices in invalidSets {
            entry.methods = indices.map { method($0) }
            let unchanged = try TypeAtlasDefaultReplyPolicy.summarized(entry, checkpoint: {})
            XCTAssertEqual(unchanged.slots, 0)
            XCTAssertEqual(unchanged.entry, entry)
        }
        entry.methods = [method(0)]; entry.methods[0].name = "kept"
        XCTAssertEqual(try TypeAtlasDefaultReplyPolicy.summarized(entry, checkpoint: {}).entry, entry)
        entry.methods = [method(0)]; entry.methods[0].swiftMetadata?.source = .witness
        XCTAssertEqual(try TypeAtlasDefaultReplyPolicy.summarized(entry, checkpoint: {}).entry, entry)
        entry.methods = [method(0)]; entry.methods[0].swiftMetadata = nil
        XCTAssertEqual(try TypeAtlasDefaultReplyPolicy.summarized(entry, checkpoint: {}).entry, entry)
    }

    func testFirstOversizedNamedRowIsStructuredRefusal() throws {
        // RED prediction: inline pin emits the oversized row, so XCTAssertThrowsError fails.
        var entry = TypeAtlasReplyTestHarness.small(0)
        entry.name = "SyntheticOversized"
        entry.methods = (0..<100).map { index in
            TypeAtlasMethod(name: String(repeating: "n", count: 2_000) + String(index), implementation: nil)
        }
        let harness = TypeAtlasReplyTestHarness([entry])
        XCTAssertThrowsError(try harness.api.execute("list-image-types")) { error in
            guard let scripting = error as? ScriptingError,
                  case .structuredRefusal(let refusal) = scripting else {
                return XCTFail("Expected structured refusal, not empty success or another error")
            }
            XCTAssertTrue(refusal.detail.contains("SyntheticOversized"))
            XCTAssertTrue(refusal.detail.contains("\"page\":true"))
            XCTAssertTrue(refusal.detail.contains("full"))
            XCTAssertTrue(refusal.detail.contains("index 0"))
            XCTAssertTrue(refusal.detail.hasSuffix(WorkspaceScriptingAPI.typeAtlasPageHint))
        }
    }
}
