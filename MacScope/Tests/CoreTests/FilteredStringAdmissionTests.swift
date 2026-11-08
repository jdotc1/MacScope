import Foundation
import XCTest
@testable import MacScope

@MainActor
final class FilteredStringAdmissionTests: XCTestCase {
    private func store(_ values: [String]) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.stringLiterals = values.enumerated().map { index, value in
            StringLiteralSummary(id: UUID(), value: value, address: UInt64(index + 1),
                                 sourceSection: "__TEXT,__cstring", byteLength: value.utf8.count)
        }
        return WorkspaceStore(workspaceName: "string-admission",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    func testLimitedDirectReadStopsBeforeIrrelevantOversizedCandidate() throws {
        let api = WorkspaceScriptingAPI(store: store(["match", String(repeating: "x", count: 4_097)]))
        let direct = try api.execute("strings", arguments: .object(["contains": .string("match"), "limit": .int(1)]))
        XCTAssertEqual(direct.arrayValue?.first?["value"], .string("match"))
        XCTAssertThrowsError(try api.execute("strings", arguments: .object([
            "contains": .string("match"), "page": .bool(true), "limit": .int(1)
        ])))
    }

    func testFilteredPagesKeepOriginalOffsetsAndTotals() throws {
        let api = WorkspaceScriptingAPI(store: store(["match one", "skip", "match two"]))
        let first = try api.execute("strings", arguments: .object([
            "contains": .string("match"), "page": .bool(true), "limit": .int(1)
        ]))
        XCTAssertEqual(first["total"], .int(2))
        XCTAssertEqual(first["rows"]?.arrayValue?.first?["value"], .string("match one"))
        let next = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let second = try api.execute("strings", arguments: .object([
            "contains": .string("match"), "page": .bool(true), "limit": .int(1), "cursor": .string(next)
        ]))
        XCTAssertEqual(second["total"], .int(2))
        XCTAssertEqual(second["rows"]?.arrayValue?.first?["value"], .string("match two"))
        XCTAssertEqual(second["nextCursor"], .null)
    }

    func testFilteredStringUTF8Boundary() throws {
        let exact = String(repeating: "é", count: 2_048)
        let api = WorkspaceScriptingAPI(store: store([exact]))
        let result = try api.execute("strings", arguments: .object(["contains": .string("é")]))
        XCTAssertEqual(result.arrayValue?.count, 1)
        let tooLong = WorkspaceScriptingAPI(store: store([exact + "a"]))
        XCTAssertThrowsError(try tooLong.execute("strings", arguments: .object(["contains": .string("é")])))
    }
}
