import Foundation
import XCTest
@testable import MacScope

@MainActor
final class TypeAtlasUnpagedAdmissionTests: XCTestCase {
    func testExactLimitAndMalformedValues() throws {
        let parse = WorkspaceScriptingAPI.exactUnpagedAtlasLimit
        XCTAssertNil(try parse(.object([:])))
        XCTAssertNil(try parse(.object(["limit": .null])))
        XCTAssertEqual(try parse(.object(["limit": .int(-1)])), -1)
        XCTAssertEqual(try parse(.object(["limit": .double(2)])), 2)
        for value in [ScriptValue.double(1.5), .double(.infinity), .double(Double(Int64.max)), .string("2"), .bool(true)] {
            XCTAssertThrowsError(try parse(.object(["limit": value])))
        }
    }

    func testUnpagedRoutesPreserveDefaultsAndRejectInvalidLimit() async throws {
        let entries = ["First", "Second", "Third"].map { name in
            TypeAtlasEntry(id: .init(slot: .primary, kind: .objcClass, key: .name(name)),
                kind: .objcClass, name: name, superclass: nil, members: [], conformances: [],
                methods: [], users: [], evidence: .descriptor)
        }
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        let snapshot = WorkspaceSnapshot(binaries: [BinaryImage(id: UUID(), name: "atlas",
            path: "/unused/atlas", kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: analysis])
        let store = WorkspaceStore(workspaceName: "Atlas admission", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        for (value, count) in [(ScriptValue.null, 3), (.int(-1), 0), (.double(2), 2)] {
            let arguments = ScriptValue.object(["limit": value])
            let direct = try api.execute("list-image-types", arguments: arguments)
            let asyncResult = try await api.executeAsync("list-image-types", arguments: arguments)
            XCTAssertEqual(direct["types"]?.arrayValue?.count, count)
            XCTAssertEqual(asyncResult["types"]?.arrayValue?.count, count)
            XCTAssertEqual(direct["total"], .int(3))
            XCTAssertEqual(asyncResult["total"], .int(3))
        }
        let malformed = ScriptValue.object(["limit": .double(1.5)])
        XCTAssertThrowsError(try api.execute("list-image-types", arguments: malformed))
        do {
            _ = try await api.executeAsync("list-image-types", arguments: malformed)
            XCTFail("Expected a malformed limit refusal")
        } catch let error as ScriptingError {
            XCTAssertEqual(error, .invalidArgument("limit must be an exact integer in the Int64 range"))
        }
        let unrelated = try api.execute("list-types")
        XCTAssertEqual(try api.execute("list-types", arguments: malformed), unrelated)
    }
}
