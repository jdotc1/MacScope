import Foundation
import XCTest
@testable import MacScope

/// DC1 slice A (A6, A7): the new import-origin and export re-export/resolver fields survive a
/// database round trip and the 45 -> 46 migration adds nullable columns without touching content.
final class ImportResolutionPersistenceTests: XCTestCase {
    private let importWithOrigin = UUID(uuidString: "A0000000-0000-0000-0000-000000000001")!
    private let importLegacy = UUID(uuidString: "A0000000-0000-0000-0000-000000000002")!
    private let exportReexport = UUID(uuidString: "A0000000-0000-0000-0000-000000000003")!
    private let exportResolver = UUID(uuidString: "A0000000-0000-0000-0000-000000000004")!
    private let exportPlain = UUID(uuidString: "A0000000-0000-0000-0000-000000000005")!

    private func snapshot() -> WorkspaceSnapshot {
        let binary = BinaryImage(
            id: UUID(uuidString: "B0000000-0000-0000-0000-000000000001")!,
            name: "dc1", path: "/missing/dc1", kind: "synthetic fixture", architecture: "arm64",
            selectedSliceIndex: 0, slot: .primary
        )
        var analysis = ImageAnalysis()
        let bytes = Data((0..<5_000).map { UInt8(truncatingIfNeeded: $0) })
        analysis.imageBytes = bytes
        analysis.hexBytes = Data(bytes.prefix(WorkspaceSnapshot.hexViewByteWindow))
        analysis.imports = [
            ImportSummary(id: importWithOrigin, name: "_with", libraryName: "/usr/lib/libSystem.B.dylib",
                          libraryOrdinal: 1,
                          origin: ImportOrigin(encoding: .chainedFixup, rawOrdinal: -3, isWeak: true, tableIndex: 41)),
            ImportSummary(id: importLegacy, name: "_legacy", libraryName: nil, libraryOrdinal: nil),
        ]
        analysis.exports = [
            ExportSummary(id: exportReexport, name: "_re", address: nil, source: "LC_DYLD_EXPORTS_TRIE",
                          terminalFlags: 0x08, reexportOrdinal: 2, reexportImportedName: "_target"),
            ExportSummary(id: exportResolver, name: "_res", address: 0x1_0000_0020, source: "LC_DYLD_EXPORTS_TRIE",
                          terminalFlags: 0x10, resolverOffset: 0x40),
            ExportSummary(id: exportPlain, name: "_plain", address: 0x1_0000_0030, source: "LC_DYLD_EXPORTS_TRIE",
                          terminalFlags: 0),
        ]
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }

    func testA6DatabaseRoundTripKeepsOriginReexportAndResolverFields() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let source = snapshot()
        let workspace = try database.saveSnapshot(workspaceName: "DC1", snapshot: source)
        let restored = try XCTUnwrap(database.loadSnapshot(workspaceID: XCTUnwrap(workspace.id)))
        let analysis = try XCTUnwrap(restored.analysis(in: .primary))
        XCTAssertEqual(analysis.imports, source.analysis(in: .primary)?.imports)
        XCTAssertEqual(analysis.exports, source.analysis(in: .primary)?.exports)
        XCTAssertEqual(analysis.imports.first { $0.id == importWithOrigin }?.origin?.rawOrdinal, -3)
        XCTAssertEqual(analysis.imports.first { $0.id == importWithOrigin }?.origin?.tableIndex, 41)
        XCTAssertNil(analysis.imports.first { $0.id == importLegacy }?.origin)
        XCTAssertEqual(analysis.exports.first { $0.id == exportReexport }?.reexportImportedName, "_target")
        XCTAssertEqual(analysis.exports.first { $0.id == exportResolver }?.resolverOffset, 0x40)
    }

    func testF1TableIndexSurvivesSaveLoadAndUUIDRemap() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var source = snapshot()
        source.mutateAnalysis(in: .primary) { analysis in
            analysis.imports.append(ImportSummary(
                id: UUID(uuidString: "A0000000-0000-0000-0000-000000000006")!, name: "_with",
                libraryName: "/usr/lib/libSystem.B.dylib", libraryOrdinal: 1,
                origin: ImportOrigin(encoding: .nlistDesc, rawOrdinal: 1, isWeak: false, tableIndex: 9)))
        }
        let state = try database.saveWorkspaceState(
            workspaceName: "F1", snapshot: source, selectedSidebarItemID: nil, selectedAddress: nil,
            selectedTool: .project, editorMode: .disassembly, isInspectorPresented: true,
            sidebarSearchText: "", focusedImageSlot: .primary, now: Date(timeIntervalSince1970: 1_800_000_000))
        let workspaceID = try XCTUnwrap(state.workspace.id)
        let loaded = try XCTUnwrap(database.loadSnapshot(workspaceID: workspaceID))
        XCTAssertEqual(loaded.analysis(in: .primary)?.imports.compactMap(\.origin?.tableIndex).sorted(), [9, 41])

        let packageURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("DC1-\(UUID().uuidString)")
            .appendingPathExtension(MacScopeDocumentPackage.fileExtension)
        defer { try? FileManager.default.removeItem(at: packageURL) }
        _ = try database.writePackage(workspaceID: workspaceID, documentID: UUID(), to: packageURL)
        let imported = try database.importPackage(from: packageURL)
        let remapped = try XCTUnwrap(imported.snapshot.analysis(in: .primary)?.imports)
        XCTAssertEqual(Set(remapped.map(\.id)).intersection([importWithOrigin, importLegacy]), [],
                       "importing back into the source database must remap import UUIDs")
        XCTAssertEqual(remapped.map(\.origin), source.analysis(in: .primary)?.imports.map(\.origin))
        XCTAssertEqual(remapped.compactMap(\.origin?.tableIndex).sorted(), [9, 41])
    }

    func testA6JSONCodableRoundTripKeepsNewFields() throws {
        let analysis = try XCTUnwrap(snapshot().analysis(in: .primary))
        let imports = try JSONDecoder().decode([ImportSummary].self, from: JSONEncoder().encode(analysis.imports))
        let exports = try JSONDecoder().decode([ExportSummary].self, from: JSONEncoder().encode(analysis.exports))
        XCTAssertEqual(imports, analysis.imports)
        XCTAssertEqual(exports, analysis.exports)
    }

    func testA7Version45MigrationAddsNullableColumnsAndKeepsContent() throws {
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        var legacy = snapshot()
        legacy.mutateAnalysis(in: .primary) { analysis in
            // Rows that never had the new data: a v45 database cannot hold anything else.
            analysis.imports = analysis.imports.map { var copy = $0; copy.origin = nil; return copy }
            analysis.exports = analysis.exports.map {
                var copy = $0; copy.reexportOrdinal = nil; copy.reexportImportedName = nil
                copy.resolverOffset = nil; return copy
            }
        }
        let workspace = try database.saveSnapshot(workspaceName: "Legacy v45", snapshot: legacy)
        for column in ["origin_encoding", "origin_raw_ordinal", "origin_is_weak", "origin_table_index"] {
            try database.executeRawForTesting("ALTER TABLE imports DROP COLUMN \(column);")
        }
        for column in ["reexport_ordinal", "reexport_imported_name", "resolver_offset"] {
            try database.executeRawForTesting("ALTER TABLE exports DROP COLUMN \(column);")
        }
        try database.setUserVersionForTesting(45)

        try database.applySchema()
        XCTAssertEqual(try database.userVersion(), 46)
        XCTAssertTrue(Set(try database.columnNames(in: "imports")).isSuperset(of:
            ["origin_encoding", "origin_raw_ordinal", "origin_is_weak", "origin_table_index"]))
        XCTAssertTrue(Set(try database.columnNames(in: "exports")).isSuperset(of:
            ["reexport_ordinal", "reexport_imported_name", "resolver_offset"]))

        let restored = try XCTUnwrap(database.loadSnapshot(workspaceID: XCTUnwrap(workspace.id)))
        XCTAssertEqual(restored.analysis(in: .primary)?.imports, legacy.analysis(in: .primary)?.imports)
        XCTAssertEqual(restored.analysis(in: .primary)?.exports, legacy.analysis(in: .primary)?.exports)

        // Idempotent: a second pass neither re-adds columns nor changes the version.
        try database.applySchema()
        XCTAssertEqual(try database.userVersion(), 46)
    }
}
