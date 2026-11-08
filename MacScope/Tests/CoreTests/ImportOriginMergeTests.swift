import Foundation
import XCTest
@testable import MacScope

/// DC1 slice A (A4, A5): the load-metadata merge keeps every producer origin, and legacy
/// metadata (no origins, no export namespace) still decodes and re-encodes without new keys.
final class ImportOriginMergeTests: XCTestCase {
    private func makeFile(
        imports: [MachOImport], chained: [MachOChainedImport], exports: [MachOExport] = [],
        exportComplete: Bool = true
    ) -> MachOFile {
        let fixups = MachODyldChainedFixups(
            dataOffset: 0, dataSize: 0, fixupsVersion: 0, startsOffset: 0, importsOffset: 0,
            symbolsOffset: 0, importsCount: 0, importsFormat: 0, symbolsFormat: 0,
            imports: chained, fixups: []
        )
        let dylib = MachODylib(
            name: "/usr/lib/libSystem.B.dylib", ordinal: 1,
            command: MachOConstants.loadCommandLoadDylib, pathKind: .systemAbsolute, timestamp: 0,
            currentVersion: MachODylibVersion(encodedValue: 0x00010003),
            compatibilityVersion: MachODylibVersion(encodedValue: 0x00010000)
        )
        var file = MachOFile(
            header: MachOHeader(magic: 0, cpuType: 0, cpuSubtype: 0, fileType: 0, loadCommandCount: 0,
                                loadCommandsSize: 0, flags: 0, reserved: 0),
            loadCommands: [], segments: [], sections: [], dylibs: [dylib], rpaths: [], symbols: [],
            imports: imports, indirectSymbols: [], relocations: [], exports: exports,
            stringLiterals: [], objectiveCMetadata: .empty, swiftMetadataSections: [],
            exceptionMetadata: .empty, functionStarts: [], dataInCodeEntries: [], uuid: nil,
            buildVersion: nil, sourceVersion: nil, legacyMinimumOSVersion: nil, codeSignature: nil,
            dyldChainedFixups: fixups, entryPointOffset: nil, entryPointVirtualAddress: nil,
            selectedSliceOffset: 0, universalBinary: nil
        )
        file.exportRecoveryComplete = exportComplete
        return file
    }

    func testA4MergedDuplicateKeepsBothProducerOrigins() {
        let file = makeFile(
            imports: [MachOImport(symbolIndex: 1, name: "f", libraryOrdinal: 1, libraryName: nil, isWeakReference: true)],
            chained: [MachOChainedImport(index: 0, name: "f", libraryOrdinal: 1, libraryName: nil,
                                         isWeakImport: false, addend: 0, encodedLibraryOrdinal: 1)]
        )
        let symbols = MachOLoadMetadata.from(file).importedSymbols
        XCTAssertEqual(symbols.count, 1)
        XCTAssertEqual(symbols[0].source, "dyld fixup")
        XCTAssertEqual(symbols[0].origins, [
            ImportOrigin(encoding: .chainedFixup, rawOrdinal: 1, isWeak: false, tableIndex: 0),
            ImportOrigin(encoding: .nlistDesc, rawOrdinal: 1, isWeak: true, tableIndex: 1),
        ])
    }

    func testA5EncodingsStayDistinctAndNamespaceIsRecorded() {
        // Chained weak-lookup (-3, no nlist-style ordinal) and nlist flat lookup (0xfe)
        // for the same name must not collapse, and each keeps its own encoding.
        let exportTerminal = MachOExport(symbolIndex: nil, name: "e", address: 1, flags: 0, source: "s")
        let reexportTerminal = MachOExport(symbolIndex: nil, name: "r", address: nil, flags: 8, source: "s",
                                           reexport: MachOExportReexport(ordinal: 1, importedName: nil))
        let file = makeFile(
            imports: [MachOImport(symbolIndex: 1, name: "g",
                                  libraryOrdinal: MachOConstants.dynamicLookupLibraryOrdinal, libraryName: nil)],
            chained: [MachOChainedImport(index: 0, name: "g", libraryOrdinal: nil, libraryName: nil,
                                         isWeakImport: true, addend: 0, encodedLibraryOrdinal: -3)],
            exports: [exportTerminal, reexportTerminal], exportComplete: false
        )
        let metadata = MachOLoadMetadata.from(file)
        XCTAssertEqual(metadata.importedSymbols.count, 2)
        let all = metadata.importedSymbols.flatMap(\.origins)
        XCTAssertTrue(all.contains(ImportOrigin(encoding: .chainedFixup, rawOrdinal: -3, isWeak: true, tableIndex: 0)))
        XCTAssertTrue(all.contains(ImportOrigin(encoding: .nlistDesc, rawOrdinal: 0xfe, isWeak: false, tableIndex: 1)))
        XCTAssertEqual(metadata.exportNamespace,
                       ExportNamespaceSummary(complete: false, terminalCount: 2, reexportCount: 1))
    }

    func testA5DistinctNlistRowsWithSameNameEncodingAndOrdinalKeepTwoOrigins() {
        let file = makeFile(
            imports: [
                MachOImport(symbolIndex: 5, name: "h", libraryOrdinal: 1, libraryName: nil, rawLibraryOrdinal: 1),
                MachOImport(symbolIndex: 9, name: "h", libraryOrdinal: 1, libraryName: nil, rawLibraryOrdinal: 1),
            ],
            chained: []
        )
        let symbols = MachOLoadMetadata.from(file).importedSymbols
        XCTAssertEqual(symbols.count, 1)
        XCTAssertEqual(symbols[0].origins.map(\.tableIndex), [5, 9])
        XCTAssertEqual(Set(symbols[0].origins).count, 2)
    }

    func testF2NlistRawOrdinalZeroKeepsSelfImageOrigin() {
        // The parser maps raw n_desc ordinal 0 to a nil libraryOrdinal; the origin must keep the raw 0.
        let file = makeFile(
            imports: [MachOImport(symbolIndex: 3, name: "s", libraryOrdinal: nil, libraryName: nil,
                                  rawLibraryOrdinal: 0)],
            chained: []
        )
        let metadata = MachOLoadMetadata.from(file)
        XCTAssertEqual(metadata.importedSymbols[0].origins,
                       [ImportOrigin(encoding: .nlistDesc, rawOrdinal: 0, isWeak: false, tableIndex: 3)])
        let entries = ImportResolutionRequestBuilder.build(from: metadata)
        XCTAssertEqual(entries.map(\.outcome), [.miss(.selfImage)])
    }

    func testLegacyMetadataRoundTripsWithoutNewKeys() throws {
        let legacy = #"{"importedSymbols":[{"name":"x","isWeak":false,"source":"import table"}],"dependentDylibs":[]}"#
        let decoded = try JSONDecoder().decode(MachOLoadMetadata.self, from: Data(legacy.utf8))
        XCTAssertEqual(decoded.importedSymbols[0].origins, [])
        XCTAssertNil(decoded.exportNamespace)
        let reencoded = String(decoding: try JSONEncoder().encode(decoded), as: UTF8.self)
        XCTAssertFalse(reencoded.contains("origins"))
        XCTAssertFalse(reencoded.contains("exportNamespace"))
    }
}
