import Foundation
import XCTest
@testable import MacScope

/// DC1 acceptance harness: the scoring-table builder over the existing synthetic cache fixtures.
/// Nothing here reads the host's real dyld cache or any app.
final class DyldCacheImportScoringTableTests: XCTestCase {
    private var directory: URL!
    private let libx = "/usr/lib/libx.dylib"
    private let libGone = "/usr/lib/libgone.dylib"

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc1-scoring-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    private func request(_ symbol: String, install: String, ordinal: Int, tableIndex: Int, weak: Bool = false) -> ImportResolutionEntry {
        let origin = ImportOrigin(encoding: .nlistDesc, rawOrdinal: ordinal, isWeak: weak, tableIndex: tableIndex)
        return ImportResolutionEntry(
            symbolName: symbol, origin: origin,
            outcome: .request(ImportResolutionRequest(
                symbolName: symbol, origin: origin, dependencyOrdinal: ordinal, installName: install,
                dependencyKind: "required", isWeakImport: weak)))
    }

    private func dylib(_ path: String, ordinal: Int) -> MachOLoadMetadata.DependentDylib {
        MachOLoadMetadata.DependentDylib(path: path, kind: "required", currentVersion: "1.0.0",
                                         compatibilityVersion: "1.0.0", ordinal: ordinal)
    }

    private func entries() -> [ImportResolutionEntry] {
        let flat = ImportOrigin(encoding: .nlistDesc, rawOrdinal: MachOConstants.dynamicLookupLibraryOrdinal,
                                isWeak: false, tableIndex: 4)
        return [
            request("_f", install: libx, ordinal: 1, tableIndex: 0),
            request("_nope", install: libx, ordinal: 1, tableIndex: 1),
            request("_h", install: libGone, ordinal: 2, tableIndex: 2),
            ImportResolutionEntry(symbolName: "_flat", origin: flat, outcome: .miss(.flatLookup)),
            ImportResolutionEntry(symbolName: "_legacy", origin: nil, outcome: .miss(.noOriginRecorded)),
        ]
    }

    private func table(_ batch: ImportResolutionBatch, _ entries: [ImportResolutionEntry]) -> DyldCacheImportScoringTable {
        DyldCacheImportScoringTable.build(
            importer: "/synthetic/app", architecture: "arm64", entries: entries, batch: batch,
            dependencies: [dylib(libx, ordinal: 1), dylib(libGone, ordinal: 2)])
    }

    func testTableHasOneRowPerImportAndCountsSumToTheTotal() throws {
        var cache = SynthCache(images: [
            SynthImage(path: libx, exports: [("_f", .regular(0x1000))], infoExports: nil),
        ])
        cache.images[0].uuidByte = 0x10
        let cacheDirectory = directory.appendingPathComponent("cache", isDirectory: true)
        try FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        _ = try SynthCacheWriter.write(cache, into: cacheDirectory)
        let input = entries()
        let batch = DyldCacheImportResolver.resolve(
            entries: input, importerArchitecture: "arm64",
            locator: HostCacheLocator(candidateDirectories: [cacheDirectory]))
        let scored = table(batch, input)

        XCTAssertEqual(scored.importTotal, 5)
        XCTAssertEqual(scored.rows.map(\.index), [0, 1, 2, 3, 4])
        XCTAssertTrue(scored.countsSumToTotal)
        XCTAssertEqual(scored.outcomeCounts["resolved"], 1)
        XCTAssertEqual(scored.outcomeCounts["notExported"], 1)
        XCTAssertEqual(scored.outcomeCounts["notCacheResident"], 3)
        XCTAssertEqual(scored.outcomeCounts["cacheUnavailable"], 0)
        XCTAssertEqual(scored.outcomeCounts["reexportChain"], 0)
        XCTAssertEqual(scored.outcomeCounts["ambiguous"], 0)

        let load = SynthCacheWriter.loadAddress(ofImage: 0)
        let hit = scored.rows[0]
        XCTAssertEqual(hit.outcome, "resolved")
        XCTAssertEqual(hit.resolvedImage, libx)
        XCTAssertEqual(hit.resolvedAddress, "0x" + String(load + 0x1000, radix: 16))
        XCTAssertEqual(hit.addressDomain, "cacheUnslidVM")
        XCTAssertEqual(hit.originImage, libx)
        XCTAssertEqual(hit.namespace, "dependency(1)")
        XCTAssertEqual(scored.rows[1].outcome, "notExported")
        XCTAssertNil(scored.rows[1].resolvedAddress)
        XCTAssertEqual(scored.rows[2].subreason, "installNameNotInCache")
        XCTAssertEqual(scored.rows[2].detail, libGone)
        XCTAssertEqual(scored.rows[3].namespace, "flatLookup")
        XCTAssertEqual(scored.rows[3].subreason, "flatLookup")
        XCTAssertEqual(scored.rows[4].namespace, "noOrigin")
        XCTAssertEqual(scored.rows[4].subreason, "noOriginRecorded")
        XCTAssertEqual(scored.cacheUUID, SynthCacheWriter.mainUUID.map { String(format: "%02x", $0) }.joined())

        let decoded = try JSONDecoder().decode(DyldCacheImportScoringTable.self, from: scored.encoded())
        XCTAssertEqual(decoded, scored)
    }

    func testMissingCacheTypesEveryRequestRowAsUnavailableAndStillSumsToTheTotal() throws {
        let emptyDirectory = directory.appendingPathComponent("none", isDirectory: true)
        try FileManager.default.createDirectory(at: emptyDirectory, withIntermediateDirectories: true)
        let input = entries()
        let batch = DyldCacheImportResolver.resolve(
            entries: input, importerArchitecture: "arm64",
            locator: HostCacheLocator(candidateDirectories: [emptyDirectory]))
        let scored = table(batch, input)
        XCTAssertTrue(scored.countsSumToTotal)
        XCTAssertEqual(scored.outcomeCounts["cacheUnavailable"], 3)
        XCTAssertEqual(scored.outcomeCounts["notCacheResident"], 2)
        XCTAssertEqual(scored.outcomeCounts["resolved"], 0)
        XCTAssertNil(scored.cacheUUID)
        XCTAssertEqual(scored.rows[0].subreason, "notPresent")
    }
}
