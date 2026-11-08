import Foundation
import XCTest
@testable import MacScope

/// DC1 slice B (B1-B17): the host shared-cache import resolver against crafted cache bytes.
/// Every cache here is synthetic; nothing reads the host's real dyld cache.
final class DyldCacheImportResolutionTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc1-slice-b-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    // MARK: Helpers

    private func bytes(_ path: String) -> [UInt8] { Array(path.utf8) }

    private func image(
        _ path: String, deps: [(String, SynthImage.DepKind)] = [],
        exports: [(String, SynthTerminal)] = [], info: [(String, SynthTerminal)]? = nil
    ) -> SynthImage {
        SynthImage(path: path, dependencies: deps, exports: exports, infoExports: info)
    }

    private func numbered(_ images: [SynthImage]) -> [SynthImage] {
        images.enumerated().map { index, item in
            var copy = item
            if copy.uuidByte == 0 { copy.uuidByte = UInt8(0x10 + index) }
            return copy
        }
    }

    private func writeCache(_ cache: SynthCache, subdirectory: String = "cache") throws -> (dir: URL, main: URL) {
        let dir = directory.appendingPathComponent(subdirectory, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var numberedCache = cache
        numberedCache.images = numbered(cache.images)
        return (dir, try SynthCacheWriter.write(numberedCache, into: dir))
    }

    private func entry(
        _ symbol: String, from install: String, weak: Bool = false, tableIndex: Int = 0, ordinal: Int = 1
    ) -> ImportResolutionEntry {
        let origin = ImportOrigin(encoding: .nlistDesc, rawOrdinal: ordinal, isWeak: weak, tableIndex: tableIndex)
        return ImportResolutionEntry(
            symbolName: symbol, origin: origin,
            outcome: .request(ImportResolutionRequest(
                symbolName: symbol, origin: origin, dependencyOrdinal: ordinal, installName: install,
                dependencyKind: "required", isWeakImport: weak)))
    }

    private func resolve(
        _ cache: SynthCache, _ entries: [ImportResolutionEntry],
        limits: DyldCacheImportResolutionLimits = .production,
        isCancelled: @escaping () -> Bool = { false },
        rowObserver: ((Int) -> Void)? = nil, subdirectory: String = "cache"
    ) throws -> ImportResolutionBatch {
        let written = try writeCache(cache, subdirectory: subdirectory)
        return DyldCacheImportResolver.resolve(
            entries: entries, importerArchitecture: "arm64",
            locator: HostCacheLocator(candidateDirectories: [written.dir]), limits: limits,
            isCancelled: isCancelled, rowObserver: rowObserver)
    }

    private func resolved(_ outcome: ImportResolutionOutcome, file: StaticString = #filePath, line: UInt = #line) -> ResolvedImport? {
        guard case .resolved(let value) = outcome else {
            XCTFail("expected resolved, got \(outcome)", file: file, line: line)
            return nil
        }
        return value
    }

    private func assertNoResolved(_ batch: ImportResolutionBatch, file: StaticString = #filePath, line: UInt = #line) {
        for row in batch.rows {
            if case .resolved = row.outcome { XCTFail("row \(row.entryIndex) must not be resolved", file: file, line: line) }
        }
    }

    private func unavailableReason(_ outcome: ImportResolutionOutcome) -> CacheUnavailableReason? {
        if case .cacheUnavailable(let reason, _) = outcome { return reason }
        return nil
    }

    private let libx = "/usr/lib/libx.dylib"
    private let liby = "/usr/lib/liby.dylib"
    private let libz = "/usr/lib/libz.dylib"

    // MARK: B1

    func testB1ResolvesExactImageSymbolAndAddressWithAuthority() throws {
        let cache = SynthCache(images: [
            image(libx, exports: [("_f", .regular(0x1000)), ("_fa", .regular(0x1100)), ("_free", .regular(0x1200)), ("_g", .regular(0x2000))]),
        ])
        let batch = try resolve(cache, [entry("_f", from: libx), entry("_free", from: libx), entry("_fa", from: libx)])
        XCTAssertFalse(batch.isPartial)
        XCTAssertEqual(batch.cacheUUID, SynthCacheWriter.mainUUID)
        let load = SynthCacheWriter.loadAddress(ofImage: 0)
        let first = try XCTUnwrap(resolved(batch.rows[0].outcome))
        XCTAssertEqual(first.symbol.imagePath, bytes(libx))
        XCTAssertEqual(first.symbol.imageUUID, [UInt8](repeating: 0x10, count: 16))
        XCTAssertEqual(first.symbol.cacheUUID, SynthCacheWriter.mainUUID)
        XCTAssertEqual(first.symbol.imageLoadAddress, load)
        XCTAssertEqual(first.symbol.address, load + 0x1000)
        XCTAssertEqual(first.symbol.imageOffset, 0x1000)
        XCTAssertEqual(first.symbol.domain, .cacheUnslidVM)
        XCTAssertEqual(first.symbol.terminalKind, .regular)
        XCTAssertEqual(first.viaPath, [bytes(libx)])
        XCTAssertTrue(first.isFinalTarget)
        XCTAssertEqual(try XCTUnwrap(resolved(batch.rows[1].outcome)).symbol.address, load + 0x1200)
        XCTAssertEqual(try XCTUnwrap(resolved(batch.rows[2].outcome)).symbol.address, load + 0x1100)
    }

    func testB1AbsentSymbolIsNotExportedAndSearchedImagesAreNamed() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x1000))])])
        let batch = try resolve(cache, [entry("_nope", from: libx), entry("_", from: libx), entry("_ff", from: libx)])
        for row in batch.rows {
            XCTAssertEqual(row.outcome, .notExported(searchedImages: [bytes(libx)]))
        }
    }

    // MARK: B2, B3

    func testB2OnlyTheNamedDependencyIsSearchedAndCatalogOrderDoesNotMatter() throws {
        let images = [
            image(libx, exports: [("_f", .regular(0x1000))]),
            image(liby, exports: [("_f", .regular(0x7000))]),
        ]
        for ordered in [images, images.reversed()] {
            let batch = try resolve(SynthCache(images: Array(ordered)), [entry("_f", from: libx), entry("_f", from: liby)],
                                    subdirectory: "order-\(ordered[0].path.hashValue)")
            let a = try XCTUnwrap(resolved(batch.rows[0].outcome))
            let b = try XCTUnwrap(resolved(batch.rows[1].outcome))
            XCTAssertEqual(a.symbol.imagePath, bytes(libx))
            XCTAssertEqual(a.symbol.imageOffset, 0x1000)
            XCTAssertEqual(b.symbol.imagePath, bytes(liby))
            XCTAssertEqual(b.symbol.imageOffset, 0x7000)
        }
    }

    func testB3NamedDependencyWithoutTheSymbolNeverFallsBackToAnotherImage() throws {
        let cache = SynthCache(images: [
            image(libx, exports: [("_f", .regular(0x1000))]),
            image(liby, exports: [("_other", .regular(0x2000))]),
        ])
        let batch = try resolve(cache, [entry("_f", from: liby, ordinal: 2)])
        XCTAssertEqual(batch.rows[0].outcome, .notExported(searchedImages: [bytes(liby)]))
    }

    // MARK: B4, B5

    func testB4ExplicitReexportUsesTheExportersOwnDependencyTable() throws {
        // libx reexports _f to ordinal 2 of ITS table (liby), not ordinal 2 of anyone else's.
        let cache = SynthCache(images: [
            image(libx, deps: [(libz, .load), (liby, .load)], exports: [("_f", .reexport(ordinal: 2, name: ""))]),
            image(liby, exports: [("_f", .regular(0x3000))]),
            image(libz, exports: [("_f", .regular(0x9000))]),
        ])
        let batch = try resolve(cache, [entry("_f", from: libx)])
        let value = try XCTUnwrap(resolved(batch.rows[0].outcome))
        XCTAssertEqual(value.viaPath, [bytes(libx), bytes(liby)])
        XCTAssertEqual(value.symbol.imagePath, bytes(liby))
        XCTAssertEqual(value.symbol.imageOffset, 0x3000)
    }

    func testB5RenamedReexportResolvesTheRenamedNameOnly() throws {
        let cache = SynthCache(images: [
            image(libx, deps: [(liby, .load)], exports: [("_f", .reexport(ordinal: 1, name: "_g"))]),
            image(liby, exports: [("_g", .regular(0x4000)), ("_f", .regular(0x5000))]),
        ])
        let batch = try resolve(cache, [entry("_f", from: libx)])
        let value = try XCTUnwrap(resolved(batch.rows[0].outcome))
        XCTAssertEqual(value.symbol.imageOffset, 0x4000)
        XCTAssertEqual(value.symbol.symbolName, bytes("_g"))
    }

    // MARK: B6

    func testB6ImplicitReexportFollowsLoadCommandOrderAndSkipsNonReexportDependencies() throws {
        let cache = SynthCache(images: [
            image("/usr/lib/umbrella.dylib", deps: [(libz, .load), (libx, .reexport), (liby, .reexport)],
                  exports: [("_own", .regular(0x100))]),
            image(libx, exports: [("_a", .regular(0x10))]),
            image(liby, exports: [("_f", .regular(0x20)), ("_own", .regular(0x999))]),
            image(libz, exports: [("_f", .regular(0x30))]),
        ])
        let batch = try resolve(cache, [
            entry("_f", from: "/usr/lib/umbrella.dylib"),
            entry("_own", from: "/usr/lib/umbrella.dylib"),
        ])
        let viaChild = try XCTUnwrap(resolved(batch.rows[0].outcome))
        XCTAssertEqual(viaChild.viaPath, [bytes("/usr/lib/umbrella.dylib"), bytes(liby)])
        XCTAssertEqual(viaChild.symbol.imageOffset, 0x20)
        // The umbrella's own export wins; its children are not consulted.
        let own = try XCTUnwrap(resolved(batch.rows[1].outcome))
        XCTAssertEqual(own.symbol.imagePath, bytes("/usr/lib/umbrella.dylib"))
        XCTAssertEqual(own.symbol.imageOffset, 0x100)
    }

    func testB6SameSymbolInTwoReexportedChildrenIsAmbiguousNotFirstWins() throws {
        let cache = SynthCache(images: [
            image("/usr/lib/umbrella.dylib", deps: [(libx, .reexport), (liby, .reexport)]),
            image(libx, exports: [("_f", .regular(0x10))]),
            image(liby, exports: [("_f", .regular(0x20))]),
        ])
        let batch = try resolve(cache, [entry("_f", from: "/usr/lib/umbrella.dylib")])
        guard case .ambiguous(let candidates, let more) = batch.rows[0].outcome else { return XCTFail("\(batch.rows[0].outcome)") }
        XCTAssertEqual(candidates.count, 2)
        XCTAssertFalse(more)
        XCTAssertEqual(candidates, candidates.sorted())
    }

    // MARK: B7

    func testB7CycleDepthAndStateBoundsAreTypedAndNeverHang() throws {
        let cycle = SynthCache(images: [
            image(libx, deps: [(liby, .load)], exports: [("_f", .reexport(ordinal: 1, name: ""))]),
            image(liby, deps: [(libx, .load)], exports: [("_f", .reexport(ordinal: 1, name: ""))]),
        ])
        let cycleBatch = try resolve(cycle, [entry("_f", from: libx)], subdirectory: "cycle")
        guard case .reexportChain(.cycle, let via) = cycleBatch.rows[0].outcome else { return XCTFail("\(cycleBatch.rows[0].outcome)") }
        XCTAssertEqual(via.first, bytes(libx))

        func chain(length: Int) -> SynthCache {
            let names = (0..<length).map { "/usr/lib/chain\($0).dylib" }
            return SynthCache(images: names.enumerated().map { index, path in
                index == length - 1
                    ? image(path, exports: [("_f", .regular(0x40))])
                    : image(path, deps: [(names[index + 1], .load)], exports: [("_f", .reexport(ordinal: 1, name: ""))])
            })
        }
        // 8 reexport edges (9 images) is the cap and resolves; 9 edges is depthLimit.
        let atCap = try resolve(chain(length: 9), [entry("_f", from: "/usr/lib/chain0.dylib")], subdirectory: "chain9")
        XCTAssertEqual(try XCTUnwrap(resolved(atCap.rows[0].outcome)).viaPath.count, 9)
        let overCap = try resolve(chain(length: 10), [entry("_f", from: "/usr/lib/chain0.dylib")], subdirectory: "chain10")
        guard case .reexportChain(.depthLimit, _) = overCap.rows[0].outcome else { return XCTFail("\(overCap.rows[0].outcome)") }

        var wide = DyldCacheImportResolutionLimits.production
        wide.maximumVisitedStates = 5
        let children = (0..<10).map { "/usr/lib/child\($0).dylib" }
        let fan = SynthCache(images: [image("/usr/lib/fan.dylib", deps: children.map { ($0, .reexport) })]
            + children.map { image($0, exports: [("_other", .regular(0x8))]) })
        let fanBatch = try resolve(fan, [entry("_f", from: "/usr/lib/fan.dylib")], limits: wide, subdirectory: "fan")
        guard case .reexportChain(.stateLimit, _) = fanBatch.rows[0].outcome else { return XCTFail("\(fanBatch.rows[0].outcome)") }
    }

    // MARK: B8

    func testB8BrokenReexportEdgesCarryTheirOwnSubreason() throws {
        let cache = SynthCache(images: [
            image(libx, deps: [(liby, .load)], exports: [
                ("_ordinal", .reexport(ordinal: 5, name: "")),
                ("_zero", .reexport(ordinal: 0, name: "")),
                ("_renamed", .reexport(ordinal: 1, name: "_h")),
                ("_same", .reexport(ordinal: 1, name: "")),
            ]),
            image(liby, exports: [("_unrelated", .regular(0x8))]),
            image("/usr/lib/gone.dylib", deps: ["/usr/lib/not-in-cache.dylib"].map { ($0, .load) },
                  exports: [("_f", .reexport(ordinal: 1, name: ""))]),
            image("/usr/lib/umbrella.dylib", deps: [("/usr/lib/not-in-cache.dylib", .reexport)]),
        ])
        let batch = try resolve(cache, [
            entry("_ordinal", from: libx), entry("_zero", from: libx), entry("_renamed", from: libx),
            entry("_same", from: libx), entry("_f", from: "/usr/lib/gone.dylib"),
            entry("_f", from: "/usr/lib/umbrella.dylib"),
        ])
        func failure(_ index: Int) -> ReexportChainFailure? {
            if case .reexportChain(let failure, _) = batch.rows[index].outcome { return failure }
            return nil
        }
        XCTAssertEqual(failure(0), .edgeOrdinalOutOfRange)
        XCTAssertEqual(failure(1), .edgeOrdinalOutOfRange)
        XCTAssertEqual(failure(2), .renamedTargetMissing)
        XCTAssertEqual(failure(3), .targetSymbolMissing)
        XCTAssertEqual(failure(4), .edgeTargetNotInCache)
        XCTAssertEqual(failure(5), .edgeTargetNotInCache)
    }

    // MARK: B9

    func testB9SymbolInBothTriesDiffersIsAmbiguousAndSameAddressIsOneRowWithDuplicateNoted() throws {
        let cache = SynthCache(images: [
            image(libx, exports: [("_diff", .regular(0x2000)), ("_same", .regular(0x3000))],
                  info: [("_diff", .regular(0x1000)), ("_same", .regular(0x3000))]),
        ])
        let batch = try resolve(cache, [entry("_diff", from: libx), entry("_same", from: libx)])
        guard case .ambiguous(let candidates, _) = batch.rows[0].outcome else { return XCTFail("\(batch.rows[0].outcome)") }
        XCTAssertEqual(candidates.map(\.address), [SynthCacheWriter.loadAddress(ofImage: 0) + 0x1000,
                                                   SynthCacheWriter.loadAddress(ofImage: 0) + 0x2000])
        let same = try XCTUnwrap(resolved(batch.rows[1].outcome))
        XCTAssertEqual(same.duplicateTerminalCount, 1)
        XCTAssertEqual(same.symbol.imageOffset, 0x3000)
    }

    // MARK: B10

    func testB10StubAndResolverWeakDefinitionAndWeakImportAreResolvedAndFlagged() throws {
        let cache = SynthCache(images: [
            image(libx, exports: [("_stub", .stubWire(stub: 0x1000, resolver: 0x2000)), ("_weakdef", .weak(0x1800)),
                                  ("_plain", .regular(0x1900))]),
        ])
        let batch = try resolve(cache, [
            entry("_stub", from: libx), entry("_weakdef", from: libx), entry("_plain", from: libx, weak: true, tableIndex: 1),
        ])
        let stub = try XCTUnwrap(resolved(batch.rows[0].outcome))
        XCTAssertEqual(stub.symbol.terminalKind, .stubAndResolver(resolverOffset: 0x2000))
        XCTAssertEqual(stub.symbol.imageOffset, 0x1000)
        XCTAssertEqual(stub.symbol.address, SynthCacheWriter.loadAddress(ofImage: 0) + 0x1000)
        XCTAssertEqual(stub.symbol.resolverAddress, SynthCacheWriter.loadAddress(ofImage: 0) + 0x2000)
        XCTAssertFalse(stub.isFinalTarget)
        let weakDef = try XCTUnwrap(resolved(batch.rows[1].outcome))
        XCTAssertNil(weakDef.symbol.resolverAddress)
        XCTAssertTrue(weakDef.symbol.isWeakDefinition)
        XCTAssertTrue(weakDef.isFinalTarget)
        let weakImport = try XCTUnwrap(resolved(batch.rows[2].outcome))
        XCTAssertTrue(weakImport.isWeakImport)
        XCTAssertFalse(weakImport.symbol.isWeakDefinition)
    }

    // MARK: B11

    func testB11AbsoluteStaysAbsoluteThreadLocalIsImageRelativeAndOverflowIsTypedWithoutAnAddress() throws {
        let cache = SynthCache(images: [
            image(libx, exports: [("_abs", .absolute(0x1234)), ("_tls", .threadLocal(0x50)), ("_over", .regular(UInt64.max - 8))]),
        ])
        let batch = try resolve(cache, [entry("_abs", from: libx), entry("_tls", from: libx), entry("_over", from: libx)])
        let absolute = try XCTUnwrap(resolved(batch.rows[0].outcome))
        XCTAssertEqual(absolute.symbol.address, 0x1234)
        XCTAssertNil(absolute.symbol.imageOffset)
        XCTAssertEqual(absolute.symbol.terminalKind, .absolute)
        let tls = try XCTUnwrap(resolved(batch.rows[1].outcome))
        XCTAssertEqual(tls.symbol.terminalKind, .threadLocal)
        XCTAssertEqual(tls.symbol.address, SynthCacheWriter.loadAddress(ofImage: 0) + 0x50)
        XCTAssertEqual(unavailableReason(batch.rows[2].outcome), .unsupportedFormat)
    }

    // MARK: B12

    func testB12NoPathHeuristicsExactBytesOnly() throws {
        var raw = image("placeholder", exports: [("_f", .regular(0x10))])
        raw.rawPath = Array("/usr/lib/lib".utf8) + [0xFF] + Array(".dylib".utf8)
        let cache = SynthCache(images: [
            image(libx, exports: [("_f", .regular(0x10))]),
            image("/usr/lib/caf\u{e9}.dylib", exports: [("_f", .regular(0x20))]),
            raw,
        ])
        let installNames = [
            "libx.dylib", "/USR/LIB/LIBX.DYLIB", "/usr/lib/libx.dylib/", "/usr/lib/../lib/libx.dylib",
            "@rpath/libx.dylib", "/usr/lib/cafe\u{301}.dylib", "/usr/lib/lib\u{FFFD}.dylib",
        ]
        let batch = try resolve(cache, installNames.map { entry("_f", from: $0) })
        for (index, name) in installNames.enumerated() {
            XCTAssertEqual(batch.rows[index].outcome, .notCacheResident(.installNameNotInCache(installName: name)), name)
        }
        // The precomposed spelling is a different byte string and does resolve.
        let exact = try resolve(cache, [entry("_f", from: "/usr/lib/caf\u{e9}.dylib")], subdirectory: "exact")
        XCTAssertEqual(try XCTUnwrap(resolved(exact.rows[0].outcome)).symbol.imageOffset, 0x20)
    }

    func testB12PreLookupMissesPassThroughWithoutConsultingTheCache() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))])])
        let miss = ImportResolutionEntry(symbolName: "_f", origin: nil, outcome: .miss(.noOriginRecorded))
        let rpath = ImportResolutionEntry(
            symbolName: "_f", origin: nil, outcome: .miss(.unresolvedPathVariable(installName: "@rpath/libx.dylib")))
        let batch = try resolve(cache, [miss, entry("_f", from: libx), rpath])
        XCTAssertEqual(batch.rows[0].outcome, .notCacheResident(.preLookup(.noOriginRecorded)))
        XCTAssertNotNil(resolved(batch.rows[1].outcome))
        XCTAssertEqual(batch.rows[2].outcome,
                       .notCacheResident(.preLookup(.unresolvedPathVariable(installName: "@rpath/libx.dylib"))))
        // Even with no cache at all, pre-lookup misses stay what they are.
        let empty = DyldCacheImportResolver.resolve(
            entries: [miss, entry("_f", from: libx)], importerArchitecture: "arm64",
            locator: HostCacheLocator(candidateDirectories: [directory.appendingPathComponent("absent")]))
        XCTAssertEqual(empty.rows[0].outcome, .notCacheResident(.preLookup(.noOriginRecorded)))
        XCTAssertEqual(unavailableReason(empty.rows[1].outcome), .notPresent)
    }

    // MARK: B13

    func testB13ArchitectureAndMagicMismatchesAreTyped() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))])])
        let written = try writeCache(cache)
        var data = try Data(contentsOf: written.main)
        data.replaceSubrange(0..<16, with: Array("dyld_v1  x86_64h".utf8))
        try data.write(to: written.main)
        let locator = HostCacheLocator(candidateDirectories: [written.dir])
        let arch = DyldCacheImportResolver.resolve(entries: [entry("_f", from: libx)], importerArchitecture: "arm64", locator: locator)
        XCTAssertEqual(unavailableReason(arch.rows[0].outcome), .architectureMismatch)

        data.replaceSubrange(0..<16, with: Array("not a dyld cache".utf8))
        try data.write(to: written.main)
        let magic = DyldCacheImportResolver.resolve(entries: [entry("_f", from: libx)], importerArchitecture: "arm64", locator: locator)
        XCTAssertEqual(unavailableReason(magic.rows[0].outcome), .unsupportedFormat)

        let unknown = DyldCacheImportResolver.resolve(entries: [entry("_f", from: libx)], importerArchitecture: "riscv", locator: locator)
        XCTAssertEqual(unavailableReason(unknown.rows[0].outcome), .architectureMismatch)
    }

    func testB13SubCacheAndMappingIdentityFailuresNeverYieldResolvedRows() throws {
        let images = [image(libx, exports: [("_f", .regular(0x10))])]
        var uuid = SynthCache(images: images)
        uuid.subCacheUUIDMismatch = true
        var missing = SynthCache(images: images)
        missing.omitLinkeditFile = true
        var overlap = SynthCache(images: images)
        overlap.overlappingMappings = true
        var duplicate = SynthCache(images: images + [image(liby)])
        duplicate.duplicateCatalogPath = true
        let expectations: [(String, SynthCache, CacheUnavailableReason)] = [
            ("uuid", uuid, .identityMismatch), ("missing", missing, .identityMismatch),
            ("overlap", overlap, .identityMismatch), ("duplicate", duplicate, .unsupportedFormat),
        ]
        for (name, cache, reason) in expectations {
            let batch = try resolve(cache, [entry("_f", from: libx)], subdirectory: name)
            XCTAssertEqual(unavailableReason(batch.rows[0].outcome), reason, name)
            assertNoResolved(batch)
        }
    }

    func testB13BadImageHeaderAndInstallNameMismatchAreRowLevelIdentityMismatches() throws {
        var badMagic = image(libx, exports: [("_f", .regular(0x10))])
        badMagic.machMagic = 0xfeedface
        var renamed = image(liby, exports: [("_f", .regular(0x10))])
        renamed.idNameOverride = "/usr/lib/other.dylib"
        let cache = SynthCache(images: [badMagic, renamed, image(libz, exports: [("_f", .regular(0x30))])])
        let batch = try resolve(cache, [entry("_f", from: libx), entry("_f", from: liby), entry("_f", from: libz)])
        XCTAssertEqual(unavailableReason(batch.rows[0].outcome), .identityMismatch)
        XCTAssertEqual(unavailableReason(batch.rows[1].outcome), .identityMismatch)
        XCTAssertEqual(try XCTUnwrap(resolved(batch.rows[2].outcome)).symbol.imageOffset, 0x30)
    }

    func testB13LocatorPrefersEarlierDirectoryAndMissingCacheIsNotPresent() throws {
        let first = directory.appendingPathComponent("first", isDirectory: true)
        try FileManager.default.createDirectory(at: first, withIntermediateDirectories: true)
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))])])
        let written = try writeCache(cache, subdirectory: "second")
        let located = try HostCacheLocator(candidateDirectories: [first, written.dir]).locate(importerArchitecture: "arm64e")
        XCTAssertEqual(located.url.deletingLastPathComponent().lastPathComponent, "second")
        XCTAssertEqual(located.architecture, "arm64e")
        XCTAssertThrowsError(try HostCacheLocator(candidateDirectories: [first]).locate(importerArchitecture: "arm64")) { error in
            XCTAssertEqual((error as? CacheUnavailableError)?.reason, .notPresent)
        }
        XCTAssertEqual(HostCacheLocator.cacheArchitectureTokens(forImporterArchitecture: "x86_64"), ["x86_64h", "x86_64"])
    }

    // MARK: B14

    func testB14MalformedTriesAreUnsupportedFormatNeverAbsence() throws {
        let truncated = Array(SynthTrie.build([("_f", .regular(0x10)), ("_free", .regular(0x20))]).dropLast(3))
        let rawTries: [(String, [UInt8])] = [
            ("truncated", truncated),
            ("ulebPastEnd", [0x80, 0x80]),
            ("terminalPastEnd", [0x7f, 0x00]),
            ("emptyEdge", [0x00, 0x01, 0x00, 0x00]),
            ("childOffsetOutside", [0x00, 0x01, 0x5f, 0x66, 0x00, 0x7f]),
            ("unterminatedLabel", [0x00, 0x01, 0x5f, 0x66]),
            ("noChildCountByte", [0x00]),
        ]
        for (name, trie) in rawTries {
            var broken = image(libx)
            broken.rawExportsTrie = trie
            let batch = try resolve(SynthCache(images: [broken]), [entry("_f", from: libx), entry("_free", from: libx)],
                                    subdirectory: "malformed-\(name)")
            // Dropping the tail only cuts the `_free` node; `_f` is intact and legitimately resolves.
            for row in (name == "truncated" ? Array(batch.rows.dropFirst()) : batch.rows) {
                guard case .cacheUnavailable(.unsupportedFormat, _) = row.outcome else {
                    XCTFail("\(name): \(row.outcome)")
                    continue
                }
            }
        }
        // A trie whose only edge points back at the root terminates (each edge consumes input) and
        // does not claim the symbol exists.
        var looping = image(libx)
        looping.rawExportsTrie = [0x00, 0x01, 0x5f, 0x00, 0x00]
        let loop = try resolve(SynthCache(images: [looping]), [entry("_____", from: libx)], subdirectory: "looping")
        XCTAssertEqual(loop.rows[0].outcome, .notExported(searchedImages: [bytes(libx)]))
    }

    func testB14WalkerRejectsUnknownKindBitsAsUnsupportedFlagsNotAbsence() {
        var units: UInt64 = 0
        // Kind bits 0x3 are not defined; flags ULEB 3, address ULEB 0.
        let trie: [UInt8] = [0x00, 0x01, 0x5f, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00]
        let result = ExportTrieWalker.walk(trie: Data(trie), symbol: [0x5f], workUnits: &units)
        XCTAssertEqual(result, .unsupportedFlags(3))
    }

    // MARK: B15

    func testB15SymbolLengthBound() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))])])
        let atCap = "_" + String(repeating: "a", count: 4_095)
        let overCap = "_" + String(repeating: "a", count: 4_096)
        let batch = try resolve(cache, [entry(atCap, from: libx), entry(overCap, from: libx), entry("_f", from: libx)])
        XCTAssertEqual(batch.rows[0].outcome, .notExported(searchedImages: [bytes(libx)]))
        XCTAssertEqual(unavailableReason(batch.rows[1].outcome), .budgetExceeded)
        XCTAssertNotNil(resolved(batch.rows[2].outcome))
    }

    func testB15DependencyAndLoadCommandBoundsAreOneUnderAtOver() throws {
        func cache(deps: Int) -> SynthCache {
            SynthCache(images: [image(libx, deps: (0..<deps).map { ("/usr/lib/dep\($0).dylib", .load) },
                                      exports: [("_f", .regular(0x10))])])
        }
        var limits = DyldCacheImportResolutionLimits.production
        limits.maximumDependencies = 3
        for (deps, ok) in [(2, true), (3, true), (4, false)] {
            let batch = try resolve(cache(deps: deps), [entry("_f", from: libx)], limits: limits, subdirectory: "deps\(deps)")
            if ok { XCTAssertNotNil(resolved(batch.rows[0].outcome), "deps \(deps)") }
            else { XCTAssertEqual(unavailableReason(batch.rows[0].outcome), .unsupportedFormat, "deps \(deps)") }
        }
        // Commands: LC_ID_DYLIB, LC_UUID, LC_SEGMENT_64, LC_DYLD_EXPORTS_TRIE = 4.
        var commandLimits = DyldCacheImportResolutionLimits.production
        for (maximum, ok) in [(5, true), (4, true), (3, false)] {
            commandLimits.maximumLoadCommands = maximum
            let batch = try resolve(cache(deps: 0), [entry("_f", from: libx)], limits: commandLimits, subdirectory: "cmds\(maximum)")
            if ok { XCTAssertNotNil(resolved(batch.rows[0].outcome), "cmds \(maximum)") }
            else { XCTAssertEqual(unavailableReason(batch.rows[0].outcome), .unsupportedFormat, "cmds \(maximum)") }
        }
        var byteLimits = DyldCacheImportResolutionLimits.production
        byteLimits.maximumLoadCommandBytes = 16
        let tiny = try resolve(cache(deps: 0), [entry("_f", from: libx)], limits: byteLimits, subdirectory: "bytes")
        XCTAssertEqual(unavailableReason(tiny.rows[0].outcome), .unsupportedFormat)
    }

    func testB15RequestCountAndDistinctDependencyBoundsRefuseBeforeResolving() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))]), image(liby), image(libz)])
        var limits = DyldCacheImportResolutionLimits.production
        limits.maximumRequestsPerBatch = 2
        let ok = try resolve(cache, [entry("_f", from: libx), entry("_f", from: libx)], limits: limits, subdirectory: "r2")
        XCTAssertFalse(ok.isPartial)
        XCTAssertEqual(ok.rows.compactMap { resolved($0.outcome) }.count, 2)
        let over = try resolve(cache, [entry("_f", from: libx), entry("_f", from: libx), entry("_f", from: libx)],
                               limits: limits, subdirectory: "r3")
        XCTAssertEqual(over.rows.map { unavailableReason($0.outcome) }, [.budgetExceeded, .budgetExceeded, .budgetExceeded])

        var dependencyLimits = DyldCacheImportResolutionLimits.production
        dependencyLimits.maximumDependencies = 2
        let atCap = try resolve(cache, [entry("_f", from: libx), entry("_f", from: liby)], limits: dependencyLimits, subdirectory: "d2")
        XCTAssertEqual(unavailableReason(atCap.rows[0].outcome), nil)
        let overCap = try resolve(cache, [entry("_f", from: libx), entry("_f", from: liby), entry("_f", from: libz)],
                                  limits: dependencyLimits, subdirectory: "d3")
        XCTAssertEqual(overCap.rows.map { unavailableReason($0.outcome) }, [.budgetExceeded, .budgetExceeded, .budgetExceeded])
    }

    func testB15WorkBudgetKeepsFinishedRowsAndTypesTheRest() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10)), ("_g", .regular(0x20))])])
        let one = try resolve(cache, [entry("_f", from: libx)], subdirectory: "work-measure")
        var limits = DyldCacheImportResolutionLimits.production
        limits.workBudget = one.workUnitsUsed + 2
        let batch = try resolve(cache, [entry("_f", from: libx), entry("_g", from: libx), entry("_f", from: libx)],
                                limits: limits, subdirectory: "work-limited")
        XCTAssertNotNil(resolved(batch.rows[0].outcome))
        XCTAssertEqual(unavailableReason(batch.rows[1].outcome), .budgetExceeded)
        XCTAssertEqual(unavailableReason(batch.rows[2].outcome), .budgetExceeded)
        XCTAssertTrue(batch.isPartial)
    }

    func testB15CancellationBeforeAndDuringABatch() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))])])
        let before = try resolve(cache, [entry("_f", from: libx), entry("_f", from: libx)], isCancelled: { true },
                                 subdirectory: "cancel-before")
        XCTAssertEqual(before.rows.map { unavailableReason($0.outcome) }, [.cancelled, .cancelled])

        let flag = CancellationFlag()
        let during = try resolve(
            cache, [entry("_f", from: libx), entry("_f", from: libx), entry("_f", from: libx)],
            isCancelled: { flag.value }, rowObserver: { index in if index == 0 { flag.value = true } },
            subdirectory: "cancel-during")
        XCTAssertNotNil(resolved(during.rows[0].outcome))
        XCTAssertEqual(unavailableReason(during.rows[1].outcome), .cancelled)
        XCTAssertEqual(unavailableReason(during.rows[2].outcome), .cancelled)
        XCTAssertTrue(during.isPartial)
    }

    // MARK: B16

    func testB16CatalogAndRequestPermutationsAndDuplicateRequestsGiveTheSameAnswers() throws {
        let images = [
            image(libx, exports: [("_f", .regular(0x10)), ("_g", .regular(0x14))]),
            image(liby, deps: [(libz, .reexport)], exports: [("_f", .regular(0x20))]),
            image(libz, exports: [("_h", .regular(0x30))]),
        ]
        let requests = [entry("_f", from: libx), entry("_f", from: liby), entry("_h", from: liby), entry("_zz", from: libz),
                        entry("_f", from: libx)]
        func semantic(_ batch: ImportResolutionBatch) -> [String] {
            batch.rows.map { row in
                switch row.outcome {
                case .resolved(let value):
                    return "resolved \(String(decoding: value.symbol.imagePath, as: UTF8.self)) \(value.symbol.imageOffset ?? 0)"
                        + " via \(value.viaPath.count)"
                case .notExported(let searched):
                    return "notExported \(searched.map { String(decoding: $0, as: UTF8.self) })"
                default:
                    return "\(row.outcome)"
                }
            }
        }
        let baseline = semantic(try resolve(SynthCache(images: images), requests, subdirectory: "perm-a"))
        let reversedCatalog = semantic(try resolve(SynthCache(images: images.reversed()), requests, subdirectory: "perm-b"))
        XCTAssertEqual(baseline, reversedCatalog)
        XCTAssertEqual(baseline[0], baseline[4], "identical requests give identical rows")
        let permuted = [requests[3], requests[1], requests[4], requests[0], requests[2]]
        let permutedRows = try resolve(SynthCache(images: images), permuted, subdirectory: "perm-c")
        XCTAssertEqual(semantic(permutedRows), [baseline[3], baseline[1], baseline[4], baseline[0], baseline[2]])
    }

    func testB16SameNameWithDistinctOriginsStaysSeparateRows() throws {
        let cache = SynthCache(images: [
            image(libx, exports: [("_f", .regular(0x10))]), image(liby, exports: [("_f", .regular(0x20))]),
        ])
        let batch = try resolve(cache, [
            entry("_f", from: libx, tableIndex: 0, ordinal: 1), entry("_f", from: liby, tableIndex: 1, ordinal: 2),
            entry("_f", from: libx, tableIndex: 2, ordinal: 1),
        ])
        XCTAssertEqual(batch.rows.count, 3)
        XCTAssertEqual(batch.rows.map { $0.origin?.tableIndex }, [0, 1, 2])
        XCTAssertEqual(try XCTUnwrap(resolved(batch.rows[0].outcome)).symbol.imageOffset, 0x10)
        XCTAssertEqual(try XCTUnwrap(resolved(batch.rows[1].outcome)).symbol.imageOffset, 0x20)
        XCTAssertEqual(try XCTUnwrap(resolved(batch.rows[2].outcome)).symbol.imageOffset, 0x10)
    }

    // MARK: B17

    func testB17IdentityChangeMidBatchPublishesNoResolvedRows() throws {
        let cache = SynthCache(images: [image(libx, exports: [("_f", .regular(0x10))])])
        let written = try writeCache(cache, subdirectory: "mid-batch")
        let miss = ImportResolutionEntry(symbolName: "_f", origin: nil, outcome: .miss(.noOriginRecorded))
        let batch = DyldCacheImportResolver.resolve(
            entries: [entry("_f", from: libx), miss, entry("_f", from: libx)], importerArchitecture: "arm64",
            locator: HostCacheLocator(candidateDirectories: [written.dir]),
            rowObserver: { index in
                guard index == 0 else { return }
                let sibling = URL(fileURLWithPath: written.main.path + ".02")
                let replacement = written.dir.appendingPathComponent("replacement")
                try? FileManager.default.copyItem(at: sibling, to: replacement)
                _ = try? FileManager.default.replaceItemAt(sibling, withItemAt: replacement)
            })
        XCTAssertEqual(unavailableReason(batch.rows[0].outcome), .changedDuringResolution)
        XCTAssertEqual(batch.rows[1].outcome, .notCacheResident(.preLookup(.noOriginRecorded)))
        XCTAssertEqual(unavailableReason(batch.rows[2].outcome), .changedDuringResolution)
        assertNoResolved(batch)
        XCTAssertTrue(batch.isPartial)
    }

    // MARK: Identity-bound mapping, descriptor and cache seam (DC2)

    func testIdentityBoundMappingDoesNotHashAndStillRefusesIdentityDrift() throws {
        let url = directory.appendingPathComponent("blob.bin")
        try Data(repeating: 0x5a, count: 4_096).write(to: url)
        let first = try DyldCacheSourceIdentityReader.identityBoundMappedData(
            for: url, expectedIdentity: nil, maximumBytes: 1 << 20)
        XCTAssertEqual(first.data.count, 4_096)
        XCTAssertEqual(first.identity, try DyldCacheSourceIdentityReader.identity(for: url))
        _ = try DyldCacheSourceIdentityReader.identityBoundMappedData(
            for: url, expectedIdentity: first.identity, maximumBytes: 1 << 20)
        XCTAssertThrowsError(try DyldCacheSourceIdentityReader.identityBoundMappedData(
            for: url, expectedIdentity: first.identity, maximumBytes: 100)) { error in
            XCTAssertEqual(error as? DyldCacheAnalysisProviderError, .outputLimitExceeded)
        }
        try Data(repeating: 0x5b, count: 8_192).write(to: url)
        XCTAssertThrowsError(try DyldCacheSourceIdentityReader.identityBoundMappedData(
            for: url, expectedIdentity: first.identity, maximumBytes: 1 << 20)) { error in
            XCTAssertEqual(error as? DyldCacheAnalysisProviderError, .sourceIdentityMismatch)
        }
        let link = directory.appendingPathComponent("link.bin")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
        XCTAssertThrowsError(try DyldCacheSourceIdentityReader.identityBoundMappedData(
            for: link, expectedIdentity: nil, maximumBytes: 1 << 20))
    }

    func testSnapshotAndDescriptorSeamForCrashSymbolication() throws {
        let cache = SynthCache(images: [
            image(libx, deps: [(liby, .reexport), (libz, .weak)], exports: [("_f", .regular(0x10))]),
            image(liby), image(libz),
        ])
        let written = try writeCache(cache)
        let snapshot = try HostCacheSnapshot.open(mainURL: written.main, expectedArchitecture: "arm64e")
        XCTAssertEqual(snapshot.cacheUUID, SynthCacheWriter.mainUUID)
        XCTAssertEqual(snapshot.files.count, 3)
        XCTAssertEqual(snapshot.catalog.map(\.path), [bytes(libx), bytes(liby), bytes(libz)])
        XCTAssertEqual(snapshot.catalogIndex(forInstallName: bytes(liby)), 1)
        XCTAssertNil(snapshot.catalogIndex(forInstallName: bytes("liby.dylib")))
        // The text mapping lives in the first sub-cache and the trie in the second: bytes cross files.
        let header = try XCTUnwrap(snapshot.bytes(at: snapshot.catalog[0].loadAddress, length: 4))
        XCTAssertEqual(Array(header), [0xcf, 0xfa, 0xed, 0xfe])
        XCTAssertNil(snapshot.bytes(at: SynthCacheWriter.base - 1, length: 4))
        let descriptor = try ImageDescriptor.load(catalogIndex: 0, in: snapshot, limits: .production)
        XCTAssertEqual(descriptor.uuid, [UInt8](repeating: 0x10, count: 16))
        XCTAssertEqual(descriptor.dependencies.map(\.kind), [.reexport, .weak])
        XCTAssertEqual(descriptor.dependencies.map(\.installName), [bytes(liby), bytes(libz)])
        XCTAssertEqual(descriptor.reexportedDependencyOrdinals, [1])
        XCTAssertEqual(descriptor.exportTries.count, 1)
        XCTAssertNoThrow(try snapshot.verifyIdentitiesUnchanged())
    }

    func testDescriptorCacheIsBoundedAndEvictsLeastRecentlyUsed() throws {
        let cache = SynthCache(images: [image(libx), image(liby), image(libz)])
        let written = try writeCache(cache)
        let snapshot = try HostCacheSnapshot.open(mainURL: written.main, expectedArchitecture: "arm64e")
        var descriptors = ImageDescriptorCache(capacity: 2)
        var loaded = 0
        for index in [0, 1, 0, 2, 0, 1] {
            _ = try descriptors.descriptor(for: index, in: snapshot, limits: .production, loaded: &loaded)
            XCTAssertLessThanOrEqual(descriptors.count, 2)
        }
        // 0,1 load; 0 hit; 2 loads and evicts 1; 0 hit; 1 reloads and evicts 2.
        XCTAssertEqual(loaded, 4)
    }
}

private final class CancellationFlag: @unchecked Sendable {
    var value = false
}
