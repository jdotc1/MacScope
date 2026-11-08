import Foundation
import XCTest
@testable import MacScope

/// DC2-2 (D1-D20, D22): crash-frame address-to-name against crafted cache bytes and crafted
/// .ips-style reports. Nothing reads the host's real cache or any crash report on disk. D21
/// (local symbols) belongs to DC2-3 and is not covered here.
final class DyldCacheSymbolicationTests: XCTestCase {
    private var directory: URL!
    private var counter = 0

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc2-symbolication-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    // MARK: Helpers

    private let build = "26C5035r"
    private let slide: UInt64 = 0x1000_0000
    private func uuid(_ byte: UInt8) -> [UInt8] { [UInt8](repeating: byte, count: 16) }
    private func load(_ index: Int) -> UInt64 { SymCacheWriter.loadAddress(ofImage: index) }

    private func uuidString(_ bytes: [UInt8]) -> String {
        let hex = bytes.map { String(format: "%02X", $0) }.joined()
        let chars = Array(hex)
        func part(_ r: Range<Int>) -> String { String(chars[r]) }
        return [part(0..<8), part(8..<12), part(12..<16), part(16..<20), part(20..<32)].joined(separator: "-")
    }

    private func image(
        _ path: String = "/usr/lib/libx.dylib", uuid byte: UInt8 = 0x11, exports: [(String, SynthTerminal)] = [],
        starts: SymStarts = .absent
    ) -> SymImage {
        SymImage(path: path, uuid: uuid(byte), exports: exports, starts: starts)
    }

    private func open(_ cache: SymCache) throws -> HostCacheSnapshot {
        counter += 1
        let dir = directory.appendingPathComponent("cache\(counter)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let main = try SymCacheWriter.write(cache, into: dir)
        return try HostCacheSnapshot.open(mainURL: main, expectedArchitecture: "arm64e")
    }

    private func symbolicator(
        _ cache: SymCache, host: HostBuildEvidence? = nil, limits: DyldCacheSymbolicationLimits = .production,
        memo: SymbolicationMemo? = nil
    ) throws -> CrashFrameSymbolicator {
        CrashFrameSymbolicator(
            snapshot: try open(cache), hostBuild: host ?? HostBuildEvidence(systemVersionBuild: build, kernelOSVersion: build),
            limits: limits, memo: memo)
    }

    private func reportImages(_ cache: SymCache, slide: UInt64? = nil) -> [[String: Any]] {
        cache.images.enumerated().map { index, item in
            ["name": item.path, "uuid": uuidString(item.uuid), "base": load(index) + (slide ?? self.slide),
             "size": 0x10000, "source": "S"]
        }
    }

    private func report(
        build: String? = nil, images: [[String: Any]], threads: [[[String: Any]]]
    ) throws -> CrashReport {
        var body: [String: Any] = [
            "procName": "probe",
            "usedImages": images,
            "threads": threads.map { ["triggered": false, "frames": $0] },
        ]
        if let build { body["osVersion"] = ["build": build, "train": "macOS 27", "releaseType": "User"] }
        return try CrashReport.parse(try JSONSerialization.data(withJSONObject: body))
    }

    private func frame(_ imageIndex: Int, _ offset: UInt64) -> [String: Any] {
        ["imageIndex": imageIndex, "imageOffset": offset]
    }

    /// One thread, every frame in cache image 0 (top frame first), returns outcomes in order.
    private func outcomes(
        _ s: CrashFrameSymbolicator, _ cache: SymCache, build: String? = nil, offsets: [UInt64], imageIndex: Int = 0
    ) throws -> [FrameSymbolOutcome] {
        let result = s.symbolicate(try report(
            build: build, images: reportImages(cache), threads: [offsets.map { frame(imageIndex, $0) }]))
        XCTAssertEqual(result.frames.count, offsets.count)
        return result.frames.map(\.outcome)
    }

    private func outcome(
        _ s: CrashFrameSymbolicator, _ cache: SymCache, _ offset: UInt64, top: Bool = true
    ) throws -> FrameSymbolOutcome {
        let list = try outcomes(s, cache, offsets: top ? [offset] : [0x1000, offset])
        return list[top ? 0 : 1]
    }

    private func named(_ outcome: FrameSymbolOutcome, file: StaticString = #filePath, line: UInt = #line) -> NamedFrame? {
        guard case .named(let value) = outcome else {
            XCTFail("expected named, got \(outcome)", file: file, line: line)
            return nil
        }
        return value
    }

    private func isMalformedTraversal(_ outcome: FrameSymbolOutcome) -> Bool {
        if case .malformed(.traversalBound) = outcome { return true }
        return false
    }

    private let fStarts: SymStarts = .offsets([0x1000, 0x1040])

    // MARK: D1-D4

    func testD1NamesFunctionWithOffsetWithinSymbolAndBound() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        let s = try symbolicator(cache)
        let result = s.symbolicate(try report(images: reportImages(cache), threads: [[frame(0, 0x1010)]]))
        let record = try XCTUnwrap(result.frames.first)
        let value = try XCTUnwrap(named(record.outcome))
        XCTAssertEqual(value.names, [SymbolName(bytes: Array("_f".utf8), display: "_f", source: .exportTrieExact)])
        XCTAssertEqual(value.functionStart, load(0) + 0x1000)
        XCTAssertEqual(value.functionEnd, load(0) + 0x1040)
        XCTAssertEqual(value.offsetWithinSymbol, 0x10)
        XCTAssertEqual(value.address, load(0) + 0x1010)
        XCTAssertEqual(value.imageOffset, 0x1010)
        XCTAssertEqual(value.imageUUID, uuid(0x11))
        XCTAssertEqual(value.imagePath, Array("/usr/lib/libx.dylib".utf8))
        XCTAssertTrue(value.buildUnchecked)
        XCTAssertFalse(result.buildChecked)
        XCTAssertEqual(record.domain, .cacheUnslidVM)
        XCTAssertEqual(record.cacheUUID, SymCacheWriter.mainUUID)
        XCTAssertEqual(record.coverAdjustment, 0)
        XCTAssertEqual(record.reportImageIndex, 0)
    }

    func testD2FrameAtFunctionStartHasOffsetZero() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        let value = try XCTUnwrap(named(try outcome(try symbolicator(cache), cache, 0x1000)))
        XCTAssertEqual(value.offsetWithinSymbol, 0)
    }

    func testD3NextFunctionStartWithoutNameIsNeverNamedByThePreviousFunction() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        XCTAssertEqual(try outcome(try symbolicator(cache), cache, 0x1040),
                       .noSymbolCovering(.startUnnamed(load(0) + 0x1040)))
    }

    func testD4DeeperFrameCoversTheByteBeforeTheReturnAddress() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        let s = try symbolicator(cache)
        let result = s.symbolicate(try report(images: reportImages(cache), threads: [[frame(0, 0x1100), frame(0, 0x1040)], [frame(0, 0x1040)]]))
        XCTAssertEqual(result.frames.map(\.coverAdjustment), [0, 1, 0])
        let deeper = try XCTUnwrap(named(result.frames[1].outcome))
        XCTAssertEqual(deeper.offsetWithinSymbol, 0x40)
        XCTAssertEqual(deeper.functionStart, load(0) + 0x1000)
        XCTAssertEqual(result.frames[2].outcome, .noSymbolCovering(.startUnnamed(load(0) + 0x1040)))
    }

    // MARK: D5-D11

    func testD5SparseExportsNeverNameAnUnrelatedEarlierFunction() throws {
        let cache = SymCache(images: [image(exports: [("_g", .regular(0x1000))], starts: .offsets([0x1000, 0x2000]))])
        XCTAssertEqual(try outcome(try symbolicator(cache), cache, 0x2010), .noSymbolCovering(.startUnnamed(load(0) + 0x2000)))
    }

    func testD6LastFunctionIsBoundedBySectionEndAndNeverReachesImageEnd() throws {
        let cache = SymCache(images: [image(exports: [("_last", .regular(0x27c0))], starts: .offsets([0x1000, 0x27c0]))])
        let s = try symbolicator(cache)
        let inside = try XCTUnwrap(named(try outcome(s, cache, 0x27f0)))
        XCTAssertEqual(inside.functionEnd, load(0) + 0x2800)
        XCTAssertEqual(try outcome(s, cache, 0x3010), .noSymbolCovering(.pastLastFunction))
        XCTAssertEqual(try outcome(s, cache, 0x2a00), .noSymbolCovering(.notExecutableCode))
        XCTAssertEqual(try outcome(s, cache, 0x6000), .noSymbolCovering(.notExecutableCode))
        XCTAssertEqual(try outcome(s, cache, 0x200), .noSymbolCovering(.notExecutableCode))
    }

    func testD7TargetBeforeTheFirstFunctionStart() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1100))], starts: .offsets([0x1100, 0x1140]))])
        let s = try symbolicator(cache)
        XCTAssertEqual(try outcome(s, cache, 0x1010), .noSymbolCovering(.beforeFirstFunction))
        let none = SymCache(images: [image(starts: .offsets([]))])
        XCTAssertEqual(try outcome(try symbolicator(none), none, 0x1010), .noSymbolCovering(.beforeFirstFunction))
    }

    func testD8WithoutFunctionStartsOnlyAnExactTopFrameExportIsNamed() throws {
        for starts in [SymStarts.absent, .empty] {
            let cache = SymCache(images: [image(exports: [("_h", .regular(0x1200))], starts: starts)])
            let s = try symbolicator(cache)
            let value = try XCTUnwrap(named(try outcome(s, cache, 0x1200)))
            XCTAssertNil(value.functionEnd)
            XCTAssertEqual(value.offsetWithinSymbol, 0)
            let reason: FunctionBoundsFailure = { if case .empty = starts { return .emptyPayload } else { return .absentCommand } }()
            XCTAssertEqual(try outcome(s, cache, 0x1210), .noSymbolCovering(.noFunctionBounds(reason)))
            XCTAssertEqual(try outcome(s, cache, 0x1200, top: false), .noSymbolCovering(.noFunctionBounds(reason)))
        }
    }

    func testD9TruncatedOrUnterminatedStartListCannotBoundTheLastParsedFunction() throws {
        var limits = DyldCacheSymbolicationLimits.production
        limits.maximumFunctionStarts = 2
        let cache = SymCache(images: [image(exports: [("_a", .regular(0x1000)), ("_b", .regular(0x1040))],
                                           starts: .offsets([0x1000, 0x1040, 0x1080, 0x10c0]))])
        let s = try symbolicator(cache, limits: limits)
        XCTAssertEqual(try outcome(s, cache, 0x10d0), .noSymbolCovering(.noFunctionBounds(.truncatedByCap)))
        XCTAssertEqual(try outcome(s, cache, 0x1050), .noSymbolCovering(.noFunctionBounds(.truncatedByCap)))
        XCTAssertNotNil(named(try outcome(s, cache, 0x1010)), "a function with a parsed successor is still bounded")
        // Exactly at the cap with a terminator is complete.
        limits.maximumFunctionStarts = 4
        let atCap = try symbolicator(cache, limits: limits)
        XCTAssertEqual(try outcome(atCap, cache, 0x10d0), .noSymbolCovering(.startUnnamed(load(0) + 0x10c0)))
        // No zero terminator.
        let raw = SymCache(images: [image(exports: [("_a", .regular(0x1000))], starts: .raw(SynthUleb.encode(0x1000)))])
        XCTAssertEqual(try outcome(try symbolicator(raw), raw, 0x1010), .noSymbolCovering(.noFunctionBounds(.unterminated)))
    }

    func testD10StubSectionsAreTypedAndNeverNamedByThePrecedingFunction() throws {
        let cache = SymCache(images: [image(exports: [("_last", .regular(0x27c0))], starts: .offsets([0x1000, 0x27c0]))])
        XCTAssertEqual(try outcome(try symbolicator(cache), cache, 0x2810), .noSymbolCovering(.stubSection("__auth_stubs")))
    }

    func testD11AddressOnlyEntryNeverBorrowsTheImageBelow() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts), image("/usr/lib/liby.dylib", uuid: 0x12)])
        let s = try symbolicator(cache)
        // In the text sub-cache mapping, between image 0's segments and image 1's header.
        let gap = s.symbolicate(cacheAddress: load(0) + 0x8000)
        XCTAssertEqual(gap.outcome, .noSymbolCovering(.outsideAnyImage))
        XCTAssertNotNil(s.snapshot.bytes(at: load(0) + 0x8000, length: 1))
        let inside = s.symbolicate(cacheAddress: load(0) + 0x1010)
        XCTAssertEqual(try XCTUnwrap(named(inside.outcome)).offsetWithinSymbol, 0x10)
        XCTAssertEqual(inside.domain, .cacheUnslidVM)
    }

    // MARK: D12-D16

    func testD12AliasesAtOneStartAreNamedWithSortedNamesAndNoPrimary() throws {
        let cache = SymCache(images: [image(exports: [("_b", .regular(0x1000)), ("_a", .regular(0x1000)), ("_c", .weak(0x1000))], starts: fStarts)])
        let value = try XCTUnwrap(named(try outcome(try symbolicator(cache), cache, 0x1004)))
        XCTAssertEqual(value.names.map(\.display), ["_a", "_b", "_c"])
        XCTAssertTrue(value.names.allSatisfy { $0.source == .exportTrieExact })
    }

    func testD13InteriorExportAloneDoesNotNameTheFunction() throws {
        let cache = SymCache(images: [image(exports: [("_inner", .regular(0x1020))], starts: fStarts)])
        XCTAssertEqual(try outcome(try symbolicator(cache), cache, 0x1010), .noSymbolCovering(.interiorSymbolOnly(load(0) + 0x1020)))
    }

    func testD14OnlyRegularCodeExportsAtAStartAreNames() throws {
        let noise: [(String, SynthTerminal)] = [
            ("_abs", .absolute(0x1000)), ("_tls", .threadLocal(0x1000)), ("_re", .reexport(ordinal: 1, name: "_x")),
            ("_data", .regular(0x200)),
        ]
        let cache = SymCache(images: [image(exports: noise, starts: fStarts)])
        let s = try symbolicator(cache)
        XCTAssertEqual(try outcome(s, cache, 0x1010), .noSymbolCovering(.startUnnamed(load(0) + 0x1000)))
        XCTAssertEqual(try outcome(s, cache, 0x200), .noSymbolCovering(.notExecutableCode))
        // Real wire order is resolver first, then stub: the stub (0x1000) is the name address.
        let stub = SymCache(images: [image(exports: noise + [("_res", .stubWire(stub: 0x1000, resolver: 0x5000))], starts: fStarts)])
        XCTAssertEqual(try XCTUnwrap(named(try outcome(try symbolicator(stub), stub, 0x1010))).names.map(\.display), ["_res"])
    }

    func testD15TrieAboveTheLegacyNodeCapStillNamesAndBoundsAreTyped() throws {
        let exports: [(String, SynthTerminal)] = (0..<5_000).map { (String(format: "_f%04d", $0), .regular(UInt64(0x1000 + $0))) }
        let target = 0x1000 + 4_321
        let cache = SymCache(images: [image(exports: exports, starts: .offsets([UInt64(target), UInt64(target + 0x40)]))])
        let value = try XCTUnwrap(named(try outcome(try symbolicator(cache), cache, UInt64(target + 0x10))))
        XCTAssertEqual(value.names.map(\.display), ["_f4321"])
        var limits = DyldCacheSymbolicationLimits.production
        limits.maximumTrieNodes = 4_096
        XCTAssertEqual(try outcome(try symbolicator(cache, limits: limits), cache, UInt64(target + 0x10)),
                       .noSymbolCovering(.exportsIncomplete(.trieNodes)))
    }

    func testD16MalformedTriesAreMalformedNeverAbsence() throws {
        let cases: [(String, [UInt8])] = [
            ("child offset outside the trie", [0, 1, 0x5f, 0x61, 0, 0x7f]),
            ("ULEB past the end", [0x80]),
            ("child loop", [0, 1, 0x5f, 0, 0]),
            ("terminal past the trie", [0x40, 0]),
        ]
        for (label, raw) in cases {
            var item = image(starts: fStarts)
            item.rawExportTrie = raw
            let cache = SymCache(images: [item])
            XCTAssertTrue(isMalformedTraversal(try outcome(try symbolicator(cache), cache, 0x1010)), label)
        }
        // A name that is not UTF-8 is malformed, not repaired.
        var bad = image(starts: fStarts)
        bad.rawExportTrie = [0, 1, 0xff, 0xfe, 0, 6, 3, 0, 0x80, 0x20, 0]
        let cache = SymCache(images: [bad])
        XCTAssertEqual(try outcome(try symbolicator(cache), cache, 0x1010), .malformed(.nameNotUTF8))
        // A name over the length bound.
        var limits = DyldCacheSymbolicationLimits.production
        limits.maximumExportNameBytes = 8
        let long = SymCache(images: [image(exports: [("_averyverylongname", .regular(0x1000))], starts: fStarts)])
        XCTAssertTrue(isMalformedTraversal(try outcome(try symbolicator(long, limits: limits), long, 0x1010)))
    }

    // MARK: D17-D19

    func testD17ImagesNotInTheCacheAreTypedAndTheAppImageIsUntouched() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        var images = reportImages(cache)
        images.append(["name": "Other", "uuid": uuidString(uuid(0x77)), "base": 0x2000_0000, "size": 0x1000, "source": "C"])
        images.append(["name": "probe", "uuid": uuidString(uuid(0x88)), "base": 0x1_0000_0000, "size": 0x1000, "source": "P"])
        let result = try symbolicator(cache).symbolicate(report(images: images, threads: [[frame(1, 0x10), frame(2, 0x10), frame(0, 0x1010)]]))
        XCTAssertEqual(result.frames[0].outcome, .imageNotInCache(ImageNotInCache(
            reportImageName: "Other", reportUUID: uuidString(uuid(0x77)), catalogCount: 1, skippedSource: .sharedCacheLibrary)))
        guard case .imageNotInCache(let app) = result.frames[1].outcome else { return XCTFail("app image UUID is not in the catalog") }
        XCTAssertEqual(app.skippedSource, .process)
        XCTAssertNotNil(named(result.frames[2].outcome))
        // An unreadable catalog image means "not found" is not proof of absence.
        var broken = image("/usr/lib/liby.dylib", uuid: 0x12)
        broken.machMagic = 0
        let partial = SymCache(images: [image(), broken])
        XCTAssertEqual(try outcome(try symbolicator(partial), partial, 0x10, top: true).self, .noSymbolCovering(.notExecutableCode))
        let lost = try symbolicator(partial).symbolicate(report(
            images: [["name": "y", "uuid": uuidString(uuid(0x12)), "base": load(1), "size": 0x1000, "source": "S"]],
            threads: [[frame(0, 0x10)]]))
        XCTAssertEqual(lost.frames[0].outcome, .cacheMismatch(.catalogScanIncomplete(unreadableImages: 1)))
    }

    func testSourceTagNeverSelectsOrSkipsAUuidLookup() throws {
        // A report tags system dylibs "P" on some OS builds; the catalog UUID alone decides.
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        var images = reportImages(cache)
        images[0]["source"] = "P"
        let result = try symbolicator(cache).symbolicate(report(images: images, threads: [[frame(0, 0x1010)]]))
        XCTAssertNotNil(named(result.frames[0].outcome), "a source-P image whose UUID is in the cache must be named")
    }

    func testD18CatalogHeaderDisagreementAndDuplicateUUIDs() throws {
        var other = image(exports: [("_f", .regular(0x1000))], starts: fStarts)
        other.textInfoUUID = uuid(0x99)
        var cache = SymCache(images: [other], includeTextInfo: true)
        XCTAssertEqual(try outcome(try symbolicator(cache), cache, 0x1010),
                       .cacheMismatch(.catalogHeaderDisagree("the imagesText UUID differs from the image's LC_UUID")))
        cache.images[0].textInfoUUID = nil
        XCTAssertNotNil(named(try outcome(try symbolicator(cache), cache, 0x1010)), "agreeing imagesText UUID is accepted")

        let twin = SymCache(images: [image(), image("/usr/lib/libz.dylib", uuid: 0x11)])
        let paths = [Array("/usr/lib/libx.dylib".utf8), Array("/usr/lib/libz.dylib".utf8)]
        XCTAssertEqual(try outcome(try symbolicator(twin), twin, 0x1010, top: true),
                       .ambiguous(.duplicateImageUUID(paths: paths, moreCandidates: false)))
    }

    func testD19DifferentOrUnverifiableBuildRefusesEverySystemFrameBeforeAnyLookup() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        var images = reportImages(cache)
        images.append(["name": "probe", "uuid": uuidString(uuid(0x55)), "base": 0x1_0000_0000, "size": 0x1000, "source": "P"])
        let threads = [[frame(0, 0x1010), frame(0, 0x1000), frame(1, 0x10)]]
        let memo = SymbolicationMemo()
        let refused = try symbolicator(cache, memo: memo).symbolicate(report(build: "26C5036", images: images, threads: threads))
        let mismatch = FrameSymbolOutcome.cacheMismatch(.osBuildDiffers(report: "26C5036", host: build))
        // The report's source tag selects nothing: a build mismatch refuses every frame before any UUID lookup.
        XCTAssertEqual(refused.frames.map(\.outcome), [mismatch, mismatch, mismatch])
        XCTAssertEqual(memo.imageBuildCount, 0)
        XCTAssertEqual(memo.scanBuildCount, 0)

        let disagree = HostBuildEvidence(systemVersionBuild: build, kernelOSVersion: "26C5036")
        let gate = try symbolicator(cache, host: disagree).symbolicate(report(build: build, images: images, threads: threads))
        XCTAssertEqual(gate.frames[0].outcome, .cacheMismatch(.hostBuildSourcesDisagree(systemVersion: build, kernel: "26C5036")))
        let unknown = try symbolicator(cache, host: HostBuildEvidence(systemVersionBuild: nil, kernelOSVersion: build))
            .symbolicate(report(build: build, images: images, threads: threads))
        XCTAssertEqual(unknown.frames[0].outcome, .cacheMismatch(.hostBuildUnavailable))

        let accepted = try symbolicator(cache).symbolicate(report(build: build, images: images, threads: threads))
        XCTAssertTrue(accepted.buildChecked)
        XCTAssertFalse(try XCTUnwrap(named(accepted.frames[0].outcome)).buildUnchecked)
    }

    // MARK: D20

    func testD20SlideConsistencyAndSlideFreeArithmetic() throws {
        let base = image(exports: [("_f", .regular(0x1000))], starts: fStarts)
        let cache = SymCache(images: [base, image("/usr/lib/liby.dylib", uuid: 0x12, exports: [("_f", .regular(0x1000))], starts: fStarts),
                                      image("/usr/lib/libz.dylib", uuid: 0x13, exports: [("_f", .regular(0x1000))], starts: fStarts)])
        let s = try symbolicator(cache)
        func run(_ slides: [UInt64]) throws -> [FrameSymbolOutcome] {
            var images = reportImages(cache)
            for index in images.indices { images[index]["base"] = load(index) &+ slides[index] }
            return s.symbolicate(try report(images: images, threads: [[frame(0, 0x1010), frame(1, 0x1010), frame(2, 0x1010)]])).frames.map(\.outcome)
        }
        let consistent = try run([0x4000_0000, 0x4000_0000, 0x4000_0000])
        let zero = try run([0, 0, 0])
        XCTAssertEqual(consistent, zero, "the slide cancels: results are identical for different slides")
        XCTAssertEqual(try XCTUnwrap(named(consistent[1])).address, load(1) + 0x1010)

        let odd = try run([0x4000_0000, 0x4000_0000, 0x5000_0000])
        XCTAssertNotNil(named(odd[0]))
        XCTAssertNotNil(named(odd[1]))
        XCTAssertEqual(odd[2], .cacheMismatch(.slideInconsistent))

        let misaligned = try run([0x4000_1000, 0x4000_1000, 0x4000_1000])
        XCTAssertEqual(misaligned, [FrameSymbolOutcome](repeating: .cacheMismatch(.slideInconsistent), count: 3))
        let noMajority = try run([0x4000_0000, 0x5000_0000, 0x6000_0000])
        XCTAssertEqual(noMajority, [FrameSymbolOutcome](repeating: .cacheMismatch(.slideInconsistent), count: 3))

        // A base below the catalog address would be a negative slide.
        var images = reportImages(cache)
        for index in images.indices { images[index]["base"] = load(index) + 0x4000_0000 }
        images[2]["base"] = 0x1000
        let negative = s.symbolicate(try report(images: images, threads: [[frame(0, 0x1010), frame(2, 0x1010)]])).frames.map(\.outcome)
        XCTAssertNotNil(named(negative[0]))
        XCTAssertEqual(negative[1], .cacheMismatch(.slideInconsistent))
    }

    // MARK: Malformed report input

    func testMalformedFramesAreTypedPerFrame() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        var images = reportImages(cache)
        images.append(["name": "bad", "uuid": "not-a-uuid", "base": 0x1000, "size": 0x1000, "source": "S"])
        let result = try symbolicator(cache).symbolicate(report(images: images, threads: [[
            ["imageOffset": 4], ["imageIndex": 9, "imageOffset": 4], ["imageIndex": 0],
            frame(1, 4), frame(0, UInt64.max),
        ]]))
        XCTAssertEqual(result.frames.map(\.outcome), [
            .malformed(.missingImageIndex), .malformed(.imageIndexOutOfRange), .malformed(.missingOffset),
            .malformed(.invalidReportUUID), .malformed(.addressOverflow),
        ])
    }

    // MARK: D22

    func testD22BoundsAtOneUnderAndOneOver() throws {
        let one = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        let two = SymCache(images: [image(exports: [("_f", .regular(0x1000)), ("_g", .regular(0x1040))], starts: fStarts)])
        let trieBytes = SynthTrie.build([("_f", .regular(0x1000))]).count
        func run(_ cache: SymCache, _ change: (inout DyldCacheSymbolicationLimits) -> Void) throws -> FrameSymbolOutcome {
            var limits = DyldCacheSymbolicationLimits.production
            change(&limits)
            return try outcome(try symbolicator(cache, limits: limits), cache, 0x1010)
        }
        XCTAssertNotNil(named(try run(one) { $0.maximumTrieNodes = 2 }))
        XCTAssertEqual(try run(one) { $0.maximumTrieNodes = 1 }, .noSymbolCovering(.exportsIncomplete(.trieNodes)))
        XCTAssertNotNil(named(try run(one) { $0.maximumTrieBytes = trieBytes }))
        XCTAssertEqual(try run(one) { $0.maximumTrieBytes = trieBytes - 1 }, .noSymbolCovering(.exportsIncomplete(.trieBytes)))
        XCTAssertNotNil(named(try run(one) { $0.maximumExportNameBytes = 2 }))
        XCTAssertTrue(isMalformedTraversal(try run(one) { $0.maximumExportNameBytes = 1 }))
        XCTAssertNotNil(named(try run(two) { $0.maximumExportEntries = 2 }))
        XCTAssertEqual(try run(two) { $0.maximumExportEntries = 1 }, .noSymbolCovering(.exportsIncomplete(.exportEntries)))
        XCTAssertNotNil(named(try run(two) { $0.maximumRetainedNameBytes = 4 }))
        XCTAssertEqual(try run(two) { $0.maximumRetainedNameBytes = 3 }, .noSymbolCovering(.exportsIncomplete(.retainedNameBytes)))
    }

    func testD22ReportFrameAndImageCapsRefuseBeforeAnyWork() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        var limits = DyldCacheSymbolicationLimits.production
        limits.maximumReportFrames = 3
        let memo = SymbolicationMemo()
        let s = try symbolicator(cache, limits: limits, memo: memo)
        XCTAssertEqual(try outcomes(s, cache, offsets: [0x1010, 0x1010, 0x1010]).count, 3)
        let over = s.symbolicate(try report(images: reportImages(cache), threads: [[frame(0, 0x1010), frame(0, 0x1010)], [frame(0, 1), frame(0, 2)]]))
        XCTAssertEqual(over.refusal, .tooManyFrames(count: 4, limit: 3))
        XCTAssertTrue(over.frames.isEmpty)
        limits.maximumReportImages = 0
        let noImages = try symbolicator(cache, limits: limits).symbolicate(report(images: reportImages(cache), threads: []))
        XCTAssertEqual(noImages.refusal, .tooManyImages(count: 1, limit: 0))
    }

    func testD22MemoIsBoundedLeastRecentlyUsedAndKeyedByCacheIdentity() throws {
        let images = (0..<3).map { image("/usr/lib/lib\($0).dylib", uuid: UInt8(0x20 + $0), exports: [("_f", .regular(0x1000))], starts: fStarts) }
        let cache = SymCache(images: images)
        var limits = DyldCacheSymbolicationLimits.production
        limits.maximumMemoImages = 2
        let memo = SymbolicationMemo(limits: limits)
        let s = try symbolicator(cache, limits: limits, memo: memo)
        let threads = [[frame(0, 0x1010), frame(1, 0x1010), frame(2, 0x1010)]]
        _ = s.symbolicate(try report(images: reportImages(cache), threads: threads))
        XCTAssertEqual(memo.imageCount, 2)
        XCTAssertEqual(memo.imageBuildCount, 3)
        XCTAssertFalse(memo.contains(cacheUUID: SymCacheWriter.mainUUID, imageUUID: uuid(0x20)), "oldest entry is evicted")
        XCTAssertTrue(memo.contains(cacheUUID: SymCacheWriter.mainUUID, imageUUID: uuid(0x22)))
        let again = s.symbolicate(try report(images: reportImages(cache), threads: [[frame(2, 0x1010)]]))
        XCTAssertNotNil(named(again.frames[0].outcome))
        XCTAssertEqual(memo.imageBuildCount, 3, "a memo hit builds nothing")

        // A different cache UUID can never see another cache's index, even with the same image UUID.
        var other = SymCache(images: [image(exports: [("_g", .regular(0x1000))], starts: fStarts)])
        other.mainUUID = uuid(0xD4)
        var first = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        first.mainUUID = uuid(0xD3)
        let shared = SymbolicationMemo()
        let a = try outcome(try symbolicator(first, memo: shared), first, 0x1010)
        let b = try outcome(try symbolicator(other, memo: shared), other, 0x1010)
        XCTAssertEqual(try XCTUnwrap(named(a)).names.map(\.display), ["_f"])
        XCTAssertEqual(try XCTUnwrap(named(b)).names.map(\.display), ["_g"])
        XCTAssertEqual(shared.imageCount, 2)
    }

    func testD22SameReportTwiceAndPermutedOrderGiveTheSameSemanticResults() throws {
        let images = (0..<2).map { image("/usr/lib/lib\($0).dylib", uuid: UInt8(0x30 + $0), exports: [("_f", .regular(0x1000))], starts: fStarts) }
        let cache = SymCache(images: images)
        let memo = SymbolicationMemo()
        let s = try symbolicator(cache, memo: memo)
        let specs: [[(Int, UInt64)]] = [[(0, 0x1010), (1, 0x1040)], [(1, 0x1000), (0, 0x6000)], [(0, 0x1040)]]
        func run(images imageOrder: [Int], threadOrder: [Int]) throws -> [[FrameSymbolOutcome]] {
            let table = reportImages(cache)
            let reordered = imageOrder.map { table[$0] }
            let threads = threadOrder.map { t in specs[t].map { frame(imageOrder.firstIndex(of: $0.0)!, $0.1) } }
            let result = s.symbolicate(try report(images: reordered, threads: threads))
            var perThread: [Int: [FrameSymbolOutcome]] = [:]
            for (position, t) in threadOrder.enumerated() {
                perThread[t] = result.frames.filter { $0.threadIndex == position }.map(\.outcome)
            }
            return specs.indices.map { perThread[$0]! }
        }
        let first = try run(images: [0, 1], threadOrder: [0, 1, 2])
        let builds = memo.imageBuildCount
        XCTAssertEqual(try run(images: [0, 1], threadOrder: [0, 1, 2]), first)
        XCTAssertEqual(memo.imageBuildCount, builds)
        XCTAssertEqual(try run(images: [1, 0], threadOrder: [2, 1, 0]), first)
        XCTAssertEqual(first[1][1], .noSymbolCovering(.notExecutableCode))
    }

    func testD22CancellationMidEnumerationLeavesNoMemoEntryAndTypesEveryFrame() throws {
        let cache = SymCache(images: [image(exports: [("_f", .regular(0x1000))], starts: fStarts)])
        var limits = DyldCacheSymbolicationLimits.production
        limits.cancellationCheckInterval = 1
        let memo = SymbolicationMemo(limits: limits)
        let s = try symbolicator(cache, limits: limits, memo: memo)
        var calls = 0
        let result = s.symbolicate(
            try report(images: reportImages(cache), threads: [[frame(0, 0x1010), frame(0, 0x1010)]]),
            isCancelled: { calls += 1; return calls >= 3 })
        XCTAssertTrue(result.wasCancelled)
        XCTAssertEqual(result.frames.map(\.outcome), [.cancelled, .cancelled])
        XCTAssertEqual(memo.imageCount, 0)
        let finished = s.symbolicate(try report(images: reportImages(cache), threads: [[frame(0, 0x1010)]]))
        XCTAssertFalse(finished.wasCancelled)
        XCTAssertNotNil(named(finished.frames[0].outcome))
    }
}
