import Foundation
import XCTest
@testable import MacScope

/// DC2-3 (D21), branch B-no: the host cache declares no local-symbol companion (probe, lane-dc2c/
/// PROBE.md), so local names are never attempted. A frame that an unexported function would have
/// named carries typed `localSymbolsUnavailable` evidence, and every export-only answer is
/// unchanged. Crafted cache bytes only; no real cache or crash report is read.
final class DyldCacheLocalSymbolsTests: XCTestCase {
    private var directory: URL!
    private var counter = 0
    private let build = "26C5035r"
    private let slide: UInt64 = 0x1000_0000
    private let starts: SymStarts = .offsets([0x1000, 0x1040])

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dc2-localsyms-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    private func load(_ index: Int) -> UInt64 { SymCacheWriter.loadAddress(ofImage: index) }
    private func uuid(_ byte: UInt8) -> [UInt8] { [UInt8](repeating: byte, count: 16) }

    private func uuidString(_ bytes: [UInt8]) -> String {
        let chars = Array(bytes.map { String(format: "%02X", $0) }.joined())
        func part(_ r: Range<Int>) -> String { String(chars[r]) }
        return [part(0..<8), part(8..<12), part(12..<16), part(16..<20), part(20..<32)].joined(separator: "-")
    }

    private func makeCache(
        exports: [(String, SynthTerminal)], declared: [UInt8]? = nil
    ) -> SymCache {
        var cache = SymCache(images: [SymImage(path: "/usr/lib/libx.dylib", uuid: uuid(0x11), exports: exports, starts: starts)])
        cache.symbolFileUUID = declared
        return cache
    }

    private func symbolicator(_ cache: SymCache, memo: SymbolicationMemo? = nil) throws -> CrashFrameSymbolicator {
        counter += 1
        let dir = directory.appendingPathComponent("cache\(counter)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let main = try SymCacheWriter.write(cache, into: dir)
        return CrashFrameSymbolicator(
            snapshot: try HostCacheSnapshot.open(mainURL: main, expectedArchitecture: "arm64e"),
            hostBuild: HostBuildEvidence(systemVersionBuild: build, kernelOSVersion: build), memo: memo)
    }

    private func symbolicate(_ s: CrashFrameSymbolicator, _ cache: SymCache, offsets: [UInt64]) throws -> [FrameSymbolication] {
        let images = cache.images.enumerated().map { index, item -> [String: Any] in
            ["name": item.path, "uuid": uuidString(item.uuid), "base": load(index) + slide, "size": 0x10000, "source": "S"]
        }
        let body: [String: Any] = [
            "procName": "probe", "usedImages": images,
            "threads": [["triggered": false, "frames": offsets.map { ["imageIndex": 0, "imageOffset": $0] }]],
        ]
        let report = try CrashReport.parse(try JSONSerialization.data(withJSONObject: body))
        return s.symbolicate(report).frames
    }

    func testD21NoDeclaredCompanionAttachesTypedEvidenceToAnUnnamedStart() throws {
        let cache = makeCache(exports: [("_g", .regular(0x1040))])
        let frames = try symbolicate(try symbolicator(cache), cache, offsets: [0x1010])
        XCTAssertEqual(frames[0].outcome, .noSymbolCovering(.startUnnamed(load(0) + 0x1000)))
        XCTAssertEqual(frames[0].localSymbolsEvidence, .noDeclaredCompanion)
    }

    func testD21DeclaredButUnreadCompanionIsTypedAndKeepsTheAnswer() throws {
        let declared = uuid(0x7E)
        let cache = makeCache(exports: [("_g", .regular(0x1040))], declared: declared)
        let frames = try symbolicate(try symbolicator(cache), cache, offsets: [0x1010])
        XCTAssertEqual(frames[0].outcome, .noSymbolCovering(.startUnnamed(load(0) + 0x1000)))
        XCTAssertEqual(frames[0].localSymbolsEvidence, .declaredCompanionNotRead(uuid: declared))
    }

    func testD21InteriorExportStaysInteriorOnlyWithEvidence() throws {
        let cache = makeCache(exports: [("_inner", .regular(0x1020))])
        let frames = try symbolicate(try symbolicator(cache), cache, offsets: [0x1010])
        XCTAssertEqual(frames[0].outcome, .noSymbolCovering(.interiorSymbolOnly(load(0) + 0x1020)))
        XCTAssertEqual(frames[0].localSymbolsEvidence, .noDeclaredCompanion)
    }

    func testD21ExportOnlyAnswersAreUnchangedAndCarryNoEvidence() throws {
        let plain = makeCache(exports: [("_f", .regular(0x1000))])
        let declared = makeCache(exports: [("_f", .regular(0x1000))], declared: uuid(0x7E))
        let a = try symbolicate(try symbolicator(plain), plain, offsets: [0x1010, 0x3010, 0x200])
        let b = try symbolicate(try symbolicator(declared), declared, offsets: [0x1010, 0x3010, 0x200])
        XCTAssertEqual(a.map(\.outcome), b.map(\.outcome))
        guard case .named(let value) = a[0].outcome else { return XCTFail("expected named, got \(a[0].outcome)") }
        XCTAssertEqual(value.names.map(\.display), ["_f"])
        XCTAssertTrue(value.names.allSatisfy { $0.source == .exportTrieExact })
        XCTAssertEqual(a[1].outcome, .noSymbolCovering(.pastLastFunction))
        XCTAssertEqual(a[2].outcome, .noSymbolCovering(.notExecutableCode))
        XCTAssertTrue(a.allSatisfy { $0.localSymbolsEvidence == nil })
        XCTAssertTrue(b.allSatisfy { $0.localSymbolsEvidence == nil })
    }

    func testD21StatusIsComputedOnceAndNeverForAnsweredFrames() throws {
        let memo = SymbolicationMemo()
        let cache = makeCache(exports: [("_f", .regular(0x1000))])
        let s = try symbolicator(cache, memo: memo)
        _ = try symbolicate(s, cache, offsets: [0x1010])
        XCTAssertEqual(memo.localSymbolsBuildCount, 0)
        // A distinct cache UUID: the memo is keyed by (cache UUID, image UUID).
        var unnamed = makeCache(exports: [("_g", .regular(0x1040))])
        unnamed.mainUUID = uuid(0xA2)
        let u = try symbolicator(unnamed, memo: memo)
        let frames = try symbolicate(u, unnamed, offsets: [0x1010, 0x1012, 0x1014])
        XCTAssertEqual(frames.compactMap(\.localSymbolsEvidence).count, 3)
        XCTAssertEqual(memo.localSymbolsBuildCount, 1)
    }

    func testD21AddressOnlyEntryPointCarriesTheSameEvidence() throws {
        let cache = makeCache(exports: [("_g", .regular(0x1040))])
        let record = try symbolicator(cache).symbolicate(cacheAddress: load(0) + 0x1010)
        XCTAssertEqual(record.outcome, .noSymbolCovering(.startUnnamed(load(0) + 0x1000)))
        XCTAssertEqual(record.localSymbolsEvidence, .noDeclaredCompanion)
    }
}
