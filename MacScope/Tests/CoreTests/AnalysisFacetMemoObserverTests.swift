// Authored, unrun.
import Foundation
import XCTest
@testable import MacScope

#if DEBUG
@MainActor
final class AnalysisFacetMemoObserverTests: XCTestCase {
    private typealias Record = NativeDecompilerPhaseRecord

    func testFirstLookupMissThenHit() throws {
        let facet = try sampleFacet(), memo = AnalysisFacetDigestMemo()
        let observer = FacetMemoTestObserver()
        var builds = 0
        let first = memo.value(observer: observer) { builds += 1; return facet }
        XCTAssertEqual(first, facet)
        XCTAssertEqual(observer.events, [false])
        let second = memo.value(observer: observer) { builds += 1; return facet }
        XCTAssertEqual(second, facet)
        XCTAssertEqual(builds, 1)
        XCTAssertEqual(observer.events, [false, true])
    }

    func testThrowingBuilderStillCountsMiss() throws {
        let facet = try sampleFacet(), memo = AnalysisFacetDigestMemo()
        let observer = FacetMemoTestObserver(), expected = FacetMemoExpectedError()
        var builds = 0
        XCTAssertThrowsError(try memo.value(observer: observer) {
            builds += 1
            throw expected
        }) { XCTAssertTrue(($0 as? FacetMemoExpectedError) === expected) }
        XCTAssertEqual(observer.events, [false])
        XCTAssertEqual(memo.value(observer: observer) { builds += 1; return facet }, facet)
        XCTAssertEqual(observer.events, [false, false])
        XCTAssertEqual(try memo.value(observer: observer) {
            builds += 1
            throw expected
        }, facet)
        XCTAssertEqual(builds, 2)
        XCTAssertEqual(observer.events, [false, false, true])
    }

    func testNilObserverUnchanged() throws {
        let facet = try sampleFacet(), memo = AnalysisFacetDigestMemo()
        let observer = FacetMemoTestObserver(), original = AnalysisFacetDigestMemo()
        var builds = 0
        XCTAssertEqual(memo.value(observer: nil) { builds += 1; return facet }, original.value { facet })
        XCTAssertEqual(memo.value(observer: nil) { builds += 1; return facet }, facet)
        XCTAssertEqual(builds, 1)
        XCTAssertEqual(observer.events, [])
        let binary = memoBinary(), analysis = memoAnalysis()
        let baseline = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
        XCTAssertEqual(try AnalysisFingerprintBuilder.fingerprint(
            binary: binary, analysis: analysis, facetMemoObserver: nil), baseline)
        XCTAssertEqual(try AnalysisFingerprintBuilder.fingerprint(
            binary: binary, analysis: analysis, navigatorContext: nil, facetMemoObserver: nil), baseline)
        let recomputed = try AnalysisFingerprintBuilder.withComputedSliceDigest(
            binary: binary, analysis: analysis, facetMemoObserver: nil
        ) { digest, recompute in
            XCTAssertEqual(digest, baseline.imageBytesSHA256)
            return try recompute()
        }
        XCTAssertEqual(recomputed, baseline)
        XCTAssertEqual(observer.events, [])
    }

    func testFingerprintEqualWithAndWithoutObserver() throws {
        for overlap in [false, true] {
            let binary = memoBinary()
            let analysis = memoAnalysis(instructions: overlap ? 4_096 : 2, xrefs: overlap ? 2_048 : 0)
            let observer = FacetMemoTestObserver()
            let first = try AnalysisFingerprintBuilder.fingerprint(
                binary: binary, analysis: analysis, facetMemoObserver: observer)
            expectEvents(observer, hits: 0, misses: 2)
            let second = try AnalysisFingerprintBuilder.fingerprint(
                binary: binary, analysis: analysis, facetMemoObserver: observer)
            expectEvents(observer, hits: 2, misses: 2)
            let omitted = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
            let explicitNil = try AnalysisFingerprintBuilder.fingerprint(
                binary: binary, analysis: analysis, facetMemoObserver: nil)
            XCTAssertEqual(first, second)
            XCTAssertEqual(first, omitted)
            XCTAssertEqual(first, explicitNil)
            // A fresh analysis has empty memos, so this fingerprint is computed rather than memo-served.
            let fresh = try AnalysisFingerprintBuilder.fingerprint(
                binary: binary,
                analysis: memoAnalysis(instructions: overlap ? 4_096 : 2, xrefs: overlap ? 2_048 : 0))
            XCTAssertEqual(first, fresh)
            XCTAssertEqual(first.facets, omitted.facets)
            XCTAssertEqual(first.overallSHA256, omitted.overallSHA256)
            expectEvents(observer, hits: 2, misses: 2)
        }
    }

    func testAdapterMapsHitAndMiss() throws {
        let cases: [([Bool], UInt64, UInt64)] = [([true], 1, 0), ([false], 0, 1), ([false, true, true], 2, 1)]
        for (events, hits, misses) in cases {
            let summary = try captureMemoRecord { record in
                let observer = NativeDecompilerFacetMemoObserver(record: record)
                for hit in events { observer.recordFacetMemo(hit: hit) }
            }
            expectMemoCounters(summary, hits: hits, misses: misses)
        }
    }

    func testAdapterAfterFinishIsIgnored() throws {
        let probe = FacetMemoRecordProbe()
        let record = Record(clock: { probe.read() }, sink: { probe.append($0) })
        let observer = NativeDecompilerFacetMemoObserver(record: record)
        record.finish()
        let before = try XCTUnwrap(probe.values.first)
        observer.recordFacetMemo(hit: false)
        observer.recordFacetMemo(hit: true)
        record.finish()
        XCTAssertEqual(probe.values, [before])
        XCTAssertEqual(probe.readCount, 2)
        XCTAssertFalse(before.counterObserved[Record.Counter.facetMemoHits.rawValue])
        XCTAssertFalse(before.counterObserved[Record.Counter.facetMemoMisses.rawValue])
        XCTAssertEqual(before.counts[Record.Counter.facetMemoHits.rawValue], 0)
        XCTAssertEqual(before.counts[Record.Counter.facetMemoMisses.rawValue], 0)
    }

    func testAdapterEndToEnd() throws {
        for overlap in [false, true] {
            let binary = memoBinary()
            let analysis = memoAnalysis(instructions: overlap ? 4_096 : 2, xrefs: overlap ? 2_048 : 0)
            for firstCall in [true, false] {
                let summary = try captureMemoRecord { _ in
                    let observer = NativeDecompilerFacetMemoObserver(record: try XCTUnwrap(Record.current()))
                    _ = try AnalysisFingerprintBuilder.fingerprint(
                        binary: binary, analysis: analysis, facetMemoObserver: observer)
                }
                expectMemoCounters(summary, hits: firstCall ? 0 : 2, misses: firstCall ? 2 : 0)
            }
        }
    }

    private func captureMemoRecord(_ operation: (Record) throws -> Void) throws -> Record.Summary {
        let probe = FacetMemoRecordProbe()
        let record = Record(clock: { probe.read() }, sink: { probe.append($0) })
        let result = Result { try Record.withTrace(record) { try operation(record) } }
        record.finish()
        XCTAssertEqual(probe.readCount, 2)
        XCTAssertEqual(probe.values.count, 1)
        let summary = try XCTUnwrap(probe.values.first)
        XCTAssertEqual(summary.elapsedNanoseconds, 10)
        XCTAssertEqual(summary.coveredNanoseconds, 0)
        XCTAssertEqual(summary.residualNanoseconds, 10)
        XCTAssertTrue(summary.completedSpans.allSatisfy { $0 == 0 })
        try result.get()
        return summary
    }

    private func expectMemoCounters(_ summary: Record.Summary, hits: UInt64, misses: UInt64,
                                    file: StaticString = #filePath, line: UInt = #line) {
        for (counter, count) in [(Record.Counter.facetMemoHits, hits), (.facetMemoMisses, misses)] {
            XCTAssertTrue(summary.counterObserved[counter.rawValue], file: file, line: line)
            XCTAssertEqual(summary.counts[counter.rawValue], count, file: file, line: line)
        }
    }

    private func expectEvents(_ observer: FacetMemoTestObserver, hits: Int, misses: Int,
                              file: StaticString = #filePath, line: UInt = #line) {
        let events = observer.events
        XCTAssertEqual(events.filter { $0 }.count, hits, file: file, line: line)
        XCTAssertEqual(events.filter { !$0 }.count, misses, file: file, line: line)
    }

    private func sampleFacet() throws -> AnalysisFacetFingerprint {
        let fingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: memoBinary(), analysis: memoAnalysis())
        return try XCTUnwrap(fingerprint.facets.first)
    }

    private func memoBinary() -> BinaryImage {
        BinaryImage(id: UUID(), name: "facet-memo-fixture", path: "/fixture/facet-memo",
                    kind: "Mach-O executable", architecture: "arm64", slot: .primary)
    }

    private func memoAnalysis(instructions: Int = 2, xrefs: Int = 0) -> ImageAnalysis {
        var result = ImageAnalysis()
        result.imageBytes = Data([0, 1, 2, 3, 4, 5])
        result.instructions = (0..<instructions).map {
            InstructionRow(address: 0x1000 + UInt64($0) * 4, bytes: "1f 20 03 d5", mnemonic: "nop",
                           operands: "", hasBreakpoint: false, comment: nil)
        }
        result.xrefs = (0..<xrefs).map {
            XRef(id: UUID(), from: 0x1000 + UInt64($0) * 4, to: 0x8000, kind: XRefKind.data)
        }
        return result
    }
}

private final class FacetMemoExpectedError: Error {}

private final class FacetMemoTestObserver: AnalysisFacetMemoObserver, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [Bool] = []
    var events: [Bool] { lock.withLock { recorded } }
    func recordFacetMemo(hit: Bool) { lock.withLock { recorded.append(hit) } }
}

private final class FacetMemoRecordProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0
    private var summaries: [NativeDecompilerPhaseRecord.Summary] = []
    var readCount: Int { lock.withLock { reads } }
    var values: [NativeDecompilerPhaseRecord.Summary] { lock.withLock { summaries } }
    func read() -> UInt64 { lock.withLock { reads += 1; return UInt64(reads) * 10 } }
    func append(_ summary: NativeDecompilerPhaseRecord.Summary) { lock.withLock { summaries.append(summary) } }
}
#endif
