// Authored, unrun.
import XCTest
@testable import MacScope

final class ConcurrentMapTilingTests: XCTestCase {
    func testExplicitTileCountsMatchSequentialAtThresholdBoundaries() {
        for count in [4_095, 4_096, 4_097, 8_192] {
            let expected = (0..<count).map { "row-\($0)-\($0 &* 31 &+ 7)" }
            for budget in [1, 8] {
                for tiles in [1, 6] {
                    let actual = AnalysisParallelism.withBudget(.init(maximumParallelism: budget)) {
                        ConcurrentMap.map(count: count, tilesPerWorker: tiles) {
                            "row-\($0)-\($0 &* 31 &+ 7)"
                        }
                    }
                    XCTAssertEqual(actual, expected, "count=\(count), budget=\(budget), tiles=\(tiles)")
                }
            }
        }
    }

    func testSkewedIndexOnlyWorkIsIdentical() {
        let count = 4_097
        let expected = (0..<count).map { Self.skewedValue($0) }
        for budget in [1, 8] {
            for tiles in [1, 6] {
                let actual = AnalysisParallelism.withBudget(.init(maximumParallelism: budget)) {
                    ConcurrentMap.map(count: count, tilesPerWorker: tiles) { Self.skewedValue($0) }
                }
                XCTAssertEqual(actual, expected)
            }
        }
    }

    func testSixTilesInitializeExactlyOnceWithinBudgetAndReleaseEveryElement() {
        let count = 8_193
        let recorder = TilingVisitRecorder(count: count)
        let lifetime = TilingLifetimeCounter()
        var result: [TilingPayload]? = AnalysisParallelism.withBudget(.init(maximumParallelism: 8)) {
            ConcurrentMap.map(count: count, threshold: 1, tilesPerWorker: 6) { index in
                recorder.enter(index)
                defer { recorder.leave() }
                return TilingPayload(index: index, lifetime: lifetime)
            }
        }
        weak var first = result?.first
        XCTAssertEqual(result?.map(\.index), Array(0..<count))
        XCTAssertEqual(recorder.visits, Array(repeating: 1, count: count))
        XCTAssertLessThanOrEqual(recorder.maximumActive, 8)
        XCTAssertEqual(lifetime.created, count)
        XCTAssertEqual(lifetime.destroyed, 0)
        XCTAssertNotNil(first)
        result = nil
        XCTAssertNil(first)
        XCTAssertEqual(lifetime.destroyed, count)
    }

    func testNestedSixTileMapsObserveSerialBudgetAndRestoreParent() {
        let rows = AnalysisParallelism.withBudget(.init(maximumParallelism: 8)) {
            let result = ConcurrentMap.map(count: 101, threshold: 1, tilesPerWorker: 6) { outer in
                let observed = AnalysisParallelism.current.maximumParallelism
                let nested = ConcurrentMap.map(count: 17, threshold: 1, tilesPerWorker: 6) { inner in
                    [outer * 17 + inner, AnalysisParallelism.current.maximumParallelism]
                }
                return [[observed]] + nested
            }
            XCTAssertEqual(AnalysisParallelism.current.maximumParallelism, 8)
            return result
        }
        XCTAssertEqual(rows, (0..<101).map { outer in
            [[1]] + (0..<17).map { [outer * 17 + $0, 1] }
        })
    }

    func testTileBoundsAndEmptyOrTinyInputs() {
        for count in [0, 1, 2, 7, 63, 65] {
            for tiles in [Int.min, -1, 0, 1, 6, 7, Int.max] {
                let actual = AnalysisParallelism.withBudget(.init(maximumParallelism: 64)) {
                    ConcurrentMap.map(count: count, threshold: 1, tilesPerWorker: tiles) { $0 }
                }
                XCTAssertEqual(actual, Array(0..<count))
            }
        }
    }

    private static func skewedValue(_ index: Int) -> UInt64 {
        var value = UInt64(index)
        let iterations = index % 19 == 0 ? 257 : 3
        for step in 0..<iterations {
            value = value &* 6_364_136_223_846_793_005 &+ UInt64(step + 1)
        }
        return value
    }
}

private final class TilingVisitRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [Int]
    private var active = 0
    private var maximum = 0
    init(count: Int) { counts = Array(repeating: 0, count: count) }
    var visits: [Int] { lock.withLock { counts } }
    var maximumActive: Int { lock.withLock { maximum } }
    func enter(_ index: Int) {
        lock.withLock { counts[index] += 1; active += 1; maximum = max(maximum, active) }
    }
    func leave() { lock.withLock { active -= 1 } }
}

private final class TilingPayload: Sendable {
    let index: Int
    private let lifetime: TilingLifetimeCounter
    init(index: Int, lifetime: TilingLifetimeCounter) {
        self.index = index
        self.lifetime = lifetime
        lifetime.create()
    }
    deinit { lifetime.destroy() }
}

private final class TilingLifetimeCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var made = 0
    private var released = 0
    var created: Int { lock.withLock { made } }
    var destroyed: Int { lock.withLock { released } }
    func create() { lock.withLock { made += 1 } }
    func destroy() { lock.withLock { released += 1 } }
}
