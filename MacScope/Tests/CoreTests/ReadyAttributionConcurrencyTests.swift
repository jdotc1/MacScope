import Foundation
import Dispatch
import XCTest
@testable import MacScope

// T11 supplemental guards; authored, unrun. Synchronous barriers, no sleeps,
// wall-time assertions, core-count assumptions or external inputs.
final class ReadyAttributionConcurrencyTests: XCTestCase {
    func testTwoDistinctIntervalsCloseConcurrentlyExactlyOnce() {
        let probe = ReadyConcurrentClock()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        let spans = [recorder.open(.load), recorder.open(.decode)]
        DispatchQueue.concurrentPerform(iterations: spans.count) { index in
            recorder.close(spans[index], outcome: .success)
        }
        let state = recorder.snapshot()
        XCTAssertEqual(state.records.map(\.opened), [1, 1])
        XCTAssertEqual(state.records.map(\.closed), [1, 1])
        XCTAssertEqual(state.records.map(\.successes), [1, 1])
        XCTAssertEqual(state.counters[.misuse, default: 0], 0)
        XCTAssertEqual(probe.calls, 4)
        XCTAssertNotNil(recorder.summary())
        XCTAssertNil(recorder.summary())
    }

    func testConcurrentDuplicateCloseConsumesOnlyOneToken() {
        let probe = ReadyConcurrentClock()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        let span = recorder.open(.load)
        DispatchQueue.concurrentPerform(iterations: 2) { _ in
            recorder.close(span, outcome: .success)
        }
        let state = recorder.snapshot()
        XCTAssertEqual(state.records.map(\.closed), [1])
        XCTAssertEqual(state.records.map(\.successes), [1])
        XCTAssertEqual(state.counters[.misuse], 1)
        XCTAssertEqual(probe.calls, 2)
        XCTAssertNotNil(recorder.summary())
    }

    func testForeignAndStaleTokensCannotCloseCurrentSpan() {
        let probe = ReadyConcurrentClock()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        let foreign = AnalysisAttribution(now: { 0 })
        let foreignSpan = foreign.open(.load)
        let original = recorder.open(.load)
        recorder.close(foreignSpan, outcome: .success)
        XCTAssertNil(recorder.summary())
        recorder.close(original, outcome: .success)
        let current = recorder.open(.load)
        recorder.close(original, outcome: .failed)
        XCTAssertNil(recorder.summary())
        recorder.close(current, outcome: .cancelled)
        foreign.close(foreignSpan, outcome: .success)
        let state = recorder.snapshot()
        XCTAssertEqual(state.records.map(\.opened), [2])
        XCTAssertEqual(state.records.map(\.closed), [2])
        XCTAssertEqual(state.records.map(\.successes), [1])
        XCTAssertEqual(state.records.map(\.cancellations), [1])
        XCTAssertEqual(state.records.map(\.failures), [0])
        XCTAssertEqual(state.counters[.misuse], 2)
        XCTAssertEqual(probe.calls, 4)
        XCTAssertNotNil(recorder.summary())
    }
}

private final class ReadyConcurrentClock: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func tick() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        count += 1
        return UInt64(count)
    }
    var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
}
