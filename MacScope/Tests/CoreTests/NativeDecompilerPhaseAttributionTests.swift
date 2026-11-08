// Authored, unrun.
import Foundation
import XCTest
@testable import MacScope

#if DEBUG
@MainActor
final class NativeDecompilerPhaseAttributionTests: XCTestCase {
    private typealias Record = NativeDecompilerPhaseRecord

    func testNestedExclusiveAndResidual() throws {
        let clock = AttributionClock(), sink = AttributionSink()
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        let parent = record.begin(.snapshotRead)
        let child = record.begin(.validation)
        record.end(child)
        record.end(parent)
        record.finish()
        let s = try XCTUnwrap(sink.values.first)
        assertTimes(s, inclusive: [.snapshotRead: 30, .validation: 10],
                    exclusive: [.snapshotRead: 20, .validation: 10], elapsed: 50,
                    covered: 30, residual: 20)
        XCTAssertTrue(s.attributionComplete)
        XCTAssertEqual(s.completedSpans[Record.Phase.snapshotRead.rawValue], 1)
        XCTAssertEqual(s.completedSpans[Record.Phase.validation.rawValue], 1)
    }

    func testSequentialChildrenAndGaps() throws {
        let clock = AttributionClock(), sink = AttributionSink()
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        let parent = record.begin(.projection)
        let first = record.begin(.validation)
        record.end(first)
        let second = record.begin(.dispatch)
        record.end(second)
        record.end(parent)
        record.finish()
        let s = try XCTUnwrap(sink.values.first)
        assertTimes(s, inclusive: [.projection: 50, .validation: 10, .dispatch: 10],
                    exclusive: [.projection: 30, .validation: 10, .dispatch: 10],
                    elapsed: 70, covered: 50, residual: 20)
        XCTAssertTrue(s.attributionComplete)
    }

    func testPartialOverlapIsFlagged() throws {
        let clock = AttributionClock(), sink = AttributionSink()
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        let a = record.begin(.projection)
        let b = record.begin(.validation)
        record.end(a)
        record.end(b)
        record.finish()
        let s = try XCTUnwrap(sink.values.first)
        assertTimes(s, inclusive: [.projection: 20, .validation: 20],
                    exclusive: [.projection: 20, .validation: 20], elapsed: 50,
                    covered: 30, residual: 20, overlap: true)
        XCTAssertTrue(s.attributionComplete) // Observed, not proof of parentage.
    }

    func testIncompleteAttemptIsMarked() throws {
        let clock = AttributionClock(), sink = AttributionSink()
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        _ = record.begin(.dispatch)
        record.finish()
        let open = try XCTUnwrap(sink.values.first)
        assertTimes(open, inclusive: [:], exclusive: [:], elapsed: 20, covered: 0, residual: 20)
        XCTAssertEqual(open.unfinishedSpans, 1)
        XCTAssertEqual(open.suppressedSpans, 0)
        XCTAssertFalse(open.attributionComplete)

        let crowdedClock = AttributionClock(), crowdedSink = AttributionSink()
        let crowded = Record(clock: { crowdedClock.read() }, sink: { crowdedSink.append($0) })
        let spans = (0..<64).map { _ in crowded.begin(.dispatch) }
        XCTAssertTrue(spans.allSatisfy { $0 != nil })
        XCTAssertNil(crowded.begin(.dispatch))
        for span in spans.reversed() { crowded.end(span) }
        crowded.finish()
        let suppressed = try XCTUnwrap(crowdedSink.values.first)
        assertTimes(suppressed, inclusive: [.dispatch: 40_960], exclusive: [.dispatch: 1_270],
                    elapsed: 1_290, covered: 1_270, residual: 20)
        XCTAssertEqual(suppressed.suppressedSpans, 1)
        XCTAssertEqual(suppressed.unfinishedSpans, 0)
        XCTAssertFalse(suppressed.attributionComplete)
        XCTAssertEqual(crowdedClock.readCount, 130)
    }

    func testIntervalLogIsBounded() throws {
        XCTAssertEqual(Record.intervalCapacity, 256)
        let clock = AttributionClock(), sink = AttributionSink()
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        for _ in 0...Record.intervalCapacity { record.end(record.begin(.dispatch)) }
        record.finish()
        let s = try XCTUnwrap(sink.values.first)
        assertTimes(s, inclusive: [.dispatch: 2_570], exclusive: [.dispatch: 2_560],
                    elapsed: 5_150, covered: 2_560, residual: 2_590, dropped: 1)
        XCTAssertEqual(s.completedSpans[Record.Phase.dispatch.rawValue], 257)
        XCTAssertEqual(s.unfinishedSpans, 0)
        XCTAssertEqual(s.suppressedSpans, 0)
        XCTAssertFalse(s.attributionComplete)
        XCTAssertEqual(clock.readCount, 516)
    }

    func testNoExtraClockReads() throws {
        let clock = AttributionClock(), sink = AttributionSink()
        Record.withTrace(nil) { Record.current()?.measure(.dispatch) {} }
        XCTAssertEqual(clock.readCount, 0)
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        let parent = record.begin(.snapshotRead)
        let child = record.begin(.validation)
        record.end(child)
        record.end(parent)
        record.finish()
        XCTAssertEqual(clock.readCount, 6)
        let before = sink.values
        record.end(child)
        record.end(parent)
        XCTAssertNil(record.begin(.dispatch))
        record.add(.visitedCalls, 99)
        record.finish()
        XCTAssertEqual(clock.readCount, 6)
        XCTAssertEqual(sink.values, before)
        let s = try XCTUnwrap(before.first)
        assertTimes(s, inclusive: [.snapshotRead: 30, .validation: 10],
                    exclusive: [.snapshotRead: 20, .validation: 10], elapsed: 50,
                    covered: 30, residual: 20)
    }

    func testConstantClockGivesZeroAttribution() throws {
        let sink = AttributionSink()
        let record = Record(clock: { 100 }, sink: { sink.append($0) })
        let parent = record.begin(.projection)
        let child = record.begin(.validation)
        record.end(child)
        record.end(parent)
        record.finish()
        let s = try XCTUnwrap(sink.values.first)
        assertTimes(s, inclusive: [:], exclusive: [:], elapsed: 0, covered: 0, residual: 0)
        XCTAssertTrue(s.attributionComplete)
        XCTAssertEqual(s.completedSpans[Record.Phase.projection.rawValue], 1)
        XCTAssertEqual(s.completedSpans[Record.Phase.validation.rawValue], 1)
    }

    func testNewCountersFollowObservedRule() throws {
        let counters: [Record.Counter] = [.visitedInstructions, .visitedBlocks, .visitedEdges, .visitedCalls]
        let sink = AttributionSink()
        let absent = Record(clock: { 100 }, sink: { sink.append($0) })
        absent.finish()
        let zero = Record(clock: { 100 }, sink: { sink.append($0) })
        for counter in counters { zero.add(counter, 0) }
        zero.finish()
        let added = Record(clock: { 100 }, sink: { sink.append($0) })
        for counter in counters { added.add(counter, 2); added.add(counter, 3) }
        added.finish()
        XCTAssertEqual(sink.values.count, 3)
        guard sink.values.count == 3 else { return }
        for counter in counters {
            XCTAssertFalse(sink.values[0].counterObserved[counter.rawValue])
            XCTAssertEqual(sink.values[0].counts[counter.rawValue], 0)
            XCTAssertTrue(sink.values[1].counterObserved[counter.rawValue])
            XCTAssertEqual(sink.values[1].counts[counter.rawValue], 0)
            XCTAssertTrue(sink.values[2].counterObserved[counter.rawValue])
            XCTAssertEqual(sink.values[2].counts[counter.rawValue], 5)
        }
        for s in sink.values {
            assertTimes(s, inclusive: [:], exclusive: [:], elapsed: 0, covered: 0, residual: 0)
            XCTAssertTrue(s.attributionComplete)
        }
    }

    func testEqualEndpointsUseSerialAndClippingBoundsCoverage() throws {
        let clock = AttributionScriptedClock([10, 20, 20, 40, 40, 50]), sink = AttributionSink()
        let record = Record(clock: { clock.read() }, sink: { sink.append($0) })
        let parent = record.begin(.projection)
        let child = record.begin(.validation)
        record.end(parent) // Reverse completion order must not reverse parentage.
        record.end(child)
        record.finish()
        let tied = try XCTUnwrap(sink.values.first)
        assertTimes(tied, inclusive: [.projection: 20, .validation: 20], exclusive: [.validation: 20],
                    elapsed: 40, covered: 20, residual: 20)
        XCTAssertTrue(tied.attributionComplete)
        let clippedClock = AttributionScriptedClock([100, 50, 200, 150]), clippedSink = AttributionSink()
        let clipped = Record(clock: { clippedClock.read() }, sink: { clippedSink.append($0) })
        clipped.end(clipped.begin(.projection))
        clipped.finish()
        let s = try XCTUnwrap(clippedSink.values.first)
        assertTimes(s, inclusive: [.projection: 150], exclusive: [.projection: 50],
                    elapsed: 50, covered: 50, residual: 0)
    }

    private func assertTimes(
        _ s: Record.Summary, inclusive: [Record.Phase: UInt64], exclusive: [Record.Phase: UInt64],
        elapsed: UInt64, covered: UInt64, residual: UInt64, overlap: Bool = false, dropped: UInt64 = 0,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertEqual(s.elapsedNanoseconds, elapsed, file: file, line: line)
        for phase in Record.Phase.allCases {
            XCTAssertEqual(s.durations[phase.rawValue], inclusive[phase, default: 0], file: file, line: line)
            XCTAssertEqual(s.exclusiveDurations[phase.rawValue], exclusive[phase, default: 0], file: file, line: line)
            XCTAssertLessThanOrEqual(s.exclusiveDurations[phase.rawValue], s.durations[phase.rawValue], file: file, line: line)
        }
        XCTAssertEqual(s.coveredNanoseconds, covered, file: file, line: line)
        XCTAssertEqual(s.residualNanoseconds, residual, file: file, line: line)
        XCTAssertEqual(s.overlappingSpans, overlap, file: file, line: line)
        XCTAssertEqual(s.droppedIntervals, dropped, file: file, line: line)
        XCTAssertEqual(covered + residual, elapsed, file: file, line: line)
        if !overlap {
            XCTAssertEqual(s.exclusiveDurations.reduce(0, +), covered, file: file, line: line)
        }
    }
}
#endif

private final class AttributionClock: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0
    var readCount: Int { lock.withLock { reads } }
    func read() -> UInt64 { lock.withLock { reads += 1; return UInt64(reads) * 10 } }
}

private final class AttributionScriptedClock: @unchecked Sendable {
    private let lock = NSLock()
    private let values: [UInt64]
    private var index = 0
    init(_ values: [UInt64]) { self.values = values }
    func read() -> UInt64 {
        lock.withLock {
            defer { index += 1 }
            return index < values.count ? values[index] : values.last ?? 0
        }
    }
}

private final class AttributionSink: @unchecked Sendable {
    private let lock = NSLock()
    private var summaries: [NativeDecompilerPhaseRecord.Summary] = []
    var values: [NativeDecompilerPhaseRecord.Summary] { lock.withLock { summaries } }
    func append(_ value: NativeDecompilerPhaseRecord.Summary) { lock.withLock { summaries.append(value) } }
}
