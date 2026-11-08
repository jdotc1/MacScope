// Dot item 1306: production phase record on the scripted decompile path (T1-T10).
// All numbers are fake-clock units (read k returns 10k), never measurements.
import Foundation
import XCTest
@testable import MacScope

private typealias Record = NativeDecompilerPhaseRecord

// MARK: - Deterministic probes (adapted from the private helpers of the existing phase tests)

/// Fires once; waiters resume asynchronously. Signalling never blocks, so a fake clock may call it.
private final class PhaseLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func signal() {
        let pending: [CheckedContinuation<Void, Never>] = lock.withLock {
            fired = true
            let result = waiters
            waiters = []
            return result
        }
        for waiter in pending { waiter.resume() }
    }
    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let ready: Bool = lock.withLock {
                if fired { return true }
                waiters.append(continuation)
                return false
            }
            if ready { continuation.resume() }
        }
    }
}

private final class PhaseClock: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0
    var readCount: Int { lock.withLock { reads } }
    func read() -> UInt64 { lock.withLock { reads += 1; return UInt64(reads) * 10 } }
}

private final class PhaseSink: @unchecked Sendable {
    private let lock = NSLock()
    private var summaries: [Record.Summary] = []
    var values: [Record.Summary] { lock.withLock { summaries } }
    func append(_ value: Record.Summary) { lock.withLock { summaries.append(value) } }
}

/// One fresh record with its own fake clock and sink.
private final class PhaseHarness: @unchecked Sendable {
    let clock: PhaseClock
    let sink: PhaseSink
    let record: Record
    init() {
        let clock = PhaseClock(), sink = PhaseSink()
        self.clock = clock
        self.sink = sink
        record = Record(clock: { clock.read() }, sink: { sink.append($0) })
    }
}

/// The test factory seam: each invocation returns a distinct fresh record, or nil when `returnsNil`.
private final class PhaseFactory: @unchecked Sendable {
    private let lock = NSLock()
    private let returnsNil: Bool
    private var invocations = 0
    private var made: [PhaseHarness] = []
    init(returnsNil: Bool = false) { self.returnsNil = returnsNil }
    var calls: Int { lock.withLock { invocations } }
    var harnesses: [PhaseHarness] { lock.withLock { made } }
    func make() -> Record? {
        lock.withLock { invocations += 1 }
        if returnsNil { return nil }
        let harness = PhaseHarness()
        lock.withLock { made.append(harness) }
        return harness.record
    }
}

/// Counts the existing cooperative checkpoints. Each call signals its own latch; `holdAt` blocks that
/// call's worker thread until `release()`, so a read can be held at an exact boundary without sleeping.
private final class PhaseCheckpointProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let holdAt: Int?
    private let readsNow: @Sendable () -> Int
    private let gate = DispatchSemaphore(value: 0)
    private var calls = 0
    private var latches: [Int: PhaseLatch] = [:]
    private var readsAtCall: [Int: Int] = [:]
    private let resumedLatch = PhaseLatch()
    init(holdAt: Int? = nil, readsNow: @escaping @Sendable () -> Int = { -1 }) {
        self.holdAt = holdAt
        self.readsNow = readsNow
    }
    var count: Int { lock.withLock { calls } }
    func reads(atCall n: Int) -> Int? { lock.withLock { readsAtCall[n] } }
    func reached(_ n: Int) -> PhaseLatch {
        lock.withLock {
            if let existing = latches[n] { return existing }
            let made = PhaseLatch()
            latches[n] = made
            return made
        }
    }
    var resumed: PhaseLatch { resumedLatch }
    func checkpoint() {
        let now = readsNow()
        let n: Int = lock.withLock { calls += 1; readsAtCall[calls] = now; return calls }
        reached(n).signal()
        if n == holdAt {
            gate.wait()
            resumedLatch.signal()
        }
    }
    func release() { gate.signal() }
}

/// Native stub: records the task-local record it sees; optionally holds (ignoring cancellation) until
/// the test releases it. `barrier` signals once that many calls are inside.
private final class PhaseNativeStub: ScriptingNativeDecompiling, @unchecked Sendable {
    private let lock = NSLock()
    private let holds: Bool
    private let barrier: Int
    private var seen: [Record?] = []
    private let gate = PhaseLatch()
    let entered = PhaseLatch()
    private let outcome: ScriptingNativeDecompileOutcome?
    init(holds: Bool = false, barrier: Int = 1, outcome: ScriptingNativeDecompileOutcome? = nil) {
        self.holds = holds
        self.barrier = barrier
        self.outcome = outcome
    }
    var calls: Int { lock.withLock { seen.count } }
    var observed: [Record?] { lock.withLock { seen } }
    func release() { gate.signal() }
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        let current = Record.current()
        let total: Int = lock.withLock { seen.append(current); return seen.count }
        if total >= barrier { entered.signal() }
        if holds { await gate.wait() }
        if let outcome { return outcome }
        return .completed(.init(text: "void f(void) {}", language: "c",
                                isComplete: true, isTruncated: false))
    }
}

@MainActor
final class NativeDecompilerAPIPhaseTests: XCTestCase {
    private let mainArguments = ScriptValue.object(["function": .string("_main")])
    private let bytesText = "function too large: 262145 bytes, 0 blocks (limits: 262144 bytes, 8192 blocks); refused before lifting"
    private let deadlineText = "decompile deadline: no result within 50 ms; the read was cancelled and no partial output is returned"

    private typealias PhaseTable = [Record.Phase: (completed: UInt64, duration: UInt64, exclusive: UInt64)]

    // MARK: T1 all eight phases, hand-worked arithmetic

    func testT1AllEightPhasesOnNativeSuccess() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let api = makeAPI(smallStore(), native: stub, factory: factory)
        _ = try await api.executeAsync("decompile", arguments: mainArguments)
        XCTAssertEqual(factory.calls, 1)
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 18)
        XCTAssertEqual(stub.observed.count, 1)
        XCTAssertTrue(stub.observed.first.flatMap { $0 } === harness.record, "the worker sees the attempt's record")
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: fullTable, elapsed: 170, covered: 150, residual: 20)
        XCTAssertEqual(summary.exclusiveDurations.reduce(0, +), 150)
        assertNewCounters(summary)
    }

    // MARK: T2 tracing off: behavioral identity

    func testT2OffIsInertAndRepliesAreIdentical() async throws {
        let store = smallStore()
        let onFactory = PhaseFactory()
        let onStub = PhaseNativeStub()
        let on = try await makeAPI(store, native: onStub, factory: onFactory)
            .executeAsync("decompile", arguments: mainArguments)
        let offFactory = PhaseFactory(returnsNil: true)
        let offStub = PhaseNativeStub()
        let off = try await makeAPI(store, native: offStub, factory: offFactory)
            .executeAsync("decompile", arguments: mainArguments)
        XCTAssertEqual(offFactory.calls, 1)
        XCTAssertTrue(offFactory.harnesses.isEmpty, "no record is constructed")
        XCTAssertEqual(offStub.observed.count, 1)
        XCTAssertNil(offStub.observed.first.flatMap { $0 }, "no task-local record is installed when off")
        XCTAssertEqual(on, off)
        XCTAssertEqual(try ScriptValue.decode(try on.jsonData()), try ScriptValue.decode(try off.jsonData()))
        let harness = try XCTUnwrap(onFactory.harnesses.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        // Frozen fields of the success reply (DESIGN section 7).
        XCTAssertEqual(off["function"], .string("_main"))
        XCTAssertEqual(off["address"], .hex(0x1000))
        XCTAssertEqual(off["pseudocode"], .string("void f(void) {}"))
        XCTAssertEqual(off["structured"], .bool(false))
        XCTAssertEqual(off["lines"], .array([.object(["n": .int(1), "text": .string("void f(void) {}")])]))
        XCTAssertEqual(off["backend"], .string("native"))
        XCTAssertEqual(off["language"], .string("c"))
        XCTAssertEqual(off["complete"], .bool(true))
        XCTAssertEqual(off["truncated"], .bool(false))
        XCTAssertEqual(off["responseComplete"], .bool(true))
        XCTAssertEqual(off["resolvedFunction"], .hex(0x1000))
        XCTAssertEqual(off["resolution"], .string("exact"))
        for absent in ["backendRequested", "cache", "generation", "fallbackReason", "requestedAddress"] {
            XCTAssertNil(off[absent], absent)
        }
    }

    // MARK: T3 size refusal, with off identity of the refusal

    func testT3SizeRefusalClosesPrefix() async throws {
        let address = ScriptValue.object(["address": .hex(0x1000)])
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let api = makeAPI(sizedStore(bytes: 262_145, blocks: 0), native: stub, factory: factory)
        var onText: String?
        do {
            _ = try await api.executeAsync("decompile", arguments: address)
            XCTFail("expected a size refusal")
        } catch {
            onText = (error as? LocalizedError)?.errorDescription
        }
        XCTAssertEqual(onText, bytesText)
        XCTAssertEqual(stub.calls, 0)
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 12)
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: [
            .snapshotRead: (1, 90, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 50, 30),
            .selector: (1, 10, 10), .sizeCheck: (1, 10, 10),
        ], elapsed: 110, covered: 90, residual: 20)
        XCTAssertTrue(summary.counterObserved[Record.Counter.functionsConsidered.rawValue])
        XCTAssertEqual(summary.counts[Record.Counter.functionsConsidered.rawValue], 2)
        XCTAssertTrue(summary.counterObserved[Record.Counter.blocksVisited.rawValue])
        XCTAssertEqual(summary.counts[Record.Counter.blocksVisited.rawValue], 0)
        XCTAssertFalse(summary.counterObserved[Record.Counter.overridesVisited.rawValue])
        // Off run: the identical refusal.
        let offApi = makeAPI(sizedStore(bytes: 262_145, blocks: 0), native: PhaseNativeStub(),
                             factory: PhaseFactory(returnsNil: true))
        do {
            _ = try await offApi.executeAsync("decompile", arguments: address)
            XCTFail("expected a size refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, onText)
        }
    }

    // MARK: T4a deterministic deadline before the selector

    func testT4aDeadlineBeforeSelector() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let probe = PhaseCheckpointProbe(holdAt: 1, readsNow: { factory.harnesses.first?.clock.readCount ?? -1 })
        defer { probe.release() }
        let api = makeAPI(smallStore(), native: stub, factory: factory, probe: probe, deadline: 50_000_000)
        do {
            _ = try await api.executeAsync("decompile", arguments: mainArguments)
            XCTFail("expected a deadline refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, deadlineText)
        }
        let harness = try XCTUnwrap(factory.harnesses.first)
        // The summary is sealed while the worker is still blocked at its entry checkpoint.
        XCTAssertEqual(harness.clock.readCount, 8)
        XCTAssertEqual(harness.sink.values.count, 1)
        let summary = try XCTUnwrap(harness.sink.values.first)
        assertSummary(summary, phases: [
            .snapshotRead: (1, 50, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 10, 10),
        ], elapsed: 70, covered: 50, residual: 20)
        for counter in Record.Counter.allCases {
            XCTAssertFalse(summary.counterObserved[counter.rawValue], "\(counter)")
        }
        // Late explicit begin/end/add after the seal are no-ops without a clock read.
        XCTAssertNil(harness.record.begin(.selector))
        harness.record.end(nil)
        harness.record.add(.blocksVisited, 1)
        harness.record.finish()
        XCTAssertEqual(harness.clock.readCount, 8)
        XCTAssertEqual(harness.sink.values, [summary])
        // Release the worker and await its acknowledgement; cancellation stops it before the selector.
        probe.release()
        await probe.resumed.wait()
        XCTAssertEqual(probe.reads(atCall: 1), 5, "the root, capture and wait begins precede worker entry")
        XCTAssertEqual(stub.calls, 0)
        XCTAssertEqual(harness.clock.readCount, 8)
        XCTAssertEqual(harness.sink.values, [summary])
    }

    // MARK: T4b deadline while the native stub waits (set-valued oracle for the live race)

    func testT4bDeadlineWhileNativeWaits() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub(holds: true)
        defer { stub.release() }
        let api = makeAPI(smallStore(), native: stub, factory: factory, deadline: 50_000_000)
        do {
            _ = try await api.executeAsync("decompile", arguments: mainArguments)
            XCTFail("expected a deadline refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, deadlineText)
        }
        let harness = try XCTUnwrap(factory.harnesses.first)
        let reads = harness.clock.readCount
        XCTAssertEqual(harness.sink.values.count, 1, "one deadline result and one summary")
        let summary = try XCTUnwrap(harness.sink.values.first)
        // Legal prefix: 8 caller/capture/wait reads plus k admitted and c completed worker spans of S/Z/M.
        let worker: [Record.Phase] = [.selector, .sizeCheck, .comments]
        let completedCounts = worker.map { summary.completedSpans[$0.rawValue] }
        let c = Int(completedCounts.reduce(0, +))
        let k = reads - 8 - c
        XCTAssertTrue((0...3).contains(c), "completed worker spans")
        XCTAssertTrue(k == c || k == c + 1, "k=\(k) c=\(c): at most one worker span is open")
        XCTAssertLessThanOrEqual(k, 3)
        XCTAssertEqual(summary.unfinishedSpans, UInt64(max(0, k - c)))
        XCTAssertEqual(summary.attributionComplete, k == c)
        XCTAssertEqual(summary.suppressedSpans, 0)
        XCTAssertEqual(summary.droppedIntervals, 0)
        XCTAssertEqual(summary.elapsedNanoseconds, UInt64(reads - 1) * 10)
        XCTAssertEqual(summary.coveredNanoseconds + summary.residualNanoseconds, summary.elapsedNanoseconds)
        // Completion is a prefix: M implies Z implies S; nothing past the native await exists.
        XCTAssertGreaterThanOrEqual(completedCounts[0], completedCounts[1])
        XCTAssertGreaterThanOrEqual(completedCounts[1], completedCounts[2])
        XCTAssertEqual(summary.completedSpans[Record.Phase.nativeObject.rawValue], 0)
        XCTAssertEqual(summary.completedSpans[Record.Phase.finalShape.rawValue], 0)
        XCTAssertEqual(summary.completedSpans[Record.Phase.snapshotRead.rawValue], 1)
        XCTAssertEqual(summary.completedSpans[Record.Phase.snapshotCapture.rawValue], 1)
        XCTAssertEqual(summary.completedSpans[Record.Phase.detachedWait.rawValue], 1)
        if reads == 14 && c == 3 {
            // Native-await prefix: hand-worked in DESIGN section 7.
            assertSummary(summary, phases: [
                .snapshotRead: (1, 110, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 70, 40),
                .selector: (1, 10, 10), .sizeCheck: (1, 10, 10), .comments: (1, 10, 10),
            ], elapsed: 130, covered: 110, residual: 20)
        }
        // Releasing the held stub afterwards changes nothing.
        stub.release()
        XCTAssertEqual(harness.clock.readCount, reads)
        XCTAssertEqual(harness.sink.values, [summary])
    }

    // MARK: T5 caller cancellation inside the native await

    func testT5CallerCancellationInNativeAwait() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub(holds: true)
        let probe = PhaseCheckpointProbe()
        defer { stub.release() }
        let api = makeAPI(smallStore(), native: stub, factory: factory, probe: probe, deadline: 10_000_000_000)
        let arguments = mainArguments
        let task = Task { try await api.executeAsync("decompile", arguments: arguments) }
        defer { task.cancel() }
        await stub.entered.wait()
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "a cancellation, not a relabeled deadline: \(error)")
        }
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 14)
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: [
            .snapshotRead: (1, 110, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 70, 40),
            .selector: (1, 10, 10), .sizeCheck: (1, 10, 10), .comments: (1, 10, 10),
        ], elapsed: 130, covered: 110, residual: 20)
        // The stub resumes and the post-native checkpoint throws; no later clock read.
        stub.release()
        await probe.reached(3).wait()
        XCTAssertEqual(harness.clock.readCount, 14)
        XCTAssertEqual(harness.sink.values, [summary])
    }

    // MARK: T5b cancellation with an open worker span

    func testT5bCancellationWithOpenWorkerSpan() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let probe = PhaseCheckpointProbe(holdAt: 2)
        defer { probe.release() }
        let api = makeAPI(smallStore(), native: stub, factory: factory, probe: probe, deadline: 10_000_000_000)
        let arguments = mainArguments
        let task = Task { try await api.executeAsync("decompile", arguments: arguments) }
        defer { task.cancel() }
        await probe.reached(2).wait()
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 11)
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: [
            .snapshotRead: (1, 80, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 40, 30),
            .selector: (1, 10, 10),
        ], elapsed: 100, covered: 80, residual: 20, unfinished: 1, complete: false)
        XCTAssertEqual(summary.completedSpans[Record.Phase.sizeCheck.rawValue], 0)
        XCTAssertTrue(summary.counterObserved[Record.Counter.functionsConsidered.rawValue])
        XCTAssertEqual(summary.counts[Record.Counter.functionsConsidered.rawValue], 2)
        XCTAssertFalse(summary.counterObserved[Record.Counter.blocksVisited.rawValue],
                       "the helper's deferred add runs after the seal and is ignored")
        XCTAssertFalse(summary.counterObserved[Record.Counter.overridesVisited.rawValue])
        probe.release()
        await probe.resumed.wait()
        XCTAssertEqual(harness.clock.readCount, 11)
        XCTAssertEqual(harness.sink.values, [summary])
        XCTAssertEqual(stub.calls, 0)
    }

    // MARK: T6 throw inside the selector

    func testT6ThrowInsideSelectorClosesSpan() async throws {
        let arguments = ScriptValue.object(["function": .string("_main"), "backend": .string("invalid")])
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let api = makeAPI(smallStore(), native: stub, factory: factory)
        var onText: String?
        do {
            _ = try await api.executeAsync("decompile", arguments: arguments)
            XCTFail("expected an invalid argument")
        } catch {
            XCTAssertTrue(error is ScriptingError, "\(error)")
            onText = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
        }
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 10)
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: [
            .snapshotRead: (1, 70, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 30, 20),
            .selector: (1, 10, 10),
        ], elapsed: 90, covered: 70, residual: 20)
        XCTAssertFalse(summary.counterObserved[Record.Counter.functionsConsidered.rawValue],
                       "the backend parser fails before function resolution")
        XCTAssertEqual(stub.calls, 0)
        // Same error with tracing off.
        let offApi = makeAPI(smallStore(), native: PhaseNativeStub(), factory: PhaseFactory(returnsNil: true))
        do {
            _ = try await offApi.executeAsync("decompile", arguments: arguments)
            XCTFail("expected an invalid argument")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription ?? String(describing: error), onText)
        }
    }

    // MARK: T7 idempotent finish and late spans

    func testT7FinishIsIdempotentAndLateSpansAreIgnored() async throws {
        let factory = PhaseFactory()
        let api = makeAPI(smallStore(), native: PhaseNativeStub(), factory: factory)
        _ = try await api.executeAsync("decompile", arguments: mainArguments)
        let harness = try XCTUnwrap(factory.harnesses.first)
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.clock.readCount, 18)
        harness.record.finish()
        harness.record.end(nil)
        XCTAssertNil(harness.record.begin(.selector))
        XCTAssertNil(harness.record.begin(.finalShape))
        harness.record.add(.blocksVisited, 9)
        harness.record.add(.functionsConsidered, 9)
        harness.record.finish()
        XCTAssertEqual(harness.clock.readCount, 18, "no clock read after the seal")
        XCTAssertEqual(harness.sink.values, [summary], "one immutable summary, same attempt id")
        // A closed token cannot reopen or double-count a span.
        let local = PhaseHarness()
        let token = local.record.begin(.selector)
        local.record.end(token)
        local.record.end(token)
        local.record.finish()
        local.record.end(token)
        let sealed = try XCTUnwrap(local.sink.values.first)
        XCTAssertEqual(local.sink.values.count, 1)
        XCTAssertEqual(sealed.completedSpans[Record.Phase.selector.rawValue], 1)
        XCTAssertEqual(local.clock.readCount, 4, "init, begin, end, finish only")
    }

    // MARK: T8 gate exclusions: no factory call, record, clock or summary

    func testT8GateExclusions() async throws {
        let store = smallStore()
        // (a) no native binding: async decompile is the MacIR control.
        let factoryA = PhaseFactory()
        let replyA = try await makeAPI(store, native: nil, factory: factoryA)
            .executeAsync("decompile", arguments: .object(["function": .string("helper")]))
        XCTAssertEqual(replyA["backend"], .string("macir"))
        XCTAssertEqual(factoryA.calls, 0)
        // (b) native supplied, other async snapshot read.
        let factoryB = PhaseFactory()
        let stubB = PhaseNativeStub()
        let blocks = try await makeAPI(store, native: stubB, factory: factoryB)
            .executeAsync("basic-blocks", arguments: .object(["address": .hex(0x1000)]))
        XCTAssertEqual(blocks.arrayValue?.count, 1)
        XCTAssertEqual(factoryB.calls, 0)
        XCTAssertEqual(stubB.calls, 0)
        // (c) synchronous decompile with native supplied.
        let factoryC = PhaseFactory()
        let syncReply = try makeAPI(store, native: PhaseNativeStub(), factory: factoryC)
            .execute("decompile", arguments: .object(["function": .string("helper")]))
        XCTAssertEqual(syncReply["backend"], .string("macir"))
        XCTAssertEqual(syncReply["fallbackReason"], .string("native-unavailable"))
        XCTAssertEqual(factoryC.calls, 0)
        // (d) a task cancelled before the invocation reaches the API's first cancellation check.
        let factoryD = PhaseFactory()
        let stubD = PhaseNativeStub()
        let apiD = makeAPI(store, native: stubD, factory: factoryD)
        let start = PhaseLatch()
        let arguments = mainArguments
        let task = Task { () throws -> ScriptValue in
            await start.wait()
            return try await apiD.executeAsync("decompile", arguments: arguments)
        }
        task.cancel()
        start.signal()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
        XCTAssertEqual(factoryD.calls, 0)
        XCTAssertEqual(stubD.calls, 0)
        XCTAssertTrue(factoryD.harnesses.isEmpty)
    }

    // MARK: T9 concurrent attempts

    func testT9ConcurrentAttemptsAreIsolated() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub(holds: true, barrier: 2)
        defer { stub.release() }
        let api = makeAPI(smallStore(), native: stub, factory: factory, deadline: 10_000_000_000)
        let first = Task { try await api.executeAsync("decompile", arguments: .object(["function": .string("_main")])) }
        let second = Task { try await api.executeAsync("decompile", arguments: .object(["function": .string("helper")])) }
        defer { first.cancel(); second.cancel() }
        await stub.entered.wait()
        XCTAssertEqual(factory.calls, 2, "one fresh record per invocation, never reentered")
        stub.release()
        _ = try await first.value
        _ = try await second.value
        let harnesses = factory.harnesses
        XCTAssertEqual(harnesses.count, 2)
        XCTAssertFalse(harnesses[0].record === harnesses[1].record)
        XCTAssertNotEqual(harnesses[0].record.attemptID, harnesses[1].record.attemptID)
        let seen = stub.observed.compactMap { $0 }
        XCTAssertEqual(seen.count, 2)
        XCTAssertFalse(seen[0] === seen[1])
        for harness in harnesses {
            XCTAssertTrue(seen.contains { $0 === harness.record }, "each worker sees exactly its own record")
            XCTAssertEqual(harness.clock.readCount, 18, "the sequence is independent of interleaving")
            XCTAssertEqual(harness.sink.values.count, 1)
            let summary = try XCTUnwrap(harness.sink.values.first)
            assertSummary(summary, phases: fullTable, elapsed: 170, covered: 150, residual: 20)
            assertNewCounters(summary)
        }
        XCTAssertNotEqual(harnesses[0].sink.values.first?.attemptID, harnesses[1].sink.values.first?.attemptID)
    }

    // MARK: T10 counters (the name-selector variant is T1/T9; this is the address selector)

    func testT10CountersByAddressSelector() async throws {
        let factory = PhaseFactory()
        let api = makeAPI(smallStore(), native: PhaseNativeStub(), factory: factory)
        _ = try await api.executeAsync("decompile", arguments: .object(["address": .hex(0x1000)]))
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 18, "counters consume no clock reads")
        let summary = try XCTUnwrap(harness.sink.values.first)
        assertSummary(summary, phases: fullTable, elapsed: 170, covered: 150, residual: 20)
        assertNewCounters(summary)
    }

    // MARK: T11 finalShape throw (dot item 1308 landing, DESIGN 1306 section 7)

    func testT11FinalShapeThrowStillClosesTheSpan() async throws {
        let arguments = ScriptValue.object(["function": .string("_main"), "lineRange": .string("2-2")])
        let factory = PhaseFactory()
        let api = makeAPI(smallStore(), native: PhaseNativeStub(), factory: factory)
        var onText: String?
        do {
            _ = try await api.executeAsync("decompile", arguments: arguments)
            XCTFail("expected lineRange 2-2 to be refused on a one-line document")
        } catch {
            onText = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
        }
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 18)
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: fullTable, elapsed: 170, covered: 150, residual: 20)
        XCTAssertEqual(summary.completedSpans[Record.Phase.finalShape.rawValue], 1)
        let offApi = makeAPI(smallStore(), native: PhaseNativeStub(), factory: PhaseFactory(returnsNil: true))
        do {
            _ = try await offApi.executeAsync("decompile", arguments: arguments)
            XCTFail("expected the same refusal with tracing off")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription ?? String(describing: error), onText)
        }
    }

    // MARK: T12 backend both ends finalShape before MacIR

    func testT12BothEndsFinalShapeBeforeMacIR() async throws {
        let arguments = ScriptValue.object(["function": .string("_main"), "backend": .string("both")])
        let store = smallStore()
        let factory = PhaseFactory()
        let probe = PhaseCheckpointProbe(readsNow: { [factory] in factory.harnesses.first?.clock.readCount ?? -1 })
        let on = await routeOutcome(makeAPI(store, native: PhaseNativeStub(), factory: factory, probe: probe),
                                    arguments)
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.clock.readCount, 18, "F ended at 15; W end, R end and finish are 16-18")
        let seen = (1...probe.count).compactMap { probe.reads(atCall: $0) }
        XCTAssertFalse(seen.contains(14), "no checkpoint runs while finalShape is open")
        XCTAssertEqual(seen.last, 15, "the first MacIR entry checkpoint (and the last) sees 15 reads")
        let summary = try XCTUnwrap(harness.sink.values.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        assertSummary(summary, phases: fullTable, elapsed: 170, covered: 150, residual: 20)
        let off = await routeOutcome(
            makeAPI(store, native: PhaseNativeStub(), factory: PhaseFactory(returnsNil: true)), arguments)
        XCTAssertEqual(on, off)
    }

    // MARK: T13 reachability of the non-success native outcomes and the MacIR routes

    func testT13NativeNonSuccessOutcomesAreStructuredRefusals() async throws {
        let blank = NativeDecompilerWirePseudocodeDocument(
            text: " \n", language: "c", isComplete: true, isTruncated: false)
        let outcomes: [(String, ScriptingNativeDecompileOutcome)] = [
            ("completed-nil", .completed(nil)), ("blank", .completed(blank)),
            ("unavailable", .unavailable), ("busy", .failed(code: "busy")),
        ]
        let arguments = ScriptValue.object(["function": .string("_main"), "backend": .string("native")])
        for (label, outcome) in outcomes {
            let factory = PhaseFactory()
            let stub = PhaseNativeStub(outcome: outcome)
            let api = makeAPI(smallStore(), native: stub, factory: factory)
            do {
                _ = try await api.executeAsync("decompile", arguments: arguments)
                XCTFail("\(label): expected a structured refusal")
            } catch {
                guard case .structuredRefusal = error as? ScriptingError else {
                    XCTFail("\(label): not a structured refusal: \(error)")
                    continue
                }
            }
            XCTAssertEqual(stub.calls, 1, label)
            let harness = try XCTUnwrap(factory.harnesses.first, label)
            XCTAssertEqual(harness.clock.readCount, 14, label)
            let summary = try XCTUnwrap(harness.sink.values.first, label)
            XCTAssertEqual(harness.sink.values.count, 1, label)
            assertSummary(summary, phases: [
                .snapshotRead: (1, 110, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 70, 40),
                .selector: (1, 10, 10), .sizeCheck: (1, 10, 10), .comments: (1, 10, 10),
            ], elapsed: 130, covered: 110, residual: 20)
        }
    }

    func testT13FallbackFoldAndMacIRRoutesMatchTracingOff() async throws {
        let store = smallStore()
        let routes: [(String, ScriptValue, Set<Record.Phase>)] = [
            ("implicit fallback", mainArguments,
             [.snapshotRead, .snapshotCapture, .detachedWait, .selector, .sizeCheck, .comments]),
            ("explicit macir", .object(["function": .string("_main"), "backend": .string("macir")]),
             [.snapshotRead, .snapshotCapture, .detachedWait, .selector, .sizeCheck]),
            ("fold", .object(["function": .string("_main"), "fold": .array([.string("arc")])]),
             [.snapshotRead, .snapshotCapture, .detachedWait, .selector, .sizeCheck]),
        ]
        for (label, arguments, reached) in routes {
            let factory = PhaseFactory()
            let on = await routeOutcome(
                makeAPI(store, native: PhaseNativeStub(outcome: .unavailable), factory: factory), arguments)
            let off = await routeOutcome(
                makeAPI(store, native: PhaseNativeStub(outcome: .unavailable),
                        factory: PhaseFactory(returnsNil: true)), arguments)
            XCTAssertEqual(on, off, label)
            let harness = try XCTUnwrap(factory.harnesses.first, label)
            let summary = try XCTUnwrap(harness.sink.values.first, label)
            XCTAssertEqual(harness.sink.values.count, 1, label)
            let got = Set(Record.Phase.allCases.filter { (summary.completedSpans[$0.rawValue]) > 0 })
            XCTAssertEqual(got, reached, label)
            XCTAssertEqual(summary.unfinishedSpans, 0, label)
        }
    }

    private enum RouteOutcome: Equatable {
        case value(ScriptValue)
        case failure(String)
    }

    private func routeOutcome(_ api: WorkspaceScriptingAPI, _ arguments: ScriptValue) async -> RouteOutcome {
        do {
            return .value(try await api.executeAsync("decompile", arguments: arguments))
        } catch {
            return .failure((error as? LocalizedError)?.errorDescription ?? String(describing: error))
        }
    }

    // MARK: WR02 TC09 zero deadline and pre-cancelled task

    private var zeroDeadlineText: String { DecompileBudgetRefusal.deadline(milliseconds: 0).errorDescription ?? "" }

    func testWR02TC09ZeroDeadlineGivesExactRefusalAndLateWorkIsInert() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let probe = PhaseCheckpointProbe(holdAt: 1, readsNow: { factory.harnesses.first?.clock.readCount ?? -1 })
        defer { probe.release() }
        let api = makeAPI(smallStore(), native: stub, factory: factory, probe: probe, deadline: 0)
        do {
            _ = try await api.executeAsync("decompile", arguments: mainArguments)
            XCTFail("expected a zero-deadline refusal")
        } catch {
            XCTAssertEqual((error as? LocalizedError)?.errorDescription, zeroDeadlineText)
        }
        XCTAssertTrue(zeroDeadlineText.contains("within 0 ms"))
        let harness = try XCTUnwrap(factory.harnesses.first)
        XCTAssertEqual(harness.sink.values.count, 1)
        let summary = try XCTUnwrap(harness.sink.values.first)
        // Set-valued prefix oracle: completed (selector, sizeCheck, comments) is one of four prefixes.
        let tuple = [Record.Phase.selector, .sizeCheck, .comments].map { summary.completedSpans[$0.rawValue] }
        XCTAssertTrue([[0, 0, 0], [1, 0, 0], [1, 1, 0], [1, 1, 1]].contains(tuple), "\(tuple)")
        XCTAssertEqual(summary.completedSpans[Record.Phase.nativeObject.rawValue], 0)
        XCTAssertEqual(summary.completedSpans[Record.Phase.finalShape.rawValue], 0)
        XCTAssertEqual(summary.suppressedSpans, 0)
        XCTAssertEqual(summary.droppedIntervals, 0)
        let reads = harness.clock.readCount
        probe.release()
        await probe.resumed.wait()
        XCTAssertEqual(stub.calls, 0)
        XCTAssertEqual(harness.clock.readCount, reads, "late operations read no clock")
        XCTAssertEqual(harness.sink.values, [summary], "the saved summary is unchanged")
    }

    func testWR02TC09PreCancelledTaskProducesNoSummary() async throws {
        let factory = PhaseFactory()
        let stub = PhaseNativeStub()
        let api = makeAPI(smallStore(), native: stub, factory: factory)
        let arguments = mainArguments
        let task = Task { try await api.executeAsync("decompile", arguments: arguments) }
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
        XCTAssertEqual(factory.harnesses.reduce(0) { $0 + $1.sink.values.count }, 0)
        XCTAssertEqual(stub.calls, 0)
    }

    // MARK: WR02 TC10 exact size boundaries

    func testWR02TC10SizeBoundariesAndRefusalPrecedence() async throws {
        let address = ScriptValue.object(["address": .hex(0x1000)])
        // (bytes, blocks, admits)
        let cases: [(UInt64, Int, Bool)] = [
            (262_144, 0, true), (262_145, 0, false), (262_144, 8_192, true), (262_144, 8_193, false),
        ]
        for (bytes, blocks, admits) in cases {
            let label = "\(bytes) bytes, \(blocks) blocks"
            let factory = PhaseFactory()
            let stub = PhaseNativeStub()
            let api = makeAPI(sizedStore(bytes: bytes, blocks: blocks), native: stub, factory: factory)
            var refusalText: String?
            do {
                _ = try await api.executeAsync("decompile", arguments: address)
                XCTAssertTrue(admits, "unexpected admission: \(label)")
            } catch {
                XCTAssertFalse(admits, "unexpected refusal: \(label): \(error)")
                refusalText = (error as? LocalizedError)?.errorDescription
            }
            let harness = try XCTUnwrap(factory.harnesses.first, label)
            let summary = try XCTUnwrap(harness.sink.values.first, label)
            XCTAssertEqual(harness.sink.values.count, 1, label)
            func observed(_ counter: Record.Counter) -> UInt64? {
                summary.counterObserved[counter.rawValue] ? summary.counts[counter.rawValue] : nil
            }
            XCTAssertEqual(observed(.functionsConsidered), 2, label)
            XCTAssertEqual(observed(.blocksVisited), UInt64(blocks), label)
            for phase in [Record.Phase.snapshotRead, .snapshotCapture, .detachedWait, .selector, .sizeCheck] {
                XCTAssertEqual(summary.completedSpans[phase.rawValue], 1, "\(phase) \(label)")
            }
            if admits {
                XCTAssertEqual(stub.calls, 1, label)
                XCTAssertNil(refusalText, label)
            } else {
                XCTAssertEqual(refusalText, DecompileBudgetRefusal.tooLarge(bytes: bytes, blocks: blocks).errorDescription, label)
                XCTAssertEqual(stub.calls, 0, label)
                for phase in [Record.Phase.comments, .nativeObject, .finalShape] {
                    XCTAssertEqual(summary.completedSpans[phase.rawValue], 0, "\(phase) \(label)")
                }
                for counter in [Record.Counter.captureHits, .captureMisses, .captureOverCap,
                                .resultCacheHits, .resultCacheMisses, .canonicalPasses] {
                    XCTAssertNil(observed(counter), "\(counter) \(label)")
                }
            }
        }
        // The empty block scan is observed as zero, not unobserved.
        let emptyFactory = PhaseFactory()
        _ = try await makeAPI(sizedStore(bytes: 262_144, blocks: 0), native: PhaseNativeStub(), factory: emptyFactory)
            .executeAsync("decompile", arguments: address)
        let emptySummary = try XCTUnwrap(emptyFactory.harnesses.first?.sink.values.first)
        XCTAssertTrue(emptySummary.counterObserved[Record.Counter.blocksVisited.rawValue])
        XCTAssertEqual(emptySummary.counts[Record.Counter.blocksVisited.rawValue], 0)
    }

    // MARK: WR02 TC11 comment presence and budgets

    func testWR02TC11OverridePresenceScanAndBackendBranches() async throws {
        let key = ImageAddress(slot: .primary, address: 0x1000)
        func observed(_ s: Record.Summary, _ counter: Record.Counter) -> UInt64? {
            s.counterObserved[counter.rawValue] ? s.counts[counter.rawValue] : nil
        }
        // One in-range nonblank override: the implicit route falls back to MacIR before native.
        let commented = smallStore()
        commented.snapshot.addressOverrides[key] = AddressOverride(customComment: "note")
        let commentedFactory = PhaseFactory()
        let commentedStub = PhaseNativeStub()
        _ = try await makeAPI(commented, native: commentedStub, factory: commentedFactory)
            .executeAsync("decompile", arguments: mainArguments)
        let commentedSummary = try XCTUnwrap(commentedFactory.harnesses.first?.sink.values.first)
        XCTAssertEqual(observed(commentedSummary, .overridesVisited), 1)
        XCTAssertEqual(commentedSummary.completedSpans[Record.Phase.comments.rawValue], 1)
        XCTAssertEqual(commentedStub.calls, 0)
        for counter in [Record.Counter.captureHits, .captureMisses, .canonicalPasses,
                        .resultCacheHits, .resultCacheMisses] {
            XCTAssertNil(observed(commentedSummary, counter), "\(counter)")
        }
        // Blank-only override: visited once, but it does not force the comments fallback.
        let blank = smallStore()
        blank.snapshot.addressOverrides[key] = AddressOverride(customComment: "   ")
        let blankFactory = PhaseFactory()
        let blankStub = PhaseNativeStub()
        _ = try await makeAPI(blank, native: blankStub, factory: blankFactory)
            .executeAsync("decompile", arguments: mainArguments)
        let blankSummary = try XCTUnwrap(blankFactory.harnesses.first?.sink.values.first)
        XCTAssertEqual(observed(blankSummary, .overridesVisited), 1)
        XCTAssertEqual(blankStub.calls, 1)
        // Explicit macir leaves the comments phase empty.
        let explicitFactory = PhaseFactory()
        let explicitStub = PhaseNativeStub()
        _ = try await makeAPI(commented, native: explicitStub, factory: explicitFactory)
            .executeAsync("decompile", arguments: .object(["function": .string("_main"), "backend": .string("macir")]))
        let explicitSummary = try XCTUnwrap(explicitFactory.harnesses.first?.sink.values.first)
        XCTAssertEqual(explicitSummary.completedSpans[Record.Phase.comments.rawValue], 0)
        XCTAssertEqual(explicitStub.calls, 0)
    }

    func testWR02TC11DirectCommentBudgetBoundaries() throws {
        func refusal(_ comments: [UInt64: String]) -> MCPToolRefusal? {
            do { try WorkspaceScriptingAPI.enforceUserCommentBudget(comments) } catch ScriptingError.structuredRefusal(let value) {
                return value
            } catch { XCTFail("unexpected error \(error)") }
            return nil
        }
        func rows(_ count: Int, text: String = "x") -> [UInt64: String] {
            Dictionary(uniqueKeysWithValues: (0..<count).map { (UInt64($0), text) })
        }
        XCTAssertNil(refusal(rows(4_096)))
        let overRows = try XCTUnwrap(refusal(rows(4_097)))
        XCTAssertEqual(overRows.code, .budgetExceeded)
        XCTAssertEqual(overRows.budget?.limit, 4_096)
        XCTAssertEqual(overRows.used, 4_097)
        XCTAssertEqual(overRows.narrowing, [])
        XCTAssertNil(refusal([0: String(repeating: "x", count: 1_048_576)]))
        let overBytes = try XCTUnwrap(refusal([0: String(repeating: "x", count: 1_048_577)]))
        XCTAssertEqual(overBytes.code, .budgetExceeded)
        XCTAssertEqual(overBytes.budget?.limit, 1_048_576)
        XCTAssertEqual(overBytes.used, 1_048_577)
        XCTAssertEqual(overBytes.narrowing, [])
        // Both caps exceeded: the row refusal wins (4,097 comments of 257 bytes is 1,052,929 bytes).
        let both = try XCTUnwrap(refusal(rows(4_097, text: String(repeating: "x", count: 257))))
        XCTAssertEqual(both.budget?.limit, 4_096)
        XCTAssertEqual(both.used, 4_097)
        XCTAssertEqual(both.budget?.unit, overRows.budget?.unit)
    }

    // MARK: WR02 TC12 tracing off is inert (nil-returning factory)

    func testWR02TC12NilFactoryIsInertAndRepliesMatch() async throws {
        let store = smallStore()
        let nilFactory = PhaseFactory(returnsNil: true)
        let off = try await makeAPI(store, native: PhaseNativeStub(), factory: nilFactory)
            .executeAsync("decompile", arguments: mainArguments)
        XCTAssertEqual(nilFactory.calls, 1, "the factory itself is asked once")
        XCTAssertTrue(nilFactory.harnesses.isEmpty, "no harness, clock or sink exists")
        let onFactory = PhaseFactory()
        let on = try await makeAPI(store, native: PhaseNativeStub(), factory: onFactory)
            .executeAsync("decompile", arguments: mainArguments)
        XCTAssertEqual(on, off)
        XCTAssertEqual(try on.jsonData(), try off.jsonData(), "serialized replies are equal")
        // Native nil and a non-decompile command never consult the attempt factory.
        let nativeNil = PhaseFactory(returnsNil: true)
        _ = try await makeAPI(store, native: nil, factory: nativeNil)
            .executeAsync("decompile", arguments: mainArguments)
        XCTAssertEqual(nativeNil.calls, 0)
        let other = PhaseFactory(returnsNil: true)
        _ = try await makeAPI(store, native: PhaseNativeStub(), factory: other)
            .executeAsync("basic-blocks", arguments: .object(["address": .hex(0x1000)]))
        XCTAssertEqual(other.calls, 0)
    }

    // MARK: Assertions

    private var fullTable: PhaseTable {
        [
            .snapshotRead: (1, 150, 30), .snapshotCapture: (1, 10, 10), .detachedWait: (1, 110, 60),
            .selector: (1, 10, 10), .sizeCheck: (1, 10, 10), .comments: (1, 10, 10),
            .nativeObject: (1, 10, 10), .finalShape: (1, 10, 10),
        ]
    }

    /// Phases absent from `phases` must be entirely zero.
    private func assertSummary(
        _ s: Record.Summary, phases: PhaseTable, elapsed: UInt64, covered: UInt64, residual: UInt64,
        unfinished: UInt64 = 0, complete: Bool = true,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        for phase in Record.Phase.allCases {
            let want = phases[phase] ?? (0, 0, 0)
            XCTAssertEqual(s.completedSpans[phase.rawValue], want.completed, "completed \(phase)", file: file, line: line)
            XCTAssertEqual(s.durations[phase.rawValue], want.duration, "duration \(phase)", file: file, line: line)
            XCTAssertEqual(s.exclusiveDurations[phase.rawValue], want.exclusive, "exclusive \(phase)", file: file, line: line)
        }
        XCTAssertEqual(s.elapsedNanoseconds, elapsed, file: file, line: line)
        XCTAssertEqual(s.coveredNanoseconds, covered, file: file, line: line)
        XCTAssertEqual(s.residualNanoseconds, residual, file: file, line: line)
        XCTAssertEqual(s.unfinishedSpans, unfinished, file: file, line: line)
        XCTAssertEqual(s.suppressedSpans, 0, file: file, line: line)
        XCTAssertEqual(s.droppedIntervals, 0, file: file, line: line)
        XCTAssertFalse(s.overlappingSpans, file: file, line: line)
        XCTAssertEqual(s.attributionComplete, complete, file: file, line: line)
    }

    /// T10: two functions, one basic block, no authored overrides, no builder, no facet memo.
    private func assertNewCounters(_ s: Record.Summary, file: StaticString = #filePath, line: UInt = #line) {
        let expected: [Record.Counter: (observed: Bool, count: UInt64)] = [
            .functionsConsidered: (true, 2), .blocksVisited: (true, 1), .overridesVisited: (true, 0),
            .xrefsVisited: (false, 0), .facetMemoHits: (false, 0), .facetMemoMisses: (false, 0),
        ]
        for (counter, want) in expected {
            XCTAssertEqual(s.counterObserved[counter.rawValue], want.observed, "observed \(counter)", file: file, line: line)
            XCTAssertEqual(s.counts[counter.rawValue], want.count, "count \(counter)", file: file, line: line)
        }
    }

    // MARK: Fixtures (copied from the private helpers of DecompileDeadlineTests / DecompileSizeRefusalTests)

    private func makeAPI(
        _ store: WorkspaceStore, native: (any ScriptingNativeDecompiling)?, factory: PhaseFactory?,
        probe: PhaseCheckpointProbe? = nil, deadline: UInt64 = 10_000_000_000
    ) -> WorkspaceScriptingAPI {
        var attempt: (@Sendable () -> Record?)?
        if let factory { attempt = { factory.make() } }
        var checkpoint: (@Sendable () -> Void)?
        if let probe { checkpoint = { probe.checkpoint() } }
        return WorkspaceScriptingAPI(
            store: store, snapshotReadCheckpoint: checkpoint, nativeDecompiler: native,
            decompileDeadlineNanoseconds: deadline, phaseAttempt: attempt)
    }

    private func sizedStore(bytes: UInt64, blocks: Int) -> WorkspaceStore {
        let id = UUID()
        let snap = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "size", path: "/tmp/size",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: id, name: "big", startAddress: 0x1000, endAddress: 0x1000 + bytes, confidence: 1),
                FunctionSummary(id: UUID(), name: "small", startAddress: 0x900000, endAddress: 0x900004, confidence: 1),
            ],
            basicBlocks: (0..<blocks).map {
                BasicBlockSummary(id: UUID(), functionID: id, startAddress: UInt64(0x1000 + $0 * 4),
                                  endAddress: UInt64(0x1004 + $0 * 4), instructionCount: 1)
            }, instructions: [], xrefs: [], hexBytes: Data())
        return WorkspaceStore(workspaceName: "size refusal", snapshot: snap,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func smallStore() -> WorkspaceStore {
        let id = UUID()
        let snap = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "names", path: "/tmp/names",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [
                FunctionSummary(id: id, name: "_main", startAddress: 0x1000, endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "helper", startAddress: 0x1008, endAddress: 0x100c, confidence: 1),
            ],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: id, startAddress: 0x1000,
                                           endAddress: 0x1008, instructionCount: 2)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov", operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "01 00 00 94", mnemonic: "bl", operands: "helper", hasBreakpoint: false, comment: "call"),
                InstructionRow(address: 0x1008, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
            ],
            xrefs: [XRef(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            controlFlowEdges: [ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x1008, kind: "call")],
            hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                                      size: 0x200, fileOffset: 0x1000, isExecutable: true)])
        return WorkspaceStore(workspaceName: "small control", snapshot: snap,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}
