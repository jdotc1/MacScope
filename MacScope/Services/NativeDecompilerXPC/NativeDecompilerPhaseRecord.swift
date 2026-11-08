import Foundation

/// App-only, bounded diagnostics. Never retained in a projection, wire value or reply.
final class NativeDecompilerPhaseRecord: @unchecked Sendable {
    enum Phase: Int, CaseIterable, Sendable {
        case snapshotRead, snapshotCapture, detachedWait, selector, sizeCheck, comments
        case ownedAdmission, projectionQueue, captureLookup, validation
        case sliceAndFingerprint, sliceDigest, fingerprint, segmentAttestation, imageFacets, projection
        case authoredPreview, contextAdmission, patchAndCave, authoredFinal, referenceCounts
        case canonicalRequest, codecAggregate, runtimeAuthority, cacheLookup, processQueue
        case dispatch, replyDecode, replyValidation, cacheRetention, nativeObject, finalShape
    }

    enum Counter: Int, CaseIterable, Sendable {
        case sliceDigestPasses, sliceDigestBytes, segmentDigestPasses, segmentDigestBytes
        case functionRows, xrefRows, instructionRows, relocationRows, sourceSymbolRows
        case projectedSymbolRows, retainedBytes, captureHits, captureMisses, captureOverCap
        case contextIterations, memoryRegions, rawRegionBytes, effectiveRegionBytes
        case authoredRows, omittedRows, encodedBytes, resultCacheHits, resultCacheMisses
        case canonicalPasses, traceRegistrationSuppressed
        case visitedInstructions, visitedBlocks, visitedEdges, visitedCalls
        case facetMemoHits, facetMemoMisses, xrefsVisited
        case blocksVisited, overridesVisited, functionsConsidered
    }

    struct Span: Sendable {
        fileprivate let slot: Int
        fileprivate let serial: UInt64
    }

    struct Summary: Equatable, Sendable {
        let attemptID: UUID
        let elapsedNanoseconds: UInt64
        /// Inclusive wall durations, indexed by Phase.rawValue. Never sum parent and child.
        let durations: [UInt64]
        let counts: [UInt64]
        /// False means unavailable/not observed, not a measured zero.
        let counterObserved: [Bool]
        let completedSpans: [UInt64]
        let suppressedSpans: UInt64
        let unfinishedSpans: UInt64
        /// Containment attribution, not CPU time or proof of task parentage.
        var exclusiveDurations = [UInt64](repeating: 0, count: Phase.allCases.count)
        var coveredNanoseconds: UInt64 = 0
        var residualNanoseconds: UInt64 = 0
        var overlappingSpans = false
        let droppedIntervals: UInt64
        let attributionComplete: Bool
    }

    private struct OpenSpan: Equatable {
        let serial: UInt64
        let phase: Phase
        let start: UInt64
    }

    private struct Interval {
        let phase: Phase
        let start: UInt64
        let end: UInt64
        let serial: UInt64
    }

    static let intervalCapacity = 256

    /// Forced once by H9 before launch serves a request. No persisted preference.
    static let launchEnabled: Bool = {
        guard let raw = ProcessInfo.processInfo.environment["MACSCOPE_NATIVE_PHASE_TRACE"] else {
            return false
        }
        return ["1", "true", "yes", "on"].contains(
            raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        )
    }()

    @TaskLocal private static var enabled = false
    @TaskLocal private static var active: NativeDecompilerPhaseRecord?

    /// An inactive path performs one cached Boolean check, without a clock/sink/lock access.
    static func current() -> NativeDecompilerPhaseRecord? {
        guard enabled else { return nil }
        return active
    }

    static func withTrace<T>(
        _ record: NativeDecompilerPhaseRecord?, operation: () throws -> T
    ) rethrows -> T {
        guard record != nil || enabled else { return try operation() }
        return try $enabled.withValue(record != nil) {
            try $active.withValue(record, operation: operation)
        }
    }

    static func withTrace<T>(
        _ record: NativeDecompilerPhaseRecord?,
        isolation: isolated (any Actor)? = #isolation,
        operation: () async throws -> T
    ) async rethrows -> T {
        guard record != nil || enabled else { return try await operation() }
        return try await $enabled.withValue(record != nil, operation: {
            try await $active.withValue(record, operation: operation, isolation: isolation)
        }, isolation: isolation)
    }

    static func makeAttempt() -> NativeDecompilerPhaseRecord? {
        guard launchEnabled else { return nil }
        return NativeDecompilerPhaseRecord()
    }

    static func measureCurrent<T>(_ phase: Phase, operation: () throws -> T) rethrows -> T {
        guard let trace = current() else { return try operation() }
        return try trace.measure(phase, operation: operation)
    }

    let attemptID: UUID
    private let lock = NSLock()
    private let clock: @Sendable () -> UInt64
    private let sink: @Sendable (Summary) -> Void
    private let export: (@Sendable (Summary) -> Void)?
    private let started: UInt64
    private var isFinished = false
    private var nextSerial: UInt64 = 0
    private var spans = [OpenSpan?](repeating: nil, count: 64)
    private var durations = [UInt64](repeating: 0, count: Phase.allCases.count)
    private var counts = [UInt64](repeating: 0, count: Counter.allCases.count)
    private var counterObserved = [Bool](repeating: false, count: Counter.allCases.count)
    private var completed = [UInt64](repeating: 0, count: Phase.allCases.count)
    private var suppressed: UInt64 = 0
    private var intervals = [Interval](repeating: Interval(
        phase: .snapshotRead, start: 0, end: 0, serial: 0
    ), count: NativeDecompilerPhaseRecord.intervalCapacity)
    private var intervalCount = 0
    private var dropped: UInt64 = 0
    private var retirements: [UUID: @Sendable () -> Void] = [:]

    init(
        attemptID: UUID = UUID(),
        clock: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        sink: @escaping @Sendable (Summary) -> Void = NativeDecompilerOperationalLogger.phase,
        export: (@Sendable (Summary) -> Void)? = NativeDecompilerPhaseExport.launchSink
    ) {
        self.attemptID = attemptID
        self.clock = clock
        self.sink = sink
        self.export = export
        started = clock()
    }

    func begin(_ phase: Phase) -> Span? {
        lock.withLock {
            guard !isFinished else { return nil }
            guard nextSerial < .max, let slot = spans.firstIndex(where: { $0 == nil }) else {
                suppressed = Self.adding(suppressed, 1)
                return nil
            }
            nextSerial += 1
            spans[slot] = OpenSpan(serial: nextSerial, phase: phase, start: clock())
            return Span(slot: slot, serial: nextSerial)
        }
    }

    func end(_ span: Span?) {
        guard let span else { return }
        lock.withLock {
            guard !isFinished, let open = spans[span.slot], open.serial == span.serial else {
                return
            }
            let end = clock()
            let elapsed = end >= open.start ? end - open.start : 0
            durations[open.phase.rawValue] = Self.adding(durations[open.phase.rawValue], elapsed)
            completed[open.phase.rawValue] = Self.adding(completed[open.phase.rawValue], 1)
            if intervalCount < Self.intervalCapacity {
                intervals[intervalCount] = Interval(
                    phase: open.phase, start: open.start, end: end, serial: open.serial
                )
                intervalCount += 1
            } else {
                dropped = Self.adding(dropped, 1)
            }
            spans[span.slot] = nil
        }
    }

    func add(_ counter: Counter, _ value: UInt64) {
        lock.withLock {
            guard !isFinished else { return }
            counterObserved[counter.rawValue] = true
            counts[counter.rawValue] = Self.adding(counts[counter.rawValue], value)
        }
    }

    func measure<T>(_ phase: Phase, operation: () throws -> T) rethrows -> T {
        let span = begin(phase)
        defer { end(span) }
        return try operation()
    }

    func measure<T>(_ phase: Phase, operation: () async throws -> T) async rethrows -> T {
        let span = begin(phase)
        defer { end(span) }
        return try await operation()
    }

    /// Idempotently seals even a timed-out attempt. Late callbacks cannot reopen it.
    func finish() {
        let terminal: (Summary, [Interval], UInt64, [@Sendable () -> Void])? = lock.withLock {
            guard !isFinished else { return nil }
            isFinished = true
            let end = clock()
            let unfinished = UInt64(spans.compactMap { $0 }.count)
            spans = [OpenSpan?](repeating: nil, count: 64)
            let summary = Summary(
                attemptID: attemptID,
                elapsedNanoseconds: end >= started ? end - started : 0,
                durations: durations, counts: counts, counterObserved: counterObserved,
                completedSpans: completed,
                suppressedSpans: suppressed, unfinishedSpans: unfinished,
                droppedIntervals: dropped,
                attributionComplete: dropped == 0 && unfinished == 0 && suppressed == 0
            )
            let cleanup = Array(retirements.values)
            retirements.removeAll()
            return (summary, Array(intervals.prefix(intervalCount)), end, cleanup)
        }
        if let (captured, log, end, cleanup) = terminal {
            // Never acquire a lookup lock while holding the record lock during cleanup.
            for retire in cleanup { retire() }
            var summary = captured
            attribute(log, endingAt: end, to: &summary)
            sink(summary)
            export?(summary)
        }
    }

    /// No clock or lock access. Partial overlap makes exclusive time approximate;
    /// even full containment can be a concurrent neighbour rather than a child (O2).
    private func attribute(_ log: [Interval], endingAt end: UInt64, to summary: inout Summary) {
        // Clip before attribution; invalid/zero intervals carry no measure. This
        // also bounds coverage when a supplied clock violates monotonicity.
        let ordered = log.compactMap { entry -> Interval? in
            let lower = max(started, entry.start), upper = min(end, entry.end)
            guard upper > lower else { return nil }
            return Interval(phase: entry.phase, start: lower, end: upper, serial: entry.serial)
        }.sorted {
            if $0.start != $1.start { return $0.start < $1.start }
            if $0.end != $1.end { return $0.end > $1.end }
            return $0.serial < $1.serial
        }
        var coveredEnd = started
        for (index, parent) in ordered.enumerated() {
            let lower = max(coveredEnd, parent.start)
            if parent.end > lower { summary.coveredNanoseconds += parent.end - lower }
            coveredEnd = max(coveredEnd, parent.end)
            var childEnd = parent.start, children: UInt64 = 0
            for child in ordered.dropFirst(index + 1) {
                if child.start >= parent.end { break }
                if child.end > parent.end {
                    summary.overlappingSpans = true
                    continue
                }
                let lower = max(childEnd, child.start)
                if child.end > lower { children += child.end - lower }
                childEnd = max(childEnd, child.end)
            }
            let own = parent.end - parent.start - children
            let phase = parent.phase.rawValue
            summary.exclusiveDurations[phase] = Self.adding(summary.exclusiveDurations[phase], own)
        }
        summary.residualNanoseconds = summary.elapsedNanoseconds >= summary.coveredNanoseconds
            ? summary.elapsedNanoseconds - summary.coveredNanoseconds : 0
    }

    /// Registration linearizes with finish. Only tiny diagnostic retirement closures
    /// are retained, and the bound remains independent of input or request size.
    fileprivate func registerLifetime(
        lease: UUID, insert: () -> (@Sendable () -> Void)?
    ) -> Bool {
        lock.withLock {
            guard !isFinished, retirements.count < 128, let retirement = insert() else {
                return false
            }
            retirements[lease] = retirement
            return true
        }
    }

    fileprivate func retireLifetime(lease: UUID) {
        lock.withLock { _ = retirements.removeValue(forKey: lease) }
    }

    private static func adding(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? .max : sum
    }
}

/// At most one active diagnostic dispatch per coordinator and 128 process-wide.
/// Neither this table nor its records retain requests, snapshots, payloads or replies.
final class NativeDecompilerPhaseLookup: @unchecked Sendable {
    static let shared = NativeDecompilerPhaseLookup()
    private struct Entry {
        let owner: UUID
        let lease: UUID
        let record: NativeDecompilerPhaseRecord
    }
    private let lock = NSLock()
    private let capacity: Int
    private var entries: [UUID: Entry] = [:]

    init(capacity: Int = 128) { self.capacity = max(0, min(128, capacity)) }

    func register(
        requestID: UUID, owner: UUID, record: NativeDecompilerPhaseRecord
    ) -> UUID? {
        let lease = UUID()
        let inserted = record.registerLifetime(lease: lease) {
            lock.withLock {
                guard entries[requestID] == nil, entries.count < capacity,
                      !entries.values.contains(where: { $0.owner == owner }) else { return nil }
                entries[requestID] = Entry(owner: owner, lease: lease, record: record)
                return { [weak self] in self?.retire(requestID: requestID, lease: lease) }
            }
        }
        return inserted ? lease : nil
    }

    func lookup(requestID: UUID) -> NativeDecompilerPhaseRecord? {
        lock.withLock { entries[requestID]?.record }
    }

    func retire(requestID: UUID, lease: UUID) {
        let record: NativeDecompilerPhaseRecord? = lock.withLock {
            guard entries[requestID]?.lease == lease else { return nil }
            return entries.removeValue(forKey: requestID)?.record
        }
        // Keep lock ordering record -> table for insertion; never invert it here.
        record?.retireLifetime(lease: lease)
    }
}
