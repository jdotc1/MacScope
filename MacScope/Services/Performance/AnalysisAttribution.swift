import Foundation

/// Opt in with MACSCOPE_READY_ATTRIBUTION=1; nil is the disabled convention.
/// No strings derived from the input enter this recorder. Callers use optional
/// chaining and lexical defer, never an allocating operation-wrapper closure.
/// The launcher emits one summary through its nonthrowing stderr log AFTER ready.
/// A slow sink delays only that caller after ready; no sink runs under this lock.
final class AnalysisAttribution: @unchecked Sendable {
    enum Label: String, CaseIterable, Hashable, Sendable {
        case readyPreDispatch, backgroundHandoff, initialFingerprint, selection
        case analysisTotal, load, decode, dataMembership, codeFilter
        case discoverySetup, discoveryPrepare, discoveryRecover, discoveryPropagate
        case discoveryFinish, discoveryOther, listing, jumpTables, blocks, edges
        case callXrefs, dataXrefs, stringRecovery, snapshot, switchHints
        case crossChecks, collector, fingerprint, fingerprintImage
        case fingerprintInstructions, fingerprintOther, fingerprintOverall
        case verifySelection, finalFingerprint, bind, journal, navigatorSchedule, apiInstall
    }

    enum Counter: String, CaseIterable, Hashable, Sendable {
        case decodedInstructions, loaderRanges, validRanges, sections, functions
        case discoveryInvocations, preparedEntries, cacheAdmissions, cacheRefusals, misuse
        case sortsSkipped, sortsRun, sliceCopiesAvoided
    }

    enum Outcome: String, Sendable { case success, cancelled, failed }

    struct Span: Sendable {
        fileprivate let owner: ObjectIdentifier
        fileprivate let key: Key
        fileprivate let generation: UInt64
    }

    fileprivate struct Key: Hashable, Sendable {
        let label: Label
        let ordinal: Int
    }

    struct Record: Sendable {
        let label: Label
        let ordinal: Int
        var opened = 0
        var closed = 0
        var successes = 0
        var cancellations = 0
        var failures = 0
        var firstNanoseconds: UInt64 = 0
        var lastNanoseconds: UInt64 = 0
        var totalNanoseconds: UInt64 = 0
        fileprivate var start: UInt64?
        fileprivate var generation: UInt64 = 0
    }

    struct Snapshot: Sendable {
        let records: [Record]
        let counters: [Counter: Int]
    }

    // Every mutable field and the injected clock are accessed under this lock.
    // Keys are closed labels x ordinals 0...4; no unbounded per-event storage.
    private let lock = NSLock()
    private let now: @Sendable () -> UInt64
    private var records: [Key: Record] = [:]
    private var counters: [Counter: Int] = [:]
    private var lastOffset: UInt64 = 0
    private var emitted = false
    /// Optional separately owned Stage A work counters. Created only when the opt-in
    /// guard created this attribution; nil is the legacy-only convention.
    let work: StartupWorkCounters?

    convenience init(work: StartupWorkCounters? = nil) {
        let clock = ContinuousClock()
        let origin = clock.now
        self.init(now: {
            let components = origin.duration(to: clock.now).components
            guard components.seconds >= 0 else { return 0 }
            let seconds = UInt64(components.seconds)
            let scaled = seconds.multipliedReportingOverflow(by: 1_000_000_000)
            guard !scaled.overflow else { return UInt64.max }
            let fraction = UInt64(max(0, components.attoseconds / 1_000_000_000))
            let sum = scaled.partialValue.addingReportingOverflow(fraction)
            return sum.overflow ? UInt64.max : sum.partialValue
        }, work: work)
    }

    /// Test clock returns offsets from one origin; never called for a nil recorder.
    init(now: @escaping @Sendable () -> UInt64, work: StartupWorkCounters? = nil) {
        self.now = now
        self.work = work
    }

    /// The sole production environment read. Invoke once at launcher entry.
    static func fromEnvironment() -> AnalysisAttribution? {
        guard ProcessInfo.processInfo.environment["MACSCOPE_READY_ATTRIBUTION"] == "1" else {
            return nil
        }
        return AnalysisAttribution(work: StartupWorkCounters())
    }

    func open(_ label: Label, ordinal: Int = 0) -> Span? {
        lock.lock()
        defer { lock.unlock() }
        guard !emitted, (0...4).contains(ordinal) else {
            increment(.misuse, by: 1)
            return nil
        }
        let key = Key(label: label, ordinal: ordinal)
        var record = records[key] ?? Record(label: label, ordinal: ordinal)
        guard record.start == nil, record.generation < UInt64.max else {
            increment(.misuse, by: 1)
            return nil
        }
        let offset = offsetLocked()
        if record.opened == 0 { record.firstNanoseconds = offset }
        record.start = offset
        record.generation += 1
        record.opened = saturated(record.opened, 1)
        records[key] = record
        return Span(owner: ObjectIdentifier(self), key: key, generation: record.generation)
    }

    func close(_ span: Span?, outcome: Outcome) {
        guard let span else { return }
        lock.lock()
        defer { lock.unlock() }
        guard span.owner == ObjectIdentifier(self),
              var record = records[span.key], let start = record.start,
              record.generation == span.generation else {
            increment(.misuse, by: 1)
            return
        }
        let end = offsetLocked()
        record.start = nil
        record.lastNanoseconds = end
        let total = record.totalNanoseconds.addingReportingOverflow(end - start)
        record.totalNanoseconds = total.overflow ? UInt64.max : total.partialValue
        record.closed = saturated(record.closed, 1)
        switch outcome {
        case .success: record.successes = saturated(record.successes, 1)
        case .cancelled: record.cancellations = saturated(record.cancellations, 1)
        case .failed: record.failures = saturated(record.failures, 1)
        }
        records[span.key] = record
    }

    func add(_ counter: Counter, _ value: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard !emitted, value >= 0 else {
            increment(.misuse, by: 1)
            return
        }
        increment(counter, by: value)
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshotLocked()
    }

    /// Inclusive aggregate durations are identified by label, never summed here.
    /// Facet lanes are exclusive work categories; their overlap is not wall time.
    /// Summary production is once-only, after all opens have matching closes.
    func summary() -> String? {
        let value: Snapshot
        lock.lock()
        guard !emitted, records.values.allSatisfy({ $0.start == nil }) else {
            lock.unlock()
            return nil
        }
        emitted = true
        value = snapshotLocked()
        lock.unlock()
        let intervals = value.records.map {
            "\($0.label.rawValue).\($0.ordinal)=\($0.firstNanoseconds):\($0.lastNanoseconds):\($0.totalNanoseconds):\($0.opened):\($0.closed):\($0.successes):\($0.cancellations):\($0.failures)"
        }.joined(separator: ",")
        let counts = Counter.allCases.map {
            "\($0.rawValue)=\(value.counters[$0, default: 0])"
        }.joined(separator: ",")
        return "attribution v1 ns[first:last:total:opened:closed:success:cancelled:failed] \(intervals) counts[\(counts)]"
    }

    /// Legacy summary followed by the appended work block, once. Same once-only gate as
    /// `summary()`; the legacy text is returned byte-identical as the line prefix.
    func summaryWithWork() -> String? {
        guard let legacy = summary() else { return nil }
        guard let block = StartupWorkReport.block(for: work?.snapshot()) else { return legacy }
        return legacy + " " + block
    }

    private func snapshotLocked() -> Snapshot {
        var ordered: [Record] = []
        for label in Label.allCases {
            for ordinal in 0...4 {
                if let record = records[Key(label: label, ordinal: ordinal)] {
                    ordered.append(record)
                }
            }
        }
        return Snapshot(records: ordered, counters: counters)
    }

    private func offsetLocked() -> UInt64 {
        lastOffset = max(lastOffset, now())
        return lastOffset
    }

    private func increment(_ counter: Counter, by value: Int) {
        counters[counter] = saturated(counters[counter, default: 0], value)
    }

    private func saturated(_ lhs: Int, _ rhs: Int) -> Int {
        let sum = lhs.addingReportingOverflow(rhs)
        return sum.overflow ? Int.max : sum.partialValue
    }
}
