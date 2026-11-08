import Foundation
import XCTest
@testable import MacScope

/// T8; authored, unrun; guard. F1 trap forces a productive discovery repeat.
/// The hook runs BEFORE the real check. Every observed checkpoint is attacked,
/// including repeated discovery and string-recovery dataReferences checkpoints.
final class ReadyCancellationAndProgressTests: XCTestCase {
    func testEveryObservedCheckpointCancelsBeforePublication() throws {
        let fixture = TinyMachO.make(code: Data([0x00, 0x00, 0x20, 0xd4]))
        let url = try fixture.write()
        defer { try? FileManager.default.removeItem(at: url) }
        let baseline = ReadyCheckpointProbe()
        var engine = AnalysisEngine()
        engine.checkpointForTesting = { baseline.visit($0) }
        let complete = try engine.analyze(url: url)
        XCTAssertFalse(complete.instructions.isEmpty)
        let expected = baseline.phases
        let nine: [AnalysisPhase] = [.load, .decode, .functionDiscovery, .listing,
            .jumpTables, .controlFlow, .dataReferences, .switchHints, .diagnostics]
        XCTAssertEqual(Array(Set(expected.map(\.rawValue))).sorted(), nine.map(\.rawValue).sorted())
        XCTAssertGreaterThan(expected.filter { $0 == .functionDiscovery }.count, 1)
        XCTAssertGreaterThan(expected.filter { $0 == .dataReferences }.count, 1)
        for index in expected.indices {
            let probe = ReadyCheckpointProbe(stopAt: index)
            let recorder = AnalysisAttribution(now: { 0 })
            var candidate = AnalysisEngine()
            candidate.attribution = recorder
            candidate.checkpointForTesting = { probe.visit($0) }
            var published = false
            XCTAssertThrowsError(try {
                _ = try candidate.analyze(url: url,
                    cancellation: AnalysisCancellationToken { probe.cancelled })
                published = true
            }()) { XCTAssertTrue($0 is AnalysisCancelled) }
            XCTAssertFalse(published)
            XCTAssertEqual(probe.phases, Array(expected.prefix(index + 1)))
            let records = recorder.snapshot().records
            XCTAssertTrue(records.allSatisfy { $0.opened == $0.closed })
            XCTAssertEqual(records.first { $0.label == .analysisTotal }?.cancellations, 1)
            if expected[index] == .functionDiscovery,
               expected.prefix(index).contains(.functionDiscovery) {
                let counters = recorder.snapshot().counters
                XCTAssertEqual(counters[.preparedEntries, default: 0], 1)
                XCTAssertEqual(counters[.cacheAdmissions, default: 0], 1)
                XCTAssertEqual(counters[.cacheRefusals, default: 0], 0)
            }
            XCTAssertNotNil(recorder.summary())
        }
    }

    /// Guard, synthetic progress values (no binary). Repeated and stale reports
    /// must neither duplicate callbacks nor move completed-phase progress back.
    // TC01 (single-section, single-round) and the supported TC04 relations. Multi-section
    // and higher-round variants stay blocked by O6.
    func testWorkCountersRecordSectionCallRelationsOnTrapFixture() throws {
        let url = try TinyMachO.make(code: Data([0x00, 0x00, 0x20, 0xd4])).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let work = StartupWorkCounters()
        var engine = AnalysisEngine()
        engine.attribution = AnalysisAttribution(now: { 0 }, work: work)
        _ = try engine.analyze(url: url)
        let snapshot = work.snapshot()
        XCTAssertEqual(snapshot.analysis, .completed)
        let attempted = try XCTUnwrap(snapshot.values[.sectionCallsAttempted])
        XCTAssertGreaterThan(attempted, 0)
        XCTAssertEqual(snapshot.values[.sectionCallsCompleted], attempted)
        XCTAssertEqual(snapshot.values[.sliceCopiesAvoided], attempted)
        XCTAssertEqual(snapshot.values[.codeSectionBuilds], 2)
        XCTAssertEqual(snapshot.misuse, 0)
    }

    func testDisabledRecorderLeavesAnalysisResultUnchanged() throws {
        let url = try TinyMachO.make(code: Data([0x00, 0x00, 0x20, 0xd4])).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let plain = try AnalysisEngine().analyze(url: url)
        var observed = AnalysisEngine()
        observed.attribution = AnalysisAttribution(now: { 0 }, work: StartupWorkCounters())
        let result = try observed.analyze(url: url)
        XCTAssertEqual(plain.instructions.map(\.address), result.instructions.map(\.address))
        XCTAssertEqual(plain.functions.map(\.startAddress), result.functions.map(\.startAddress))
    }

    func testRepeatedReportsRemainOrderedAndMonotonic() {
        let callbacks = ReadyCheckpointProbe()
        let status = MCPStartupStatus(onNewPhase: { callbacks.visit($0) })
        let phases: [AnalysisPhase] = [.load, .decode, .functionDiscovery, .listing,
            .jumpTables, .controlFlow, .dataReferences, .switchHints, .diagnostics]
        var completed: [Int] = []
        for phase in phases {
            status.report(AnalysisProgress(phase: phase, elapsed: .zero))
            status.report(AnalysisProgress(phase: phase, elapsed: .zero))
            status.report(AnalysisProgress(phase: .load, elapsed: .zero))
            completed.append(status.snapshot().completedPhases)
        }
        XCTAssertEqual(callbacks.phases, phases)
        XCTAssertEqual(completed, Array(0...8))
        status.markReady()
        status.report(AnalysisProgress(phase: .diagnostics, elapsed: .zero))
        XCTAssertEqual(status.snapshot().state, "ready")
        XCTAssertEqual(status.snapshot().completedPhases, 9)
        XCTAssertEqual(callbacks.phases, phases)
    }
}

private final class ReadyCheckpointProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let stopAt: Int?
    private var seen: [AnalysisPhase] = []
    private var stopped = false
    init(stopAt: Int? = nil) { self.stopAt = stopAt }
    func visit(_ phase: AnalysisPhase) {
        lock.lock()
        defer { lock.unlock() }
        if seen.count == stopAt { stopped = true }
        seen.append(phase)
    }
    var phases: [AnalysisPhase] {
        lock.lock(); defer { lock.unlock() }; return seen
    }
    var cancelled: Bool {
        lock.lock(); defer { lock.unlock() }; return stopped
    }
}
