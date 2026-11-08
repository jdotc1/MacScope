import Foundation
import XCTest
@testable import MacScope

/// T11; authored, unrun; guards. Fake offsets are events, never wall time.
final class ReadyAttributionRecordingTests: XCTestCase {
    /// F1 removed before loading: exercises the production defer, not a wrapper.
    func testEngineFailureClosesRealSpans() throws {
        let url = try TinyMachO.make(code: Data([0xc0, 0x03, 0x5f, 0xd6])).write()
        try FileManager.default.removeItem(at: url)
        let probe = ReadyAttributionProbe()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        var engine = AnalysisEngine()
        engine.attribution = recorder
        XCTAssertThrowsError(try engine.analyze(url: url))
        let records = recorder.snapshot().records
        XCTAssertFalse(records.isEmpty)
        let load = try XCTUnwrap(records.first { $0.label == .load })
        let total = try XCTUnwrap(records.first { $0.label == .analysisTotal })
        XCTAssertEqual(load.opened, 1)
        XCTAssertEqual(load.closed, 1)
        XCTAssertEqual(load.failures, 1)
        XCTAssertEqual(total.closed, 1)
        XCTAssertEqual(total.failures, 1)
        XCTAssertTrue(records.allSatisfy { $0.opened == $0.closed })
        XCTAssertNotNil(recorder.summary())
    }

    func testErrorAndCancellationEachCloseTheirOpenedInterval() throws {
        let probe = ReadyAttributionProbe()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        struct Failure: Error {}
        func failing() throws {
            let span = recorder.open(.load)
            defer { recorder.close(span, outcome: .failed) }
            throw Failure()
        }
        XCTAssertThrowsError(try failing())
        let cancelled = recorder.open(.decode)
        recorder.close(cancelled, outcome: .cancelled)
        let snapshot = recorder.snapshot()
        XCTAssertEqual(snapshot.records.count, 2)
        XCTAssertEqual(snapshot.records.map(\.opened), [1, 1])
        XCTAssertEqual(snapshot.records.map(\.closed), [1, 1])
        XCTAssertEqual(snapshot.records.map(\.failures), [1, 0])
        XCTAssertEqual(snapshot.records.map(\.cancellations), [0, 1])
        XCTAssertEqual(snapshot.records.map(\.totalNanoseconds), [10, 10])
        XCTAssertEqual(probe.clockCalls, 4)
        let summary = try XCTUnwrap(recorder.summary())
        probe.emit(summary)
        XCTAssertNil(recorder.summary())
        XCTAssertEqual(probe.lines, [summary])
    }

    func testDuplicateSpansAndCounterOverflowStayBounded() throws {
        let probe = ReadyAttributionProbe()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        let span = recorder.open(.load)
        XCTAssertNil(recorder.open(.load))
        XCTAssertNil(recorder.open(.decode, ordinal: 5))
        XCTAssertNil(recorder.summary(), "Cannot emit while an interval is open")
        recorder.add(.decodedInstructions, Int.max)
        recorder.add(.decodedInstructions, 1)
        recorder.close(span, outcome: .success)
        recorder.close(span, outcome: .success)
        let state = recorder.snapshot()
        XCTAssertEqual(state.records.count, 1)
        XCTAssertEqual(state.records[0].closed, 1)
        XCTAssertEqual(state.records[0].successes, 1)
        XCTAssertEqual(state.counters[.decodedInstructions], Int.max)
        XCTAssertEqual(state.counters[.misuse], 3)
        XCTAssertEqual(probe.clockCalls, 2)
        let line = try XCTUnwrap(recorder.summary())
        XCTAssertTrue(line.hasPrefix("attribution v1 "))
        XCTAssertFalse(line.contains("/tmp/"))
        XCTAssertFalse(line.contains("private_symbol"))
        XCTAssertTrue(state.records.allSatisfy { AnalysisAttribution.Label.allCases.contains($0.label) })
        XCTAssertLessThanOrEqual(state.records.count, AnalysisAttribution.Label.allCases.count * 5)
    }

    func testDisabledOptionalDoesNotReadClockOrEmit() {
        let probe = ReadyAttributionProbe()
        let available = AnalysisAttribution(now: { probe.tick() })
        let enabled = false
        let recorder: AnalysisAttribution? = enabled ? available : nil
        let span = recorder?.open(.load)
        recorder?.add(.decodedInstructions, 1)
        recorder?.close(span, outcome: .success)
        if let line = recorder?.summary() { probe.emit(line) }
        XCTAssertEqual(probe.clockCalls, 0)
        XCTAssertEqual(probe.lines, [])
        XCTAssertTrue(available.snapshot().records.isEmpty)
        XCTAssertTrue(available.snapshot().counters.isEmpty)
    }

    /// F1 launch integration: exact phase lines and the ready line generated
    /// from THAT launch's settled status; no cross-run duration assertion.
    @MainActor
    func testEnabledRecorderKeepsPhaseAndReadyLineFormats() async throws {
        let url = try TinyMachO.make(code: Data([0xc0, 0x03, 0x5f, 0xd6])).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let probe = ReadyAttributionProbe()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url,
            log: { probe.emit($0) }, onLaunchState: { _ in }, attribution: recorder)
        await launch.analysis.value
        XCTAssertEqual(launch.gate.status.snapshot().state, "ready")
        let lines = probe.lines
        let phases = ["load", "decode", "functionDiscovery", "listing", "jumpTables",
                      "controlFlow", "dataReferences", "switchHints", "diagnostics"]
        XCTAssertEqual(lines.filter { $0.hasPrefix("phase ") }, phases.map { "phase \($0)" })
        let ready = "ready in \(launch.gate.status.snapshot().elapsedMs) ms"
        let readyIndex = try XCTUnwrap(lines.firstIndex(of: ready))
        XCTAssertEqual(lines.filter { $0.hasPrefix("ready in ") }, [ready])
        let summaryIndex = try XCTUnwrap(lines.firstIndex { $0.hasPrefix("attribution v1 ") })
        XCTAssertEqual(summaryIndex, readyIndex + 1)
        XCTAssertEqual(lines.filter { $0.hasPrefix("attribution v1 ") }.count, 1)
        XCTAssertTrue(recorder.snapshot().records.allSatisfy { $0.opened == $0.closed })
        XCTAssertGreaterThan(probe.clockCalls, 0)
    }

    // TC06 / TC12: the extension is strictly appended; the legacy text is byte-identical.
    func testLegacySummaryIsByteIdenticalPrefixOfExtendedSummary() throws {
        func drive(_ recorder: AnalysisAttribution) {
            let span = recorder.open(.analysisTotal)
            recorder.add(.sections, 3)
            recorder.close(span, outcome: .success)
        }
        let plain = AnalysisAttribution(now: { 0 })
        drive(plain)
        let legacy = try XCTUnwrap(plain.summary())

        let counters = StartupWorkCounters()
        counters.beginAnalysis()
        counters.add(.sections, 3)
        counters.close(.setup)
        counters.finishAnalysis(.success)
        let extended = AnalysisAttribution(now: { 0 }, work: counters)
        drive(extended)
        let combined = try XCTUnwrap(extended.summaryWithWork())
        XCTAssertEqual(combined, legacy + " work v1 analysis=completed [sections=3,workMisuse=0]")
        XCTAssertNil(extended.summaryWithWork(), "once-only emission is preserved")

        let withoutWork = AnalysisAttribution(now: { 0 })
        drive(withoutWork)
        XCTAssertEqual(withoutWork.summaryWithWork(), legacy)
    }

    @MainActor
    func testEnabledLaunchAppendsWorkBlockToTheSingleSummaryLine() async throws {
        let url = try TinyMachO.make(code: Data([0xc0, 0x03, 0x5f, 0xd6])).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let probe = ReadyAttributionProbe()
        let recorder = AnalysisAttribution(now: { probe.tick() }, work: StartupWorkCounters())
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, log: { probe.emit($0) },
            onLaunchState: { _ in }, attribution: recorder)
        await launch.analysis.value
        let summaries = probe.lines.filter { $0.hasPrefix("attribution v1 ") }
        XCTAssertEqual(summaries.count, 1)
        let line = try XCTUnwrap(summaries.first)
        let range = try XCTUnwrap(line.range(of: " work v1 analysis=completed ["))
        XCTAssertTrue(line.hasSuffix("]"))
        XCTAssertTrue(line[..<range.lowerBound].hasSuffix("]"), "legacy counts[...] precedes the block")
        XCTAssertTrue(line.contains("codeSectionBuilds=2"))
    }
}

private final class ReadyAttributionProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private var output: [String] = []
    func tick() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        calls += 1
        return UInt64(calls) * 10
    }
    func emit(_ line: String) { lock.lock(); output.append(line); lock.unlock() }
    var clockCalls: Int { lock.lock(); defer { lock.unlock() }; return calls }
    var lines: [String] { lock.lock(); defer { lock.unlock() }; return output }
}
