import Foundation
import XCTest
@testable import MacScope

/// Item 1326 Stage A: recorder semantics, report format, and the collector observer.
/// Authored once; raw counters only (O7), no thresholds or timing.
final class StartupWorkCountersTests: XCTestCase {
    private typealias Field = StartupWorkCounters.Field

    private func active() -> StartupWorkCounters {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        return work
    }

    // TC03: unseen and unclosed fields are absent, a reached empty loop is a complete zero.
    func testAbsentIsNeverZeroAndReachedEmptyLoopIsCompleteZero() {
        let work = active()
        work.add(.sections, 3)
        work.begin(.codeInstructions)
        XCTAssertTrue(work.snapshot().values.isEmpty, "collecting fields are not yet complete")
        work.close(.setup)
        work.close(.codeFilter)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertEqual(snapshot.analysis, .completed)
        XCTAssertEqual(snapshot.values[.sections], 3)
        XCTAssertEqual(snapshot.values[.codeInstructions], 0)
        XCTAssertNil(snapshot.values[.blocks], "an unreached site stays absent")
        XCTAssertNil(snapshot.values[.codeSectionBuilds])
    }

    func testClosingNeverReachedOwnerIsSilentButRepeatedCloseIsMisuse() {
        let work = active()
        work.close(.cfg)
        work.add(.blocks, 1)
        work.close(.cfg)
        work.close(.cfg)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertEqual(snapshot.values[.blocks], 1)
        XCTAssertEqual(snapshot.misuse, 1)
    }

    // TC07: interruption by cancellation or failure leaves collecting fields absent.
    func testCancelledAndFailedLifecyclesDropCollectingFields() {
        for outcome in [AnalysisAttribution.Outcome.cancelled, .failed] {
            let work = active()
            work.add(.sections, 2)
            work.close(.setup)
            work.add(.leaders, 5)
            work.finishAnalysis(outcome)
            let snapshot = work.snapshot()
            XCTAssertEqual(snapshot.analysis, outcome == .cancelled ? .cancelled : .failed)
            XCTAssertEqual(snapshot.values[.sections], 2)
            XCTAssertNil(snapshot.values[.leaders])
            XCTAssertEqual(snapshot.misuse, 0)
        }
    }

    // TC08: checked integers; overflow and negative amounts are bounded misuse.
    func testOverflowInvalidatesFieldAndNegativeAmountIsMisuse() {
        let work = active()
        work.add(.blocks, Int.max)
        work.add(.blocks, 1)
        work.add(.leaders, -1)
        work.close(.cfg)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertNil(snapshot.values[.blocks])
        XCTAssertEqual(snapshot.misuse, 2)
    }

    // TC09: one active analysis scope; reuse is invalid and calls outside it are ignored.
    func testReuseInvalidatesAndMutationOutsideScopeIsIgnored() {
        let idle = StartupWorkCounters()
        idle.add(.sections, 4)
        idle.close(.setup)
        XCTAssertEqual(idle.snapshot().analysis, .notEntered)
        XCTAssertTrue(idle.snapshot().values.isEmpty)
        XCTAssertNil(idle.snapshot().misuse)

        let work = active()
        work.add(.sections, 1)
        work.close(.setup)
        work.finishAnalysis(.success)
        work.add(.sections, 9)
        XCTAssertEqual(work.snapshot().values[.sections], 1)
        work.beginAnalysis()
        XCTAssertEqual(work.snapshot().analysis, .invalid)
    }

    func testStoreGaugePeakNeverBelowCurrent() {
        let work = active()
        work.publishStoreGauge(current: 6)
        work.publishStoreGauge(current: 2)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertEqual(snapshot.values[.retainedEntriesCurrent], 2)
        XCTAssertEqual(snapshot.values[.retainedEntriesPeak], 6)
    }

    func testReportOmitsNothingMeaningfulAndKeepsDeclarationOrder() throws {
        XCTAssertNil(StartupWorkReport.block(for: nil))
        XCTAssertNil(StartupWorkReport.block(for: StartupWorkCounters().snapshot()))
        let work = active()
        work.add(.blocks, 2)
        work.add(.sections, 1)
        work.close(.setup)
        work.close(.cfg)
        work.finishAnalysis(.success)
        let block = try XCTUnwrap(StartupWorkReport.block(for: work.snapshot()))
        XCTAssertEqual(block, "work v1 analysis=completed [sections=1,blocks=2,workMisuse=0]")
    }

    // MARK: Collector observer (SR20)

    private func row(_ address: UInt64) -> InstructionRow {
        InstructionRow(address: address, bytes: "1f 20 03 d5", mnemonic: "nop",
                       operands: "", hasBreakpoint: false, comment: nil)
    }

    private func text() -> SectionSummary {
        SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000, size: 0x1000,
                       fileOffset: 0, isExecutable: true)
    }

    func testCollectorRecordsInputCardinalitiesAndOutputRows() throws {
        let work = active()
        let input = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000), row(0x1004)],
            controlFlowEdges: [ControlFlowEdge(id: UUID(), from: 0x1004, to: 0x9999, kind: "branch")],
            xrefs: [], sections: [text()], work: work)
        let diagnostics = AnalysisDiagnosticsCollector().collect(input)
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(diagnostics.count, 1)
        XCTAssertEqual(values[.collectorInputInstructions], 2)
        XCTAssertEqual(values[.collectorInputEdges], 1)
        XCTAssertEqual(values[.collectorInputXrefs], 0)
        XCTAssertEqual(values[.collectorInputRows], 3)
        XCTAssertEqual(values[.diagnosticSectionRanges], 1)
        XCTAssertEqual(values[.collectorOutputRows], 1)
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(values[.diagnosticMembershipQueries]), 1)
    }

    // TC05: the injected abort predicate, default nil, aborts at the first consult.
    func testAbortPredicateAtAdmissionLeavesCollectorFieldsAbsent() {
        let work = active()
        let input = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [], xrefs: [],
            sections: [text()], abortPredicate: { true }, work: work)
        XCTAssertTrue(AnalysisDiagnosticsCollector().collect(input).isEmpty)
        work.close(.collector)
        work.finishAnalysis(.success)
        XCTAssertTrue(work.snapshot().values.isEmpty)
    }

    func testAbortPredicateMidCollectKeepsInputsAndDropsOutput() {
        let work = active()
        let calls = ConsultCounter()
        let rows = (0..<200).map { row(0x1000 + UInt64($0) * 4) }
        // First consult (admission) passes; the next one aborts.
        let input = AnalysisDiagnosticsCollector.Input(
            instructions: rows, controlFlowEdges: [], xrefs: [], sections: [text()],
            abortPredicate: { calls.next() > 1 }, work: work)
        XCTAssertTrue(AnalysisDiagnosticsCollector().collect(input).isEmpty)
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.collectorInputInstructions], 200)
        XCTAssertNil(values[.collectorOutputRows], "output rows only exist for a completed collect")
    }

    func testAbsentObserverAndPredicateKeepCollectResultUnchanged() {
        let plain = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [], xrefs: [], sections: [text()])
        let work = active()
        let observed = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [], xrefs: [], sections: [text()],
            abortPredicate: { false }, work: work)
        XCTAssertEqual(AnalysisDiagnosticsCollector().collect(plain).map(\.kind),
                       AnalysisDiagnosticsCollector().collect(observed).map(\.kind))
    }
}

private final class ConsultCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func next() -> Int { lock.lock(); defer { lock.unlock() }; count += 1; return count }
}
