import Foundation
import XCTest
@testable import MacScope

/// Item 1330 (TC09): collector counters over the supplied InstructionRow, SectionSummary and
/// ControlFlowEdge shapes. The publication-permit arm needs a permit fixture and stays OPEN (OP6).
final class StartupWorkCollectorTests: XCTestCase {
    private func active() -> StartupWorkCounters {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        return work
    }

    private func row(_ address: UInt64) -> InstructionRow {
        InstructionRow(address: address, bytes: "1f 20 03 d5", mnemonic: "nop",
                       operands: "", hasBreakpoint: false, comment: nil)
    }

    private func text() -> SectionSummary {
        SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000, size: 0x1000,
                       fileOffset: 0, isExecutable: true)
    }

    private func branch() -> ControlFlowEdge {
        ControlFlowEdge(id: UUID(), from: 0x1000, to: 0x9999, kind: "branch")
    }

    /// Consults of the injected predicate: admission is the first, each loop entry another.
    private final class Consults: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func next() -> Int { lock.lock(); defer { lock.unlock() }; count += 1; return count }
    }

    private func completingInput(_ work: StartupWorkCounters) -> AnalysisDiagnosticsCollector.Input {
        AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [branch()], xrefs: [],
            sections: [text()], work: work)
    }

    /// Aborts on the fourth consult, which is after the edge loop issued its one query.
    private func postQueryAbortInput(_ work: StartupWorkCounters) -> AnalysisDiagnosticsCollector.Input {
        let consults = Consults()
        return AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [branch()], xrefs: [],
            sections: [text()], abortPredicate: { consults.next() >= 4 }, work: work)
    }

    func testCompletedCollectCountsInputsQueriesAndOutput() {
        let work = active()
        let diagnostics = AnalysisDiagnosticsCollector().collect(completingInput(work))
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(diagnostics.count, 1)
        XCTAssertEqual(values[.collectorInputInstructions], 1)
        XCTAssertEqual(values[.collectorInputEdges], 1)
        XCTAssertEqual(values[.collectorInputXrefs], 0)
        XCTAssertEqual(values[.collectorInputRows], 2)
        XCTAssertEqual(values[.diagnosticSectionRanges], 1)
        XCTAssertEqual(values[.diagnosticMembershipQueries], 1)
        XCTAssertEqual(values[.diagnosticMembershipComparisons], 0)
        XCTAssertEqual(values[.collectorOutputRows], 1)
    }

    func testAdmissionAbortLeavesEveryCollectorFieldAbsent() {
        let work = active()
        let input = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [branch()], xrefs: [],
            sections: [text()], abortPredicate: { true }, work: work)
        XCTAssertTrue(AnalysisDiagnosticsCollector().collect(input).isEmpty)
        work.close(.collector)
        work.finishAnalysis(.success)
        XCTAssertTrue(work.snapshot().values.isEmpty)
    }

    func testPostQueryAbortKeepsInputsAndDropsQueriesAndOutput() {
        let work = active()
        XCTAssertTrue(AnalysisDiagnosticsCollector().collect(postQueryAbortInput(work)).isEmpty)
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.collectorInputInstructions], 1)
        XCTAssertEqual(values[.collectorInputEdges], 1)
        XCTAssertEqual(values[.collectorInputRows], 2)
        XCTAssertNil(values[.diagnosticMembershipQueries], "an aborted query tally is not certified")
        XCTAssertNil(values[.diagnosticMembershipComparisons])
        XCTAssertNil(values[.collectorOutputRows])
    }

    func testNoQueryCollectKeepsMembershipAbsentAndOutputZero() {
        let work = active()
        let input = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [], xrefs: [], sections: [text()], work: work)
        XCTAssertTrue(AnalysisDiagnosticsCollector().collect(input).isEmpty)
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertNil(values[.diagnosticMembershipQueries])
        XCTAssertNil(values[.diagnosticMembershipComparisons])
        XCTAssertEqual(values[.collectorOutputRows], 0)
    }

    // R12: a later unavailable output must not let an earlier subtotal be certified.
    func testCompletedThenAbortedCallDoesNotCertifyEarlierOutputSubtotal() {
        let work = active()
        let collector = AnalysisDiagnosticsCollector()
        XCTAssertEqual(collector.collect(completingInput(work)).count, 1)
        XCTAssertTrue(collector.collect(postQueryAbortInput(work)).isEmpty)
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.collectorInputInstructions], 2)
        XCTAssertNil(values[.collectorOutputRows])
        XCTAssertNil(values[.diagnosticMembershipQueries])
    }

    func testAbortedThenCompletedCallKeepsOutputAbsent() {
        let work = active()
        let collector = AnalysisDiagnosticsCollector()
        XCTAssertTrue(collector.collect(postQueryAbortInput(work)).isEmpty)
        XCTAssertEqual(collector.collect(completingInput(work)).count, 1)
        work.close(.collector)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.collectorInputInstructions], 2)
        XCTAssertNil(values[.collectorOutputRows])
    }

    func testAbsentObserverKeepsCollectResultUnchanged() {
        let plain = AnalysisDiagnosticsCollector.Input(
            instructions: [row(0x1000)], controlFlowEdges: [branch()], xrefs: [], sections: [text()])
        let observed = completingInput(active())
        XCTAssertEqual(AnalysisDiagnosticsCollector().collect(plain).map(\.kind),
                       AnalysisDiagnosticsCollector().collect(observed).map(\.kind))
    }
}
