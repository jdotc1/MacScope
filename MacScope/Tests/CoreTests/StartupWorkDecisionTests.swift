import Foundation
import XCTest
@testable import MacScope

/// Item 1330 (TC15): pure decision evaluator over typed snapshots, pin fields only.
/// DT03 to DT07, DT10 (K10), DT11 and DT12 need fields the work report does not carry and
/// stay OPEN; the full analysis projection is OPEN (OP12). Counts are never turned into time.
final class StartupWorkDecisionTests: XCTestCase {
    private typealias Field = StartupWorkCounters.Field
    private typealias Snapshot = StartupWorkCounters.Snapshot

    private enum Outcome: Equatable {
        case open
        case repeatedDiscovery, singlePass
        case selectK1, noRecordedK1Duplication
        case countsConsistent, stopInstrumentationIntegrity
        case k3WorkRemovalProvenInBaseline, noIndexDuplication
        case considerK11, conditionNotMet
    }

    private func snapshot(_ values: [Field: Int], analysis: StartupWorkCounters.AnalysisState = .completed,
                          misuse: Int? = 0) -> Snapshot {
        Snapshot(analysis: analysis, values: values, misuse: misuse)
    }

    private func usable(_ snapshot: Snapshot) -> Bool {
        snapshot.analysis == .completed && snapshot.values.values.allSatisfy { $0 >= 0 }
    }

    private func dt01(_ snapshot: Snapshot) -> Outcome {
        guard usable(snapshot) else { return .open }
        let r = snapshot.values[.discoveryInvocations], s = snapshot.values[.sections]
        if (r ?? 0) > 1 || (s ?? 0) > 1 { return .repeatedDiscovery }
        if r == 1, s == 1 { return .singlePass }
        return .open
    }

    private func dt02(_ snapshot: Snapshot) -> Outcome {
        guard usable(snapshot) else { return .open }
        let producers: [Field] = [.swiftCandidateExtractions, .objcCandidateCollections,
                                  .symbolCandidateCollections, .symbolNameMapBuilds]
        let counts = producers.map { snapshot.values[$0] }
        let filterBuilds = snapshot.values[.sectionStartFilterBuilds]
        let sectionCount = snapshot.values[.sections]
        if counts.contains(where: { ($0 ?? 0) > 1 }) { return .selectK1 }
        if let filterBuilds, let sectionCount, filterBuilds > sectionCount { return .selectK1 }
        guard !counts.contains(where: { $0 == nil }), filterBuilds != nil, sectionCount != nil else { return .open }
        return .noRecordedK1Duplication
    }

    private func dt08(_ snapshot: Snapshot) -> Outcome {
        guard usable(snapshot), let misuse = snapshot.misuse,
              let sections = snapshot.values[.sections],
              let invocations = snapshot.values[.discoveryInvocations],
              let completed = snapshot.values[.sectionCallsCompleted] else { return .open }
        let expected = sections.multipliedReportingOverflow(by: invocations)
        guard !expected.overflow else { return .open }
        return expected.partialValue == completed && misuse == 0
            ? .countsConsistent : .stopInstrumentationIntegrity
    }

    private func dt09(_ snapshot: Snapshot) -> Outcome {
        guard usable(snapshot), let builds = snapshot.values[.propagationIndexBuilds] else { return .open }
        if builds >= 2, (snapshot.values[.propagationIndexRows] ?? 0) > 0 {
            return .k3WorkRemovalProvenInBaseline
        }
        return builds <= 1 ? .noIndexDuplication : .open
    }

    private func dt10K11(_ snapshot: Snapshot) -> Outcome {
        guard usable(snapshot),
              let comparisons = snapshot.values[.diagnosticMembershipComparisons],
              let queries = snapshot.values[.diagnosticMembershipQueries],
              let ranges = snapshot.values[.diagnosticSectionRanges] else { return .open }
        return comparisons > queries && ranges > 1 ? .considerK11 : .conditionNotMet
    }

    func testDT01RepeatedSingleAndMissing() {
        XCTAssertEqual(dt01(snapshot([.discoveryInvocations: 2])), .repeatedDiscovery)
        XCTAssertEqual(dt01(snapshot([.sections: 3])), .repeatedDiscovery)
        XCTAssertEqual(dt01(snapshot([.discoveryInvocations: 1, .sections: 1])), .singlePass)
        XCTAssertEqual(dt01(snapshot([.discoveryInvocations: 1])), .open, "absence is not one")
        XCTAssertEqual(dt01(snapshot([:])), .open)
    }

    func testDT02NegativeBranchNeedsEveryInputComplete() {
        let full: [Field: Int] = [.swiftCandidateExtractions: 1, .objcCandidateCollections: 1,
                                  .symbolCandidateCollections: 1, .symbolNameMapBuilds: 1,
                                  .sectionStartFilterBuilds: 2, .sections: 2]
        XCTAssertEqual(dt02(snapshot(full)), .noRecordedK1Duplication)
        var duplicated = full
        duplicated[.symbolNameMapBuilds] = 2
        XCTAssertEqual(dt02(snapshot(duplicated)), .selectK1)
        var filtered = full
        filtered[.sectionStartFilterBuilds] = 3
        XCTAssertEqual(dt02(snapshot(filtered)), .selectK1)
        var missing = full
        missing[.objcCandidateCollections] = nil
        XCTAssertEqual(dt02(snapshot(missing)), .open)
    }

    func testDT08EqualityMisuseAndOverflow() {
        let base: [Field: Int] = [.sections: 3, .discoveryInvocations: 2, .sectionCallsCompleted: 6]
        XCTAssertEqual(dt08(snapshot(base)), .countsConsistent)
        XCTAssertEqual(dt08(snapshot(base, misuse: 1)), .stopInstrumentationIntegrity)
        var short = base
        short[.sectionCallsCompleted] = 5
        XCTAssertEqual(dt08(snapshot(short)), .stopInstrumentationIntegrity)
        var overflow = base
        overflow[.sections] = Int.max
        XCTAssertEqual(dt08(snapshot(overflow)), .open)
        var missing = base
        missing[.sectionCallsCompleted] = nil
        XCTAssertEqual(dt08(snapshot(missing)), .open, "a missing operand is never zero")
        XCTAssertEqual(dt08(snapshot(base, misuse: nil)), .open)
    }

    func testDT09IndexDuplicationAndLifecycleRejection() {
        XCTAssertEqual(dt09(snapshot([.propagationIndexBuilds: 2, .propagationIndexRows: 5])),
                       .k3WorkRemovalProvenInBaseline)
        XCTAssertEqual(dt09(snapshot([.propagationIndexBuilds: 1, .propagationIndexRows: 5])),
                       .noIndexDuplication)
        XCTAssertEqual(dt09(snapshot([.propagationIndexBuilds: 2])), .open)
        XCTAssertEqual(dt09(snapshot([.propagationIndexBuilds: 1], analysis: .invalid)), .open)
        XCTAssertEqual(dt09(snapshot([.propagationIndexBuilds: 1], analysis: .cancelled)), .open)
    }

    func testDT10K11ConditionAndOpenInputs() {
        XCTAssertEqual(dt10K11(snapshot([.diagnosticMembershipComparisons: 5, .diagnosticMembershipQueries: 3,
                                         .diagnosticSectionRanges: 2])), .considerK11)
        XCTAssertEqual(dt10K11(snapshot([.diagnosticMembershipComparisons: 3, .diagnosticMembershipQueries: 3,
                                         .diagnosticSectionRanges: 2])), .conditionNotMet)
        XCTAssertEqual(dt10K11(snapshot([.diagnosticMembershipComparisons: 5, .diagnosticMembershipQueries: 3,
                                         .diagnosticSectionRanges: 1])), .conditionNotMet)
        XCTAssertEqual(dt10K11(snapshot([.diagnosticSectionRanges: 2])), .open)
    }

    func testEvaluatorsRejectAnInvalidReusedRecorder() {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        work.add(.sections, 3)
        work.add(.discoveryInvocations, 2)
        work.close(.setup)
        work.close(.discovery)
        work.finishAnalysis(.success)
        XCTAssertEqual(dt01(work.snapshot()), .repeatedDiscovery)
        work.beginAnalysis()
        XCTAssertEqual(dt01(work.snapshot()), .open)
    }
}
