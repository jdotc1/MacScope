import Foundation
import XCTest
@testable import MacScope

/// Item 1330: recorder contract matrix (TC02, TC03, TC15). Raw counter semantics only.
final class StartupWorkCounterContractTests: XCTestCase {
    private typealias Field = StartupWorkCounters.Field
    private typealias Phase = StartupWorkCounters.Phase

    private func active() -> StartupWorkCounters {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        return work
    }

    // Every phase and field: an unseen close is empty; begin then close is a complete zero.
    func testEveryPhaseUnseenCloseIsEmptyAndBeginThenCloseIsZero() {
        for phase in Phase.allCases {
            let unseen = active()
            unseen.close(phase)
            unseen.finishAnalysis(.success)
            XCTAssertTrue(unseen.snapshot().values.isEmpty, "unseen close of \(phase)")
            XCTAssertEqual(unseen.snapshot().misuse, 0)

            let fields = Field.allCases.filter { $0.phase == phase }
            XCTAssertFalse(fields.isEmpty, "\(phase) owns at least one field")
            let reached = active()
            for field in fields { reached.begin(field) }
            reached.close(phase)
            reached.finishAnalysis(.success)
            let snapshot = reached.snapshot()
            XCTAssertEqual(Set(snapshot.values.keys), Set(fields), "only \(phase) fields are present")
            for field in fields { XCTAssertEqual(snapshot.values[field], 0) }
            XCTAssertEqual(snapshot.misuse, 0)
        }
    }

    func testInterruptedFieldIsAbsentAndTerminalMisuseIsIntZero() {
        let work = active()
        work.add(.blocks, 3)
        work.interrupt(.blocks)
        work.add(.leaders, 2)
        work.close(.cfg)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertNil(snapshot.values[.blocks], "an interrupted field stays absent")
        XCTAssertEqual(snapshot.values[.leaders], 2)
        XCTAssertEqual(snapshot.misuse, 0)
    }

    // R01: reuse invalidates; the snapshot reports no values from the earlier scope.
    func testInvalidReuseSuppressesPriorValuesAndMisuse() {
        let work = active()
        work.add(.sections, 4)
        work.close(.setup)
        work.finishAnalysis(.success)
        XCTAssertEqual(work.snapshot().values[.sections], 4)
        work.beginAnalysis()
        let snapshot = work.snapshot()
        XCTAssertEqual(snapshot.analysis, .invalid)
        XCTAssertTrue(snapshot.values.isEmpty)
        XCTAssertNil(snapshot.misuse)
        work.add(.sections, 1)
        work.close(.setup)
        XCTAssertTrue(work.snapshot().values.isEmpty)
    }

    // R02: completion is final; later contributions are counted misuse and invalidate the field.
    func testClosedPhaseContributionIsMisuseAndInvalidatesField() {
        let work = active()
        work.add(.sections, 2)
        work.close(.setup)
        work.add(.sections, 5)
        work.begin(.sections)
        work.set(.sections, 9)
        work.interrupt(.sections)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertNil(snapshot.values[.sections])
        XCTAssertEqual(snapshot.misuse, 4)
    }

    func testBeginOnClosedPhaseInvalidatesCompletedField() {
        let work = active()
        work.add(.sections, 1)
        work.close(.setup)
        work.begin(.sections)
        work.finishAnalysis(.success)
        XCTAssertNil(work.snapshot().values[.sections])
        XCTAssertEqual(work.snapshot().misuse, 1)
    }

    func testStoreGaugeRepublishesWhileActive() {
        let work = active()
        work.publishStoreGauge(current: 6)
        work.publishStoreGauge(current: 2)
        work.publishStoreGauge(current: 4)
        work.finishAnalysis(.success)
        let snapshot = work.snapshot()
        XCTAssertEqual(snapshot.values[.retainedEntriesCurrent], 4)
        XCTAssertEqual(snapshot.values[.retainedEntriesPeak], 6)
        XCTAssertEqual(snapshot.misuse, 0)
    }

    // TC03: the thirteen legacy attribution names and the deterministic legacy text.
    func testLegacyCounterNamesAndDeterministicText() {
        XCTAssertEqual(AnalysisAttribution.Counter.allCases.map(\.rawValue), [
            "decodedInstructions", "loaderRanges", "validRanges", "sections", "functions",
            "discoveryInvocations", "preparedEntries", "cacheAdmissions", "cacheRefusals",
            "misuse", "sortsSkipped", "sortsRun", "sliceCopiesAvoided",
        ])
        let attribution = AnalysisAttribution(now: { 0 })
        let counts = AnalysisAttribution.Counter.allCases.map { "\($0.rawValue)=0" }.joined(separator: ",")
        let intervalHeader = "ns[first:last:total:opened:closed:success:cancelled:failed]"
        XCTAssertEqual(attribution.summary(), "attribution v1 \(intervalHeader)  counts[\(counts)]")
        XCTAssertNil(attribution.summary(), "the summary is once-only")
    }

    func testWorkBlockIsAppendedAfterLegacyTextWithoutChangingIt() throws {
        let plain = AnalysisAttribution(now: { 0 })
        let work = StartupWorkCounters()
        let observed = AnalysisAttribution(now: { 0 }, work: work)
        work.beginAnalysis()
        work.add(.sections, 1)
        work.close(.setup)
        work.finishAnalysis(.success)
        let legacy = try XCTUnwrap(plain.summary())
        let combined = try XCTUnwrap(observed.summaryWithWork())
        XCTAssertEqual(combined, legacy + " work v1 analysis=completed [sections=1,workMisuse=0]")
    }
}
