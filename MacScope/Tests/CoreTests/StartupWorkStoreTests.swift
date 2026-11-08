import Foundation
import XCTest
@testable import MacScope

/// Item 1330 (TC08): store-observer counters over empty typed slices only.
/// The refusal arm needs a nonempty DecodedInstruction fixture and stays OPEN (OP6).
final class StartupWorkStoreTests: XCTestCase {
    private typealias Field = StartupWorkCounters.Field

    private let none: ArraySlice<DecodedInstruction> = []

    private func active() -> StartupWorkCounters {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        return work
    }

    func testEmptyAdmissionHitAndReleaseCountOnceAndPublishGauge() {
        let work = active()
        let store = DiscoveryPreparationStore(work: work)
        let first = store.prepare(sectionOrdinal: 0, rows: none, codeStart: nil, codeEnd: nil,
                                  existingStarts: [])
        XCTAssertNotNil(first)
        XCTAssertEqual(first?.decodedAddresses.count, 0)
        let hit = store.prepare(sectionOrdinal: 0, rows: none, codeStart: nil, codeEnd: nil,
                                existingStarts: [])
        XCTAssertNotNil(hit)
        store.release()
        work.close(.discovery)
        work.finishAnalysis(.success)
        let values = work.snapshot().values
        XCTAssertEqual(values[.cacheAdmissions], 1, "a hit does not admit again")
        XCTAssertEqual(values[.decodedAddressBuilds], 1)
        XCTAssertEqual(values[.directCallBuilds], 1)
        XCTAssertNil(values[.cacheRefusals], "no refusal site was reached")
        XCTAssertEqual(values[.retainedEntriesCurrent], 0)
        XCTAssertEqual(values[.retainedEntriesPeak], 0)
        XCTAssertEqual(store.statistics.admissions, 1)
        XCTAssertEqual(store.statistics.refusals, 0)
    }

    func testEmptyUnavailableBuildIsCountedOncePerSection() {
        let work = active()
        let store = DiscoveryPreparationStore(work: work)
        XCTAssertNil(store.unavailable(sectionOrdinal: 3, rows: none), "unprepared section has no set")
        _ = store.prepare(sectionOrdinal: 3, rows: none, codeStart: nil, codeEnd: nil, existingStarts: [])
        XCTAssertEqual(store.unavailable(sectionOrdinal: 3, rows: none), [])
        XCTAssertEqual(store.unavailable(sectionOrdinal: 3, rows: none), [])
        work.close(.discovery)
        work.finishAnalysis(.success)
        XCTAssertEqual(work.snapshot().values[.unavailableAddressBuilds], 1)
    }

    func testAbsentObserverLeavesStoreStatisticsUnchanged() {
        let plain = DiscoveryPreparationStore()
        let observed = DiscoveryPreparationStore(work: active())
        for store in [plain, observed] {
            _ = store.prepare(sectionOrdinal: 0, rows: none, codeStart: nil, codeEnd: nil, existingStarts: [])
            store.release()
        }
        XCTAssertEqual(plain.statistics.admissions, observed.statistics.admissions)
        XCTAssertEqual(plain.statistics.retainedEntries, observed.statistics.retainedEntries)
    }

    func testGaugeIsConditionalOnAnEnteredStoreAndKeepsPeakAfterRelease() {
        let idle = active()
        idle.finishAnalysis(.success)
        XCTAssertNil(idle.snapshot().values[.retainedEntriesCurrent], "no publication, no gauge")

        let work = active()
        work.publishStoreGauge(current: 6)
        work.publishStoreGauge(current: 2)
        work.finishAnalysis(.success)
        XCTAssertEqual(work.snapshot().values[.retainedEntriesCurrent], 2)
        XCTAssertEqual(work.snapshot().values[.retainedEntriesPeak], 6)
    }

    func testReusedRecorderReportsNoStoreValues() {
        let work = active()
        let store = DiscoveryPreparationStore(work: work)
        _ = store.prepare(sectionOrdinal: 0, rows: none, codeStart: nil, codeEnd: nil, existingStarts: [])
        work.finishAnalysis(.success)
        work.beginAnalysis()
        XCTAssertTrue(work.snapshot().values.isEmpty)
    }
}
