import Foundation
import XCTest
@testable import MacScope

// T5 RED with adapter: old counted constructions vs actual new build counters.
// F3 scalar stream, not a timing test. Authored, unrun.
final class DiscoveryPreparationWorkCountTests: XCTestCase {
    func testRedWithAdapterTwoOldDecodedBuildsBecomeOneAcrossFourRounds() {
        var rows = ReadyFixture.instructions(count: 8)
        rows[2].mnemonic = "unavailable"
        var oldDecodedBuilds = 0
        var oldUnavailableBuilds = 0
        func oldRound() -> (Set<UInt64>, Set<UInt64>) {
            oldDecodedBuilds += 1
            let directMembership = Set(rows.map(\.address))
            oldDecodedBuilds += 1
            let decoded = Set(rows.map(\.address))
            oldUnavailableBuilds += 1
            let unavailable = Set(rows.filter { $0.mnemonic == "unavailable" }.map(\.address))
            XCTAssertEqual(directMembership, decoded)
            return (decoded, unavailable)
        }
        let store = DiscoveryPreparationStore()
        for _ in 0..<4 {
            let expected = oldRound()
            let value = store.prepare(sectionOrdinal: 0, instructions: rows,
                codeStart: 0x1000, codeEnd: 0x1020, existingStarts: [0x1000])
            XCTAssertEqual(value?.decodedAddresses, expected.0)
            XCTAssertEqual(store.unavailable(sectionOrdinal: 0, instructions: rows), expected.1)
        }
        XCTAssertEqual(oldDecodedBuilds, 8)
        XCTAssertEqual(oldUnavailableBuilds, 4)
        XCTAssertEqual(store.statistics.decodedAddressBuilds, 1)
        XCTAssertEqual(store.statistics.unavailableAddressBuilds, 1)
        XCTAssertEqual(store.statistics.directCallBuilds, 1)
        let nextInvocation = DiscoveryPreparationStore()
        XCTAssertNotNil(nextInvocation.prepare(sectionOrdinal: 0, instructions: rows,
            codeStart: 0x1000, codeEnd: 0x1020, existingStarts: [0x1000]))
        XCTAssertEqual(nextInvocation.statistics.decodedAddressBuilds, 1)
    }
    func testRedWithAdapterReservationZeroExactAndOneOverBudget() {
        let rows = ReadyFixture.instructions(count: 4)
        // Conservative reservation is 3*N = 12, not an allocation measurement.
        for (budget, admitted) in [(0, false), (11, false), (12, true), (13, true)] {
            let store = DiscoveryPreparationStore(entryLimit: budget)
            let result = store.prepare(sectionOrdinal: 0, instructions: rows,
                codeStart: 0x1000, codeEnd: 0x1010, existingStarts: [0x1000])
            XCTAssertEqual(result != nil, admitted)
            XCTAssertEqual(store.statistics.admissions, admitted ? 1 : 0)
            XCTAssertEqual(store.statistics.refusals, admitted ? 0 : 1)
            XCTAssertEqual(store.statistics.decodedAddressBuilds, admitted ? 1 : 0)
            if admitted {
                XCTAssertEqual(result?.decodedAddresses, Set(rows.map(\.address)))
                XCTAssertEqual(store.unavailable(sectionOrdinal: 0, instructions: rows), [])
                XCTAssertEqual(store.statistics.retainedEntries, 4)
            }
            let binary = ReadyFixture.binary(instructions: rows)
            let expected = AnalysisEngine().functionSummariesForTesting(from: binary,
                codeSection: binary.executableTextSection, decodedInstructions: rows,
                preparation: DiscoveryPreparationStore(entryLimit: 0))
            XCTAssertEqual(AnalysisEngine().functionSummariesForTesting(from: binary,
                codeSection: binary.executableTextSection, decodedInstructions: rows,
                preparation: store), expected)
            store.release()
            XCTAssertEqual(store.statistics.retainedEntries, 0)
        }
    }
    func testRedWithAdapterAggregateBudgetRejectsSecondSection() {
        let rows = ReadyFixture.instructions(count: 4)
        let store = DiscoveryPreparationStore(entryLimit: 12)
        XCTAssertNotNil(store.prepare(sectionOrdinal: 0, instructions: rows,
            codeStart: 0x1000, codeEnd: 0x1010, existingStarts: []))
        XCTAssertNil(store.prepare(sectionOrdinal: 1, instructions: rows,
            codeStart: 0x1000, codeEnd: 0x1010, existingStarts: []))
        XCTAssertEqual(store.statistics.admissions, 1)
        XCTAssertEqual(store.statistics.refusals, 1)
        XCTAssertEqual(store.statistics.decodedAddressBuilds, 1)
        XCTAssertEqual(store.statistics.retainedEntries, 4)
    }
    func testRedWithAdapterGlobalCapAndCapPlusOneWithoutLargeAllocation() {
        let store = DiscoveryPreparationStore()
        XCTAssertTrue(store.canAdmit(entryUpperBound: 0))
        XCTAssertTrue(store.canAdmit(entryUpperBound: 8_388_608))
        XCTAssertFalse(store.canAdmit(entryUpperBound: 8_388_609))
        XCTAssertFalse(store.canAdmit(entryUpperBound: Int.max))
        XCTAssertEqual(store.statistics.decodedAddressBuilds, 0)
        XCTAssertEqual(store.statistics.retainedEntries, 0)
    }
}
