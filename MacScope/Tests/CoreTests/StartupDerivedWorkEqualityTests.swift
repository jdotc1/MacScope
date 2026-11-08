import Foundation
import XCTest
@testable import MacScope

/// Item 1330 (TC04, TC09, TC17): the pure K11 helper arm only. The K10 build-count arm and the
/// full collector projection stay OPEN (OP6, OP12); nothing here is wired into the collector.
final class StartupDerivedWorkEqualityTests: XCTestCase {
    private let raw: [Range<UInt64>] = [10..<20, 15..<25, 25..<30, 40..<50]

    func testOverlapAndAdjacencyMergeIntoSortedUnion() {
        XCTAssertEqual(DiagnosticRangeMembership(validatedRanges: raw).intervals, [10..<30, 40..<50])
        XCTAssertEqual(DiagnosticRangeMembership(validatedRanges: raw.reversed()).intervals, [10..<30, 40..<50])
        XCTAssertEqual(DiagnosticRangeMembership(validatedRanges: [5..<9, 1..<3]).intervals, [1..<3, 5..<9])
    }

    func testBoundariesAndVisitedIntervalCounts() {
        let index = DiagnosticRangeMembership(validatedRanges: raw)
        let expected: [(UInt64, Bool, Int)] = [
            (9, false, 2), (10, true, 2), (29, true, 2), (30, false, 2),
            (40, true, 1), (49, true, 1), (50, false, 1),
        ]
        for (address, member, visited) in expected {
            let result = index.contains(address)
            XCTAssertEqual(result.isMember, member, "address \(address)")
            XCTAssertEqual(result.visited, visited, "address \(address)")
        }
    }

    func testMembershipEqualsRawReference() {
        let index = DiagnosticRangeMembership(validatedRanges: raw)
        for address in UInt64(0)...60 {
            XCTAssertEqual(index.contains(address).isMember, raw.contains(where: { $0.contains(address) }),
                           "address \(address)")
        }
    }

    func testEmptyInputAndEmptyRangesAreNeverMembers() {
        let none = DiagnosticRangeMembership(validatedRanges: [])
        XCTAssertTrue(none.intervals.isEmpty)
        let result = none.contains(10)
        XCTAssertFalse(result.isMember)
        XCTAssertEqual(result.visited, 0)
        XCTAssertTrue(DiagnosticRangeMembership(validatedRanges: [7..<7]).intervals.isEmpty)
    }

    func testTopOfAddressSpaceDoesNotOverflow() {
        let top = UInt64.max - 4
        let index = DiagnosticRangeMembership(validatedRanges: [top..<(UInt64.max - 1), (UInt64.max - 1)..<UInt64.max])
        XCTAssertEqual(index.intervals, [top..<UInt64.max])
        XCTAssertTrue(index.contains(UInt64.max - 1).isMember)
        XCTAssertFalse(index.contains(UInt64.max).isMember)
    }

    func testFamiliesStayIndependent() {
        let all = DiagnosticRangeMembership(validatedRanges: [0..<100])
        let executable = DiagnosticRangeMembership(validatedRanges: [10..<20])
        let linkage = DiagnosticRangeMembership(validatedRanges: [50..<60])
        XCTAssertTrue(all.contains(55).isMember)
        XCTAssertFalse(executable.contains(55).isMember)
        XCTAssertTrue(linkage.contains(55).isMember)
        XCTAssertFalse(linkage.contains(15).isMember)
    }

    // Range validation stays at the collector: zero-size and overflowing sections yield no range.
    func testCollectorRejectsInvalidSectionExtentsBeforeAnyRangeExists() {
        let work = StartupWorkCounters()
        work.beginAnalysis()
        let sections = [
            SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000, size: 0,
                           fileOffset: 0, isExecutable: true),
            SectionSummary(id: UUID(), name: "__DATA,__data", address: UInt64.max - 2, size: 8,
                           fileOffset: 0, isExecutable: false),
            SectionSummary(id: UUID(), name: "__DATA,__ok", address: 0x2000, size: 0x10,
                           fileOffset: 0, isExecutable: false),
        ]
        let input = AnalysisDiagnosticsCollector.Input(
            instructions: [], controlFlowEdges: [], xrefs: [], sections: sections, work: work)
        _ = AnalysisDiagnosticsCollector().collect(input)
        work.close(.collector)
        work.finishAnalysis(.success)
        XCTAssertEqual(work.snapshot().values[.diagnosticSectionRanges], 1)
    }
}
