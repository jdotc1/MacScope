import Foundation
import XCTest
@testable import MacScope

// T6 RED with adapter, adversarial all-miss F3 stream. Authored, unrun.
final class CodeDataMembershipWorkCountTests: XCTestCase {
    func testRedWithAdapterNineRangesReduceComparisons() {
        let ranges = (0..<9).map {
            BinaryCodeDataRange(address: UInt64(100 + $0 * 10), size: 1, kind: "data")
        }
        let probes: [UInt64] = [1, 2, 3, 5, 7, 11, 13]
        var oldCount = 0
        let old = probes.map { address in
            ranges.contains { range in
                oldCount += 1
                guard range.size > 0 else { return false }
                let (end, overflow) = range.address.addingReportingOverflow(range.size)
                return !overflow && address >= range.address && address < end
            }
        }
        let index = CodeDataRangeIndex(ranges: ranges)
        var newCount = 0
        let new = probes.map { index.countedContains(address: $0, comparisons: &newCount) }
        XCTAssertEqual(old, Array(repeating: false, count: 7))
        XCTAssertEqual(new, old)
        XCTAssertEqual(oldCount, 63)
        XCTAssertEqual(newCount, 28) // Seven probes, four lower-endpoint comparisons each.
    }
    func testGuardSmallRangeOriginalPredicateAdapter() {
        for count in [0, 1, 8] {
            let ranges = (0..<count).map {
                BinaryCodeDataRange(address: UInt64(100 + $0 * 10), size: 1, kind: "data")
            }
            var comparisons = 0
            let selected = ranges.contains { range in
                comparisons += 1
                return CodeDataRangeIndexTests.linear(1, [range])
            }
            XCTAssertFalse(selected)
            XCTAssertEqual(comparisons, count)
        }
    }
}
