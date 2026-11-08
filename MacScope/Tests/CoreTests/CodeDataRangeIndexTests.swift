import Foundation
import XCTest
@testable import MacScope

// T4 guard; F3 scalar loader ranges. Authored, unrun.
final class CodeDataRangeIndexTests: XCTestCase {
    static func linear(_ address: UInt64, _ ranges: [BinaryCodeDataRange]) -> Bool {
        ranges.contains { range in
            guard range.size > 0 else { return false }
            let (end, overflow) = range.address.addingReportingOverflow(range.size)
            return !overflow && address >= range.address && address < end
        }
    }
    func testGuardHalfOpenUnionAndOriginalOrder() {
        let pairs: [(UInt64, UInt64)] = [(30, 4), (10, 5), (14, 6), (20, 5),
            (12, 1), (10, 5), (80, 0), (UInt64.max - 1, 4), (55, 1)]
        let ranges = pairs.enumerated().map {
            BinaryCodeDataRange(address: $0.element.0, size: $0.element.1, kind: "kind\($0.offset)")
        }
        let saved = ranges
        let index = CodeDataRangeIndex(ranges: ranges)
        XCTAssertEqual(index.validRangeCount, 7)
        XCTAssertEqual(index.intervalCount, 3)
        let addresses: [UInt64] = [56, 10, 9, 14, 24, 25, 30, 33, 34, 55, 80, .max, 11]
        let expected: [UInt64] = [10, 14, 24, 30, 33, 55, 11]
        XCTAssertEqual(addresses.filter { index.contains(address: $0) }, expected)
        XCTAssertEqual(Set(addresses.filter { index.contains(address: $0) }), Set(expected))
        XCTAssertEqual(addresses.filter { Self.linear($0, ranges) }, expected)
        XCTAssertEqual(ranges, saved)
        let rows = addresses.map { address in
            DecodedInstruction(address: address, bytes: [0xc3], mnemonic: "ret",
                operands: "", branchTarget: nil, comment: nil, flow: .return)
        }
        XCTAssertEqual(rows.filter { !index.contains(address: $0.address) },
                       rows.filter { !Self.linear($0.address, ranges) })
    }
    func testGuardZeroOneEightNineAndNonAlignedEndpoints() {
        for count in [0, 1, 8, 9] {
            let ranges = (0..<count).map {
                BinaryCodeDataRange(address: UInt64(101 + 7 * $0), size: 3, kind: "data")
            }
            let index = CodeDataRangeIndex(ranges: ranges)
            XCTAssertEqual(index.intervalCount, count)
            for range in ranges {
                XCTAssertFalse(index.contains(address: range.address - 1))
                XCTAssertTrue(index.contains(address: range.address))
                XCTAssertTrue(index.contains(address: range.address + 2))
                XCTAssertFalse(index.contains(address: range.address + 3))
            }
            let probes: [UInt64] = [0, 101, 103, 104, 108, 150, 159, 160, .max]
            XCTAssertEqual(probes.map { index.contains(address: $0) },
                           probes.map { Self.linear($0, ranges) })
        }
        let high = CodeDataRangeIndex(ranges: [
            BinaryCodeDataRange(address: .max - 2, size: 2, kind: "valid")])
        XCTAssertTrue(high.contains(address: .max - 1))
        XCTAssertFalse(high.contains(address: .max))
    }
}
