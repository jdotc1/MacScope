import Foundation
import XCTest
@testable import MacScope

extension SwiftSlotInventory {
    /// Explicit test inventory: the given ranges are fully inspected; `rebases` are proven rebase
    /// events and `binds` occupy their slot. No extent (valid for any slice).
    static func testInventory(covering ranges: [Range<UInt64>], rebases: [UInt64: UInt64] = [:],
                              binds: Set<UInt64> = []) -> SwiftSlotInventory {
        var builder = Builder()
        for range in ranges { builder.cover(range) }
        for (va, target) in rebases.sorted(by: { $0.key < $1.key }) { builder.rebase(va, target: target) }
        for va in binds.sorted() { builder.occupy(va, .bind) }
        return builder.build(extent: nil)
    }
}

final class SwiftSlotInventoryTests: XCTestCase {
    private func inventory(_ configure: (inout SwiftSlotInventory.Builder) -> Void,
                           extent: SwiftSlotInventory.Extent? = nil) -> SwiftSlotInventory {
        var builder = SwiftSlotInventory.Builder()
        builder.cover(0x1000..<0x2000)
        configure(&builder)
        return builder.build(extent: extent)
    }

    func testUnknownFailsClosed() {
        XCTAssertEqual(SwiftSlotInventory.unknown.word(atSlot: 0x1000), .uninspected(.unknownProducer))
    }

    func testUntouchedRebaseAndOutsideCoverage() {
        let inv = inventory { $0.rebase(0x1010, target: 0x4000) }
        XCTAssertEqual(inv.word(atSlot: 0x1000), .untouched)
        XCTAssertEqual(inv.word(atSlot: 0x1010), .rebase(target: 0x4000))
        XCTAssertEqual(inv.word(atSlot: 0x3000), .uninspected(.outsideCoverage))
        XCTAssertEqual(inv.word(atSlot: 0x1ffc), .uninspected(.outsideCoverage), "extent crosses coverage end")
    }

    func testOverlapIsByExtentNotEqualStart() {
        let inv = inventory {
            $0.occupy(0x1004, width: 4, .narrowWrite)
            $0.rebase(0x1100, target: 0x9)
        }
        XCTAssertEqual(inv.word(atSlot: 0x1000), .occupied(.narrowWrite), "write inside the 8-byte extent")
        XCTAssertEqual(inv.word(atSlot: 0x1008), .untouched)
        XCTAssertEqual(inv.word(atSlot: 0x1104), .occupied(.narrowWrite), "misaligned slot overlapping a rebase")
        XCTAssertEqual(inv.word(atSlot: 0x1100), .rebase(target: 0x9))
    }

    func testTwoEventsAreAmbiguousWithoutLastWriteWins() {
        let dup = inventory {
            $0.rebase(0x1010, target: 1)
            $0.rebase(0x1010, target: 2)
        }
        XCTAssertEqual(dup.word(atSlot: 0x1010), .ambiguous)
        let mixed = inventory {
            $0.rebase(0x1010, target: 1)
            $0.occupy(0x1010, .bind)
        }
        XCTAssertEqual(mixed.word(atSlot: 0x1010), .ambiguous)
    }

    func testBlockerWithholdsEveryAnswerButOccupied() {
        let inv = inventory {
            $0.rebase(0x1010, target: 1)
            $0.occupy(0x1020, .bind)
            $0.block(.classicImage, .unsupportedOpcode)
        }
        XCTAssertEqual(inv.word(atSlot: 0x1010), .uninspected(.unsupportedOpcode))
        XCTAssertEqual(inv.word(atSlot: 0x1000), .uninspected(.unsupportedOpcode))
        XCTAssertEqual(inv.word(atSlot: 0x1020), .occupied(.bind))
        XCTAssertEqual(inv.withheld.map(\.scope), [.classicImage])
    }

    func testOccupiedRangeAndOverflowGuard() {
        let inv = inventory { $0.occupyRange(0x1200..<0x1300, .indirectPointer) }
        XCTAssertEqual(inv.word(atSlot: 0x1204), .occupied(.indirectPointer))
        XCTAssertEqual(inv.word(atSlot: 0x1300), .untouched)
        XCTAssertEqual(inv.word(atSlot: UInt64.max - 3), .uninspected(.malformedInventory))
    }

    func testExtentMismatchFailsClosedAndReboundRestamps() {
        let inv = inventory({ _ in }, extent: .init(offset: 0, size: 0x100))
        XCTAssertEqual(inv.attested(sliceOffset: 0, sliceSize: 0x100).word(atSlot: 0x1000), .untouched)
        XCTAssertEqual(inv.attested(sliceOffset: 0, sliceSize: 0x200).word(atSlot: 0x1000),
                       .uninspected(.extentMismatch))
        XCTAssertEqual(inv.attested(sliceOffset: 0x4000, sliceSize: 0x100).word(atSlot: 0x1000),
                       .uninspected(.extentMismatch))
        XCTAssertEqual(inv.rebound(sliceOffset: 0x4000, sliceSize: 0x100)
                        .attested(sliceOffset: 0x4000, sliceSize: 0x100).word(atSlot: 0x1000), .untouched)
        XCTAssertEqual(inv.rebound(sliceOffset: 0x4000, sliceSize: 0x200).word(atSlot: 0x1000),
                       .uninspected(.extentMismatch))
    }
}
