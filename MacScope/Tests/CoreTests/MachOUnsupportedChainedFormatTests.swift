import XCTest
@testable import MacScope

/// Item 1285 R6 invariant/control, authored-unrun; expectations are hand-derived.
/// Ordinary parse of the ten listed unsupported formats, over five rebase words,
/// yields no fixups, one named/value/address diagnostic, an unsupportedFormat
/// chained-page withheld scope, and uninspected words, never decoded occupancy,
/// rebase or untouched authority. A format-2 bind is the positive control.
/// Synthetic in-memory bytes only. This does not pin the strict coverage audit.
final class MachOUnsupportedChainedFormatTests: XCTestCase {
    func testUnsupportedFormatsWithholdWordsAcrossRebasePayloads() throws {
        for format: UInt16 in [0, 3, 4, 5, 7, 8, 10, 11, 13, 0xffff] {
            for raw: UInt64 in [0, UInt64.max, UInt64(1) << 63, UInt64(1) << 62, 0xdead_beef] {
                let fixture = MachOFixture.makeExecutableWithChainedFixupChain(
                    pointerFormat: format, rebaseRawOverride: raw)
                let parsed = try MachOParser().parse(fixture.bytes)
                let label = "format=\(format), raw=\(raw)"
                let chained = try XCTUnwrap(parsed.dyldChainedFixups)
                XCTAssertEqual(chained.fixups, [], label)
                XCTAssertEqual(parsed.loaderFindings.count, 1, label)
                let finding = try XCTUnwrap(parsed.loaderFindings.first)
                XCTAssertEqual(finding.kind, .chainedFixupsUnhandledPointerFormat, label)
                XCTAssertEqual(finding.value, UInt64(format), label)
                XCTAssertEqual(finding.address, fixture.chainedBindAddress, label)
                XCTAssertTrue(finding.message.contains("Unhandled chained pointer format \(format) "), label)

                let inventory = parsed.swiftSlotInventory
                let withheld = inventory.withheld.filter {
                    $0.scope == .chainedPage && $0.reason == .unsupportedFormat
                }
                XCTAssertEqual(withheld.count, 1, label)
                let extent = try XCTUnwrap(withheld.first?.extent)
                XCTAssertTrue(extent.contains(fixture.chainedBindAddress), label)
                XCTAssertTrue(extent.contains(fixture.chainedRebaseAddress), label)
                // Withheld reason and query reason are different at the pin:
                // note() does not add a blocker; the uncovered word is outsideCoverage.
                // Parser part7of7:4587-4591,4619-4621; SwiftSlotInventory:142-143,204-205.
                XCTAssertEqual(inventory.word(atSlot: fixture.chainedBindAddress),
                               .uninspected(.outsideCoverage), label)
                XCTAssertEqual(inventory.word(atSlot: fixture.chainedRebaseAddress),
                               .uninspected(.outsideCoverage), label)
                XCTAssertTrue(inventory.writes.isEmpty, label)
            }
        }
    }

    func testFormatTwoBindIsOccupiedWithoutUnsupportedFormatWithholding() throws {
        let fixture = MachOFixture.makeExecutableWithChainedFixupChain(pointerFormat: 2)
        let parsed = try MachOParser().parse(fixture.bytes)
        let chained = try XCTUnwrap(parsed.dyldChainedFixups)
        XCTAssertEqual(chained.fixups.count, 2)
        XCTAssertEqual(parsed.swiftSlotInventory.word(atSlot: fixture.chainedBindAddress), .occupied(.bind))
        XCTAssertFalse(parsed.swiftSlotInventory.withheld.contains { $0.reason == .unsupportedFormat })
        XCTAssertTrue(parsed.loaderFindings.isEmpty)
    }
}
