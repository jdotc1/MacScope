import Foundation
import XCTest
@testable import MacScope

final class SwiftMetadataCStringFootprintTests: XCTestCase {
    private func section(address: UInt64 = 0x1000, fileOffset: UInt64 = 0,
                         size: UInt64, zeroFill: Bool = false) -> SwiftMetadataParser.Section {
        .init(name: "__cstring", address: address, fileOffset: fileOffset,
              size: size, isZeroFill: zeroFill, segmentName: "__TEXT")
    }

    private func parser(_ bytes: [UInt8], _ sections: [SwiftMetadataParser.Section]) -> SwiftMetadataParser {
        SwiftMetadataParser(data: Data(bytes), sections: sections)
    }

    func testCStringRejectsUnmappedTerminatorDespiteAvailableFileBytes() {
        let value = parser([0x61, 0x62, 0], [section(size: 2)])
        XCTAssertNil(value.readCString(atVA: 0x1000))
    }

    func testCStringDoesNotSpliceAdjacentSections() {
        let left = section(size: 2)
        let right = section(address: 0x1002, fileOffset: 2, size: 1)
        for sections in [[left, right], [right, left]] {
            XCTAssertNil(parser([0x61, 0x62, 0], sections).readCString(atVA: 0x1000))
        }
    }

    func testCStringRejectsZeroFillDespiteAvailableFileBytes() {
        XCTAssertNil(parser([0x61, 0], [section(size: 2, zeroFill: true)]).readCString(atVA: 0x1000))
    }

    func testCStringRejectsCompleteOverlapInEitherSectionOrder() {
        let first = section(size: 2)
        let second = section(fileOffset: 2, size: 2)
        for sections in [[first, second], [second, first]] {
            XCTAssertNil(parser([0x61, 0, 0x62, 0], sections).readCString(atVA: 0x1000))
        }
    }

    func testCStringRejectsTerminatorOnlyOverlapInEitherSectionOrder() {
        let whole = section(size: 2)
        let tail = section(address: 0x1001, fileOffset: 2, size: 1)
        for sections in [[whole, tail], [tail, whole]] {
            XCTAssertNil(parser([0x61, 0, 0], sections).readCString(atVA: 0x1000))
        }
    }

    func testCStringRejectsPartialOverlapBeginningBeforeString() {
        let whole = section(size: 3)
        let prefix = section(address: 0x0fff, fileOffset: 3, size: 2)
        for sections in [[whole, prefix], [prefix, whole]] {
            XCTAssertNil(parser([0x61, 0x62, 0, 0, 0], sections).readCString(atVA: 0x1000))
        }
    }

    func testCStringRejectsZeroFillCompetitorAtTerminator() {
        let whole = section(size: 2)
        let tail = section(address: 0x1001, fileOffset: 2, size: 1, zeroFill: true)
        for sections in [[whole, tail], [tail, whole]] {
            XCTAssertNil(parser([0x61, 0, 0], sections).readCString(atVA: 0x1000))
        }
    }

    func testCStringRejectsDuplicateSectionDeclarations() {
        let whole = section(size: 2)
        XCTAssertNil(parser([0x61, 0], [whole, whole]).readCString(atVA: 0x1000))
    }

    func testCStringIgnoresOverlapAfterFirstTerminator() {
        let whole = section(size: 4)
        let tail = section(address: 0x1002, fileOffset: 2, size: 2, zeroFill: true)
        for sections in [[whole, tail], [tail, whole]] {
            XCTAssertEqual(parser([0x61, 0, 0x62, 0], sections).readCString(atVA: 0x1000), "a")
        }
    }

    func testCStringAcceptsTerminatorAtSectionAndFileBoundary() {
        XCTAssertEqual(parser([0x61, 0x62, 0], [section(size: 3)]).readCString(atVA: 0x1000), "ab")
    }

    func testCStringRejectsTruncatedFileDespiteMappedVMExtent() {
        XCTAssertNil(parser([0x61, 0x62], [section(size: 3)]).readCString(atVA: 0x1000))
    }

    func testCStringAcceptsEmptyString() {
        XCTAssertEqual(parser([0], [section(size: 1)]).readCString(atVA: 0x1000), "")
    }

    func testCStringPreservesASCIIAtNonzeroFileAndVMOffsets() {
        let value = parser([0xff, 0xff, 0x7f, 0x61, 0x62, 0], [section(fileOffset: 2, size: 4)])
        XCTAssertEqual(value.readCString(atVA: 0x1001), "ab")
    }

    func testCStringPreservesMultibyteUTF8() {
        XCTAssertEqual(parser([0x63, 0x61, 0x66, 0xc3, 0xa9, 0], [section(size: 6)])
            .readCString(atVA: 0x1000), "café")
    }

    func testCStringPreservesReplacementDecodingOfMalformedUTF8() {
        XCTAssertEqual(parser([0xc3, 0x28, 0], [section(size: 3)])
            .readCString(atVA: 0x1000), "\u{fffd}(")
    }

    func testCStringAcceptsTerminatorInLastByteOfExistingCap() {
        let count = SwiftMetadataParser.Limits.maxStringLength
        let bytes = [UInt8](repeating: 0x61, count: count - 1) + [0]
        XCTAssertEqual(parser(bytes, [section(size: UInt64(bytes.count))]).readCString(atVA: 0x1000),
                       String(repeating: "a", count: count - 1))
    }

    func testCStringRejectsTerminatorOneByteBeyondExistingCap() {
        let count = SwiftMetadataParser.Limits.maxStringLength
        let bytes = [UInt8](repeating: 0x61, count: count) + [0]
        XCTAssertNil(parser(bytes, [section(size: UInt64(bytes.count))]).readCString(atVA: 0x1000))
    }

    func testCStringRejectsCapSizedUnterminatedInput() {
        let bytes = [UInt8](repeating: 0x61, count: SwiftMetadataParser.Limits.maxStringLength)
        XCTAssertNil(parser(bytes, [section(size: UInt64(bytes.count))]).readCString(atVA: 0x1000))
    }

    func testCStringAcceptsInclusiveVMEndAtUInt64Max() {
        let value = parser([0x61, 0], [section(address: UInt64.max - 1, size: 2)])
        XCTAssertEqual(value.readCString(atVA: UInt64.max - 1), "a")
        XCTAssertEqual(value.readCString(atVA: UInt64.max), "")
    }

    func testCStringRejectsUnrepresentableSectionVMExtent() {
        XCTAssertNil(parser([0], [section(address: UInt64.max, size: 2)])
            .readCString(atVA: UInt64.max))
    }

    func testCStringDoesNotBorrowWrappedFileOffset() {
        let value = parser([0], [section(fileOffset: UInt64.max, size: 3)])
        XCTAssertNil(value.readCString(atVA: 0x1001))
    }

    func testCStringRejectsFileOffsetsBeyondIntAndFileBounds() {
        for offset in [UInt64(1), UInt64(Int.max), UInt64.max] {
            XCTAssertNil(parser([0], [section(fileOffset: offset, size: 1)]).readCString(atVA: 0x1000))
        }
        XCTAssertNil(parser([], [section(size: 1)]).readCString(atVA: 0x1000))
    }

    func testCStringIgnoresUnrelatedMalformedAndEmptySections() {
        let unrelated = section(address: UInt64.max, fileOffset: UInt64.max, size: 2)
        let empty = section(size: 0, zeroFill: true)
        XCTAssertEqual(parser([0x61, 0], [unrelated, empty, section(size: 2)])
            .readCString(atVA: 0x1000), "a")
    }

    func testCStringIgnoresDisjointVASectionsThatAliasTheSameFileBytes() {
        let original = section(size: 2)
        let alias = section(address: 0x2000, size: 2)
        XCTAssertEqual(parser([0x61, 0], [alias, original]).readCString(atVA: 0x1000), "a")
    }

    func testCStringRejectsMalformedCompetingExtentAtTerminator() {
        let whole = section(address: UInt64.max - 2, size: 2)
        let malformed = section(address: UInt64.max - 1, fileOffset: 2, size: 3)
        for sections in [[whole, malformed], [malformed, whole]] {
            XCTAssertNil(parser([0x61, 0, 0], sections).readCString(atVA: UInt64.max - 2))
        }
    }

    func testCStringRequiresOnlyItsOwnFileBackedPrefix() {
        XCTAssertEqual(parser([0x61, 0], [section(size: 4)]).readCString(atVA: 0x1000), "a")
    }

    func testCStringRejectsUnmappedOrEmptySectionStart() {
        XCTAssertNil(parser([0], []).readCString(atVA: 0x1000))
        XCTAssertNil(parser([0], [section(size: 0)]).readCString(atVA: 0x1000))
        XCTAssertNil(parser([0], [section(address: 0x1001, size: 1)]).readCString(atVA: 0x1000))
    }

    func testSharedFootprintRejectsZeroWidthAndWrappingRequest() {
        let value = parser([0], [section(address: UInt64.max, size: 1)])
        XCTAssertNil(value.uniqueFileBackedSpan(atVA: UInt64.max, width: 0))
        XCTAssertNil(value.uniqueFileBackedSpan(atVA: UInt64.max, width: 2))
        XCTAssertEqual(value.uniqueFileBackedSpan(atVA: UInt64.max, width: 1)?.fileOffset, 0)
    }

    func testSharedFootprintRejectsWrappingFileReadEnd() {
        let value = parser([0, 0], [section(fileOffset: UInt64.max, size: 2)])
        XCTAssertNil(value.uniqueFileBackedSpan(atVA: 0x1000, width: 2))
    }

    func testSharedFootprintRejectsUnbackedLargeWidthWithoutNarrowing() {
        let value = parser([0], [section(address: 0, size: UInt64.max)])
        XCTAssertNil(value.uniqueFileBackedSpan(atVA: 0, width: UInt64.max))
    }
}
