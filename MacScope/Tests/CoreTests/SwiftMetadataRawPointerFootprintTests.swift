import Foundation
import XCTest
@testable import MacScope

/// NEW source definitions only; no existing fixtures are loaded or replayed.
final class SwiftMetadataRawPointerFootprintTests: XCTestCase {
    private let pointer: UInt64 = 0x1234_5678_9abc_def0
    private let pointerBytes: [UInt8] = [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]

    private func loaded(_ slot: UInt64 = 0x1000,
                        sections: [SwiftMetadataParser.Section], bytes: [UInt8]? = nil,
                        rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:])
        -> SwiftMetadataConstantInterpreter.Value? {
        let parser = SwiftMetadataParser(data: Data(bytes ?? pointerBytes), sections: sections,
                                         rebaseTargets: rebases, bindNames: binds)
        return SwiftMetadataConstantInterpreter(parser: parser).loaded(slot)
    }

    func testValidRawPointerUsesAllEightLittleEndianBytes() {
        XCTAssertEqual(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 8)
        ]), .address(pointer))
    }

    func testValidRawZeroRemainsAnAddress() {
        XCTAssertEqual(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 8)
        ], bytes: Array(repeating: 0, count: 8)), .address(0))
    }

    func testValidUnalignedPointerAtNonzeroFileAndVMOffsets() {
        XCTAssertEqual(loaded(0x1003, sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 2, size: 11)
        ], bytes: [0, 0, 0, 0, 0] + pointerBytes), .address(pointer))
    }

    func testZeroFillCannotBorrowPresentFileBytes() {
        XCTAssertNil(loaded(sections: [
            .init(name: "__bss", address: 0x1000, fileOffset: 0, size: 8, isZeroFill: true)
        ]))
    }

    func testVMFootprintMustContainAllEightBytes() {
        for size in [UInt64(1), 4, 5, 7] {
            XCTAssertNil(loaded(sections: [
                .init(name: "__data", address: 0x1000, fileOffset: 0, size: size)
            ]), "Declared VM extent: \(size)")
        }
    }

    func testContiguousFourByteSectionsCannotCombine() {
        XCTAssertNil(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 4),
            .init(name: "__const", address: 0x1004, fileOffset: 4, size: 4)
        ]))
    }

    func testDiscontiguousFourByteSectionsCannotCombine() {
        XCTAssertNil(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 4),
            .init(name: "__const", address: 0x1004, fileOffset: 12, size: 4)
        ], bytes: Array(pointerBytes.prefix(4)) + Array(repeating: 0, count: 8)
            + Array(pointerBytes.suffix(4))))
    }

    func testAnyOverlappingByteRejectsRegardlessOfSectionOrder() {
        let complete = SwiftMetadataParser.Section(name: "__data", address: 0x1000,
                                                    fileOffset: 0, size: 8)
        // Offsets 1 and 7 do not coincide with either old readU32 start.
        for delta in [UInt64(0), 1, 4, 7] {
            let competing = SwiftMetadataParser.Section(name: "__const", address: 0x1000 + delta,
                                                         fileOffset: 8, size: 1)
            for sections in [[complete, competing], [competing, complete]] {
                XCTAssertNil(loaded(sections: sections, bytes: pointerBytes + [0]))
            }
        }
    }

    func testLeftStartingPartialOverlapRejectsInBothOrders() {
        let complete = SwiftMetadataParser.Section(name: "__data", address: 0x1000,
                                                    fileOffset: 0, size: 8)
        let competing = SwiftMetadataParser.Section(name: "__const", address: 0x0fff,
                                                     fileOffset: 8, size: 2)
        for sections in [[complete, competing], [competing, complete]] {
            XCTAssertNil(loaded(sections: sections, bytes: pointerBytes + [0, 0]))
        }
    }

    func testOverlappingZeroFillAlsoMakesMappingAmbiguous() {
        let complete = SwiftMetadataParser.Section(name: "__data", address: 0x1000,
                                                    fileOffset: 0, size: 8)
        let zeroFill = SwiftMetadataParser.Section(name: "__bss", address: 0x1007,
                                                    fileOffset: 0, size: 1, isZeroFill: true)
        for sections in [[complete, zeroFill], [zeroFill, complete]] {
            XCTAssertNil(loaded(sections: sections))
        }
    }

    func testIdenticalDuplicateMappingsAreNotUnique() {
        let section = SwiftMetadataParser.Section(name: "__data", address: 0x1000,
                                                   fileOffset: 0, size: 8)
        XCTAssertNil(loaded(sections: [section, section]))
    }

    func testEmptyAndExactlyAdjacentSectionsDoNotOverlap() {
        XCTAssertEqual(loaded(sections: [
            .init(name: "__const", address: 0x1004, fileOffset: UInt64.max, size: 0),
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 8),
            .init(name: "__const", address: 0x1008, fileOffset: 8, size: 1),
            .init(name: "__const", address: 0x0fff, fileOffset: 9, size: 1)
        ], bytes: pointerBytes + [0, 0]), .address(pointer))
    }

    func testFileOffsetPlusDeltaCannotWrapIntoFile() {
        XCTAssertNil(loaded(0x1004, sections: [
            .init(name: "__data", address: 0x1000, fileOffset: UInt64.max - 3, size: 16)
        ]))
    }

    func testFileFootprintMustContainAllEightBytes() {
        XCTAssertNil(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 8)
        ], bytes: Array(pointerBytes.prefix(7))))
    }

    func testFileOffsetMustFitArrayIndex() {
        XCTAssertNil(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: UInt64(Int.max) + 1, size: 8)
        ]))
    }

    func testPointerVMFootprintCannotWrap() {
        XCTAssertNil(loaded(UInt64.max - 6, sections: [
            .init(name: "__data", address: UInt64.max - 8, fileOffset: 0, size: 8)
        ], bytes: [0, 0] + pointerBytes))
    }

    func testRelevantSectionExtentCannotWrap() {
        XCTAssertNil(loaded(sections: [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: UInt64.max)
        ]))
    }

    func testFootprintEndingAtMaximumVAIsRepresentable() {
        XCTAssertEqual(loaded(UInt64.max - 7, sections: [
            .init(name: "__data", address: UInt64.max - 7, fileOffset: 0, size: 8)
        ]), .address(pointer))
    }

    func testExplicitFixupsOverrideValidRawBytesInOriginalOrder() {
        let sections: [SwiftMetadataParser.Section] = [
            .init(name: "__data", address: 0x1000, fileOffset: 0, size: 8)
        ]
        XCTAssertEqual(loaded(sections: sections, rebases: [0x1000: 0x2000]), .address(0x2000))
        XCTAssertEqual(loaded(sections: sections, binds: [0x1000: "_bound"]), .bound("_bound"))
        XCTAssertEqual(loaded(sections: sections, rebases: [0x1000: 0x2000],
                              binds: [0x1000: "_bound"]), .bound("_bound"))
    }

    func testExplicitFixupsDoNotRequireRawFootprint() {
        XCTAssertEqual(loaded(UInt64.max, sections: [], rebases: [UInt64.max: 0]), .address(0))
        XCTAssertEqual(loaded(UInt64.max, sections: [], rebases: [UInt64.max: 0x2000],
                              binds: [UInt64.max: "_bound"]), .bound("_bound"))
        XCTAssertEqual(loaded(sections: [
            .init(name: "__bss", address: 0x1000, fileOffset: UInt64.max, size: 1, isZeroFill: true)
        ], rebases: [0x1000: 0x2000]), .address(0x2000))
    }
}
