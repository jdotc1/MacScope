import Foundation
import XCTest
@testable import MacScope

final class SwiftFileOffsetArithmetic742Tests: XCTestCase {
    private func section(_ address: UInt64, _ offset: UInt64, _ size: UInt64,
                         zeroFill: Bool = false) -> SwiftMetadataParser.Section {
        .init(name: "__742", address: address, fileOffset: offset, size: size,
              isZeroFill: zeroFill)
    }
    private func parser(_ sections: [SwiftMetadataParser.Section], bytes: [UInt8] = []) -> SwiftMetadataParser {
        .init(data: Data(bytes), sections: sections)
    }

    func testOrdinaryHalfOpenRangeAndEmptySection() {
        let p = parser([section(0x100, 99, 0), section(0x100, 7, 4)])
        XCTAssertNil(p.fileOffset(forVA: 0xff))
        XCTAssertEqual(p.fileOffset(forVA: 0x100), 7)
        XCTAssertEqual(p.fileOffset(forVA: 0x103), 10)
        XCTAssertNil(p.fileOffset(forVA: 0x104))
    }

    func testRepresentableMaxEndpointExcludesMaxAddress() {
        let p = parser([section(UInt64.max - 3, 0, 3)])
        XCTAssertEqual(p.fileOffset(forVA: UInt64.max - 3), 0)
        XCTAssertEqual(p.fileOffset(forVA: UInt64.max - 1), 2)
        XCTAssertNil(p.fileOffset(forVA: UInt64.max))
    }

    func testUnrepresentableEndpointSkipsRatherThanShadowingLaterMatch() {
        let p = parser([section(UInt64.max - 3, 99, 4),
                        section(UInt64.max - 3, 5, 3)])
        XCTAssertEqual(p.fileOffset(forVA: UInt64.max - 2), 6)
        XCTAssertNil(p.fileOffset(forVA: UInt64.max))
        let q = parser([section(UInt64.max - 3, 99, 8), section(0, 2, 4)])
        XCTAssertEqual(q.fileOffset(forVA: 1), 3)
        // Wrapped endpoint 4 never makes high-start section contain low VA 1.
    }

    func testMatchingOffsetOverflowRefusesAndShadowsLaterMapping() {
        let p = parser([section(0x100, UInt64.max - 1, 4), section(0x100, 0, 4)])
        XCTAssertNil(p.fileOffset(forVA: 0x102)) // max-1 + 2 = max+1, never offset zero.
        XCTAssertNil(p.fileOffset(forVA: 0x100)) // No sum overflow, but cannot fit Int.
    }

    func testExactIntBoundaryAndNoByteAvailabilityPromise() {
        let limit = UInt64(Int.max)
        let p = parser([section(0x100, limit - 1, 4)])
        XCTAssertEqual(p.fileOffset(forVA: 0x100), Int.max - 1)
        XCTAssertEqual(p.fileOffset(forVA: 0x101), Int.max)
        XCTAssertNil(p.fileOffset(forVA: 0x102))
        // Empty bytes deliberately: translation is not a readable-span proof.
    }

    func testOverlapsAliasesAndZeroFillKeepFirstMatch() {
        let a = section(0x100, 1, 4)
        let b = section(0x100, 8, 4)
        XCTAssertEqual(parser([a, b]).fileOffset(forVA: 0x101), 2)
        XCTAssertEqual(parser([b, a]).fileOffset(forVA: 0x101), 9)
        XCTAssertEqual(parser([a, a]).fileOffset(forVA: 0x101), 2)
        XCTAssertEqual(parser([section(0x100, 3, 4, zeroFill: true), b])
            .fileOffset(forVA: 0x101), 4)
        XCTAssertNil(parser([section(0x100, UInt64(Int.max) + 1, 4), b])
            .fileOffset(forVA: 0x101))
    }

    func testReflectionPublicCallerRetainsArrayWidthRefusal() {
        // One complete scalar-readable record with an unreadable 20-byte footprint.
        // Flags/name data are irrelevant: public reflection scan refuses before naming.
        let p = SwiftMetadataParser(data: Data([UInt8](repeating: 0, count: 19)), sections: [
            .init(name: "__swift5_builtin", address: 0x100, fileOffset: 0, size: 20)
        ])
        let report = p.parseBuiltinTypesReport()
        XCTAssertTrue(report.records.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
        XCTAssertEqual(report.diagnostics.first?.grade, .abandonedList)
        XCTAssertEqual(report.diagnostics.first?.address, 0x100)
    }

    func testPublicBuiltinReportRejectsOverflowTranslationAndRetainsFreshValidRecord() {
        let malformed = SwiftMetadataParser(data: Data([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]), sections: [
            .init(name: "__752_overflow", address: 0x100,
                  fileOffset: UInt64.max - 1, size: 22),
            .init(name: "__swift5_builtin", address: 0x102, fileOffset: 0, size: 20)
        ])
        let malformedReport = malformed.parseBuiltinTypesReport()
        XCTAssertTrue(malformedReport.records.isEmpty)
        XCTAssertEqual(malformedReport.diagnostics.count, 1)
        XCTAssertEqual(malformedReport.diagnostics.first?.grade, .abandonedList)
        XCTAssertEqual(malformedReport.diagnostics.first?.address, 0x102)

        // Fresh independent literal layout: 20-byte record at 0x400, name at 0x480.
        // Raw self-relative word 0x80 maps the name slot to the complete Su + NUL span.
        let valid = SwiftMetadataParser(data: Data([
            0x80, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
            0x07, 0x00, 0x01, 0x00,
            0x10, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x53, 0x75, 0x00
        ]), sections: [
            .init(name: "__swift5_builtin", address: 0x400, fileOffset: 0, size: 20),
            .init(name: "__swift5_typeref", address: 0x480, fileOffset: 20, size: 3)
        ])
        let validReport = valid.parseBuiltinTypesReport()
        XCTAssertEqual(validReport.records, [SwiftBuiltinTypeRecord(
            descriptorAddress: 0x400, typeName: "UInt", size: 8,
            alignmentAndFlags: 0x10007, stride: 16, extraInhabitantCount: 2
        )])
        XCTAssertTrue(validReport.diagnostics.isEmpty)
    }
}
