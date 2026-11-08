import Foundation
import XCTest
@testable import MacScope

final class SwiftFieldDescriptorAddressBoundsTests: XCTestCase {
    private struct Fixture {
        let anchor = UInt64.max - 0x1000
        var bytes = Data()
        var sections: [SwiftMetadataParser.Section] = []

        mutating func map(_ address: UInt64, _ payload: [UInt8], name: String = "__const") {
            let offset = UInt64(bytes.count)
            bytes.append(contentsOf: payload)
            sections.append(.init(name: name, address: address, fileOffset: offset, size: UInt64(payload.count)))
        }
        func word(_ value: UInt32) -> [UInt8] {
            (0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
        }
        func relative(_ from: UInt64, _ to: UInt64) -> [UInt8] {
            let delta: Int64 = to >= from ? Int64(to - from) : -Int64(from - to)
            return word(UInt32(bitPattern: Int32(delta)))
        }
        mutating func seed(_ fields: UInt64) {
            let descriptor = anchor + 0x100
            map(anchor, relative(anchor, descriptor), name: "__swift5_types")
            var type = word(17) + word(0)
            type += relative(descriptor + 8, anchor + 0x200)
            type += word(0)
            type += relative(descriptor + 16, fields)
            type += word(0) + word(0)
            map(descriptor, type)
            map(anchor + 0x200, Array("Container\0".utf8))
            map(anchor + 0x300, Array("member\0Si\0".utf8))
        }
        func record(_ address: UInt64) -> [UInt8] {
            // Called only for a full representable 12-byte record.
            word(2) + relative(address + 4, anchor + 0x307)
                + relative(address + 8, anchor + 0x300)
        }
        func header(_ count: UInt32, stride: UInt16 = 12) -> [UInt8] {
            Array(repeating: 0, count: 10)
                + [UInt8(truncatingIfNeeded: stride), UInt8(truncatingIfNeeded: stride >> 8)]
                + word(count)
        }
        func parser() -> SwiftMetadataParser { .init(data: bytes, sections: sections) }
        mutating func lowBait(recordStart: Int = 8, headerSlot: Int? = 2, countSlot: Int? = 4) {
            // Readable low records have real names/types, so the pre-change wrapped path
            // would manufacture a field instead of merely failing a later name read.
            var low = Array(repeating: UInt8(0), count: 128)
            func put(_ offset: Int, _ payload: [UInt8]) {
                low.replaceSubrange(offset..<(offset + payload.count), with: payload)
            }
            if recordStart >= 0 { put(recordStart, word(2)) }
            put(recordStart + 4, word(UInt32(80 - (recordStart + 4))))
            put(recordStart + 8, word(UInt32(64 - (recordStart + 8))))
            if let headerSlot { put(headerSlot, [12, 0]) }
            if let countSlot { put(countSlot, word(1)) }
            put(64, Array("bait\0".utf8))
            put(80, Array("Si\0".utf8))
            map(0, low)
        }
    }

    func testHeaderAddressOverflowCannotBorrowLowMappedHeader() {
        var f = Fixture()
        f.seed(UInt64.max - 7)
        f.lowBait()
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.count, 1)
        XCTAssertEqual(report.types.first?.name, "Container")
        XCTAssertEqual(report.types.first?.fields.count, 0)
    }

    func testCountAddressOverflowRefusesEvenWithMappedLowCount() {
        var f = Fixture()
        let fields = UInt64.max - 11
        f.seed(fields)
        f.map(fields + 10, [12, 0])
        f.lowBait(recordStart: 4, headerSlot: nil, countSlot: 0)
        XCTAssertEqual(f.parser().parseTypesReport().types.first?.fields.count, 0)
    }

    func testFirstRecordAddressOverflowIsSkippedAtOriginalDescriptor() {
        var f = Fixture()
        let fields = UInt64.max - 15
        f.seed(fields)
        f.map(fields, f.header(1))
        f.lowBait(recordStart: 0, headerSlot: nil, countSlot: nil)
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.first?.fields.count, 0)
        XCTAssertTrue(report.diagnostics.contains { $0.address == fields && $0.message.contains("Field record address overflows") })
    }

    func testRecordMemberSlotOverflowCannotBorrowLowPointerSlots() {
        var f = Fixture()
        let fields = UInt64.max - 19
        f.seed(fields)
        f.map(fields, f.header(1) + f.word(2))
        f.lowBait(recordStart: -4, headerSlot: nil, countSlot: nil)
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.first?.fields.count, 0)
        XCTAssertTrue(report.diagnostics.contains { $0.address == UInt64.max - 3 && $0.message.contains("member address overflows") })
    }

    func testExactMaximumBoundaryRecordRemainsACompleteField() {
        var f = Fixture()
        let fields = UInt64.max - 27
        f.seed(fields)
        f.map(fields, f.header(1) + f.record(fields + 16))
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.first?.fields.map(\.name), ["member"])
        XCTAssertEqual(report.types.first?.fields.first?.typeName, "Int")
        XCTAssertTrue(report.diagnostics.isEmpty)
    }

    func testLaterRecordOverflowPreservesPreviouslyRecoveredField() {
        var f = Fixture()
        let fields = UInt64.max - 27
        f.seed(fields)
        f.map(fields, f.header(2) + f.record(fields + 16))
        f.lowBait(recordStart: 0, headerSlot: nil, countSlot: nil)
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.first?.fields.map(\.name), ["member"])
        XCTAssertTrue(report.diagnostics.contains { $0.address == fields && $0.message.contains("1 of 2 skipped") })
    }

    func testUnreadableNameStillSkipsOnlyItsOwnRepresentableRecord() {
        var f = Fixture()
        let fields = UInt64.max - 63
        f.seed(fields)
        f.map(fields, f.header(2) + f.word(2) + f.word(0) + f.word(0) + f.record(fields + 28))
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.first?.fields.map(\.name), ["member"])
        XCTAssertTrue(report.diagnostics.contains { $0.address == fields + 16 && $0.message.contains("Cannot read field record") })
    }

    func testUnexpectedRecordStrideStillRefusesWithoutInventingFields() {
        var f = Fixture()
        let fields = UInt64.max - 63
        f.seed(fields)
        f.map(fields, f.header(1, stride: 16) + f.record(fields + 16))
        XCTAssertEqual(f.parser().parseTypesReport().types.first?.fields.count, 0)
    }
}
