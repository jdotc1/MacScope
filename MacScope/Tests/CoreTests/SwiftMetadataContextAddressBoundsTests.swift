import Foundation
import XCTest
@testable import MacScope

final class SwiftMetadataContextAddressBoundsTests: XCTestCase {
    private struct Fixture {
        var bytes: [UInt8] = []
        var sections: [SwiftMetadataParser.Section] = []
        mutating func add(_ address: UInt64, _ content: [UInt8], name: String = "__context") {
            sections.append(.init(name: name, address: address, fileOffset: UInt64(bytes.count), size: UInt64(content.count)))
            bytes.append(contentsOf: content)
        }
        func parser(rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:]) -> SwiftMetadataParser {
            SwiftMetadataParser(data: Data(bytes), sections: sections, rebaseTargets: rebases, bindNames: binds)
        }
    }
    private func word(_ value: Int32) -> [UInt8] {
        let bits = UInt32(bitPattern: value)
        return (0..<4).map { UInt8(truncatingIfNeeded: bits >> ($0 * 8)) }
    }

    func testDescriptorNameCannotUseWrappedFixedFieldWithReadableLowBait() {
        var f = Fixture()
        f.add(4, word(12))
        f.add(16, Array("Bait\0".utf8))
        XCTAssertEqual(f.parser().readCString(atVA: 16), "Bait")
        XCTAssertNil(f.parser().descriptorName(at: UInt64.max - 3))
    }

    func testDescriptorNameAllowsExactMaximumSlotAndNegativeTarget() {
        var f = Fixture()
        f.add(UInt64.max - 3, word(-28))
        f.add(UInt64.max - 31, Array("Edge\0".utf8))
        XCTAssertEqual(f.parser().descriptorName(at: UInt64.max - 11), "Edge")
    }

    func testDescriptorNameAllowsLowZeroBaseAndPositiveTarget() {
        var f = Fixture()
        f.add(8, word(8))
        f.add(16, Array("Low\0".utf8))
        XCTAssertEqual(f.parser().descriptorName(at: 0), "Low")
    }

    func testAnonymousParentFieldCannotWrapToLowBoundSlot() {
        var f = Fixture()
        f.add(UInt64.max - 3, word(2)) // anonymous context skips its own name
        f.add(0, word(9)) // wrapped parent field would select indirect slot 8
        XCTAssertNil(f.parser(binds: [8: "_$s4BaitMm"]).qualifiedName(atDescriptor: UInt64.max - 3))
    }

    func testParentRelativeOverflowCannotUseLowBindOrRebase() {
        var f = Fixture()
        f.add(UInt64.max - 7, word(2))
        f.add(UInt64.max - 3, word(9)) // displacement 8 would wrap to 4
        f.add(0x100, word(0))
        f.add(0x108, word(8))
        f.add(0x110, Array("Bait\0".utf8))
        XCTAssertEqual(f.parser().qualifiedName(atDescriptor: 0x100), "Bait")
        XCTAssertNil(f.parser(binds: [4: "_$s4BaitMm"]).qualifiedName(atDescriptor: UInt64.max - 7))
        XCTAssertNil(f.parser(rebases: [4: 0x100]).qualifiedName(atDescriptor: UInt64.max - 7))
    }

    func testParentRelativeUnderflowCannotUseHighBindOrRebase() {
        var f = Fixture()
        f.add(0, word(2))
        f.add(4, word(-7)) // tagged displacement -8 would wrap to max-3
        f.add(0x100, word(0))
        f.add(0x108, word(8))
        f.add(0x110, Array("Bait\0".utf8))
        XCTAssertNil(f.parser(binds: [UInt64.max - 3: "_$s4BaitMm"]).qualifiedName(atDescriptor: 0))
        XCTAssertNil(f.parser(rebases: [UInt64.max - 3: 0x100]).qualifiedName(atDescriptor: 0))
    }

    func testLegalParentDirectRebaseAndExternalBindStillName() {
        var f = Fixture()
        f.add(0x100, word(0))
        f.add(0x108, word(8))
        f.add(0x110, Array("Root\0".utf8))
        f.add(0x200, word(2))
        f.add(0x204, word(-260)) // direct parent 0x100
        f.add(0x300, word(2))
        f.add(0x304, word(13)) // indirect slot 0x310
        XCTAssertEqual(f.parser().qualifiedName(atDescriptor: 0x200), "Root")
        XCTAssertEqual(f.parser(rebases: [0x310: 0x100]).qualifiedName(atDescriptor: 0x300), "Root")
        XCTAssertEqual(f.parser(binds: [0x310: "_$s4RootMm"]).qualifiedName(atDescriptor: 0x300), "Root")
    }

    func testParentDirectUnderflowAndCycleRemainUnnamed() {
        var f = Fixture()
        f.add(0, word(2))
        f.add(4, word(-8))
        f.add(0x100, word(2))
        f.add(0x104, word(-4))
        XCTAssertNil(f.parser().qualifiedName(atDescriptor: 0))
        XCTAssertNil(f.parser().qualifiedName(atDescriptor: 0x100))
    }

    func testTypeReportRejectsWrappedNameButRetainsIndependentValidType() {
        var f = Fixture()
        f.add(UInt64.max - 63, word(60) + word(-32), name: "__swift5_types")
        f.add(UInt64.max - 3, word(17))
        f.add(4, word(12))
        f.add(16, Array("Bait\0".utf8))
        // Second entry at max-59 points backward to max-91.
        f.add(UInt64.max - 91, word(17))
        f.add(UInt64.max - 83, word(-20))
        f.add(UInt64.max - 103, Array("Good\0".utf8))
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.map(\.name), ["Good"])
        XCTAssertTrue(report.diagnostics.contains { $0.address == UInt64.max - 3 })
    }

    func testTypeReportKeepsKnownNameButDoesNotReadWrappedFields() {
        var f = Fixture()
        f.add(UInt64.max - 63, word(48), name: "__swift5_types")
        f.add(UInt64.max - 15, word(17))
        f.add(UInt64.max - 7, word(-24))
        f.add(UInt64.max - 31, Array("Type\0".utf8))
        // The old +16 field slot wrapped to 0 and would resolve this otherwise valid field list.
        f.add(0, word(0x100))
        var fields = [UInt8](repeating: 0, count: 28)
        fields[10] = 12; fields[12] = 1
        fields.replaceSubrange(24..<28, with: word(8))
        f.add(0x100, fields)
        f.add(0x120, Array("bait\0".utf8))
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.map(\.name), ["Type"])
        XCTAssertTrue(report.types.first?.fields.isEmpty == true)
    }

    func testClassReportKeepsNameWithoutWrappedSuperclassTypeProof() {
        var f = Fixture()
        f.add(UInt64.max - 63, word(44), name: "__swift5_types")
        f.add(UInt64.max - 19, word(16))
        f.add(UInt64.max - 11, word(-20))
        f.add(UInt64.max - 31, Array("Class\0".utf8))
        f.add(UInt64.max - 3, word(0)) // legitimate null Fields
        f.add(0, word(16)) // overflowing superclass field bait
        f.add(16, Array("Si\0".utf8))
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.map(\.name), ["Class"])
        XCTAssertNil(report.types.first?.superclass)
        XCTAssertNil(report.types.first?.superclassUnresolvedReason)
    }

    func testUnknownKindKeepsLabelWithoutDemandingUnknownLayoutFields() {
        var f = Fixture()
        f.add(UInt64.max - 63, word(48), name: "__swift5_types")
        f.add(UInt64.max - 15, word(31))
        f.add(UInt64.max - 7, word(-24))
        f.add(UInt64.max - 31, Array("Future\0".utf8))
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.map(\.name), ["Future"])
        XCTAssertEqual(report.types.first?.kind, .unknown)
        XCTAssertTrue(report.types.first?.fields.isEmpty == true)
        XCTAssertFalse(report.diagnostics.isEmpty)
    }

    func testAnonymousPartialFactSurvivesUnreadableNextParent() {
        var f = Fixture()
        f.add(0x80, word(0x80), name: "__swift5_types")
        f.add(0x100, word(17))
        f.add(0x104, word(0xfc)) // anonymous parent at 0x200
        f.add(0x108, word(0x18))
        f.add(0x120, Array("Local\0".utf8))
        f.add(0x200, word(2)) // no next parent slot
        let report = f.parser().parseTypesReport()
        XCTAssertEqual(report.types.map(\.name), ["Local"])
        XCTAssertEqual(report.types.first?.isPrivateOrLocal, true)
        XCTAssertEqual(report.types.first?.isImportedCType, false)
        XCTAssertNil(report.types.first?.qualifiedName)
    }

    func testTagOnlyParentUsesSameSlotFixupWithoutNullConflation() {
        var f = Fixture()
        f.add(0x100, word(2))
        f.add(0x104, word(1))
        XCTAssertEqual(f.parser(binds: [0x104: "_$s4RootMm"]).qualifiedName(atDescriptor: 0x100), "Root")
    }

}
