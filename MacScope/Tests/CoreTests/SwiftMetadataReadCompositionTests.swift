import Foundation
import XCTest
@testable import MacScope

final class SwiftMetadataReadCompositionTests: XCTestCase {
    private func section(_ address: UInt64, _ offset: UInt64, _ size: UInt64) -> SwiftMetadataParser.Section {
        .init(name: "__composition", address: address, fileOffset: offset, size: size)
    }

    private func decode(_ parser: SwiftMetadataParser, slot: UInt64)
        -> (typeName: String?, mangled: String?, reason: String?) {
        var diagnostics: [MetadataParseDiagnostic] = []
        return parser.decodeFieldType(at: parser.resolveRelativePointer(at: slot), diagnostics: &diagnostics)
    }

    func testCompleteRelativeSlotRequiresSeparateStrictTargetTermination() {
        let bytes: [UInt8] = [0x10, 0, 0, 0, 0x53, 0x69, 0]
        let complete = SwiftMetadataParser(data: Data(bytes), sections: [
            section(0x1000, 0, 4), section(0x1010, 4, 3)
        ])
        XCTAssertEqual(complete.readU16(atVA: 0x1000), 0x10)
        XCTAssertEqual(complete.readU32(atVA: 0x1000), 0x10)
        XCTAssertEqual(decode(complete, slot: 0x1000).typeName, "Int")
        let partial = SwiftMetadataParser(data: Data(bytes), sections: [
            section(0x1000, 0, 4), section(0x1010, 4, 2)
        ])
        XCTAssertEqual(partial.resolveRelativePointer(at: 0x1000), 0x1010)
        let unresolved = decode(partial, slot: 0x1000)
        XCTAssertNil(unresolved.typeName)
        XCTAssertEqual(unresolved.mangled, "Si")
        XCTAssertEqual(unresolved.reason, "unnameableShape")
        XCTAssertEqual(partial.readMangledBytes(atVA: 0x1010), [0x53, 0x69])
        XCTAssertNil(partial.readCString(atVA: 0x1010))
    }

    func testReadableShortScalarCannotPromoteAnIncompleteRelativeSlot() {
        let parser = SwiftMetadataParser(data: Data([0x10, 0, 0, 0, 0x53, 0x69, 0]), sections: [
            section(0x1000, 0, 2), section(0x1010, 4, 3)
        ])
        XCTAssertEqual(parser.readU16(atVA: 0x1000), 0x10)
        XCTAssertNil(parser.readU32(atVA: 0x1000))
        XCTAssertNil(parser.resolveRelativePointer(at: 0x1000))
        XCTAssertNil(decode(parser, slot: 0x1000).typeName)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertEqual(parser.decodeFieldType(at: 0x1010, diagnostics: &diagnostics).typeName, "Int")
    }

    func testIndirectRebaseCannotRescueSplitRelativeSlot() {
        let parser = SwiftMetadataParser(data: Data([0x11, 0, 0, 0]), sections: [
            section(0x1000, 0, 2), section(0x1002, 2, 2)
        ], rebaseTargets: [0x1010: 0x2000])
        XCTAssertEqual(parser.readU16(atVA: 0x1000), 0x11)
        XCTAssertEqual(parser.readU16(atVA: 0x1002), 0)
        XCTAssertNil(parser.readI32(atVA: 0x1000))
        XCTAssertNil(parser.resolveRelativeIndirectablePointer(at: 0x1000))
        let complete = SwiftMetadataParser(data: Data([0x11, 0, 0, 0]), sections: [
            section(0x1000, 0, 4)
        ], rebaseTargets: [0x1010: 0x2000])
        XCTAssertEqual(complete.resolveRelativeIndirectablePointer(at: 0x1000), 0x2000)
    }

    func testTwoIndividuallyProvedWordsDoNotProveOneU64() {
        let bytes: [UInt8] = [0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90]
        let split = SwiftMetadataParser(data: Data(bytes), sections: [
            section(0x1000, 0, 4), section(0x1004, 4, 4)
        ])
        XCTAssertEqual(split.readU32(atVA: 0x1000), 0x12345678)
        XCTAssertEqual(split.readU32(atVA: 0x1004), 0x90abcdef)
        XCTAssertNil(split.readU64(atVA: 0x1000))
        let whole = SwiftMetadataParser(data: Data(bytes), sections: [section(0x1000, 0, 8)])
        XCTAssertEqual(whole.readU64(atVA: 0x1000), 0x90abcdef12345678)
    }

    func testPartialWordOverlapDoesNotPoisonDisjointStringButBlocksWiderRead() {
        let owner = section(0x1000, 0, 12)
        let overlap = section(0x1006, 12, 1)
        let bytes: [UInt8] = [0x10, 0, 0, 0, 1, 2, 3, 4, 0x53, 0x69, 0, 0, 0xff]
        for sections in [[owner, overlap], [overlap, owner]] {
            let parser = SwiftMetadataParser(data: Data(bytes), sections: sections)
            XCTAssertEqual(parser.readU32(atVA: 0x1000), 0x10)
            XCTAssertNil(parser.readU64(atVA: 0x1000))
            XCTAssertNil(parser.readU32(atVA: 0x1004))
            var diagnostics: [MetadataParseDiagnostic] = []
            XCTAssertEqual(parser.decodeFieldType(at: 0x1008, diagnostics: &diagnostics).typeName, "Int")
        }
    }

    func testCheckedNegativeRelativeTargetAtMaximumSlotStillDecodesStrictType() {
        let slot = UInt64.max - 3
        let target = slot - 12
        let parser = SwiftMetadataParser(data: Data([0xf4, 0xff, 0xff, 0xff, 0x53, 0x69, 0]), sections: [
            section(slot, 0, 4), section(target, 4, 3)
        ])
        XCTAssertEqual(parser.readI32(atVA: slot), -12)
        XCTAssertEqual(parser.resolveRelativePointer(at: slot), target)
        XCTAssertEqual(decode(parser, slot: slot).typeName, "Int")
    }

    func testCompleteMaximumSlotCannotWrapIntoOtherwiseValidType() {
        let slot = UInt64.max - 3
        let parser = SwiftMetadataParser(data: Data([4, 0, 0, 0, 0x53, 0x69, 0]), sections: [
            section(slot, 0, 4), section(0, 4, 3)
        ])
        XCTAssertEqual(parser.readU32(atVA: slot), 4)
        XCTAssertNil(parser.resolveRelativePointer(at: slot))
        XCTAssertNil(decode(parser, slot: slot).typeName)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertEqual(parser.decodeFieldType(at: 0, diagnostics: &diagnostics).typeName, "Int")
    }

    func testSymbolicPayloadAndIntegerReaderShareFootprintWithoutSharingTermination() {
        let raw: [UInt8] = [0x18, 0, 0, 0, 0, 0, 0, 0, 0]
        let parser = SwiftMetadataParser(data: Data(raw + [0]), sections: [section(0x1000, 0, 9)])
        XCTAssertEqual(parser.readU64(atVA: 0x1001), 0)
        XCTAssertEqual(parser.readMangledBytes(atVA: 0x1000), raw)
        XCTAssertNil(parser.readMangledBytes(atVA: 0x1000, requiresTerminator: true))
        var diagnostics: [MetadataParseDiagnostic] = []
        let decoded = parser.decodeFieldType(at: 0x1000, diagnostics: &diagnostics)
        XCTAssertNil(decoded.typeName)
        XCTAssertEqual(decoded.reason, "unnameableShape")
        let terminated = SwiftMetadataParser(data: Data(raw + [0]), sections: [section(0x1000, 0, 10)])
        XCTAssertEqual(terminated.readMangledBytes(atVA: 0x1000, requiresTerminator: true), raw)
    }
}
