import Foundation
import XCTest
@testable import MacScope

final class SwiftOutcomeLegacyNominalContextTests: XCTestCase {
    private typealias Image = SwiftOutcomeLegacyAdmittedImage
    private let declined: SwiftOutcomeJSON = .object([
        "status": .string("declined"), "reason": .string("method_context_not_admitted")])

    // Hand-authored little-endian metadata, not donor/program-generated output:
    // types[0] 0x1000 + 0x20 = descriptor 0x1020;
    // parent field 0x1024 + 0x1c = module 0x1040;
    // type-name field 0x1028 + 0x38 = Point at 0x1060;
    // module-name field 0x1048 + 0x20 = Demo at 0x1068.
    // Admission/record oracle: swift_nominal_context.py:36–64.
    private func rawBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 0x180)
        put([0x20, 0, 0, 0], at: 0, into: &bytes)
        put([0x51, 0, 0, 0, 0x1c, 0, 0, 0, 0x38, 0, 0, 0], at: 0x20, into: &bytes)
        put([0x40, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0], at: 0x40, into: &bytes)
        put([0x50, 0x6f, 0x69, 0x6e, 0x74, 0], at: 0x60, into: &bytes)
        put([0x44, 0x65, 0x6d, 0x6f, 0], at: 0x68, into: &bytes)
        return bytes
    }
    private func put(_ values: [UInt8], at offset: Int, into bytes: inout [UInt8]) {
        bytes.replaceSubrange(offset..<(offset + values.count), with: values)
    }
    private func image(_ bytes: [UInt8], typeAddress: UInt64 = 0x1000,
                       typeSize: UInt64 = 4, typeName: String = "__swift5_types",
                       typeSegment: String = "__TEXT", metadataSize: UInt64 = 0x160,
                       metadataFlags: UInt32 = 0, sliceSize: UInt64 = 0x180,
                       metadataSections: [Image.Section]? = nil) -> Image {
        let types = Image.Section(address: typeAddress, size: typeSize, fileOffset: typeAddress - 0x1000,
                                  executable: false, flags: 0, segment: typeSegment, name: typeName)
        let metadata = metadataSections ?? [Image.Section(address: 0x1020, size: metadataSize,
            fileOffset: 0x20, executable: false, flags: metadataFlags, segment: "__TEXT", name: "__const")]
        return Image(data: Data(bytes), sliceSHA256: "literal-slice", containerSHA256: "literal-container",
                     architecture: "arm64", cpuSubtype: 0, uuid: nil, sliceOffset: 0,
                     sliceSize: sliceSize, preferredBase: 0x1000, sections: [types] + metadata, functions: [])
    }
    private func declaration(typeName: String? = "Point", module: String = "Demo") -> SwiftThrowingDeclaration {
        SwiftThrowingDeclaration(symbol: "_$s4Demo5PointV3sumyS2iKF", module: module,
            callableKind: "struct_instance_method", typeName: typeName, functionName: "sum",
            parameterTypes: ["Swift.Int"], resultType: "Swift.Int")
    }
    private var admitted: SwiftOutcomeJSON {
        .object(["status": .string("admitted_struct_context"),
                 "descriptor_pc": .string("0x1020"), "descriptor_flags": .string("0x51"),
                 "parent_pc": .string("0x1040"), "parent_flags": .string("0x40"),
                 "type_name": .string("Point"), "module": .string("Demo"),
                 "raw_descriptor": .string("51000000" + "1c000000" + "38000000" + "00000000" + "00000000" + "00000000" + "00000000"),
                 "raw_parent": .string("400000000000000020000000")])
    }

    func testNC01UniqueDirectRecordAndExactChargeCount() throws {
        var charges = 0
        let result = try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes()), declaration: declaration()) { charges += 1 }
        XCTAssertEqual(result, admitted)
        // 8 charged words/relatives + 6 Point bytes + 5 Demo bytes + extent = 20.
        XCTAssertEqual(charges, 20)
    }
    func testNC02ZeroModuleFlagsAlsoAdmitted() throws {
        var bytes = rawBytes(); bytes[0x40] = 0
        var expected = admitted
        expected["parent_flags"] = .string("0x0")
        expected["raw_parent"] = .string("000000000000000020000000")
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()), expected)
    }
    func testNC03SectionGuardsDoNotCharge() throws {
        // swift_nominal_context.py:10–12; zero entries cannot produce a match.
        let cases = [image(rawBytes(), typeName: "__const"), image(rawBytes(), typeSegment: "__DATA"),
                     image(rawBytes(), typeSize: 3), image(rawBytes(), typeSize: 5), image(rawBytes(), typeSize: 0)]
        var charges = 0
        for fixture in cases {
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: fixture, declaration: declaration()) { charges += 1 }, declined)
        }
        for limit in [-1, 0] {
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes()), declaration: declaration(), maxEntries: limit) { charges += 1 }, declined)
        }
        XCTAssertEqual(charges, 0)
    }
    func testNC04ExactEntryLimitAndDuplicateRefusal() throws {
        // Duplicate entries count twice, even when they point to the same descriptor.
        var bytes = rawBytes(); put([0x1c, 0, 0, 0], at: 4, into: &bytes)
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes, typeSize: 8), declaration: declaration(), maxEntries: 1) { charges += 1 }, declined)
        XCTAssertEqual(charges, 0)
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes, typeSize: 8), declaration: declaration(), maxEntries: 2) { charges += 1 }, declined)
        XCTAssertEqual(charges, 40)
    }
    func testNC05IndirectEntryRefusesBeforeAndAfterMatch() throws {
        // Low-bit tags refuse globally, not just when the name matches (source:38–40).
        var bytes = rawBytes(); bytes[0] = 0x21
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()) { charges += 1 }, declined)
        XCTAssertEqual(charges, 1)
        bytes = rawBytes(); bytes[4] = 1; charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes, typeSize: 8), declaration: declaration()) { charges += 1 }, declined)
        XCTAssertEqual(charges, 21)
    }
    func testNC06StructFlagVersionAndGenericRefusals() throws {
        // Exact 0x51 required after owner/module equality (source:53–55).
        let flagCases: [[UInt8]] = [[0xd1, 0, 0, 0], [0x51, 1, 0, 0], [0x11, 0, 0, 0], [0x51, 0, 1, 0]]
        for flags in flagCases {
            var bytes = rawBytes(); put(flags, at: 0x20, into: &bytes)
            var charges = 0
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()) { charges += 1 }, declined)
            XCTAssertEqual(charges, 18)
        }
    }
    func testNC07SpecialModuleAndNonRootParentRefused() throws {
        let flagCases: [UInt8] = [1, 0x41, 0x80]
        for flags in flagCases {
            var bytes = rawBytes(); bytes[0x40] = flags
            var charges = 0
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()) { charges += 1 }, declined)
            XCTAssertEqual(charges, 18)
        }
        var bytes = rawBytes(); bytes[0x44] = 4
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()) { charges += 1 }, declined)
        XCTAssertEqual(charges, 19)
    }
    func testNC08WrongOwnerAndModuleAreNotMatches() throws {
        for wanted in [declaration(typeName: "Other"), declaration(typeName: nil), declaration(module: "Else")] {
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes()), declaration: wanted), declined)
        }
        var bytes = rawBytes(); put([0x7c, 0, 0, 0], at: 4, into: &bytes)
        bytes[0x80] = 0x50 // A non-struct kind 16 is skipped without name reads.
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes, typeSize: 8), declaration: declaration()) { charges += 1 }, admitted)
        XCTAssertEqual(charges, 23)
    }
    func testNC09SignedNegativeEntryAndParentPointers() throws {
        // 0x1080 + Int32(0xffffffa0) = 0x1020 (source:16–24).
        var bytes = rawBytes(); put([0xa0, 0xff, 0xff, 0xff], at: 0x80, into: &bytes)
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes, typeAddress: 0x1080, metadataSize: 0x60), declaration: declaration()), admitted)
        bytes = rawBytes(); put([UInt8](repeating: 0, count: 0x3c), at: 0x20, into: &bytes)
        put([0x40, 0, 0, 0], at: 0, into: &bytes)
        put([0x40, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0], at: 0x20, into: &bytes)
        put([0x51, 0, 0, 0, 0xdc, 0xff, 0xff, 0xff, 0x18, 0, 0, 0], at: 0x40, into: &bytes)
        var expected = admitted
        expected["descriptor_pc"] = .string("0x1040"); expected["parent_pc"] = .string("0x1020")
        expected["raw_descriptor"] = .string("51000000" + "dcffffff" + "18000000" + "00000000" + "00000000" + "00000000" + "00000000")
        expected["raw_parent"] = .string("400000000000000040000000")
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()), expected)
    }
    func testNC10NullAndUnmappedRelativePointersDecline() throws {
        for offset in [0, 0x28, 0x24, 0x48] {
            var bytes = rawBytes(); put([0, 0, 0, 0], at: offset, into: &bytes)
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()), declined)
        }
        var bytes = rawBytes(); put([4, 0, 0, 0], at: 0, into: &bytes)
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()), declined)
    }
    func testNC11RelativeAddressOverflowAndUnderflowDecline() throws {
        // These isolated raw entries use explicit near-limit mapping coordinates.
        let cases: [(UInt64, [UInt8])] = [(UInt64.max - 3, [4, 0, 0, 0]), (0, [0xfc, 0xff, 0xff, 0xff])]
        for (address, bytes) in cases {
            let fixture = Image(data: Data(bytes), sliceSHA256: "literal", containerSHA256: "literal",
                architecture: "arm64", cpuSubtype: 0, uuid: nil, sliceOffset: 0, sliceSize: 4, preferredBase: 0,
                sections: [Image.Section(address: address, size: 4, fileOffset: 0, executable: false,
                    flags: 0, segment: "__TEXT", name: "__swift5_types")], functions: [])
            var charges = 0
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: fixture, declaration: declaration()) { charges += 1 }, declined)
            XCTAssertEqual(charges, 2)
        }
    }
    func testNC12ASCIIAndIdentifierLengthBound() throws {
        // Source:25–33 permits exactly 128 ASCII bytes followed by NUL.
        var bytes = rawBytes(); bytes[0x60] = 0x80
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration()) { charges += 1 }, declined)
        XCTAssertEqual(charges, 10) // Decode only after the terminator, not at byte 0x80.
        bytes = rawBytes(); put([0xb8, 0, 0, 0], at: 0x48, into: &bytes)
        put([0x44, 0x65, 0x6d, 0x6f, 0], at: 0x100, into: &bytes)
        put([UInt8](repeating: 0x61, count: 128) + [0], at: 0x60, into: &bytes)
        let result = try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration(typeName: String(repeating: "a", count: 128)))
        XCTAssertEqual(result["status"], .string("admitted_struct_context"))
        XCTAssertEqual(result["type_name"], .string(String(repeating: "a", count: 128)))
        bytes[0xe0] = 0x61; charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(bytes), declaration: declaration(typeName: String(repeating: "a", count: 129))) { charges += 1 }, declined)
        XCTAssertEqual(charges, 133)
    }
    func testNC13MetadataExtentSliceAndNonFileBackedBounds() throws {
        // Descriptor words fit but the required complete 28-byte record does not.
        let sections = [Image.Section(address: 0x1020, size: 12, fileOffset: 0x20, executable: false, flags: 0, segment: "__TEXT", name: "__const"),
                        Image.Section(address: 0x1040, size: 0x140, fileOffset: 0x40, executable: false, flags: 0, segment: "__TEXT", name: "__const")]
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes(), metadataSections: sections), declaration: declaration()) { charges += 1 }, declined)
        XCTAssertEqual(charges, 20)
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes(), sliceSize: 0x6c), declaration: declaration()), declined)
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(Array(rawBytes().prefix(0x6c))), declaration: declaration()), declined)
        let flagCases: [UInt32] = [1, 12, 18]
        for flags in flagCases {
            XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes(), metadataFlags: flags), declaration: declaration()), declined)
        }
    }
    func testNC14CallerChargeRefusalsEscapeUnchanged() throws {
        // Validation's _Refusal is not in the donor's caught tuple (source:65;
        // swift_outcome_witness_validation.py:11–13,29–32,119–123).
        enum BudgetRefusal: Error, Equatable { case exhausted }
        for limit in [0, 3, 9, 18, 19] {
            var completed = 0
            XCTAssertThrowsError(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes()), declaration: declaration()) {
                guard completed < limit else { throw BudgetRefusal.exhausted }
                completed += 1
            }) { error in XCTAssertEqual(error as? BudgetRefusal, .exhausted) }
            XCTAssertEqual(completed, limit)
        }
        // Even an error sharing the image reader's type is a caller error here.
        let callerError = SwiftOutcomeError(code: "unmapped_address")
        XCTAssertThrowsError(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes()), declaration: declaration()) { throw callerError }) {
            XCTAssertEqual($0 as? SwiftOutcomeError, callerError)
        }
    }
    func testNC15RawParentExtentIsCheckedWithoutExtraCharge() throws {
        // Every scalar parent read fits, but no section contains its full raw
        // 12-byte evidence record (source:61–62). Evidence reads remain uncharged.
        let sections = [
            Image.Section(address: 0x1020, size: 28, fileOffset: 0x20, executable: false, flags: 0, segment: "__TEXT", name: "__const"),
            Image.Section(address: 0x1040, size: 4, fileOffset: 0x40, executable: false, flags: 0, segment: "__TEXT", name: "__const"),
            Image.Section(address: 0x1044, size: 4, fileOffset: 0x44, executable: false, flags: 0, segment: "__TEXT", name: "__const"),
            Image.Section(address: 0x1048, size: 4, fileOffset: 0x48, executable: false, flags: 0, segment: "__TEXT", name: "__const"),
            Image.Section(address: 0x1060, size: 0x120, fileOffset: 0x60, executable: false, flags: 0, segment: "__TEXT", name: "__const")]
        var charges = 0
        XCTAssertEqual(try admitSwiftOutcomeLegacyStructContext(image: image(rawBytes(), metadataSections: sections), declaration: declaration()) { charges += 1 }, declined)
        XCTAssertEqual(charges, 20)
    }
}
