import Foundation
import XCTest
@testable import MacScope

final class SwiftFieldSymbolicTargetBoundsTests: XCTestCase {
    private func word(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }
    private func signed(_ value: Int32) -> [UInt8] { word(UInt32(bitPattern: value)) }
    private func reference(_ control: UInt8, _ displacement: Int32) -> [UInt8] {
        [control] + signed(displacement) + [0]
    }
    private func descriptor() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 0x60)
        bytes.replaceSubrange(0..<4, with: word(17)) // Struct context.
        bytes.replaceSubrange(4..<8, with: signed(0x1c)) // Parent module at +0x20.
        bytes.replaceSubrange(8..<12, with: signed(0x48)) // Leaf name at +0x50.
        bytes.replaceSubrange(0x28..<0x2c, with: signed(0x18)) // Module name at +0x40.
        bytes.replaceSubrange(0x40..<0x45, with: Array("Demo\0".utf8))
        bytes.replaceSubrange(0x50..<0x57, with: Array("Widget\0".utf8))
        return bytes
    }
    private func parser(_ regions: [(UInt64, [UInt8])], rebases: [UInt64: UInt64] = [:],
                        binds: [UInt64: String] = [:]) -> SwiftMetadataParser {
        var bytes = Data()
        var sections: [SwiftMetadataParser.Section] = []
        for (address, payload) in regions {
            sections.append(.init(name: "__field_symbolic", address: address,
                                  fileOffset: UInt64(bytes.count), size: UInt64(payload.count)))
            bytes.append(contentsOf: payload)
        }
        return SwiftMetadataParser(data: bytes, sections: sections,
                                   rebaseTargets: rebases, bindNames: binds)
    }
    private func decode(_ parser: SwiftMetadataParser, at address: UInt64)
        -> (typeName: String?, mangled: String?, reason: String?) {
        var diagnostics: [MetadataParseDiagnostic] = []
        return parser.decodeFieldType(at: address, diagnostics: &diagnostics)
    }
    private func assertRefused(_ value: SwiftMetadataParser, at address: UInt64, reason: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        let result = decode(value, at: address)
        XCTAssertNil(result.typeName, file: file, line: line)
        XCTAssertEqual(result.mangled, "…", file: file, line: line)
        XCTAssertEqual(result.reason, reason, file: file, line: line)
    }

    func testDirectPositiveOverflowCannotNameMappedLowDescriptor() {
        let base = UInt64.max - 15
        let value = parser([(base, reference(1, 32)), (17, descriptor()),
                            (0x400, reference(1, -1008))]) // 0x401 - 1008 == 17.
        assertRefused(value, at: base, reason: "unresolvedDescriptor")
        XCTAssertEqual(decode(value, at: 0x400).typeName, "Widget")
    }
    func testDirectNegativeUnderflowCannotNameMappedHighDescriptor() {
        let bait = UInt64.max - 254
        let value = parser([(0x100, reference(1, -512)), (bait, descriptor()),
                            (UInt64.max - 15, reference(1, -240))])
        assertRefused(value, at: 0x100, reason: "unresolvedDescriptor")
        XCTAssertEqual(decode(value, at: UInt64.max - 15).typeName, "Widget")
    }
    func testIndirectOverflowCannotConsultLowBindOrRebase() {
        let base = UInt64.max - 15
        let regions: [(UInt64, [UInt8])] = [(base, reference(2, 32)), (0x400, descriptor())]
        assertRefused(parser(regions, binds: [17: "_$sSiMn"]), at: base, reason: "needsFixup")
        assertRefused(parser(regions, rebases: [17: 0x400]), at: base, reason: "needsFixup")
    }
    func testIndirectUnderflowCannotConsultHighBindOrRebase() {
        let slot = UInt64.max - 254
        let regions: [(UInt64, [UInt8])] = [(0x100, reference(2, -512)), (0x400, descriptor())]
        assertRefused(parser(regions, binds: [slot: "_$sSiMn"]), at: 0x100, reason: "needsFixup")
        assertRefused(parser(regions, rebases: [slot: 0x400]), at: 0x100, reason: "needsFixup")
    }
    func testLegalDirectHighAndZeroAddressTargetsRemainResolved() {
        let high = parser([(UInt64.max - 15, reference(1, -113)),
                           (UInt64.max - 127, descriptor())])
        XCTAssertEqual(decode(high, at: UInt64.max - 15).typeName, "Widget")
        let low = parser([(0x100, reference(1, -257)), (0, descriptor())])
        XCTAssertEqual(decode(low, at: 0x100).typeName, "Widget")
    }
    func testLegalPositiveDirectTargetAndNonzeroReferenceIndexRemainResolved() {
        let raw = Array("Say".utf8) + [1] + signed(252) + Array("G\0".utf8)
        // Payload address is 0x104; 0x104 + 252 == 0x200, not base + 1.
        let value = parser([(0x100, raw), (0x200, descriptor())])
        XCTAssertEqual(decode(value, at: 0x100).typeName, "[Widget]")
        XCTAssertEqual(decode(value, at: 0x100).mangled, "Say…G")
    }
    func testLegalIndirectRebaseAndExternalBindRemainResolved() {
        let regions: [(UInt64, [UInt8])] = [(0x100, reference(2, 255)), (0x400, descriptor())]
        let rebased = decode(parser(regions, rebases: [0x200: 0x400]), at: 0x100)
        XCTAssertEqual(rebased.typeName, "Widget")
        XCTAssertNil(rebased.reason)
        let bound = decode(parser(regions, binds: [0x200: "_$sSiMn"]), at: 0x100)
        XCTAssertEqual(bound.typeName, "Int")
        XCTAssertNil(bound.reason)
    }
    func testLegalIndirectEndpointSlotsRemainAvailableToFixups() {
        let low = parser([(0x100, reference(2, -257))], binds: [0: "_$sSiMn"])
        XCTAssertEqual(decode(low, at: 0x100).typeName, "Int")
        let high = parser([(UInt64.max - 15, reference(2, 14))],
                          binds: [UInt64.max: "_$sSiMn"])
        XCTAssertEqual(decode(high, at: UInt64.max - 15).typeName, "Int")
    }
    func testUnfixedSlotAndInvalidBoundDescriptorKeepDistinctReasons() {
        let regions: [(UInt64, [UInt8])] = [(0x100, reference(2, 255))]
        assertRefused(parser(regions), at: 0x100, reason: "needsFixup")
        assertRefused(parser(regions, binds: [0x200: "not_a_descriptor"]), at: 0x100,
                      reason: "unresolvedDescriptor")
        assertRefused(parser(regions, rebases: [0x200: 0x400]), at: 0x100,
                      reason: "unresolvedDescriptor")
    }
    func testUnsupportedControlAndIndependentStdlibNeighborStaySeparate() {
        let value = parser([(0x100, reference(3, 255)), (0x400, Array("Si\0".utf8))])
        assertRefused(value, at: 0x100, reason: "unsupportedReference")
        XCTAssertEqual(decode(value, at: 0x400).typeName, "Int")
    }
    func testPartialSymbolicPayloadCannotUseOtherwiseValidExternalBind() {
        let value = parser([(0x100, [2] + signed(255)), (0x400, Array("Si\0".utf8))],
                           binds: [0x200: "_$sSiMn"])
        assertRefused(value, at: 0x100, reason: "unnameableShape")
        XCTAssertEqual(value.readMangledBytes(atVA: 0x100), [2] + signed(255))
        XCTAssertNil(value.readMangledBytes(atVA: 0x100, requiresTerminator: true))
        XCTAssertEqual(decode(value, at: 0x400).typeName, "Int")
    }
    func testReferenceFieldOverflowIsMaskedByStrictMappedFootprint() {
        // A symbolic unit cannot start at max and have a complete mapped payload/terminator.
        // This exercises the earlier public refusal, not the private checked-add branch.
        let value = parser([(UInt64.max, [1]), (0, signed(0) + [0]), (0x400, descriptor())])
        XCTAssertNil(value.readMangledBytes(atVA: UInt64.max, requiresTerminator: true))
        let result = decode(value, at: UInt64.max)
        XCTAssertNil(result.typeName)
        XCTAssertEqual(result.reason, "unnameableShape")
    }
}
