import Foundation
import XCTest
@testable import MacScope

final class SwiftExtensionSymbolicTargetBoundsTests: XCTestCase {
    private func word(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }
    private func signed(_ value: Int32) -> [UInt8] { word(UInt32(bitPattern: value)) }
    private func module(_ name: String) -> [UInt8] {
        word(0) + word(0) + signed(4) + Array(name.utf8) + [0]
    }
    private func parser(_ regions: [(UInt64, [UInt8])], rebases: [UInt64: UInt64] = [:],
                        binds: [UInt64: String] = [:]) -> SwiftMetadataParser {
        var data = Data()
        var sections: [SwiftMetadataParser.Section] = []
        for (address, bytes) in regions {
            sections.append(.init(name: "__extension_bounds", address: address,
                                  fileOffset: UInt64(data.count), size: UInt64(bytes.count)))
            data.append(contentsOf: bytes)
        }
        return SwiftMetadataParser(data: data, sections: sections, rebaseTargets: rebases, bindNames: binds)
    }
    private func extensionBytes(nameDelta: Int32, parentDelta: Int32 = 0) -> [UInt8] {
        word(1) + signed(parentDelta) + signed(nameDelta)
    }

    func testDirectPositiveOverflowCannotNameMappedLowModule() {
        let descriptor = UInt64.max - 255, mangled = UInt64.max - 15
        let value = parser([(descriptor, extensionBytes(nameDelta: 232)),
                            (mangled, [1] + signed(32) + [0]), (17, module("Bait"))])
        XCTAssertNil(value.qualifiedName(atDescriptor: descriptor))
        XCTAssertEqual(value.qualifiedName(atDescriptor: 17), "Bait")
    }
    func testDirectNegativeUnderflowCannotNameMappedHighModule() {
        let descriptor: UInt64 = 0x80, mangled: UInt64 = 0x100
        let bait = UInt64.max - 254
        let value = parser([(descriptor, extensionBytes(nameDelta: 120)),
                            (mangled, [1] + signed(-512) + [0]), (bait, module("Bait"))])
        XCTAssertNil(value.qualifiedName(atDescriptor: descriptor))
        XCTAssertEqual(value.qualifiedName(atDescriptor: bait), "Bait")
    }
    func testIndirectPositiveOverflowCannotUseBoundLowSlot() {
        let descriptor = UInt64.max - 255, mangled = UInt64.max - 15
        let value = parser([(descriptor, extensionBytes(nameDelta: 232)),
                            (mangled, [2] + signed(32) + [0])], binds: [17: "_$s4Demo6TargetMn"])
        XCTAssertNil(value.qualifiedName(atDescriptor: descriptor))
    }
    func testIndirectNegativeUnderflowCannotUseHighRebase() {
        let value = parser([(0x80, extensionBytes(nameDelta: 120)),
                            (0x100, [2] + signed(-512) + [0]), (0x500, module("Target"))],
                           rebases: [UInt64.max - 254: 0x500])
        XCTAssertNil(value.qualifiedName(atDescriptor: 0x80))
        XCTAssertEqual(value.qualifiedName(atDescriptor: 0x500), "Target")
    }
    func testLegalDirectForwardAndBackwardTargetsRemainNamed() {
        let forward = parser([(0x1000, extensionBytes(nameDelta: 248)),
                              (0x1100, [1] + signed(255) + [0]), (0x1200, module("Forward"))])
        XCTAssertEqual(forward.qualifiedName(atDescriptor: 0x1000), "Forward")
        // Use a disjoint backwards target: 0x1101 - 513 == 0xF00.
        let disjoint = parser([(0x1000, extensionBytes(nameDelta: 248)),
                               (0x1100, [1] + signed(-513) + [0]), (0xf00, module("Backward"))])
        XCTAssertEqual(disjoint.qualifiedName(atDescriptor: 0x1000), "Backward")
    }
    func testLegalIndirectRebaseAndBindRemainNamed() {
        let regions: [(UInt64, [UInt8])] = [(0x1000, extensionBytes(nameDelta: 248)),
                                           (0x1100, [2] + signed(255) + [0]),
                                           (0x1300, module("Rebased"))]
        XCTAssertEqual(parser(regions, rebases: [0x1200: 0x1300])
            .qualifiedName(atDescriptor: 0x1000), "Rebased")
        XCTAssertEqual(parser(regions, binds: [0x1200: "_$s4Demo6TargetMn"])
            .qualifiedName(atDescriptor: 0x1000), "Demo.Target")
    }
    func testLegalNearMaximumBackwardTargetRemainsNamed() {
        let descriptor = UInt64.max - 255, mangled = UInt64.max - 15, target = UInt64.max - 127
        let value = parser([(descriptor, extensionBytes(nameDelta: 232)),
                            (mangled, [1] + signed(-113) + [0]), (target, module("High"))])
        XCTAssertEqual(value.qualifiedName(atDescriptor: descriptor), "High")
    }
    func testOverflowingExtensionNameFieldCannotUseLowStdlibBait() {
        let descriptor = UInt64.max - 3
        let value = parser([(descriptor, word(1)), (4, signed(12)), (16, [0x53, 0x69, 0])])
        XCTAssertNil(value.qualifiedName(atDescriptor: descriptor))
    }
    func testPartialMangledPrefixRemainsDiagnosticOnly() {
        let value = parser([(0x1000, extensionBytes(nameDelta: 248)), (0x1100, [0x53, 0x69])])
        XCTAssertEqual(value.readMangledBytes(atVA: 0x1100), [0x53, 0x69])
        XCTAssertNil(value.readMangledBytes(atVA: 0x1100, requiresTerminator: true))
        XCTAssertNil(value.qualifiedName(atDescriptor: 0x1000))
    }
    func testTerminatedStdlibAndGenuineMarkerFallbackRemainAvailable() {
        let stdlib = parser([(0x1000, extensionBytes(nameDelta: 248)), (0x1100, [0x53, 0x69, 0])])
        XCTAssertEqual(stdlib.qualifiedName(atDescriptor: 0x1000), "Swift.Int")
        let marker = parser([(0x1000, extensionBytes(nameDelta: 248, parentDelta: 508)),
                             (0x1100, [0x5a, 0x5a, 0]), (0x1200, module("Demo"))])
        XCTAssertEqual(marker.qualifiedName(atDescriptor: 0x1000), "Demo.<ext:ZZ>")
    }
    func testRecursionDepthLimitIsPreserved() {
        let value = parser([(0x1000, extensionBytes(nameDelta: 248)),
                            (0x1100, [1] + signed(255) + [0]), (0x1200, module("Target"))])
        XCTAssertNil(value.qualifiedName(atDescriptor: 0x1000, depth: 4))
        XCTAssertEqual(value.qualifiedName(atDescriptor: 0x1000, depth: 3), "Target")
    }
}
