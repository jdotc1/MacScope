// Public methodLinks only; no parser initialization, loader, compiler fixture or real binary.
import Foundation
import XCTest
@testable import MacScope

final class SwiftMetadataFunctionRelativePointerBoundsTests: XCTestCase {
    private struct Case {
        let label: String
        let field: UInt64
        let raw: UInt32
        // Explicit mapped decoy for rejected wrap cases, actual target for accepted cases.
        let mappedTarget: UInt64
        let accepted: Bool
    }

    func testDirectTopLevelRelativePointers() {
        let cases: [Case] = [
            .init(label: "positive", field: 0x1000, raw: 0x1000, mappedTarget: 0x2000, accepted: true),
            .init(label: "negative", field: 0x2000, raw: 0xfffff000, mappedTarget: 0x1000, accepted: true),
            .init(label: "signed boundary crossing", field: 0x7ffffffffffffff0, raw: 0x1010, mappedTarget: 0x8000000000001000, accepted: true),
            .init(label: "Int32 min valid", field: 0x80001000, raw: 0x80000000, mappedTarget: 0x1000, accepted: true),
            .init(label: "Int32 min underflow", field: 0x10, raw: 0x80000000, mappedTarget: 0xffffffff80000010, accepted: false),
            .init(label: "negative underflow", field: 0x10, raw: 0xffffff00, mappedTarget: 0xffffffffffffff10, accepted: false),
            .init(label: "positive overflow", field: 0xffffffffffffff00, raw: 0x1100, mappedTarget: 0x1000, accepted: false),
            .init(label: "raw zero", field: 0x1000, raw: 0, mappedTarget: 0x2000, accepted: false),
            .init(label: "odd direct offset allowed", field: 0x1001, raw: 0xfff, mappedTarget: 0x2000, accepted: true)
        ]
        for c in cases {
            var b = Builder()
            b.section("__swift5_types", c.field, 4, 0)
            b.u32(c.raw, 0)
            // Class descriptor with a zero-count vtable: presence of the owner key is observable.
            b.section("descriptor", c.mappedTarget, 0x80, 0x20)
            b.u32(0x80000010, 0x20)
            b.u32(0x68, 0x28) // name field + 0x68 => descriptor + 0x70
            b.bytes[0x90] = 0x43; b.bytes[0x91] = 0
            let links = b.links()
            XCTAssertEqual(links.types[c.mappedTarget] != nil, c.accepted, c.label)
            XCTAssertEqual(Set(links.types.keys), c.accepted ? Set([c.mappedTarget]) : Set<UInt64>(), c.label)
            if c.accepted { XCTAssertEqual(links.types[c.mappedTarget], [], c.label) }
            XCTAssertTrue(links.conformances.isEmpty, c.label)
        }
    }

    func testIndirectableProtocolRelativePointers() {
        let cases: [Case] = [
            .init(label: "positive even", field: 0x1000, raw: 0x1000, mappedTarget: 0x2000, accepted: true),
            .init(label: "negative even", field: 0x2000, raw: 0xfffff000, mappedTarget: 0x1000, accepted: true),
            .init(label: "Int32 min valid", field: 0x80001000, raw: 0x80000000, mappedTarget: 0x1000, accepted: true),
            .init(label: "Int32 min underflow", field: 0x10, raw: 0x80000000, mappedTarget: 0xffffffff80000010, accepted: false),
            .init(label: "negative underflow", field: 0x10, raw: 0xffffff00, mappedTarget: 0xffffffffffffff10, accepted: false),
            .init(label: "positive overflow", field: 0xffffffffffffff00, raw: 0x1100, mappedTarget: 0x1000, accepted: false),
            .init(label: "odd positive tag", field: 0x1000, raw: 0x1001, mappedTarget: 0x2001, accepted: false),
            .init(label: "odd negative tag", field: 0x2000, raw: 0xfffff001, mappedTarget: 0x1001, accepted: false),
            .init(label: "raw zero", field: 0x1000, raw: 0, mappedTarget: 0x2000, accepted: false)
        ]
        for c in cases {
            var b = Builder()
            b.section("__swift5_proto", c.field + 0x20, 4, 0)
            b.u32(0xffffffe0, 0) // top-level direct pointer back 32 bytes
            b.section("conformance", c.field, 16, 0x20)
            b.u32(c.raw, 0x20)
            b.u32(0x48, 0x28) // witness pattern field + 0x48 => conformance + 0x50
            b.section("protocol", c.mappedTarget, 0x40, 0x40)
            b.u32(3, 0x40); b.u32(0x28, 0x48) // name at protocol + 0x30
            b.u32(1, 0x50) // one requirement, zero signature requirements
            b.u32(1, 0x58) // callable requirement, not async
            b.bytes[0x70] = 0x50; b.bytes[0x71] = 0
            b.section("pattern", c.field + 0x50, 16, 0xa0)
            b.u64(c.field, 0xa0); b.u64(0x4000, 0xa8)
            b.section("text", 0x4000, 4, 0xc0, executable: true)
            let links = b.links()
            XCTAssertEqual(links.conformances[c.field] != nil, c.accepted, c.label)
            XCTAssertEqual(Set(links.conformances.keys), c.accepted ? Set([c.field]) : Set<UInt64>(), c.label)
            XCTAssertTrue(links.types.isEmpty, c.label)
            if c.accepted {
                XCTAssertEqual(links.conformances[c.field], [SwiftMetadataMethod(
                    source: .witness, index: 0, descriptorAddress: c.mappedTarget + 24,
                    implementation: 0x4000, flags: 1)], c.label)
                XCTAssertEqual(links.conformances[c.field]?.map(\.implementation), [0x4000])
                XCTAssertEqual(links.conformances[c.field]?.map(\.index), [0])
                XCTAssertEqual(links.conformances[c.field]?.map(\.descriptorAddress), [c.mappedTarget + 24])
            }
        }
    }

    func testDirectOverflowBaitsRemainReachableWithoutWrapping() {
        // Independent legal pointers to the three mapped baits from the negative table.
        let cases: [Case] = [
            .init(label: "Int32 min underflow bait", field: 0xffffffff80000000, raw: 0x10,
                  mappedTarget: 0xffffffff80000010, accepted: true),
            .init(label: "negative underflow bait", field: 0xffffffffffffff00, raw: 0x10,
                  mappedTarget: 0xffffffffffffff10, accepted: true),
            .init(label: "positive overflow bait", field: 0xff0, raw: 0x10,
                  mappedTarget: 0x1000, accepted: true)
        ]
        for c in cases {
            let links = nominalLayout(field: c.field, raw: c.raw, target: c.mappedTarget).links()
            XCTAssertEqual(Set(links.types.keys), Set([c.mappedTarget]), c.label)
            XCTAssertEqual(links.types[c.mappedTarget], [], c.label)
            XCTAssertTrue(links.conformances.isEmpty, c.label)
        }
    }

    func testIndirectableOverflowBaitsRemainReachableWithoutWrapping() {
        let cases: [Case] = [
            .init(label: "Int32 min underflow bait", field: 0xffffffff7fffff90, raw: 0x80,
                  mappedTarget: 0xffffffff80000010, accepted: true),
            .init(label: "negative underflow bait", field: 0xfffffffffffffe90, raw: 0x80,
                  mappedTarget: 0xffffffffffffff10, accepted: true),
            .init(label: "positive overflow bait", field: 0xf80, raw: 0x80,
                  mappedTarget: 0x1000, accepted: true)
        ]
        for c in cases {
            let links = witnessLayout(field: c.field, raw: c.raw, target: c.mappedTarget).links()
            XCTAssertEqual(Set(links.conformances.keys), Set([c.field]), c.label)
            XCTAssertEqual(links.conformances[c.field], [SwiftMetadataMethod(
                source: .witness, index: 0, descriptorAddress: c.mappedTarget + 24,
                implementation: 0x4000, flags: 1)], c.label)
            XCTAssertTrue(links.types.isEmpty, c.label)
        }
    }

    func testDirectNegativeDisplacementCanTargetZero() {
        let links = nominalLayout(field: 0x80000000, raw: 0x80000000, target: 0).links()
        XCTAssertEqual(Set(links.types.keys), Set<UInt64>([0]))
        XCTAssertEqual(links.types[0], [])
        XCTAssertTrue(links.conformances.isEmpty)
    }

    func testIndirectableNegativeDisplacementCanTargetZero() {
        let links = witnessLayout(field: 0x80000000, raw: 0x80000000, target: 0).links()
        XCTAssertEqual(Set(links.conformances.keys), Set<UInt64>([0x80000000]))
        XCTAssertEqual(links.conformances[0x80000000], [SwiftMetadataMethod(
            source: .witness, index: 0, descriptorAddress: 24, implementation: 0x4000, flags: 1)])
        XCTAssertTrue(links.types.isEmpty)
    }

    // Same literal descriptor/protocol bytes as the corresponding retained negative layouts.
    // These builders write bytes, not a relative-target oracle; field+0x20/+0x50 are fixed
    // top-level/pattern geometry, and target+24 above is the fixed requirement record offset.
    private func nominalLayout(field: UInt64, raw: UInt32, target: UInt64) -> Builder {
        var b = Builder()
        b.section("__swift5_types", field, 4, 0)
        b.u32(raw, 0)
        b.section("descriptor", target, 0x80, 0x20)
        b.u32(0x80000010, 0x20)
        b.u32(0x68, 0x28)
        b.bytes[0x90] = 0x43; b.bytes[0x91] = 0
        return b
    }

    private func witnessLayout(field: UInt64, raw: UInt32, target: UInt64) -> Builder {
        var b = Builder()
        b.section("__swift5_proto", field + 0x20, 4, 0)
        b.u32(0xffffffe0, 0)
        b.section("conformance", field, 16, 0x20)
        b.u32(raw, 0x20)
        b.u32(0x48, 0x28)
        b.section("protocol", target, 0x40, 0x40)
        b.u32(3, 0x40); b.u32(0x28, 0x48)
        b.u32(1, 0x50)
        b.u32(1, 0x58)
        b.bytes[0x70] = 0x50; b.bytes[0x71] = 0
        b.section("pattern", field + 0x50, 16, 0xa0)
        b.u64(field, 0xa0); b.u64(0x4000, 0xa8)
        b.section("text", 0x4000, 4, 0xc0, executable: true)
        return b
    }

    // Fresh sparse in-memory literal builder; does not derive deltas with the production algorithm.
    private struct Builder {
        var bytes = [UInt8](repeating: 0, count: 0x100)
        var sections: [SwiftMetadataParser.Section] = []
        mutating func section(_ name: String, _ va: UInt64, _ size: UInt64, _ offset: UInt64,
                              executable: Bool = false) {
            sections.append(.init(name: name, address: va, fileOffset: offset, size: size,
                                  isExecutable: executable))
        }
        mutating func u32(_ value: UInt32, _ offset: Int) {
            for i in 0..<4 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (i * 8)) }
        }
        mutating func u64(_ value: UInt64, _ offset: Int) {
            for i in 0..<8 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (i * 8)) }
        }
        func links() -> SwiftMetadataFunctionExtractor.MethodLinks {
            SwiftMetadataFunctionExtractor.methodLinks(data: Data(bytes), sections: sections,
                                                       inventory: .testInventory(
                                                           covering: sections.map { $0.address..<($0.address + $0.size) }))
        }
    }
}
