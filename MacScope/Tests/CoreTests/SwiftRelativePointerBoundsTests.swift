import Foundation
import XCTest
@testable import MacScope

/// NEW definitions only: not compiled, discovered, imported or executed in this handback.
final class SwiftRelativePointerBoundsTests: XCTestCase {
    private func parser(_ raw: Int32, at address: UInt64,
                        rebases: [UInt64: UInt64] = [:],
                        binds: [UInt64: String] = [:]) -> SwiftMetadataParser {
        var data = Data(repeating: 0, count: 4)
        write(raw, at: 0, into: &data)
        return SwiftMetadataParser(data: data, sections: [
            .init(name: "__relative_test", address: address, fileOffset: 0, size: 4)
        ], rebaseTargets: rebases, bindNames: binds)
    }

    private func write(_ raw: Int32, at offset: Int, into data: inout Data) {
        let word = UInt32(bitPattern: raw)
        for byte in 0..<4 {
            data[offset + byte] = UInt8(truncatingIfNeeded: word >> (byte * 8))
        }
    }

    func testPositiveOverflowCannotAliasLowAddressOrRebaseSlot() {
        let field = UInt64.max - 7
        // The old wrap produced 8. A rebase at that alias must not rescue overflow.
        XCTAssertNil(parser(16, at: field).resolveRelativePointer(at: field))
        XCTAssertNil(parser(16, at: field).resolveRelativeIndirectablePointer(at: field))
        XCTAssertNil(parser(17, at: field, rebases: [8: 0x1234])
            .resolveRelativeIndirectablePointer(at: field))
    }

    func testNegativeUnderflowCannotAliasHighAddressOrRebaseSlot() {
        let field: UInt64 = 4
        let alias = UInt64.max - 3
        XCTAssertNil(parser(-8, at: field).resolveRelativePointer(at: field))
        XCTAssertNil(parser(-8, at: field).resolveRelativeIndirectablePointer(at: field))
        XCTAssertNil(parser(-7, at: field, rebases: [alias: 0x1234])
            .resolveRelativeIndirectablePointer(at: field))
        XCTAssertNil(parser(Int32.min, at: field).resolveRelativePointer(at: field))
        XCTAssertNil(parser(Int32.min, at: field).resolveRelativeIndirectablePointer(at: field))
        XCTAssertNil(parser(Int32.min + 1, at: field)
            .resolveRelativeIndirectablePointer(at: field))
    }

    func testValidSignedOffsetsPreserveUnsignedAddressRangeAndExactBoundaries() {
        let cases: [(field: UInt64, raw: Int32, target: UInt64)] = [
            (0x1000, 16, 0x1010),
            (0x1000, -16, 0x0ff0),
            (0x8000_0000_0000_0000, 16, 0x8000_0000_0000_0010),
            (0x8000_0000_0000_0000, -16, 0x7fff_ffff_ffff_fff0),
            (UInt64.max - 4, 4, UInt64.max),
            (16, -16, 0),
            (0x8000_0000, Int32.min, 0),
            (0x8000_0010, Int32.min, 16)
        ]
        for value in cases {
            let subject = parser(value.raw, at: value.field)
            XCTAssertEqual(subject.resolveRelativePointer(at: value.field), value.target)
            XCTAssertEqual(subject.resolveRelativeIndirectablePointer(at: value.field), value.target)
        }
        let field = UInt64.max - UInt64(Int32.max)
        let maximum = parser(Int32.max, at: field)
        XCTAssertEqual(maximum.resolveRelativePointer(at: field), UInt64.max)
    }

    func testNullUnmappedAndUnreadableSlotsRemainNil() {
        let field: UInt64 = 0x1000
        let null = parser(0, at: field, rebases: [field: 0x1234])
        XCTAssertNil(null.resolveRelativePointer(at: field))
        XCTAssertNil(null.resolveRelativeIndirectablePointer(at: field))
        let unmapped = SwiftMetadataParser(data: Data([4, 0, 0, 0]), sections: [])
        let truncated = SwiftMetadataParser(data: Data([4, 0, 0]), sections: [
            .init(name: "__relative_test", address: field, fileOffset: 0, size: 4)
        ])
        for subject in [unmapped, truncated] {
            XCTAssertNil(subject.resolveRelativePointer(at: field))
            XCTAssertNil(subject.resolveRelativeIndirectablePointer(at: field))
        }
    }

    func testTaggedIndirectClearsTagBeforeSignedArithmeticAndKeepsRebasePrecedence() {
        let cases: [(field: UInt64, raw: Int32, slot: UInt64)] = [
            (0x1000, 17, 0x1010),
            (0x1000, -15, 0x0ff0),
            (0x1000, 1, 0x1000),
            (0x8000_0000, Int32.min + 1, 0)
        ]
        for value in cases {
            let subject = parser(value.raw, at: value.field,
                rebases: [value.slot: 0x4321], binds: [value.slot: "_bound_impostor"])
            XCTAssertEqual(subject.resolveRelativeIndirectablePointer(at: value.field), 0x4321)
            XCTAssertNil(parser(value.raw, at: value.field)
                .resolveRelativeIndirectablePointer(at: value.field))
            XCTAssertNil(parser(value.raw, at: value.field, binds: [value.slot: "_bound_only"])
                .resolveRelativeIndirectablePointer(at: value.field))
        }
        // An even word remains direct; a rebase entry must not override its computed target.
        XCTAssertEqual(parser(16, at: 0x1000, rebases: [0x1010: 0x4321])
            .resolveRelativeIndirectablePointer(at: 0x1000), 0x1010)
        // Rebase values are still returned unchanged; this is not a target-validity validator.
        XCTAssertEqual(parser(17, at: 0x1000, rebases: [0x1010: 0])
            .resolveRelativeIndirectablePointer(at: 0x1000), 0)
        // Direct rel32 has no tag: an odd positive displacement is still exactly +1.
        XCTAssertEqual(parser(1, at: 0x1000).resolveRelativePointer(at: 0x1000), 0x1001)
    }

    func testMixedRuntimeArraysRejectWrapAliasesWithoutLosingValidOrderOrMultiplicity() {
        for name in ["__swift_as_entry", "__swift_as_ret", "__swift_as_cont"] {
            for positiveOverflow in [true, false] {
                let base: UInt64 = positiveOverflow ? UInt64.max - 31 : 0x10
                let expected: [UInt64] = positiveOverflow
                    ? [UInt64.max - 239, UInt64.max - 247, UInt64.max - 239]
                    : [0x90, 0x88, 0x90]
                let words: [Int32] = positiveOverflow ? [-208, 32, -224, -220] : [128, -64, 112, 116]
                var data = Data(repeating: 0, count: 144)
                for (index, word) in words.enumerated() { write(word, at: index * 4, into: &data) }
                let subject = SwiftMetadataParser(data: data, sections: [
                    .init(name: name, address: base, fileOffset: 0, size: 16, segmentName: "__TEXT"),
                    .init(name: "__text", address: positiveOverflow ? UInt64.max - 255 : 0x80,
                          fileOffset: 16, size: 64, isExecutable: true, segmentName: "__TEXT"),
                    // A mapped, aligned wrap alias exists, so old membership/alignment gates
                    // alone would accept it. The new relative arithmetic must refuse first.
                    .init(name: "__text", address: positiveOverflow ? 0 : UInt64.max - 63,
                          fileOffset: 80, size: positiveOverflow ? 64 : 48,
                          isExecutable: true, segmentName: "__TEXT")
                ])
                let report = subject.parseAsyncFunctionsReport()
                let actual: [UInt64]
                switch name {
                case "__swift_as_entry": actual = report.records.entries.map(\.entryAddress)
                case "__swift_as_ret": actual = report.records.resumePartialAddresses
                default: actual = report.records.continuationPartialAddresses
                }
                XCTAssertEqual(actual, expected)
                let refusals = report.diagnostics.filter {
                    $0.message == "Unreadable \(name) entry or target outside __text"
                }
                XCTAssertEqual(refusals, [.init(grade: .skippedItem, address: base + 4,
                    message: "Unreadable \(name) entry or target outside __text")])
                if name == "__swift_as_entry" {
                    XCTAssertTrue(report.records.entries.allSatisfy { $0.pointerRecords.isEmpty })
                    XCTAssertEqual(report.records.entryGroups.first { $0.entryAddress == expected[0] }?.entryCount, 2)
                    XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
                    XCTAssertTrue(report.records.continuationPartialAddresses.isEmpty)
                } else {
                    XCTAssertTrue(report.records.entries.isEmpty)
                    if name == "__swift_as_ret" {
                        XCTAssertTrue(report.records.continuationPartialAddresses.isEmpty)
                    } else {
                        XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
                    }
                }
            }
        }
    }
}
