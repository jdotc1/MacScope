import Foundation
import XCTest
@testable import MacScope

final class SwiftRelativeEntryArrayAddressBoundsTests: XCTestCase {
    private enum Kind: CaseIterable {
        case types, protocols, conformances
        var sectionName: String {
            switch self {
            case .types: return "__swift5_types"
            case .protocols: return "__swift5_protos"
            case .conformances: return "__swift5_proto"
            }
        }
    }

    private struct Fixture {
        var bytes = Data()
        var sections: [SwiftMetadataParser.Section] = []
        mutating func map(_ address: UInt64, _ payload: [UInt8], name: String = "__const") {
            sections.append(.init(name: name, address: address,
                                  fileOffset: UInt64(bytes.count), size: UInt64(payload.count)))
            bytes.append(contentsOf: payload)
        }
        func word(_ value: UInt32) -> [UInt8] {
            (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        func relative(_ from: UInt64, _ to: UInt64) -> [UInt8] {
            let delta: Int64 = to >= from ? Int64(to - from) : -Int64(from - to)
            return word(UInt32(bitPattern: Int32(delta)))
        }
        mutating func descriptor(_ address: UInt64, name: String, kind: Kind) {
            var payload = [UInt8](repeating: 0, count: 128)
            func put(_ offset: Int, _ value: [UInt8]) {
                payload.replaceSubrange(offset..<(offset + value.count), with: value)
            }
            switch kind {
            case .types, .protocols:
                put(0, word(kind == .types ? 17 : 3))
                put(8, word(0x18))
                put(0x20, Array((name + "\0").utf8))
            case .conformances:
                put(0, word(0x40))
                put(4, word(0x1c))
                put(12, word(2 << 3))
                put(0x20, Array("Host\0".utf8))
                put(0x40, word(3))
                put(0x48, word(0x18))
                put(0x60, Array((name + "\0").utf8))
            }
            map(address, payload)
        }
        mutating func entries(_ address: UInt64, targets: [UInt64?], kind: Kind,
                              sectionName: String? = nil) {
            var payload: [UInt8] = []
            for (index, target) in targets.enumerated() {
                payload += target.map { relative(address + UInt64(index * 4), $0) } ?? word(0)
            }
            map(address, payload, name: sectionName ?? kind.sectionName)
        }
        func parser() -> SwiftMetadataParser { .init(data: bytes, sections: sections) }
    }

    private func names(_ parser: SwiftMetadataParser, _ kind: Kind) -> [String] {
        switch kind {
        case .types: return parser.parseTypesReport().types.map(\.name)
        case .protocols: return parser.parseProtocols().map(\.name)
        case .conformances: return parser.parseConformancesReport().conformances.map(\.protocolName)
        }
    }

    private func overflowFixture(_ kind: Kind, start: UInt64, count: Int) -> Fixture {
        var fixture = Fixture()
        // This declared high list is malformed as a whole. Its first entries are unreadable
        // under the existing span proof; the old wrapping loop could still visit low bait.
        fixture.map(start, [UInt8](repeating: 0, count: count * 4), name: kind.sectionName)
        fixture.descriptor(0x100, name: "Bait", kind: kind)
        fixture.entries(0, targets: [0x100, 0x100], kind: kind, sectionName: "__low_bait")
        return fixture
    }

    func testTypesTwoEntryOverflowCannotBorrowMappedLowType() {
        let fixture = overflowFixture(.types, start: UInt64.max - 3, count: 2)
        let report = fixture.parser().parseTypesReport()
        XCTAssertTrue(report.types.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 2) // existing unreadable entry, then overflow
        XCTAssertEqual(report.diagnostics.last?.address, UInt64.max - 3)
        XCTAssertTrue(report.diagnostics.last?.message.contains("Entry address overflows") == true)
    }

    func testProtocolsThreeEntryOverflowCannotBorrowMappedLowProtocol() {
        let fixture = overflowFixture(.protocols, start: UInt64.max - 7, count: 3)
        XCTAssertTrue(fixture.parser().parseProtocols().isEmpty)
    }

    func testConformanceThreeEntryOverflowCannotBorrowMappedLowConformance() {
        let fixture = overflowFixture(.conformances, start: UInt64.max - 3, count: 3)
        let report = fixture.parser().parseConformancesReport()
        XCTAssertTrue(report.conformances.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
        XCTAssertEqual(report.diagnostics.first?.address, UInt64.max - 3)
        XCTAssertTrue(report.diagnostics.first?.message.contains("remaining 2") == true)
    }

    func testLowBaitIsIndependentlyReadableForAllThreeAPIs() {
        for kind in Kind.allCases {
            var fixture = Fixture()
            fixture.descriptor(0x100, name: "Bait", kind: kind)
            fixture.entries(0, targets: [0x100, 0x100], kind: kind)
            XCTAssertEqual(names(fixture.parser(), kind), ["Bait", "Bait"])
        }
    }

    func testExactHighBoundaryEntriesRemainOrderedAndReadable() {
        for kind in Kind.allCases {
            var fixture = Fixture()
            let first = UInt64.max - 0x3ff
            let second = UInt64.max - 0x2ff
            fixture.descriptor(first, name: "First", kind: kind)
            fixture.descriptor(second, name: "Second", kind: kind)
            fixture.entries(UInt64.max - 7, targets: [first, second], kind: kind)
            XCTAssertEqual(names(fixture.parser(), kind), ["First", "Second"])
        }
    }

    func testOrdinaryNullEntryKeepsValidNeighborsAndTheirOrder() {
        for kind in Kind.allCases {
            var fixture = Fixture()
            fixture.descriptor(0x2000, name: "First", kind: kind)
            fixture.descriptor(0x2100, name: "Second", kind: kind)
            fixture.entries(0x1000, targets: [0x2100, nil, 0x2000], kind: kind)
            XCTAssertEqual(names(fixture.parser(), kind), ["Second", "First"])
        }
    }

    func testFirstMatchingSectionPolicyDoesNotFallThroughAfterOverflow() {
        for kind in Kind.allCases {
            var fixture = overflowFixture(kind, start: UInt64.max - 3, count: 2)
            fixture.descriptor(0x2000, name: "Neighbor", kind: kind)
            fixture.entries(0x1000, targets: [0x2000], kind: kind)
            XCTAssertTrue(names(fixture.parser(), kind).isEmpty)
        }
    }

    func testExistingUnreadableTypeDescriptorStillAbandonsList() {
        var fixture = Fixture()
        fixture.descriptor(0x2000, name: "Neighbor", kind: .types)
        fixture.entries(0x1000, targets: [0x3000, 0x2000], kind: .types)
        let report = fixture.parser().parseTypesReport()
        XCTAssertTrue(report.types.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
        XCTAssertEqual(report.diagnostics.first?.address, 0x3000)
        XCTAssertTrue(report.diagnostics.first?.message.contains("Cannot read Swift type descriptor") == true)
    }

    func testExistingUnreadableConformanceDescriptorStillAbandonsList() {
        var fixture = Fixture()
        fixture.descriptor(0x2000, name: "Neighbor", kind: .conformances)
        fixture.entries(0x1000, targets: [0x3000, 0x2000], kind: .conformances)
        let report = fixture.parser().parseConformancesReport()
        XCTAssertTrue(report.conformances.isEmpty)
        XCTAssertEqual(report.diagnostics.count, 1)
        XCTAssertEqual(report.diagnostics.first?.address, 0x3000)
        XCTAssertTrue(report.diagnostics.first?.message.contains("Cannot read protocol conformance descriptor") == true)
    }
}
