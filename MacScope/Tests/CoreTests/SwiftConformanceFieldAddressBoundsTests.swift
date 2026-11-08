import Foundation
import XCTest
@testable import MacScope

final class SwiftConformanceFieldAddressBoundsTests: XCTestCase {
    private struct Fixture {
        var bytes: [UInt8] = []
        var sections: [SwiftMetadataParser.Section] = []

        mutating func append(_ payload: [UInt8], at address: UInt64, name: String) {
            sections.append(.init(name: name, address: address,
                                  fileOffset: UInt64(bytes.count), size: UInt64(payload.count)))
            bytes.append(contentsOf: payload)
        }

        mutating func entries(at address: UInt64, targets: [UInt64]) {
            var payload = [UInt8](repeating: 0, count: targets.count * 4)
            for (index, target) in targets.enumerated() {
                SwiftConformanceFieldAddressBoundsTests.relative(target, from: address + UInt64(index * 4),
                                                                 into: &payload, at: index * 4)
            }
            append(payload, at: address, name: "__swift5_proto")
        }

        mutating func descriptor(at address: UInt64, protocolTarget: UInt64,
                                 typeTarget: UInt64, kind: UInt32) {
            var payload = [UInt8](repeating: 0, count: 16)
            SwiftConformanceFieldAddressBoundsTests.relative(protocolTarget, from: address, into: &payload, at: 0)
            SwiftConformanceFieldAddressBoundsTests.relative(typeTarget, from: address + 4, into: &payload, at: 4)
            SwiftConformanceFieldAddressBoundsTests.word(kind << 3, into: &payload, at: 12)
            append(payload, at: address, name: "__descriptor")
        }

        mutating func nominal(at address: UInt64, kind: UInt32, name: String) {
            var payload = [UInt8](repeating: 0, count: 0x80)
            SwiftConformanceFieldAddressBoundsTests.word(kind, into: &payload, at: 0)
            SwiftConformanceFieldAddressBoundsTests.word(0x1c, into: &payload, at: 4)
            SwiftConformanceFieldAddressBoundsTests.word(0x48, into: &payload, at: 8)
            SwiftConformanceFieldAddressBoundsTests.word(0x18, into: &payload, at: 0x28)
            payload.replaceSubrange(0x40..<0x45, with: Array("Demo\0".utf8))
            let text = Array((name + "\0").utf8)
            payload.replaceSubrange(0x50..<(0x50 + text.count), with: text)
            append(payload, at: address, name: "__nominal")
        }

        func parser(rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:]) -> SwiftMetadataParser {
            SwiftMetadataParser(data: Data(bytes), sections: sections,
                                rebaseTargets: rebases, bindNames: binds)
        }
    }

    private static func word(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        for index in 0..<4 { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    }

    private static func relative(_ target: UInt64, from field: UInt64, into bytes: inout [UInt8], at offset: Int) {
        // Every fixture displacement is deliberately small, including at the UInt64 boundary.
        let delta = target >= field ? Int32(target - field) : -Int32(field - target)
        word(UInt32(bitPattern: delta), into: &bytes, at: offset)
    }

    private func assertAbandoned(_ parser: SwiftMetadataParser, descriptor: UInt64, remaining: Int,
                                 file: StaticString = #filePath, line: UInt = #line) {
        let report = parser.parseConformancesReport()
        XCTAssertTrue(report.conformances.isEmpty, file: file, line: line)
        XCTAssertEqual(report.diagnostics.count, 1, file: file, line: line)
        XCTAssertEqual(report.diagnostics.first?.address, descriptor, file: file, line: line)
        XCTAssertEqual(report.diagnostics.first?.message,
                       "Cannot read protocol conformance descriptor at 0x" + String(descriptor, radix: 16)
                       + "; abandoned the remaining \(remaining) __swift5_proto entries", file: file, line: line)
    }

    func testFlagsOverflowCannotBorrowMappedLowFlagsAndAbandonsRemainingList() {
        let descriptor = UInt64.max - 7
        var fixture = Fixture()
        fixture.entries(at: descriptor - 0x100, targets: [descriptor, descriptor])
        fixture.append([UInt8](repeating: 0, count: 8), at: descriptor, name: "__high_prefix")
        var bait = [UInt8](repeating: 0, count: 4)
        Self.word(2 << 3, into: &bait, at: 0)
        fixture.append(bait, at: 4, name: "__low_flags")
        assertAbandoned(fixture.parser(), descriptor: descriptor, remaining: 2)
    }

    func testTypeRefOverflowIsStoppedByEarlierFlagsGateDespiteBothLowBaits() {
        let descriptor = UInt64.max - 1
        var fixture = Fixture()
        fixture.entries(at: descriptor - 0x100, targets: [descriptor])
        var bait = [UInt8](repeating: 0, count: 16)
        Self.word(0x100, into: &bait, at: 2) // wrapped typeRef address
        Self.word(2 << 3, into: &bait, at: 10) // wrapped flags address
        fixture.append(bait, at: 0, name: "__low_bait")
        fixture.append(Array("Bait\0".utf8), at: 0x102, name: "__bait_name")
        assertAbandoned(fixture.parser(), descriptor: descriptor, remaining: 1)
    }

    func testRepresentableFlagsStartStillRequiresCompleteMappedWord() {
        let descriptor = UInt64.max - 12
        var fixture = Fixture()
        fixture.entries(at: descriptor - 0x100, targets: [descriptor])
        fixture.append([UInt8](repeating: 0, count: 13), at: descriptor, name: "__short_descriptor")
        assertAbandoned(fixture.parser(), descriptor: descriptor, remaining: 1)
    }

    func testExactHighBoundaryFlagsAndObjCNameRemainLegal() {
        let descriptor = UInt64.max - 15
        let proto = descriptor - 0x200
        let name = descriptor - 0x100
        var fixture = Fixture()
        fixture.entries(at: descriptor - 0x300, targets: [descriptor])
        fixture.nominal(at: proto, kind: 3, name: "Proto")
        fixture.append(Array("Host\0".utf8), at: name, name: "__objc_name")
        fixture.descriptor(at: descriptor, protocolTarget: proto, typeTarget: name, kind: 2)
        let report = fixture.parser().parseConformancesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.conformances.first?.typeName, "Host")
        XCTAssertEqual(report.conformances.first?.protocolQualifiedName, "Demo.Proto")
        XCTAssertEqual(report.conformances.count, 1)
        XCTAssertNil(report.conformances.first?.typeDescriptorAddress)
    }

    private func ordinary(kind: UInt32, target: UInt64) -> Fixture {
        var fixture = Fixture()
        fixture.entries(at: 0x100, targets: [0x200])
        fixture.descriptor(at: 0x200, protocolTarget: 0x400, typeTarget: target, kind: kind)
        fixture.nominal(at: 0x400, kind: 3, name: "Proto")
        fixture.nominal(at: 0x600, kind: 17, name: "Host")
        return fixture
    }

    func testDirectNominalTypeKeepsDescriptorAndQualifiedName() {
        let report = ordinary(kind: 0, target: 0x600).parser().parseConformancesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.conformances.count, 1)
        XCTAssertEqual(report.conformances.first?.typeName, "Host")
        XCTAssertEqual(report.conformances.first?.typeQualifiedName, "Demo.Host")
        XCTAssertEqual(report.conformances.first?.typeDescriptorAddress, 0x600)
    }

    func testIndirectRebaseKeepsNominalTypeAndDescriptor() {
        let report = ordinary(kind: 1, target: 0x800).parser(rebases: [0x800: 0x600]).parseConformancesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.conformances.count, 1)
        XCTAssertEqual(report.conformances.first?.typeQualifiedName, "Demo.Host")
        XCTAssertEqual(report.conformances.first?.typeDescriptorAddress, 0x600)
    }

    func testExternalTypeBindKeepsNameWithoutInventedDescriptor() {
        let report = ordinary(kind: 1, target: 0x800).parser(binds: [0x800: "_$s4Demo4HostVMn"]).parseConformancesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.conformances.count, 1)
        XCTAssertEqual(report.conformances.first?.typeName, "Host")
        XCTAssertEqual(report.conformances.first?.typeQualifiedName, "Demo.Host")
        XCTAssertNil(report.conformances.first?.typeDescriptorAddress)
    }

    func testUnsupportedIndirectObjCKindRemainsSkippedNotAbandoned() {
        let report = ordinary(kind: 3, target: 0x600).parser().parseConformancesReport()
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertTrue(report.conformances.isEmpty)
    }
}
