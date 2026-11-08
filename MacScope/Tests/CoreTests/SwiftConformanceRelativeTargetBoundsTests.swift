import Foundation
import XCTest
@testable import MacScope

final class SwiftConformanceRelativeTargetBoundsTests: XCTestCase {
    private struct Fixture {
        var bytes: [UInt8] = []
        var sections: [SwiftMetadataParser.Section] = []

        mutating func append(_ payload: [UInt8], at address: UInt64, name: String) {
            sections.append(.init(name: name, address: address,
                                  fileOffset: UInt64(bytes.count), size: UInt64(payload.count)))
            bytes.append(contentsOf: payload)
        }

        mutating func conformance(at address: UInt64, protocolWord: Int32) {
            var entry = [UInt8](repeating: 0, count: 4)
            SwiftConformanceRelativeTargetBoundsTests.word(0x20, into: &entry, at: 0)
            append(entry, at: address - 0x20, name: "__swift5_proto")
            var descriptor = [UInt8](repeating: 0, count: 0x40)
            SwiftConformanceRelativeTargetBoundsTests.word(UInt32(bitPattern: protocolWord), into: &descriptor, at: 0)
            SwiftConformanceRelativeTargetBoundsTests.word(0x1c, into: &descriptor, at: 4)
            // TypeReferenceKind 2: direct ObjC class-name string. No type-descriptor proof needed.
            SwiftConformanceRelativeTargetBoundsTests.word(2 << 3, into: &descriptor, at: 12)
            descriptor.replaceSubrange(0x20..<0x25, with: Array("Host\0".utf8))
            append(descriptor, at: address, name: "__conformance")
        }

        mutating func protocolDescriptor(at address: UInt64) {
            var descriptor = [UInt8](repeating: 0, count: 0x60)
            SwiftConformanceRelativeTargetBoundsTests.word(3, into: &descriptor, at: 0)
            SwiftConformanceRelativeTargetBoundsTests.word(0x1c, into: &descriptor, at: 4)
            SwiftConformanceRelativeTargetBoundsTests.word(0x48, into: &descriptor, at: 8)
            // Module context at +0x20, name at +0x40; protocol name at +0x50.
            SwiftConformanceRelativeTargetBoundsTests.word(0x18, into: &descriptor, at: 0x28)
            descriptor.replaceSubrange(0x40..<0x45, with: Array("Demo\0".utf8))
            descriptor.replaceSubrange(0x50..<0x56, with: Array("Proto\0".utf8))
            append(descriptor, at: address, name: "__protocol")
        }

        func parser(rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:]) -> SwiftMetadataParser {
            SwiftMetadataParser(data: Data(bytes), sections: sections,
                                rebaseTargets: rebases, bindNames: binds)
        }
    }

    private static func word(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        for index in 0..<4 { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (8 * index)) }
    }

    private func assertNamed(_ parser: SwiftMetadataParser, simple: String = "Proto",
                             qualified: String = "Demo.Proto", file: StaticString = #filePath, line: UInt = #line) {
        let report = parser.parseConformancesReport()
        XCTAssertTrue(report.diagnostics.isEmpty, file: file, line: line)
        XCTAssertEqual(report.conformances.count, 1, file: file, line: line)
        XCTAssertEqual(report.conformances.first?.typeName, "Host", file: file, line: line)
        XCTAssertEqual(report.conformances.first?.protocolName, simple, file: file, line: line)
        XCTAssertEqual(report.conformances.first?.protocolQualifiedName, qualified, file: file, line: line)
    }

    private func assertRefused(_ parser: SwiftMetadataParser, file: StaticString = #filePath, line: UInt = #line) {
        let report = parser.parseConformancesReport()
        XCTAssertTrue(report.conformances.isEmpty, file: file, line: line)
        // Arithmetic refusal remains an unnameable skipped conformance, not an unreadable-list failure.
        XCTAssertTrue(report.diagnostics.isEmpty, file: file, line: line)
    }

    func testPositiveOverflowCannotNameMappedLowProtocol() {
        var fixture = Fixture()
        fixture.conformance(at: UInt64.max - 0xff, protocolWord: 0x200)
        fixture.protocolDescriptor(at: 0x100)
        assertRefused(fixture.parser())
    }

    func testNegativeUnderflowCannotNameMappedHighProtocol() {
        var fixture = Fixture()
        fixture.conformance(at: 0x100, protocolWord: -0x200)
        fixture.protocolDescriptor(at: UInt64.max - 0xff)
        assertRefused(fixture.parser())
    }

    func testTaggedOverflowCannotUseLowRebaseOrExternalBind() {
        var fixture = Fixture()
        fixture.conformance(at: UInt64.max - 0xff, protocolWord: 0x201)
        fixture.protocolDescriptor(at: 0x300)
        assertRefused(fixture.parser(rebases: [0x100: 0x300]))
        assertRefused(fixture.parser(binds: [0x100: "_$sSQMp"]))
    }

    func testTaggedUnderflowCannotUseHighRebaseOrExternalBind() {
        var fixture = Fixture()
        fixture.conformance(at: 0x100, protocolWord: -0x1ff)
        fixture.protocolDescriptor(at: 0x300)
        let wrapped = UInt64.max - 0xff
        assertRefused(fixture.parser(rebases: [wrapped: 0x300]))
        assertRefused(fixture.parser(binds: [wrapped: "_$sSQMp"]))
    }

    func testLegalPositiveAndNegativeDirectTargetsKeepQualifiedNames() {
        let cases: [(UInt64, UInt64, Int32)] = [
            (0x1000, 0x1200, 0x200), (0x1200, 0x1000, -0x200)
        ]
        for (source, target, word) in cases {
            var fixture = Fixture()
            fixture.conformance(at: source, protocolWord: word)
            fixture.protocolDescriptor(at: target)
            assertNamed(fixture.parser())
        }
    }

    func testLegalTaggedRebasePreservesSimpleAndQualifiedNames() {
        var fixture = Fixture()
        fixture.conformance(at: 0x1000, protocolWord: 0x101)
        fixture.protocolDescriptor(at: 0x1200)
        assertNamed(fixture.parser(rebases: [0x1100: 0x1200]))
    }

    func testLegalExternalBindPreservesSimpleAndQualifiedNames() {
        var fixture = Fixture()
        fixture.conformance(at: 0x1000, protocolWord: 0x101)
        assertNamed(fixture.parser(binds: [0x1100: "_$sSQMp"]),
                    simple: "Equatable", qualified: "Swift.Equatable")
    }

    func testNullAndTaggedZeroDisplacementKeepDistinctSemantics() {
        var null = Fixture()
        null.conformance(at: 0x1000, protocolWord: 0)
        assertRefused(null.parser(binds: [0x1000: "_$sSQMp"]))
        var indirect = Fixture()
        indirect.conformance(at: 0x1000, protocolWord: 1)
        assertNamed(indirect.parser(binds: [0x1000: "_$sSQMp"]),
                    simple: "Equatable", qualified: "Swift.Equatable")
    }
}
