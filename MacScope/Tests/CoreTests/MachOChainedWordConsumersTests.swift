import Foundation
import XCTest
@testable import MacScope

/// Item 1332 consumer contracts for the chained-pointer word consolidation.
/// All fixtures are in-memory bytes. Expected values are hand-derived from the
/// raw bit layouts and are never computed with MachOChainedPointerWord; no
/// authentication operation occurs.
final class MachOChainedWordConsumersTests: XCTestCase {
    private let imageBase: UInt64 = 0x2_0000_0000

    private enum FixtureIssue: Error { case invalidOffset }

    // MARK: Local byte helpers

    /// File offset of a fixture address (address = imageBase + file offset), with the
    /// full eight-byte extent checked against the buffer.
    private func offset(of address: UInt64, in bytes: Data) throws -> Int {
        let (relative, underflow) = address.subtractingReportingOverflow(imageBase)
        guard !underflow, let at = Int(exactly: relative), at >= 0, at <= bytes.count,
              bytes.count - at >= 8 else {
            XCTFail("fixture pointer does not fit the byte buffer")
            throw FixtureIssue.invalidOffset
        }
        return at
    }

    private func readUInt64(_ bytes: Data, at offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for byte in 0..<8 { value |= UInt64(bytes[bytes.startIndex + offset + byte]) << (8 * byte) }
        return value
    }

    private func writeUInt64(_ value: UInt64, into bytes: inout Data, at offset: Int) {
        for byte in 0..<8 {
            bytes[bytes.startIndex + offset + byte] = UInt8((value >> (8 * UInt64(byte))) & 0xff)
        }
    }

    /// Overwrites one fixture word and reads the bytes back before any parse.
    private func inject(_ raw: UInt64, at address: UInt64, into bytes: inout Data) throws {
        let at = try offset(of: address, in: bytes)
        writeUInt64(raw, into: &bytes, at: at)
        XCTAssertEqual(readUInt64(bytes, at: at), raw, "the bytes, not merely the source value, must match")
    }

    // MARK: TC02

    func testSupportedConsumerProjection() throws {
        let arm64eBind: UInt64 = 0x400f_ffff_0000_0000   // bind, next 1, signed19 addend -1
        let genericBind: UInt64 = 0x8010_0000_ff00_0000  // bind, next 2, unsigned addend 255
        let rows: [(format: UInt16, bind: UInt64, addend: Int64, target: UInt64)] = [
            (1, arm64eBind, -1, 0x120),
            (2, genericBind, 255, 0x120),
            (6, genericBind, 255, 0x2_0000_0120),
            (9, arm64eBind, -1, 0x2_0000_0120),
            (12, arm64eBind, -1, 0x2_0000_0120),
        ]
        for row in rows {
            let fixture = MachOFixture.makeExecutableWithChainedFixupChain(
                imageBase: imageBase, pointerFormat: row.format, rebaseRawOverride: 0x120)
            var bytes = fixture.bytes
            try inject(row.bind, at: fixture.chainedBindAddress, into: &bytes)
            try inject(0x120, at: fixture.chainedRebaseAddress, into: &bytes)
            let parsed = try MachOParser().parse(bytes)
            let chained = try XCTUnwrap(parsed.dyldChainedFixups, "format \(row.format)")
            let expected = [
                MachOChainedFixup(
                    fileOffset: fixture.chainedBindAddress - imageBase, address: fixture.chainedBindAddress,
                    pointerFormat: row.format,
                    kind: .bind(importOrdinal: 0, symbolName: "_puts", addend: row.addend)),
                MachOChainedFixup(
                    fileOffset: fixture.chainedRebaseAddress - imageBase, address: fixture.chainedRebaseAddress,
                    pointerFormat: row.format, kind: .rebase(targetAddress: row.target)),
            ]
            XCTAssertEqual(chained.fixups.count, 2, "format \(row.format)")
            XCTAssertEqual(chained.fixups, expected, "format \(row.format)")
            XCTAssertTrue(parsed.loaderFindings.isEmpty, "format \(row.format)")
        }
    }

    // MARK: TC04 (BLOCKED on owner input O3: fixture admissibility is not established)

    func testAuditReservedBoundaryWords() throws {
        struct Row {
            let name: String
            let format: UInt16
            let isBind: Bool
            let permitted: UInt64
            let forbidden: UInt64
            let importCount: Int
            let importsFormat: UInt32
            let importAddend: Int64
            let expectedOrdinal: Int
            let positiveTarget: UInt64
            let negativeTarget: UInt64
        }
        let plain = MachOConstants.dyldChainedImport
        let withAddend = MachOConstants.dyldChainedImportAddend
        let rows = [
            Row(name: "format1 rebase", format: 1, isBind: false, permitted: 0x0000_0400_0000_0000,
                forbidden: 0x0000_0c00_0000_0000, importCount: 1, importsFormat: plain, importAddend: 0,
                expectedOrdinal: 0, positiveTarget: 0x0400_0000_0000, negativeTarget: 0x0100_0400_0000_0000),
            Row(name: "format2 rebase", format: 2, isBind: false, permitted: 0x0000_0008_0000_0000,
                forbidden: 0x0000_0018_0000_0000, importCount: 1, importsFormat: plain, importAddend: 0,
                expectedOrdinal: 0, positiveTarget: 0x8_0000_0000, negativeTarget: 0x0100_0008_0000_0000),
            Row(name: "format1 bind", format: 1, isBind: true, permitted: 0x4008_0000_0000_8000,
                forbidden: 0x4008_0000_0001_8000, importCount: 32769, importsFormat: plain, importAddend: 0,
                expectedOrdinal: 32768, positiveTarget: 0, negativeTarget: 0),
            Row(name: "format2 bind", format: 2, isBind: true, permitted: 0x8010_0000_8000_0000,
                forbidden: 0x8010_0001_8000_0000, importCount: 1, importsFormat: withAddend, importAddend: -128,
                expectedOrdinal: 0, positiveTarget: 0, negativeTarget: 0),
        ]
        for row in rows {
            for positive in [true, false] {
                let label = "\(row.name) \(positive ? "permitted" : "first forbidden bit")"
                let word = positive ? row.permitted : row.forbidden
                let initialBind: UInt64 = row.format == 1 ? 0x4008_0000_0000_0000 : 0x8010_0000_0000_0000
                let fixture = MachOFixture.makeExecutableWithChainedFixupChain(
                    importsFormat: row.importsFormat, imageBase: imageBase, pointerFormat: row.format,
                    rebaseRawOverride: row.isBind ? 0 : word,
                    importCount: row.importCount, importAddend: row.importAddend)
                var bytes = fixture.bytes
                try inject(row.isBind ? word : initialBind, at: fixture.chainedBindAddress, into: &bytes)
                try inject(row.isBind ? 0 : word, at: fixture.chainedRebaseAddress, into: &bytes)

                let result = try MachOParser().parseWithFixupCoverage(bytes)
                XCTAssertTrue(result.coverage.refusalReasons.isEmpty, label)
                if positive {
                    XCTAssertTrue(result.coverage.fixupRefusalReasons.isEmpty, label)
                } else {
                    XCTAssertEqual(result.coverage.fixupRefusalReasons, [.unsupportedFixup], label)
                }
                XCTAssertFalse(result.coverage.fixupRefusalReasons.contains(.ambiguousBind), label)
                XCTAssertFalse(result.coverage.fixupRefusalReasons.contains(.missingDeclaration), label)

                let fixups = try XCTUnwrap(result.file.dyldChainedFixups, label).fixups
                XCTAssertEqual(fixups.count, 2, label)
                guard fixups.count == 2 else { continue }
                let bind = fixups[0], terminal = fixups[1]
                if row.isBind {
                    XCTAssertEqual(bind.kind, .bind(importOrdinal: row.expectedOrdinal, symbolName: "_puts", addend: 0),
                                   label)
                } else {
                    XCTAssertEqual(bind.kind, .bind(importOrdinal: 0, symbolName: "_puts", addend: 0), label)
                    XCTAssertEqual(terminal.kind,
                                   .rebase(targetAddress: positive ? row.positiveTarget : row.negativeTarget), label)
                }
            }
        }
    }

    // MARK: TC05

    func testPageWalkerLiteralGeometry() throws {
        func segment() -> MachOSegment {
            MachOSegment(name: "__DATA", vmAddress: 0x10000, vmSize: 0x1000, fileOffset: 0, fileSize: 0x1000,
                         maxProtection: 3, initialProtection: 3, sectionCount: 0, flags: 0)
        }
        func page(_ words: [UInt64]) -> Data {
            var data = Data(count: 0x1000)
            for (word, at) in zip(words, [0x10, 0x18, 0x40]) { writeUInt64(word, into: &data, at: at) }
            return data
        }
        struct Seen: Equatable { var offset: UInt64; var address: UInt64; var raw: UInt64 }
        func walk(_ data: Data, format: UInt16) throws -> (seen: [Seen], visited: Set<UInt64>) {
            var visited = Set<UInt64>()
            var seen: [Seen] = []
            try MachOParser().walkChainedPage(
                data: data, segment: segment(), pageSize: 0x1000, pageOffset: 0, first: 0x10,
                format: format, visited: &visited) { link in
                seen.append(Seen(offset: link.fileOffset, address: link.address, raw: link.raw))
            }
            return (seen, visited)
        }
        let offsets: [UInt64] = [0x10, 0x18, 0x40]
        let addresses: [UInt64] = [0x10010, 0x10018, 0x10040]

        // Format 1: stride 8, auth bit 63 set on purpose; next fields 1 and 5.
        let format1: [UInt64] = [0x8008_0000_0000_1234, 0x8028_0000_0000_1234, 0x8000_0000_0000_1234]
        let first = try walk(page(format1), format: 1)
        XCTAssertEqual(first.seen.map(\.offset), offsets)
        XCTAssertEqual(first.seen.map(\.address), addresses)
        XCTAssertEqual(first.seen.map(\.raw), format1)
        XCTAssertEqual(first.visited, Set(offsets))

        // Format 2: stride 4; next fields 2 and 10.
        let format2: [UInt64] = [0x0010_0000_0000_1234, 0x0050_0000_0000_1234, 0x0000_0000_0000_1234]
        let second = try walk(page(format2), format: 2)
        XCTAssertEqual(second.seen.map(\.offset), offsets)
        XCTAssertEqual(second.seen.map(\.address), addresses)
        XCTAssertEqual(second.seen.map(\.raw), format2)
        XCTAssertEqual(second.visited, Set(offsets))

        // Format 2 short delta: next 1 at stride 4 is below the 8-byte minimum. The visitor
        // ran for the first link before the refusal.
        var short = Set<UInt64>()
        var shortSeen: [UInt64] = []
        do {
            try MachOParser().walkChainedPage(
                data: page([0x0008_0000_0000_1234, 0, 0]), segment: segment(), pageSize: 0x1000, pageOffset: 0,
                first: 0x10, format: 2, visited: &short) { shortSeen.append($0.fileOffset) }
            XCTFail("a 4-byte delta must be refused")
        } catch let issue as ChainedPageWalkIssue {
            XCTAssertEqual(issue, .malformed)
        }
        XCTAssertEqual(shortSeen, [0x10])
        XCTAssertEqual(short, [0x10])

        // Unsupported format 0: pins the internal compatibility geometry (generic next12,
        // stride 4) only; it asserts no parser support for the format.
        let direct = try walk(page(format2), format: 0)
        XCTAssertEqual(direct.seen.map(\.offset), offsets)
        XCTAssertEqual(direct.seen.map(\.address), addresses)
        XCTAssertEqual(direct.visited, Set(offsets))
    }
}
