// AR2 parser tests: SPEC ids 4 and 13 through 19 over the strict all-slot range walk. Byte fixtures are synthesized here.
// The SigFx helpers are shared by the other three AR2 test files; they build bytes only and never execute or load anything.

import CryptoKit
import Foundation
import XCTest
@testable import MacScope

/// Byte fixtures (design section 5): B blobs, S superblobs, G, T thin images, F and F64 fat images, X, E and C records.
enum SigFx {
    static let xmlMagic: UInt32 = 0xfade7171
    static let derMagic: UInt32 = 0xfade7172
    static let cdMagic: UInt32 = 0xfade0c02

    static func be(_ values: [UInt32]) -> [UInt8] { CEBytes.be32(values) }
    static func le(_ values: [UInt32]) -> [UInt8] { CEBytes.le32(values) }
    static func be64(_ value: UInt64) -> [UInt8] { (0..<8).map { UInt8((value >> UInt64((7 - $0) * 8)) & 0xff) } }

    /// B(m, p): magic, length 8 plus the payload length, then the payload.
    static func blob(_ magic: UInt32, _ payload: [UInt8]) -> [UInt8] { be([magic, UInt32(8 + payload.count)]) + payload }

    /// S: magic, total length, count, index entries, then the blobs consecutively in table order.
    static func superBlob(_ entries: [(slot: UInt32, blob: [UInt8])]) -> [UInt8] {
        var offset = 12 + 8 * entries.count
        var table: [UInt8] = [], body: [UInt8] = []
        for entry in entries {
            table += be([entry.slot, UInt32(offset)])
            body += entry.blob
            offset += entry.blob.count
        }
        return be([0xfade0cc0, UInt32(offset), UInt32(entries.count)]) + table + body
    }

    /// G: slot 5, B(0xfade7171, 01). Index end 20, blob length 9, declared length 29.
    static var g: [UInt8] { superBlob([(5, blob(xmlMagic, [1]))]) }

    static func xml(_ element: String = "<true/>") -> [UInt8] {
        Array(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>key</key>" + element + "</dict></plist>").utf8)
    }
    static func xmlDocument(_ body: String) -> [UInt8] {
        Array(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\">" + body + "</plist>").utf8)
    }
    /// E(v): the historical set envelope; the current envelope is separate and never a fallback.
    static func der(_ value: Bool = true) -> [UInt8] { [0x31, 0x0a, 0x30, 0x08, 0x0c, 0x03, 0x6b, 0x65, 0x79, 0x01, 0x01, value ? 0xff : 0x00] }
    static let derCurrent: [UInt8] = [0x70, 0x0f, 0x02, 0x01, 0x01, 0xb0, 0x0a, 0x30, 0x08, 0x0c, 0x03, 0x6b, 0x65, 0x79, 0x01, 0x01, 0xff]
    static let derEmpty: [UInt8] = [0x31, 0x00]
    static let defaultXMLBlob = blob(xmlMagic, [0xff, 0x00, 0x61])
    static let defaultDERBlob = blob(derMagic, [0x00, 0xff, 0x00, 0x7f])

    /// C(h, t): the 46-byte CodeDirectory. `identifier` is the ASCII byte before the NUL (a, or b for Cb).
    static func codeDirectory(hashSize: UInt8, hashType: UInt8, identifier: UInt8 = 0x61) -> [UInt8] {
        be([cdMagic, 46, 0x20000, 0, 46, 44, 0, 0, 0]) + [hashSize, hashType, 0, 12] + [0, 0, 0, 0] + [identifier, 0]
    }

    /// T: thin 64-bit little-endian image. A nil region is unsigned (32 bytes). Signed images keep the region at byte 128.
    static func thin(_ region: [UInt8]? = nil, cpu: UInt32 = 0x0100000c, subtype: UInt32 = 0, duplicateCommand: Bool = false) -> [UInt8] {
        let magic: [UInt8] = [0xcf, 0xfa, 0xed, 0xfe]
        guard let region else { return magic + le([cpu, subtype, 2, 0, 0, 0, 0]) }
        let command = le([0x1d, 16, 128, UInt32(region.count)])
        let commands = duplicateCommand ? command + command : command
        var out = magic + le([cpu, subtype, 2, duplicateCommand ? 2 : 1, UInt32(commands.count), 0, 0]) + commands
        out += [UInt8](repeating: 0, count: 128 - out.count)
        return out + region
    }

    /// F and F64: slice i at (i + 1) * 4096, alignment exponent 12.
    static func fat(_ slices: [[UInt8]], wide: Bool = false) -> [UInt8] {
        var out = be([wide ? 0xcafebabf : 0xcafebabe, UInt32(slices.count)])
        for (index, slice) in slices.enumerated() {
            let cpu = UInt32(slice[4]) | UInt32(slice[5]) << 8 | UInt32(slice[6]) << 16 | UInt32(slice[7]) << 24
            let subtype = UInt32(slice[8]) | UInt32(slice[9]) << 8 | UInt32(slice[10]) << 16 | UInt32(slice[11]) << 24
            let offset = UInt64((index + 1) * 4096)
            if wide { out += be([cpu, subtype]) + be64(offset) + be64(UInt64(slice.count)) + be([12, 0]) }
            else { out += be([cpu, subtype, UInt32(offset), UInt32(slice.count), 12]) }
        }
        for (index, slice) in slices.enumerated() {
            out += [UInt8](repeating: 0, count: (index + 1) * 4096 - out.count)
            out += slice
        }
        return out
    }

    /// Captures an in-memory image through the descriptor-independent reader seam.
    static func capture(_ bytes: [UInt8], limits: CE.SignatureEvidenceLimits = .init(), ledgerLimit: Int = 1_048_576,
                        isCancelled: () -> Bool = { false }, revalidate: () throws -> Void = {},
                        read: ((UInt64, Int) throws -> [UInt8])? = nil) throws -> CE.SignatureEvidence {
        var ledger = CE.ReadLedger(limit: ledgerLimit)
        return try CE.SignatureEvidenceReader.capture(size: UInt64(bytes.count), limits: limits, ledger: &ledger, isCancelled: isCancelled,
                                                      revalidate: revalidate, read: read ?? { offset, count in Array(bytes[Int(offset)..<Int(offset) + count]) })
    }

    static func range(_ start: UInt64, _ end: UInt64) -> CE.ByteRange { CE.ByteRange(uncheckedStart: start, end: end) }
    static func sha256(_ bytes: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: bytes)) }
}

final class ComponentSignatureParserTests: XCTestCase {
    private func parse(_ region: [UInt8], limits: CE.SignatureEvidenceLimits = .init()) throws -> CE.SignatureParseOutcome {
        try CE.BoundedSignatureParser(limits: limits).parse(region: region)
    }

    private func refusal(_ region: [UInt8], file: StaticString = #filePath, line: UInt = #line) throws -> CE.SignatureRefusal? {
        if case .refused(let reason) = try parse(region) { return reason }
        XCTFail("expected a refusal", file: file, line: line)
        return nil
    }

    /// Overlap O: slots 2 and 3, index end 28, a 24-byte blob at 28 and an 8-byte blob inside it at 36; declared length 52.
    private var overlapRegion: [UInt8] {
        var out = SigFx.be([0xfade0cc0, 52, 2, 2, 28, 3, 36])
        out += SigFx.be([0xfade0c01, 24]) + [UInt8](repeating: 0, count: 16)
        out.replaceSubrange(36..<44, with: SigFx.be([0xfade0c01, 8]))
        return out
    }

    func testSimplestValidFixtureIsParsedWithOneSlot() throws {
        guard case .parsed(let parsed) = try parse(SigFx.g) else { return XCTFail("G must parse") }
        XCTAssertEqual(parsed.declaredLength, 29)
        XCTAssertEqual(parsed.trailingByteCount, 0)
        XCTAssertEqual(parsed.slots, [CE.SignatureSlotRecord(index: 0, slot: 5, offset: 20, length: 9, magic: SigFx.xmlMagic)])
    }

    /// SPEC 13: the overlap fixture is exactly overlappingBlobRanges with both slot indices and ranges.
    func testOverlapNamesBothSlotsAndRanges() throws {
        XCTAssertEqual(try refusal(overlapRegion), .overlappingBlobRanges(
            firstIndex: 0, firstRange: SigFx.range(28, 52), secondIndex: 1, secondRange: SigFx.range(36, 44)))
    }

    /// SPEC 14: a repeated slot type is duplicateSlotType; no entry is preferred or merged.
    func testDuplicateSlotTypeIsRefusedWithoutMerging() throws {
        var region = SigFx.be([0xfade0cc0, 44, 2, 2, 28, 2, 36])
        region += SigFx.be([0xfade0c01, 8]) + SigFx.be([0xfade0c01, 8])
        XCTAssertEqual(try refusal(region), .duplicateSlotType(2))
    }

    /// SPEC 15: a count that does not fit the declared length is indexTablePastDeclaredLength, not a slot-budget outcome.
    func testIndexTablePastDeclaredLengthIsCheckedBeforeTheSlotCap() throws {
        let region = SigFx.be([0xfade0cc0, 20, 2]) + [UInt8](repeating: 0, count: 8)
        XCTAssertEqual(region.count, 20)
        XCTAssertEqual(try refusal(region), .indexTablePastDeclaredLength(count: 2, declaredLength: 20))
    }

    /// SPEC 16: a slot offset that points back into the index.
    func testSlotOffsetInsideIndex() throws {
        var region = SigFx.g
        region.replaceSubrange(16..<20, with: SigFx.be([12]))
        XCTAssertEqual(try refusal(region), .slotOffsetInsideIndex(slot: 5, offset: 12))
    }

    /// SPEC 17: the entitlement type and magic must agree in both directions and both forms.
    func testEntitlementTypeMagicMismatchInBothDirections() throws {
        let cases: [(slot: UInt32, magic: UInt32)] = [(5, SigFx.derMagic), (7, SigFx.xmlMagic), (9, SigFx.xmlMagic), (9, SigFx.derMagic)]
        for item in cases {
            let region = SigFx.superBlob([(item.slot, SigFx.blob(item.magic, [1]))])
            XCTAssertEqual(try refusal(region), .entitlementTypeMagicMismatch(slot: item.slot, magic: item.magic), "slot \(item.slot)")
        }
    }

    /// SPEC 18: a blob length that runs past the declared length is exactly blobExtentPastDeclaredLength.
    func testBlobExtentPastDeclaredLength() throws {
        var region = SigFx.g
        region.replaceSubrange(24..<28, with: SigFx.be([10]))
        XCTAssertEqual(region.count, 29)
        XCTAssertEqual(try refusal(region), .blobExtentPastDeclaredLength(slot: 5, offset: 20, length: 10, declaredLength: 29))
    }

    /// SPEC 19: bytes after the declared length are kept and counted, never parsed.
    func testTrailingBytesAreCountedAndLeaveSlotsUnchanged() throws {
        let plain = try parse(SigFx.g)
        let region = SigFx.g + [0xde, 0xad, 0xbe, 0xef]
        guard case .parsed(let parsed) = try parse(region), case .parsed(let base) = plain else { return XCTFail("both must parse") }
        XCTAssertEqual(parsed.slots, base.slots)
        XCTAssertEqual(parsed.trailingByteCount, 4)
        XCTAssertEqual(parsed.regionByteCount, 33)
        XCTAssertEqual(parsed.declaredLength, 29)
    }

    /// SPEC 4: each mutation has its own typed reason; the donor slot-5 alias of the CodeDirectory fails on its magic first.
    func testMixedOverlapAliasAndDuplicateMutations() throws {
        // Alias: both slots at offset 28 with an identical valid non-entitlement blob.
        let alias = SigFx.be([0xfade0cc0, 36, 2, 2, 28, 3, 28]) + SigFx.be([0xfade0c01, 8])
        XCTAssertEqual(try refusal(alias), .overlappingBlobRanges(firstIndex: 0, firstRange: SigFx.range(28, 36),
                                                                   secondIndex: 1, secondRange: SigFx.range(28, 36)))
        // Donor alias: slot 5 pointing at the slot-0 CodeDirectory blob.
        let directory = SigFx.codeDirectory(hashSize: 32, hashType: 2)
        var donor = SigFx.be([0xfade0cc0, UInt32(28 + directory.count), 2, 0, 28, 5, 28]) + directory
        XCTAssertEqual(try refusal(donor), .entitlementTypeMagicMismatch(slot: 5, magic: SigFx.cdMagic))
        donor.replaceSubrange(20..<24, with: SigFx.be([9]))
        XCTAssertEqual(try refusal(donor), .overlappingBlobRanges(firstIndex: 0, firstRange: SigFx.range(28, 28 + UInt64(directory.count)),
                                                                   secondIndex: 1, secondRange: SigFx.range(28, 28 + UInt64(directory.count))))
    }

    /// SPEC 5 (region level): header truncation, magic, lengths and offsets keep their fixed precedence.
    func testMalformedHeadersKeepTheirOwnReasons() throws {
        XCTAssertEqual(try refusal(Array(SigFx.g.prefix(11))), .superBlobHeaderTruncated)
        XCTAssertEqual(try refusal([UInt8](repeating: 0, count: 29)), .superBlobMagicMismatch(observed: 0))
        var detached = SigFx.g
        detached.replaceSubrange(0..<4, with: SigFx.be([0xfade0cc1]))
        XCTAssertEqual(try refusal(detached), .superBlobMagicMismatch(observed: 0xfade0cc1))
        var count = SigFx.g
        count.replaceSubrange(8..<12, with: SigFx.be([UInt32.max]))
        XCTAssertEqual(try refusal(count), .indexTablePastDeclaredLength(count: UInt32.max, declaredLength: 29))
        var declared = SigFx.g
        declared.replaceSubrange(4..<8, with: SigFx.be([UInt32.max]))
        XCTAssertEqual(try refusal(declared), .declaredLengthInvalid(declared: UInt32.max, available: 29))
        var small = SigFx.g
        small.replaceSubrange(4..<8, with: SigFx.be([11]))
        XCTAssertEqual(try refusal(small), .declaredLengthInvalid(declared: 11, available: 29))
        var past = SigFx.g
        past.replaceSubrange(16..<20, with: SigFx.be([30]))
        XCTAssertEqual(try refusal(past), .slotOffsetPastDeclaredLength(slot: 5, offset: 30, declaredLength: 29))
        var atEnd = SigFx.g
        atEnd.replaceSubrange(16..<20, with: SigFx.be([29]))
        XCTAssertEqual(try refusal(atEnd), .blobHeaderTruncated(slot: 5, offset: 29))
        var seven = SigFx.g
        seven.replaceSubrange(24..<28, with: SigFx.be([7]))
        XCTAssertEqual(try refusal(seven), .blobLengthInvalid(slot: 5, length: 7))
    }

    /// The slot cap is a PARTIAL outcome carrying the declared count, never a refusal and never zero.
    func testSlotCapIsCappedWithTheDeclaredCount() throws {
        var limits = CE.SignatureEvidenceLimits()
        limits.slots = 1
        let region = SigFx.superBlob([(5, SigFx.defaultXMLBlob), (7, SigFx.defaultDERBlob)])
        XCTAssertEqual(try parse(region, limits: limits), .capped(.slots, declaredCount: 2))
    }

    func testRegionAboveTheSignatureCapIsCappedBeforeParsing() throws {
        var limits = CE.SignatureEvidenceLimits()
        limits.signatureBytes = 28
        XCTAssertEqual(try parse(SigFx.g, limits: limits), .capped(.signatureBytes, declaredCount: nil))
    }
}
