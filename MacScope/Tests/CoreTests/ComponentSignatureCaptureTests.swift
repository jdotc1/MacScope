// AR2 capture tests over in-memory images through the reader's descriptor-independent read seam, plus one
// sink test that runs the real AR1 capture over a private temporary bundle. Typed literals only; no sleeps, no network.
// SPEC ids covered: 1, 2, 3, 5 (image level), 6, 7, 8, 22, 23, 24, 26 and 27. Ids 9a to 9c, 25 and the AC procedure are
// listed NOT COVERED in the lane verdict.

import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import MacScope

final class ComponentSignatureCaptureTests: XCTestCase {
    private let xmlBlob = SigFx.defaultXMLBlob
    private let derBlob = SigFx.defaultDERBlob

    private var defaultRegion: [UInt8] { SigFx.superBlob([(5, xmlBlob), (7, derBlob)]) }

    private func only(_ evidence: CE.SignatureEvidence, file: StaticString = #filePath, line: UInt = #line) -> CE.SignatureSliceEvidence {
        XCTAssertEqual(evidence.slices.count, 1, file: file, line: line)
        return evidence.slices[0]
    }

    /// SPEC 1: default XML and DER blobs are retained as exact complete bytes with exact offsets and digests.
    func testRawXMLAndDERRemainExactBytes() throws {
        let image = SigFx.thin(defaultRegion, subtype: 0x80000002)
        let evidence = try SigFx.capture(image)
        let slice = only(evidence)
        XCTAssertEqual(slice.state, .collected)
        XCTAssertEqual(evidence.completion, .complete)
        XCTAssertEqual(slice.key.cpuSubtype, 0x80000002)
        XCTAssertEqual(slice.slots.value?.map(\.slot), [5, 7])
        let region = try XCTUnwrap(slice.signature.value)
        XCTAssertEqual(region.bytes, defaultRegion)
        XCTAssertEqual(region.sliceRelativeOffset, 128)
        XCTAssertEqual(region.containerOffset, 128)
        XCTAssertEqual(region.sha256, SigFx.sha256(defaultRegion))
        let xml = try XCTUnwrap(slice.entitlementsXML.value), der = try XCTUnwrap(slice.entitlementsDER.value)
        XCTAssertEqual(xml.bytes, xmlBlob)
        XCTAssertEqual(der.bytes, derBlob)
        XCTAssertEqual(xml.containerOffset, 156)
        XCTAssertEqual(der.containerOffset, 167)
        XCTAssertEqual(xml.sha256, SigFx.sha256(xmlBlob))
        XCTAssertEqual(der.sha256, SigFx.sha256(derBlob))
        XCTAssertEqual(slice.sliceSHA256.hex, SigFx.sha256(image).map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined())
        XCTAssertEqual(evidence.containerSHA256, slice.sliceSHA256)
        // Decoding failures cannot change raw collected evidence into absence.
        XCTAssertNil(RawEntitlementAdapter_decodeXML(xml).dictionary)
        XCTAssertEqual(slice.state, .collected)
    }

    private func RawEntitlementAdapter_decodeXML(_ blob: CE.SignatureBlobEvidence) -> CE.EntitlementFormObservation {
        CE.RawEntitlementAdapter.decodeXML(blob.payload)
    }

    /// SPEC 2: fat slices keep exact offsets; Intel and other unsupported slices are unexamined, not absent.
    func testUniversalSlicesAndIntelStayExact() throws {
        let unsigned = SigFx.thin(nil), arm64e = SigFx.thin(defaultRegion, subtype: 0x80000002)
        let intel = SigFx.thin(defaultRegion, cpu: 0x01000007, subtype: 3)
        let image = SigFx.fat([unsigned, arm64e, intel])
        let evidence = try SigFx.capture(image)
        XCTAssertEqual(evidence.slices.map(\.key.sliceOffset), [4096, 8192, 12288])
        XCTAssertEqual(evidence.slices.map(\.state), [.signatureAbsent, .collected, .unexamined(.unsupportedArchitecture)])
        XCTAssertEqual(evidence.slices[1].signature.value?.containerOffset, 8320)
        XCTAssertEqual(evidence.slices[2].signature, .unavailable(.unsupportedArchitecture))
        XCTAssertEqual(evidence.slices[2].entitlementsXML, .unavailable(.unsupportedArchitecture))
        XCTAssertEqual(evidence.slices[2].codeDirectories, .unavailable(.unsupportedArchitecture))
        XCTAssertEqual(evidence.slices[2].sliceSHA256, .complete(algorithm: .sha256, bytes: SigFx.sha256(intel),
                                                                 source: SigFx.range(12288, 12288 + UInt64(intel.count))))
    }

    /// SPEC 3: unsigned, signed without an entitlement slot, and a short CodeDirectory stay three different things.
    func testUnsignedVersusNoEntitlementSlotVersusShortCodeDirectory() throws {
        for subtype: UInt32 in [0, 1] {
            let slice = only(try SigFx.capture(SigFx.thin(nil, subtype: subtype)))
            XCTAssertEqual(slice.state, .signatureAbsent)
            XCTAssertEqual(slice.signature, .notPresent)
        }
        let signed = only(try SigFx.capture(SigFx.thin(SigFx.superBlob([(0, SigFx.codeDirectory(hashSize: 32, hashType: 2))]))))
        XCTAssertEqual(signed.state, .entitlementsAbsent)
        XCTAssertNotNil(signed.signature.value)
        XCTAssertEqual(signed.entitlementsXML, .notPresent)
        XCTAssertEqual(signed.entitlementsDER, .notPresent)
        XCTAssertEqual(signed.codeDirectories.value?.count, 1)
        let short = only(try SigFx.capture(SigFx.thin(SigFx.superBlob([(0, SigFx.blob(SigFx.cdMagic, [1, 2]))]))))
        XCTAssertEqual(short.codeDirectories.value?.first?.digest, .unavailable(.codeDirectoryHeaderTruncated))
    }

    /// SPEC 5 (image level): a duplicate signature command and structural refusals stay explicit and never become absence.
    func testMalformedCommandsAndRegionsStayExplicit() throws {
        let duplicate = only(try SigFx.capture(SigFx.thin(SigFx.g, duplicateCommand: true)))
        XCTAssertEqual(duplicate.state, .malformed(.signatureCommandDuplicate))
        XCTAssertEqual(duplicate.signature, .unavailable(.structureRefused(.signatureCommandDuplicate)))
        var outside = SigFx.thin(SigFx.g)
        outside.replaceSubrange(32 + 8..<32 + 12, with: SigFx.le([UInt32.max]))
        XCTAssertEqual(only(try SigFx.capture(outside)).state, .malformed(.signatureRangeOutsideSlice))
        var overlapping = SigFx.thin(SigFx.g)
        overlapping.replaceSubrange(32 + 8..<32 + 12, with: SigFx.le([16]))
        XCTAssertEqual(only(try SigFx.capture(overlapping)).state, .malformed(.signatureRangeOverlapsCommands))
        let truncated = only(try SigFx.capture(SigFx.thin(Array(SigFx.g.prefix(11)))))
        XCTAssertEqual(truncated.state, .malformed(.superBlobHeaderTruncated))
        XCTAssertEqual(truncated.slots, .unavailable(.structureRefused(.superBlobHeaderTruncated)))
        XCTAssertNotNil(truncated.signature.value)
    }

    /// SPEC 6: caps make the capture PARTIAL, name the limit, and never turn unread fields into absence.
    func testBudgetsNeverBecomeAbsence() throws {
        var limits = CE.SignatureEvidenceLimits()
        limits.signatureBytes = 28
        let capped = try SigFx.capture(SigFx.thin(SigFx.g), limits: limits)
        let slice = only(capped)
        XCTAssertEqual(slice.state, .budgetExceeded(.signatureBytes))
        XCTAssertEqual(slice.signature, .unavailable(.capReached(.signatureBytes)))
        XCTAssertEqual(capped.ledger.signatureBytesRead, 0)
        guard case .partial(let partial) = capped.completion else { return XCTFail("expected PARTIAL") }
        XCTAssertEqual(partial.knownMismatches, [.limitReached(.signatureBytes)])
        XCTAssertTrue(partial.remainderUnknown)
        XCTAssertEqual(partial.observedOmittedSliceCount, 1)
        XCTAssertNil(partial.observedOmittedIndexedBlobCount)

        // Slot cap: the whole raw signature is retained, no slot is parsed, and the declared count is recorded.
        var slotLimits = CE.SignatureEvidenceLimits()
        slotLimits.slots = 1
        let slots = only(try SigFx.capture(SigFx.thin(defaultRegion), limits: slotLimits))
        XCTAssertEqual(slots.state, .budgetExceeded(.slots))
        XCTAssertEqual(slots.signature.value?.bytes, defaultRegion)
        XCTAssertEqual(slots.slots, .unavailable(.capReached(.slots)))
        XCTAssertEqual(slots.entitlementsXML, .unavailable(.capReached(.slots)))

        // Aggregate cap: the first slice keeps its signature, the second is budgetExceeded.
        var aggregate = CE.SignatureEvidenceLimits()
        aggregate.totalSignatureBytes = 29
        let image = SigFx.fat([SigFx.thin(SigFx.g, subtype: 0), SigFx.thin(SigFx.g, subtype: 2)])
        let both = try SigFx.capture(image, limits: aggregate)
        XCTAssertEqual(both.slices.map(\.state), [.collected, .budgetExceeded(.totalSignatureBytes)])
        XCTAssertEqual(both.slices[1].signature, .unavailable(.capReached(.totalSignatureBytes)))
    }

    /// SPEC 7: one 64 KiB streaming pass equals the direct digest across chunk boundaries.
    func testStreamingHashAcrossChunkBoundaries() throws {
        let tail = (0..<150_000).map { UInt8($0 % 256) }
        let image = SigFx.thin(SigFx.g) + tail
        var reads: [(UInt64, Int)] = []
        let evidence = try SigFx.capture(image, read: { offset, count in
            reads.append((offset, count))
            return Array(image[Int(offset)..<Int(offset) + count])
        })
        XCTAssertEqual(evidence.containerSHA256.hex, SigFx.sha256(image).map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined())
        XCTAssertEqual(evidence.slices[0].sliceSHA256, evidence.containerSHA256.withSource(of: evidence.slices[0]))
        XCTAssertEqual(evidence.ledger.bytesHashed, UInt64(image.count))
        XCTAssertEqual(evidence.ledger.signatureBytesRead, 29)
        XCTAssertTrue(reads.filter { $0.1 == 65_536 }.count >= 2, "the hash pass must use 64 KiB chunks")
        XCTAssertEqual(reads.filter { $0.0 == 128 && $0.1 == 29 }.count, 1)
    }

    /// SPEC 8: cancellation publishes nothing, including a cancellation raised at the final commit boundary.
    func testCancelledCapturePublishesNothing() throws {
        XCTAssertThrowsError(try SigFx.capture(SigFx.thin(nil), isCancelled: { true })) {
            XCTAssertEqual($0 as? CE.SignatureCaptureError, .cancelled)
        }
        let image = SigFx.thin(SigFx.g)
        var cancelled = false
        XCTAssertThrowsError(try SigFx.capture(image, isCancelled: { cancelled }, read: { offset, count in
            if offset == 128 { cancelled = true }
            return Array(image[Int(offset)..<Int(offset) + count])
        })) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .cancelled) }
        var committing = false
        XCTAssertThrowsError(try SigFx.capture(image, isCancelled: { committing }, revalidate: { committing = true })) {
            XCTAssertEqual($0 as? CE.SignatureCaptureError, .cancelled)
        }
    }

    /// SPEC 22: keys carry index, CPU, full subtype, magic, offset and size; no lookup by architecture string.
    func testKeysAreNumericAndBindOnlyTheirOwnBytes() throws {
        for wide in [false, true] {
            let first = SigFx.thin(SigFx.superBlob([(5, SigFx.blob(SigFx.xmlMagic, SigFx.xml("<true/>")))]), subtype: 0)
            let second = SigFx.thin(SigFx.superBlob([(5, SigFx.blob(SigFx.xmlMagic, SigFx.xml("<false/>")))]), subtype: 0x80000002)
            let image = SigFx.fat([first, second], wide: wide)
            let evidence = try SigFx.capture(image)
            XCTAssertEqual(evidence.slices.map(\.key), [
                CE.SignatureSliceKey(index: 0, cpuType: 0x0100000c, cpuSubtype: 0, headerMagic: 0xcffaedfe, sliceOffset: 4096, sliceSize: UInt64(first.count)),
                CE.SignatureSliceKey(index: 1, cpuType: 0x0100000c, cpuSubtype: 0x80000002, headerMagic: 0xcffaedfe, sliceOffset: 8192, sliceSize: UInt64(second.count)),
            ])
            let path = CEHarness.path("Contents/MacOS/Main")
            let inventoryID = UUID()
            let attachment = try CE.SignatureEvidenceAttachment(inventoryID: inventoryID, entries: [(path, evidence)])
            let keys = evidence.slices.map { CE.SignatureEvidenceKey(inventoryID: inventoryID, componentID: path, slice: $0.key) }
            XCTAssertEqual(attachment.slice(for: keys[1])?.key, evidence.slices[1].key)
            XCTAssertEqual(attachment.key(componentID: path, sliceIndex: 1), keys[1])
            XCTAssertNotEqual(attachment.slice(for: keys[0])?.entitlementsXML.value?.bytes, attachment.slice(for: keys[1])?.entitlementsXML.value?.bytes)
            // Changing any key field fails; another inventory or component never joins.
            let altered = CE.SignatureSliceKey(index: 1, cpuType: 0x0100000c, cpuSubtype: 2, headerMagic: 0xcffaedfe,
                                               sliceOffset: 8192, sliceSize: UInt64(second.count))
            XCTAssertNil(attachment.slice(for: CE.SignatureEvidenceKey(inventoryID: inventoryID, componentID: path, slice: altered)))
            XCTAssertNil(attachment.slice(for: CE.SignatureEvidenceKey(inventoryID: UUID(), componentID: path, slice: keys[1].slice)))
            XCTAssertNil(attachment.slice(for: CE.SignatureEvidenceKey(inventoryID: inventoryID, componentID: CEHarness.path("Contents/MacOS/Other"), slice: keys[1].slice)))
        }
        // Padding outside every slice changes only the container hash.
        let base = SigFx.fat([SigFx.thin(SigFx.g), SigFx.thin(nil, subtype: 2)])
        var padded = base
        padded[3000] = 0x5a
        let left = try SigFx.capture(base), right = try SigFx.capture(padded)
        XCTAssertNotEqual(left.containerSHA256, right.containerSHA256)
        XCTAssertEqual(left.slices.map(\.sliceSHA256), right.slices.map(\.sliceSHA256))
    }

    /// SPEC 23: distinct complete CodeDirectory records per slice with the canonical digest of the whole blob.
    func testCodeDirectoryRecordsAndCanonicalDigest() throws {
        let first = SigFx.codeDirectory(hashSize: 32, hashType: 2), second = SigFx.codeDirectory(hashSize: 32, hashType: 2, identifier: 0x62)
        let image = SigFx.fat([SigFx.thin(SigFx.superBlob([(0, first)]), subtype: 0), SigFx.thin(SigFx.superBlob([(0, second)]), subtype: 2)])
        let evidence = try SigFx.capture(image)
        let records = try evidence.slices.map { try XCTUnwrap($0.codeDirectories.value?.first) }
        XCTAssertEqual(records.map(\.byteCount), [46, 46])
        XCTAssertEqual(records.map(\.hashSize), [32, 32])
        XCTAssertEqual(records.map(\.hashType), [2, 2])
        XCTAssertEqual(records.map(\.rawBlobSHA256), [SigFx.sha256(first), SigFx.sha256(second)])
        XCTAssertNotEqual(records[0].regionRange, SigFx.range(0, 0))
        XCTAssertEqual(records[0].digest, .available(CE.CodeDirectoryDigest(algorithm: .sha256, fullBytes: SigFx.sha256(first))))
        XCTAssertEqual(records[1].digest, .available(CE.CodeDirectoryDigest(algorithm: .sha256, fullBytes: SigFx.sha256(second))))
        XCTAssertNotEqual(records[0].rawBlobSHA256, records[1].rawBlobSHA256)
    }

    /// SPEC 24: primary and five alternates by slot (ruling O1 digests); table order never decides the role.
    func testPrimaryAndAlternatesFollowTheirSlotsAndOwnerRulingDigests() throws {
        let blobs: [(slot: UInt32, blob: [UInt8])] = [
            (0x1004, SigFx.codeDirectory(hashSize: 32, hashType: 2, identifier: 0x62)),
            (0x1003, SigFx.codeDirectory(hashSize: 32, hashType: 255)),
            (0x1002, SigFx.codeDirectory(hashSize: 48, hashType: 4)),
            (0x1001, SigFx.codeDirectory(hashSize: 20, hashType: 3)),
            (0x1000, SigFx.codeDirectory(hashSize: 20, hashType: 1)),
            (0, SigFx.codeDirectory(hashSize: 32, hashType: 2)),
        ]
        let records = try XCTUnwrap(only(try SigFx.capture(SigFx.thin(SigFx.superBlob(blobs)))).codeDirectories.value)
        XCTAssertEqual(records.map(\.slot), [0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004])
        XCTAssertEqual(records.map(\.role), [.primary, .alternate(0), .alternate(1), .alternate(2), .alternate(3), .alternate(4)])
        let byBlob = Dictionary(uniqueKeysWithValues: blobs.map { ($0.slot, $0.blob) })
        XCTAssertEqual(records[0].digest, .available(.init(algorithm: .sha256, fullBytes: SigFx.sha256(byBlob[0]!))))
        XCTAssertEqual(records[1].digest, .available(.init(algorithm: .sha1, fullBytes: Array(Insecure.SHA1.hash(data: byBlob[0x1000]!)))))
        XCTAssertEqual(records[2].digest, .available(.init(algorithm: .sha256Truncated20, fullBytes: SigFx.sha256(byBlob[0x1001]!))))
        guard case .available(let truncated) = records[2].digest else { return XCTFail("type 3 must produce a digest") }
        XCTAssertEqual(truncated.derivedCDHash, Array(SigFx.sha256(byBlob[0x1001]!).prefix(20)))
        XCTAssertEqual(truncated.fullBytes.count, 32)
        XCTAssertEqual(records[3].digest, .available(.init(algorithm: .sha384, fullBytes: Array(SHA384.hash(data: byBlob[0x1002]!)))))
        XCTAssertEqual(records[4].digest, .unavailable(.unsupportedDigestAlgorithm(255)))
        XCTAssertEqual(records[4].hashType, 255)
        // A duplicate alternate is rejected by the parser, not collapsed.
        let duplicate = SigFx.superBlob([(0x1000, SigFx.codeDirectory(hashSize: 32, hashType: 2)), (0x1000, SigFx.codeDirectory(hashSize: 32, hashType: 2, identifier: 0x62))])
        XCTAssertEqual(only(try SigFx.capture(SigFx.thin(duplicate))).state, .malformed(.duplicateSlotType(0x1000)))
    }

    /// SPEC 26: a read fault at the signature offset or in the hash pass is a typed capture-wide fault; nothing is published.
    func testReadFaultsThrowTypedErrors() throws {
        let image = SigFx.thin(SigFx.g)
        XCTAssertThrowsError(try SigFx.capture(image, read: { offset, count in
            if offset == 128 { throw CE.EvidenceError.io(.read, errno: EIO, .wholeRoot) }
            return Array(image[Int(offset)..<Int(offset) + count])
        })) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .unavailable(.read, errno: EIO, range: SigFx.range(128, 157))) }
        XCTAssertThrowsError(try SigFx.capture(image, read: { offset, count in
            if offset == 128 { return Array(image[128..<156]) }
            return Array(image[Int(offset)..<Int(offset) + count])
        })) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .shortRead(range: SigFx.range(128, 157), expected: 29, actual: 28)) }
        XCTAssertThrowsError(try SigFx.capture(image, read: { offset, count in
            if offset == 0 && count == image.count { throw CE.EvidenceError.io(.read, errno: EIO, .wholeRoot) }
            return Array(image[Int(offset)..<Int(offset) + count])
        })) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .unavailable(.read, errno: EIO, range: SigFx.range(0, UInt64(image.count)))) }
        XCTAssertEqual(CE.SignatureCaptureError.unavailable(.read, errno: EIO, range: nil).readFailure, .readFailed(.readError(errno: EIO)))
    }

    /// SPEC 27: reached caps are PARTIAL and name the limit, the ranges actually read and hashed, and unknown counts.
    func testCapsReportRangesCountsAndUnknowns() throws {
        // Container cap before any read.
        var container = CE.SignatureEvidenceLimits()
        container.containerHashBytes = 1
        let blocked = try SigFx.capture(SigFx.thin(nil), limits: container)
        guard case .partial(let first) = blocked.completion else { return XCTFail("expected PARTIAL") }
        XCTAssertEqual(first.successfullyReadRanges, [])
        XCTAssertEqual(first.hashedContainerRange, SigFx.range(0, 0))
        XCTAssertEqual(first.losses.first?.limit, .containerHashBytes)
        XCTAssertEqual(blocked.containerSHA256, .unavailable(.capReached(.containerHashBytes)))
        XCTAssertTrue(blocked.slices.isEmpty)
        XCTAssertTrue(first.remainderUnknown)
        // Header cap after the first eight bytes.
        var header = CE.SignatureEvidenceLimits()
        header.headerBytes = 8
        let starved = try SigFx.capture(SigFx.thin(nil), limits: header)
        guard case .partial(let second) = starved.completion else { return XCTFail("expected PARTIAL") }
        XCTAssertEqual(second.successfullyReadRanges, [SigFx.range(0, 8)])
        XCTAssertEqual(second.losses.first?.limit, .headerBytes)
        XCTAssertNil(second.observedOmittedSliceCount)
        // A declared slice count above the cap carries the declared count separately and no identities.
        let declared = SigFx.be([0xcafebabe, 65])
        let overflow = try SigFx.capture(declared)
        XCTAssertEqual(overflow.declaredSliceCount, 65)
        XCTAssertTrue(overflow.slices.isEmpty)
        guard case .partial(let third) = overflow.completion else { return XCTFail("expected PARTIAL") }
        XCTAssertEqual(third.knownMismatches, [.declaredSliceCountAboveCap(declared: 65), .limitReached(.slices)])
        XCTAssertNil(third.observedOmittedSliceCount)
        XCTAssertEqual(third.losses.first?.attempted, 65)
        XCTAssertEqual(third.losses.first?.basis, .declaredHeaderDomain)
    }

    /// SPEC 9b and 9c in spirit: fat layout defects throw typed container errors and publish nothing.
    func testInvalidFatLayoutsThrow() throws {
        let valid = SigFx.fat([SigFx.thin(nil)])
        var count = valid
        count.replaceSubrange(4..<8, with: SigFx.be([2]))
        XCTAssertThrowsError(try SigFx.capture(count)) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .invalidContainer(.invalidFatLayout)) }
        var subtype = valid
        subtype.replaceSubrange(12..<16, with: SigFx.be([2]))
        XCTAssertThrowsError(try SigFx.capture(subtype)) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .invalidContainer(.fatSliceIdentityMismatch)) }
        var overlap = SigFx.fat([SigFx.thin(nil), SigFx.thin(nil, subtype: 2)])
        overlap.replaceSubrange(28..<32, with: SigFx.be([4096]))
        XCTAssertThrowsError(try SigFx.capture(overlap)) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .invalidContainer(.fatSliceIdentityMismatch)) }
    }
}

private extension CE.DigestObservation {
    /// The same digest with a different source range, used to compare a whole-input slice digest with the container digest.
    func withSource(of slice: CE.SignatureSliceEvidence) -> CE.DigestObservation {
        guard case .complete(let algorithm, let bytes, _) = self, case .complete(_, _, let source) = slice.sliceSHA256 else { return self }
        return .complete(algorithm: algorithm, bytes: bytes, source: source)
    }
}
