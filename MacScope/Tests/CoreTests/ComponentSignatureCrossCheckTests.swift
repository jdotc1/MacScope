// AR2 test-only cross-check (SPEC 28). The legacy observations are hand-built values of the same legacy types, so no
// legacy parser is run and no synthetic image has to satisfy it. Production cross-checking is notPerformed (AQ5).

import Foundation
import XCTest
@testable import MacScope

final class ComponentSignatureCrossCheckTests: XCTestCase {
    private let dictionaryXML = SigFx.xml("<true/>")

    private struct Case {
        let image: [UInt8]
        let strict: CE.SignatureSliceEvidence
        let digest: [UInt8]
    }

    private func make(region: [UInt8]?, duplicateCommand: Bool = false, cpu: UInt32 = 0x0100000c) throws -> Case {
        let image = SigFx.thin(region, cpu: cpu, duplicateCommand: duplicateCommand)
        let slice = try SigFx.capture(image).slices[0]
        guard case .complete(_, let bytes, _) = slice.sliceSHA256 else { throw CE.SignatureCaptureError.invalidEvidence(.digestWithoutSource) }
        return Case(image: image, strict: slice, digest: bytes)
    }

    private var signedRegion: [UInt8] {
        SigFx.superBlob([(0, SigFx.codeDirectory(hashSize: 32, hashType: 2)), (5, SigFx.blob(SigFx.xmlMagic, dictionaryXML))])
    }

    /// Legacy blobs shaped from the strict slot table, with the summaries a lenient reader would produce.
    private func legacyBlobs(_ strict: CE.SignatureSliceEvidence, keys: [String] = ["key"], parsed: Bool = true) -> [MachOCodeSignatureBlob] {
        (strict.slots.value ?? []).map { slot in
            var directory: MachOCodeDirectorySummary?
            var entitlements: MachOCodeSignatureEntitlementsSummary?
            if slot.slot == 0 {
                directory = MachOCodeDirectorySummary(version: 0x20000, flags: 0, hashOffset: 46, identifierOffset: 44, specialSlotCount: 0,
                                                      codeSlotCount: 0, codeLimit: 0, hashSize: 32, hashType: 2, platform: 0, pageSize: 12,
                                                      identifier: "a", teamIdentifier: nil)
            } else if slot.slot == 5 {
                entitlements = MachOCodeSignatureEntitlementsSummary(format: .xml, keyCount: keys.count, keys: keys, isParsed: parsed)
            }
            return MachOCodeSignatureBlob(type: slot.slot, relativeOffset: slot.offset, fileOffset: 0, magic: slot.magic, length: slot.length,
                                          codeDirectory: directory, entitlements: entitlements)
        }
    }

    private func legacySignature(_ blobs: [MachOCodeSignatureBlob]) -> MachOCodeSignature {
        MachOCodeSignature(dataOffset: 128, dataSize: 0, superBlob: MachOCodeSignatureSuperBlob(magic: 0xfade0cc0, length: 0, blobCount: UInt32(blobs.count), blobs: blobs))
    }

    private func metadata(xml: [UInt8]? = nil, keys: [String] = ["key"]) -> CE.LegacyMetadataObservation {
        .summary(MachOLoadMetadata.CodeSignatureInfo(entitlementsFormat: "XML", entitlementsXML: String(decoding: xml ?? dictionaryXML, as: UTF8.self),
                                                     entitlementsKeyCount: keys.count, entitlementsKeys: keys, entitlementsParsed: true))
    }

    private func compare(_ item: Case, strict: CE.LegacyStrictObservation, metadata: CE.LegacyMetadataObservation,
                         digest: [UInt8]? = nil) -> CE.SignatureCrossCheckResult {
        CE.SignatureCrossCheck.compare(sliceBytes: item.image, key: item.strict.key, expectedSliceSHA256: digest ?? item.digest,
                                       strict: item.strict, legacyStrict: strict, legacyMetadata: metadata)
    }

    func testAgreementLegsAreComparedAndLenientLegsStayNotCovered() throws {
        let item = try make(region: signedRegion)
        XCTAssertEqual(item.strict.state, .collected)
        let result = compare(item, strict: .accepted(legacySignature(legacyBlobs(item.strict))), metadata: metadata())
        XCTAssertEqual(result.differences, [])
        for leg in [CE.SignatureCheckLeg.sliceBinding, .structuralAdmission, .slotInventory, .entitlementSummary, .codeDirectorySummary, .entitlementValues] {
            XCTAssertEqual(result.coverage(of: leg), .compared, "\(leg)")
        }
        for leg in [CE.SignatureCheckLeg.digestCorrectness, .lenientCodeDirectory, .lenientDERValue] {
            guard case .notCovered? = result.coverage(of: leg) else { return XCTFail("\(leg) must stay NOT COVERED") }
        }
        XCTAssertEqual(result.sliceSHA256, item.digest)
    }

    func testLegacyAcceptedWhereStrictRefuses() throws {
        let item = try make(region: SigFx.g, duplicateCommand: true)
        XCTAssertEqual(item.strict.state, .malformed(.signatureCommandDuplicate))
        let blob = MachOCodeSignatureBlob(type: 5, relativeOffset: 20, fileOffset: 0, magic: SigFx.xmlMagic, length: 9, codeDirectory: nil, entitlements: nil)
        let result = compare(item, strict: .accepted(legacySignature([blob])), metadata: .summary(nil))
        XCTAssertEqual(result.differences, [.legacyAcceptedStrictRefusal(.signatureCommandDuplicate)])
        XCTAssertEqual(result.coverage(of: .slotInventory), .notPerformed(reason: "strictRefusal"))
    }

    func testLegacyRejectedWhereStrictAccepts() throws {
        let item = try make(region: signedRegion)
        let result = compare(item, strict: .rejected(reason: "legacy refused"), metadata: .rejected(reason: "legacy refused"))
        XCTAssertTrue(result.differences.contains(.legacyRejectedStrictAccepted(legacyReason: "legacy refused")))
        XCTAssertEqual(result.coverage(of: .slotInventory), .notPerformed(reason: "legacyRejected"))
    }

    func testValueDisagreementKeepsBothSidesVisible() throws {
        let item = try make(region: signedRegion)
        let other = SigFx.xml("<false/>")
        let result = compare(item, strict: .accepted(legacySignature(legacyBlobs(item.strict))), metadata: metadata(xml: other))
        XCTAssertEqual(result.differences, [.valueDisagreement(form: .xml)])
    }

    func testCanonicallyEquivalentKeysAreProjectionLossNotDisagreement() throws {
        let composed = "\u{e9}", decomposed = "e\u{301}"
        let document = SigFx.xmlDocument("<dict><key>\(composed)</key><true/><key>\(decomposed)</key><true/></dict>")
        let item = try make(region: SigFx.superBlob([(5, SigFx.blob(SigFx.xmlMagic, document))]))
        let strictKeys = CE.RawEntitlementAdapter.decodeXML(document).dictionary?.entries.map(\.key)
        XCTAssertEqual(strictKeys?.count, 2, "both original spellings must survive the strict decode")
        let blobs = legacyBlobs(item.strict, keys: [composed], parsed: true)
        let result = compare(item, strict: .accepted(legacySignature(blobs)), metadata: .summary(nil))
        XCTAssertTrue(result.differences.contains(.legacyProjectionLoss(field: "xml.keys")))
        XCTAssertFalse(result.differences.contains(.summaryDisagreement(field: "xml.keys")))
    }

    func testDigestMismatchAndUnexaminedSlicesAreNotPerformedAndNeverAgreement() throws {
        let item = try make(region: signedRegion)
        let wrong = compare(item, strict: .accepted(legacySignature(legacyBlobs(item.strict))), metadata: metadata(),
                            digest: [UInt8](repeating: 0, count: 32))
        XCTAssertEqual(wrong.coverage(of: .sliceBinding), .notPerformed(reason: "sliceBytesDigestMismatch"))
        XCTAssertEqual(wrong.coverage(of: .slotInventory), .notPerformed(reason: "sliceBytesDigestMismatch"))
        XCTAssertTrue(wrong.differences.isEmpty)
        let intel = try make(region: signedRegion, cpu: 0x01000007)
        XCTAssertEqual(intel.strict.state, .unexamined(.unsupportedArchitecture))
        let result = compare(intel, strict: .accepted(nil), metadata: .summary(nil))
        XCTAssertEqual(result.coverage(of: .structuralAdmission), .notPerformed(reason: "strictEvidenceNotExamined"))
        XCTAssertTrue(result.differences.isEmpty)
    }

    func testProductionNotRetainedReasonIsStable() {
        XCTAssertEqual(CE.SignatureCrossCheck.notRetainedReason, "boundedCaptureDoesNotRetainWholeSliceForLegacyParser")
    }
}
