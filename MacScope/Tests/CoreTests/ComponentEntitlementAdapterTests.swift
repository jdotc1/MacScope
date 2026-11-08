// AR2 raw entitlement adapter and read guard tests (SPEC 10-12, 20, 21, 29). Forms are decoded independently;
// disagreement keeps both dictionaries; XML observations never claim lossless source keys (ruling O6).

import Foundation
import XCTest
@testable import MacScope

final class ComponentEntitlementAdapterTests: XCTestCase {
    private func evidence(xml: [UInt8]? = nil, der: [UInt8]? = nil) throws -> (CE.SignatureSliceEvidence, CE.SignatureEvidenceAttachment, CE.SignatureEvidenceKey) {
        var entries: [(slot: UInt32, blob: [UInt8])] = []
        if let xml { entries.append((5, SigFx.blob(SigFx.xmlMagic, xml))) }
        if let der { entries.append((7, SigFx.blob(SigFx.derMagic, der))) }
        let image = SigFx.thin(entries.isEmpty ? nil : SigFx.superBlob(entries))
        let capture = try SigFx.capture(image)
        let path = CEHarness.path("Contents/MacOS/Main")
        let inventoryID = UUID()
        let attachment = try CE.SignatureEvidenceAttachment(inventoryID: inventoryID, entries: [(path, capture)])
        let key = CE.SignatureEvidenceKey(inventoryID: inventoryID, componentID: path, slice: capture.slices[0].key)
        return (capture.slices[0], attachment, key)
    }

    private func convert(xml: [UInt8]? = nil, der: [UInt8]? = nil) throws -> CE.AttributedEntitlementResult {
        let (slice, _, key) = try evidence(xml: xml, der: der)
        return CE.RawEntitlementAdapter.convert(slice: slice, key: key)
    }

    func testEachFormDecodesIndependentlyAndEquivalentFormsAgree() throws {
        let result = try convert(xml: SigFx.xml("<true/>"), der: SigFx.der(true))
        guard case .bothEquivalent = result.agreement else { return XCTFail("\(result.agreement)") }
        XCTAssertEqual(result.xml?.sourceKeyFidelity, .notProvedForFoundationXML)
        XCTAssertEqual(result.der?.sourceKeyFidelity, .exactUTF8Bytes)
        XCTAssertNotNil(result.xml?.dictionary)
        XCTAssertNotNil(result.der?.dictionary)
        guard case .xmlOnly = try convert(xml: SigFx.xml()).agreement else { return XCTFail("xml only") }
        guard case .derOnly = try convert(der: SigFx.der()).agreement else { return XCTFail("der only") }
    }

    func testDifferentFormsKeepBothDictionariesWithoutAWinner() throws {
        let result = try convert(xml: SigFx.xml("<true/>"), der: SigFx.der(false))
        guard case .bothDifferent = result.agreement else { return XCTFail("\(result.agreement)") }
        XCTAssertNotNil(result.xml?.dictionary)
        XCTAssertNotNil(result.der?.dictionary)
        XCTAssertNotEqual(result.xml?.dictionary, result.der?.dictionary)
    }

    func testBooleanAndIntegerStayDifferentValues() {
        let boolean = CE.RawEntitlementAdapter.decodeXML(SigFx.xml("<true/>")).dictionary
        let integer = CE.RawEntitlementAdapter.decodeXML(SigFx.xml("<integer>1</integer>")).dictionary
        XCTAssertNotNil(boolean)
        XCTAssertNotNil(integer)
        XCTAssertNotEqual(boolean, integer)
    }

    func testOneFailedFormDoesNotHideTheOther() throws {
        let broken = try convert(xml: Array("not a plist".utf8), der: SigFx.der(true))
        guard case .oneUnavailable(let available, let failed) = broken.agreement else { return XCTFail("\(broken.agreement)") }
        XCTAssertEqual(available, .der)
        XCTAssertEqual(failed, .xml)
        guard case .onlyFormUnavailable(.xml) = try convert(xml: Array("not a plist".utf8)).agreement else { return XCTFail("only form") }
        guard case .bothUnavailable = try convert(xml: Array("x".utf8), der: [0xff]).agreement else { return XCTFail("both") }
    }

    func testUnsignedAndEntitlementFreeSlicesAreNotPresentNeverEmptyDictionaries() throws {
        let unsigned = try convert()
        XCTAssertTrue(unsigned.isNotPresent)
        XCTAssertNil(unsigned.xml)
        XCTAssertNil(unsigned.der)
        let image = SigFx.thin(SigFx.superBlob([(0, SigFx.codeDirectory(hashSize: 32, hashType: 2))]))
        let slice = try SigFx.capture(image).slices[0]
        let key = CE.SignatureEvidenceKey(inventoryID: UUID(), componentID: CEHarness.path("a"), slice: slice.key)
        XCTAssertTrue(CE.RawEntitlementAdapter.convert(slice: slice, key: key).isNotPresent)
    }

    func testDERRefusalsAreTypedAndExact() {
        XCTAssertNotNil(CE.RawEntitlementAdapter.decodeDER(SigFx.derEmpty).dictionary)
        guard case .unavailable(.malformedDER) = CE.RawEntitlementAdapter.decodeDER([0x31, 0x05]).state else { return XCTFail("truncated") }
        // Duplicate keys are a refusal, never a merge.
        let entry: [UInt8] = [0x30, 0x08, 0x0c, 0x03, 0x6b, 0x65, 0x79, 0x01, 0x01, 0xff]
        let duplicate: [UInt8] = [0x31, UInt8(entry.count * 2)] + entry + entry
        guard case .unavailable(.duplicateKey) = CE.RawEntitlementAdapter.decodeDER(duplicate).state else { return XCTFail("duplicate") }
    }

    func testPayloadBoundsAreTypedLimitsNotPartialDictionaries() {
        let large = [UInt8](repeating: 0x20, count: CE.RawEntitlementAdapter.payloadBound + 1)
        guard case .unavailable(.limit(.payloadBytes)) = CE.RawEntitlementAdapter.decodeXML(large).state else { return XCTFail("xml payload") }
        guard case .unavailable(.limit(.payloadBytes)) = CE.RawEntitlementAdapter.decodeDER(large).state else { return XCTFail("der payload") }
        var keys = ""
        for index in 0..<257 { keys += "<key>k\(index)</key><true/>" }
        guard case .unavailable(.limit(.rootKeys)) = CE.RawEntitlementAdapter.decodeXML(SigFx.xmlDocument("<dict>\(keys)</dict>")).state else {
            return XCTFail("root keys")
        }
        var nested = "<true/>"
        for _ in 0..<20 { nested = "<array>\(nested)</array>" }
        guard case .unavailable(.limit(.depth)) = CE.RawEntitlementAdapter.decodeXML(SigFx.xmlDocument("<dict><key>k</key>\(nested)</dict>")).state else {
            return XCTFail("depth")
        }
        let booleans = String(repeating: "<true/>", count: 5000)
        guard case .unavailable(.limit(.nodes)) = CE.RawEntitlementAdapter.decodeXML(SigFx.xmlDocument("<dict><key>k</key><array>\(booleans)</array></dict>")).state else {
            return XCTFail("nodes")
        }
    }

    func testReadGuardOrderIdentityAndCancellation() throws {
        let (slice, attachment, key) = try evidence(xml: SigFx.xml(), der: SigFx.der())
        // Success runs the adapter once, revalidates, and returns the attributed result.
        var adapterRuns = 0, revalidations = 0
        let result = try CE.EntitlementReadGuard.read(attachment: attachment, key: key, isCancelled: { false }, revalidate: { revalidations += 1 }) {
            adapterRuns += 1
            return CE.RawEntitlementAdapter.convert(slice: $0, key: key)
        }
        XCTAssertEqual(result.key, key)
        XCTAssertEqual(adapterRuns, 1)
        XCTAssertEqual(revalidations, 1)
        // A key that is not a member of the attachment fails before the adapter runs.
        let altered = CE.SignatureEvidenceKey(inventoryID: key.inventoryID, componentID: key.componentID,
            slice: CE.SignatureSliceKey(index: 0, cpuType: key.slice.cpuType, cpuSubtype: 9, headerMagic: key.slice.headerMagic,
                                        sliceOffset: key.slice.sliceOffset, sliceSize: key.slice.sliceSize))
        var ran = false
        XCTAssertThrowsError(try CE.EntitlementReadGuard.read(attachment: attachment, key: altered, isCancelled: { false }, revalidate: {}) {
            ran = true
            return CE.RawEntitlementAdapter.convert(slice: $0, key: altered)
        }) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .wrongSlice) }
        XCTAssertFalse(ran)
        // An adapter that returns another slice's identity is refused after revalidation.
        let other = CE.SignatureEvidenceKey(inventoryID: key.inventoryID, componentID: CEHarness.path("other"), slice: key.slice)
        XCTAssertThrowsError(try CE.EntitlementReadGuard.read(attachment: attachment, key: key, isCancelled: { false }, revalidate: {}) {
            CE.RawEntitlementAdapter.convert(slice: $0, key: other)
        }) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .wrongSlice) }
        // Cancellation at each barrier publishes nothing; a changed input from revalidation propagates.
        XCTAssertThrowsError(try CE.EntitlementReadGuard.read(attachment: attachment, key: key, isCancelled: { true }, revalidate: {}) {
            CE.RawEntitlementAdapter.convert(slice: $0, key: key)
        }) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .cancelled) }
        var cancelled = false
        XCTAssertThrowsError(try CE.EntitlementReadGuard.read(attachment: attachment, key: key, isCancelled: { cancelled }, revalidate: {}) {
            cancelled = true
            return CE.RawEntitlementAdapter.convert(slice: $0, key: key)
        }) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .cancelled) }
        XCTAssertThrowsError(try CE.EntitlementReadGuard.read(attachment: attachment, key: key, isCancelled: { false }, revalidate: { throw CE.SignatureCaptureError.changedInput }) {
            CE.RawEntitlementAdapter.convert(slice: $0, key: key)
        }) { XCTAssertEqual($0 as? CE.SignatureCaptureError, .changedInput) }
        _ = slice
    }
}
