// AR3 slice 2 (NF12, NF16, NF17, NF21, NF22, NF23). Signature evidence is captured from synthesized in-memory byte
// images through the AR2 reader seam; nothing here opens, loads or executes a binary. Expected values are literal.

import Foundation
import XCTest
@testable import MacScope

private enum SigImages {
    static func signed(xml: String? = "<true/>", der: Bool? = nil, cpu: UInt32 = 0x0100000c) -> [UInt8] {
        var entries: [(slot: UInt32, blob: [UInt8])] = []
        if let xml { entries.append((5, SigFx.blob(SigFx.xmlMagic, SigFx.xml(xml)))) }
        if let der { entries.append((7, SigFx.blob(SigFx.derMagic, SigFx.der(der)))) }
        return SigFx.thin(SigFx.superBlob(entries), cpu: cpu)
    }
    static func evidence(_ bytes: [UInt8]) throws -> CE.SignatureEvidence { try SigFx.capture(bytes) }
}

final class ComponentEvidenceSecurityDeltaSignatureTests: XCTestCase {
    private typealias F = SDFx

    private func spec(_ evidence: CE.SignatureEvidence?) -> SDFx.Spec { F.Spec(path: F.main, kind: "app", evidence: evidence) }

    func testEntitlementValueChangeIsObservedPerKeyAndIdenticalEvidenceIsUnchanged() throws {
        let before = try SigImages.evidence(SigImages.signed(xml: "<true/>"))
        let after = try SigImages.evidence(SigImages.signed(xml: "<false/>"))
        let changed = F.report(try F.analyze([spec(before)], [spec(after)]))
        let rows = F.rows(changed, .entitlements).filter { F.text($0.subject).hasSuffix("/key") }
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.disposition, .observedChange)
        XCTAssertEqual(rows.first?.previousValue, .boolean(true))
        XCTAssertEqual(rows.first?.currentValue, .boolean(false))
        XCTAssertTrue(changed.findings.contains { $0.kind == .signatureEvidenceChanged })

        let same = F.report(try F.analyze([spec(before)], [spec(before)]))
        XCTAssertTrue(F.rows(same, .signatureEvidence).allSatisfy { $0.disposition == .unchanged })
        XCTAssertFalse(same.findings.contains { $0.kind == .signatureEvidenceChanged })
    }

    func testEntitlementKeyAddedAndRemovedAcrossSides() throws {
        let one = try SigImages.evidence(SigImages.signed(xml: "<true/>"))
        let none = try SigImages.evidence(SigImages.signed(xml: nil, der: nil))
        let report = F.report(try F.analyze([spec(one)], [spec(none)]))
        let gone = F.rows(report, .entitlements).filter { F.text($0.subject).hasSuffix("/key") }
        XCTAssertEqual(gone.first?.disposition, .observedRemoval)
        XCTAssertEqual(gone.first?.previousValue, .boolean(true))
    }

    func testMissingEvidenceIsSymmetricUnexaminedOrUnresolvedNeverAbsence() throws {
        let evidence = try SigImages.evidence(SigImages.signed())
        let neither = F.report(try F.analyze([spec(nil)], [spec(nil)]))
        XCTAssertTrue(F.rows(neither, .signatureEvidence).allSatisfy { $0.disposition == .unchanged && $0.previousState == .unexamined })
        let oneSided = F.report(try F.analyze([spec(evidence)], [spec(nil)]))
        let rows = F.rows(oneSided, .signatureEvidence)
        XCTAssertFalse(rows.isEmpty)
        XCTAssertTrue(rows.allSatisfy { $0.disposition == .unresolved })
        XCTAssertFalse(oneSided.findings.contains { $0.kind == .signatureEvidenceChanged })
    }

    func testSlicePairingUsesExactNumericKeyAndAddedSliceNeedsCompleteContainer() throws {
        let thin = try SigImages.evidence(SigImages.signed())
        let fat = try SigImages.evidence(SigFx.fat([SigImages.signed(), SigImages.signed(xml: "<true/>", cpu: 0x01000007)]))
        XCTAssertEqual(fat.slices.count, 2)
        let report = F.report(try F.analyze([spec(thin)], [F.Spec(path: F.main, kind: "app", architectures: ["arm64", "x86_64"], evidence: fat)]))
        let sliceRows = F.rows(report, .signatureEvidence)
        XCTAssertTrue(sliceRows.contains { $0.disposition == .observedAddition && F.text($0.subject).hasPrefix("slice[cpu=01000007") })
        XCTAssertTrue(sliceRows.contains { F.text($0.subject).hasPrefix("slice[cpu=0100000c") && $0.disposition == .unchanged })
    }

    func testObservationsAreReportedInStableByteOrder() throws {
        let evidence = try SigImages.evidence(SigImages.signed(xml: "<true/>", der: true))
        let report = F.report(try F.analyze([spec(evidence)], [spec(evidence)]))
        let subjects = F.rows(report, .signatureEvidence).map { F.text($0.subject) }
        XCTAssertEqual(subjects, subjects.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) })
    }
}

final class ComponentEvidenceSecurityDeltaEntitlementEvidenceTests: XCTestCase {
    private typealias F = SDFx

    private func diff(_ a: KeyValuePairs<String, EntitlementValue>, _ b: KeyValuePairs<String, EntitlementValue>,
                      typed: Bool = false) -> [SDelta.EntitlementDelta.Row] {
        SDelta.EntitlementDelta.diff(previous: F.dict(a), current: F.dict(b), previousTyped: typed, currentTyped: typed)
    }

    func testKeyTablesAreMergedInByteOrder() {
        let rows = diff(["b": .boolean(true), "a": .string("x"), "z": .boolean(true)],
                        ["a": .string("y"), "c": .boolean(true), "z": .boolean(true)])
        XCTAssertEqual(rows.map { F.text($0.key) }, ["a", "b", "c", "z"])
        XCTAssertEqual(rows.map(\.kind), [.changed, .removed, .added, .unchanged])
    }

    func testIntegersWithoutProvenWidthAreNormalizedAndEqualAcrossSignedness() {
        let rows = diff(["n": .integer(5)], ["n": .unsignedInteger(5)])
        XCTAssertEqual(rows.first?.kind, .unchanged)
        XCTAssertEqual(rows.first?.previous, .normalizedInteger("5"))
    }

    func testTypedDERIntegersKeepTheirWidth() {
        let rows = diff(["n": .integer(5)], ["n": .integer(6)], typed: true)
        XCTAssertEqual(rows.first?.kind, .changed)
        XCTAssertEqual(rows.first?.previous, .signed(5))
        XCTAssertEqual(rows.first?.current, .signed(6))
    }

    func testNonFiniteRealIsUnresolvedNotCompared() {
        let rows = diff(["r": .real(.nan)], ["r": .real(1)])
        XCTAssertEqual(rows.first?.kind, .unresolved)
    }

    func testNestedDictionaryOrderDoesNotMatter() {
        let a = EntitlementValue.dictionary(F.dict(["x": .boolean(true), "y": .boolean(false)]))
        let b = EntitlementValue.dictionary(F.dict(["y": .boolean(false), "x": .boolean(true)]))
        XCTAssertEqual(diff(["d": a], ["d": b]).first?.kind, .unchanged)
    }
}

final class ComponentEvidenceSecurityDeltaPagerTests: XCTestCase {
    private typealias F = SDFx

    private func report(count: Int) throws -> SDelta.Report {
        var before: [String: EntitlementValue] = [:], after: [String: EntitlementValue] = [:]
        for index in 0..<count { before["k\(String(format: "%03d", index))"] = .boolean(true); after["k\(String(format: "%03d", index))"] = .boolean(false) }
        return F.report(try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(EntitlementDictionary(before)))],
                                      [F.Spec(path: F.main, kind: "app", info: .present(EntitlementDictionary(after)))]))
    }

    func testValueProjectionIsLosslessAndTagged() throws {
        let big = SDelta.Pager.value(.unsigned(UInt64.max))
        XCTAssertEqual(try big.jsonData(), try ScriptValue.object(["type": .string("unsigned"), "value": .string("18446744073709551615")]).jsonData())
        let text = SDelta.Pager.text(SDelta.ExactKey(text: "A"))
        XCTAssertEqual(text, .object(["utf8": .string("QQ==")]))
    }

    func testPagesWalkAllRowsExactlyOnceWithOpaqueCursor() throws {
        let report = try report(count: 7)
        var seen = 0
        var cursor: String?
        var pages = 0
        repeat {
            let page = try SDelta.Pager.page(report: report, section: .observations, cursor: cursor, limit: 3)
            XCTAssertEqual(page.total, report.observations.count)
            XCTAssertLessThanOrEqual(page.byteCount, SDelta.Pager.pageByteCap)
            seen += page.items.count; cursor = page.nextCursor; pages += 1
        } while cursor != nil
        XCTAssertEqual(seen, report.observations.count)
        XCTAssertEqual(pages, (report.observations.count + 2) / 3)
    }

    func testInvalidLimitMalformedStaleAndOutOfBoundsCursorsAreNamedRefusals() throws {
        let report = try report(count: 2)
        func code(_ cursor: String?, _ limit: Int?) -> SDelta.RefusalCode? {
            do { _ = try SDelta.Pager.page(report: report, section: .observations, cursor: cursor, limit: limit); return nil }
            catch let refusal as SDelta.Refusal { return refusal.code } catch { return nil }
        }
        XCTAssertEqual(code(nil, 0), .invalidOptions)
        XCTAssertEqual(code(nil, 257), .invalidOptions)
        XCTAssertEqual(code("garbage", nil), .malformedInput)
        XCTAssertEqual(code(String(repeating: "a", count: 1025), nil), .malformedInput)
        XCTAssertEqual(code("\(UUID().uuidString).observations.0", nil), .staleCursor)
        XCTAssertEqual(code("\(report.reportID.uuidString).findings.0", nil), .malformedInput)
        XCTAssertEqual(code("\(report.reportID.uuidString).observations.99", nil), .outOfBounds)
        XCTAssertNil(code("\(report.reportID.uuidString).observations.\(report.observations.count)", nil))
    }

    func testRefusalDiagnosticIsBoundedAndCarriesNoReportBody() throws {
        let refusal = SDelta.Refusal.make(.cancelled)
        let diagnostic = SDelta.Pager.diagnostic(for: refusal)
        XCTAssertEqual(diagnostic, .object(["refused": .bool(true), "code": .string("cancelled")]))
        XCTAssertLessThan(try diagnostic.jsonData().count, SDelta.Pager.diagnosticCeiling)
    }
}
