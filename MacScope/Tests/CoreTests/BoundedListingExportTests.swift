import Foundation
import XCTest
@testable import MacScope

/// New synthetic fixtures; source staged only.
final class BoundedListingExportTests: XCTestCase {
    private func fixture() -> WorkspaceSnapshot {
        let rows = [
            InstructionRow(address: 0x1000, bytes: "1f 20 03 d5", mnemonic: "nop", operands: "",
                           hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "",
                           hasBreakpoint: false, comment: nil)
        ]
        var snapshot = WorkspaceSnapshot(binaries: [], functions: [], instructions: rows,
                                         xrefs: [], hexBytes: Data())
        snapshot.sections = [SectionSummary(id: UUID(), name: "__TEXT,<text>", address: 0x1000,
                                            size: 8, fileOffset: 0, isExecutable: true)]
        snapshot.addressOverrides = [
            ImageAddress.primary(0x1000): AddressOverride(customName: "name<&\"'", customComment: "line1\nline2\n"),
            ImageAddress.primary(0x1004): AddressOverride(isUndefined: true)
        ]
        return snapshot
    }

    func testBoundedTextMatchesLegacyResolvedRowsAndOverrides() throws {
        let snapshot = fixture()
        let listing = DisassemblyListingBuilder.buildResolved(snapshot: snapshot, slot: snapshot.primarySlot)
        let result = try DocumentExportService().renderBoundedListing(
            rows: listing.rows, resolved: listing.resolved, format: .plainText, limits: .init())
        XCTAssertTrue(result.isComplete)
        XCTAssertEqual(result.consumedRows, listing.rows.count)
        XCTAssertEqual(result.text, DocumentExportService().renderListing(snapshot: snapshot))
        XCTAssertTrue(result.text.contains("undefined"))
        XCTAssertTrue(result.text.contains("; line1\n; line2\n; "))
    }

    func testHTMLEscapesCanonicalTextWithoutExecutingMarkup() throws {
        let rows: [ListingRow] = [.prefixComment(.init(address: 1, text: "<script>x&\"'\r</script>"))]
        let result = try DocumentExportService().renderBoundedListing(
            rows: rows, resolved: [:], format: .html, limits: .init())
        XCTAssertTrue(result.isComplete)
        XCTAssertTrue(result.text.contains("; &lt;script&gt;x&amp;&quot;&#39;&#13;&lt;/script&gt;"))
        XCTAssertFalse(result.text.contains("<script>"))
        XCTAssertTrue(result.text.hasSuffix("</code></pre></body></html>"))
        XCTAssertTrue(result.text.contains("font:10pt Arial"))
    }

    func testHTMLAndTextRetainSameCanonicalContent() throws {
        let snapshot = fixture()
        let listing = DisassemblyListingBuilder.buildResolved(snapshot: snapshot)
        let service = DocumentExportService()
        let text = try service.renderBoundedListing(rows: listing.rows, resolved: listing.resolved,
                                                   format: .plainText, limits: .init())
        let html = try service.renderBoundedListing(rows: listing.rows, resolved: listing.resolved,
                                                   format: .html, limits: .init())
        let pre = try XCTUnwrap(html.text.range(of: "<code>"))
        let end = try XCTUnwrap(html.text.range(of: "</code>"))
        let unescaped = String(html.text[pre.upperBound..<end.lowerBound])
            .replacingOccurrences(of: "&#13;", with: "\r")
            .replacingOccurrences(of: "&#39;", with: "'")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&amp;", with: "&")
        XCTAssertEqual(unescaped, text.text)
        XCTAssertEqual(html.consumedRows, text.consumedRows)
    }

    func testRowLimitAndOutputLimitDoNotSplitCanonicalRows() throws {
        let rows: [ListingRow] = [.label(.init(address: 1, name: "a", isFunctionStart: false)),
                                 .prefixComment(.init(address: 2, text: "first\nsecond"))]
        let rowBound = try DocumentExportService().renderBoundedListing(
            rows: rows, resolved: [:], format: .plainText, limits: .init(maximumRows: 1))
        XCTAssertFalse(rowBound.isComplete)
        XCTAssertEqual(rowBound.stopReason, .rowLimit)
        XCTAssertEqual(rowBound.consumedRows, 1)
        XCTAssertEqual(rowBound.text, "a:")
        let byteBound = try DocumentExportService().renderBoundedListing(
            rows: rows, resolved: [:], format: .plainText, limits: .init(maximumUTF8Bytes: 5))
        XCTAssertEqual(byteBound.stopReason, .outputByteLimit)
        XCTAssertEqual(byteBound.consumedRows, 1)
        XCTAssertEqual(byteBound.text, "a:", "No dangling separator or partial comment row")
        XCTAssertEqual(byteBound.inputRowCount, 2)
    }

    func testInputFieldLimitAndUnsupportedHTMLControlsRefuseBeforeRow() throws {
        let rows: [ListingRow] = [.prefixComment(.init(address: 1, text: "12345"))]
        let result = try DocumentExportService().renderBoundedListing(
            rows: rows, resolved: [:], format: .plainText,
            limits: .init(maximumInputFieldUTF8Bytes: 4))
        XCTAssertEqual(result.stopReason, .inputFieldLimit)
        XCTAssertEqual(result.consumedRows, 0)
        XCTAssertEqual(result.text, "")
        let control: [ListingRow] = [.prefixComment(.init(address: 1, text: "\u{0}"))]
        let html = try DocumentExportService().renderBoundedListing(
            rows: control, resolved: [:], format: .html, limits: .init())
        XCTAssertEqual(html.stopReason, .unsupportedHTMLControl)
        XCTAssertEqual(html.consumedRows, 0)
        XCTAssertTrue(html.text.hasSuffix("<pre><code></code></pre></body></html>"))
    }

    func testExactUTF8ByteBudgetAndInvalidLimits() throws {
        let rows: [ListingRow] = [.label(.init(address: 1, name: "é", isFunctionStart: false))]
        let service = DocumentExportService()
        let fits = try service.renderBoundedListing(rows: rows, resolved: [:], format: .plainText,
                                                    limits: .init(maximumUTF8Bytes: 3))
        XCTAssertTrue(fits.isComplete)
        XCTAssertEqual(fits.text.utf8.count, 3)
        let short = try service.renderBoundedListing(rows: rows, resolved: [:], format: .plainText,
                                                     limits: .init(maximumUTF8Bytes: 2))
        XCTAssertEqual(short.stopReason, .outputByteLimit)
        XCTAssertThrowsError(try DocumentExportService.ListingLimits(maximumRows: 0))
        XCTAssertThrowsError(try DocumentExportService.ListingLimits(maximumUTF8Bytes: 8_388_609))
        XCTAssertThrowsError(try DocumentExportService.ListingLimits(maximumInputFieldUTF8Bytes: 65_537))
        XCTAssertThrowsError(try service.renderBoundedListing(rows: [], resolved: [:], format: .html,
                                                             limits: .init(maximumUTF8Bytes: 1)))
    }

    func testHTMLExpansionIsIncludedInByteBudget() throws {
        let service = DocumentExportService()
        let empty = try service.renderBoundedListing(rows: [], resolved: [:], format: .html, limits: .init())
        let rows: [ListingRow] = [.label(.init(address: 1, name: "&&", isFunctionStart: false))]
        let exact = try service.renderBoundedListing(rows: rows, resolved: [:], format: .html,
            limits: .init(maximumUTF8Bytes: empty.text.utf8.count + 11))
        XCTAssertTrue(exact.isComplete)
        XCTAssertTrue(exact.text.contains("&amp;&amp;:"))
        let short = try service.renderBoundedListing(rows: rows, resolved: [:], format: .html,
            limits: .init(maximumUTF8Bytes: empty.text.utf8.count + 10))
        XCTAssertEqual(short.stopReason, .outputByteLimit)
        XCTAssertEqual(short.text, empty.text)
    }

    func testCancellationDoesNotReturnACompletedOrPartialArtifact() throws {
        enum Cancelled: Error { case synthetic }
        var checks = 0
        let rows: [ListingRow] = [.label(.init(address: 1, name: "first", isFunctionStart: false)),
                                 .label(.init(address: 2, name: "second", isFunctionStart: false))]
        XCTAssertThrowsError(try DocumentExportService().renderBoundedListing(
            rows: rows, resolved: [:], format: .plainText, limits: .init(), checkCancellation: {
                checks += 1
                if checks == 3 { throw Cancelled.synthetic }
            })) { XCTAssertTrue($0 is Cancelled) }
        XCTAssertEqual(checks, 3)
    }

    func testResolvedFocusedImageRowsDoNotBorrowPrimaryOverrides() throws {
        let secondary = ImageSlot(rawValue: 1)
        var primary = ImageAnalysis()
        primary.instructions = [.init(address: 0x1000, bytes: "1f 20 03 d5", mnemonic: "nop",
                                      operands: "", hasBreakpoint: false, comment: nil)]
        primary.functions = [.init(id: UUID(), name: "primary_function", startAddress: 0x1000,
                                   endAddress: 0x1004, confidence: 1)]
        var sibling = ImageAnalysis()
        sibling.instructions = [.init(address: 0x1000, bytes: "c0 03 5f d6", mnemonic: "ret",
                                      operands: "", hasBreakpoint: false, comment: nil)]
        sibling.functions = [.init(id: UUID(), name: "sibling_function", startAddress: 0x1000,
                                   endAddress: 0x1004, confidence: 1)]
        var snapshot = WorkspaceSnapshot(binaries: [
            BinaryImage(id: UUID(), name: "Primary", path: "/synthetic/primary", kind: "Mach-O",
                        architecture: "arm64", slot: .primary),
            BinaryImage(id: UUID(), name: "Sibling", path: "/synthetic/sibling", kind: "Mach-O",
                        architecture: "arm64", slot: secondary)
        ], analysisBySlot: [.primary: primary, secondary: sibling])
        snapshot.addressOverrides[.primary(0x1000)] = AddressOverride(customName: "primary_name")
        snapshot.addressOverrides[ImageAddress(slot: secondary, address: 0x1000)] =
            AddressOverride(customName: "sibling_name", customComment: "sibling evidence")
        let rows = DisassemblyListingBuilder.buildResolved(snapshot: snapshot, slot: secondary)
        let service = DocumentExportService()
        let result = try service.renderBoundedListing(rows: rows.rows, resolved: rows.resolved,
                                                     format: .plainText, limits: .init())
        XCTAssertEqual(result.text, service.renderListing(snapshot: snapshot, in: secondary))
        XCTAssertTrue(result.text.contains("sibling_name:"))
        XCTAssertTrue(result.text.contains("sibling evidence"))
        XCTAssertFalse(result.text.contains("primary_name"))
        XCTAssertFalse(result.text.contains("nop"))
    }

}
