import XCTest
@testable import MacScope

/// Pure builder and pager tests: authored reports in, exact wire values out. No store, no parser, no AIRS.
final class AIRSReadPagingTests: XCTestCase {
    private func unwindReport(_ findings: [UnwindAuditFinding], identity: MachOSliceArtifactIdentity,
                              function: UInt64? = nil, census: AIRSCensus? = nil) throws -> AIRSReadReport {
        let built = AIRSReadBuilder.unwind(
            report: AIRSReadFixtures.report(identity, findings), census: census,
            context: AIRSReadFixtures.context(function: function))
        return try XCTUnwrap(AIRSReadFixtures.builtReport(built))
    }

    private func pages(_ report: AIRSReadReport, limit: Int) throws -> [ScriptValue] {
        var result: [ScriptValue] = []
        var offset = 0
        let cursor = AIRSReadFixtures.cursorFactory(report)
        while true {
            guard case .page(let page) = AIRSReadPager.page(report: report, offset: offset, limit: limit, makeCursor: cursor) else {
                XCTFail("expected a page at offset \(offset)"); return result
            }
            result.append(page)
            guard let token = page["nextCursor"]?.stringValue else { return result }
            guard case .success(let decoded) = AIRSReadCursor.decode(token) else { XCTFail("bad token"); return result }
            offset = decoded.offset
            if result.count > 600 { XCTFail("runaway"); return result }
        }
    }

    func testUnwindAllFunctionsLimitOne() throws {
        let identity = try AIRSReadFixtures.identity()
        let report = try unwindReport(AIRSReadFixtures.threeFindings(identity), identity: identity)
        let all = try pages(report, limit: 1)
        XCTAssertEqual(all.map { $0["rows"]?.arrayValue?.count }, [1, 1, 1])
        XCTAssertEqual(all.map { $0["total"]?.intValue }, [3, 3, 3])
        XCTAssertEqual(all.map { $0["isTruncated"]?.boolValue }, [true, true, false])
        XCTAssertEqual(all.map { $0["nextCursor"] != .null }, [true, true, false])
        XCTAssertEqual(all.map { $0["returnedBefore"]?.intValue }, [0, 1, 2])
        XCTAssertEqual(all.map { $0["remainingAfter"]?.intValue }, [2, 1, 0])
        let d = report.denominators.fields
        XCTAssertEqual((d["agreement"]?.intValue ?? -1) + (d["inconsistency"]?.intValue ?? -1) + (d["unresolved"]?.intValue ?? -1), 3)
        XCTAssertEqual(all.reduce(0) { $0 + ($1["rows"]?.arrayValue?.count ?? 0) }, 3)
    }

    func testLimitAboveTotalReturnsTerminalPage() throws {
        let identity = try AIRSReadFixtures.identity()
        let report = try unwindReport(AIRSReadFixtures.threeFindings(identity), identity: identity)
        let all = try pages(report, limit: 256)
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all[0]["rows"]?.arrayValue?.count, 3)
        XCTAssertEqual(all[0]["total"]?.intValue, 3)
        XCTAssertEqual(all[0]["isTruncated"]?.boolValue, false)
        XCTAssertEqual(all[0]["nextCursor"], .null)
    }

    func testDuplicateAddressDoesNotSkipID() throws {
        let identity = try AIRSReadFixtures.identity()
        let findings = [
            AIRSReadFixtures.finding(identity, id: "b", start: 0x1000, end: 0x1010),
            AIRSReadFixtures.finding(identity, id: "a", start: 0x1000, end: 0x1010),
            AIRSReadFixtures.finding(identity, id: "c", start: 0x2000, end: 0x2010),
        ]
        let report = try unwindReport(findings, identity: identity)
        let ids = try pages(report, limit: 1).flatMap { page in
            (page["rows"]?.arrayValue ?? []).compactMap { $0["finding"]?["function"]?["id"]?.stringValue }
        }
        XCTAssertEqual(ids, ["a", "b", "c"])
    }

    func testHighUInt64AddressStaysExact() throws {
        let identity = try AIRSReadFixtures.identity()
        let finding = AIRSReadFixtures.finding(identity, id: "high", start: 0xfffffffffffffff0, end: 0xfffffffffffffff4)
        let report = try unwindReport([finding], identity: identity)
        let row = try XCTUnwrap(report.rows.first)
        XCTAssertEqual(row["finding"]?["function"]?["address"]?.stringValue, "0xfffffffffffffff0")
        XCTAssertEqual(row["finding"]?["endAddress"]?.stringValue, "0xfffffffffffffff4")
        XCTAssertEqual(row["finding"]?["checkedPCs"]?.arrayValue?.first?.stringValue, "0xfffffffffffffff0")
        let text = String(decoding: try row.jsonData(), as: UTF8.self)
        XCTAssertFalse(text.contains(":-"), text)
        XCTAssertFalse(text.contains("e+"), text)
        XCTAssertEqual(UInt64("fffffffffffffff0", radix: 16), 0xfffffffffffffff0)
    }

    func testCursorOffsetRangeAndLimitChanges() throws {
        let identity = try AIRSReadFixtures.identity()
        let report = try unwindReport(AIRSReadFixtures.threeFindings(identity), identity: identity)
        let factory = AIRSReadFixtures.cursorFactory(report)
        XCTAssertEqual(AIRSReadPager.page(report: report, offset: 4, limit: 1, makeCursor: factory), .offsetOutOfBounds(total: 3))
        guard case .page(let terminal) = AIRSReadPager.page(report: report, offset: 3, limit: 1, makeCursor: factory) else {
            return XCTFail("terminal offset must be a page")
        }
        XCTAssertEqual(terminal["rows"]?.arrayValue?.count, 0)
        XCTAssertEqual(terminal["total"]?.intValue, 3)
        XCTAssertEqual(terminal["nextCursor"], .null)
        guard case .page(let widened) = AIRSReadPager.page(report: report, offset: 1, limit: 2, makeCursor: factory) else {
            return XCTFail("changed limit must page")
        }
        XCTAssertEqual(widened["rows"]?.arrayValue?.count, 2)
        XCTAssertEqual(widened["nextCursor"], .null)
        XCTAssertEqual(AIRSReadCursor.decode(AIRSReadCursor(
            command: "c", entryID: UUID(), reportID: UUID(), imageSlot: 0, imageOwnerID: UUID(), installationID: UUID(),
            generation: UUID(), focusEpoch: UUID(), reportStateEpoch: UUID(), modelID: "m", filterToken: "all", offset: 0)
            .encoded() ?? "").isOK, true)
    }

    func testByteBudgetNeverConsumesNextRow() throws {
        let context = AIRSReadFixtures.context()
        let filler = String(repeating: "x", count: 70_000)
        let rows: [ScriptValue] = (0..<3).map { .object(["i": .int(Int64($0)), "pad": .string(filler)]) }
        let report = AIRSReadFixtures.syntheticReport(rows: rows, context: context)
        let factory = AIRSReadFixtures.cursorFactory(report)
        guard case .page(let first) = AIRSReadPager.page(report: report, offset: 0, limit: 3, makeCursor: factory) else {
            return XCTFail("first page")
        }
        XCTAssertEqual(first["rows"]?.arrayValue?.count, 2)
        XCTAssertEqual(first["returnedBefore"]?.intValue, 0)
        guard case .success(let next) = AIRSReadCursor.decode(try XCTUnwrap(first["nextCursor"]?.stringValue)) else {
            return XCTFail("cursor")
        }
        XCTAssertEqual(next.offset, 2)
        XCTAssertLessThanOrEqual(try first.jsonData().count, AIRSReadPager.pageByteCap)
        guard case .page(let second) = AIRSReadPager.page(report: report, offset: 2, limit: 3, makeCursor: factory) else {
            return XCTFail("second page")
        }
        XCTAssertEqual(second["rows"]?.arrayValue?.first?["i"]?.intValue, 2)
        XCTAssertEqual(second["nextCursor"], .null)

        let huge = AIRSReadFixtures.syntheticReport(
            rows: [.object(["pad": .string(String(repeating: "y", count: 200_000))])], context: context)
        guard case .refusal(let refusal) = AIRSReadPager.page(report: huge, offset: 0, limit: 1,
                                                             makeCursor: AIRSReadFixtures.cursorFactory(huge)) else {
            return XCTFail("one indivisible oversized row must refuse")
        }
        XCTAssertEqual(refusal.code, .budgetExceeded)
        XCTAssertEqual(refusal.detail, "pageByteLimit")
        XCTAssertEqual(refusal.budget?.unit, .bytes)
        XCTAssertEqual(refusal.budget?.limit, 196_608)
    }

    // MARK: Region caps

    private func swiftReport(_ raw: AIRSSwiftRawResult, function: UInt64, model: AIRSReadModel) throws -> AIRSReadReport {
        try XCTUnwrap(AIRSReadFixtures.builtReport(AIRSReadBuilder.swift(
            raw: raw, context: AIRSReadFixtures.context(command: AIRSMCPReads.swiftErrorCommand, model: model, function: function))))
    }

    func testRegionCapRetainsAllEdges() throws {
        let raw = AIRSReadFixtures.rawRegions(AIRSReadFixtures.singleCaller257Request())
        let report = try swiftReport(raw, function: 0x1000, model: .regionsV1)
        let d = report.denominators.fields
        XCTAssertEqual(d["recoveredEdgeCount"]?.intValue, 257)
        XCTAssertEqual(d["regionResultCount"]?.intValue, 256)
        XCTAssertEqual(d["omittedRegionCount"]?.intValue, 1)
        XCTAssertEqual(d["regionDetailsComplete"]?.boolValue, false)
        let all = try pages(report, limit: 100)
        XCTAssertEqual(all.map { $0["rows"]?.arrayValue?.count }, [100, 100, 57])
        XCTAssertEqual(all.map { $0["total"]?.intValue }, [257, 257, 257])
        let omitted = report.rows.filter { $0["regionAvailability"]?.stringValue == "omittedByRegionCap" }
        XCTAssertEqual(omitted.count, 1)
        XCTAssertEqual(all.last?["sourceComplete"], .bool(false))
    }

    func testRegionDeclinesConsumeGlobalCap() throws {
        let raw = AIRSReadFixtures.rawRegions(AIRSReadFixtures.region257Request())
        guard case .regions(let regionReport) = raw.outcome else { return XCTFail("regions") }
        XCTAssertEqual(regionReport.recoveredEdgeCount, 257)
        XCTAssertEqual(regionReport.regions.count, 256)
        XCTAssertEqual(regionReport.omittedRegionCount, 1)
        XCTAssertTrue(regionReport.regions.allSatisfy { $0.reason == .unsupportedLayout })
        XCTAssertEqual(regionReport.callerScanCount, 256)
        XCTAssertEqual(regionReport.scannedWordCount, 1024)
    }

    func testPerFunctionRegionOmissionsAreNotGlobalOmissions() throws {
        let raw = AIRSReadFixtures.rawRegions(AIRSReadFixtures.region257Request())
        let last = try swiftReport(raw, function: UInt64(0x1000 + 256 * 16), model: .regionsV1)
        XCTAssertEqual(last.denominators.fields["selectedRecoveredEdgeCount"]?.intValue, 1)
        XCTAssertEqual(last.denominators.fields["selectedRegionResultCount"]?.intValue, 0)
        XCTAssertEqual(last.denominators.fields["selectedOmittedRegionCount"]?.intValue, 1)
        XCTAssertEqual(last.rows.count, 1)
        let first = try swiftReport(raw, function: 0x1000, model: .regionsV1)
        XCTAssertEqual(first.denominators.fields["selectedOmittedRegionCount"]?.intValue, 0)
        XCTAssertEqual(first.denominators.fields["omittedRegionCount"]?.intValue, 1)
    }

    func testRejectedRegionsAreNotComplete() throws {
        var request = AIRSReadFixtures.regionRequest()
        request.code.hasEmbeddedData = true
        let raw = AIRSReadFixtures.rawRegions(request)
        let built = AIRSReadBuilder.swift(
            raw: raw, context: AIRSReadFixtures.context(command: AIRSMCPReads.swiftErrorCommand, model: .regionsV1, function: 0x1000))
        guard case .aborted(let value) = built else { return XCTFail("rejected input must abort") }
        XCTAssertEqual(value["refusal"]?["detail"]?.stringValue, "tainted_code_mapping")
        XCTAssertEqual(value["analysis"]?["status"]?.stringValue, "aborted")
        XCTAssertEqual(value["analysis"]?["total"], .null)
        XCTAssertEqual(value["analysis"]?["sourceComplete"], .bool(false))
        XCTAssertEqual(value["analysis"]?["rows"]?.arrayValue?.count, 0)
    }

    func testRawStartCapPrecedesDedup() throws {
        let identity = try AIRSReadFixtures.identity()
        let one = [AIRSReadFixtures.finding(identity, id: "f", start: 0x1000, end: 0x1010)]
        let capped = AIRSReadBuilder.unwind(
            report: AIRSReadFixtures.report(identity, one),
            census: AIRSReadFixtures.census(starts: [0x1000], raw: 50_001), context: AIRSReadFixtures.context())
        guard case .aborted(let value) = capped else { return XCTFail("50001 raw starts must refuse") }
        let refusal = try XCTUnwrap(value["refusal"])
        XCTAssertEqual(refusal["code"]?.stringValue, "budgetExceeded")
        XCTAssertEqual(refusal["budget"]?["unit"]?.stringValue, "rows")
        XCTAssertEqual(refusal["budget"]?["limit"]?.intValue, 50_000)
        XCTAssertEqual(refusal["used"]?.intValue, 50_001)
        XCTAssertEqual(value["analysis"]?["total"], .null)
        XCTAssertEqual(value["analysis"]?["sourceComplete"], .bool(false))
        let d = try XCTUnwrap(value["analysis"]?["denominators"])
        XCTAssertEqual(d["functionsAudited"]?.intValue, 0)
        XCTAssertEqual(d["functionsRefusedByLimit"]?.intValue, 1)
        XCTAssertEqual(d["rawStartsRefusedByLimit"]?.intValue, 50_001)

        let boundary = try unwindReport(one, identity: identity, census: AIRSReadFixtures.census(starts: [0x1000], raw: 50_000))
        XCTAssertEqual(boundary.rows.count, 1)
    }
}

private extension Result {
    var isOK: Bool { if case .success = self { return true } else { return false } }
}
