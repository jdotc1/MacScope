import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

@MainActor
final class SwiftOutcomeReadIntegrationTests: XCTestCase {
    private let command = AIRSMCPReads.swiftErrorCommand

    private func request(twoCallers: Bool = false) -> SwiftErrorFlowRequest {
        var value: SwiftErrorFlowRequest
        if twoCallers {
            value = SwiftOutcomeTestFixture.request(
                words: [0x94000008, 0xb5000055, 0xd65f03c0, 0xd65f03c0,
                        0x94000004, 0xb5000055, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0],
                functions: [
                    .init(start: 0x1000, endExclusive: 0x1010, boundarySource: "lc_function_starts"),
                    .init(start: 0x1010, endExclusive: 0x1020, boundarySource: "lc_function_starts"),
                    .init(start: 0x1020, endExclusive: 0x1024, boundarySource: "lc_function_starts"),
                ])
        } else {
            value = SwiftOutcomeTestFixture.request()
        }
        value.symbols = [.init(address: twoCallers ? 0x1020 : 0x1010, name: "_$s4Demo5parseyS2iKF",
                               nType: 0x0f, nDesc: 0, sectionOrdinal: 1)]
        return value
    }

    private func census(_ request: SwiftErrorFlowRequest) -> AIRSCensus {
        AIRSCensus(rawFunctionStartCount: request.functions.count,
                   uniqueStarts: request.functions.map(\.start), parseOutcome: "terminated", isComplete: true)
    }

    private func context(function: UInt64 = 0x1000) -> AIRSReadContext {
        AIRSReadFixtures.context(command: command, model: .outcomeWitnessV2, function: function)
    }

    private func built(_ raw: AIRSSwiftRawResult, context: AIRSReadContext) throws -> AIRSReadReport {
        guard case .report(let report) = AIRSReadBuilder.swift(raw: raw, context: context) else {
            throw SwiftOutcomeError(code: "test_expected_report")
        }
        return report
    }

    private func candidate(_ fields: [String: SwiftOutcomeJSON] = [:]) throws -> Data {
        var value = fields
        value["model_version"] = .string("swift-outcome-witness-v2")
        value["status"] = .string("unresolved")
        value["eligible"] = .bool(false)
        return try SwiftOutcomeWitnessCodec.encode(.object(value))
    }

    private func raw(request: SwiftErrorFlowRequest, edges: SwiftErrorFlowReport,
                     witnesses: [Int: SwiftOutcomeReadResult.Witness]) -> AIRSSwiftRawResult {
        AIRSSwiftRawResult(census: census(request),
            outcome: .outcomeWitnesses(.init(edgeReport: edges, witnessesByEdgeIndex: witnesses)),
            admittedIntervals: request.functions, model: .outcomeWitnessV2,
            modelID: "macscope-swift-outcome-witness-v2")
    }

    func testReadModelIsExplicitSwiftOnly() throws {
        let fields: [String: ScriptValue] = ["imageSlot": .int(0), "function": .string("0x1000")]
        XCTAssertEqual(try AIRSMCPReads.parse(command: command, fields: fields).model, AIRSReadModel.v1)
        var selected = fields
        selected["model"] = .string("outcomeWitnessV2")
        let options = try AIRSMCPReads.parse(command: command, fields: selected)
        XCTAssertEqual(options.model, AIRSReadModel.outcomeWitnessV2)
        XCTAssertEqual(options.model.modelID(for: command), String("macscope-swift-outcome-witness-v2"))
        XCTAssertThrowsError(try AIRSMCPReads.parse(command: AIRSMCPReads.unwindCommand, fields: selected)) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.allowed, [String](arrayLiteral: "v1", "v4"))
        }
        let expected: [String] = ["v1", "v4", "registerCopiesV2", "regionsV1", "outcomeWitnessV2"]
        XCTAssertEqual(AIRSMCPReads.sharedArgumentSchema("model")?["enum"]?.arrayValue?.compactMap(\.stringValue), expected)
    }

    func testAdmittedRequestRunnerRetainsOneConservativeWitnessPerNativeEdge() throws {
        let input = request(twoCallers: true)
        let raw = AIRSSwiftRunner.analyze(request: input, census: census(input), model: .outcomeWitnessV2)
        guard case .outcomeWitnesses(let retained) = raw.outcome else { return XCTFail("Witness route not selected") }
        XCTAssertEqual(retained.edgeReport, SwiftErrorFlowAnalyzer.analyze(input, model: .nativeV1))
        XCTAssertEqual(retained.witnessesByEdgeIndex.count, Int(2))
        XCTAssertEqual(retained.encodedCount, Int(2))
        for index in 0..<2 {
            guard case .encoded(let bytes)? = retained.witnessesByEdgeIndex[index] else {
                return XCTFail("Missing original edge index \(index)")
            }
            let witness = try SwiftOutcomeWitnessCodec.parse(bytes)
            XCTAssertEqual(try SwiftOutcomeWitnessCodec.encode(witness), bytes)
            XCTAssertEqual(witness["status"], SwiftOutcomeJSON.string("unresolved"))
            XCTAssertEqual(witness["eligible"], SwiftOutcomeJSON.bool(false))
            XCTAssertEqual(witness["call"]["abi"], SwiftOutcomeJSON.object(["status": .string("unavailable")]))
            XCTAssertEqual(witness["completeness"]["complete"], SwiftOutcomeJSON.bool(false))
            let missing: SwiftOutcomeJSON = .array([.string("abi_unqualified"), .string("abi_unqualified")])
            XCTAssertEqual(witness["completeness"]["missing"], missing)
        }
        let first = try XCTUnwrap(retained.edgeReport.edges.first)
        let declaration = try XCTUnwrap(retained.edgeReport.declarations.first)
        let callsite = try SwiftOutcomeReadBridge.nativeCallsite(request: input, edge: first, declaration: declaration)
        XCTAssertEqual(callsite["provenance"]["call"]["slice_file_offset"], SwiftOutcomeJSON.integer(512))
        XCTAssertEqual(callsite["provenance"]["call"]["container_file_offset"], SwiftOutcomeJSON.integer(16896))
        XCTAssertEqual(callsite["provenance"]["callee_entry"]["word"], SwiftOutcomeJSON.integer(3596551104))
        XCTAssertEqual(callsite["declaration"]["status"], SwiftOutcomeJSON.string("syntax_admitted"))
    }

    func testNativeSelectionAndRejectionAreNotBroadened() throws {
        let input = request()
        let plain = AIRSSwiftRunner.analyze(request: input, census: census(input), model: .v1)
        guard case .edges = plain.outcome else { return XCTFail("Default model changed") }
        var invalid = input
        invalid.slice.cpuSubtype = 2
        let rejected = AIRSSwiftRunner.analyze(request: invalid, census: census(invalid), model: .outcomeWitnessV2)
        guard case .outcomeWitnesses(let retained) = rejected.outcome else { return XCTFail("Wrong outcome") }
        XCTAssertEqual(retained.edgeReport.status, SwiftErrorFlowStatus.rejected)
        XCTAssertTrue(retained.witnessesByEdgeIndex.isEmpty)
        guard case .aborted = AIRSReadBuilder.swift(raw: rejected, context: context()) else {
            return XCTFail("Rejected native input became an empty success page")
        }
    }

    func testProjectionKeepsOriginalIndicesAfterFilteringSortingAndDuplicateEdges() throws {
        let input = request(twoCallers: true)
        let native = SwiftErrorFlowAnalyzer.analyze(input)
        let first = try XCTUnwrap(native.edges.first), second = try XCTUnwrap(native.edges.last)
        let reordered = SwiftErrorFlowReport(status: .analyzed, slice: input.slice,
            declarations: native.declarations, edges: [second, first, first],
            abstentions: [.init(code: "global", address: nil), .init(code: "selected", address: 0x1008),
                          .init(code: "other", address: 0x1018)])
        let bytes0 = try candidate(["index": .integer(0)])
        let bytes1 = try candidate(["index": .integer(1)])
        let bytes2 = try candidate(["index": .integer(2)])
        let report = try built(raw(request: input, edges: reordered,
            witnesses: [0: .encoded(bytes0), 1: .encoded(bytes1), 2: .encoded(bytes2)]), context: context())
        XCTAssertEqual(report.rows.count, Int(2))
        XCTAssertEqual(report.rows.map { $0["edgeIndex"]?.intValue }, [Int64?](arrayLiteral: 1, 2))
        XCTAssertEqual(report.rows[0]["witnessJSON"]?.stringValue, String(decoding: bytes1, as: UTF8.self))
        XCTAssertEqual(report.rows[1]["witnessJSON"]?.stringValue, String(decoding: bytes2, as: UTF8.self))
        XCTAssertEqual(report.denominators.fields["edges"]?.intValue, Int64(3))
        XCTAssertEqual(report.denominators.fields["selectedEdges"]?.intValue, Int64(2))
        XCTAssertEqual(report.denominators.fields["selectedWitnessCount"]?.intValue, Int64(2))
        XCTAssertEqual(report.denominators.fields["selectedAbstentionsByCode"]?["selected"]?.intValue, Int64(1))
        XCTAssertNil(report.denominators.fields["selectedAbstentionsByCode"]?["other"])
        XCTAssertEqual(report.header["admission"]?["declarations"]?.arrayValue?.count, Int(1))
        XCTAssertEqual(report.header["sourceReconstructionAllowed"]?.boolValue, Bool(false))
        XCTAssertEqual(report.header["runtimeReachabilityProven"]?.boolValue, Bool(false))
        XCTAssertEqual(report.sourceComplete, Bool(true))
        XCTAssertEqual(report.denominators.fields["witnessDetailsComplete"]?.boolValue, Bool(false))
    }

    func testWitnessProjectionPreservesEveryNativeAdmissionAndDenominatorField() throws {
        let input = request(twoCallers: true)
        let nativeRaw = AIRSSwiftRunner.analyze(request: input, census: census(input), model: .v1)
        let witnessRaw = AIRSSwiftRunner.analyze(request: input, census: census(input), model: .outcomeWitnessV2)
        let nativeContext = AIRSReadFixtures.context(command: command, model: .v1, function: 0x1000)
        let native = try built(nativeRaw, context: nativeContext)
        let witnesses = try built(witnessRaw, context: context())
        XCTAssertEqual(witnesses.header["admission"], native.header["admission"])
        for (key, value) in native.denominators.fields {
            XCTAssertEqual(witnesses.denominators.fields[key], value, key)
        }
        XCTAssertEqual(witnesses.rows.map { $0["edge"] }, native.rows.map { $0["edge"] })
        XCTAssertEqual(witnesses.rows.map { $0["regionAvailability"] }, native.rows.map { $0["regionAvailability"] })
        XCTAssertEqual(witnesses.header["edgeAnalysisModelVersion"]?.stringValue,
                       String("macscope-swift-error-flow-native-v1"))
        XCTAssertEqual(witnesses.header["witnessABIStatus"]?.stringValue, String("unavailable"))
        XCTAssertEqual(witnesses.sourceComplete, native.sourceComplete)
        XCTAssertEqual(witnesses.sourceComplete, Bool(true))
        XCTAssertEqual(witnesses.denominators.fields["witnessDetailsComplete"]?.boolValue, Bool(false))
    }

    func testCensusCompletenessRemainsIndependentOfCandidateFacts() throws {
        let input = request(twoCallers: true)
        let native = SwiftErrorFlowAnalyzer.analyze(input)
        let bytes = try candidate()
        var value = raw(request: input, edges: native,
                        witnesses: [0: .encoded(bytes), 1: .refused(code: "witness_aggregate_byte_limit")])
        let complete = try built(value, context: context())
        XCTAssertEqual(complete.sourceComplete, Bool(true))
        XCTAssertEqual(complete.denominators.fields["selectedWitnessRefusalCount"]?.intValue, Int64(0))
        XCTAssertEqual(complete.denominators.fields["witnessRefusalCount"]?.intValue, Int64(1))
        XCTAssertEqual(complete.denominators.fields["witnessDetailsComplete"]?.boolValue, Bool(false))
        XCTAssertEqual(try built(value, context: context(function: 0x1010)).sourceComplete, Bool(false))
        value.census?.isComplete = false
        XCTAssertEqual(try built(value, context: context()).sourceComplete, Bool(false))
        value.census?.isComplete = nil
        XCTAssertNil(try built(value, context: context()).sourceComplete)
        value.census = nil
        XCTAssertNil(try built(value, context: context()).sourceComplete)
    }

    func testProjectionPreservesFullWidthIntegerCanonicalBytesAsAString() throws {
        let input = request(), native = SwiftErrorFlowAnalyzer.analyze(input)
        let bytes = try candidate(["large": .integer(18446744073709551615)])
        let expected: String = "{\"eligible\":false,\"large\":18446744073709551615,\"model_version\":\"swift-outcome-witness-v2\",\"status\":\"unresolved\"}"
        let report = try built(raw(request: input, edges: native, witnesses: [0: .encoded(bytes)]), context: context())
        let text = try XCTUnwrap(report.rows.first?["witnessJSON"]?.stringValue)
        XCTAssertEqual(text, expected)
        XCTAssertEqual(Data(text.utf8), bytes)
        XCTAssertEqual(try SwiftOutcomeWitnessCodec.parse(Data(text.utf8))["large"], SwiftOutcomeJSON.integer(18446744073709551615))
    }

    func testUnadmittedBoundaryAndAbsentFunctionStayDistinct() throws {
        let input = request()
        var value = AIRSSwiftRunner.analyze(request: input, census: census(input), model: .outcomeWitnessV2)
        value.census?.uniqueStarts.append(0x1008)
        guard case .aborted(let refusal) = AIRSReadBuilder.swift(raw: value, context: context(function: 0x1008)) else {
            return XCTFail("Interior retained start was admitted")
        }
        XCTAssertEqual(refusal["analysis"]?["denominators"]?["selectedFunctionAdmitted"]?.boolValue, Bool(false))
        guard case .absent(_, let reason) = AIRSReadBuilder.swift(raw: value, context: context(function: 0x2000)) else {
            return XCTFail("Unknown function was not absent")
        }
        XCTAssertEqual(reason, String("noSuchSubject"))
    }

    func testAggregateEncodingAndMissingEntryRefusalsKeepEdgesVisible() throws {
        let input = request(), native = SwiftErrorFlowAnalyzer.analyze(input)
        let bounded = SwiftOutcomeReadBridge.build(request: input, edgeReport: native,
                                                   limits: try BroadWitnessLimits(maxAggregateBytes: 0))
        XCTAssertEqual(bounded.witnessesByEdgeIndex[0], SwiftOutcomeReadResult.Witness.refused(code: "witness_aggregate_byte_limit"))
        let encoding = SwiftOutcomeReadBridge.build(request: input, edgeReport: native,
                                                    limits: try BroadWitnessLimits(maxBytes: 1))
        XCTAssertEqual(encoding.witnessesByEdgeIndex[0], SwiftOutcomeReadResult.Witness.refused(code: "witness_byte_limit"))
        let report = try built(raw(request: input, edges: native, witnesses: bounded.witnessesByEdgeIndex), context: context())
        XCTAssertEqual(report.rows.count, Int(1))
        XCTAssertEqual(report.rows[0]["witnessJSON"], ScriptValue.null)
        XCTAssertEqual(report.rows[0]["witnessRefusalReason"]?.stringValue, String("witness_aggregate_byte_limit"))
        XCTAssertEqual(report.denominators.fields["selectedWitnessRefusalCount"]?.intValue, Int64(1))
        XCTAssertEqual(report.sourceComplete, Bool(false))
        let missing = try built(raw(request: input, edges: native, witnesses: [:]), context: context())
        XCTAssertEqual(missing.rows[0]["witnessRefusalReason"]?.stringValue, String("retained_witness_missing"))
        XCTAssertEqual(missing.sourceComplete, Bool(false))
    }

    private func largeReport(integerCount: Int, duplicate: Bool) throws -> AIRSReadReport {
        let input = request(), native = SwiftErrorFlowAnalyzer.analyze(input)
        let edge = try XCTUnwrap(native.edges.first)
        let edges = SwiftErrorFlowReport(status: .analyzed, slice: native.slice,
            declarations: native.declarations, edges: duplicate ? [edge, edge] : [edge], abstentions: [])
        let bytes = try candidate(["payload": .array(Array(repeating: .integer(18446744073709551615), count: integerCount))])
        let witnesses: [Int: SwiftOutcomeReadResult.Witness] = duplicate
            ? [0: .encoded(bytes), 1: .encoded(bytes)] : [0: .encoded(bytes)]
        return try built(raw(request: input, edges: edges, witnesses: witnesses), context: context())
    }

    func testByteCapShrinksWholeRowsAndContinuationUsesRetainedBytes() throws {
        let report = try largeReport(integerCount: 5500, duplicate: true)
        let first = AIRSReadProjection.firstPage(.report(report), limit: 256, entryID: report.entryID)
        XCTAssertEqual(first.retain?.id, report.id)
        XCTAssertEqual(first.value["returnedThisPage"]?.intValue, Int64(1))
        XCTAssertEqual(first.value["total"]?.intValue, Int64(2))
        XCTAssertEqual(first.value["isTruncated"]?.boolValue, Bool(true))
        XCTAssertLessThanOrEqual(try first.value.jsonData().count, Int(196608))
        let token = try XCTUnwrap(first.value["nextCursor"]?.stringValue)
        guard case .success(let cursor) = AIRSReadCursor.decode(token) else { return XCTFail("Invalid minted cursor") }
        XCTAssertEqual(cursor.offset, Int(1))
        XCTAssertEqual(cursor.modelID, String("macscope-swift-outcome-witness-v2"))
        XCTAssertEqual(cursor.filterToken, String("fn:4096"))
        XCTAssertEqual(cursor.reportID, report.id)
        XCTAssertEqual(cursor.entryID, report.entryID)
        XCTAssertEqual(cursor.imageOwnerID, report.imageOwnerID)
        XCTAssertEqual(cursor.installationID, report.installationID)
        XCTAssertEqual(cursor.generation, report.generation)
        XCTAssertEqual(cursor.focusEpoch, report.focusEpoch)
        XCTAssertEqual(cursor.reportStateEpoch, report.reportStateEpoch)
        let second = AIRSReadProjection.page(report: report, offset: cursor.offset, limit: 256, entryID: report.entryID)
        XCTAssertEqual(second["rows"]?.arrayValue, [ScriptValue](arrayLiteral: report.rows[1]))
        XCTAssertEqual(second["nextCursor"], ScriptValue.null)
        XCTAssertEqual(second["isTruncated"]?.boolValue, Bool(false))
        XCTAssertEqual(second["returnedBefore"]?.intValue, Int64(1))
        XCTAssertEqual(second["remainingAfter"]?.intValue, Int64(0))
        XCTAssertEqual(second["denominators"], first.value["denominators"])
        XCTAssertEqual(second["sourceComplete"]?.boolValue, Bool(true))
        XCTAssertEqual(second["denominators"]?["witnessDetailsComplete"]?.boolValue, Bool(false))
        // A repeated page receives only the retained report, not input bytes or a producer callback.
        XCTAssertEqual(AIRSReadProjection.page(report: report, offset: cursor.offset, limit: 256,
                                                entryID: report.entryID), second)
    }

    func testSingleOversizeRowRefusesInsteadOfTrimmingAndIsNotRetained() throws {
        let report = try largeReport(integerCount: 10000, duplicate: false)
        switch AIRSReadPager.page(report: report, offset: 0, limit: 1, makeCursor: { _ in nil }) {
        case .refusal(let refusal):
            XCTAssertEqual(refusal.code, MCPRefusalCode.budgetExceeded)
            XCTAssertEqual(refusal.detail, String("pageByteLimit"))
        default: XCTFail("Oversize witness was trimmed or served")
        }
        let projected = AIRSReadProjection.firstPage(.report(report), limit: 1, entryID: report.entryID)
        XCTAssertNil(projected.retain)
        XCTAssertFalse(AIRSReadProjection.hasCursor(projected.value))
        switch AIRSReadPager.page(report: report, offset: 2, limit: 1, makeCursor: { _ in nil }) {
        case .offsetOutOfBounds(let total): XCTAssertEqual(total, Int(1))
        default: XCTFail("Out-of-range continuation accepted")
        }
    }

    func testCursorFailureDoesNotServeUncontinuablePrefix() throws {
        let report = try largeReport(integerCount: 1, duplicate: true)
        switch AIRSReadPager.page(report: report, offset: 0, limit: 1, makeCursor: { _ in nil }) {
        case .refusal(let refusal): XCTAssertEqual(refusal.detail, String("pageByteLimit"))
        default: XCTFail("A truncated prefix escaped without a continuation")
        }
    }

    func testDetachedProjectionUsesTheSameWitnessRoute() async throws {
        let input = request()
        let value = AIRSSwiftRunner.analyze(request: input, census: census(input), model: .outcomeWitnessV2)
        let c = context()
        let projected = await AIRSReadProjection.detachedSwift(raw: value, context: c, limit: 1)
        XCTAssertEqual(projected.value["analysisModelVersion"]?.stringValue, String("macscope-swift-outcome-witness-v2"))
        XCTAssertEqual(projected.value["rows"]?.arrayValue?.first?["kind"]?.stringValue, String("swiftOutcomeWitness"))
        XCTAssertEqual(projected.value["sourceComplete"]?.boolValue, Bool(true))
        XCTAssertEqual(projected.value["denominators"]?["witnessDetailsComplete"]?.boolValue, Bool(false))
        XCTAssertNil(projected.retain)
    }
}
#endif
