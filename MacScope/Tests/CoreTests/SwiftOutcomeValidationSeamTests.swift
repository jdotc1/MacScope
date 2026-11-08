import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

private struct SeamFixture {
    let base: OutcomeFixture.Value
    let request: SwiftErrorFlowRequest
    let bytes: Data

    init() throws {
        let base = try OutcomeFixture.manual()
        self.base = base
        request = SwiftErrorFlowRequest(
            slice: SwiftErrorFlowSliceIdentity(
                artifactSHA256: base.image.sliceSHA256, sliceOffset: 0, sliceByteCount: 1024,
                cpuType: 0x0100000c, cpuSubtype: 0, littleEndian: true),
            code: SwiftErrorFlowCode(
                baseAddress: 0x1000, sliceRelativeFileOffset: 256, sectionOrdinal: 1,
                hasEmbeddedData: false, hasRelocations: false,
                words: [0x94000004, 0xb4000055, 0xd65f03c0, 0xd65f03c0]),
            functions: base.image.functions, symbols: [])
        bytes = try SwiftOutcomeWitnessCodec.encode(base.candidate)
    }

    static func edge(callerStart: UInt64 = 0x1000) -> SwiftErrorFlowEdge {
        SwiftErrorFlowEdge(
            callerStart: callerStart, callAddress: 0x1000, calleeAddress: 0x1010,
            symbol: "_$s4Test3fooyS2iKF", testAddress: 0x1004, comparisonAddress: nil,
            successAddress: 0x1008, errorAddress: 0x100c,
            callOffset: 0, testOffset: 4, successOffset: 8, errorOffset: 12,
            testKind: "cbz", evidenceWords: [0x94000004, 0xb4000055])
    }

    func read(_ witnesses: [Int: SwiftOutcomeReadResult.Witness],
              edges: [SwiftErrorFlowEdge] = [SeamFixture.edge()]) -> SwiftOutcomeReadResult {
        SwiftOutcomeReadResult(
            edgeReport: SwiftErrorFlowReport(status: .analyzed, slice: request.slice,
                                             declarations: [], edges: edges, abstentions: []),
            witnessesByEdgeIndex: witnesses)
    }

    static func refusal(_ status: String, _ reason: String, _ index: Int,
                        _ detail: SwiftOutcomeJSON = .null) -> SwiftOutcomeJSON {
        .object([
            "seam_version": .string("swift-outcome-validation-seam-v1"),
            "validator_invoked": .bool(false), "status": .string(status), "reason": .string(reason),
            "eligible": .bool(false), "call_return_proven": .bool(false),
            "source_reconstruction_allowed": .bool(false), "edge_index": .integer(Int128(index)),
            "detail": detail,
        ])
    }
}

final class SeamValidationTests: XCTestCase {
    func testUC01_returnsDirectResultAndRetainsCandidate() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes)])
        let record = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: f.base.image, registry: f.base.registry)
        let direct = validateBroadSwiftWitness(
            image: f.base.image, function: f.base.image.functions[0],
            candidate: try SwiftOutcomeWitnessCodec.parse(f.bytes),
            limits: BroadWitnessLimits(), registry: f.base.registry, imageLedger: nil)
        XCTAssertEqual(record, direct)
        XCTAssertEqual(record["status"], .string("eligible_structural_only"))
        XCTAssertEqual(record["eligible"], .bool(true))
        XCTAssertEqual(record["reason"], .string("independent_bounded_byte_replay"))
        XCTAssertEqual(record["call_return_proven"], .bool(false))
        XCTAssertEqual(record["source_reconstruction_allowed"], .bool(false))
        XCTAssertEqual(record["seam_version"], .null)
        guard case .encoded(let kept)? = read.witnessesByEdgeIndex[0] else {
            return XCTFail("The retained witness was replaced or removed")
        }
        XCTAssertEqual(kept, f.bytes)
        let retained = try SwiftOutcomeWitnessCodec.parse(kept)
        XCTAssertEqual(retained["status"], .string("unresolved"))
        XCTAssertEqual(retained["eligible"], .bool(false))
        XCTAssertTrue(SwiftOutcomeValidationSeam.isEligible(record))
    }

    func testUC01_suppliedLedgerPassesThroughWithoutReplacement() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes)])
        let candidate = try SwiftOutcomeWitnessCodec.parse(f.bytes)
        let issued = createIndependentSwiftImageLedger(f.base.image)
        for (ledger, eligible) in [(issued, true), (issued.copy(), false)] {
            let before = SwiftOutcomeImageLedger.factoryCallCount
            let record = SwiftOutcomeValidationSeam.validate(
                edgeIndex: 0, request: f.request, readResult: read, image: f.base.image,
                imageLedger: ledger, registry: f.base.registry)
            XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 0)
            let direct = validateBroadSwiftWitness(
                image: f.base.image, function: f.base.image.functions[0], candidate: candidate,
                registry: f.base.registry, imageLedger: ledger)
            XCTAssertEqual(record, direct)
            XCTAssertEqual(record["eligible"], .bool(eligible))
            XCTAssertEqual(record["seam_version"], .null)
            if eligible {
                XCTAssertEqual(record["accounting"]["image_ledger_reused"], .bool(true))
                XCTAssertEqual(record["accounting"]["image_work_charged_here"], .integer(0))
            } else {
                XCTAssertEqual(record["reason"], .string("independent_image_ledger_custody"))
                XCTAssertEqual(record["status"], .string("unresolved"))
            }
        }
    }

    func testUC02_absentImageAndIndexPrecedence() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes)])
        let before = SwiftOutcomeImageLedger.factoryCallCount
        let record = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: nil)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 0)
        XCTAssertEqual(record, SeamFixture.refusal("unresolved", "seam_raw_slice_absent", 0))
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 7, request: f.request, readResult: read, image: nil),
            SeamFixture.refusal("declined", "seam_edge_index", 7))
    }

    func testUC03_negativeAndPastEndIndexes() throws {
        let f = try SeamFixture()
        for index in [-1, 1] {
            let record = SwiftOutcomeValidationSeam.validate(
                edgeIndex: index, request: f.request, readResult: f.read([0: .encoded(f.bytes)]),
                image: f.base.image)
            XCTAssertEqual(record, SeamFixture.refusal("declined", "seam_edge_index", index))
            XCTAssertEqual(record["edge_index"], .integer(Int128(index)))
        }
    }

    func testUC04_missingWitnessAndAbsentImagePrecedence() throws {
        let f = try SeamFixture()
        let read = f.read([:])
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: f.base.image),
            SeamFixture.refusal("unresolved", "seam_witness_missing", 0))
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: nil),
            SeamFixture.refusal("unresolved", "seam_raw_slice_absent", 0))
    }

    func testUC05_retentionRefusalIsNotValidation() throws {
        let f = try SeamFixture()
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request,
            readResult: f.read([0: .refused(code: "witness_aggregate_byte_limit")]), image: f.base.image),
            SeamFixture.refusal("unresolved", "seam_witness_refused", 0,
                                .string("witness_aggregate_byte_limit")))
    }

    func testUC06_eachRequestIdentityFieldAndImageArchitecture() throws {
        let f = try SeamFixture()
        var digest = f.request; digest.slice.artifactSHA256 = String(repeating: "0", count: 64)
        var offset = f.request; offset.slice.sliceOffset = 1
        var size = f.request; size.slice.sliceByteCount = 1023
        var cpu = f.request; cpu.slice.cpuType = 7
        var subtype = f.request; subtype.slice.cpuSubtype = 1
        let read = f.read([0: .encoded(f.bytes)])
        for request in [digest, offset, size, cpu, subtype] {
            XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
                edgeIndex: 0, request: request, readResult: read, image: f.base.image),
                SeamFixture.refusal("declined", "seam_image_identity", 0))
        }
        let image = f.base.image
        let otherArchitecture = SwiftOutcomeValidatorImage.admit(
            data: image.data, path: image.path, sliceSHA256: image.sliceSHA256,
            containerSHA256: image.containerSHA256, architecture: "x86_64", cpuSubtype: image.cpuSubtype,
            uuid: image.uuid, fileType: image.fileType, preferredBase: image.preferredBase,
            sliceOffset: image.sliceOffset, sliceSize: image.sliceSize, sliceIndex: image.sliceIndex,
            containerSliceCount: image.containerSliceCount, sections: image.sections, functions: image.functions)
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: otherArchitecture),
            SeamFixture.refusal("declined", "seam_image_identity", 0))
    }

    func testUC07_callerLookupAndIdentityPrecedence() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes)], edges: [SeamFixture.edge(callerStart: 0x2000)])
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: f.base.image),
            SeamFixture.refusal("declined", "seam_caller_function", 0))
        var request = f.request; request.slice.sliceByteCount = 1023
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: request, readResult: read, image: f.base.image),
            SeamFixture.refusal("declined", "seam_image_identity", 0))
    }

    func testUC08_codecCodesAndCallerPrecedence() throws {
        let f = try SeamFixture()
        let malformed = Data([0xff, 0xfe])
        let oversized = Data(repeating: 0x20, count: BroadWitnessLimits().maxBytes + 1)
        for (bytes, code) in [(malformed, "malformed_witness_json"), (oversized, "witness_byte_limit")] {
            XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
                edgeIndex: 0, request: f.request, readResult: f.read([0: .encoded(bytes)]), image: f.base.image),
                SeamFixture.refusal("declined", "seam_witness_parse", 0, .string(code)))
        }
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request,
            readResult: f.read([0: .encoded(malformed)], edges: [SeamFixture.edge(callerStart: 0x2000)]),
            image: f.base.image), SeamFixture.refusal("declined", "seam_caller_function", 0))
    }

    func testUC08_suppliedLimitsReachCodecAndValidator() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes)])
        let byteLimit = try BroadWitnessLimits(maxBytes: 0)
        XCTAssertEqual(SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: f.base.image,
            limits: byteLimit, registry: f.base.registry),
            SeamFixture.refusal("declined", "seam_witness_parse", 0, .string("witness_byte_limit")))
        let workLimit = try BroadWitnessLimits(maxWork: 0)
        let record = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: f.base.image,
            limits: workLimit, registry: f.base.registry)
        let direct = validateBroadSwiftWitness(
            image: f.base.image, function: f.base.image.functions[0],
            candidate: try SwiftOutcomeWitnessCodec.parse(f.bytes, limits: workLimit),
            limits: workLimit, registry: f.base.registry)
        XCTAssertEqual(record, direct)
        XCTAssertEqual(record["reason"], .string("validator_work_limit"))
        XCTAssertEqual(record["status"], .string("unresolved"))
        XCTAssertEqual(record["eligible"], .bool(false))
        XCTAssertEqual(record["seam_version"], .null)
    }

    func testUC09_emptyObjectPropagatesValidatorRefusal() throws {
        let f = try SeamFixture()
        let record = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: f.read([0: .encoded(Data("{}".utf8))]),
            image: f.base.image, registry: f.base.registry)
        let direct = validateBroadSwiftWitness(image: f.base.image, function: f.base.image.functions[0],
                                               candidate: .object([:]), registry: f.base.registry)
        XCTAssertEqual(record, direct)
        XCTAssertEqual(record["model_version"], .string("swift-outcome-validation-v2"))
        XCTAssertEqual(record["status"], .string("declined"))
        XCTAssertEqual(record["reason"], .string("candidate_model"))
        XCTAssertEqual(record["eligible"], .bool(false))
        XCTAssertEqual(record["seam_version"], .null)
    }

    func testUC10_unadmittedImageReachesValidatorCustodyCheck() throws {
        let f = try SeamFixture()
        let image = OutcomeFixture.image(f.base.image.data, admitted: false)
        let record = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: f.read([0: .encoded(f.bytes)]),
            image: image, registry: f.base.registry)
        let direct = validateBroadSwiftWitness(
            image: image, function: f.base.image.functions[0],
            candidate: try SwiftOutcomeWitnessCodec.parse(f.bytes), registry: f.base.registry)
        XCTAssertEqual(record, direct)
        XCTAssertEqual(record["seam_version"], .null)
        XCTAssertEqual(record["reason"], .string("image_admission_custody"))
        XCTAssertEqual(record["status"], .string("unresolved"))
        XCTAssertEqual(record["eligible"], .bool(false))
        XCTAssertEqual(record["model_version"], .string("swift-outcome-validation-v2"))
    }

    func testUC11_batchBuildsAndReusesOneLedger() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes), 1: .encoded(f.bytes)],
                          edges: [SeamFixture.edge(), SeamFixture.edge()])
        let before = SwiftOutcomeImageLedger.factoryCallCount
        let records = SwiftOutcomeValidationSeam.validateAll(
            request: f.request, readResult: read, image: f.base.image, registry: f.base.registry)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 1)
        XCTAssertEqual(records.keys.sorted(), [0, 1])
        let first = try XCTUnwrap(records[0])
        let second = try XCTUnwrap(records[1])
        for record in [first, second] {
            XCTAssertEqual(record["eligible"], .bool(true))
            XCTAssertEqual(record["accounting"]["image_ledger_reused"], .bool(true))
            XCTAssertEqual(record["accounting"]["image_work_charged_here"], .integer(0))
            XCTAssertGreaterThan(try XCTUnwrap(record["accounting"]["image_initial_work"].integer), Int128(0))
        }
        XCTAssertEqual(first["accounting"]["image_initial_work"], second["accounting"]["image_initial_work"])
    }

    func testUC11_batchLedgerPredicateDoesNotPreparseWitness() throws {
        let f = try SeamFixture()
        let before = SwiftOutcomeImageLedger.factoryCallCount
        let records = SwiftOutcomeValidationSeam.validateAll(
            request: f.request, readResult: f.read([0: .encoded(f.bytes)]), image: f.base.image,
            limits: try BroadWitnessLimits(maxBytes: 0), registry: f.base.registry)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 1)
        XCTAssertEqual(records, [
            0: SeamFixture.refusal("declined", "seam_witness_parse", 0, .string("witness_byte_limit")),
        ])
    }

    func testUC12_batchWithoutImageNeverBuildsLedger() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes), 1: .refused(code: "witness_aggregate_byte_limit")],
                          edges: [SeamFixture.edge(), SeamFixture.edge()])
        let before = SwiftOutcomeImageLedger.factoryCallCount
        let records = SwiftOutcomeValidationSeam.validateAll(request: f.request, readResult: read, image: nil)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 0)
        XCTAssertEqual(records, [
            0: SeamFixture.refusal("unresolved", "seam_raw_slice_absent", 0),
            1: SeamFixture.refusal("unresolved", "seam_raw_slice_absent", 1),
        ])
    }

    func testUC13_batchWithoutEncodedWitnessNeverBuildsLedger() throws {
        let f = try SeamFixture()
        let read = f.read([1: .refused(code: "witness_aggregate_byte_limit")],
                          edges: [SeamFixture.edge(), SeamFixture.edge()])
        let before = SwiftOutcomeImageLedger.factoryCallCount
        let records = SwiftOutcomeValidationSeam.validateAll(
            request: f.request, readResult: read, image: f.base.image)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 0)
        XCTAssertEqual(records, [
            0: SeamFixture.refusal("unresolved", "seam_witness_missing", 0),
            1: SeamFixture.refusal("unresolved", "seam_witness_refused", 1,
                                   .string("witness_aggregate_byte_limit")),
        ])
    }

    func testUC13_emptyAndOutOfRangeOnlyWitnessMapsNeverBuildLedger() throws {
        let f = try SeamFixture()
        let outside = f.read([-1: .encoded(f.bytes), 1: .encoded(f.bytes)])
        let beforeOutside = SwiftOutcomeImageLedger.factoryCallCount
        let outsideRecords = SwiftOutcomeValidationSeam.validateAll(
            request: f.request, readResult: outside, image: f.base.image, registry: f.base.registry)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - beforeOutside, 0)
        XCTAssertEqual(outsideRecords, [0: SeamFixture.refusal("unresolved", "seam_witness_missing", 0)])
        let empty = f.read([0: .encoded(f.bytes)], edges: [])
        let beforeEmpty = SwiftOutcomeImageLedger.factoryCallCount
        let emptyRecords = SwiftOutcomeValidationSeam.validateAll(
            request: f.request, readResult: empty, image: f.base.image, registry: f.base.registry)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - beforeEmpty, 0)
        XCTAssertEqual(emptyRecords, [Int: SwiftOutcomeJSON]())
    }

    func testUC14_batchUnadmittedImageNeverBuildsLedger() throws {
        let f = try SeamFixture()
        let image = OutcomeFixture.image(f.base.image.data, admitted: false)
        let read = f.read([0: .encoded(f.bytes), 1: .encoded(f.bytes)],
                          edges: [SeamFixture.edge(), SeamFixture.edge()])
        let before = SwiftOutcomeImageLedger.factoryCallCount
        let records = SwiftOutcomeValidationSeam.validateAll(
            request: f.request, readResult: read, image: image, registry: f.base.registry)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount - before, 0)
        XCTAssertEqual(records.keys.sorted(), [0, 1])
        for index in [0, 1] {
            let record = try XCTUnwrap(records[index])
            XCTAssertEqual(record["reason"], .string("image_admission_custody"))
            XCTAssertEqual(record["status"], .string("unresolved"))
        }
    }

    func testUC15_strictEligibilityRejectsMissingAndElevatedProofFields() throws {
        let f = try SeamFixture()
        let read = f.read([0: .encoded(f.bytes)])
        let eligible = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: f.base.image, registry: f.base.registry)
        XCTAssertTrue(SwiftOutcomeValidationSeam.isEligible(eligible))
        let refusal = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: read, image: nil)
        let blocked = SwiftOutcomeJSON.object([
            "status": .string("blocked"), "eligible": .bool(true),
            "reason": .string("independent_bounded_byte_replay"), "call_return_proven": .bool(false),
            "source_reconstruction_allowed": .bool(false),
        ])
        var callProven = eligible; callProven["call_return_proven"] = .bool(true)
        var sourceAllowed = eligible; sourceAllowed["source_reconstruction_allowed"] = .bool(true)
        var noCallProof = try XCTUnwrap(eligible.object); noCallProof.removeValue(forKey: "call_return_proven")
        var noSourceProof = try XCTUnwrap(eligible.object); noSourceProof.removeValue(forKey: "source_reconstruction_allowed")
        var ineligible = eligible; ineligible["eligible"] = .bool(false)
        let rejected: [SwiftOutcomeJSON] = [refusal, blocked, callProven, sourceAllowed,
                                           .object(noCallProof), .object(noSourceProof), ineligible, .null, .array([])]
        for record in rejected { XCTAssertFalse(SwiftOutcomeValidationSeam.isEligible(record)) }
        var wrongReason = eligible; wrongReason["reason"] = .string("validation_required")
        var wrongStatus = eligible; wrongStatus["status"] = .string("unresolved")
        var noReason = try XCTUnwrap(eligible.object); noReason.removeValue(forKey: "reason")
        var numericCallProof = eligible; numericCallProof["call_return_proven"] = .integer(0)
        var stringSourceProof = eligible; stringSourceProof["source_reconstruction_allowed"] = .string("false")
        var numericEligible = eligible; numericEligible["eligible"] = .integer(1)
        for record in [wrongReason, wrongStatus, .object(noReason), numericCallProof,
                       stringSourceProof, numericEligible] {
            XCTAssertFalse(SwiftOutcomeValidationSeam.isEligible(record))
        }
    }

    func testUC16_liveDeclarationShapeRefusesBeforeUnavailableABI() throws {
        let f = try SeamFixture()
        var candidate = f.base.candidate
        candidate["call"]["declaration"] = .object([
            "status": .string("syntax_admitted"), "symbol": .string("_$s4Test3fooyS2iKF"),
            "module": .string("Test"), "name": .string("foo"),
            "parameters": .array([.string("Swift.Int")]), "result": .string("Swift.Int"),
            "convention": .string("swift_sync_untyped_throws"), "error_register": .string("x21"),
            "source": .string("exact_external_symbol_grammar"),
        ])
        candidate["call"]["abi"] = .object(["status": .string("unavailable")])
        OutcomeFixture.finish(&candidate)
        let bytes = try SwiftOutcomeWitnessCodec.encode(candidate)
        let record = SwiftOutcomeValidationSeam.validate(
            edgeIndex: 0, request: f.request, readResult: f.read([0: .encoded(bytes)]),
            image: f.base.image, registry: f.base.registry)
        XCTAssertEqual(record["status"], .string("declined"))
        XCTAssertEqual(record["reason"], .string("declaration_identity"))
        XCTAssertEqual(record["eligible"], .bool(false))
        XCTAssertEqual(record["model_version"], .string("swift-outcome-validation-v2"))
    }
}
#endif
