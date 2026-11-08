import Foundation

/// Keeps retained candidates separate from independent validation results.
enum SwiftOutcomeValidationSeam {
    static let version = "swift-outcome-validation-seam-v1"

    static func validate(edgeIndex: Int, request: SwiftErrorFlowRequest,
                         readResult: SwiftOutcomeReadResult,
                         image: SwiftOutcomeValidatorImage?,
                         imageLedger: SwiftOutcomeImageLedger? = nil,
                         limits: BroadWitnessLimits = BroadWitnessLimits(),
                         registry: SwiftOutcomeABIRegistry = .frozen) -> SwiftOutcomeJSON {
        guard readResult.edgeReport.edges.indices.contains(edgeIndex) else {
            return refusal(status: "declined", reason: "seam_edge_index", edgeIndex: edgeIndex)
        }
        guard let image else {
            return refusal(status: "unresolved", reason: "seam_raw_slice_absent", edgeIndex: edgeIndex)
        }
        guard let witness = readResult.witnessesByEdgeIndex[edgeIndex] else {
            return refusal(status: "unresolved", reason: "seam_witness_missing", edgeIndex: edgeIndex)
        }
        let bytes: Data
        switch witness {
        case .refused(let code):
            return refusal(status: "unresolved", reason: "seam_witness_refused",
                           edgeIndex: edgeIndex, detail: .string(code))
        case .encoded(let retained):
            bytes = retained
        }
        guard image.sliceSHA256 == request.slice.artifactSHA256,
              image.sliceOffset == request.slice.sliceOffset,
              image.sliceSize == request.slice.sliceByteCount,
              image.architecture == "arm64",
              request.slice.cpuType == 0x0100000c,
              image.cpuSubtype == Int(request.slice.cpuSubtype) else {
            return refusal(status: "declined", reason: "seam_image_identity", edgeIndex: edgeIndex)
        }
        let edge = readResult.edgeReport.edges[edgeIndex]
        guard let function = request.functions.first(where: { $0.start == edge.callerStart }) else {
            return refusal(status: "declined", reason: "seam_caller_function", edgeIndex: edgeIndex)
        }
        let candidate: SwiftOutcomeJSON
        do {
            candidate = try SwiftOutcomeWitnessCodec.parse(bytes, limits: limits)
        } catch let error as SwiftOutcomeError {
            return refusal(status: "declined", reason: "seam_witness_parse",
                           edgeIndex: edgeIndex, detail: .string(error.code))
        } catch {
            // The supplied codec throws SwiftOutcomeError; keep the public seam nonthrowing.
            return refusal(status: "declined", reason: "seam_witness_parse",
                           edgeIndex: edgeIndex, detail: .string("malformed_witness_json"))
        }
        return validateBroadSwiftWitness(image: image, function: function, candidate: candidate,
                                         limits: limits, registry: registry, imageLedger: imageLedger)
    }

    static func validateAll(request: SwiftErrorFlowRequest, readResult: SwiftOutcomeReadResult,
                            image: SwiftOutcomeValidatorImage?,
                            limits: BroadWitnessLimits = BroadWitnessLimits(),
                            registry: SwiftOutcomeABIRegistry = .frozen) -> [Int: SwiftOutcomeJSON] {
        let indices = readResult.edgeReport.edges.indices
        let ledger: SwiftOutcomeImageLedger?
        if let image, image.hasValidAdmission,
           indices.contains(where: { index in
               if case .encoded? = readResult.witnessesByEdgeIndex[index] { return true }
               return false
           }) {
            ledger = createIndependentSwiftImageLedger(image)
        } else {
            ledger = nil
        }
        var records: [Int: SwiftOutcomeJSON] = [:]
        for index in indices {
            records[index] = validate(edgeIndex: index, request: request, readResult: readResult,
                                      image: image, imageLedger: ledger, limits: limits, registry: registry)
        }
        return records
    }

    static func isEligible(_ record: SwiftOutcomeJSON) -> Bool {
        guard case .object = record else { return false }
        return record["status"] == .string("eligible_structural_only")
            && record["eligible"] == .bool(true)
            && record["reason"] == .string("independent_bounded_byte_replay")
            && record["call_return_proven"] == .bool(false)
            && record["source_reconstruction_allowed"] == .bool(false)
    }

    private static func refusal(status: String, reason: String, edgeIndex: Int,
                                detail: SwiftOutcomeJSON = .null) -> SwiftOutcomeJSON {
        .object([
            "seam_version": .string(version),
            "validator_invoked": .bool(false),
            "status": .string(status),
            "reason": .string(reason),
            "eligible": .bool(false),
            "call_return_proven": .bool(false),
            "source_reconstruction_allowed": .bool(false),
            "edge_index": .integer(Int128(edgeIndex)),
            "detail": detail,
        ])
    }
}
