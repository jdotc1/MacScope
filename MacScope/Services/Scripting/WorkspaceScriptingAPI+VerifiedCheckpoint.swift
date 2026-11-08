import Foundation

/// VA4 slice F: the read-only `verified-checkpoint` command. It runs the existing pure checkpoint
/// reader (`VerifiedCheckpoint.check`) over the LIVE store and returns the report. It mutates
/// nothing, registers no undo step and writes no journal record (a read).
///
/// The reply always says `process: "same"`: the live store is read in the server's own process, so
/// this is never the fresh-process proof (that is the headless action, slice D/G). Every reply also
/// carries the analysis generation it was read at. An expectation that is malformed, too large, or
/// names an image slot other than `imageSlot` is a typed refusal, not a report.
extension WorkspaceScriptingAPI {
    static let verifiedCheckpointCommand = "verified-checkpoint"

    static func verifiedCheckpointReply(_ arguments: ScriptValue, store: WorkspaceStore) throws -> ScriptValue {
        func refusal(_ code: MCPRefusalCode, _ detail: String, field: String,
                     maximum: Int64? = nil, imageSlot: Int? = nil) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: code, detail: detail, retryable: false, field: field,
                                              maximum: maximum, imageSlot: imageSlot))
        }
        guard let raw = arguments["expectation"], raw != .null else { throw ScriptingError.missingArgument("expectation") }
        guard case .object = raw else {
            throw refusal(.malformedInput, "expectation must be an object", field: "expectation")
        }
        let slotFilter: Int?
        switch arguments["imageSlot"] {
        case nil, .some(.null): slotFilter = nil
        case let .some(.int(value)) where value >= 0 && value <= Int64(Int32.max): slotFilter = Int(value)
        default: throw refusal(.malformedInput, "imageSlot must be a non-negative integer", field: "imageSlot")
        }
        let expectation: VerifiedCheckpointExpectation
        do {
            let data = try raw.jsonData()
            expectation = try VerifiedCheckpointExpectation.decode(data)
        } catch let invalid as VerifiedCheckpointInvalid {
            let bounded = ["expectation-too-large", "expectation-too-many-operations",
                           "expectation-too-many-installations", "expectation-value-too-large"]
            throw refusal(bounded.contains(invalid.reason) ? .outOfBounds : .malformedInput, invalid.reason,
                          field: "expectation",
                          maximum: bounded.contains(invalid.reason) ? Int64(boundForRefusal(invalid.reason)) : nil)
        } catch {
            throw refusal(.malformedInput, "expectation-malformed", field: "expectation")
        }
        if let slotFilter, let stray = expectation.operations.first(where: { $0.slot != slotFilter }) {
            throw refusal(.malformedInput,
                          "operation \(stray.operationID.uuidString) targets slot \(stray.slot), not imageSlot \(slotFilter)",
                          field: "imageSlot", imageSlot: slotFilter)
        }
        let report = store.verifiedCheckpoint(expectation)
        guard case var .object(fields) = report.jsonValue() else {
            throw ScriptingError.invalidArgument("verified-checkpoint report shape")
        }
        fields["command"] = .string(verifiedCheckpointCommand)
        fields["process"] = .string("same")
        fields["readOnly"] = .bool(true)
        fields["processNote"] = .string("read in the serving process; not the fresh-process proof")
        fields["bounds"] = .object([
            "maximumOperations": .int(Int64(VerifiedCheckpointBounds.maximumOperations)),
            "maximumRequestBytes": .int(Int64(VerifiedCheckpointBounds.maximumRequestFileBytes)),
            "maximumReportEntries": .int(Int64(VerifiedCheckpointBounds.maximumReportEntries)),
            "maximumDiagnosticBytes": .int(Int64(VerifiedCheckpointBounds.maximumDiagnosticBytes)),
        ])
        return withGeneration(.object(fields), generation: store.snapshot.analysisGenerationID)
    }

    private static func boundForRefusal(_ reason: String) -> Int {
        switch reason {
        case "expectation-too-large": return VerifiedCheckpointBounds.maximumRequestFileBytes
        case "expectation-value-too-large": return VerifiedCheckpointBounds.maximumCommentBytes
        default: return VerifiedCheckpointBounds.maximumOperations
        }
    }
}
