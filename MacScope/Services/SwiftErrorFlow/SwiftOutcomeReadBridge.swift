import Foundation

/// An entry exists for every original native edge, including an encoding or retention refusal.
/// Indices refer to `edgeReport.edges` before function filtering or presentation sorting.
struct SwiftOutcomeReadResult: Sendable {
    enum Witness: Equatable, Sendable {
        case encoded(Data)
        case refused(code: String)
    }
    let edgeReport: SwiftErrorFlowReport
    let witnessesByEdgeIndex: [Int: Witness]

    var encodedCount: Int {
        witnessesByEdgeIndex.values.reduce(0) { count, witness in
            if case .encoded = witness { return count + 1 }
            return count
        }
    }
    var encodedByteCount: Int {
        witnessesByEdgeIndex.values.reduce(0) { count, witness in
            if case .encoded(let bytes) = witness { return count + bytes.count }
            return count
        }
    }
}

/// Native admission supplies the call/declaration facts, never an ABI qualification. Witness
/// production and canonical encoding finish in the worker; page requests only read these bytes.
enum SwiftOutcomeReadBridge {
    static func build(request: SwiftErrorFlowRequest, edgeReport: SwiftErrorFlowReport,
                      limits: BroadWitnessLimits = BroadWitnessLimits()) -> SwiftOutcomeReadResult {
        guard edgeReport.status == .analyzed else {
            return SwiftOutcomeReadResult(edgeReport: edgeReport, witnessesByEdgeIndex: [:])
        }
        let image = SwiftOutcomeImage(request)
        var retained: [Int: SwiftOutcomeReadResult.Witness] = [:]
        var retainedBytes = 0
        for (index, edge) in edgeReport.edges.enumerated() {
            do {
                guard let function = request.functions.first(where: { $0.start == edge.callerStart }),
                      let declaration = edgeReport.declarations.first(where: {
                          $0.address == edge.calleeAddress && $0.symbol == edge.symbol
                      }) else { throw SwiftOutcomeError(code: "native_admission_mismatch") }
                let callsite = try nativeCallsite(request: request, edge: edge, declaration: declaration)
                let witness = buildBroadSwiftWitness(image: image, function: function,
                                                    callsite: callsite, limits: limits)
                let bytes = try SwiftOutcomeWitnessCodec.encode(witness, limits: limits)
                guard bytes.count <= limits.maxAggregateBytes - retainedBytes else {
                    throw SwiftOutcomeError(code: "witness_aggregate_byte_limit")
                }
                retained[index] = .encoded(bytes)
                retainedBytes += bytes.count
            } catch let error as SwiftOutcomeError {
                retained[index] = .refused(code: error.code)
            } catch {
                retained[index] = .refused(code: "witness_encoding_failed")
            }
        }
        return SwiftOutcomeReadResult(edgeReport: edgeReport, witnessesByEdgeIndex: retained)
    }

    /// Coordinates are derived from the admitted request's raw mapping, not caller-relative edge
    /// offsets. Int128 preserves the complete unsigned address range without a floating conversion.
    static func nativeCallsite(request: SwiftErrorFlowRequest, edge: SwiftErrorFlowEdge,
                               declaration: SwiftErrorFlowDeclaration) throws -> SwiftOutcomeJSON {
        let image = SwiftOutcomeImage(request)
        func provenance(_ address: UInt64) throws -> SwiftOutcomeJSON {
            let word = try image.wordAt(address)
            let sliceOffset = Int128(request.code.sliceRelativeFileOffset)
                + Int128(address) - Int128(request.code.baseAddress)
            return .object([
                "pc": .integer(Int128(address)), "word": .integer(Int128(word)),
                "slice_file_offset": .integer(sliceOffset),
                "container_file_offset": .integer(Int128(request.slice.sliceOffset) + sliceOffset),
            ])
        }
        return .object([
            "status": .string("admitted_callsite"),
            "call_pc": .integer(Int128(edge.callAddress)),
            "callee_pc": .integer(Int128(edge.calleeAddress)),
            "provenance": .object([
                "call": try provenance(edge.callAddress),
                "callee_entry": try provenance(edge.calleeAddress),
            ]),
            "declaration": .object([
                "status": .string("syntax_admitted"), "symbol": .string(declaration.symbol),
                "module": .string(declaration.module), "name": .string(declaration.name),
                "parameters": .array(declaration.parameters.map(SwiftOutcomeJSON.string)),
                "result": .string(declaration.result),
                "convention": .string("swift_sync_untyped_throws"),
                "error_register": .string("x21"),
                "source": .string("exact_external_symbol_grammar"),
            ]),
            "abi": .object(["status": .string("unavailable")]),
        ])
    }

    static func project(_ witness: SwiftOutcomeReadResult.Witness?, originalEdgeIndex: Int,
                        into row: inout [String: ScriptValue]) -> Bool {
        row["edgeIndex"] = .int(Int64(originalEdgeIndex))
        row["witnessStatus"] = .string("unresolved")
        row["witnessEligible"] = .bool(false)
        switch witness {
        case .encoded(let bytes)?:
            // The canonical codec emits ASCII. Decoding does not parse, normalize or re-encode JSON.
            row["witnessJSON"] = .string(String(decoding: bytes, as: UTF8.self))
            row["witnessAvailability"] = .string("present")
            row["witnessRefusalReason"] = .null
            return true
        case .refused(let code)?:
            row["witnessJSON"] = .null
            row["witnessAvailability"] = .string("refused")
            row["witnessRefusalReason"] = .string(code)
            return false
        case nil:
            row["witnessJSON"] = .null
            row["witnessAvailability"] = .string("refused")
            row["witnessRefusalReason"] = .string("retained_witness_missing")
            return false
        }
    }
}
