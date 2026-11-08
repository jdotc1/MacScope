import Foundation

/// What the metadata-only retained-input load established about the function-start table.
/// `nil` census means "not captured": every dependent denominator is then null, never zero.
struct AIRSCensus: Equatable, Sendable {
    var rawFunctionStartCount: Int
    /// Unique retained starts, ascending.
    var uniqueStarts: [UInt64]
    /// Exact `FunctionStartsParseOutcome` case name.
    var parseOutcome: String
    /// true for `.terminated`, nil for `.unknown`, false for every other case.
    var isComplete: Bool?

    init(rawFunctionStartCount: Int, uniqueStarts: [UInt64], parseOutcome: String, isComplete: Bool?) {
        self.rawFunctionStartCount = rawFunctionStartCount
        self.uniqueStarts = uniqueStarts
        self.parseOutcome = parseOutcome
        self.isComplete = isComplete
    }

    init(binary: LoadedBinary) {
        rawFunctionStartCount = binary.functionStarts.count
        uniqueStarts = Array(Set(binary.functionStarts)).sorted()
        let outcome = binary.functionStartsParseOutcome
        switch outcome {
        case .unknown: parseOutcome = "unknown"; isComplete = nil
        case .absentCommand: parseOutcome = "absentCommand"; isComplete = false
        case .emptyPayload: parseOutcome = "emptyPayload"; isComplete = false
        case .unterminatedPayload: parseOutcome = "unterminatedPayload"; isComplete = false
        case .terminated: parseOutcome = "terminated"; isComplete = true
        case .entryLimitReached: parseOutcome = "entryLimitReached"; isComplete = false
        case .unavailableImageBase: parseOutcome = "unavailableImageBase"; isComplete = false
        }
    }

    var sourceFields: [String: ScriptValue] {
        [
            "rawFunctionStartCount": .int(Int64(rawFunctionStartCount)),
            "functionsInImage": .int(Int64(uniqueStarts.count)),
            "functionsInImageScope": .string("retainedFunctionStarts"),
            "functionStartCompleteness": isComplete.map(ScriptValue.bool) ?? .null,
            "functionStartParseOutcome": .string(parseOutcome),
            "trueBinaryFunctionCount": .null,
        ]
    }

    /// Fields for a missing census: counts are null, with the explicit reason.
    static let unavailableFields: [String: ScriptValue] = [
        "rawFunctionStartCount": .null, "functionsInImage": .null,
        "functionsInImageScope": .string("retainedFunctionStarts"),
        "functionStartCompleteness": .null, "functionStartParseOutcome": .null,
        "trueBinaryFunctionCount": .null, "censusStatus": .string("census-unavailable"),
    ]
}

/// The repeated, unchanged denominator block. Wraps a plain object so nothing defaults to zero.
struct AIRSReadDenominators: Equatable, Sendable {
    var fields: [String: ScriptValue]
    var value: ScriptValue { .object(fields) }

    static func unwind(report: UnwindAuditReport, census: AIRSCensus?) -> AIRSReadDenominators {
        var fields = census?.sourceFields ?? AIRSCensus.unavailableFields
        let findings = report.findings
        func count(_ verdict: String) -> Int64 { Int64(findings.filter { $0.verdict == verdict }.count) }
        var byReason: [String: Int64] = [:]
        var reasonless: Int64 = 0
        for finding in findings where finding.verdict == "unresolved" {
            let codes = Set(finding.reasonCodes)
            if codes.isEmpty { reasonless += 1 }
            for code in codes { byReason[code, default: 0] += 1 }
        }
        fields["functionsAudited"] = .int(Int64(findings.count))
        fields["agreement"] = .int(count("agreement"))
        fields["inconsistency"] = .int(count("inconsistency"))
        fields["unresolved"] = .int(count("unresolved"))
        fields["unresolvedByReason"] = .object(byReason.mapValues { .int($0) })
        fields["unresolvedReasonless"] = .int(reasonless)
        fields["functionsRefusedByLimit"] = .int(0)
        fields["rawStartsRefusedByLimit"] = .int(0)
        return .init(fields: fields)
    }
}

/// Immutable retained rows plus every page-level fact. Pages are views of one of these; a
/// continuation never recomputes.
struct AIRSReadReport: Sendable {
    let id: UUID
    let command: String
    let model: AIRSReadModel
    let modelID: String
    let imageSlot: Int
    let imageOwnerID: UUID
    let installationID: UUID
    let generation: UUID
    let entryID: UUID
    let focusEpoch: UUID
    let reportStateEpoch: UUID
    /// `all` or `fn:<decimal start>`: a collision-free retained descriptor, never a hash.
    let filterToken: String
    var rows: [ScriptValue]
    /// Page-level static fields, repeated unchanged on every page.
    var header: [String: ScriptValue]
    var denominators: AIRSReadDenominators
    /// nil = genuinely unknown from retained provenance.
    var sourceComplete: Bool?
}

/// A whole-report abort: a refusal plus an `analysis` adjunct that is explicitly not a zero-result page.
enum AIRSAbort {
    static func refusal(_ refusal: MCPToolRefusal, denominators: AIRSReadDenominators?,
                        diagnostic: String? = nil) -> ScriptValue {
        guard case .object(var base) = refusal.value else { return refusal.value }
        var adjunct: [String: ScriptValue] = [
            "status": .string("aborted"), "rows": .array([]), "total": .null, "totalLowerBound": .int(0),
            "totalIsExact": .bool(false), "isTruncated": .bool(false), "nextCursor": .null,
            "sourceComplete": .bool(false), "denominators": denominators?.value ?? .null,
        ]
        if let diagnostic { adjunct["diagnostic"] = .string(diagnostic) }
        base["analysis"] = .object(adjunct)
        return .object(base)
    }
}

/// Lossless wire projections: every UInt64 is a canonical lowercase `0x` string.
enum AIRSWire {
    static func identity(_ identity: MachOSliceArtifactIdentity) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "rawCPUType": .int(Int64(identity.rawCPUType)), "rawCPUSubtype": .int(Int64(identity.rawCPUSubtype)),
            "architectureVariant": .string(identity.architectureVariant.rawValue),
            "selectedSliceSHA256": .string(identity.selectedSliceSHA256),
            "selectedSliceByteCount": .hex(identity.selectedSliceByteCount),
        ]
        if let uuid = identity.uuid { fields["uuid"] = .string(uuid.uuidString) }
        return .object(fields)
    }

    static func fingerprint(_ value: FunctionVersionFingerprint) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "id": .string(value.id), "address": .hex(value.address), "size": .hex(value.size),
        ]
        if let name = value.symbolName { fields["symbolName"] = .string(name) }
        if let count = value.basicBlockCount { fields["basicBlockCount"] = .int(Int64(count)) }
        if let count = value.edgeCount { fields["edgeCount"] = .int(Int64(count)) }
        if let text = value.cfgShapeHash { fields["cfgShapeHash"] = .string(text) }
        if let text = value.normalizedBodyHash { fields["normalizedBodyHash"] = .string(text) }
        if let text = value.semanticBodyHash { fields["semanticBodyHash"] = .string(text) }
        if let count = value.instructionCount { fields["instructionCount"] = .int(Int64(count)) }
        if let ids = value.calleeIDs { fields["calleeIDs"] = .array(ids.map { .string($0) }) }
        if let names = value.importedCalleeNames { fields["importedCalleeNames"] = .array(names.map { .string($0) }) }
        if let refs = value.stringReferences { fields["stringReferences"] = .array(refs.map { .string($0) }) }
        return .object(fields)
    }

    static func evidence(_ value: UnwindAuditEvidence) -> ScriptValue {
        var fields: [String: ScriptValue] = ["code": .string(value.code), "message": .string(value.message)]
        if let address = value.address { fields["address"] = .hex(address) }
        if let text = value.expected { fields["expected"] = .string(text) }
        if let text = value.observed { fields["observed"] = .string(text) }
        return .object(fields)
    }

    static func unwindRow(_ finding: UnwindAuditFinding, modelID: String) -> ScriptValue {
        var item: [String: ScriptValue] = [
            "identity": identity(finding.identity), "function": fingerprint(finding.function),
            "endAddress": .hex(finding.endAddress), "verdict": .string(finding.verdict),
            "coverage": .string(finding.coverage), "mode": .string(finding.mode), "scope": .string(finding.scope),
            "reasonCodes": .array(finding.reasonCodes.map { .string($0) }),
            "checkedPCs": .array(finding.checkedPCs.map { .hex($0) }),
            "evidence": .array(finding.evidence.map(evidence)),
            "limitations": .array(finding.limitations.map { .string($0) }),
            "instructionCount": .int(Int64(finding.instructionCount)),
        ]
        if let encoding = finding.encoding { item["encoding"] = .int(Int64(encoding)) }
        let unresolved = finding.verdict == "unresolved"
        return .object([
            "kind": .string("unwindFinding"), "analysisModelVersion": .string(modelID), "finding": .object(item),
            "refusalReason": unresolved && finding.reasonCodes.count == 1 ? .string(finding.reasonCodes[0]) : .null,
            "refusalReasons": .array(unresolved ? finding.reasonCodes.map { .string($0) } : []),
        ])
    }

    static func edge(_ edge: SwiftErrorFlowEdge) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "callerStart": .hex(edge.callerStart), "callAddress": .hex(edge.callAddress),
            "calleeAddress": .hex(edge.calleeAddress), "symbol": .string(edge.symbol),
            "testAddress": .hex(edge.testAddress), "successAddress": .hex(edge.successAddress),
            "errorAddress": .hex(edge.errorAddress), "callOffset": .hex(edge.callOffset),
            "testOffset": .hex(edge.testOffset), "successOffset": .hex(edge.successOffset),
            "errorOffset": .hex(edge.errorOffset), "testKind": .string(edge.testKind),
            "evidenceWords": .array(edge.evidenceWords.map { .int(Int64($0)) }),
        ]
        if let address = edge.comparisonAddress { fields["comparisonAddress"] = .hex(address) }
        if let register = edge.testedRegister { fields["testedRegister"] = .int(Int64(register)) }
        return .object(fields)
    }

    static func word(_ word: SwiftErrorRegionWord) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "address": .hex(word.address), "word": .int(Int64(word.word)), "kind": .string(word.kind),
            "opaqueCall": .bool(word.opaqueCall),
        ]
        if let target = word.targetAddress { fields["targetAddress"] = .hex(target) }
        return .object(fields)
    }

    static func entry(_ value: SwiftErrorEntryValidation) -> ScriptValue {
        .object([
            "scope": .string(value.scope.rawValue), "status": .string(value.status.rawValue),
            "protectedStartAddress": .hex(value.protectedStartAddress),
            "protectedEndExclusive": .hex(value.protectedEndExclusive), "callerStart": .hex(value.callerStart),
            "callerWordCount": .int(Int64(value.callerWordCount)), "scannedWordCount": .int(Int64(value.scannedWordCount)),
            "callerScanComplete": .bool(value.callerScanComplete),
            "unexpectedEntryCount": .int(Int64(value.unexpectedEntryCount)),
            "unexpectedEntries": .array(value.unexpectedEntries.map(word)),
            "entryDetailsComplete": .bool(value.entryDetailsComplete),
            "unclassifiedWordCount": .int(Int64(value.unclassifiedWordCount)),
            "unclassifiedWords": .array(value.unclassifiedWords.map(word)),
            "unclassifiedDetailsComplete": .bool(value.unclassifiedDetailsComplete),
            "exclusiveEntryProven": .bool(value.exclusiveEntryProven), "flagStateProven": .bool(value.flagStateProven),
        ])
    }

    static func regionRow(_ value: SwiftErrorRegionResult) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "edge": edge(value.edge), "status": .string(value.status.rawValue),
            "instructions": .array(value.instructions.map(word)),
            "opaqueCallCount": .int(Int64(value.opaqueCallCount)),
            "postcallWindow": entry(value.postcallWindow),
            "callReturnProven": .bool(value.callReturnProven),
            "joinReachabilityProven": .bool(value.joinReachabilityProven),
            "sourceReconstructionAllowed": .bool(value.sourceReconstructionAllowed),
            "runtimeReachabilityProven": .bool(value.runtimeReachabilityProven),
        ]
        if let reason = value.reason { fields["reason"] = .string(reason.rawValue) }
        if let start = value.startAddress { fields["startAddress"] = .hex(start) }
        if let end = value.endExclusive { fields["endExclusive"] = .hex(end) }
        if let join = value.joinAddress { fields["joinAddress"] = .hex(join) }
        if let incoming = value.incomingEntries { fields["incomingEntries"] = entry(incoming) }
        return .object(fields)
    }
}

/// Identity of one admitted read: everything a cursor binds to besides the offset.
struct AIRSReadContext: Sendable {
    var command: String
    var model: AIRSReadModel
    var modelID: String
    var imageSlot: Int
    var imageOwnerID: UUID
    var installationID: UUID
    var generation: UUID
    var entryID: UUID
    var epochs: AIRSEpochs
    var function: UInt64?

    var filterToken: String { function.map { "fn:\($0)" } ?? "all" }
}

enum AIRSBuildResult {
    case report(AIRSReadReport)
    case absent(subject: ScriptValue, reason: String)
    /// A whole-report abort (refusal plus the `analysis` adjunct).
    case aborted(ScriptValue)
}

/// Pure construction of an immutable retained report from analyzer output. No store access.
enum AIRSReadBuilder {
    static let maximumRawFunctionStarts = 50_000

    private static func mint(_ c: AIRSReadContext, rows: [ScriptValue], header: [String: ScriptValue],
                             denominators: AIRSReadDenominators, sourceComplete: Bool?) -> AIRSReadReport {
        var header = header
        header["imageSlot"] = .int(Int64(c.imageSlot))
        header["model"] = .string(c.model.rawValue)
        header["analysisModelVersion"] = .string(c.modelID)
        if let function = c.function { header["function"] = .hex(function) }
        return AIRSReadReport(
            id: UUID(), command: c.command, model: c.model, modelID: c.modelID, imageSlot: c.imageSlot,
            imageOwnerID: c.imageOwnerID, installationID: c.installationID, generation: c.generation,
            entryID: c.entryID, focusEpoch: c.epochs.focus, reportStateEpoch: c.epochs.reportState,
            filterToken: c.filterToken, rows: rows, header: header, denominators: denominators,
            sourceComplete: sourceComplete)
    }

    private static func refusal(_ detail: String, code: MCPRefusalCode = .preconditionFailed, retryable: Bool = false,
                                budget: MCPRefusalBudget? = nil, used: Int64? = nil,
                                denominators: AIRSReadDenominators?) -> AIRSBuildResult {
        .aborted(AIRSAbort.refusal(MCPToolRefusal(code: code, detail: detail, retryable: retryable, budget: budget, used: used),
                                   denominators: denominators))
    }

    // MARK: Unwind

    static func unwind(report: UnwindAuditReport, census: AIRSCensus?, context c: AIRSReadContext) -> AIRSBuildResult {
        if let census, census.rawFunctionStartCount > maximumRawFunctionStarts {
            var fields = census.sourceFields
            fields["functionsAudited"] = .int(0)
            fields["agreement"] = .int(0); fields["inconsistency"] = .int(0); fields["unresolved"] = .int(0)
            fields["functionsRefusedByLimit"] = .int(Int64(census.uniqueStarts.count))
            fields["rawStartsRefusedByLimit"] = .int(Int64(census.rawFunctionStartCount))
            return refusal("functionStartBudgetExceeded", code: .budgetExceeded,
                           budget: MCPRefusalBudget(unit: .rows, limit: Int64(maximumRawFunctionStarts)),
                           used: Int64(census.rawFunctionStartCount), denominators: .init(fields: fields))
        }
        let denominators = AIRSReadDenominators.unwind(report: report, census: census)
        if let census, Set(report.findings.map(\.function.address)) != Set(census.uniqueStarts) {
            return refusal("reportReceiptMismatch", code: .conflictsWithAuthority, denominators: denominators)
        }
        let sorted = report.findings.sorted {
            ($0.function.address, $0.function.id) < ($1.function.address, $1.function.id)
        }
        let selected = c.function.map { start in sorted.filter { $0.function.address == start } } ?? sorted
        if let function = c.function, selected.isEmpty {
            return .absent(subject: .object(["function": .hex(function)]), reason: "noSuchSubject")
        }
        let rows = selected.map { AIRSWire.unwindRow($0, modelID: c.modelID) }
        let complete: Bool? = census?.isComplete
        return .report(mint(c, rows: rows, header: ["source": .string("retainedCoordinatorReport")],
                            denominators: denominators, sourceComplete: complete))
    }

    // MARK: Swift

    private static func countByCode(_ items: [SwiftErrorFlowAbstention]) -> ScriptValue {
        var counts: [String: Int64] = [:]
        for item in items { counts[item.code, default: 0] += 1 }
        return .object(counts.mapValues { .int($0) })
    }

    static func swift(raw: AIRSSwiftRawResult, context c: AIRSReadContext) -> AIRSBuildResult {
        guard let function = c.function else {
            return refusal("functionRequired", denominators: nil)
        }
        let census = raw.census
        var base = census?.sourceFields ?? AIRSCensus.unavailableFields
        let edgeReport: SwiftErrorFlowReport
        var regionReport: SwiftErrorRegionReport?
        var witnessReport: SwiftOutcomeReadResult?
        switch raw.outcome {
        case .rejected(let code):
            return refusal(code, denominators: .init(fields: base))
        case .edges(let value): edgeReport = value
        case .regions(let value): edgeReport = value.edgeReport; regionReport = value
        case .outcomeWitnesses(let value): edgeReport = value.edgeReport; witnessReport = value
        }
        guard edgeReport.status == .analyzed else {
            let code = edgeReport.abstentions.first?.code ?? "analysis_rejected"
            base["abstentionsByCode"] = countByCode(edgeReport.abstentions)
            return refusal(code, denominators: .init(fields: base))
        }
        guard let interval = raw.admittedIntervals.first(where: { $0.start == function }) else {
            if census?.uniqueStarts.contains(function) == true {
                base["functionsAdmitted"] = .int(Int64(raw.admittedIntervals.count))
                base["selectedFunctionAdmitted"] = .bool(false)
                return refusal("functionBoundaryNotAdmitted", denominators: .init(fields: base))
            }
            return .absent(subject: .object(["function": .hex(function)]), reason: "noSuchSubject")
        }
        let indexed = edgeReport.edges.enumerated().filter { $0.element.callerStart == function }
        let ordered = indexed.sorted {
            let l = $0.element, r = $1.element
            return (l.callerStart, l.callAddress, l.calleeAddress, l.testAddress, $0.offset)
                < (r.callerStart, r.callAddress, r.calleeAddress, r.testAddress, $1.offset)
        }
        var availability: [Int: SwiftErrorRegionResult] = [:]
        if let regionReport {
            var pointer = 0
            for (index, edge) in edgeReport.edges.enumerated() where pointer < regionReport.regions.count {
                if regionReport.regions[pointer].edge == edge { availability[index] = regionReport.regions[pointer]; pointer += 1 }
            }
        }
        var rows: [ScriptValue] = []
        var selectedRegionResults = 0
        var selectedWitnessCount = 0
        var selectedRegionDetailsComplete = true
        for (index, edge) in ordered.map({ ($0.offset, $0.element) }) {
            var row: [String: ScriptValue] = [
                "kind": .string("swiftErrorEdge"),
                "analysisModelVersion": .string(edgeReport.model),
                "edge": AIRSWire.edge(edge),
            ]
            if let witnessReport {
                row["kind"] = .string("swiftOutcomeWitness")
                row["analysisModelVersion"] = .string(c.modelID)
                row["edgeAnalysisModelVersion"] = .string(edgeReport.model)
                if SwiftOutcomeReadBridge.project(witnessReport.witnessesByEdgeIndex[index],
                                                  originalEdgeIndex: index, into: &row) {
                    selectedWitnessCount += 1
                }
            }
            if regionReport == nil {
                row["region"] = .null; row["regionAvailability"] = .string("notRequested")
            } else if let region = availability[index] {
                row["region"] = AIRSWire.regionRow(region); row["regionAvailability"] = .string("present")
                selectedRegionResults += 1
                let windows = [region.postcallWindow] + (region.incomingEntries.map { [$0] } ?? [])
                if !windows.allSatisfy({ $0.callerScanComplete && $0.entryDetailsComplete && $0.unclassifiedDetailsComplete }) {
                    selectedRegionDetailsComplete = false
                }
            } else {
                row["region"] = .null; row["regionAvailability"] = .string("omittedByRegionCap")
                selectedRegionDetailsComplete = false
            }
            rows.append(.object(row))
        }
        let selectedAbstentions = edgeReport.abstentions.filter {
            guard let address = $0.address else { return false }
            return address >= interval.start && address < interval.endExclusive
        }
        let globalAbstentions = edgeReport.abstentions.filter { $0.address == nil }
        let selectedEdges = ordered.count
        base["functionsAdmitted"] = .int(Int64(raw.admittedIntervals.count))
        base["selectedFunctionAdmitted"] = .bool(true)
        base["declarations"] = .int(Int64(edgeReport.declarations.count))
        base["edges"] = .int(Int64(edgeReport.edges.count))
        base["selectedEdges"] = .int(Int64(selectedEdges))
        base["abstentionsByCode"] = countByCode(edgeReport.abstentions)
        base["selectedAbstentionsByCode"] = countByCode(selectedAbstentions)
        base["globalAbstentions"] = .array(globalAbstentions.map { .object(["code": .string($0.code)]) })
        base["selectedAbstentions"] = .array(selectedAbstentions.map {
            .object(["code": .string($0.code), "address": $0.address.map(ScriptValue.hex) ?? .null])
        })
        var header: [String: ScriptValue] = ["source": .string("ephemeralSwiftCoordinator")]
        let relevantCallees = Set(ordered.map { $0.element.calleeAddress })
        header["admission"] = .object([
            "status": .string(edgeReport.status.rawValue),
            "slice": .object([
                "artifactSHA256": .string(edgeReport.slice.artifactSHA256),
                "sliceOffset": .hex(edgeReport.slice.sliceOffset), "sliceByteCount": .hex(edgeReport.slice.sliceByteCount),
                "cpuType": .int(Int64(edgeReport.slice.cpuType)), "cpuSubtype": .int(Int64(edgeReport.slice.cpuSubtype)),
                "littleEndian": .bool(edgeReport.slice.littleEndian),
            ]),
            "interval": .object([
                "start": .hex(interval.start), "endExclusive": .hex(interval.endExclusive),
                "boundarySource": .string(interval.boundarySource),
            ]),
            "declarations": .array(edgeReport.declarations.filter { relevantCallees.contains($0.address) }.map {
                .object(["address": .hex($0.address), "symbol": .string($0.symbol), "module": .string($0.module),
                         "name": .string($0.name), "parameters": .array($0.parameters.map { .string($0) }),
                         "result": .string($0.result)])
            }),
            "abstentions": .array(selectedAbstentions.map {
                .object(["code": .string($0.code), "address": $0.address.map(ScriptValue.hex) ?? .null])
            }),
        ])
        header["sourceReconstructionAllowed"] = .bool(false)
        header["runtimeReachabilityProven"] = .bool(false)
        var complete: Bool? = census?.isComplete
        if let witnessReport {
            header["edgeAnalysisModelVersion"] = .string(edgeReport.model)
            header["witnessModelVersion"] = .string(witnessModel)
            header["validationModelVersion"] = .string(validationModel)
            header["witnessStatus"] = .string("unresolved")
            header["witnessEligible"] = .bool(false)
            header["witnessABIStatus"] = .string("unavailable")
            base["witnessCount"] = .int(Int64(witnessReport.encodedCount))
            base["witnessRefusalCount"] = .int(Int64(edgeReport.edges.count - witnessReport.encodedCount))
            base["witnessEncodedBytes"] = .int(Int64(witnessReport.encodedByteCount))
            base["selectedWitnessCount"] = .int(Int64(selectedWitnessCount))
            base["selectedWitnessRefusalCount"] = .int(Int64(selectedEdges - selectedWitnessCount))
            base["witnessDetailsComplete"] = .bool(false)
            // ABI/candidate completeness is separate from retained source completeness. Only a
            // selected witness that could not be retained makes this source projection incomplete.
            if selectedWitnessCount != selectedEdges { complete = false }
        }
        if let regionReport {
            header["entryModel"] = .string(regionReport.entryModel)
            header["edgeAnalysisModelVersion"] = .string(edgeReport.model)
            let omitted = selectedEdges - selectedRegionResults
            base["recoveredEdgeCount"] = .int(Int64(regionReport.recoveredEdgeCount))
            base["regionResultCount"] = .int(Int64(regionReport.regions.count))
            base["omittedRegionCount"] = .int(Int64(regionReport.omittedRegionCount))
            base["regionDetailsComplete"] = .bool(regionReport.regionDetailsComplete)
            base["callerScanCount"] = .int(Int64(regionReport.callerScanCount))
            base["scannedWordCount"] = .int(Int64(regionReport.scannedWordCount))
            base["selectedRecoveredEdgeCount"] = .int(Int64(selectedEdges))
            base["selectedRegionResultCount"] = .int(Int64(selectedRegionResults))
            base["selectedOmittedRegionCount"] = .int(Int64(omitted))
            base["selectedRegionDetailsComplete"] = .bool(selectedRegionDetailsComplete)
            if !selectedRegionDetailsComplete { complete = false }
        }
        return .report(mint(c, rows: rows, header: header, denominators: .init(fields: base), sourceComplete: complete))
    }
}
