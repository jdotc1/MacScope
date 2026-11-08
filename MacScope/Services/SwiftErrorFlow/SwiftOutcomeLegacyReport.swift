import Foundation

// Pure request adapter for donor recovery (swift_error_flow.py:1637-1777).
// Admission is the existing SwiftErrorFlowRequest contract, not a new Mach-O
// parser. Only the supplied executable section is represented. No live wiring.
struct SwiftOutcomeLegacyReportLimits: Sendable {
    var maxFileBytes: UInt64 = 512 * 1024 * 1024
    var maxFunctions = 50_000
    var maxInstructionsPerFunction = 16_384
    var maxTotalInstructions = 1_000_000
    var maxEvidencePerFunction = 32
    var maxTotalEvidence = 8192
}
func recoverSwiftOutcomeLegacyRequest(_ request: SwiftErrorFlowRequest,
                                     limits: SwiftOutcomeLegacyReportLimits = SwiftOutcomeLegacyReportLimits(),
                                     includeErrorRegions: Bool = false,
                                     validateRegionEntries: Bool = false,
                                     includeStructuredPresentation: Bool = false) throws -> SwiftOutcomeJSON {
    guard !includeStructuredPresentation || includeErrorRegions && validateRegionEntries else { throw SwiftOutcomeError(code: "swift_presentation_option") }
    guard !validateRegionEntries || includeErrorRegions else { throw SwiftOutcomeError(code: "swift_region_option") }
    guard request.slice.cpuType == 0x0100000c, [UInt32(0),1].contains(request.slice.cpuSubtype), request.slice.littleEndian else { throw SwiftOutcomeError(code: "swift_flow_architecture") }
    guard [limits.maxFunctions, limits.maxInstructionsPerFunction, limits.maxTotalInstructions, limits.maxEvidencePerFunction, limits.maxTotalEvidence].allSatisfy({ $0 >= 0 }) else { throw SwiftOutcomeError(code: "invalid_limits") }
    guard request.slice.sliceByteCount <= limits.maxFileBytes, request.functions.count <= limits.maxFunctions else { throw SwiftOutcomeError(code: "swift_flow_limit") }
    guard Set(request.functions.map(\.start)).count == request.functions.count else { throw SwiftOutcomeError(code: "swift_flow_boundaries") }
    let codeEnd = Int128(request.code.baseAddress) + Int128(request.code.words.count) * 4
    guard codeEnd <= Int128(UInt64.max), request.code.baseAddress >= request.code.sliceRelativeFileOffset else { throw SwiftOutcomeError(code: "swift_flow_boundaries") }
    let preferredBase = request.code.baseAddress - request.code.sliceRelativeFileOffset
    let functions = Dictionary(uniqueKeysWithValues: request.functions.map { ($0.start, $0) })
    var groups: [UInt64: [SwiftErrorFlowSymbol]] = [:]
    for symbol in request.symbols where symbol.nType & 0xe0 == 0 && symbol.nType & 0x0e == 0x0e && functions[symbol.address] != nil && symbol.sectionOrdinal == request.code.sectionOrdinal && symbol.address >= request.code.baseAddress && Int128(symbol.address) < codeEnd {
        groups[symbol.address, default: []].append(symbol)
    }
    var remaining = limits.maxTotalInstructions, calls: [SwiftOutcomeJSON] = [], scans: [SwiftOutcomeJSON] = [], reasons: [String: Int] = [:]
    var observed = 0, omitted = 0, scanned = 0, complete = true
    for function in request.functions {
        let name = request.symbols.first { $0.address == function.start }?.name ?? swiftOutcomeHex(function.start)
        var scan: SwiftOutcomeJSON = .object(["function_pc": .string(swiftOutcomeHex(function.start)), "name": .string(name), "scanned_words": .integer(0)])
        guard function.boundarySource == "lc_function_starts", function.endExclusive > function.start, function.start % 4 == 0, (function.endExclusive - function.start) % 4 == 0 else {
            scan["status"] = .string("excluded_boundary"); complete = false; scans.append(scan); continue
        }
        let count128 = min(Int128((function.endExclusive - function.start) / 4), Int128(limits.maxInstructionsPerFunction), Int128(remaining))
        let count = Int(count128)
        let whole = UInt64(count) * 4 == function.endExclusive - function.start
        scan["status"] = .string(whole ? "complete" : "partial_budget"); complete = complete && whole
        guard function.start >= request.code.baseAddress, Int128(function.start) + Int128(count) * 4 <= codeEnd, (function.start - request.code.baseAddress) % 4 == 0 else { throw SwiftOutcomeError(code: "unmapped_address") }
        let first = Int((function.start - request.code.baseAddress) / 4)
        let words = Array(request.code.words[first..<(first + count)])
        let recovery = SwiftOutcomeLegacyRecovery(words: words, start: function.start, endExclusive: function.endExclusive)
        var retained = 0
        let direct = recovery.directEdges()
        for (index, word) in words.enumerated() {
            scanned += 1; remaining -= 1; scan["scanned_words"] = .integer(Int128(index + 1))
            guard word & 0xfc000000 == 0x94000000 else { continue }
            observed += 1
            guard retained < limits.maxEvidencePerFunction, calls.count < limits.maxTotalEvidence else { omitted += 1; continue }
            retained += 1
            let pc = function.start + UInt64(index) * 4, instruction = try decodeSwiftOutcomeLegacyInstruction(word: word, address: pc)
            let target = swiftOutcomeLegacyTarget(instruction)
            var call: SwiftOutcomeJSON = .object(["call_pc": .string(swiftOutcomeHex(pc)), "call_image_offset": .string(swiftOutcomeHex(Int128(pc) - Int128(preferredBase))), "call_word": .string(swiftOutcomeLegacyWord(word)), "caller_pc": .string(swiftOutcomeHex(function.start)), "callee_pc": target.map { .string(swiftOutcomeHex($0)) } ?? .null, "status": .string("declined")])
            if let target {
                if functions[target]?.boundarySource != "lc_function_starts" { call["reason"] = .string("callee_not_exact_function_entry") }
                else if let symbols = groups[target], symbols.count == 1 {
                    let symbol = symbols[0]
                    if symbol.nType == 0x0f, symbol.nDesc & 0x300 == 0, let declaration = parseThrowingDeclaration(symbol.name) {
                        call["callee"] = swiftOutcomeLegacyWith(declaration.record(), ["symbol": .string(symbol.name), "image_offset": .string(swiftOutcomeHex(Int128(target) - Int128(preferredBase)))])
                        call = swiftOutcomeLegacyWith(call, recovery.edges(callOffset: index * 4).object ?? [:])
                        if validateRegionEntries && call["test_kind"].string == "cmp_zero_bcond" { call["flag_entry_validation"] = recovery.flagEntries(call: call, scan: direct) }
                        if includeErrorRegions && call["status"].string == "recovered_candidate" {
                            var region = recovery.region(call: call)
                            if validateRegionEntries && region["status"].string == "structural_region_candidate" { region["incoming_validation"] = recovery.incoming(region: region, call: call, scan: direct) }
                            call["error_region"] = region
                        }
                    } else { call["reason"] = .string("callee_declaration_outside_subset") }
                } else { call["reason"] = .string("callee_symbol_absent_or_ambiguous") }
            } else { call["reason"] = .string("callee_target_out_of_range") }
            if call["status"].string == "declined", let reason = call["reason"].string { reasons[reason, default: 0] += 1 }
            if includeStructuredPresentation {
                call["presentation"] = recovery.presentation(call: call)
                call["success_result"] = recovery.successResult(call: call, scan: direct)
                call["success_constant"] = recovery.pathConstant(call: call, scan: direct)
                call["error_constant"] = recovery.pathConstant(call: call, error: true, scan: direct)
                call["return_choice"] = swiftOutcomeLegacyReturnChoice(call)
            }
            calls.append(call)
        }
        scans.append(scan)
    }
    let recovered = calls.filter { $0["status"].string == "recovered_candidate" }.count
    var summary: SwiftOutcomeJSON = .object(["scanned_word_count": .integer(Int128(scanned)), "observed_direct_call_count": .integer(Int128(observed)), "retained_call_count": .integer(Int128(calls.count)), "omitted_call_count": .integer(Int128(omitted)), "recovered_candidate_count": .integer(Int128(recovered)), "declined_retained_call_count": .integer(Int128(calls.count - recovered))])
    var report: SwiftOutcomeJSON = .object(["schema_version": .integer(1), "report_kind": .string("airs.swift_error_flow"), "model_version": .string("swift-sync-error-edges-v37"), "scope": .string("structural_call_return_edges"), "address_space": .string("preferred_vm"), "word_scan_complete": .bool(complete), "call_details_complete": .bool(omitted == 0), "reasons": .array(reasons.keys.sorted().map { .object(["code": .string($0), "count": .integer(Int128(reasons[$0] ?? 0))]) }), "functions": .array(scans), "calls": .array(calls)])
    if includeErrorRegions {
        report["error_region_model_version"] = .string("swift-sync-error-region-v24")
        summary["recovered_error_region_count"] = .integer(Int128(calls.filter { $0["error_region"]["status"].string == "structural_region_candidate" }.count))
        summary["declined_error_region_count"] = .integer(Int128(calls.filter { $0["error_region"]["status"].string == "declined" }.count))
    }
    if validateRegionEntries { report["region_incoming_model_version"] = .string("swift-region-direct-entries-v7"); report["flag_entry_model_version"] = .string("swift-compare-flag-entries-v1") }
    if includeStructuredPresentation {
        report["structured_presentation_model_version"] = .string("swift-structural-presentation-v10")
        report["success_result_model_version"] = .string("swift-success-result-v24"); report["success_constant_model_version"] = .string("swift-success-constant-v17"); report["error_constant_model_version"] = .string("swift-error-constant-v19"); report["return_choice_model_version"] = .string("swift-return-choice-v45")
        for status in ["eligible_structural_only", "blocked", "unresolved"] { summary["presentation_" + status + "_count"] = .integer(Int128(calls.filter { $0["presentation"]["status"].string == status }.count)) }
    }
    report["summary"] = summary
    // Request projection: no fictitious raw Mach-O image, input issues, nominal
    // context, optional witness orchestration, or CLI/text report is invented.
    return report
}
