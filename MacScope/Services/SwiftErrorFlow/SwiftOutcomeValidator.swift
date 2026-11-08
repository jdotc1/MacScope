import Foundation

func validateBroadSwiftWitness(image: SwiftOutcomeValidatorImage,
                               function: SwiftErrorFlowFunction,
                               candidate: SwiftOutcomeJSON,
                               limits: BroadWitnessLimits = BroadWitnessLimits(),
                               registry: SwiftOutcomeABIRegistry = .frozen,
                               imageLedger: Any? = nil) -> SwiftOutcomeJSON {
    SwiftOutcomeIndependentValidation(image: image, function: function, candidate: candidate,
                                      limits: limits, registry: registry, ledger: imageLedger).validate()
}

private final class SwiftOutcomeIndependentValidation {
    typealias J = SwiftOutcomeJSON
    let image: SwiftOutcomeValidatorImage
    let function: SwiftErrorFlowFunction
    let candidate: J
    let limits: BroadWitnessLimits
    let registry: SwiftOutcomeABIRegistry
    let suppliedLedger: Any?
    var sections: [SwiftNominalSectionInput] = []
    var decoded: [UInt64: SwiftOutcomeInstruction] = [:]
    var facts: [String: J] = [:]
    var work = 0, instructions = 0, edgeCount = 0, states = 0
    var imageInitialWork = 0, imageWorkHere = 0
    var reused = false
    var result: [String: J] = [
        "model_version": .string("swift-outcome-validation-v2"), "status": .string("unresolved"),
        "reason": .string("validation_incomplete"), "eligible": .bool(false), "facts": .object([:]),
        "eligibility_scope": .string("checked_structural_facts_only"), "value_fact_status": .string("unchecked"),
        "symbolic_return_values_complete": .bool(false),
        "completeness": .object(["complete": .bool(false), "missing": .array([])]),
        "runtime_branch_proven": .bool(false), "call_return_proven": .bool(false), "error_state_proven": .bool(false),
        "source_reconstruction_allowed": .bool(false), "handler_semantics_proven": .bool(false),
        "exclusive_entry_proven": .bool(false),
        "limitations": .array(["structural_only", "no_runtime_execution_proof", "no_source_or_handler_semantics",
                                "calls_have_candidate_continuations"].map(J.string))]
    let branches: Set<String> = ["b", "bcond", "xcbz", "xcbnz", "wcbz", "wcbnz", "xtbz", "xtbnz", "wtbz", "wtbnz"]

    init(image: SwiftOutcomeValidatorImage, function: SwiftErrorFlowFunction, candidate: J,
         limits: BroadWitnessLimits, registry: SwiftOutcomeABIRegistry, ledger: Any?) {
        self.image = image; self.function = function; self.candidate = candidate
        self.limits = limits; self.registry = registry; suppliedLedger = ledger
    }
    func need(_ condition: Bool, _ reason: String, _ status: String = "declined") throws {
        if !condition { throw SwiftOutcomeValidatorStop(reason: reason, status: status) }
    }
    func charge(_ amount: Int = 1) throws {
        try need(amount >= 0 && amount <= limits.maxWork - work, "validator_work_limit", "unresolved")
        work += amount
    }
    func hex(_ value: UInt64) -> J { .string("0x" + String(value, radix: 16)) }
    func word(_ value: UInt32) -> J { .string(String(format: "0x%08x", value)) }
    func int(_ value: Int) -> J { .integer(Int128(value)) }
    func plus(_ pc: UInt64, _ delta: Int128, reason: String = "cfg_target_outside_caller") throws -> UInt64 {
        let sum = Int128(pc).addingReportingOverflow(delta)
        try need(!sum.overflow && sum.partialValue >= 0 && sum.partialValue <= Int128(UInt64.max), reason)
        return UInt64(sum.partialValue)
    }
    func address(_ value: J) throws -> UInt64 {
        guard let text = value.string, text.hasPrefix("0x"), text.count >= 3, text.count <= 18,
              text.dropFirst(2).allSatisfy({ "0123456789abcdef".contains($0) }),
              let number = UInt64(text.dropFirst(2), radix: 16), hex(number) == value, number % 4 == 0 else {
            throw SwiftOutcomeValidatorStop(reason: "invalid_address")
        }
        return number
    }
    func read(_ offset: Int, _ size: Int) throws -> Data {
        try need(size >= 0 && size < Int.max, "raw_extent")
        try charge(size + 1)
        try need(offset >= 0 && offset <= image.data.count && size <= image.data.count - offset
                 && UInt64(offset) + UInt64(size) <= image.sliceSize, "raw_extent")
        let start = image.data.index(image.data.startIndex, offsetBy: offset)
        let end = image.data.index(start, offsetBy: size)
        return Data(image.data[start..<end])
    }
    func rawWord(_ offset: Int) throws -> UInt32 {
        let bytes = [UInt8](try read(offset, 4))
        return UInt32(bytes[0]) | UInt32(bytes[1]) << 8 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
    }
    func mapped(_ pc: UInt64, _ size: Int = 4) throws -> Int {
        try need(size >= 0 && UInt64(size) <= UInt64.max - pc, "vm_extent")
        let end = pc + UInt64(size)
        let hits = sections.filter { $0.address <= pc && end <= $0.end }
        try charge(sections.count)
        try need(hits.count == 1, "raw_mapping_ambiguous")
        let section = hits[0]
        try need(section.executable && ![UInt32(1),8,12,18].contains(section.flags & 255)
                 && !section.name.lowercased().contains("stub"), "raw_mapping_not_executable")
        guard let displacement = Int(exactly: pc - section.address) else { throw SwiftOutcomeValidatorStop(reason: "raw_extent") }
        let sum = section.offset.addingReportingOverflow(displacement)
        try need(!sum.overflow, "raw_extent")
        return sum.partialValue
    }
    func instruction(_ pc: UInt64) throws -> SwiftOutcomeInstruction {
        try charge()
        if let old = decoded[pc] { return old }
        try need(decoded.count < limits.maxInstructions, "validator_instruction_limit", "unresolved")
        let raw = try rawWord(mapped(pc))
        let d: SwiftOutcomeInstruction
        do { d = try decodeSwiftOutcomeInstruction(word: raw, address: pc) }
        catch { throw SwiftOutcomeValidatorStop(reason: "unsupported_instruction", status: "unresolved") }
        decoded[pc] = d; instructions = decoded.count
        return d
    }
    func row(_ pc: UInt64) throws -> J {
        let d = try instruction(pc), offset = try mapped(pc)
        let container = try plus(image.sliceOffset, Int128(offset), reason: "raw_extent")
        return .object(["pc": hex(pc), "word": word(d.word), "slice_offset": hex(UInt64(offset)),
                        "container_offset": hex(container), "kind": .string(d.kind)])
    }
    func fields(_ value: J) throws -> [String: J] {
        guard let object = value.object else { throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image") }
        return object
    }
    func required(_ value: J, _ key: String) throws -> J { try swiftOutcomeRequired(value, key) }
    func get(_ value: J, _ key: String, defaultValue fallback: J = .null) throws -> J {
        try swiftOutcomeValidatorGet(value, key, defaultValue: fallback)
    }
    func contains(_ value: J, _ key: String) throws -> Bool { try swiftOutcomeContains(value, key) }
    func bytes(_ raw: String?) throws -> Data {
        guard let raw = raw else { throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image") }
        // Python bytes.fromhex permits ASCII whitespace only between complete octets.
        let octets = Array(raw.utf8)
        let whitespace: Set<UInt8> = [9, 10, 11, 12, 13, 32]
        func nibble(_ value: UInt8) -> UInt8? {
            switch value {
            case 48...57: return value - 48
            case 65...70: return value - 65 + 10
            case 97...102: return value - 97 + 10
            default: return nil
            }
        }
        var result: [UInt8] = [], cursor = 0
        while cursor < octets.count {
            if whitespace.contains(octets[cursor]) { cursor += 1; continue }
            guard cursor + 1 < octets.count, let high = nibble(octets[cursor]),
                  let low = nibble(octets[cursor + 1]) else {
                throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image")
            }
            result.append(high << 4 | low); cursor += 2
        }
        return Data(result)
    }
    func accounting() -> J {
        .object(["work": int(work), "instructions": int(instructions), "edges": int(edgeCount), "states": int(states),
                 "image_initial_work": int(imageInitialWork), "image_work_charged_here": int(imageWorkHere),
                 "image_ledger_reused": .bool(reused)])
    }
    func snapshot() -> J {
        var output = result; output["facts"] = .object(facts); output["accounting"] = accounting()
        return .object(output)
    }
    func statuses() -> J {
        var output: [String: J] = [:]
        for key in ["identity", "call", "abi", "cfg", "post_call", "regions", "values"] {
            output[key] = .string(facts[key] == nil ? "unchecked" : "checked")
        }
        if facts["values"] != nil { output["values"] = result["value_fact_status"] }
        return .object(output)
    }
    func validate() -> J {
        do { try run() }
        catch let stop as SwiftOutcomeValidatorStop {
            result["status"] = .string(stop.status); result["reason"] = .string(stop.reason)
            result["completeness"] = .object(["complete": .bool(false), "missing": .array([.string(stop.reason)])])
            if let diagnostic = stop.instruction {
                var check = snapshot(); check["unresolved_instruction"] = diagnostic; check["fact_statuses"] = statuses()
                if (try? SwiftOutcomeWitnessCodec.preflight(check, limits: limits)) != nil { result["unresolved_instruction"] = diagnostic }
            }
        } catch {
            result["status"] = .string("declined"); result["reason"] = .string("malformed_candidate_or_image")
            result["completeness"] = .object(["complete": .bool(false), "missing": .array([.string("malformed_candidate_or_image")])])
        }
        result["fact_statuses"] = statuses()
        return snapshot()
    }
    func run() throws {
        try need(image.hasValidAdmission, "image_admission_custody", "unresolved")
        _ = try SwiftOutcomeWitnessCodec.preflight(candidate, limits: limits)
        try need(candidate.object != nil, "candidate_object")
        try need(candidate["model_version"] == .string("swift-outcome-witness-v2")
                 && candidate["validation_model"] == .string("swift-outcome-validation-v2")
                 && candidate["profile"] == .string("broad-v1"), "candidate_model")
        try need(candidate["status"] == .string("unresolved") && candidate["eligible"] == .bool(false), "candidate_scope")
        var pending = [candidate]
        while let current = pending.popLast() {
            try charge()
            if let object = current.object {
                for key in SwiftOutcomeWitnessCodec.scalarSorted(object.keys) {
                    let value = object[key]!
                    if key.hasSuffix("_proven") || key == "source_reconstruction_allowed" { try need(value == .bool(false), "proof_scope") }
                    if value.object != nil || value.array != nil { pending.append(value) }
                }
            } else if let array = current.array { pending.append(contentsOf: array) }
        }
        try need(candidate["source_models"] == .object([
            "edge": .string("swift-broad-error-flow-v1"), "witness": .string("swift-outcome-witness-v2"),
            "validation": .string("swift-outcome-validation-v2"), "cfg": .string("swift-bounded-structural-cfg-v1"),
            "value": .string("swift-outcome-values-v1")]), "source_models")
        let identity = try required(candidate, "identity")
        let expected: [String: J] = ["slice_sha256": .string(image.sliceSHA256), "container_sha256": .string(image.containerSHA256),
            "slice_offset": hex(image.sliceOffset), "slice_size": hex(image.sliceSize), "architecture": .string(image.architecture),
            "cpu_subtype": int(image.cpuSubtype), "uuid": image.uuid.map(J.string) ?? .null,
            "preferred_base": hex(image.preferredBase), "slice_index": image.sliceIndex.map(int) ?? .null,
            "container_slice_count": image.containerSliceCount.map(int) ?? .null]
        for key in SwiftOutcomeWitnessCodec.scalarSorted(expected.keys) {
            try need(contains(identity, key) && get(identity, key) == expected[key], "image_identity")
        }
        try need(image.architecture == "arm64" && [0,1].contains(image.cpuSubtype), "ordinary_arm64_required")
        try need(image.sliceSize == UInt64(image.data.count), "slice_extent")
        try need(image.functions.contains(function) && function.boundarySource == "lc_function_starts", "caller_membership")
        try need(function.start < function.endExclusive && function.start % 4 == 0 && function.endExclusive % 4 == 0, "caller_extent")
        try need((function.endExclusive - function.start) / 4 <= UInt64(limits.maxInstructions), "validator_instruction_limit", "unresolved")
        let rawLedger: Any = suppliedLedger ?? createIndependentSwiftImageLedger(image)
        guard let ledger = rawLedger as? SwiftOutcomeImageLedger else { throw SwiftOutcomeValidatorStop(reason: "independent_image_ledger_custody", status: "unresolved") }
        try need(ledger.matches(image), "independent_image_ledger_custody", "unresolved")
        imageInitialWork = ledger.initialWorkSteps; reused = suppliedLedger != nil
        imageWorkHere = reused ? 0 : ledger.initialWorkSteps
        try need(ledger.status == "ready", ledger.reason ?? "independent_image_ledger_not_ready", ledger.status)
        sections = ledger.sections
        func boundary(_ f: SwiftErrorFlowFunction) throws -> J {
            try charge(); try need(ledger.functionIndex[f.start] == f, "raw_function_membership")
            try need(ledger.boundaries[f.start] == f.endExclusive, "raw_boundary_end")
            return .object(["start_pc": hex(f.start), "end_pc_exclusive": hex(f.endExclusive), "boundary_source": .string("lc_function_starts")])
        }
        try need(required(identity, "caller") == boundary(function), "caller_identity")
        let callPC = try address(required(identity, "call_pc"))
        try need(function.start <= callPC && callPC < function.endExclusive, "call_outside_caller")
        let call = try required(candidate, "call"), d = try instruction(callPC)
        try need(d.kind == "bl" && required(call, "pc") == hex(callPC) && required(call, "word") == word(d.word), "direct_call_word")
        let target = try plus(callPC, d.immediate, reason: "direct_target_overflow")
        try need(required(call, "callee_pc") == hex(target), "direct_target")
        guard let callee = ledger.functionIndex[target], callee.boundarySource == "lc_function_starts" else {
            throw SwiftOutcomeValidatorStop(reason: "callee_exact_entry")
        }
        try need(required(identity, "callee") == boundary(callee), "callee_identity"); _ = try mapped(target)
        for (name, pc) in [("call", callPC), ("callee_entry", target)] {
            let raw = try rawWord(mapped(pc)), offset = try mapped(pc)
            let container = try plus(image.sliceOffset, Int128(offset), reason: "raw_extent")
            try need(get(get(call, "provenance", defaultValue: .object([:])), name) == .object(["pc": hex(pc), "word": word(raw),
                "slice_file_offset": hex(UInt64(offset)), "container_file_offset": hex(container)]), "call_provenance")
        }
        facts["identity"] = .string("checked_against_raw_header_sections_and_function_starts")
        guard let table = ledger.symbolTable else { throw SwiftOutcomeValidatorStop(reason: "raw_symbols_missing") }
        var names: [String] = [], visibility: [SwiftOutcomeRawSymbol] = []
        for symbol in ledger.symbols[target] ?? [] {
            try charge(); visibility.append(symbol)
            let section = Int(symbol.section), index = symbol.stringIndex
            try need(section >= 1 && section <= sections.count, "symbol_section")
            try need(sections[section-1].address <= target && target < sections[section-1].end, "symbol_section")
            try need(index > 0 && index < table.length, "symbol_string_extent")
            let raw = [UInt8](try read(table.strings + index, min(table.length - index, limits.maxString + 1)))
            guard let end = raw.firstIndex(of: 0), end > 0, end <= limits.maxString else { throw SwiftOutcomeValidatorStop(reason: "symbol_string_extent") }
            guard raw[..<end].allSatisfy({ $0 < 128 }), let name = String(bytes: raw[..<end], encoding: .ascii) else {
                throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image")
            }
            names.append(name)
        }
        try need(names.count == 1, "symbol_aliases")
        let parsed = parseBroadSwiftDeclaration(names[0])
        try need(parsed.supported, "declaration_unqualified", "unresolved")
        guard let declaration = parsed.identity else { throw SwiftOutcomeValidatorStop(reason: "declaration_unqualified", status: "unresolved") }
        try need(swiftOutcomeSymbolVisibilityAllowed(kind: Int(visibility[0].kind), desc: Int(visibility[0].description), declaration: declaration, callKind: d.kind), "symbol_visibility")
        try need(required(call, "declaration") == .object(["status": .string("syntax_admitted"), "identity": declaration.json, "reason": .null]), "declaration_identity")
        facts["call"] = .string("checked_direct_target_and_exact_symbol_syntax")
        let abi = try required(call, "abi")
        let qualificationID = try get(get(get(abi, "evidence", defaultValue: .object([:])), "lowering", defaultValue: .object([:])), "qualification_id")
        let stable = try get(abi, "profile") == .string("swift6-arm64-sync-untyped-stable-research-v2")
        let storage: J
        if stable {
            let checked = try validateSwiftOutcomeStableABI(image: image, function: function, callee: callee, callPC: callPC,
                declaration: declaration, abi: abi, read: read, mapped: mapped, instruction: instruction, charge: charge, limits: limits)
            storage = checked.storage; result["caller_error_state"] = checked.callerErrorState
            result["outcome_scope"] = .string("byte_zero_nonzero_geometry_with_conditional_abi_roles")
            result["outcome_preconditions"] = .array(["well_formed_swift_stable_arm64_calling_convention", "synchronous_untyped_throws", "incoming_x21_zero_required_by_selected_convention"].map(J.string))
            result["abi_assumption"] = .string("explicit_selected_swift6_stable_arm64_sync_untyped")
            result["compiler_verified"] = .bool(false)
        } else {
            guard let id = qualificationID.string, let q = registry.qualification(id: id) else {
                throw SwiftOutcomeValidatorStop(reason: "abi_qualification_unknown", status: "unresolved")
            }
            try need(q.sliceSHA256 == image.sliceSHA256 && !q.sourceSHA256.isEmpty && !q.sourceCapture.isEmpty && !q.disassemblyCapture.isEmpty, "abi_source_identity", "unresolved")
            var changed = declaration.json; changed["symbol"] = .string(q.symbol)
            let sourceIdentity = parseBroadSwiftDeclaration(q.symbol).identity?.json ?? .null
            let dj = declaration.json
            let context = J.array(q.context.map { .object(["name": .string($0.name), "kind": .string($0.kind)]) })
            let parameters = dj["parameter_types"].array ?? []
            let types = parameters + [dj["result_type"]]
            try need(changed == sourceIdentity && (dj["symbol"].string ?? "").drop(while: { $0 == "_" }) == q.symbol.drop(while: { $0 == "_" })
                && dj["callable_kind"] == .string(q.callableKind) && dj["context"] == context
                && parameters.map { $0["name"] } == q.parameterTypes.map(J.string) && dj["result_type"]["name"] == .string(q.resultType)
                && dj["throws"] == .bool(true) && dj["generic_parameter_counts"] == .array([]) && dj["generic_requirements"] == .array([])
                && types.allSatisfy { $0["inout"] == .bool(false) && $0["arguments"] == .array([]) && $0["generic_depth"] == .null }, "abi_tuple_identity", "unresolved")
            try need(q.resultLocation == "x0" && ["Swift.Int", "Swift.UInt", "Swift.Bool", "Swift.Int32", "Swift.UInt32"].contains(q.resultType), "abi_result_subset", "unresolved")
            for (key, value) in [("argument_locations", J.array(q.parameterLocations.map(J.string))), ("receiver_location", q.receiverLocation.map(J.string) ?? .null), ("result_location", J.string(q.resultLocation))] {
                if try contains(abi, key) { try need(required(abi, key) == value, "abi_" + key) }
            }
            try need(get(abi, "status") == .string("admitted") && get(abi, "profile") == registry.syncARM64Swift6["identifier"]
                && get(abi, "error_register") == .string("x21") && get(abi, "research_only") == .bool(true), "abi_claim")
            let lowering = try required(required(abi, "evidence"), "lowering")
            let retained: [String: J] = ["source_sha256": .string(q.sourceSHA256), "slice_sha256": .string(q.sliceSHA256), "compiler": .string(q.compiler), "target": .string(q.target), "optimization": .string(q.optimization), "source_capture": .string(q.sourceCapture), "disassembly_capture": .string(q.disassemblyCapture)]
            for key in SwiftOutcomeWitnessCodec.scalarSorted(retained.keys) {
                if try contains(lowering, key) { try need(required(lowering, key) == retained[key], "qualification_retained_identity") }
            }
            if try contains(lowering, "observations") {
                try need(required(lowering, "observations") == .array(q.observations.map { .object(["pc": hex($0.pc), "raw_bytes": .string($0.bytesHex), "meaning": .string($0.note)]) }), "qualification_retained_observations")
            }
            for observation in q.observations {
                let expected = try bytes(observation.bytesHex); try need(!expected.isEmpty, "empty_qualification")
                try need(read(mapped(observation.pc, expected.count), expected.count) == expected, "qualification_bytes_changed", "unresolved")
            }
            storage = .object(["locations": .array([.string("x0")]), "category": .string("integer"), "bit_width": int(64), "indirect": .bool(false)])
        }
        if !(declaration.json["context"].array ?? []).isEmpty {
            let dj = declaration.json
            let input = SwiftNominalDeclarationInput(module: dj["module"].string ?? "", context: (dj["context"].array ?? []).map { (name: $0["name"].string ?? "", kind: $0["kind"].string ?? "") })
            let context = try replaySwiftNominalContext(declaration: input, sections: sections, read: read, limits: limits, charge: charge)
            let retained = try get(get(abi, "evidence", defaultValue: .object([:])), "nominal_context")
            if retained != .null {
                for key in SwiftOutcomeWitnessCodec.scalarSorted(context.object?.keys.map { $0 } ?? []) { try need(get(retained, key) == context[key], "nominal_retained_records") }
                if try contains(retained, "slice") { try need(required(retained, "slice") == sliceBinding(), "nominal_retained_slice") }
            }
        }
        if try contains(abi, "binding") {
            let binding = try required(abi, "binding")
            let sectionRecords: [J] = image.sections.map { .object(["segment": .string($0.segment), "name": .string($0.name), "address": .integer(Int128($0.address)), "size": .integer(Int128($0.size)), "file_offset": .integer(Int128($0.fileOffset)), "flags": .integer(Int128($0.flags))]) }
            try need(get(binding, "schema") == .string("airs.swift-abi-binding.v1") && get(binding, "slice") == sliceBinding() && get(binding, "sections") == .array(sectionRecords), "abi_binding_identity")
            let ranges = try swiftOutcomeIterable(required(binding, "ranges"))
            for range in ranges {
                let rangePC = try required(range, "pc")
                let raw = try bytes(required(range, "raw").string)
                guard let number = rangePC.integer, let pc = UInt64(exactly: number), !raw.isEmpty else { throw SwiftOutcomeValidatorStop(reason: "abi_binding_range") }
                let end = try plus(pc, Int128(raw.count), reason: "abi_binding_mapping")
                let hits = sections.filter { $0.address <= pc && end <= $0.end }
                try charge(sections.count); try need(hits.count == 1, "abi_binding_mapping")
                let section = hits[0]
                guard let delta = Int(exactly: pc-section.address) else { throw SwiftOutcomeValidatorStop(reason: "abi_binding_mapping") }
                let offset = section.offset.addingReportingOverflow(delta)
                try need(!offset.overflow && ![UInt32(1),12,18].contains(section.flags & 255), "abi_binding_bytes")
                try need(read(offset.partialValue, raw.count) == raw, "abi_binding_bytes")
            }
        }
        facts["abi"] = .string(stable ? "checked_selected_abi_assumption_and_raw_patterns" : "checked_registry_identity_and_observation_bytes")
        try replayCaller(callPC: callPC, storage: storage, stable: stable)
    }
    func sliceBinding() -> J {
        .object(["sha256": .string(image.sliceSHA256), "offset": .integer(Int128(image.sliceOffset)),
                 "size": .integer(Int128(image.sliceSize)), "architecture": .string(image.architecture)])
    }
    func replayCaller(callPC: UInt64, storage: J, stable: Bool) throws {
        var ds: [UInt64: SwiftOutcomeInstruction] = [:], pcs: [UInt64] = []
        var cursor = function.start
        while cursor < function.endExclusive { ds[cursor] = try instruction(cursor); pcs.append(cursor); cursor += 4 }
        var edges: [J] = [], leaders: Set<UInt64> = [function.start], terminals = Set<UInt64>()
        func edge(_ pc: UInt64, _ kind: String, _ destination: UInt64? = nil) throws {
            try charge(); try need(edges.count < limits.maxEdges, "validator_edge_limit", "unresolved")
            if let destination = destination {
                try need(function.start <= destination && destination < function.endExclusive && destination % 4 == 0, "cfg_target_outside_caller")
                leaders.insert(destination)
            }
            var value = try row(pc); value["source_pc"] = hex(pc)
            value["target_pc"] = destination.map(hex) ?? .null; value["kind"] = .string(kind)
            edges.append(value); terminals.insert(pc)
        }
        for pc in pcs {
            let d = ds[pc]!
            if branches.contains(d.kind) {
                try edge(pc, d.kind == "b" ? "branch" : "conditional_taken", plus(pc, d.immediate))
                if d.kind != "b" { try edge(pc, "conditional_fallthrough", plus(pc, 4)) }
            } else if d.kind == "bl" { try edge(pc, "call_return_candidate", plus(pc, 4)) }
            else if d.kind == "ret" { try edge(pc, "return") }
            else if d.kind == "brk" { try edge(pc, "exception_transfer") }
            else { try need(pc + 4 < function.endExclusive, "cfg_fallthrough_outside_caller") }
            if terminals.contains(pc) && pc + 4 < function.endExclusive { leaders.insert(pc + 4) }
        }
        try need(leaders.count <= limits.maxBlocks, "validator_block_limit", "unresolved")
        var blocks: [J] = [], owner: [UInt64: Int] = [:]
        for pc in pcs {
            if leaders.contains(pc) { blocks.append(.object(["start_pc": hex(pc), "end_pc_exclusive": .null, "instructions": .array([]), "successors": .array([]), "predecessors": .array([])])) }
            let index = blocks.count - 1; owner[pc] = index
            var rows = blocks[index]["instructions"].array!; rows.append(try row(pc))
            blocks[index]["instructions"] = .array(rows); blocks[index]["end_pc_exclusive"] = hex(pc + 4)
        }
        for block in blocks {
            let pc = try address(block["instructions"].array!.last!["pc"])
            if !terminals.contains(pc) { try edge(pc, "fallthrough", pc + 4) }
        }
        for value in edges {
            let source = try address(value["source_pc"]), index = owner[source]!
            var successors = blocks[index]["successors"].array!; successors.append(value)
            blocks[index]["successors"] = .array(successors)
            if value["target_pc"] != .null {
                let destination = try address(value["target_pc"]), other = owner[destination]!
                var predecessors = blocks[other]["predecessors"].array!; predecessors.append(value)
                blocks[other]["predecessors"] = .array(predecessors)
            }
        }
        let cfg = try required(candidate, "cfg")
        try need(get(cfg, "blocks") == .array(blocks) && get(cfg, "edges") == .array(edges), "cfg_replay_mismatch")
        try need(get(get(cfg, "completeness", defaultValue: .object([:])), "complete") == .bool(true) && get(get(cfg, "completeness", defaultValue: .object([:])), "all_words_classified") == .bool(true), "cfg_partial", "unresolved")
        var returns: [J] = [], calls: [J] = [], exceptions: [J] = []
        for pc in pcs {
            let d = ds[pc]!
            if d.kind == "ret" { returns.append(try row(pc)) }
            if d.kind == "bl" {
                var call = try row(pc); call["callee_pc"] = try hex(plus(pc, d.immediate))
                call["continuation_pc"] = hex(pc+4); call["runtime_return_proven"] = .bool(false); calls.append(call)
            }
            if d.kind == "brk" {
                var value = try row(pc); value["exception"] = .string("breakpoint"); value["resume_proven"] = .bool(false); exceptions.append(value)
            }
        }
        try need(get(cfg, "returns") == .array(returns) && get(cfg, "call_return_candidates") == .array(calls), "cfg_auxiliary_facts")
        if !exceptions.isEmpty || ["exception_transfers", "external_exception_handling_unmodeled", "exception_resume_proven"].contains(where: { cfg.object?[$0] != nil }) {
            try need(get(cfg, "exception_transfers") == .array(exceptions) && get(cfg, "external_exception_handling_unmodeled") == .bool(true) && get(cfg, "exception_resume_proven") == .bool(false), "cfg_exception_facts")
        }
        try need(get(cfg, "function_pc") == hex(function.start) && get(cfg, "model") == .string("swift-bounded-structural-cfg-v1") && get(cfg, "status") == .string("eligible_structural_only"), "cfg_model")
        var seen = Set<UInt64>(), depthMax = 0
        for root in blocks {
            let start = try address(root["start_pc"])
            if seen.contains(start) { continue }
            seen.insert(start); var stack = [(owner[start]!, 1)]
            while let (index, depth) = stack.popLast() {
                try charge(); try need(depth <= limits.maxDepth, "cfg_depth_limit", "unresolved"); depthMax = max(depthMax, depth)
                for e in blocks[index]["successors"].array!.reversed() where e["target_pc"] != .null {
                    let dst = try address(e["target_pc"])
                    if !seen.contains(dst) {
                        try need(depth < limits.maxDepth, "cfg_depth_limit", "unresolved")
                        seen.insert(dst); stack.append((owner[dst]!, depth+1))
                    }
                }
            }
        }
        for (key, expected) in [("retained_words", ds.count), ("blocks", blocks.count), ("edges", edges.count), ("max_discovery_depth", depthMax)] {
            try need(get(get(cfg, "accounting", defaultValue: .object([:])), key) == int(expected), "cfg_accounting")
        }
        edgeCount = edges.count; facts["cfg"] = .string("independently_rebuilt_all_caller_words_and_edges")
        let post = try required(candidate, "post_call"), testPC = try address(required(post, "test_pc"))
        try need(ds[testPC] != nil, "postcall_test_outside_caller")
        try need(limits.maxStateEntries >= 2 && limits.maxProvenanceNodes >= 2, "value_seed_limit", "unresolved")
        let scalar = SwiftOutcomeScalarReplay(callPC: callPC, limits: limits, charge: charge)
        if stable { scalar.registers[21] = .array([.string("raw_postcall_x21"), hex(callPC), int(64)]) }
        let errorOrigin = scalar.registers[21]!
        let wireOrigin = stable ? "raw_post_call_register:x21" : "abi_post_call_error:x21"
        scalar.registers.removeValue(forKey: 0)
        for location in storage["locations"].array ?? [] {
            guard let text = location.string, let first = text.first, first == "x" || first == "w",
                  !text.dropFirst().isEmpty, text.dropFirst().allSatisfy({ $0.isASCII && $0.isNumber }),
                  let register = Int(text.dropFirst()) else { continue }
            let bits = first == "w" ? 32 : 64
            let value: J = register == 0 ? .array([.string("call_result"), hex(callPC), int(bits)])
                : .array([.string("call_result_component"), hex(callPC), .string(text), int(bits)])
            try scalar.write(register, value, bits: bits)
        }
        let frame = SwiftOutcomeScalarReplay(callPC: callPC, limits: limits, charge: charge); frame.registers = [:]
        for pc in pcs where pc < callPC {
            let d = ds[pc]!
            if branches.contains(d.kind) || ["bl", "ret", "brk"].contains(d.kind) {
                frame.stackPointer = nil; frame.registers = [:]; frame.cells = [:]; break
            }
            do { try frame.step(d) }
            catch let stop as SwiftOutcomeValidatorStop {
                if stop.reason != "value_transfer_unqualified" { throw stop }
                if changesSP(d) { frame.stackPointer = nil }
                frame.registers.removeValue(forKey: d.rd); frame.cells = [:]
            }
        }
        scalar.stackPointer = frame.stackPointer; scalar.cells = [:]
        var trace: [J] = [], aliasObservations: [J] = [], visited: Set<UInt64> = [callPC]
        cursor = try plus(callPC, 4); var comparison: SwiftOutcomeInstruction?
        while cursor != testPC {
            try charge(); try need(trace.count < limits.postCallWindow, "postcall_window", "unresolved")
            try need(ds[cursor] != nil && !visited.contains(cursor), "postcall_cycle_or_target", "unresolved")
            visited.insert(cursor); let d = ds[cursor]!; trace.append(hex(cursor))
            if d.word & 0xfffffc1f == 0xf100001f {
                try need(comparison == nil, "multiple_error_comparisons", "unresolved"); comparison = d; cursor += 4; continue
            }
            try need(comparison == nil, "comparison_not_adjacent", "unresolved")
            if d.kind == "b" { cursor = try plus(cursor, d.immediate); continue }
            try need(!branches.contains(d.kind) && !["ret", "bl", "brk"].contains(d.kind), "postcall_control_unqualified", "unresolved")
            try scalar.step(d)
            var origins: [J] = scalar.registers.keys.sorted().filter { scalar.registers[$0] == errorOrigin }.map {
                .object(["register": .string("x\($0)"), "kind": .string("register_copy"), "origin": .string(wireOrigin)])
            }
            for slot in scalar.cells.keys.sorted() {
                let cell = scalar.cells[slot]!
                if cell.value == errorOrigin { origins.append(.object(["stack_slot": int(slot), "epoch": int(cell.epoch), "kind": .string("stack_slot"), "origin": .string(wireOrigin)])) }
            }
            aliasObservations.append(.object(["pc": hex(cursor), "origins": .array(origins)])); cursor += 4
        }
        try need(trace.count < limits.postCallWindow, "postcall_window", "unresolved")
        let test = ds[testPC]!; trace.append(hex(testPC))
        let register: Int, zero: Bool
        if let comparison = comparison {
            try need(test.kind == "bcond" && ["0","1"].contains(test.addressing) && comparison.address+4 == testPC, "error_comparison_condition", "unresolved")
            try need(get(post, "test_kind") == .string("cmp_zero_bcond") && get(post, "comparison_pc") == hex(comparison.address)
                && get(post, "comparison_word") == word(comparison.word) && get(post, "test_condition") == .string(test.addressing == "0" ? "eq" : "ne"), "comparison_facts")
            register = comparison.rn; zero = test.addressing == "0"
        } else {
            try need(["xcbz", "xcbnz"].contains(test.kind), "error_test_unqualified", "unresolved")
            register = test.rn; zero = test.kind == "xcbz"
            try need(post.object?["test_kind"] == nil, "test_encoding")
        }
        try need(scalar.read(register) == errorOrigin, "error_register_alias", "unresolved")
        let taken = try plus(testPC, test.immediate), fallthroughPC = try plus(testPC, 4)
        let success = zero ? taken : fallthroughPC, error = zero ? fallthroughPC : taken
        try need(get(post, "test_word") == word(test.word) && get(post, "test_register") == .string("x\(register)") && get(post, "success_successor_pc") == hex(success) && get(post, "error_successor_pc") == hex(error), "test_polarity")
        try need(get(post, "trace") == .array(trace) && get(post, "status") == .string("candidate") && [.string("qualified_error_alias_zero_test"), .string("qualified_error_alias_compare_zero")].contains(get(post, "reason")), "postcall_trace")
        facts["post_call"] = .string("checked_error_alias_epoch_flags_and_branch_polarity")
        func paths(_ start: UInt64) throws -> [[J]] {
            var pending: [(UInt64, [J], Set<UInt64>)] = [(start, [], [])], complete: [[J]] = []; var walked = 0
            while let (pc, previous, seen) = pending.popLast() {
                try charge(); walked += 1; try need(walked <= limits.maxProvenanceNodes, "arm_path_limit", "unresolved")
                try need(ds[pc] != nil && !seen.contains(pc), "cyclic_or_external_arm", "unresolved")
                try need(previous.count < limits.maxDepth, "path_depth_limit", "unresolved")
                let d = ds[pc]!, rows = previous + [try row(pc)], nextSeen = seen.union([pc])
                if ["ret", "brk"].contains(d.kind) { complete.append(rows); continue }
                let destinations: [UInt64]
                if d.kind == "b" { destinations = [try plus(pc, d.immediate)] }
                else if branches.contains(d.kind) { destinations = [try plus(pc, d.immediate), try plus(pc, 4)] }
                else { destinations = [try plus(pc, 4)] }
                for dst in destinations.reversed() { pending.append((dst, rows, nextSeen)) }
            }
            return complete
        }
        let successPaths = try paths(success), errorPaths = try paths(error)
        let successSet = Set(try successPaths.flatMap { try $0.map { try address($0["pc"]) } })
        let errorSet = Set(try errorPaths.flatMap { try $0.map { try address($0["pc"]) } })
        let partition: J = .object(["success_only_pcs": .array(successSet.subtracting(errorSet).sorted().map(hex)),
            "error_only_pcs": .array(errorSet.subtracting(successSet).sorted().map(hex)),
            "shared_pcs": .array(successSet.intersection(errorSet).sorted().map(hex)),
            "unreachable_pcs": .array(Set(pcs).subtracting(successSet).subtracting(errorSet).sorted().map(hex))])
        let regions = try required(candidate, "regions")
        try need(get(regions, "status") == .string("structural_candidates") && get(regions, "success_entry_pc") == hex(success) && get(regions, "error_entry_pc") == hex(error), "region_entries")
        try need(get(regions, "paths") == .array([("success",success), ("error",error)].map { .object(["outcome": .string($0.0), "entry_pc": hex($0.1), "reachability": .string("unproven")]) }), "region_paths")
        let hasPartition = try contains(regions, "partition")
        if hasPartition { try need(required(regions, "partition") == partition, "region_partition") }
        let tails: [J] = try returns.map {
            let pc = try address($0["pc"])
            let outcome = !hasPartition ? "unknown" : (successSet.contains(pc) && errorSet.contains(pc) ? "shared" : (successSet.contains(pc) ? "success" : (errorSet.contains(pc) ? "error" : "unreachable")))
            return .object(["pc": $0["pc"], "kind": .string("return"), "outcome": .string(outcome)])
        }
        try need(get(regions, "tails") == .array(tails), "region_return_tails")
        let protected = Set(try trace.map(address)).union(successSet).union(errorSet)
        for e in edges where e["target_pc"] != .null {
            let source = try address(e["source_pc"]), destination = try address(e["target_pc"])
            try need(!protected.contains(destination) || protected.contains(source) || (source == callPC && destination == callPC+4), "unexpected_incoming_edge", "blocked")
        }
        facts["regions"] = .string("checked_all_arm_paths_returns_partitions_and_direct_incoming_edges")
        let values = try required(candidate, "value_facts")
        var observations: [J] = [], exceptionObservations: [J] = []
        var (retainedItems, retainedBytes) = try retentionCost(partition)
        retainedBytes += 4096; retainedItems += 256
        for (arm, armPaths) in [("success",successPaths), ("error",errorPaths)] {
            for rows in armPaths {
                let state = scalar.clone()
                for r in rows {
                    let d = ds[try address(r["pc"])]!
                    if d.kind == "brk" { break }
                    try state.step(d); states += 1
                }
                let last = rows.last!, lastInstruction = ds[try address(last["pc"])]!
                let observation: J
                if lastInstruction.kind == "brk" {
                    observation = .object(["arm": .string(arm), "pc": last["pc"], "exception": .string("breakpoint"), "resume_proven": .bool(false)])
                    if exceptionObservations.contains(observation) { continue }
                } else {
                    let value = state.read(0)
                    observation = .object(["arm": .string(arm), "return_pc": last["pc"], "register": .string("x0"),
                        "value": value ?? .array([.string("unknown"), int(64)]),
                        "status": .string(value != nil ? "modeled_symbolic_value" : "unknown"),
                        "reason": .string(value != nil ? "independent_instruction_replay" : "no_supported_scalar_origin"),
                        "raw_error_register_value": state.read(21) ?? .array([.string("unknown"), int(64)]),
                        "error_role": .string("conditional_on_selected_abi_preconditions"), "runtime_propagation_proven": .bool(false), "source_handler_proven": .bool(false)])
                    if observations.contains(observation) { continue }
                }
                let (items, size) = try retentionCost(observation)
                try need(items <= limits.maxContainerItems - retainedItems && size <= limits.maxBytes - retainedBytes, "validator_output_limit", "unresolved")
                retainedItems += items; retainedBytes += size
                if lastInstruction.kind == "brk" { exceptionObservations.append(observation) } else { observations.append(observation) }
            }
        }
        try need(get(values, "seed") == .object(["register": .string("x21"), "kind": .string("register_copy"), "origin": .string(wireOrigin), "width": int(64)]), "value_seed")
        try need(get(values, "observations") == .array(aliasObservations), "value_observations")
        result["return_observations"] = .array(observations); result["exception_observations"] = .array(exceptionObservations)
        result["exception_resume_proven"] = .bool(false); result["external_exception_handling_unmodeled"] = .bool(true)
        result["region_partition"] = partition
        let complete = !observations.isEmpty && observations.allSatisfy { $0["status"] != .string("unknown") }
        result["symbolic_return_values_complete"] = .bool(complete)
        result["value_fact_status"] = .string(complete ? "checked_symbolic_values" : (observations.isEmpty ? "not_applicable_no_return_paths" : "checked_with_explicit_unknowns"))
        facts["values"] = .string("independently_replayed_scalar_call_result_epoch")
        try need(candidate["completeness"] == .object(["complete": .bool(true), "missing": .array([])]), "candidate_partial", "unresolved")
        let counts = try get(candidate, "accounting", defaultValue: .object([:]))
        for (key, expected) in [("instructions", ds.count), ("blocks", blocks.count), ("edges", edges.count), ("value_steps",aliasObservations.count)] { try need(get(counts, key) == int(expected), "candidate_accounting") }
        guard let workNumber = try get(counts, "work").integer, let candidateWork = Int(exactly: workNumber), candidateWork >= 0, candidateWork <= limits.maxWork else { throw SwiftOutcomeValidatorStop(reason: "candidate_work_accounting") }
        let encoded = SwiftOutcomeWitnessCodec.canonicalBytes(candidate).count
        try need(get(counts, "encoded_bytes") == int(encoded), "candidate_size_accounting")
        do { _ = try SwiftOutcomeWitnessCodec.preflight(snapshot(), limits: limits) }
        catch { throw SwiftOutcomeValidatorStop(reason: "validator_output_limit", status: "unresolved") }
        result["status"] = .string("eligible_structural_only"); result["eligible"] = .bool(true); result["reason"] = .string("independent_bounded_byte_replay")
        result["completeness"] = .object(["complete": .bool(true), "missing": .array([])])
    }
    func retentionCost(_ value: J) throws -> (Int, Int) {
        try swiftOutcomeRetentionCost(value, limits: limits, charge: charge)
    }
    func changesSP(_ d: SwiftOutcomeInstruction) -> Bool {
        (["xadd_ext", "xsub_ext"].contains(d.kind) && d.rd == 31)
            || (["xstr", "xldr", "xldr_post"].contains(d.kind) && d.rn == 31 && ["pre", "post"].contains(d.addressing))
            || (["add", "sub"].contains(d.kind) && d.rd == 31)
            || (["stp", "ldp"].contains(d.kind) && d.rn == 31 && d.addressing != "offset")
    }
}

/// Donor validator lines 1070–1085; retained expansion is charged before append.
func swiftOutcomeRetentionCost(_ value: SwiftOutcomeJSON, limits: BroadWitnessLimits,
    charge: (Int) throws -> Void = { _ in }) throws -> (Int, Int) {
    func need(_ condition: Bool, _ reason: String, _ status: String) throws {
        if !condition { throw SwiftOutcomeValidatorStop(reason: reason, status: status) }
    }
        var pending = [(value, 0)], items = 0, size = 0
        while let (node, depth) = pending.popLast() {
            try charge(1); items += 1
            try need(items <= limits.maxContainerItems && depth <= limits.maxDepth, "validator_output_limit", "unresolved")
            switch node {
            case .object(let object):
                size += 2 + 2*object.count
                for key in SwiftOutcomeWitnessCodec.scalarSorted(object.keys) { size += 2 + 6*key.unicodeScalars.count; pending.append((object[key]!, depth+1)) }
            case .array(let array): size += 2 + 2*array.count; pending.append(contentsOf: array.map { ($0,depth+1) })
            case .string(let text): size += 2 + 6*text.unicodeScalars.count
            default: size += 21
            }
            try need(size <= limits.maxBytes, "validator_output_limit", "unresolved")
        }
        return (items,size)
    }

/// Preserve Python bracket/get/membership distinctions at each donor evaluation point.
func swiftOutcomeRequired(_ value: SwiftOutcomeJSON, _ key: String) throws -> SwiftOutcomeJSON {
    guard let object = value.object, let child = object[key] else {
        throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image")
    }
    return child
}
func swiftOutcomeValidatorGet(_ value: SwiftOutcomeJSON, _ key: String,
    defaultValue fallback: SwiftOutcomeJSON = .null) throws -> SwiftOutcomeJSON {
    guard let object = value.object else {
        throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image")
    }
    return object[key] ?? fallback
}
func swiftOutcomeContains(_ value: SwiftOutcomeJSON, _ key: String) throws -> Bool {
    switch value {
    case .object(let object): return object[key] != nil
    case .array(let array): return array.contains(.string(key))
    case .string(let text): return text.contains(key)
    default: throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image")
    }
}

/// Donor for-in accepts any iterable; malformed spans fail when their fields are read.
func swiftOutcomeIterable(_ value: SwiftOutcomeJSON) throws -> [SwiftOutcomeJSON] {
    switch value {
    case .array(let array): return array
    case .object(let object): return SwiftOutcomeWitnessCodec.scalarSorted(object.keys).map(SwiftOutcomeJSON.string)
    case .string(let text): return text.unicodeScalars.map { .string(String($0)) }
    default: throw SwiftOutcomeValidatorStop(reason: "malformed_candidate_or_image")
    }
}
