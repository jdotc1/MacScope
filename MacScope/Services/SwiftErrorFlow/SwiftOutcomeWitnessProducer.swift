import Foundation

func buildBroadSwiftWitness(image: SwiftOutcomeImage, function: SwiftErrorFlowFunction,
                           callsite: SwiftOutcomeJSON, limits: BroadWitnessLimits = BroadWitnessLimits(),
                           profile: String = "broad-v1") -> SwiftOutcomeJSON {
    SwiftOutcomeBroadProducer(image: image, function: function, callsite: callsite, limits: limits, profile: profile).build()
}

private final class SwiftOutcomeBroadProducer {
    let image: SwiftOutcomeImage, function: SwiftErrorFlowFunction, callsite: SwiftOutcomeJSON
    let limits: BroadWitnessLimits, profile: String
    var result: SwiftOutcomeJSON
    var missing: [SwiftOutcomeJSON] = []

    init(image: SwiftOutcomeImage, function: SwiftErrorFlowFunction, callsite: SwiftOutcomeJSON,
         limits: BroadWitnessLimits, profile: String) {
        self.image = image; self.function = function; self.callsite = callsite
        self.limits = limits; self.profile = profile
        result = .object([
            "model_version": .string(witnessModel), "validation_model": .string(validationModel),
            "profile": .string(profile), "source_models": .object([:]), "status": .string("unresolved"), "eligible": .bool(false),
            "reason": .string("candidate_facts_incomplete"), "identity": .object([:]), "call": .object([:]), "cfg": .object([:]),
            "post_call": .object(["status": .string("unknown"), "reason": .string("not_examined"), "test_pc": .null,
                "test_word": .null, "test_register": .null, "error_successor_pc": .null, "success_successor_pc": .null, "trace": .array([])]),
            "regions": Self.emptyRegions,
            "value_facts": .object(["seed": .null, "observations": .array([])]),
            "completeness": .object(["complete": .bool(false), "missing": .array([])]),
            "accounting": .object(["work": .integer(0), "instructions": .integer(0), "blocks": .integer(0), "edges": .integer(0), "value_steps": .integer(0), "encoded_bytes": .integer(0)]),
            "limitations": .array(["candidate_requires_independent_validation", "research_only", "runtime_call_return_unproven", "paths_structural_only", "dominance_and_exclusivity_unproven", "source_reconstruction_forbidden"].map(SwiftOutcomeJSON.string))])
    }
    static var emptyRegions: SwiftOutcomeJSON { .object(["status": .string("unknown"), "success_entry_pc": .null, "error_entry_pc": .null, "paths": .array([]), "tails": .array([])]) }
    func need(_ condition: Bool, _ reason: String) throws { if !condition { throw SwiftOutcomeError(code: reason) } }
    func work(_ count: Int = 1) throws {
        let current = result["accounting"]["work"].integer ?? 0
        try need(Int128(count) <= Int128(limits.maxWork) - current, "witness_work_limit")
        result["accounting"]["work"] = .integer(current + Int128(count))
    }
    func provenance(_ value: SwiftOutcomeJSON) throws -> SwiftOutcomeJSON {
        var selected: [String: SwiftOutcomeJSON] = [:]
        for name in ["call", "callee_entry"] {
            let source = try swiftOutcomeGet(value, name, default: .object([:]))
            var row: [String: SwiftOutcomeJSON] = [:]
            for key in ["pc", "word", "slice_file_offset", "container_file_offset"] {
                let value = try swiftOutcomeGet(source, key)
                row[key] = value.integer.map { .string(swiftOutcomeHex($0)) } ?? value
            }
            selected[name] = .object(row)
        }
        return .object(selected)
    }
    func build() -> SwiftOutcomeJSON {
        do {
            try need(profile == "broad-v1", "unsupported_profile")
            result["source_models"] = .object(["edge": .string("swift-broad-error-flow-v1"), "witness": .string(witnessModel),
                "validation": .string(validationModel), "cfg": .string("swift-bounded-structural-cfg-v1"), "value": .string("swift-outcome-values-v1")])
            try need(callsite.object != nil, "callsite_object_required")
            try need(callsite["status"] == .string("admitted_callsite"), "callsite_not_admitted")
            guard let pc128 = callsite["call_pc"].integer, let target128 = callsite["callee_pc"].integer else { throw SwiftOutcomeError(code: "integer_call_addresses_required") }
            try need(pc128 >= 0 && pc128 < Int128(1) << 64 && target128 >= 0 && target128 < Int128(1) << 64 && pc128 % 4 == 0 && target128 % 4 == 0, "call_address_range")
            let pc = UInt64(pc128), target = UInt64(target128)
            try work(image.functions.count + image.sections.count)
            try need(image.functions.count <= limits.maxWork && image.sections.count <= limits.maxWork, "image_metadata_limit")
            try need(image.functions.contains(function) && function.start <= pc && pc < function.endExclusive, "caller_membership")
            let callees = image.functions.filter { $0.start == target }
            try need(callees.count == 1, "callee_membership")
            result["identity"] = .object([
                "slice_sha256": .string(image.sliceSHA256), "container_sha256": .string(image.containerSHA256),
                "slice_offset": .string(swiftOutcomeHex(image.sliceOffset)), "slice_size": .string(swiftOutcomeHex(image.sliceSize)),
                "architecture": .string(image.architecture), "uuid": image.uuid.map(SwiftOutcomeJSON.string) ?? .null,
                "preferred_base": .string(swiftOutcomeHex(image.preferredBase)), "slice_index": image.sliceIndex.map { .integer(Int128($0)) } ?? .null,
                "container_slice_count": image.containerSliceCount.map { .integer(Int128($0)) } ?? .null,
                "cpu_subtype": .integer(Int128(image.cpuSubtype)), "caller": swiftOutcomeFunctionRange(function),
                "callee": swiftOutcomeFunctionRange(callees[0]), "call_pc": .string(swiftOutcomeHex(pc))])
            let selected: SwiftOutcomeJSON = .object([
                "provenance": try provenance(callsite.object?["provenance"] ?? .object([:])),
                "declaration": callsite.object?["declaration"] ?? .object([:]),
                "abi": try SwiftOutcomeWitnessCodec.publicRecord(callsite.object?["abi"] ?? .object([:]), limits: limits)])
            _ = try SwiftOutcomeWitnessCodec.preflight(selected, limits: limits)
            let word: UInt32
            do { word = try image.wordAt(pc) }
            catch let error as SwiftOutcomeError {
                // InputError is a ValueError in the donor and is caught as message text.
                if error.code == "unmapped_address" { throw SwiftOutcomeError(code: "No section contains VM range " + swiftOutcomeHex(pc) + "+0x4") }
                if error.code == "unmapped_bytes" { throw SwiftOutcomeError(code: "The requested VM range is not file backed") }
                throw error
            }
            try need(word & 0xfc000000 == 0x94000000, "direct_bl_required")
            var displacement = Int128(word & 0x03ffffff)
            if displacement & 0x02000000 != 0 { displacement -= 0x04000000 }
            try need(pc128 + displacement * 4 == target128, "raw_call_target_mismatch")
            try need(selected["provenance"]["call"]["word"] == .string(swiftOutcomeWord(word)), "call_provenance_mismatch")
            var call = selected
            call["pc"] = .string(swiftOutcomeHex(pc)); call["word"] = .string(swiftOutcomeWord(word)); call["callee_pc"] = .string(swiftOutcomeHex(target)); result["call"] = call
            try need(swiftOutcomeGet(selected["declaration"], "status") == .string("syntax_admitted"), "declaration_unqualified")
            let abi = selected["abi"]
            var qualified = try swiftOutcomeGet(abi, "status") == .string("admitted")
            if qualified { qualified = try [SwiftOutcomeJSON.string("swift6-arm64-sync-untyped-research-v1"), .string("swift6-arm64-sync-untyped-stable-research-v2")].contains(swiftOutcomeGet(abi, "profile")) }
            if qualified { qualified = try swiftOutcomeGet(abi, "error_register") == .string("x21") }
            if qualified {
                let evidence = try swiftOutcomeGet(abi, "evidence", default: .object([:]))
                let lowering = try swiftOutcomeGet(evidence, "lowering", default: .object([:]))
                qualified = try swiftOutcomeGet(lowering, "qualification_id").isTruthy
            }
            if !qualified { missing.append(.string("abi_unqualified")) }
            let cfgLimits = try SwiftCFGLimits(maxWork: limits.maxWork - Int(result["accounting"]["work"].integer!), maxBlocks: limits.maxBlocks,
                maxEdges: limits.maxEdges, maxDepth: min(limits.maxDepth, 4096), maxRetainedWords: limits.maxInstructions)
            let cfg = try buildSwiftCFG(image: image, function: function, limits: cfgLimits)
            result["cfg"] = cfg
            for (key, source) in [("instructions", "retained_words"), ("blocks", "blocks"), ("edges", "edges")] { result["accounting"][key] = cfg["accounting"][source] }
            try work(Int(cfg["accounting"]["work"].integer!))
            try need(cfg["completeness"]["complete"] == .bool(true), "cfg_" + (cfg["reason"].string ?? "None"))
            if qualified { try postCall(pc) }
            else { result["post_call"]["reason"] = .string("abi_unqualified") }
            if result["post_call"]["status"] != .string("candidate") { missing.append(result["post_call"]["reason"]) }
            result["completeness"]["complete"] = .bool(missing.isEmpty)
            if missing.isEmpty { result["reason"] = .string("validation_required") }
        } catch let error as SwiftOutcomeError { missing.append(.string(error.code)) }
        catch { missing.append(.string("malformed_candidate_input")) }
        result["completeness"]["missing"] = .array(missing)
        do {
            let raw = try SwiftOutcomeWitnessCodec.encode(result, limits: limits)
            result["accounting"]["encoded_bytes"] = .integer(Int128(raw.count))
            for _ in 0..<3 {
                let count = try SwiftOutcomeWitnessCodec.encode(result, limits: limits).count
                if result["accounting"]["encoded_bytes"] == .integer(Int128(count)) { break }
                result["accounting"]["encoded_bytes"] = .integer(Int128(count))
            }
        } catch {
            result["cfg"] = .object([:]); result["call"] = .object([:])
            result["value_facts"] = .object(["seed": .null, "observations": .array([])])
            result["post_call"]["status"] = .string("unknown"); result["post_call"]["reason"] = .string("witness_output_limit"); result["post_call"]["trace"] = .array([])
            result["regions"] = Self.emptyRegions
            result["completeness"] = .object(["complete": .bool(false), "missing": .array([.string("witness_output_limit")])])
            result["reason"] = .string("candidate_facts_incomplete"); result["accounting"]["encoded_bytes"] = .integer(0)
        }
        return result
    }

    func postCall(_ pc: UInt64) throws {
        let rows = (result["cfg"]["blocks"].array ?? []).flatMap { $0["instructions"].array ?? [] }
        var byPC: [UInt64: SwiftOutcomeJSON] = [:]
        for row in rows { if let address = swiftOutcomeParseHex(row["pc"]) { byPC[address] = row } }
        result["post_call"]["reason"] = .string("post_call_test_unknown")
        let stable = result["call"]["abi"]["profile"] == .string("swift6-arm64-sync-untyped-stable-research-v2")
        let origin = stable ? "raw_post_call_register:x21" : "abi_post_call_error:x21"
        let seed = SwiftAbstractValue.registerCopy(origin: origin, width: 64)
        let valueLimits = ValueLimits(maxStateEntries: limits.maxStateEntries, maxProvenanceDepth: limits.maxDepth,
            maxSteps: limits.postCallWindow, maxProvenanceNodes: limits.maxProvenanceNodes)
        var state = try initialState([21: seed], limits: valueLimits)
        var prefixLimits = valueLimits; prefixLimits.maxSteps = limits.maxInstructions
        var prefix = try initialState(limits: prefixLimits), frameKnown = true
        let control: Set<String> = ["ret", "brk", "bl", "b", "bcond", "xcbz", "xcbnz", "wcbz", "wcbnz", "xtbz", "xtbnz", "wtbz", "wtbnz"]
        var address = function.start
        while address < pc {
            try work()
            guard let row = byPC[address] else { frameKnown = false; break }
            let instruction = try decodeSwiftOutcomeInstruction(word: UInt32(swiftOutcomeParseHex(row["word"])!), address: address)
            if control.contains(instruction.kind) { frameKnown = false; break }
            if ["adr", "adrp"].contains(instruction.kind) { prefix.registers.removeAll { $0.register == instruction.rd }; address += 4; continue }
            let step = transferSwiftValue(prefix, instruction, limits: prefixLimits)
            if step.status != "resolved" { frameKnown = false; break }
            prefix = step.state; address += 4
        }
        state.spOffset = frameKnown ? prefix.spOffset : nil
        result["value_facts"]["seed"] = .object(["register": .string("x21"), "kind": .string("register_copy"), "origin": .string(origin), "width": .integer(64)])
        var cursor = Int128(pc) + 4, seen: Set<UInt64> = []
        var comparison: (register: Int, pc: UInt64, word: SwiftOutcomeJSON)?
        for _ in 0..<limits.postCallWindow {
            try work()
            guard let cursor64 = UInt64(exactly: cursor), let row = byPC[cursor64] else { break }
            if seen.contains(cursor64) { result["post_call"]["reason"] = .string("post_call_cycle"); return }
            seen.insert(cursor64)
            result["post_call"]["trace"] = .array(result["post_call"]["trace"].array! + [row["pc"]])
            let instruction = try decodeSwiftOutcomeInstruction(word: UInt32(swiftOutcomeParseHex(row["word"])!), address: cursor64)
            let value = state.readRegister(instruction.rn)
            let compareTest = comparison != nil && instruction.kind == "bcond" && ["0", "1"].contains(instruction.addressing)
            if comparison != nil && !compareTest { result["post_call"]["reason"] = .string("comparison_branch_not_adjacent_or_supported"); return }
            if (["xcbz", "xcbnz"].contains(instruction.kind) && value == seed) || compareTest {
                let target = cursor + instruction.immediate, fall = cursor + 4
                let zeroTarget = instruction.kind == "xcbz" || (compareTest && instruction.addressing == "0")
                let error = zeroTarget ? fall : target, success = zeroTarget ? target : fall
                guard let error64 = UInt64(exactly: error), let success64 = UInt64(exactly: success), byPC[error64] != nil, byPC[success64] != nil else { break }
                var post = result["post_call"]
                post["status"] = .string("candidate"); post["reason"] = .string("qualified_error_alias_zero_test")
                post["test_pc"] = .string(swiftOutcomeHex(cursor)); post["test_word"] = row["word"]
                post["test_register"] = .string("x\(compareTest ? comparison!.register : instruction.rn)")
                post["error_successor_pc"] = .string(swiftOutcomeHex(error)); post["success_successor_pc"] = .string(swiftOutcomeHex(success))
                if compareTest, let comparison {
                    post["test_kind"] = .string("cmp_zero_bcond"); post["comparison_pc"] = .string(swiftOutcomeHex(comparison.pc)); post["comparison_word"] = comparison.word; post["test_condition"] = .string(zeroTarget ? "eq" : "ne")
                }
                result["post_call"] = post
                var regions = result["regions"]
                regions["status"] = .string("structural_candidates"); regions["success_entry_pc"] = .string(swiftOutcomeHex(success)); regions["error_entry_pc"] = .string(swiftOutcomeHex(error))
                regions["paths"] = .array([("success", success), ("error", error)].map { .object(["outcome": .string($0.0), "entry_pc": .string(swiftOutcomeHex($0.1)), "reachability": .string("unproven")]) })
                regions["tails"] = .array([]); result["regions"] = regions
                try partitionRegions(byPC, success64, error64); return
            }
            if instruction.kind == "xsubs" && instruction.rd == 31 && instruction.immediate == 0 && value == seed {
                comparison = (instruction.rn, cursor64, row["word"]); cursor += 4; continue
            }
            if instruction.kind == "b" { cursor += instruction.immediate; continue }
            if control.contains(instruction.kind) { result["post_call"]["reason"] = .string("post_call_control_without_error_test"); return }
            let transferred = transferSwiftValue(state, instruction, limits: valueLimits)
            result["accounting"]["value_steps"] = .integer(result["accounting"]["value_steps"].integer! + 1)
            if transferred.status != "resolved" {
                let memory = ["xstr", "wstr", "xldr", "wldr", "xldr_post", "stp", "ldp"]
                guard transferred.reason == "stack_base_unqualified", memory.contains(instruction.kind) else {
                    result["post_call"]["reason"] = transferred.reason.map(SwiftOutcomeJSON.string) ?? .null; return
                }
                let load = ["xldr", "wldr", "xldr_post", "ldp"].contains(instruction.kind)
                var writes = load ? Set(instruction.kind == "ldp" ? [instruction.rd, instruction.rt2] : [instruction.rd]) : Set<Int>()
                let writeback = ["pre", "post"].contains(instruction.addressing)
                if writeback && instruction.rn != 31 { writes.insert(instruction.rn) }
                try work(state.registers.count + state.registerEpochs.count + writes.count + 1)
                var epochs: [Int: Int] = [:]
                for pair in state.registerEpochs { epochs[pair.register] = pair.epoch }
                for register in writes where register != 31 { epochs[register] = (epochs[register] ?? 0) + 1 }
                state.registers.removeAll { writes.contains($0.register) }
                state.registerEpochs = epochs.sorted { $0.key < $1.key }.map { SwiftRegisterEpoch(register: $0.key, epoch: $0.value) }
                if !load { state.stack = []; state.stackEpoch += 1 }
                if writeback && instruction.rn == 31 { state.spOffset = nil }
                state.steps += 1
            } else { state = transferred.state }
            try work(state.registers.count + state.stack.count)
            var observations: [SwiftOutcomeJSON] = []
            for pair in state.registers where pair.value == seed { observations.append(.object(["register": .string("x\(pair.register)"), "kind": .string("register_copy"), "origin": .string(origin)])) }
            for cell in state.stack where cell.value == seed { observations.append(.object(["stack_slot": .integer(Int128(cell.slot)), "epoch": .integer(Int128(cell.epoch)), "kind": .string("stack_slot"), "origin": .string(origin)])) }
            result["value_facts"]["observations"] = .array(result["value_facts"]["observations"].array! + [.object(["pc": row["pc"], "origins": .array(observations)])])
            cursor += 4
        }
    }

    func partitionRegions(_ byPC: [UInt64: SwiftOutcomeJSON], _ success: UInt64, _ error: UInt64) throws {
        var edges: [UInt64: [SwiftOutcomeJSON]] = [:]
        for edge in result["cfg"]["edges"].array! {
            try work(); let source = swiftOutcomeParseHex(edge["source_pc"])!
            edges[source, default: []].append(edge["target_pc"])
        }
        func reach(_ entry: UInt64) throws -> Set<UInt64> {
            var seen: Set<UInt64> = [], pending = [entry]
            while let address = pending.popLast() {
                if seen.contains(address) { continue }
                try work(); seen.insert(address)
                let targets = edges[address] ?? [.string(swiftOutcomeHex(Int128(address) + 4))]
                for target in targets {
                    if let target = swiftOutcomeParseHex(target), byPC[target] != nil, !seen.contains(target) { pending.append(target) }
                }
            }
            return seen
        }
        let good = try reach(success), bad = try reach(error)
        let partition = ["success_only_pcs": good.subtracting(bad), "error_only_pcs": bad.subtracting(good),
            "shared_pcs": good.intersection(bad), "unreachable_pcs": Set(byPC.keys).subtracting(good).subtracting(bad)]
        result["regions"]["partition"] = .object(partition.mapValues { .array($0.sorted().map { .string(swiftOutcomeHex($0)) }) })
        for row in result["cfg"]["returns"].array! {
            let address = swiftOutcomeParseHex(row["pc"])!
            let label = good.contains(address) && bad.contains(address) ? "shared" : good.contains(address) ? "success" : bad.contains(address) ? "error" : "unreachable"
            result["regions"]["tails"] = .array(result["regions"]["tails"].array! + [.object(["pc": row["pc"], "kind": .string("return"), "outcome": .string(label)])])
        }
    }
}
