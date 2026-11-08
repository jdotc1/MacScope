import Foundation

/// Complete supplemental v1 validator over an already-admitted raw selected slice.
/// Not called by the v2 producer or live read wiring. No recovery/builder oracle.
func validateSwiftOutcomeLegacyAdmitted(image: SwiftOutcomeLegacyAdmittedImage, function: SwiftErrorFlowFunction,
                                       witness: SwiftOutcomeJSON, limits: WitnessLimits = WitnessLimits()) -> SwiftOutcomeJSON {
    SwiftOutcomeLegacyAdmittedCheck(image: image,function: function,witness: witness,limits: limits).run()
}

private final class SwiftOutcomeLegacyAdmittedCheck {
    let image: SwiftOutcomeLegacyAdmittedImage, function: SwiftErrorFlowFunction, witness: SwiftOutcomeJSON, limits: WitnessLimits
    var steps = 0, callerWords = 0, symbolRecords = 0, sourceSteps = 0
    var checked: [UInt64: UInt32] = [:]
    var facts: [String: SwiftOutcomeJSON] = [:]
    init(image: SwiftOutcomeLegacyAdmittedImage, function: SwiftErrorFlowFunction, witness: SwiftOutcomeJSON, limits: WitnessLimits) {
        self.image = image; self.function = function; self.witness = witness; self.limits = limits
    }
    struct Refusal: Error { let reason: String; let status: String }
    func need(_ ok: Bool, _ reason: String, _ status: String = "declined") throws { if !ok { throw Refusal(reason: reason,status: status) } }
    var work: Int128 { Int128(steps) + Int128(callerWords) + Int128(symbolRecords) + Int128(sourceSteps) }
    func sourceCharge() throws {
        try need(work < Int128(limits.maxTotalWork), "witness_total_work_limit", "unresolved"); sourceSteps += 1
    }
    func charge() throws {
        steps += 1
        try need(steps <= limits.maxSteps && work <= Int128(limits.maxTotalWork), "witness_work_limit", "unresolved")
    }
    func required(_ object: SwiftOutcomeJSON,_ key: String) throws -> SwiftOutcomeJSON {
        guard let value = object.object?[key] else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        return value
    }
    // Python's == permits Boolean/integer equality except where the donor
    // explicitly tests type. Keep that quirk local to legacy v1 validation.
    func equal(_ lhs: SwiftOutcomeJSON,_ rhs: SwiftOutcomeJSON) -> Bool {
        switch (lhs,rhs) {
        case (.bool(let b),.integer(let n)),(.integer(let n),.bool(let b)): return n == (b ? 1 : 0)
        case (.array(let a),.array(let b)): return a.count == b.count && zip(a,b).allSatisfy { equal($0.0,$0.1) }
        case (.object(let a),.object(let b)): return a.count == b.count && a.allSatisfy { key,value in b[key].map { equal(value,$0) } ?? false }
        default: return lhs == rhs
        }
    }
    func addr(_ value: SwiftOutcomeJSON) throws -> UInt64 {
        guard let s = value.string, s.hasPrefix("0x"), let n = UInt64(s.dropFirst(2), radix: 16),
              s == swiftOutcomeHex(n), n % 4 == 0 else { throw Refusal(reason: "invalid_address",status: "declined") }
        return n
    }
    func instruction(_ pc: UInt64) throws -> SwiftOutcomeInstruction {
        try charge()
        try need(pc >= function.start && pc < function.endExclusive && pc % 4 == 0, "instruction_outside_caller")
        guard let s = image.sections.first(where: { $0.address <= pc && Int128(pc) + 4 <= $0.end }), s.executable,
              ![UInt32(1), 12, 18].contains(s.flags & 255) else { throw Refusal(reason: "instruction_not_executable",status: "declined") }
        let offset = Int128(s.fileOffset) + Int128(pc) - Int128(s.address)
        try need(offset >= 0 && offset <= Int128(image.data.count) - 4 && offset + 4 <= Int128(image.sliceSize), "instruction_mapping")
        let word = UInt32(try image.unsigned(at: offset,count: 4))
        checked[pc] = word
        try need(checked.count <= limits.maxInstructions, "witness_instruction_limit", "unresolved")
        do { return try decodeSwiftOutcomeLegacyInstruction(word: word, address: pc) }
        catch { throw Refusal(reason: "instruction_unmodeled",status: "unresolved") }
    }
    func records(_ value: SwiftOutcomeJSON, _ start: UInt64, _ end: UInt64) throws -> [SwiftOutcomeInstruction] {
        guard let rows = value.array else { throw Refusal(reason: "interval_details_incomplete",status: "unresolved") }
        try need(end >= start && rows.count <= limits.maxInstructions && Int128(rows.count) * 4 == Int128(end) - Int128(start), "interval_details_incomplete", "unresolved")
        return try rows.enumerated().map { i, row in
            let pc = start + UInt64(i) * 4
            try need(row.object != nil && row["pc"] == .string(swiftOutcomeHex(pc)), "interval_address_mismatch")
            let d = try instruction(pc)
            try need(row["word"] == .string(swiftOutcomeWord(d.word)), "instruction_word_mismatch")
            if let kind = row.object?["kind"] { try need(kind == .string(d.kind), "instruction_kind_mismatch") }
            return d
        }
    }
    func proofFlags() throws {
        var pending = [witness]
        while let node = pending.popLast() {
            if let obj = node.object {
                for (k,v) in obj {
                    if k.hasSuffix("_proven") || k == "source_reconstruction_allowed" { try need(v == .bool(false), "retained_proof_scope") }
                    pending.append(v)
                }
            } else if let rows = node.array { pending.append(contentsOf: rows) }
        }
    }
    func run() -> SwiftOutcomeJSON {
        var status = "eligible_structural_only", reason = "bounded_facts_checked", complete = true
        do { try check() }
        catch let error as Refusal {
            status = error.status; reason = error.reason
            if reason.contains("limit") || reason.contains("budget") { complete = false }
        } catch let error as SwiftOutcomeError {
            status = "unresolved"; reason = "malformed_or_incomplete_evidence"
            if error.code.contains("limit") { reason = error.code; complete = false }
        } catch { status = "unresolved"; reason = "malformed_or_incomplete_evidence" }
        let mappings: [SwiftOutcomeJSON] = checked.keys.sorted().compactMap { pc in
            guard let section = image.sections.first(where: { $0.address <= pc && Int128(pc) + 4 <= $0.end }), let word = checked[pc] else { return nil }
            let offset = Int128(section.fileOffset) + Int128(pc) - Int128(section.address)
            return .object(["pc": .string(swiftOutcomeHex(pc)), "word": .string(swiftOutcomeWord(word)),
                            "slice_offset": .integer(offset), "container_offset": .integer(Int128(image.sliceOffset) + offset)])
        }
        return .object(["model_version": .string("swift-outcome-validation-v1"), "status": .string(status),
                        "reason": .string(reason), "details_complete": .bool(complete), "call_return_proven": .bool(false),
                        "source_reconstruction_allowed": .bool(false), "runtime_branch_proven": .bool(false),
                        "handler_semantics_proven": .bool(false), "exclusive_entry_proven": .bool(false),
                        "checked_instruction_count": .integer(Int128(checked.count)), "work_steps": .integer(work),
                        "local_steps": .integer(Int128(steps)), "caller_words": .integer(Int128(callerWords)),
                        "source_steps": .integer(Int128(sourceSteps)), "symbol_records": .integer(Int128(symbolRecords)),
                        "facts": .object(facts), "instruction_mappings": .array(mappings)])
    }
    func check() throws {
        _ = try boundedCopy(witness, limits: limits)
        try need(witness.object != nil, "witness_container")
        try need(witness["model_version"] == .string("swift-outcome-witness-v1") && witness["validation_model_version"] == .string("swift-outcome-validation-v1") && witness["schema_version"] == .integer(1), "witness_model")
        if witness["model_profile"].array != nil || witness["model_profile"].object != nil { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        guard let profile = witness["model_profile"].string, ["legacy", "methods"].contains(profile) else { throw Refusal(reason: "source_models",status: "declined") }
        try need(witness["source_models"] == sourceModels(profile), "source_models")
        try need(equal(witness["image"],image.identity), "selected_image_mismatch")
        try need(image.architecture == "arm64" && [UInt32(0),1].contains(image.cpuSubtype), "architecture")
        try need(image.functions.contains(function) && function.boundarySource == "lc_function_starts" && witness["caller"] == swiftOutcomeFunctionRange(function), "caller_identity")
        let c = try required(witness,"evidence")
        try need(c.object != nil, "call_container")
        try need(c.object?["presentation"] == nil, "unvalidated_presentation")
        try proofFlags()
        try need(c["status"] == .string("recovered_candidate"), "edge_not_recovered")
        let cp = try addr(required(c,"call_pc")), tp = try addr(required(c,"test_pc")), sp = try addr(required(c,"success_pc")), ep = try addr(required(c,"error_pc")), target = try addr(required(c,"callee_pc"))
        try need(c["caller_pc"] == .string(swiftOutcomeHex(function.start)) && c["call_image_offset"] == .string(swiftOutcomeHex(Int128(cp) - Int128(image.preferredBase))), "call_identity")
        try need(witness["witness_id"] == .string("swift-outcome-witness-v1:" + image.sliceSHA256 + ":" + swiftOutcomeHex(function.start) + ":" + swiftOutcomeHex(cp)), "witness_identity")
        let call = try instruction(cp)
        try need(call.kind == "bl" && c["call_word"] == .string(swiftOutcomeWord(call.word)) && Int128(cp) + call.immediate == Int128(target), "call_target_mismatch")
        try need(image.functions.contains(where: { $0.start == target && $0.boundarySource == "lc_function_starts" }), "callee_entry")
        let retained = try validateSymbol(target: target, call: c, profile: profile)
        facts["call"] = .string("checked_against_image")
        try need(cp < tp && Int128(tp) <= Int128(cp) + 32, "postcall_window")
        guard tp <= UInt64.max - 4 else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        let window = try records(required(c,"window"), cp + 4, tp + 4)
        guard let branch = window.last else { throw SwiftOutcomeError(code: "test_encoding") }
        var aliases: Set<Int> = [21], compare: SwiftOutcomeInstruction?, literal = false
        for d in window.dropLast() {
            if d.word & 0xfffffc1f == 0xf100001f {
                try need(aliases.contains(d.rn) && d.address == tp - 4, "error_compare"); compare = d; continue
            }
            try need(compare == nil, "comparison_not_adjacent")
            if d.kind == "nop" { continue }
            try need(["mov","movz","movn","xmovk","wmovz","wmovn","wmovk","wmov"].contains(d.kind), "postcall_unmodeled", "unresolved")
            if d.kind != "mov" { literal = true }
            if d.rd != 31 { if d.kind == "mov" && aliases.contains(d.rn) { aliases.insert(d.rd) } else { aliases.remove(d.rd) } }
        }
        let reg: Int, zero: Bool
        if let compare {
            try need(branch.kind == "bcond" && ["0","1"].contains(branch.addressing) && c["test_kind"] == .string("cmp_zero_bcond") && c["comparison_pc"] == .string(swiftOutcomeHex(tp - 4)) && c["test_condition"] == .string(branch.addressing == "0" ? "eq" : "ne"), "test_encoding")
            reg = compare.rn; zero = branch.addressing == "0"
        } else {
            try need(!literal, "literal_prefix_requires_compare")
            try need(["xcbz","xcbnz"].contains(branch.kind) && c.object?["test_kind"] == nil, "test_encoding")
            reg = branch.rn; zero = branch.kind == "xcbz"
        }
        try need(aliases.contains(reg) && c["tested_register"] == .string("x\(reg)"), "error_register")
        let bt = Int128(tp) + branch.immediate
        try need(bt > Int128(tp) + 4 && bt >= Int128(function.start) && bt < Int128(function.endExclusive), "successor_bounds")
        try need(Int128(sp) == (zero ? bt : Int128(tp) + 4) && Int128(ep) == (zero ? Int128(tp) + 4 : bt), "branch_polarity_mismatch")
        facts["test"] = .string("checked_against_image")
        let region = c["error_region"]
        guard region.object != nil else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        try need(region["status"] == .string("structural_region_candidate"), "region_missing", "unresolved")
        let lo = try addr(required(region,"start_pc")), hi = try addr(required(region,"end_pc_exclusive")), join = try addr(required(region,"join_pc"))
        try need(lo == ep && hi > lo && hi - lo <= 64, "error_interval")
        let errors = try records(required(region,"instructions"), lo, hi)
        try need(region["call_return_proven"] == .bool(false) && region["join_reachability_proven"] == .bool(false), "region_proof")
        let shared = region["shared_epilogue"]
        try need(shared.object != nil, "shared_tail_required", "unresolved")
        let success = region["success_interval"]
        guard success.object != nil else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        let sl = try addr(required(success,"start_pc")), sh = try addr(required(success,"end_pc_exclusive"))
        try need(sl == sp && sh > sl && sh - sl <= 32, "success_interval")
        let successes = try records(required(success,"instructions"), sl, sh), forward = sp < ep
        try need(forward ? (sh == ep && hi == join) : (hi == sp && sh == join), "interval_geometry")
        try need(forward ? region["layout"] == .string("success_fallthrough_error_forward") : region.object?["layout"] == nil, "layout_direction")
        guard let skip = (forward ? successes : errors).last else { throw SwiftOutcomeError(code: "skipping_arm_join_branch") }
        try need(skip.kind == "b" && Int128(skip.address) + skip.immediate == Int128(join), "skipping_arm_join_branch")
        let te = try addr(required(shared,"end_pc_exclusive"))
        try need(shared["start_pc"] == .string(swiftOutcomeHex(join)) && te > join && te - join <= 32 && shared["restore_state_proven"] == .bool(false), "tail_geometry")
        let tail = try records(required(shared,"instructions"), join, te)
        try need(tail.last?.word == 0xd65f03c0, "tail_return")
        for d in tail.dropLast() {
            try need(d.kind == "nop" || (d.kind == "ldp" && d.rn == 31 && d.addressing == "offset" && d.immediate >= 0 && (19...30).contains(d.rd) && (19...30).contains(d.rt2)) || (d.kind == "add" && d.rd == 31 && d.rn == 31 && d.immediate > 0 && d.immediate <= 4096 && d.immediate % 16 == 0), "tail_shape_unqualified", "unresolved")
        }
        let size = Int128(function.endExclusive) - Int128(function.start)
        try need(size >= 0 && size % 4 == 0 && size / 4 <= Int128(limits.maxCallerWords), "caller_scan_budget", "unresolved")
        let protected = [(lo,hi),(sl,sh),(join,te),(cp + 4,tp + 4)]
        var unknown = 0, conflicts = 0
        for i in 0..<Int(size / 4) {
            try need(work < Int128(limits.maxTotalWork), "witness_total_work_limit", "unresolved")
            callerWords += 1
            let pc = function.start + UInt64(i) * 4, word = try image.wordAt(function.start + UInt64(i) * 4)
            guard let d = try? decodeSwiftOutcomeLegacyInstruction(word: word, address: pc) else { unknown += 1; continue }
            if ["b","bl","bcond","xcbz","xcbnz","wcbz","wcbnz","xtbz","xtbnz","wtbz","wtbnz"].contains(d.kind) {
                let dest = Int128(pc) + d.immediate
                try need(dest >= 0 && dest <= Int128(UInt64.max) && dest % 4 == 0, "caller_direct_target_out_of_range", "unresolved")
                let permitted = (pc == tp && dest == bt) || ((errors + successes).contains(where: { $0.address == pc && $0.kind == "b" && ($0.address + 4 == hi || $0.address + 4 == sh) && dest == Int128(join) }))
                for (a,b) in protected where Int128(a) <= dest && dest < Int128(b) && !(a <= pc && pc < b) { if !permitted { conflicts += 1; break } }
            }
        }
        try need(conflicts == 0, "unexpected_direct_entries", "blocked")
        try need(unknown == 0, "caller_scan_unclassified", "unresolved")
        let ledger = region.object?["incoming_validation"] ?? .object([:])
        guard ledger.object != nil else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        try need(ledger["caller_scan_complete"] == .bool(true) && equal(ledger["scanned_word_count"],.integer(size / 4)) && ledger["status"] == .string("no_unexpected_direct_entries") && equal(ledger["unexpected_entry_count"],.integer(0)) && equal(ledger["unclassified_word_count"],.integer(0)) && ledger["entry_details_complete"] == .bool(true) && ledger["unclassified_details_complete"] == .bool(true), "caller_ledger_incomplete", "unresolved")
        try need(equal(region["opaque_call_count"],.integer(Int128(errors.filter { $0.kind == "bl" }.count))), "opaque_call_count")
        try retainedRecords(c, callerSize: size)
        facts["intervals"] = .string("checked_against_image")
        try validateValues(call: c, retained: retained, window: window, compare: compare, errors: errors, successes: successes, tail: tail,
                           cp: cp, tp: tp, sp: sp, ep: ep, hi: hi, sh: sh, join: join, reg: reg, zero: zero)
    }
    func validateSymbol(target: UInt64, call: SwiftOutcomeJSON, profile: String) throws -> SwiftOutcomeJSON {
        var cursor: Int128 = 32
        var table: (UInt64,UInt64,UInt64,UInt64)?
        let commands = try image.unsigned(at: 16,count: 4)
        for _ in 0..<commands {
            try sourceCharge()
            let command = try image.unsigned(at: cursor,count: 4), size = try image.unsigned(at: cursor + 4,count: 4)
            if command == 2 {
                table = (try image.unsigned(at: cursor + 8,count: 4),try image.unsigned(at: cursor + 12,count: 4),
                         try image.unsigned(at: cursor + 16,count: 4),try image.unsigned(at: cursor + 20,count: 4))
            }
            cursor += Int128(size)
        }
        try need(table != nil,"callee_symbols")
        guard let (offset,count,strings,length) = table else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        var found: [String] = []
        try need(Int128(count) <= Int128(limits.maxCallerWords),"symbol_scan_budget","unresolved")
        for i in 0..<count {
            try need(work < Int128(limits.maxTotalWork),"witness_total_work_limit","unresolved")
            symbolRecords += 1
            let base = Int128(offset) + Int128(i) * 16
            let sx = try image.unsigned(at: base,count: 4), kind = try image.unsigned(at: base + 4,count: 1)
            let section = try image.unsigned(at: base + 5,count: 1), desc = try image.unsigned(at: base + 6,count: 2)
            let pc = try image.unsigned(at: base + 8,count: 8)
            if kind & 0xe0 != 0 || kind & 0x0e != 0x0e || pc != target { continue }
            try need(found.isEmpty,"callee_aliases")
            let sec = section >= 1 && section <= UInt64(image.sections.count) ? image.sections[Int(section - 1)] : nil
            try need(sec.map { $0.executable && $0.address <= pc && Int128(pc) < $0.end && ![UInt32(1),12,18].contains($0.flags & 255) } ?? false,"callee_section")
            try need(kind == 15 && desc & 0x300 == 0,"callee_visibility")
            let start = Int128(strings) + Int128(sx), end = min(min(Int128(strings) + Int128(length),start + 513),Int128(image.data.count))
            var bytes: [UInt8] = [], terminated = false
            if start >= 0 && start < end {
                for index in Int(start)..<Int(end) {
                    let b = image.data[image.data.startIndex + index]
                    if b == 0 { terminated = true; break }
                    bytes.append(b)
                }
            }
            try need(terminated,"callee_symbol_extent")
            guard bytes.allSatisfy({ $0 < 128 }), let symbol = String(bytes: bytes,encoding: .ascii) else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
            found.append(symbol)
        }
        try need(found.count == 1,"callee_symbols")
        guard let symbol = found.first else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        let declaration = parseThrowingDeclaration(symbol,allowMethods: profile == "methods")
        try need(declaration != nil,"callee_declaration")
        guard let declaration else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        var expected = declaration.record()
        expected["symbol"] = .string(symbol); expected["image_offset"] = .string(swiftOutcomeHex(Int128(target) - Int128(image.preferredBase)))
        let retained = try required(call,"callee")
        try need(retained.object != nil && (expected.object ?? [:]).allSatisfy { retained[$0.key] == $0.value },"callee_declaration_mismatch")
        if declaration.callableKind == "struct_instance_method" {
            let context = try admitSwiftOutcomeLegacyStructContext(image: image,declaration: declaration,charge: sourceCharge)
            try need(context["status"] == .string("admitted_struct_context") && declaration.parameterTypes == ["Swift.Int"] && declaration.resultType == "Swift.Int","method_context")
            try need(call["method_context"] == context,"method_context_mismatch")
        }
        return retained
    }
    func retainedRecords(_ call: SwiftOutcomeJSON, callerSize: Int128) throws {
        var pending = [call]
        while let node = pending.popLast() {
            if let obj = node.object {
                if obj["word"] != nil && obj["pc"] != nil {
                    let d = try instruction(addr(node["pc"]))
                    for key in ["target_pc","call_target_pc"] {
                        if let target = obj[key] { try need(["b","bl"].contains(d.kind) && target == .string(swiftOutcomeHex(Int128(d.address) + d.immediate)),"retained_target_mismatch") }
                    }
                    if let semantics = obj["semantics"] { try need(d.kind == "bl" && semantics == .string("opaque_call"),"opaque_semantics") }
                }
                if obj["scanned_word_count"] != nil {
                    try need(node["status"] == .string("no_unexpected_direct_entries") && node["caller_scan_complete"] == .bool(true)
                             && equal(node["scanned_word_count"],.integer(callerSize / 4)) && equal(node["unexpected_entry_count"],.integer(0))
                             && equal(node["unclassified_word_count"],.integer(0)) && node["unexpected_entries"] == .array([])
                             && node["unclassified_words"] == .array([]) && node["entry_details_complete"] == .bool(true)
                             && node["unclassified_details_complete"] == .bool(true),"retained_ledger_mismatch")
                }
                // Swift JSON objects have no insertion-order contract. Sorting makes
                // traversal deterministic; every retained row receives its donor charge.
                for key in SwiftOutcomeWitnessCodec.scalarSorted(obj.keys) { if let v = obj[key], v.object != nil || v.array != nil { pending.append(v) } }
            } else if let rows = node.array { pending.append(contentsOf: rows) }
        }
    }
    enum Scalar: Equatable { case bits(UInt64), callResult }
    func replay(_ instructions: [SwiftOutcomeInstruction], values initial: [Int:Scalar], armEnd: UInt64, join: UInt64) throws -> [Int:Scalar] {
        var values = initial
        for d in instructions {
            try charge()
            if d.kind == "nop" { continue }
            if d.kind == "b" { try need(Int128(d.address) + 4 == Int128(armEnd) && Int128(d.address) + d.immediate == Int128(join),"arm_branch"); continue }
            if d.kind == "bl" { values.removeAll(); continue }
            try need(["mov","wmov","movz","movn","wmovz","wmovn","xmovk","wmovk"].contains(d.kind),"value_transfer_unqualified","unresolved")
            if d.rd == 31 { continue }
            if d.kind.hasSuffix("movz") || d.kind.hasSuffix("movn") {
                let mask: UInt64 = d.kind.hasPrefix("w") ? 0xffffffff : .max
                let bits = UInt64(truncatingIfNeeded: d.immediate)
                values[d.rd] = .bits((d.kind.hasSuffix("movz") ? bits : ~bits) & mask)
            } else if ["xmovk","wmovk"].contains(d.kind) {
                if case .some(.bits(let bits)) = values[d.rd], let shift = Int(d.addressing), (0..<64).contains(shift) {
                    let mask: UInt64 = d.kind == "wmovk" ? 0xffffffff : .max
                    values[d.rd] = .bits(((bits & ~(UInt64(65535) << shift)) | (UInt64(truncatingIfNeeded: d.immediate) << shift)) & mask)
                } else { values.removeValue(forKey: d.rd) }
            } else {
                var value: Scalar? = d.rn == 31 ? .bits(0) : values[d.rn]
                if d.kind == "wmov" { if case .some(.bits(let bits)) = value { value = .bits(bits & 0xffffffff) } else { value = nil } }
                values[d.rd] = value
            }
        }
        return values
    }
    func validateValues(call c: SwiftOutcomeJSON, retained: SwiftOutcomeJSON, window: [SwiftOutcomeInstruction], compare: SwiftOutcomeInstruction?,
                        errors: [SwiftOutcomeInstruction], successes: [SwiftOutcomeInstruction], tail: [SwiftOutcomeInstruction],
                        cp: UInt64,tp: UInt64,sp: UInt64,ep: UInt64,hi: UInt64,sh: UInt64,join: UInt64,reg: Int,zero: Bool) throws {
        let prefix = Array(window.dropLast(compare == nil ? 1 : 2))
        let initial = try replay(prefix,values: [0:.callResult],armEnd: tp,join: join)
        let ev = try replay(errors,values: [:],armEnd: hi,join: join)[0]
        let sv = try replay(successes,values: initial,armEnd: sh,join: join)[0]
        guard let ev, let sv else { throw Refusal(reason: "outcome_values_unresolved",status: "unresolved") }
        guard case .bits = ev else { throw Refusal(reason: "outcome_values_unresolved",status: "unresolved") }
        guard let ret = tail.last else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        let flags = ["source_reconstruction_allowed","runtime_value_proven","exclusive_path_proven","caller_return_type_proven"]
        func outcome(_ path: String,_ value: Scalar) throws -> SwiftOutcomeJSON {
            let isBits: Bool
            if case .bits = value { isBits = true } else { isBits = false }
            let key = path == "error" ? "error_constant" : isBits ? "success_constant" : "success_result"
            let fact = c[key]
            guard fact.object != nil else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
            try need(flags.allSatisfy { fact[$0] == .bool(false) },"value_proof_scope")
            try need(fact["call_pc"] == .string(swiftOutcomeHex(cp)) && fact[path + "_pc"] == .string(swiftOutcomeHex(path == "error" ? ep : sp))
                     && fact["return_pc"] == .string(swiftOutcomeHex(ret.address)) && fact["register"] == .string("x0"),"value_binding")
            if case .bits(let bits) = value {
                let text = String(format: "0x%016llx",bits)
                try need(fact["status"] == .string("constant_register_candidate") && fact["constant_bits"] == .string(text) && fact["bit_width"] == .integer(64),"constant_mismatch")
                return .object(["kind": .string("constant_bits"),"bit_width": .integer(64),"constant_bits": .string(text)])
            }
            try need([SwiftOutcomeJSON.string("preserved_register_candidate"),.string("copied_register_candidate")].contains(fact["status"]) && retained["result"] == .string("Swift.Int"),"result_mismatch")
            return .object(["kind": .string("call_result"),"register": .string("x0"),"candidate_status": fact["status"]])
        }
        let sd = try outcome("success",sv), ed = try outcome("error",ev), choice = c["return_choice"]
        guard choice.object != nil else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        try need(choice["status"] == .string("structural_choice_candidate") && choice["call_pc"] == .string(swiftOutcomeHex(cp)) && choice["return_pc"] == .string(swiftOutcomeHex(ret.address)) && choice["success"] == sd && choice["error"] == ed,"choice_mismatch")
        var condition: SwiftOutcomeJSON = .object(["test_pc": .string(swiftOutcomeHex(tp)),"register": .string("x\(reg)"),"error_when": .string("nonzero")])
        if compare != nil { condition["comparison_pc"] = .string(swiftOutcomeHex(tp - 4)); condition["test_kind"] = .string("cmp_zero_bcond"); condition["test_condition"] = .string(zero ? "eq" : "ne") }
        try need(choice["condition"] == condition,"choice_condition")
        try need(witness["runtime_branch_proven"] == .bool(false),"proof_scope")
        for obj in [witness,choice] { for key in ["source_reconstruction_allowed","call_return_proven","handler_semantics_proven"] { try need(obj[key] == .bool(false),"proof_scope") } }
        let successBits: Bool
        if case .bits = sv { successBits = true } else { successBits = false }
        let selected = ["success_constant":successBits,"success_result":sv == .callResult,"error_constant":true]
        for key in ["success_constant","success_result","error_constant"] {
            let fact = c.object?[key] ?? .object([:])
            try need(fact.object != nil,"outcome_container")
            try need(flags.allSatisfy { fact[$0] == .bool(false) },"value_proof_scope")
            if ["constant_register_candidate","preserved_register_candidate","copied_register_candidate","adjusted_register_candidate"].contains(fact["status"].string ?? "") {
                try need(selected[key] == true,"conflicting_success_values")
                try need(flags.allSatisfy { fact[$0] == .bool(false) },"value_proof_scope")
            }
            let arm = key == "error_constant" ? errors : successes
            let valid = Set((arm + tail + window).map(\.address))
            let detail = fact.object?["instructions"] ?? .array([])
            try need(detail.array != nil && (detail.array?.count ?? 0) <= 64,"outcome_details","unresolved")
            let rows = detail.array ?? []
            if selected[key] == true { try need(!rows.isEmpty,"outcome_details","unresolved") }
            var seen: Set<UInt64> = []
            for row in rows {
                guard row.object != nil, let rawPC = row.object?["pc"] else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
                let pc = try addr(rawPC)
                try need(valid.contains(pc),"outcome_address")
                let d = try instruction(pc)
                try need(row["word"] == .string(swiftOutcomeWord(d.word)),"outcome_word")
                if let kind = row.object?["kind"] { try need(kind == .string(d.kind),"outcome_kind") }
                seen.insert(pc)
            }
            if selected[key] == true { try need((arm + tail).allSatisfy { seen.contains($0.address) },"outcome_details","unresolved") }
        }
        try need(choice["runtime_value_proven"] == .bool(false) && choice["exclusive_path_proven"] == .bool(false) && choice["caller_return_type_proven"] == .bool(false),"choice_proof_scope")
        try need(equal(choice["same_constant_bits"],successBits ? .bool(sv == ev) : .null),"choice_equality")
        facts["values"] = .string("independently_replayed")
        var nodes: [SwiftOutcomeJSON] = [("call_pc","call"),("test_pc","test"),("success_pc","success"),("error_pc","error")].map { .object(["id": .string($0.1),"pc": c[$0.0]]) }
        nodes.append(.object(["id": .string("join"),"pc": .string(swiftOutcomeHex(join))]))
        guard let lastError = errors.last, let lastSuccess = successes.last else { throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence") }
        let edges: [SwiftOutcomeJSON] = [("call","test"),("test","success"),("test","error"),("error","join"),("success","join")].map { a,b in
            let pc = a == "test" ? tp : a == "error" ? lastError.address : a == "success" ? lastSuccess.address : cp
            return .object(["from": .string(a),"to": .string(b),"provenance_pc": .string(swiftOutcomeHex(pc)),"relationship": .string("recorded_structural")])
        }
        try need(witness["graph"] == .object(["nodes": .array(nodes),"edges": .array(edges)]) && nodes.count <= limits.maxNodes && edges.count <= limits.maxEdges,"graph_mismatch")
    }
}
