import Foundation

// Retained-record reconciliation, not byte authentication. Source:
// swift_error_flow.py:1114-1635 and swift_error_text.py:25-52,173-191.
func swiftOutcomeLegacyAdjustedWord(_ outcome: SwiftOutcomeJSON) -> UInt32? {
    guard let op = outcome["operation"].string, ["add_immediate_modulo", "sub_immediate_modulo"].contains(op), outcome["bit_width"] == .integer(64), let shift128 = outcome["immediate_shift"].integer, shift128 == 0 || shift128 == 12, let immediate = outcome["immediate"].integer, immediate >= 1, immediate <= 4095 << Int(shift128), immediate % (1 << Int(shift128)) == 0, let source = outcome["adjustment_source_register"].integer, (0...30).contains(source), let destination = outcome["adjustment_register"].integer, (0...30).contains(destination) else { return nil }
    return (op == "add_immediate_modulo" ? 0x91000000 : 0xd1000000) | (shift128 == 12 ? 1 << 22 : 0) | UInt32(immediate >> Int(shift128)) << 10 | UInt32(source) << 5 | UInt32(destination)
}
func swiftOutcomeLegacyCalleeConsistent(_ callee: SwiftOutcomeJSON, allowMethods: Bool = false) -> Bool {
    guard let symbol = callee["symbol"].string, let declaration = parseThrowingDeclaration(symbol, allowMethods: allowMethods) else { return false }
    return swiftOutcomeLegacyContains(callee, declaration.record())
}
private struct SwiftOutcomeLegacyChoiceBinder {
    let call: SwiftOutcomeJSON
    var region: SwiftOutcomeJSON { call["error_region"] }
    var plan: SwiftOutcomeJSON { call["presentation"]["display_plan"] }
    func require(_ condition: Bool) throws { if !condition { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") } }
    func decode(_ row: SwiftOutcomeJSON) throws -> SwiftOutcomeInstruction {
        guard let pc = swiftOutcomeLegacyPC(row["pc"]), let word = swiftOutcomeLegacyParseWord(row["word"]) else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        return try decodeSwiftOutcomeLegacyInstruction(word: word, address: pc)
    }
    func callWord() throws {
        guard let pc = swiftOutcomeLegacyPC(call["call_pc"]), let target = swiftOutcomeLegacyPC(call["callee_pc"]), let word = swiftOutcomeLegacyParseWord(call["call_word"]), pc % 4 == 0, target % 4 == 0 else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        let ins = try decodeSwiftOutcomeLegacyInstruction(word: word, address: pc)
        try require(ins.kind == "bl" && swiftOutcomeLegacyTarget(ins) == target)
    }
    func entryLedgers() throws {
        func check(_ ledger: SwiftOutcomeJSON, _ scope: String) throws -> Int128 {
            guard swiftOutcomeLegacyClearLedger(ledger, scope: scope), let count = ledger["scanned_word_count"].integer, count >= Int128((call["window"].array?.count ?? 0) + 1), ledger["unexpected_entries"] == .array([]), ledger["unclassified_words"] == .array([]) else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }; return count
        }
        let count = try check(region["incoming_validation"], "caller_local_direct_edges")
        if call["test_kind"].string == "cmp_zero_bcond" {
            let flag = call["flag_entry_validation"]
            guard let pc = swiftOutcomeLegacyPC(call["call_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), pc <= UInt64.max - 4, test <= UInt64.max - 4 else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
            let other = try check(flag, "caller_local_direct_edges_into_postcall_flag_window")
            try require(other == count && flag["flag_state_proven"] == .bool(false) && flag["protected_start_pc"] == .string(swiftOutcomeHex(pc + 4)) && flag["protected_end_pc_exclusive"] == .string(swiftOutcomeHex(test + 4)))
        }
    }
    func errorArm(tailCount: Int, join: UInt64) throws {
        let outcome = call["error_constant"]
        guard let rows = region["instructions"].array, (1...16).contains(rows.count), region["status"].string == "structural_region_candidate", region["call_return_proven"] == .bool(false), region["join_reachability_proven"] == .bool(false), let start = swiftOutcomeLegacyPC(region["start_pc"]), start % 4 == 0, Int128(start) + Int128(rows.count) * 4 <= Int128(UInt64.max), let capturedAll = outcome["instructions"].array, capturedAll.count >= tailCount else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        let end = start + UInt64(rows.count) * 4, captured = Array(capturedAll.dropLast(tailCount))
        try require(region["start_pc"] == call["error_pc"] && region["end_pc_exclusive"] == .string(swiftOutcomeHex(end)) && plan["error_interval"] == .object(["start_pc": region["start_pc"], "end_pc_exclusive": region["end_pc_exclusive"], "instructions": .array(rows)]) && captured.count == rows.count)
        var calls = 0, branches = 0, constants: [Int: UInt64] = [:]
        for (index, row) in rows.enumerated() {
            let pc = start + UInt64(index) * 4, ins = try decode(row)
            try require(ins.address == pc)
            var expected: SwiftOutcomeJSON = .object(["pc": row["pc"], "word": row["word"], "kind": .string(ins.kind)])
            var evidence: SwiftOutcomeJSON = .object(["pc": row["pc"], "word": row["word"], "phase": .string("error")])
            if ins.kind == "bl" {
                guard let target = swiftOutcomeLegacyTarget(ins), target % 4 == 0 else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
                expected["call_target_pc"] = .string(swiftOutcomeHex(target)); expected["semantics"] = .string("opaque_call"); evidence["constant_state"] = .string("cleared_after_opaque_call"); calls += 1
            } else if ins.kind == "b" {
                try require(index == rows.count - 1 && swiftOutcomeLegacyTarget(ins) == join && region["layout"].string != "success_fallthrough_error_forward" && region["end_pc_exclusive"] == call["success_pc"])
                expected["target_pc"] = .string(swiftOutcomeHex(join)); branches += 1
            } else { try require(SwiftOutcomeLegacyKinds.arm.contains(ins.kind)) }
            try require(row == expected && captured[index] == evidence)
            if ins.kind == "bl" { constants.removeAll() } else if !["nop", "b"].contains(ins.kind) { swiftOutcomeLegacyTransferConstant(ins, constants: &constants) }
        }
        guard let constant = constants[0] else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        try require(outcome["constant_bits"] == .string(swiftOutcomeLegacyBits(constant)) && (branches != 0 || end == join) && region["opaque_call_count"] == .integer(Int128(calls)) && outcome["opaque_call_count"] == .integer(Int128(calls)))
    }
    func successArm(outcome: SwiftOutcomeJSON, tailCount: Int, join: UInt64) throws -> [SwiftOutcomeJSON] {
        let interval = region["success_interval"], forward = region["layout"].string == "success_fallthrough_error_forward"
        var keys: Set<String> = ["start_pc", "end_pc_exclusive", "instructions"]
        if forward { keys.insert("instructions_complete") }
        guard let fields = interval.object, Set(fields.keys) == keys, interval == plan["success_interval"], !forward || interval["instructions_complete"] == .bool(true), let rows = interval["instructions"].array, (1...8).contains(rows.count), let start = swiftOutcomeLegacyPC(interval["start_pc"]), start % 4 == 0, Int128(start) + Int128(rows.count) * 4 <= Int128(UInt64.max), let all = outcome["instructions"].array, all.count >= tailCount + rows.count else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        let end = start + UInt64(rows.count) * 4, prefix = Array(all.dropLast(tailCount)), captured = Array(prefix.suffix(rows.count)), preceding = prefix.dropLast(rows.count)
        try require(interval["start_pc"] == call["success_pc"] && interval["end_pc_exclusive"] == .string(swiftOutcomeHex(end)) && (forward ? end == swiftOutcomeLegacyPC(call["error_pc"]) : end == join) && preceding.allSatisfy { $0["phase"].string == "post_call" } && !(outcome["status"].string == "constant_register_candidate" && call["test_kind"].string != "cmp_zero_bcond" && !preceding.isEmpty))
        var arithmetic = 0, kinds: [String] = []
        for (index, row) in rows.enumerated() {
            let ins = try decode(row), pc = start + UInt64(index) * 4
            try require(ins.address == pc)
            var expected: SwiftOutcomeJSON = .object(["pc": row["pc"], "word": row["word"], "kind": .string(ins.kind)]); kinds.append(ins.kind)
            if forward && index == rows.count - 1 { try require(ins.kind == "b" && swiftOutcomeLegacyTarget(ins) == join); expected["target_pc"] = .string(swiftOutcomeHex(join)) }
            else if swiftOutcomeLegacyIsArithmetic(ins) { arithmetic += 1; try require(arithmetic <= 1 && outcome["status"].string == "adjusted_register_candidate") }
            else { try require(SwiftOutcomeLegacyKinds.arm.contains(ins.kind)) }
            try require(row == expected && captured[index] == .object(["pc": row["pc"], "word": row["word"], "phase": .string("success")]))
        }
        if arithmetic > 0 { try require((forward ? Array(kinds.dropLast()) : kinds).allSatisfy { ["nop", "mov", "add", "sub"].contains($0) }) }
        return captured
    }
    func postcall(outcome: SwiftOutcomeJSON, tailCount: Int, armCount: Int) throws {
        guard let start = swiftOutcomeLegacyPC(call["call_pc"]), start <= UInt64.max - 8, start % 4 == 0, let rows = call["window"].array, (1...8).contains(rows.count), Int128(start) + Int128(rows.count + 1) * 4 <= Int128(UInt64.max), let success = swiftOutcomeLegacyPC(call["success_pc"]), let error = swiftOutcomeLegacyPC(call["error_pc"]), [success, error].allSatisfy({ $0 >= start && $0 <= UInt64.max - 4 && $0 % 4 == 0 }), let evidence = outcome["instructions"].array, evidence.count >= tailCount + armCount else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        var words: [UInt32] = [0]
        for (index, row) in rows.enumerated() {
            guard Set(row.object?.keys.map { $0 } ?? []) == Set(["pc", "word", "kind"]), row["pc"] == .string(swiftOutcomeHex(start + UInt64(index + 1) * 4)), let word = swiftOutcomeLegacyParseWord(row["word"]) else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }; words.append(word)
        }
        if call["test_kind"].string != "cmp_zero_bcond" { try require(["test_kind", "test_condition", "comparison_pc"].allSatisfy { call.object?[$0] == nil }) }
        let recovery = SwiftOutcomeLegacyRecovery(words: words, start: start, endExclusive: max(success, error) + 4)
        let rebuilt = recovery.edges(callOffset: 0)
        try require(rebuilt["status"].string == "recovered_candidate" && swiftOutcomeLegacyContains(call, rebuilt))
        let expectWindow = outcome["status"].string != "constant_register_candidate" || call["test_kind"].string == "cmp_zero_bcond"
        let expected: [SwiftOutcomeJSON] = expectWindow ? rows.map { .object(["pc": $0["pc"], "word": $0["word"], "phase": .string("post_call")]) } : []
        try require(Array(evidence.dropLast(tailCount + armCount)) == expected)
    }
    func successLiteral(outcome: SwiftOutcomeJSON, arm: [SwiftOutcomeJSON]) throws {
        var constants: [Int: UInt64] = [:]
        let window = call["window"].array ?? []
        let records = (call["test_kind"].string == "cmp_zero_bcond" ? Array(window.dropLast(2)) : []) + arm
        for row in records { let ins = try decode(row); if ["nop", "b"].contains(ins.kind) { continue }; try require(SwiftOutcomeLegacyKinds.arm.contains(ins.kind)); swiftOutcomeLegacyTransferConstant(ins, constants: &constants) }
        guard let value = constants[0] else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        try require(outcome["constant_bits"] == .string(swiftOutcomeLegacyBits(value)))
    }
    func resultAliases(outcome: SwiftOutcomeJSON, arm: [SwiftOutcomeJSON]) throws {
        try require(call["tested_register"].string != "x0")
        let rows = call["window"].array ?? [], window = Array(rows.dropLast(call["test_kind"].string == "cmp_zero_bcond" ? 2 : 1))
        var aliases: Set<Int> = [0], copied = false, adjusted = false
        for (phase, records) in [("post_call", window), ("success", arm)] {
            for row in records {
                let ins = try decode(row)
                if ins.kind == "nop" || phase == "success" && ins.kind == "b" { continue }
                if phase == "success" && swiftOutcomeLegacyIsArithmetic(ins) { try require(!adjusted && aliases.contains(ins.rn)); adjusted = true; aliases = [ins.rd]; continue }
                try require(phase == "post_call" ? ins.kind == "mov" : SwiftOutcomeLegacyKinds.arm.contains(ins.kind))
                if ins.rd == 31 { continue }
                if ins.kind == "mov" && aliases.contains(ins.rn) { if ins.rd == 0 && ins.rn != 0 { copied = true }; aliases.insert(ins.rd) } else { aliases.remove(ins.rd) }
                try require(!aliases.isEmpty)
            }
        }
        let status = adjusted ? "adjusted_register_candidate" : copied ? "copied_register_candidate" : "preserved_register_candidate"
        try require(aliases.contains(0) && outcome["status"].string == status && outcome["result_registers_before_tail"] == .array(aliases.sorted().map { .string("x\($0)") }))
    }
    func capturedTail(_ outcome: SwiftOutcomeJSON) throws -> [SwiftOutcomeJSON] {
        guard let rows = outcome["instructions"].array, rows.count <= 24, rows.allSatisfy({ $0.object != nil }) else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        var first = rows.count
        while first > 0 && rows[first - 1]["phase"].string == "return_tail" { first -= 1 }
        try require((1...8).contains(rows.count - first) && !rows.prefix(first).contains { $0["phase"].string == "return_tail" })
        return rows.dropFirst(first).map { swiftOutcomeLegacyWithout($0, ["phase"]) }
    }
    func literal(_ outcome: SwiftOutcomeJSON) throws -> SwiftOutcomeJSON {
        guard let bits = outcome["constant_bits"].string, bits.count == 18, bits.hasPrefix("0x"), bits.dropFirst(2).allSatisfy({ "0123456789abcdef".contains($0) }), outcome["bit_width"] == .integer(64), outcome["depends_on_call_result"] == .bool(false) else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }
        return .object(["kind": .string("constant_bits"), "bit_width": .integer(64), "constant_bits": .string(bits)])
    }
}
func swiftOutcomeLegacyReturnChoice(_ call: SwiftOutcomeJSON, allowMethods: Bool = false) -> SwiftOutcomeJSON {
    var result: SwiftOutcomeJSON = .object(["status": .string("unresolved")])
    for key in SwiftOutcomeLegacyKinds.valueProofs + ["call_return_proven", "handler_semantics_proven"] { result[key] = .bool(false) }
    func fail(_ reason: String) -> SwiftOutcomeJSON { swiftOutcomeLegacyWith(result, ["reason": .string(reason)]) }
    guard call.object != nil else { return fail("outcome_evidence_inconsistent") }
    guard call["presentation"]["status"].string == "eligible_structural_only" else { return fail("structural_presentation_not_eligible") }
    guard call["presentation"].object?["postcall_entry_validation"] == nil else { return fail("outcome_evidence_inconsistent") }
    let error = call.object?["error_constant"] ?? .object([:]), constant = call.object?["success_constant"] ?? .object([:]), returned = call.object?["success_result"] ?? .object([:])
    guard error.object != nil, constant.object != nil, returned.object != nil else { return fail("outcome_evidence_missing_or_conflicting") }
    let errorKnown = error["status"].string == "constant_register_candidate", constantKnown = constant["status"].string == "constant_register_candidate", returnedKnown = ["preserved_register_candidate", "copied_register_candidate", "adjusted_register_candidate"].contains(returned["status"].string ?? "")
    guard errorKnown, constantKnown != returnedKnown else { return fail("outcome_evidence_missing_or_conflicting") }
    let success = constantKnown ? constant : returned, binder = SwiftOutcomeLegacyChoiceBinder(call: call), region = call["error_region"], plan = call["presentation"]["display_plan"], shared = region.object?["shared_epilogue"] != nil
    guard swiftOutcomeLegacyCalleeConsistent(call["callee"], allowMethods: allowMethods), !returnedKnown || call["callee"]["result"].string == "Swift.Int" else { return fail("outcome_evidence_inconsistent") }
    do {
        try binder.callWord()
        var condition: SwiftOutcomeJSON = .object(["test_pc": call["test_pc"], "register": call["tested_register"], "error_when": .string("nonzero")])
        let compare = call["test_kind"].string == "cmp_zero_bcond", ne = compare && call["test_condition"].string == "ne"
        if compare { for key in ["comparison_pc", "test_kind", "test_condition"] { condition[key] = call[key] } }
        try binder.require(call["presentation"]["source_reconstruction_allowed"] == .bool(false) && plan["condition"] == condition && plan["success_entry_pc"] == call["success_pc"] && plan["error_interval"]["start_pc"] == call["error_pc"] && region.object != nil)
        if ne { try binder.require(region["layout"].string == "success_fallthrough_error_forward" && shared && success["return_tail_layout"].string == "shared_epilogue") }
        if !shared { try binder.require((returnedKnown && returned["return_tail_layout"].string == "success_entry") || (compare && constantKnown && constant["return_tail_layout"].string == "success_entry")) }
        let successTail = try binder.capturedTail(success), errorTail = try binder.capturedTail(error)
        guard let join = swiftOutcomeLegacyPC(region["join_pc"]), join % 4 == 0, Int128(join) + Int128(successTail.count) * 4 <= Int128(UInt64.max) else { return fail("outcome_evidence_inconsistent") }
        let tail: SwiftOutcomeJSON
        if shared { tail = region["shared_epilogue"] }
        else { try binder.require(region["join_pc"] == call["success_pc"] && plan.object?["shared_epilogue"] == nil); tail = .object(["start_pc": region["join_pc"], "end_pc_exclusive": .string(swiftOutcomeHex(join + UInt64(successTail.count) * 4)), "instructions": .array(successTail), "restore_state_proven": .bool(false)]) }
        guard let rows = tail["instructions"].array, (1...8).contains(rows.count), Int128(join) + Int128(rows.count) * 4 <= Int128(UInt64.max) else { return fail("outcome_evidence_inconsistent") }
        let end = join + UInt64(rows.count) * 4, layout = shared ? "shared_epilogue" : "success_entry"
        try binder.require(tail["restore_state_proven"] == .bool(false) && (!returnedKnown || success["return_tail_layout"].string == layout) && (success.object?["return_tail_layout"] ?? .string(layout)) == .string(layout) && tail["start_pc"] == region["join_pc"] && tail["end_pc_exclusive"] == .string(swiftOutcomeHex(end)) && swiftOutcomeLegacyRowsMatch(rows, start: join, end: end, limit: 8))
        let words = try rows.map { row -> UInt32 in guard let word = swiftOutcomeLegacyParseWord(row["word"]) else { throw SwiftOutcomeError(code: "outcome_evidence_inconsistent") }; return word }
        let rebuilt = SwiftOutcomeLegacyRecovery(words: words, start: join, endExclusive: end).sharedReturnTail(join: join)
        try binder.require(rebuilt == tail && successTail == rows && errorTail == rows)
        if shared { try binder.require(plan["shared_epilogue"] == tail) }
        try binder.errorArm(tailCount: errorTail.count, join: join)
        let arm = shared ? try binder.successArm(outcome: success, tailCount: successTail.count, join: join) : []
        try binder.postcall(outcome: success, tailCount: successTail.count, armCount: arm.count)
        try binder.entryLedgers()
        if constantKnown { try binder.successLiteral(outcome: success, arm: arm) } else { try binder.resultAliases(outcome: success, arm: arm) }
        let returnPC = rows.last?["pc"] ?? .null
        for (path, outcome) in [("success", success), ("error", error)] {
            try binder.require(outcome["register"].string == "x0" && outcome["call_pc"] == call["call_pc"] && outcome[path + "_pc"] == call[path + "_pc"] && outcome["return_pc"] == returnPC && swiftOutcomeLegacyFalseProofs(outcome, keys: SwiftOutcomeLegacyKinds.valueProofs))
        }
        try binder.require(error["call_return_proven"] == .bool(false) && error["handler_semantics_proven"] == .bool(false))
        let successDescription: SwiftOutcomeJSON
        if returnedKnown && success["status"].string == "adjusted_register_candidate" {
            guard let expected = swiftOutcomeLegacyAdjustedWord(success) else { return fail("outcome_evidence_inconsistent") }
            try binder.require(success["return_tail_layout"].string == "shared_epilogue" && arm.filter { $0["word"] == .string(swiftOutcomeLegacyWord(expected)) }.count == 1)
            successDescription = .object(["kind": .string(success["operation"].string == "add_immediate_modulo" ? "call_result_add_immediate" : "call_result_sub_immediate"), "register": .string("x0"), "immediate": success["immediate"], "bit_width": .integer(64), "operation": success["operation"], "immediate_shift": success["immediate_shift"]])
        } else if constantKnown { successDescription = try binder.literal(success) }
        else { successDescription = .object(["kind": .string("call_result"), "register": .string("x0"), "candidate_status": success["status"]]) }
        let errorDescription = try binder.literal(error)
        return swiftOutcomeLegacyWith(result, ["status": .string("structural_choice_candidate"), "reason": .string("bound_selected_path_outcomes"), "call_pc": call["call_pc"], "condition": condition, "success": successDescription, "error": errorDescription, "return_pc": returnPC, "same_constant_bits": constantKnown ? .bool(success["constant_bits"] == error["constant_bits"]) : .null])
    } catch { return fail("outcome_evidence_inconsistent") }
}

func swiftOutcomeLegacyConsistentChoice(_ call: SwiftOutcomeJSON) -> SwiftOutcomeJSON? {
    let choice = call["return_choice"]
    guard choice["status"].string == "structural_choice_candidate", call["presentation"]["status"].string == "eligible_structural_only", swiftOutcomeLegacyFalseProofs(choice, keys: SwiftOutcomeLegacyKinds.valueProofs + ["call_return_proven", "handler_semantics_proven"]) else { return nil }
    switch choice["same_constant_bits"] { case .null, .bool: break; default: return nil }
    // swift_error_text.py:42 uses Python container equality: bools compare
    // equal to integer 0/1 recursively. Keep this rule local to this helper;
    // proof flags and literal widths retain the donor's explicit type checks.
    func equivalent(_ lhs: SwiftOutcomeJSON, _ rhs: SwiftOutcomeJSON) -> Bool {
        switch (lhs, rhs) {
        case (.bool(let value), .integer(let number)), (.integer(let number), .bool(let value)):
            return number == (value ? 1 : 0)
        case (.array(let left), .array(let right)):
            return left.count == right.count && zip(left, right).allSatisfy { equivalent($0.0, $0.1) }
        case (.object(let left), .object(let right)):
            return left.count == right.count && left.allSatisfy { key, value in
                guard let other = right[key] else { return false }
                return equivalent(value, other)
            }
        default: return lhs == rhs
        }
    }
    let rebuilt = swiftOutcomeLegacyReturnChoice(call)
    guard equivalent(rebuilt, choice) else { return nil }
    for path in ["success", "error"] { if choice[path]["kind"].string == "constant_bits" && choice[path]["bit_width"] != .integer(64) { return nil } }
    return rebuilt
}
func swiftOutcomeLegacySummary(call: SwiftOutcomeJSON) -> String? {
    guard let choice = swiftOutcomeLegacyConsistentChoice(call) else { return nil }
    let success = choice["success"], error = choice["error"]
    guard let errorBits = error["constant_bits"].string, error["kind"].string == "constant_bits" else { return nil }
    if success["kind"].string == "constant_bits", case .bool = choice["same_constant_bits"], let bits = success["constant_bits"].string {
        return "Recorded literal outcomes (structural; runtime unproven): success x0 bits \(bits); error x0 bits \(errorBits)"
    }
    if success["kind"].string == "call_result", success["register"].string == "x0", choice["same_constant_bits"] == .null, let status = success["candidate_status"].string, ["preserved_register_candidate", "copied_register_candidate"].contains(status) {
        return "Recorded call-result/error outcomes (structural; runtime unproven): success x0 \(status == "preserved_register_candidate" ? "preserved" : "copied") call-result candidate; error x0 bits \(errorBits)"
    }
    if ["call_result_add_immediate", "call_result_sub_immediate"].contains(success["kind"].string ?? ""), let immediate = success["immediate"].integer {
        // Renderer guards raw retained fields separately before printing the
        // normalized pair (swift_error_text.py:420-426). A bool that compared
        // equal during consistency reconciliation must still withhold output.
        let rawSuccess = call["return_choice"]["success"]
        guard rawSuccess["bit_width"] == .integer(64),
              let rawImmediate = rawSuccess["immediate"].integer,
              let rawShift = rawSuccess["immediate_shift"].integer,
              rawImmediate == immediate, rawShift == success["immediate_shift"].integer else { return nil }
        let op = success["kind"].string == "call_result_add_immediate" ? "+" : "-"
        return "Recorded adjusted-result/error outcomes (structural; runtime unproven): success x0 call result \(op) \(immediate) modulo 2^64; error x0 bits \(errorBits)"
    }
    return nil
}
