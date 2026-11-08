import Foundation

// Pure legacy recovery over an admitted caller word prefix. No filesystem, CLI,
// Mach-O parser, witness eligibility, or live read wiring is introduced here.
// Source: swift_error_flow.py:107-1111. Original function end is retained when
// words is a bounded prefix so incomplete caller scans remain unresolved.
struct SwiftOutcomeLegacyRecovery: Sendable {
    let words: [UInt32]
    let start: UInt64
    let endExclusive: UInt64
    let validSpan: Bool
    init(words: [UInt32], start: UInt64 = 0x1000, endExclusive: UInt64? = nil) {
        self.words = words; self.start = start
        let upper = Int128(start) + Int128(words.count) * 4
        let end = endExclusive.map { Int128($0) } ?? upper
        validSpan = start % 4 == 0 && end >= Int128(start) && end <= Int128(UInt64.max)
            && upper <= end && end % 4 == 0
        self.endExclusive = end >= 0 && end <= Int128(UInt64.max) ? UInt64(end) : start
    }
    func instruction(_ pc: UInt64) throws -> SwiftOutcomeInstruction {
        guard validSpan, pc % 4 == 0, pc >= start, pc < endExclusive,
              (pc - start) / 4 < UInt64(words.count) else { throw SwiftOutcomeError(code: "Shared interval outside scanned caller") }
        return try decodeSwiftOutcomeLegacyInstruction(word: words[Int((pc - start) / 4)], address: pc)
    }
    func row(_ instruction: SwiftOutcomeInstruction, kind: Bool = false) -> SwiftOutcomeJSON {
        var value: SwiftOutcomeJSON = .object(["pc": .string(swiftOutcomeHex(instruction.address)), "word": .string(swiftOutcomeLegacyWord(instruction.word))])
        if kind { value["kind"] = .string(instruction.kind) }
        return value
    }
    func edges(callOffset: Int) -> SwiftOutcomeJSON {
        var aliases: Set<Int> = [21], window: [SwiftOutcomeJSON] = []
        var comparison: (Int, UInt64)?, literalPrefix = false
        func fail(_ reason: String) -> SwiftOutcomeJSON { .object(["reason": .string(reason), "window": .array(window)]) }
        guard validSpan else { return fail("legacy_caller_span") }
        guard callOffset >= 0, callOffset % 4 == 0, callOffset / 4 < words.count else { return fail("postcall_window_exhausted") }
        let first = callOffset / 4 + 1
        if first < words.count {
            for index in first..<min(words.count, first + 8) {
                let pc = start + UInt64(index) * 4, word = words[index]
                guard let ins = try? decodeSwiftOutcomeLegacyInstruction(word: word, address: pc) else { return fail(comparison == nil ? "intervening_instruction_unmodeled" : "comparison_branch_unmodeled") }
                window.append(row(ins, kind: true))
                var metadata: [String: SwiftOutcomeJSON] = [:]
                let register: Int, zeroTarget: Bool
                if let (r, cmpPC) = comparison {
                    guard ins.kind == "bcond", ["0", "1"].contains(ins.addressing) else { return fail("comparison_branch_not_adjacent_or_supported") }
                    register = r; zeroTarget = ins.addressing == "0"
                    metadata = ["test_kind": .string("cmp_zero_bcond"), "comparison_pc": .string(swiftOutcomeHex(cmpPC)), "test_condition": .string(zeroTarget ? "eq" : "ne")]
                } else {
                    if ins.kind == "nop" { continue }
                    if SwiftOutcomeLegacyKinds.literals.contains(ins.kind) {
                        literalPrefix = true; aliases.remove(ins.rd)
                        if aliases.isEmpty { return fail("error_value_clobbered") }; continue
                    }
                    if ins.kind == "mov" {
                        if ins.rd != 31 { if aliases.contains(ins.rn) { aliases.insert(ins.rd) } else { aliases.remove(ins.rd) } }
                        if aliases.isEmpty { return fail("error_value_clobbered") }; continue
                    }
                    if word & 0xfffffc1f == 0xf100001f {
                        guard aliases.contains(ins.rn) else { return fail("not_error_result_comparison") }
                        comparison = (ins.rn, pc); continue
                    }
                    if ["wcbz", "wcbnz"].contains(ins.kind) { return fail("narrow_error_test") }
                    if literalPrefix { return fail("literal_prefix_requires_compare_test") }
                    guard ["xcbz", "xcbnz"].contains(ins.kind) else { return fail("intervening_instruction_unmodeled") }
                    guard aliases.contains(ins.rn) else { return fail("not_error_result_test") }
                    register = ins.rn; zeroTarget = ins.kind == "xcbz"
                }
                guard let target = swiftOutcomeLegacyTarget(ins), target > pc, target != pc + 4, target % 4 == 0,
                      target >= start, target < endExclusive, pc + 4 < endExclusive else { return fail("unsupported_successor_region") }
                metadata.merge(["status": .string("recovered_candidate"), "test_pc": .string(swiftOutcomeHex(pc)), "tested_register": .string("x\(register)"), "success_pc": .string(swiftOutcomeHex(zeroTarget ? target : pc + 4)), "error_pc": .string(swiftOutcomeHex(zeroTarget ? pc + 4 : target)), "window": .array(window)], uniquingKeysWith: { _, b in b })
                return .object(metadata)
            }
        }
        return fail(comparison == nil ? "postcall_window_exhausted" : "comparison_branch_missing_or_outside_window")
    }
    func sharedReturnTail(join: UInt64) -> SwiftOutcomeJSON? {
        guard validSpan else { return nil }
        var tail: [SwiftOutcomeJSON] = []
        for index in 0..<8 {
            let (pc, overflow) = join.addingReportingOverflow(UInt64(index) * 4)
            guard !overflow, let ins = try? instruction(pc) else { return nil }
            tail.append(row(ins, kind: true))
            if ins.kind == "ret" { return .object(["start_pc": .string(swiftOutcomeHex(join)), "end_pc_exclusive": .string(swiftOutcomeHex(pc + 4)), "instructions": .array(tail), "restore_state_proven": .bool(false)]) }
            if ins.kind == "nop" { continue }
            if ins.kind == "xldr", ins.rn == 31, (19...30).contains(ins.rd), (0...4096).contains(ins.immediate), ins.immediate % 8 == 0 { continue }
            if ins.kind == "xldr_post", ins.rn == 31, (19...30).contains(ins.rd), ins.immediate > 0, ins.immediate <= 240, ins.immediate % 16 == 0, index + 1 < 8 {
                guard (try? instruction(pc + 4).kind) == "ret" else { return nil }
                tail[tail.count - 1]["sp_writeback_bytes"] = .integer(ins.immediate); continue
            }
            if ins.kind == "ldp", ins.rn == 31, ins.addressing == "offset", ins.immediate >= 0, (19...30).contains(ins.rd), (19...30).contains(ins.rt2) { continue }
            if ins.kind == "ldp", ins.rn == 31, ins.addressing == "post", ins.immediate > 0, ins.immediate <= 496, ins.immediate % 16 == 0, (19...30).contains(ins.rd), (19...30).contains(ins.rt2), index + 1 < 8 {
                guard (try? instruction(pc + 4).kind) == "ret" else { return nil }; continue
            }
            if ins.word == 0x910003bf, index + 2 < 8, let restore = try? instruction(pc + 4), let terminal = try? instruction(pc + 8) {
                if restore.kind == "ldp", restore.rn == 31, restore.addressing == "post", restore.rd == 29, restore.rt2 == 30, restore.immediate > 0, restore.immediate <= 496, restore.immediate % 16 == 0, terminal.kind == "ret" { continue }
                if restore.kind == "xldr", restore.rn == 31, restore.rd == 30, restore.immediate == 8, terminal.kind == "xldr_post", terminal.rn == 31, terminal.rd == 29, terminal.immediate == 16, index + 3 < 8, (try? instruction(pc + 12).kind) == "ret" { continue }
                return nil
            }
            if ins.kind == "add", ins.rd == 31, ins.rn == 31, ins.immediate > 0, ins.immediate <= 4096, ins.immediate % 16 == 0 { continue }
            return nil
        }
        return nil
    }
    func sharedEpilogue(success: UInt64, join: UInt64, allowArithmetic: Bool = false) -> SwiftOutcomeJSON? {
        guard validSpan, success >= start, success < join, join < endExclusive, (success | join) % 4 == 0, join - success <= 32 else { return nil }
        var rows: [SwiftOutcomeJSON] = [], hasArithmetic = false
        for pc in stride(from: success, to: join, by: 4) {
            guard let ins = try? instruction(pc) else { return nil }
            if allowArithmetic && swiftOutcomeLegacyIsArithmetic(ins) { if hasArithmetic { return nil }; hasArithmetic = true }
            else if !SwiftOutcomeLegacyKinds.arm.contains(ins.kind) { return nil }
            rows.append(row(ins, kind: true))
        }
        if hasArithmetic && rows.contains(where: { !["nop", "mov", "add", "sub"].contains($0["kind"].string ?? "") }) { return nil }
        guard let tail = sharedReturnTail(join: join) else { return nil }
        return .object(["success_interval": .object(["start_pc": .string(swiftOutcomeHex(success)), "end_pc_exclusive": .string(swiftOutcomeHex(join)), "instructions": .array(rows)]), "shared_epilogue": tail])
    }
    func forwardRegion(call: SwiftOutcomeJSON) -> SwiftOutcomeJSON {
        var result: SwiftOutcomeJSON = .object(["status": .string("declined"), "instructions": .array([])])
        func fail(_ reason: String) -> SwiftOutcomeJSON { swiftOutcomeLegacyWith(result, ["reason": .string(reason)]) }
        guard validSpan, let error = swiftOutcomeLegacyPC(call["error_pc"]), let success = swiftOutcomeLegacyPC(call["success_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), test <= UInt64.max - 4, success == test + 4, start <= success, success < error, error < endExclusive, (success | error) % 4 == 0 else { return fail("unsupported_error_region_layout") }
        guard error - success <= 32 else { return fail("success_region_budget") }
        var rows: [SwiftOutcomeJSON] = [], errors: [SwiftOutcomeJSON] = [], calls = 0, arithmetic = false, join: UInt64?
        let allow = call["test_kind"].string == "cmp_zero_bcond" ? call["test_condition"].string == "ne" : call["window"].array?.last?["kind"].string == "xcbnz"
        func saveSuccess() { result["success_interval"] = .object(["start_pc": .string(swiftOutcomeHex(success)), "end_pc_exclusive": .string(swiftOutcomeHex(error)), "instructions": .array(rows), "instructions_complete": .bool(UInt64(rows.count) * 4 == error - success)]) }
        saveSuccess()
        for pc in stride(from: success, to: error, by: 4) {
            guard let ins = try? instruction(pc) else {
                if pc >= start, (pc - start) / 4 < UInt64(words.count) { rows.append(.object(["pc": .string(swiftOutcomeHex(pc)), "word": .string(swiftOutcomeLegacyWord(words[Int((pc - start) / 4)])), "kind": .string("unclassified")])); saveSuccess(); return fail("success_region_instruction_unmodeled") }
                return fail("error_region_outside_scanned_prefix")
            }
            rows.append(row(ins, kind: true)); saveSuccess()
            if pc + 4 == error {
                guard ins.kind == "b" else { return fail("unsupported_error_region_layout") }
                join = swiftOutcomeLegacyTarget(ins)
                rows[rows.count - 1][join == nil ? "target_reason" : "target_pc"] = .string(join.map(swiftOutcomeHex) ?? "outside_vm_address_space"); saveSuccess()
            } else if allow && swiftOutcomeLegacyIsArithmetic(ins) {
                if arithmetic { return fail("success_region_control_flow_unmodeled") }; arithmetic = true
            } else if !SwiftOutcomeLegacyKinds.arm.contains(ins.kind) { return fail("success_region_control_flow_unmodeled") }
        }
        if arithmetic && rows.dropLast().contains(where: { !["nop", "mov", "add", "sub"].contains($0["kind"].string ?? "") }) { return fail("success_region_control_flow_unmodeled") }
        guard let join, error < join, join < endExclusive, join % 4 == 0 else { return fail("unsupported_error_region_layout") }
        guard join - error <= 64 else { return fail("error_region_budget") }
        for pc in stride(from: error, to: join, by: 4) {
            guard let ins = try? instruction(pc) else { return fail(pc >= start && (pc - start) / 4 < UInt64(words.count) ? "error_region_instruction_unmodeled" : "error_region_outside_scanned_prefix") }
            var item = row(ins, kind: true); errors.append(item); result["instructions"] = .array(errors)
            if ins.kind == "bl" {
                guard let target = swiftOutcomeLegacyTarget(ins), target % 4 == 0 else { return fail("error_region_call_target_invalid") }
                item["call_target_pc"] = .string(swiftOutcomeHex(target)); item["semantics"] = .string("opaque_call"); calls += 1
                errors[errors.count - 1] = item; result["instructions"] = .array(errors)
            } else if !SwiftOutcomeLegacyKinds.arm.contains(ins.kind) { return fail("error_region_instruction_unmodeled") }
        }
        guard let tail = sharedReturnTail(join: join) else { return fail("shared_epilogue_unmodeled") }
        return swiftOutcomeLegacyWith(result, ["status": .string("structural_region_candidate"), "layout": .string("success_fallthrough_error_forward"), "start_pc": .string(swiftOutcomeHex(error)), "end_pc_exclusive": .string(swiftOutcomeHex(join)), "join_pc": .string(swiftOutcomeHex(join)), "shared_epilogue": tail, "opaque_call_count": .integer(Int128(calls)), "call_return_proven": .bool(false), "join_reachability_proven": .bool(false)])
    }
    func region(call: SwiftOutcomeJSON) -> SwiftOutcomeJSON {
        var result: SwiftOutcomeJSON = .object(["status": .string("declined"), "instructions": .array([])])
        func fail(_ reason: String) -> SwiftOutcomeJSON { swiftOutcomeLegacyWith(result, ["reason": .string(reason)]) }
        guard validSpan, let error = swiftOutcomeLegacyPC(call["error_pc"]), let success = swiftOutcomeLegacyPC(call["success_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), let callPC = swiftOutcomeLegacyPC(call["call_pc"]), test <= UInt64.max - 4, callPC <= UInt64.max - 4 else { return fail("unsupported_error_region_layout") }
        let compare = call["test_kind"].string == "cmp_zero_bcond", ne = call["test_condition"].string == "ne"
        if compare {
            guard ["eq", "ne"].contains(call["test_condition"].string ?? "") else { return fail("compare_handler_layout_not_qualified") }
            let flag = call["flag_entry_validation"]
            guard flag.object != nil else { return fail("compare_flag_entries_required") }
            guard swiftOutcomeLegacyClearLedger(flag, scope: "caller_local_direct_edges_into_postcall_flag_window"), flag["protected_start_pc"] == .string(swiftOutcomeHex(callPC + 4)), flag["protected_end_pc_exclusive"] == .string(swiftOutcomeHex(test + 4)), test >= 4, call["comparison_pc"] == .string(swiftOutcomeHex(test - 4)), flag["flag_state_proven"] == .bool(false) else { return fail("compare_flag_entries_not_clear") }
            if !ne && (error != test + 4 || success <= error) { return fail("compare_handler_layout_not_qualified") }
            if ne {
                guard success == test + 4, error > success else { return fail("compare_handler_layout_not_qualified") }
                guard let cmp = try? instruction(test - 4), let branch = try? instruction(test), let window = call["window"].array, window.count >= 2,
                      cmp.word & 0xfffffc1f == 0xf100001f, call["tested_register"] == .string("x\(cmp.rn)"), branch.kind == "bcond", branch.addressing == "1", swiftOutcomeLegacyTarget(branch) == error,
                      swiftOutcomeLegacyContains(window[window.count - 2], row(cmp, kind: true)), swiftOutcomeLegacyContains(window[window.count - 1], row(branch, kind: true)) else { return fail("compare_forward_words_inconsistent") }
            }
        }
        if success == test + 4, error > success { return forwardRegion(call: call) }
        guard error == test + 4, start <= error, error < success, success < endExclusive, (error | success) % 4 == 0 else { return fail("unsupported_error_region_layout") }
        guard success - error <= 64 else { return fail("error_region_budget") }
        guard success >= start, (success - start) / 4 <= UInt64(words.count) else { return fail("error_region_outside_scanned_prefix") }
        var join = success, calls = 0, rows: [SwiftOutcomeJSON] = [], shared: SwiftOutcomeJSON = .object([:])
        for pc in stride(from: error, to: success, by: 4) {
            guard let ins = try? instruction(pc) else { return fail("error_region_instruction_unmodeled") }
            var item = row(ins, kind: true); rows.append(item); result["instructions"] = .array(rows)
            if ins.kind == "bl" {
                guard let target = swiftOutcomeLegacyTarget(ins), target % 4 == 0 else { return fail("error_region_call_target_invalid") }
                item["call_target_pc"] = .string(swiftOutcomeHex(target)); item["semantics"] = .string("opaque_call"); calls += 1
            } else if ins.kind == "b" {
                guard pc + 4 == success, let target = swiftOutcomeLegacyTarget(ins) else { return fail("error_region_control_flow_unmodeled") }
                if target != success {
                    let allow = compare ? !ne : call["window"].array?.last?["kind"].string == "xcbz"
                    guard let decoded = sharedEpilogue(success: success, join: target, allowArithmetic: allow) else { return fail("error_region_control_flow_unmodeled") }
                    shared = decoded; join = target
                }
                item["target_pc"] = .string(swiftOutcomeHex(join))
            } else if !SwiftOutcomeLegacyKinds.arm.contains(ins.kind) { return fail("error_region_instruction_unmodeled") }
            rows[rows.count - 1] = item; result["instructions"] = .array(rows)
        }
        result = swiftOutcomeLegacyWith(result, shared.object ?? [:])
        return swiftOutcomeLegacyWith(result, ["status": .string("structural_region_candidate"), "start_pc": .string(swiftOutcomeHex(error)), "join_pc": .string(swiftOutcomeHex(join)), "end_pc_exclusive": .string(swiftOutcomeHex(success)), "opaque_call_count": .integer(Int128(calls)), "call_return_proven": .bool(false), "join_reachability_proven": .bool(false)])
    }
    func directEdges() -> SwiftOutcomeJSON {
        guard validSpan else { return .object(["direct_edges": .array([]), "unclassified_word_count": .integer(0), "unclassified_words": .array([]), "scanned_word_count": .integer(0), "caller_scan_complete": .bool(false)]) }
        var direct: [SwiftOutcomeJSON] = [], unknown: [SwiftOutcomeJSON] = [], count = 0
        for (index, word) in words.enumerated() {
            let pc = start + UInt64(index) * 4
            do {
                let ins = try decodeSwiftOutcomeLegacyInstruction(word: word, address: pc)
                if SwiftOutcomeLegacyKinds.branches.contains(ins.kind) || ins.kind == "bl" {
                    guard let target = swiftOutcomeLegacyTarget(ins) else { throw SwiftOutcomeError(code: "direct_target_out_of_range") }
                    direct.append(.object(["source_pc": .string(swiftOutcomeHex(pc)), "target_pc": .string(swiftOutcomeHex(target)), "word": .string(swiftOutcomeLegacyWord(word)), "kind": .string(ins.kind)]))
                }
            } catch {
                count += 1
                if unknown.count < 16 { unknown.append(.object(["pc": .string(swiftOutcomeHex(pc)), "word": .string(swiftOutcomeLegacyWord(word))])) }
            }
        }
        return .object(["direct_edges": .array(direct), "unclassified_word_count": .integer(Int128(count)), "unclassified_words": .array(unknown), "scanned_word_count": .integer(Int128(words.count)), "caller_scan_complete": .bool(endExclusive >= start && UInt64(words.count) * 4 == endExclusive - start)])
    }
    func flagEntries(call: SwiftOutcomeJSON, scan: SwiftOutcomeJSON? = nil) -> SwiftOutcomeJSON {
        let scan = scan ?? directEdges()
        guard validSpan, let callPC = swiftOutcomeLegacyPC(call["call_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), callPC <= UInt64.max - 4, test <= UInt64.max - 4 else { return .object(["status": .string("unresolved")]) }
        let lo = callPC + 4, hi = test + 4
        let entries = (scan["direct_edges"].array ?? []).filter { edge in
            guard let target = swiftOutcomeLegacyPC(edge["target_pc"]) else { return false }; return target >= lo && target < hi
        }
        return swiftOutcomeLegacyWith(swiftOutcomeLegacyLedger(scan: scan, entries: entries, scope: "caller_local_direct_edges_into_postcall_flag_window"), ["protected_start_pc": .string(swiftOutcomeHex(lo)), "protected_end_pc_exclusive": .string(swiftOutcomeHex(hi)), "flag_state_proven": .bool(false)])
    }
    func incoming(region: SwiftOutcomeJSON, call: SwiftOutcomeJSON, scan: SwiftOutcomeJSON? = nil) -> SwiftOutcomeJSON {
        let scan = scan ?? directEdges()
        guard validSpan, let lo = swiftOutcomeLegacyPC(region["start_pc"]), let hi = swiftOutcomeLegacyPC(region["end_pc_exclusive"]), lo < hi else { return .object(["status": .string("unresolved")]) }
        var entries: [SwiftOutcomeJSON] = []
        for edge in scan["direct_edges"].array ?? [] {
            guard let source = swiftOutcomeLegacyPC(edge["source_pc"]), let target = swiftOutcomeLegacyPC(edge["target_pc"]) else { continue }
            var conflict = !(lo..<hi).contains(source) && (lo..<hi).contains(target)
            if region.object?["shared_epilogue"] != nil,
               let join = swiftOutcomeLegacyPC(region["join_pc"]), let tailEnd = swiftOutcomeLegacyPC(region["shared_epilogue"]["end_pc_exclusive"]),
               let success = swiftOutcomeLegacyPC(region["success_interval"]["start_pc"]), let successEnd = swiftOutcomeLegacyPC(region["success_interval"]["end_pc_exclusive"]), success < successEnd, join < tailEnd, hi >= 4, successEnd >= 4 {
                let forward = region["layout"].string == "success_fallthrough_error_forward"
                let compare = call["test_kind"].string == "cmp_zero_bcond"
                var expected = !compare && edge["source_pc"] == call["test_pc"] && edge["kind"].string == (forward ? "xcbnz" : "xcbz") && target == (forward ? lo : success)
                if compare, call["test_condition"].string == (forward ? "ne" : "eq"), edge["source_pc"] == call["test_pc"], target == (forward ? lo : success), edge["kind"].string == "bcond", let recorded = call["window"].array?.last, let word = swiftOutcomeLegacyParseWord(edge["word"]), let ins = try? decodeSwiftOutcomeLegacyInstruction(word: word, address: source) {
                    expected = recorded["pc"] == call["test_pc"] && recorded["word"] == edge["word"] && word & 0xff00001f == (forward ? 0x54000001 : 0x54000000) && swiftOutcomeLegacyTarget(ins) == target
                }
                let exit = source == (forward ? successEnd : hi) - 4 && edge["kind"].string == "b" && target == join
                if expected { conflict = false }
                if ((success..<successEnd).contains(target) || (join..<tailEnd).contains(target)) && !(expected || exit) { conflict = true }
            }
            if conflict { entries.append(edge) }
        }
        return swiftOutcomeLegacyLedger(scan: scan, entries: entries, scope: "caller_local_direct_edges")
    }
    func presentation(call: SwiftOutcomeJSON) -> SwiftOutcomeJSON {
        let result: SwiftOutcomeJSON = .object(["status": .string("unresolved"), "source_reconstruction_allowed": .bool(false), "limitations": .array([
            .string("Structural candidate only; not reconstructed Swift source."), .string("Calls remain opaque; displayed targets do not identify runtime behavior."), .string("Caller-local direct-edge checks do not exclude indirect or external entries."), .string("Reachability, exclusive entry, call return and handler semantics remain unproven.")])])
        func fail(_ reason: String, blocked: Bool = false) -> SwiftOutcomeJSON { swiftOutcomeLegacyWith(result, ["status": .string(blocked ? "blocked" : "unresolved"), "reason": .string(reason)]) }
        guard call["status"].string == "recovered_candidate" else { return fail("edge_not_recovered", blocked: true) }
        let region = call["error_region"], entry = region["incoming_validation"]
        guard region["status"].string == "structural_region_candidate" else { return fail("region_not_recovered", blocked: true) }
        guard entry.object != nil else { return fail("incoming_validation_missing") }
        if entry["status"].string == "unexpected_direct_entries" { return fail("unexpected_direct_entries", blocked: true) }
        guard swiftOutcomeLegacyClearLedger(entry, scope: "caller_local_direct_edges"), region["call_return_proven"] == .bool(false), region["join_reachability_proven"] == .bool(false) else { return fail("incoming_validation_not_complete_or_consistent") }
        guard validSpan, let error = swiftOutcomeLegacyPC(call["error_pc"]), let success = swiftOutcomeLegacyPC(call["success_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), let callPC = swiftOutcomeLegacyPC(call["call_pc"]), let end = swiftOutcomeLegacyPC(region["end_pc_exclusive"]), let join = swiftOutcomeLegacyPC(region["join_pc"]), let rows = region["instructions"].array, test <= UInt64.max - 4, callPC <= UInt64.max - 4 else { return fail("presentation_evidence_inconsistent") }
        let forward = region["layout"].string == "success_fallthrough_error_forward", shared = region.object?["shared_epilogue"] != nil
        let compare = call["test_kind"].string == "cmp_zero_bcond", ne = call["test_condition"].string == "ne"
        guard (forward ? success == test + 4 && success < error && error < end : error == test + 4 && error < end && end == success), error % 4 == 0, end % 4 == 0, region["start_pc"] == call["error_pc"], join == end || shared, swiftOutcomeLegacyRowsMatch(rows, start: error, end: end, limit: 16), let register = call["tested_register"].string, register.first == "x", let n = Int(register.dropFirst()), (0...30).contains(n), register == "x\(n)" else { return fail("presentation_evidence_inconsistent") }
        if compare {
            let flag = call["flag_entry_validation"]
            guard (forward ? ne : call["test_condition"].string == "eq"), test >= 4, call["comparison_pc"] == .string(swiftOutcomeHex(test - 4)), swiftOutcomeLegacyClearLedger(flag, scope: "caller_local_direct_edges_into_postcall_flag_window"), flag["protected_start_pc"] == .string(swiftOutcomeHex(callPC + 4)), flag["protected_end_pc_exclusive"] == .string(swiftOutcomeHex(test + 4)), flag["flag_state_proven"] == .bool(false), let window = call["window"].array, window.count >= 2, let cw = swiftOutcomeLegacyParseWord(window[window.count - 2]["word"]), let bw = swiftOutcomeLegacyParseWord(window[window.count - 1]["word"]), window[window.count - 2]["pc"] == .string(swiftOutcomeHex(test - 4)), window[window.count - 1]["pc"] == call["test_pc"], cw & 0xfffffc1f == 0xf100001f, register == "x\((cw >> 5) & 31)", bw & 0xff00001f == (ne ? 0x54000001 : 0x54000000), let decoded = try? decodeSwiftOutcomeLegacyInstruction(word: bw, address: test), decoded.kind == "bcond", decoded.addressing == (ne ? "1" : "0"), swiftOutcomeLegacyTarget(decoded) == (ne ? error : success) else { return fail("presentation_evidence_inconsistent") }
        }
        if shared {
            let arm = region["success_interval"], tail = region["shared_epilogue"]
            guard let armRows = arm["instructions"].array, let tailRows = tail["instructions"].array, let tailEnd = swiftOutcomeLegacyPC(tail["end_pc_exclusive"]), arm["start_pc"] == call["success_pc"], arm["end_pc_exclusive"] == .string(swiftOutcomeHex(forward ? error : join)), tail["start_pc"] == region["join_pc"], swiftOutcomeLegacyRowsMatch(armRows, start: success, end: forward ? error : join, limit: 8), swiftOutcomeLegacyRowsMatch(tailRows, start: join, end: tailEnd, limit: 8), tailRows.last?["kind"].string == "ret", tail["restore_state_proven"] == .bool(false), (!forward || arm["instructions_complete"] == .bool(true)), (forward ? join == end : join > end), let exit = forward ? armRows.last : rows.last, exit["kind"].string == "b", exit["target_pc"] == region["join_pc"] else { return fail("presentation_evidence_inconsistent") }
            if compare {
                guard let pc = swiftOutcomeLegacyPC(exit["pc"]), let word = swiftOutcomeLegacyParseWord(exit["word"]), let ins = try? decodeSwiftOutcomeLegacyInstruction(word: word, address: pc), ins.kind == "b", swiftOutcomeLegacyTarget(ins) == join else { return fail("presentation_evidence_inconsistent") }
                if !forward {
                    guard sharedEpilogue(success: success, join: join, allowArithmetic: true) == .object(["success_interval": arm, "shared_epilogue": tail]) else { return fail("presentation_evidence_inconsistent") }
                }
            }
        } else if forward { return fail("presentation_evidence_inconsistent") }
        guard let ins = try? instruction(callPC), ins.kind == "bl", row(ins)["word"] == call["call_word"], swiftOutcomeLegacyTarget(ins) == swiftOutcomeLegacyPC(call["callee_pc"]), callPC >= start else { return fail("presentation_call_evidence_inconsistent") }
        let recovered = edges(callOffset: Int(callPC - start))
        guard recovered["status"].string == "recovered_candidate", swiftOutcomeLegacyContains(call, recovered) else { return fail("presentation_call_evidence_inconsistent") }
        let scan = directEdges(), postcall = flagEntries(call: call, scan: directEdges())
        if postcall["status"].string != "no_unexpected_direct_entries" {
            return swiftOutcomeLegacyWith(fail(postcall["status"].string == "unexpected_direct_entries" ? "unexpected_postcall_entries" : "postcall_entries_unresolved", blocked: postcall["status"].string == "unexpected_direct_entries"), ["postcall_entry_validation": swiftOutcomeLegacyWith(postcall, ["scope": .string("caller_local_direct_edges_into_postcall_window")])])
        }
        guard incoming(region: region, call: call, scan: scan) == entry, self.region(call: call) == swiftOutcomeLegacyWithout(region, ["incoming_validation"]), !compare || postcall == call["flag_entry_validation"] else { return fail("presentation_current_evidence_inconsistent") }
        var condition: SwiftOutcomeJSON = .object(["test_pc": call["test_pc"], "register": call["tested_register"], "error_when": .string("nonzero")])
        if compare { for key in ["comparison_pc", "test_kind", "test_condition"] { condition[key] = call[key] } }
        var plan: SwiftOutcomeJSON = .object(["kind": .string("structural_error_interval"), "label": .string("Structural error-path candidate"), "condition": condition, "error_interval": .object(["start_pc": region["start_pc"], "end_pc_exclusive": region["end_pc_exclusive"], "instructions": .array(rows)]), "success_entry_pc": call["success_pc"]])
        if shared { plan["shared_epilogue"] = region["shared_epilogue"]; plan["success_interval"] = region["success_interval"] }
        return swiftOutcomeLegacyWith(result, ["status": .string("eligible_structural_only"), "reason": .string("complete_caller_local_direct_validation"), "display_plan": plan])
    }
    func successResult(call: SwiftOutcomeJSON, scan: SwiftOutcomeJSON? = nil) -> SwiftOutcomeJSON {
        let result = swiftOutcomeLegacyOutcomeBase(error: false)
        var evidence: [SwiftOutcomeJSON] = []
        func fail(_ reason: String, include: Bool = true) -> SwiftOutcomeJSON { swiftOutcomeLegacyWith(result, include ? ["reason": .string(reason), "instructions": .array(evidence)] : ["reason": .string(reason)]) }
        let compare = call["test_kind"].string == "cmp_zero_bcond", ne = compare && call["test_condition"].string == "ne"
        let region = call["error_region"], shared = region.object?["shared_epilogue"] != nil
        let fresh = directEdges()
        if ne && (flagEntries(call: call, scan: fresh) != call["flag_entry_validation"] || incoming(region: region, call: call, scan: fresh) != region["incoming_validation"] || presentation(call: call)["status"].string != "eligible_structural_only") { return fail("compare_ne_success_evidence_inconsistent", include: false) }
        guard call["callee"]["result"].string == "Swift.Int" else { return fail("callee_result_not_scalar_int", include: false) }
        guard call["presentation"]["status"].string == "eligible_structural_only" else { return fail("structural_presentation_not_eligible", include: false) }
        guard validSpan, let callPC = swiftOutcomeLegacyPC(call["call_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), let join = swiftOutcomeLegacyPC(region["join_pc"]), let success = swiftOutcomeLegacyPC(call["success_pc"]), callPC <= UInt64.max - 4, test <= UInt64.max - 4, test >= callPC + 4, test - (callPC + 4) < 32 else { return fail("bounded_result_evidence_unavailable") }
        var aliases: Set<Int> = [0], copied = false
        var adjustment: SwiftOutcomeInstruction?
        func transfer(_ ins: SwiftOutcomeInstruction) {
            guard ins.rd != 31 else { return }
            if ins.kind == "mov" && aliases.contains(ins.rn) { if ins.rd == 0 && ins.rn != 0 { copied = true }; aliases.insert(ins.rd) }
            else { aliases.remove(ins.rd) }
        }
        for pc in stride(from: callPC + 4, through: test, by: 4) {
            guard let ins = try? instruction(pc) else { return fail("bounded_result_evidence_unavailable") }
            evidence.append(swiftOutcomeLegacyWith(row(ins), ["phase": .string("post_call")]))
            if pc == test {
                if compare {
                    guard ["eq", "ne"].contains(call["test_condition"].string ?? ""), ins.kind == "bcond", ins.addressing == (ne ? "1" : "0"), call["tested_register"].string != "x0", swiftOutcomeLegacyTarget(ins) == swiftOutcomeLegacyPC(call[ne ? "error_pc" : "success_pc"]) else { return fail("unsupported_result_test") }
                } else if !["xcbz", "xcbnz"].contains(ins.kind) || ins.rn == 0 { return fail("unsupported_result_test") }
            } else if compare && pc == test - 4 {
                guard call["comparison_pc"] == .string(swiftOutcomeHex(pc)), ins.word & 0xfffffc1f == 0xf100001f, call["tested_register"] == .string("x\(ins.rn)") else { return fail("unsupported_result_comparison") }
            } else if ins.kind == "nop" { continue }
            else if ins.kind == "mov" { transfer(ins); if aliases.isEmpty { return fail("post_call_result_not_preserved") } }
            else { return fail("post_call_result_not_preserved") }
        }
        let interval = shared ? region["success_interval"] : .object(["start_pc": call["success_pc"], "end_pc_exclusive": call["success_pc"]])
        guard let lo = swiftOutcomeLegacyPC(interval["start_pc"]), let hi = swiftOutcomeLegacyPC(interval["end_pc_exclusive"]), hi >= lo, hi - lo <= 32, !shared || hi > lo, shared || join == lo else { return fail("bounded_result_evidence_unavailable") }
        let forward = region["layout"].string == "success_fallthrough_error_forward"
        let arithmetic = shared && (interval["instructions"].array ?? []).contains { ["add", "sub"].contains($0["kind"].string ?? "") }
        let binding = arithmetic ? "arithmetic" : "result"
        guard let scan else { return fail(arithmetic ? "success_add_layout_not_qualified" : "success_result_evidence_inconsistent") }
        if arithmetic {
            guard compare ? ["eq", "ne"].contains(call["test_condition"].string ?? "") : ["xcbz", "xcbnz"].contains(call["window"].array?.last?["kind"].string ?? "") else { return fail("success_add_layout_not_qualified") }
            let decoded: SwiftOutcomeJSON? = forward ? forwardRegion(call: call) : sharedEpilogue(success: lo, join: join, allowArithmetic: true)
            guard fresh == scan, incoming(region: region, call: call, scan: fresh) == region["incoming_validation"], decoded?["success_interval"] == interval, decoded?["shared_epilogue"] == region["shared_epilogue"] else { return fail("success_add_evidence_inconsistent") }
        } else if fresh != scan || incoming(region: region, call: call, scan: fresh) != region["incoming_validation"] { return fail("success_result_evidence_inconsistent") }
        if compare && flagEntries(call: call, scan: fresh) != call["flag_entry_validation"] { return fail("compare_success_\(binding)_evidence_inconsistent") }
        guard self.region(call: call) == swiftOutcomeLegacyWithout(region, ["incoming_validation"]), presentation(call: call) == call["presentation"] else { return fail("success_\(binding)_evidence_inconsistent") }
        guard callBinding(call), flagEntries(call: call, scan: fresh)["status"].string == "no_unexpected_direct_entries" else { return fail("success_\(binding)_postcall_evidence_inconsistent") }
        if arithmetic {
            guard let window = call["window"].array, window.count == Int((test - callPC) / 4), window.enumerated().allSatisfy({ index, item in
                guard let ins = try? instruction(callPC + UInt64(index + 1) * 4) else { return false }; return item == row(ins, kind: true)
            }), let ins = try? instruction(test), (compare ? ins.kind == "bcond" && ins.addressing == (ne ? "1" : "0") : ins.kind == (forward ? "xcbnz" : "xcbz") && call["tested_register"] == .string("x\(ins.rn)")), swiftOutcomeLegacyTarget(ins) == swiftOutcomeLegacyPC(call[forward ? "error_pc" : "success_pc"]), (forward ? lo == test + 4 : swiftOutcomeLegacyPC(call["error_pc"]) == test + 4) else { return fail("success_add_evidence_inconsistent") }
        }
        for pc in stride(from: lo, to: hi, by: 4) {
            guard let ins = try? instruction(pc) else { return fail("bounded_result_evidence_unavailable") }
            evidence.append(swiftOutcomeLegacyWith(row(ins), ["phase": .string("success")]))
            if arithmetic && ["add", "sub"].contains(ins.kind) {
                guard aliases.contains(ins.rn), adjustment == nil else { return fail("success_result_not_preserved") }
                adjustment = ins; aliases = [ins.rd]; continue
            }
            if ins.kind == "nop" { continue }
            if SwiftOutcomeLegacyKinds.arm.contains(ins.kind) { transfer(ins); if aliases.isEmpty { return fail("success_result_not_preserved") }; continue }
            if ins.kind == "b", pc == hi - 4, swiftOutcomeLegacyTarget(ins) == join { continue }
            return fail("success_result_not_preserved")
        }
        guard aliases.contains(0) else { return fail("result_not_restored_to_x0") }
        guard let tail = sharedReturnTail(join: join), !shared || tail == region["shared_epilogue"], let tailRows = tail["instructions"].array else { return fail("bounded_return_tail_missing") }
        evidence += tailRows.map { swiftOutcomeLegacyWith($0, ["phase": .string("return_tail")]) }
        if !shared {
            guard scan["caller_scan_complete"] == .bool(true), scan["unclassified_word_count"] == .integer(0), let tailEnd = swiftOutcomeLegacyPC(tail["end_pc_exclusive"]), let regionEnd = swiftOutcomeLegacyPC(region["end_pc_exclusive"]) else { return fail("return_tail_entries_unresolved") }
            let conflicts = (scan["direct_edges"].array ?? []).filter { edge in
                guard let src = swiftOutcomeLegacyPC(edge["source_pc"]), let dst = swiftOutcomeLegacyPC(edge["target_pc"]) else { return true }
                let expected = src == test && dst == join && edge["kind"].string == (compare ? "bcond" : "xcbz")
                let exit = src == regionEnd - 4 && edge["kind"].string == "b" && dst == join
                return (join..<tailEnd).contains(dst) && !(expected || exit)
            }
            if !conflicts.isEmpty { return swiftOutcomeLegacyWith(fail("unexpected_return_tail_entry"), ["unexpected_tail_entry_count": .integer(Int128(conflicts.count)), "tail_entry_details_complete": .bool(conflicts.count <= 16), "unexpected_tail_entries": .array(Array(conflicts.prefix(16)))]) }
        }
        var output = swiftOutcomeLegacyWith(result, ["status": .string(adjustment != nil ? "adjusted_register_candidate" : copied ? "copied_register_candidate" : "preserved_register_candidate"), "reason": .string(adjustment.map { "recorded_success_path_\($0.kind)s_immediate" } ?? (copied ? "recorded_success_path_restores_x0_copy" : "recorded_success_path_preserves_x0")), "result_registers_before_tail": .array(aliases.sorted().map { .string("x\($0)") }), "return_tail_layout": .string(shared ? "shared_epilogue" : "success_entry"), "call_pc": call["call_pc"], "success_pc": .string(swiftOutcomeHex(success)), "return_pc": tailRows.last?["pc"] ?? .null, "instructions": .array(evidence)])
        if let adjustment { output = swiftOutcomeLegacyWith(output, ["operation": .string(adjustment.kind + "_immediate_modulo"), "immediate": .integer(adjustment.immediate), "bit_width": .integer(64), "adjustment_register": .integer(Int128(adjustment.rd)), "adjustment_source_register": .integer(Int128(adjustment.rn)), "immediate_shift": .integer(adjustment.word & (1 << 22) == 0 ? 0 : 12)]) }
        return output
    }
    func callBinding(_ call: SwiftOutcomeJSON) -> Bool {
        guard let pc = swiftOutcomeLegacyPC(call["call_pc"]), pc >= start, let ins = try? instruction(pc), ins.kind == "bl", row(ins)["word"] == call["call_word"], swiftOutcomeLegacyTarget(ins) == swiftOutcomeLegacyPC(call["callee_pc"]) else { return false }
        let recovered = edges(callOffset: Int(pc - start))
        return recovered["status"].string == "recovered_candidate" && swiftOutcomeLegacyContains(call, recovered)
    }
    func pathConstant(call: SwiftOutcomeJSON, error: Bool = false, scan: SwiftOutcomeJSON? = nil) -> SwiftOutcomeJSON {
        let path = error ? "error" : "success", result = swiftOutcomeLegacyOutcomeBase(error: error)
        var evidence: [SwiftOutcomeJSON] = []
        func fail(_ reason: String, include: Bool = true) -> SwiftOutcomeJSON { swiftOutcomeLegacyWith(result, include ? ["reason": .string(reason), "instructions": .array(evidence)] : ["reason": .string(reason)]) }
        let compare = call["test_kind"].string == "cmp_zero_bcond", ne = compare && call["test_condition"].string == "ne", cmpSuccess = compare && !error
        let region = call["error_region"], shared = region.object?["shared_epilogue"] != nil, fresh = directEdges()
        if ne {
            if !error {
                guard let first = swiftOutcomeLegacyPC(call["call_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), test > first, let window = call["window"].array, window.count == Int((test - first) / 4), window.enumerated().allSatisfy({ index, item in
                    guard let ins = try? instruction(first + UInt64(index + 1) * 4) else { return false }; return item == row(ins, kind: true)
                }) else { return fail("compare_ne_success_evidence_inconsistent", include: false) }
            }
            guard flagEntries(call: call, scan: fresh) == call["flag_entry_validation"], incoming(region: region, call: call, scan: fresh) == region["incoming_validation"], presentation(call: call)["status"].string == "eligible_structural_only" else { return fail("compare_ne_\(path)_evidence_inconsistent", include: false) }
        }
        guard ["Swift.Int", "Swift.Void"].contains(call["callee"]["result"].string ?? "") else { return fail("callee_result_outside_admitted_subset", include: false) }
        guard call["presentation"]["status"].string == "eligible_structural_only" else { return fail("structural_presentation_not_eligible", include: false) }
        if !shared && !error && !cmpSuccess { return fail("bounded_\(path)_interval_missing", include: false) }
        var successResult = call["success_result"]
        if !shared && !cmpSuccess {
            if compare && !["preserved_register_candidate", "copied_register_candidate"].contains(successResult["status"].string ?? "") { successResult = call["success_constant"] }
            guard ["preserved_register_candidate", "copied_register_candidate"].contains(successResult["status"].string ?? "") || compare && successResult["status"].string == "constant_register_candidate", successResult["return_tail_layout"].string == "success_entry" else { return fail("validated_success_return_tail_missing", include: false) }
        }
        guard validSpan, let callPC = swiftOutcomeLegacyPC(call["call_pc"]), let test = swiftOutcomeLegacyPC(call["test_pc"]), let join = swiftOutcomeLegacyPC(region["join_pc"]), callPC <= UInt64.max - 4, test >= 4, test <= UInt64.max - 4 else { return fail("bounded_constant_evidence_unavailable") }
        let interval: SwiftOutcomeJSON = cmpSuccess ? .object(["start_pc": .string(swiftOutcomeHex(callPC + 4)), "end_pc_exclusive": .string(swiftOutcomeHex(test + 4))]) : error ? region : region["success_interval"]
        guard let lo = swiftOutcomeLegacyPC(interval["start_pc"]), let hi = swiftOutcomeLegacyPC(interval["end_pc_exclusive"]), hi > lo, hi - lo <= (error ? 64 : 32), (hi - lo) % 4 == 0 else { return fail("bounded_constant_evidence_unavailable") }
        if cmpSuccess && !shared && region["join_pc"] != call["success_pc"] { return fail("success_entry_binding_inconsistent") }
        var intervals: [(UInt64, UInt64, String)] = [(lo, hi, cmpSuccess ? "post_call" : path)]
        var armEnd: UInt64 = 0
        if cmpSuccess && shared {
            let arm = region["success_interval"]
            guard let a = swiftOutcomeLegacyPC(arm["start_pc"]), let b = swiftOutcomeLegacyPC(arm["end_pc_exclusive"]), a == swiftOutcomeLegacyPC(call["success_pc"]), b == (ne ? swiftOutcomeLegacyPC(call["error_pc"]) : join), b > a, b - a <= 32 else { return fail("bounded_constant_evidence_unavailable") }
            armEnd = b
            if !ne {
                guard let decoded = sharedEpilogue(success: a, join: b), decoded["success_interval"]["instructions"] == arm["instructions"], decoded["shared_epilogue"] == region["shared_epilogue"] else { return fail("shared_success_evidence_inconsistent") }
            }
            intervals.append((a, b, "success"))
        }
        var constants: [Int: UInt64] = [:], opaque = 0
        for (lower, upper, phase) in intervals {
            for pc in stride(from: lower, to: upper, by: 4) {
                guard let ins = try? instruction(pc) else { return fail("bounded_constant_evidence_unavailable") }
                evidence.append(swiftOutcomeLegacyWith(row(ins), ["phase": .string(phase)]))
                if cmpSuccess && phase == "post_call" && pc == test - 4 {
                    guard call["comparison_pc"] == .string(swiftOutcomeHex(pc)), ins.word & 0xfffffc1f == 0xf100001f, call["tested_register"] == .string("x\(ins.rn)") else { return fail("unsupported_success_comparison") }; continue
                }
                if cmpSuccess && phase == "post_call" && pc == test {
                    guard ["eq", "ne"].contains(call["test_condition"].string ?? ""), ins.kind == "bcond", ins.addressing == (ne ? "1" : "0"), swiftOutcomeLegacyTarget(ins) == swiftOutcomeLegacyPC(call[ne ? "error_pc" : "success_pc"]) else { return fail("unsupported_success_test") }; continue
                }
                if ne && cmpSuccess && phase == "success" && pc == armEnd - 4 && ins.kind == "b" && swiftOutcomeLegacyTarget(ins) == join { continue }
                if cmpSuccess && !SwiftOutcomeLegacyKinds.arm.contains(ins.kind) { return fail("success_constant_instruction_unsupported") }
                if ins.kind == "nop" { continue }
                if ins.kind == "b", pc == hi - 4, swiftOutcomeLegacyTarget(ins) == join { continue }
                if error && ins.kind == "bl" { constants.removeAll(); opaque += 1; evidence[evidence.count - 1]["constant_state"] = .string("cleared_after_opaque_call"); continue }
                guard SwiftOutcomeLegacyKinds.arm.contains(ins.kind) else { return fail("\(path)_constant_instruction_unsupported") }
                swiftOutcomeLegacyTransferConstant(ins, constants: &constants)
            }
        }
        guard let tail = sharedReturnTail(join: join), !shared || tail == region["shared_epilogue"], let tailRows = tail["instructions"].array else { return fail("bounded_return_tail_missing") }
        if cmpSuccess {
            evidence += tailRows.map { swiftOutcomeLegacyWith($0, ["phase": .string("return_tail")]) }
            guard let scan, scan["caller_scan_complete"] == .bool(true), scan["unclassified_word_count"] == .integer(0), let tailEnd = swiftOutcomeLegacyPC(tail["end_pc_exclusive"]), let exitEnd = swiftOutcomeLegacyPC(ne ? region["success_interval"]["end_pc_exclusive"] : region["end_pc_exclusive"]) else { return fail("return_tail_entries_unresolved") }
            let conflicts = (scan["direct_edges"].array ?? []).filter { edge in
                guard let src = swiftOutcomeLegacyPC(edge["source_pc"]), let dst = swiftOutcomeLegacyPC(edge["target_pc"]) else { return true }
                let expected = src == test && edge["kind"].string == "bcond" && dst == join
                // Match donor signed-integer comparison even when exitEnd < 4.
                let exit = Int128(src) == Int128(exitEnd) - 4 && edge["kind"].string == "b" && dst == join
                return (join..<tailEnd).contains(dst) && !(expected || exit)
            }
            if !conflicts.isEmpty { return swiftOutcomeLegacyWith(fail("unexpected_return_tail_entry"), ["unexpected_tail_entries": .array(Array(conflicts.prefix(16))), "unexpected_tail_entry_count": .integer(Int128(conflicts.count)), "tail_entry_details_complete": .bool(conflicts.count <= 16)]) }
        } else if !shared {
            let captured = (successResult["instructions"].array ?? []).filter { $0["phase"].string == "return_tail" }.map { swiftOutcomeLegacyWithout($0, ["phase"]) }
            guard successResult["register"].string == "x0", successResult["call_pc"] == call["call_pc"], successResult["success_pc"] == call["success_pc"], region["join_pc"] == call["success_pc"], successResult["return_pc"] == tailRows.last?["pc"], captured == tailRows, swiftOutcomeLegacyFalseProofs(successResult, keys: SwiftOutcomeLegacyKinds.valueProofs) else { return fail("validated_success_return_tail_inconsistent") }
        }
        if !cmpSuccess { evidence += tailRows.map { swiftOutcomeLegacyWith($0, ["phase": .string("return_tail")]) } }
        guard let constant = constants[0] else { return fail("\(path)_x0_constant_not_known") }
        guard let scan, fresh == scan, incoming(region: region, call: call, scan: fresh) == region["incoming_validation"], self.region(call: call) == swiftOutcomeLegacyWithout(region, ["incoming_validation"]), presentation(call: call) == call["presentation"], !compare || flagEntries(call: call, scan: fresh) == call["flag_entry_validation"] else { return fail("\(path)_constant_evidence_inconsistent") }
        guard callBinding(call), flagEntries(call: call, scan: fresh)["status"].string == "no_unexpected_direct_entries" else { return fail("\(path)_constant_postcall_evidence_inconsistent") }
        var output = swiftOutcomeLegacyWith(result, ["status": .string("constant_register_candidate"), "reason": .string("recorded_\(path)_path_assigns_constant"), "constant_bits": .string(swiftOutcomeLegacyBits(constant)), "bit_width": .integer(64), "depends_on_call_result": .bool(false), "call_pc": call["call_pc"], path + "_pc": call[path + "_pc"], "return_pc": tailRows.last?["pc"] ?? .null, "instructions": .array(evidence)])
        if cmpSuccess { output["return_tail_layout"] = .string(shared ? "shared_epilogue" : "success_entry") }
        if error { output["opaque_call_count"] = .integer(Int128(opaque)) }
        return output
    }
    func recoverCall(callOffset: Int = 0, callee: SwiftOutcomeJSON, callWord: UInt32? = nil) -> SwiftOutcomeJSON {
        guard validSpan, callOffset >= 0, callOffset % 4 == 0, callOffset / 4 < words.count else { return .object(["status": .string("declined"), "reason": .string("legacy_caller_span")]) }
        let pc = start + UInt64(callOffset)
        guard let ins = try? instruction(pc), ins.kind == "bl", let target = swiftOutcomeLegacyTarget(ins) else { return .object(["status": .string("declined"), "reason": .string("callee_target_out_of_range")]) }
        var call: SwiftOutcomeJSON = .object(["call_pc": .string(swiftOutcomeHex(pc)), "call_word": .string(swiftOutcomeLegacyWord(callWord ?? ins.word)), "caller_pc": .string(swiftOutcomeHex(start)), "callee_pc": .string(swiftOutcomeHex(target)), "status": .string("declined")])
        if callee.object != nil {
            call["callee"] = callee; call = swiftOutcomeLegacyWith(call, edges(callOffset: callOffset).object ?? [:])
        } else { call["reason"] = .string("callee_declaration_outside_subset") }
        let scan = directEdges()
        if call["test_kind"].string == "cmp_zero_bcond" { call["flag_entry_validation"] = flagEntries(call: call, scan: scan) }
        if call["status"].string == "recovered_candidate" {
            var region = self.region(call: call)
            if region["status"].string == "structural_region_candidate" { region["incoming_validation"] = incoming(region: region, call: call, scan: scan) }
            call["error_region"] = region
        }
        call["presentation"] = presentation(call: call)
        call["success_result"] = successResult(call: call, scan: scan)
        call["success_constant"] = pathConstant(call: call, scan: scan)
        call["error_constant"] = pathConstant(call: call, error: true, scan: scan)
        call["return_choice"] = swiftOutcomeLegacyReturnChoice(call)
        return call
    }
}

// Shared typed JSON operations. Missing fields stay distinct from explicit
// booleans/integers in all proof and count checks; no NSNumber coercion.
enum SwiftOutcomeLegacyKinds {
    static let literals: Set<String> = ["movz", "movn", "xmovk", "wmovz", "wmovn", "wmovk", "wmov"]
    static let arm: Set<String> = literals.union(["nop", "mov"])
    static let branches: Set<String> = ["b", "bcond", "wcbz", "wcbnz", "xcbz", "xcbnz", "wtbz", "wtbnz", "xtbz", "xtbnz"]
    static let valueProofs = ["runtime_value_proven", "source_reconstruction_allowed", "exclusive_path_proven", "caller_return_type_proven"]
}
func swiftOutcomeLegacyWord(_ word: UInt32) -> String { "0x" + String(repeating: "0", count: 8 - String(word, radix: 16).count) + String(word, radix: 16) }
func swiftOutcomeLegacyBits(_ bits: UInt64) -> String { "0x" + String(repeating: "0", count: 16 - String(bits, radix: 16).count) + String(bits, radix: 16) }
func swiftOutcomeLegacyPC(_ value: SwiftOutcomeJSON) -> UInt64? {
    guard let text = value.string, text.hasPrefix("0x"), (3...18).contains(text.count), text.dropFirst(2).allSatisfy({ "0123456789abcdef".contains($0) }), let pc = UInt64(text.dropFirst(2), radix: 16), text == swiftOutcomeHex(pc) else { return nil }; return pc
}
func swiftOutcomeLegacyParseWord(_ value: SwiftOutcomeJSON) -> UInt32? {
    guard let text = value.string, text.count == 10, text.hasPrefix("0x"), text.dropFirst(2).allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }; return UInt32(text.dropFirst(2), radix: 16)
}
func swiftOutcomeLegacyTarget(_ ins: SwiftOutcomeInstruction) -> UInt64? {
    let target = Int128(ins.address) + ins.immediate
    return target >= 0 && target <= Int128(UInt64.max) ? UInt64(target) : nil
}
func swiftOutcomeLegacyWith(_ value: SwiftOutcomeJSON, _ fields: [String: SwiftOutcomeJSON]) -> SwiftOutcomeJSON { .object((value.object ?? [:]).merging(fields, uniquingKeysWith: { _, b in b })) }
func swiftOutcomeLegacyWithout(_ value: SwiftOutcomeJSON, _ keys: Set<String>) -> SwiftOutcomeJSON { .object((value.object ?? [:]).filter { !keys.contains($0.key) }) }
func swiftOutcomeLegacyContains(_ value: SwiftOutcomeJSON, _ fields: SwiftOutcomeJSON) -> Bool { guard let fields = fields.object else { return false }; return fields.allSatisfy { value.object?[$0.key] == $0.value } }
func swiftOutcomeLegacyFalseProofs(_ value: SwiftOutcomeJSON, keys: [String]) -> Bool { keys.allSatisfy { value[$0] == .bool(false) } }
func swiftOutcomeLegacyClearLedger(_ ledger: SwiftOutcomeJSON, scope: String) -> Bool {
    ledger["status"].string == "no_unexpected_direct_entries" && ledger["scope"].string == scope && ["caller_scan_complete", "entry_details_complete", "unclassified_details_complete"].allSatisfy { ledger[$0] == .bool(true) } && ["unexpected_entry_count", "unclassified_word_count"].allSatisfy { ledger[$0] == .integer(0) } && ledger["exclusive_entry_proven"] == .bool(false)
}
func swiftOutcomeLegacyLedger(scan: SwiftOutcomeJSON, entries: [SwiftOutcomeJSON], scope: String) -> SwiftOutcomeJSON {
    let unknown = scan["unclassified_words"].array ?? []
    let status = !entries.isEmpty ? "unexpected_direct_entries" : scan["caller_scan_complete"] != .bool(true) || scan["unclassified_word_count"] != .integer(0) ? "unresolved" : "no_unexpected_direct_entries"
    return .object(["status": .string(status), "scope": .string(scope), "caller_scan_complete": scan["caller_scan_complete"], "scanned_word_count": scan["scanned_word_count"], "unclassified_word_count": scan["unclassified_word_count"], "unclassified_words": .array(unknown), "unclassified_details_complete": .bool(scan["unclassified_word_count"] == .integer(Int128(unknown.count))), "unexpected_entry_count": .integer(Int128(entries.count)), "unexpected_entries": .array(Array(entries.prefix(16))), "entry_details_complete": .bool(entries.count <= 16), "exclusive_entry_proven": .bool(false)])
}
func swiftOutcomeLegacyRowsMatch(_ rows: [SwiftOutcomeJSON], start: UInt64, end: UInt64, limit: Int) -> Bool {
    end > start && rows.count > 0 && rows.count <= limit && end - start == UInt64(rows.count) * 4 && rows.enumerated().allSatisfy { index, row in row["pc"] == .string(swiftOutcomeHex(start + UInt64(index) * 4)) && swiftOutcomeLegacyParseWord(row["word"]) != nil }
}
func swiftOutcomeLegacyIsArithmetic(_ ins: SwiftOutcomeInstruction) -> Bool { ["add", "sub"].contains(ins.kind) && ins.word & 0xff800000 == (ins.kind == "add" ? 0x91000000 : 0xd1000000) && ins.rd != 31 && ins.rn != 31 && (ins.word >> 10) & 4095 != 0 }
func swiftOutcomeLegacyOutcomeBase(error: Bool) -> SwiftOutcomeJSON {
    var value: SwiftOutcomeJSON = .object(["status": .string("declined"), "register": .string("x0")])
    for key in SwiftOutcomeLegacyKinds.valueProofs { value[key] = .bool(false) }
    if error { value["call_return_proven"] = .bool(false); value["handler_semantics_proven"] = .bool(false) }; return value
}
func swiftOutcomeLegacyTransferConstant(_ ins: SwiftOutcomeInstruction, constants: inout [Int: UInt64]) {
    guard ins.rd != 31 else { return }
    switch ins.kind {
    case "movz", "movn", "wmovz", "wmovn":
        let value = UInt64(truncatingIfNeeded: ins.immediate), mask = ins.kind.hasPrefix("w") ? UInt64(UInt32.max) : UInt64.max
        constants[ins.rd] = (ins.kind.hasSuffix("movz") ? value : ~value) & mask
    case "xmovk", "wmovk":
        if let old = constants[ins.rd], let shift = Int(ins.addressing), (0...48).contains(shift) {
            let mask: UInt64 = 0xffff << shift
            constants[ins.rd] = ((old & ~mask) | UInt64(truncatingIfNeeded: ins.immediate) << shift) & (ins.kind == "wmovk" ? UInt64(UInt32.max) : UInt64.max)
        }
    case "mov", "wmov":
        if ins.rn == 31 { constants[ins.rd] = 0 }
        else if let old = constants[ins.rn] { constants[ins.rd] = ins.kind == "wmov" ? old & UInt64(UInt32.max) : old }
        else { constants.removeValue(forKey: ins.rd) }
    default: break
    }
}
