import Foundation

func swiftOutcomeIsErrorTransportInstruction(_ word: UInt32) -> Bool {
    word & 0xffe0ffff == 0xaa0003f5 && ![21, 31].contains((word >> 16) & 31)
}
func swiftOutcomeIsDirectResultStore(_ word: UInt32) -> Bool {
    guard (word >> 5) & 31 == 8 else { return false }
    let vector = word & 0x04000000 != 0, size = (word >> 30) & 3
    if word & 0x3b000000 == 0x39000000 {
        let opc = (word >> 22) & 3
        return opc == 0 || (vector && opc == 2 && size == 0)
    }
    if word & 0x3b000000 == 0x29000000 && word & 0x00400000 == 0 && (word >> 23) & 3 == 2 {
        return (vector ? [0, 1, 2] : [0, 2]).contains(size)
    }
    return false
}
func swiftOutcomePrefixEncodingAllocated(_ word: UInt32) -> Bool {
    let wide = word & 0x80000000 != 0
    if word & 0x1f000000 == 0x11000000 { return word & 0x00800000 == 0 }
    if word & 0x1f000000 == 0x0b000000 {
        if word & 0x00200000 != 0 {
            return (word >> 22) & 3 == 0 && (word >> 10) & 7 <= 4 && (wide || ![3, 7].contains((word >> 13) & 7))
        }
        return (word >> 22) & 3 != 3 && (wide || (word >> 10) & 63 < 32)
    }
    if word & 0x1f000000 == 0x0a000000 { return wide || (word >> 10) & 63 < 32 }
    if word & 0x1f800000 == 0x12000000 {
        let n = (word >> 22) & 1, imms = (word >> 10) & 63
        let encoded = (n << 6) | (~imms & 63)
        let length = 31 - encoded.leadingZeroBitCount
        if (!wide && n != 0) || length < 1 { return false }
        let levels = (UInt32(1) << length) - 1
        return (UInt32(1) << length) <= (wide ? 64 : 32) && imms & levels != levels
    }
    if word & 0x1f800000 == 0x13000000 {
        return (word >> 29) & 3 != 3 && (word >> 22) & 1 == (wide ? 1 : 0) && (wide || ((word >> 16) & 63 < 32 && (word >> 10) & 63 < 32))
    }
    if word & 0x1f800000 == 0x12800000 { return (word >> 29) & 3 != 1 && (wide || (word >> 21) & 3 < 2) }
    if word & 0x1f000000 == 0x10000000 { return true }
    let size = (word >> 30) & 3, vector = word & 0x04000000 != 0, opc = (word >> 22) & 3
    if word & 0x3a000000 == 0x28000000 { return (vector ? [0, 1, 2] : [0, 2]).contains(size) }
    if word & 0x3a000000 == 0x38000000 {
        if vector { if [2, 3].contains(opc) && size != 0 { return false } }
        else if opc == 3 && size >= 2 { return false }
        if word & 0x3b000000 == 0x39000000 { return true }
        if word & 0x3b000000 != 0x38000000 { return false }
        let mode = (word >> 10) & 3
        if word & 0x00200000 != 0 { return mode == 2 && [2, 3, 6, 7].contains((word >> 13) & 7) }
        if vector && mode == 2 { return false }
        if !vector && size == 3 && opc == 2 && mode != 0 { return false }
        return true
    }
    return word == 0xd503201f
}
func swiftOutcomePrefixOperandEffects(_ word: UInt32) -> (reads: Set<Int>, writes: Set<Int>, control: Bool, known: Bool) {
    let rd = Int(word & 31), rn = Int((word >> 5) & 31), rm = Int((word >> 16) & 31)
    if word & 0x7c000000 == 0x14000000 || word & 0xff000000 == 0x54000000 || [0x34000000, 0x36000000].contains(word & 0x7e000000) || word & 0xfe000000 == 0xd6000000 { return ([], [], true, true) }
    guard swiftOutcomePrefixEncodingAllocated(word) else { return ([], [], false, false) }
    var reads: Set<Int> = [], writes: Set<Int> = [], known = true
    if word & 0x1f000000 == 0x11000000 { reads.insert(rn); writes.insert(rd) }
    else if [0x0a000000, 0x0b000000].contains(word & 0x1f000000) { reads.formUnion([rn, rm]); writes.insert(rd) }
    else if [0x12000000, 0x13000000].contains(word & 0x1f800000) { reads.insert(rn); writes.insert(rd) }
    else if word & 0x1f800000 == 0x12800000 || word & 0x1f000000 == 0x10000000 { writes.insert(rd) }
    else if word & 0x3a000000 == 0x28000000 {
        reads.insert(rn)
        if word & 0x04000000 == 0 {
            if word & 0x00400000 != 0 { writes.formUnion([rd, Int((word >> 10) & 31)]) }
            else { reads.formUnion([rd, Int((word >> 10) & 31)]) }
        }
        if [1, 3].contains((word >> 23) & 3) { writes.insert(rn); if rn != 31 { known = false } }
    } else if word & 0x3a000000 == 0x38000000 {
        reads.insert(rn)
        if word & 0x04000000 == 0 {
            if (word >> 22) & 3 == 0 { reads.insert(rd) }
            else if !((word >> 22) & 3 == 2 && (word >> 30) & 3 == 3) { writes.insert(rd) }
        }
        if word & 0x3b200c00 == 0x38200800 { reads.insert(rm) }
        if word & 0x01000000 == 0 && word & 0x00200000 == 0 && [1, 3].contains((word >> 10) & 3) { writes.insert(rn); if rn != 31 { known = false } }
    } else if word != 0xd503201f { known = false }
    reads.remove(31); writes.remove(31)
    return (reads, writes, false, known)
}
func swiftOutcomeFormalPrefixInputs(_ words: [UInt32], locations: [String], charge: (Int) throws -> Void = { _ in }) throws -> Bool {
    var wanted: Set<Int> = []
    for location in locations {
        let raw = location.hasPrefix("indirect ") ? String(location.dropFirst(9)) : location
        if raw.range(of: "^[xw]([0-9]|[12][0-9]|30)$", options: .regularExpression) != nil, let r = Int(raw.dropFirst()) { wanted.insert(r) }
    }
    var live = wanted, observed: Set<Int> = []
    for word in words {
        try charge(1)
        let effects = swiftOutcomePrefixOperandEffects(word)
        if effects.control || !effects.known { break }
        observed.formUnion(effects.reads.intersection(live)); live.subtract(effects.writes)
        if wanted.isSubset(of: observed) { return true }
    }
    return wanted.isSubset(of: observed)
}
func swiftOutcomeAllocatedResultGPRWrite(_ word: UInt32, register: Int) -> Bool {
    guard Int(word & 31) == register else { return false }
    if [0x11000000, 0x0b000000, 0x0a000000].contains(word & 0x1f000000) || [0x12000000, 0x12800000, 0x13000000].contains(word & 0x1f800000) { return swiftOutcomePrefixEncodingAllocated(word) }
    if word & 0x1fe00000 == 0x1a800000 {
        guard let instruction = try? decodeSwiftOutcomeInstruction(word: word) else { return false }
        return ["wcsel", "wcsinc", "wcsinv", "wcsneg", "xcsel", "xcsinc", "xcsinv", "xcsneg"].contains(instruction.kind)
    }
    return word & 0x7fe00000 == 0x1b000000
}
func swiftOutcomeIndependentLeafPreservesX21(_ words: [UInt32], charge: (Int) throws -> Void = { _ in }) throws -> Bool {
    guard !words.isEmpty, words.count <= 256, words.last == 0xd65f03c0 else { return false }
    let loads: Set<String> = ["ldp", "xldr", "wldr", "xldr_post", "xldr_raw", "xldur", "wldr_raw", "wldur", "wldrb", "wldrh"]
    let memory = Set(SwiftOutcomeInstructionKinds.memoryWidths.keys).union(["stp", "ldp", "xldr", "wldr", "xstr", "wstr", "xldr_post"])
    let historicalDestinations: Set<String> = [
        "add", "sub", "mov", "movz", "movn", "wmovk", "xmovk", "xudiv", "wudiv", "xsdiv", "wsdiv",
        "wrbit", "xrbit", "wrev", "xrev", "wrev16", "xrev16", "xrev32", "wclz", "xclz", "wcls", "xcls", "wadc", "wadcs", "wsbc",
        "wsbcs", "xadc", "xadcs", "xsbc", "xsbcs", "wadd", "wadds", "wsubs", "xadds", "xsubs", "wadds_reg", "wsubs_reg",
        "xadds_reg", "xsubs_reg", "wadds_ext", "wsubs_ext", "xadds_ext", "xsubs_ext", "smulh", "umulh", "smaddl", "smsubl", "umaddl", "umsubl",
        "wmadd", "wmsub", "xmadd", "xmsub", "wlslv", "wlsrv", "wasrv", "wrorv", "xlslv", "xlsrv", "xasrv", "xrorv", "wextr", "xextr",
        "wsbfm", "wbfm", "wubfm", "xsbfm", "xbfm", "xubfm", "wlsl", "wcsel", "wcsinc", "wcsinv", "wcsneg", "xcsel", "xcsinc", "xcsinv", "xcsneg",
        "xldr", "wldr", "wands", "wbics", "xands", "xbics", "wands_imm", "xands_imm", "wand_imm", "worr_imm", "weor_imm", "xand_imm", "xorr_imm",
        "xeor_imm", "wand_reg", "wbic_reg", "worr_reg", "worn_reg", "weor_reg", "weon_reg", "xand_reg", "xbic_reg", "xorr_reg", "xorn_reg", "xeor_reg", "xeon_reg"]
    for word in words.dropLast() {
        try charge(1)
        let effects = swiftOutcomePrefixOperandEffects(word)
        if effects.control { return false }
        if effects.known { if effects.writes.contains(21) { return false }; continue }
        let prefix = [0x11000000, 0x0a000000, 0x0b000000, 0x10000000].contains(word & 0x1f000000) || [0x12000000, 0x13000000, 0x12800000].contains(word & 0x1f800000) || [0x28000000, 0x38000000].contains(word & 0x3a000000)
        if prefix && !swiftOutcomePrefixEncodingAllocated(word) { return false }
        guard let d = try? decodeSwiftOutcomeInstruction(word: word) else { return false }
        if ["ret", "bl", "brk", "b", "bcond", "wcbz", "wcbnz", "xcbz", "xcbnz", "wtbz", "wtbnz", "xtbz", "xtbnz"].contains(d.kind) { return false }
        if ["pre", "post"].contains(d.addressing) && d.rn == 21 { return false }
        if SwiftOutcomeInstructionKinds.fpDestinations.contains(d.kind) || SwiftOutcomeInstructionKinds.fpFlags.contains(d.kind) || d.kind == "nop" { continue }
        if memory.contains(d.kind) {
            if !["", "offset", "pre", "post"].contains(d.addressing) { return false }
            if loads.contains(d.kind) && (d.rd == 21 || (d.kind == "ldp" && d.rt2 == 21)) { return false }
            continue
        }
        if SwiftOutcomeInstructionKinds.gprDestinations.contains(d.kind) || historicalDestinations.contains(d.kind) { if d.rd == 21 { return false }; continue }
        return false
    }
    return true
}

func swiftOutcomeSymbolVisibilityAllowed(kind: Int, desc: Int, declaration: SwiftBroadCallableIdentity, callKind: String) -> Bool {
    if kind == 15 && desc & 0x380 == 0 { return true }
    if kind == 30 && desc == 0 && callKind == "bl" && declaration.throwsFlag && declaration.callableKind == "static_method" && declaration.context.last?.kind == "class" && declaration.specialization == nil { return true }
    let restricted = (kind == 14 && desc == 0) || (kind == 0x1e && desc == 0x80 && callKind == "bl")
    return restricted && declaration.callableKind == "generic_specialization" && !(declaration.specialization?.bindings.isEmpty ?? true)
}

/// Frozen stable ABI assumptions corroborated only by independent byte effects.
func validateSwiftOutcomeStableABI(
    image: SwiftOutcomeValidatorImage, function: SwiftErrorFlowFunction, callee: SwiftErrorFlowFunction,
    callPC: UInt64, declaration decl: SwiftBroadCallableIdentity, abi: SwiftOutcomeJSON,
    read: (Int, Int) throws -> Data, mapped: (UInt64, Int) throws -> Int,
    instruction ins: (UInt64) throws -> SwiftOutcomeInstruction,
    charge: @escaping (Int) throws -> Void, limits: BroadWitnessLimits
) throws -> (storage: SwiftOutcomeJSON, callerErrorState: SwiftOutcomeJSON) {
    func need(_ condition: Bool, _ reason: String, _ status: String = "declined") throws {
        if !condition { throw SwiftOutcomeValidatorStop(reason: reason, status: status) }
    }
    func get(_ value: SwiftOutcomeJSON, _ key: String,
        defaultValue fallback: SwiftOutcomeJSON = .null) throws -> SwiftOutcomeJSON {
        try swiftOutcomeValidatorGet(value, key, defaultValue: fallback)
    }
    func required(_ value: SwiftOutcomeJSON, _ key: String) throws -> SwiftOutcomeJSON {
        try swiftOutcomeRequired(value, key)
    }
    func contains(_ value: SwiftOutcomeJSON, _ key: String) throws -> Bool {
        try swiftOutcomeContains(value, key)
    }
    func hex(_ pc: UInt64) -> SwiftOutcomeJSON { .string("0x" + String(pc, radix: 16)) }
    func strings(_ values: [String]) -> SwiftOutcomeJSON { .array(values.map { .string($0) }) }
    func key(_ node: SwiftBroadType) -> String { node.name + (node.arguments.isEmpty ? "" : "<" + node.arguments.map(key).joined(separator: ",") + ">") }
    let registry = SwiftOutcomeABIRegistry.frozen
    try need(get(abi, "status") == .string("admitted") && get(abi, "error_register") == .string("x21") && get(abi, "research_only") == .bool(true) && get(abi, "compiler_verified") == .bool(false) && get(abi, "profile_assumption") == .string("explicit_selected_swift6_stable_arm64_sync_untyped"), "stable_profile_assumption")
    try need(decl.throwsFlag, "stable_throws_required", "unresolved")
    let selectedSource = registry.ownedSourceBySlice[image.sliceSHA256], owned = selectedSource != nil
    var parameters = decl.parameterTypes, output = decl.resultType
    let specialization = decl.specialization
    if let specialization {
        try need(owned && !specialization.asyncRemoved && !specialization.representationChanged && specialization.kind == "generic_reabstracted" && specialization.bindings.allSatisfy { $0.replacement.name == "Swift.Int" && $0.replacement.arguments.isEmpty }, "stable_specialization_unqualified", "unresolved")
        parameters = specialization.substitutedParameterTypes; output = specialization.substitutedResultType
    } else { try need(decl.genericParameterCounts.isEmpty && decl.genericRequirements.isEmpty, "stable_generic_unqualified", "unresolved") }
    let shape = key(output)
    guard let cap = registry.stableStorageCapabilities[shape], !output.isInout, output.genericDepth == nil, !shape.hasPrefix("BroadOwned.") || owned else { throw SwiftOutcomeValidatorStop(reason: "stable_result_shape", status: "unresolved") }
    let storage = cap.json
    try need(get(abi, "result_storage") == storage && get(abi, "result_type") == .string(shape) && get(abi, "result_location") == (cap.locations.first.map { .string($0) } ?? .null), "stable_result_storage")
    var arguments: [SwiftOutcomeJSON] = [], integer = 0, floating = 0
    for node in parameters {
        let shapeArg = key(node)
        try need(node.genericDepth == nil, "stable_argument_generic", "unresolved")
        var loc: [String], evidence: String
        if node.isInout {
            try need(shapeArg == "Swift.Int", "stable_inout_shape", "unresolved")
            loc = ["indirect x\(integer)"]; integer += 1; evidence = "swift-stable-v2-inout-int"
        } else if ["Swift.Float", "Swift.Double"].contains(shapeArg) {
            loc = [(shapeArg == "Swift.Float" ? "s" : "d") + String(floating)]; floating += 1
            evidence = registry.stableStorageCapabilities[shapeArg]!.evidenceID
        } else if let argcap = registry.stableStorageCapabilities[shapeArg], shapeArg.hasPrefix("Swift."), shapeArg != "Swift.Void" {
            guard let width = argcap.bitWidth else { throw SwiftOutcomeValidatorStop(reason: "stable_argument_shape", status: "unresolved") }
            loc = [(width < 64 ? "w" : "x") + String(integer)]; integer += 1; evidence = argcap.evidenceID
        } else if shapeArg == "Tuple<Swift.Int,Swift.Bool>" {
            loc = ["x\(integer)", "w\(integer + 1)"]; integer += 2; evidence = "swift-stable-v2-tuple-int-bool"
        } else if owned && ["BroadOwned.BroadSmall", "BroadOwned.BroadLarge"].contains(shapeArg) {
            loc = ["indirect x\(integer)"]; integer += 1; evidence = "owned-v2-resilient-argument"
        } else if owned && ["Swift.String", "Swift.Array<Swift.Int>"].contains(shapeArg) {
            let n = shapeArg == "Swift.String" ? 2 : 1
            loc = (integer..<(integer + n)).map { "x\($0)" }; integer += n; evidence = "owned-v2-string-array-argument"
        } else { throw SwiftOutcomeValidatorStop(reason: "stable_argument_shape", status: "unresolved") }
        try need(integer <= 8 && floating <= 8, "stable_argument_capacity", "unresolved")
        arguments.append(.object(["type": .string(shapeArg), "locations": strings(loc), "evidence_id": .string(evidence), "inout": .bool(node.isInout)]))
    }
    try need(get(abi, "argument_storage") == .array(arguments) && get(abi, "argument_locations") == .array(arguments.map { $0["locations"] }), "stable_argument_storage")
    if let specialization { try need(specialization.passID == 5 && !specialization.serialized && [[], [2], [3], [4]].contains(specialization.droppedArgumentOrdinals), "stable_specialization_arguments", "unresolved") }
    let original = decl.originalCallableKind ?? decl.callableKind
    var receiver: SwiftOutcomeJSON = .null
    if ["struct_instance_method", "enum_instance_method"].contains(original) {
        try need(owned, "stable_value_receiver_unqualified", "unresolved"); receiver = .string("indirect x20")
    } else if original == "class_instance_method" { receiver = .string("reference x20") }
    try need(get(abi, "receiver_location") == receiver, "stable_receiver_storage")
    let lowering = try get(get(abi, "evidence", defaultValue: .object([:])), "lowering", defaultValue: .object([:]))
    let observations: SwiftOutcomeJSON = .array(registry.stableLoweringObservations.map {
        .object(["pc": hex($0.pc), "raw_bytes": .string($0.bytesHex), "meaning": .string($0.note), "source_case": .string($0.sourceCase)])
    })
    try need(get(lowering, "qualification_id") == .string(cap.evidenceID) && get(lowering, "source_evidence_id") == .string("owned-v2-fixed-initial-lowering-observations") && get(lowering, "source_sha256") == .string(registry.v2Source) && contains(lowering, "selected_source_sha256") && required(lowering, "selected_source_sha256") == (selectedSource.map { .string($0) } ?? .null) && get(lowering, "selected_slice_sha256") == .string(image.sliceSHA256) && get(lowering, "compiler") == .string(registry.compiler) && get(lowering, "target") == .string("arm64-apple-macosx14.0") && registry.v2Slices.contains(get(lowering, "reference_slice_sha256").string ?? "") && get(lowering, "public_abi_references") == strings(registry.abiReferences) && get(lowering, "observations") == observations && get(lowering, "assumption") == required(abi, "profile_assumption") && get(lowering, "compiler_verified") == .bool(false), "stable_evidence_identity")
    try need(get(lowering, "specialization") == (specialization?.json ?? .null), "stable_specialization_identity")
    let preconditions = strings(["well_formed_swift_stable_arm64_calling_convention", "synchronous_untyped_throws", "caller_supplies_error_register_state_required_by_convention"])
    if try contains(abi, "profile_preconditions") { try need(required(abi, "profile_preconditions") == preconditions, "stable_profile_preconditions") }
    if try contains(abi, "family") || contains(abi, "family_evidence") {
        var family: String
        if specialization != nil { family = "concrete_generic_specialization" }
        else if decl.context.isEmpty { family = "free" }
        else {
            let leaf = decl.context.last!
            var selected: String?
            if owned && decl.module == "BroadOwned" && leaf.name.hasPrefix("BroadOwner") {
                let suffix = String(leaf.name.dropFirst("BroadOwner".count))
                if suffix.count == 4 && suffix.allSatisfy({ $0.isASCII && $0.isNumber }), let index = Int(suffix) {
                    if stride(from: 297, to: 340, by: 3).contains(index) { selected = "extension" }
                    else if stride(from: 235, to: 295, by: 2).contains(index) { selected = "direct_final_class" }
                }
            }
            family = selected ?? (leaf.kind == "enum" ? "enum" : (decl.callableKind == "static_method" ? "static_type" : (leaf.kind == "struct" ? "struct" : "direct_class_research")))
        }
        if try contains(abi, "family") { try need(required(abi, "family") == .string(family), "stable_family_lineage") }
        if try contains(abi, "family_evidence") { try need(required(abi, "family_evidence") == .object(["source_sha256": selectedSource.map { .string($0) } ?? .null, "compiled_target_pc": hex(callee.start), "direct_call_pc": hex(callPC), "scope": .string("source_lineage_plus_exact_emitted_target_not_runtime_dispatch")]), "stable_family_evidence") }
    }
    if try contains(abi, "abi_shape") { try need(required(abi, "abi_shape") == .object(["arguments": .array(arguments), "receiver": receiver, "result": cap.json, "error_register": .string("x21"), "specialized": .bool(specialization != nil)]), "stable_abi_shape") }
    let beforeStart = max(function.start, callPC >= 128 ? callPC - 128 : 0)
    if try contains(abi, "caller_error_observations") {
        var clear: [SwiftOutcomeJSON] = [], tests: [SwiftOutcomeJSON] = []
        for pc in stride(from: beforeStart, to: callPC, by: 4) { if [0xd2800015, 0x52800015, 0xaa1f03f5].contains(try ins(pc).word) { clear.append(hex(pc)) } }
        let (after, overflow) = callPC.addingReportingOverflow(68)
        try need(!overflow, "stable_caller_instruction_observations")
        for pc in stride(from: callPC + 4, to: min(function.endExclusive, after), by: 4) { if try ins(pc).word & 0x7e00001f == 0x34000015 { tests.append(hex(pc)) } }
        try need(required(abi, "caller_error_observations") == .object(["clear_instruction_pcs": .array(clear), "test_instruction_pcs": .array(tests), "incoming_state_proven": .bool(false), "scope": .string("instruction_presence_not_path_or_state_proof")]), "stable_caller_instruction_observations")
    }
    let state = SwiftOutcomeScalarReplay(callPC: callPC, limits: limits, charge: charge)
    state.registers = [:]; state.stackPointer = nil
    for pc in stride(from: beforeStart, to: callPC, by: 4) {
        let d = try ins(pc)
        if ["bl", "b", "ret", "brk", "bcond", "xcbz", "xcbnz", "wcbz", "wcbnz", "xtbz", "xtbnz", "wtbz", "wtbnz"].contains(d.kind) { state.registers = [:]; break }
        do { try state.step(d) }
        catch let stop as SwiftOutcomeValidatorStop {
            if stop.reason != "value_transfer_unqualified" { throw stop }
            state.registers.removeValue(forKey: d.rd)
        }
    }
    if let incoming = state.read(21)?.array, incoming.first == .string("constant") { try need(incoming.count > 1 && incoming[1] == .integer(0), "caller_error_contract_contradiction", "blocked") }
    guard callee.endExclusive >= callee.start, let size = Int(exactly: callee.endExclusive - callee.start) else { throw SwiftOutcomeValidatorStop(reason: "stable_callee_budget", status: "unresolved") }
    try need(size / 4 <= limits.maxInstructions && size % 4 == 0, "stable_callee_budget", "unresolved")
    let raw = try read(mapped(callee.start, size), size)
    try need(raw.count == size, "stable_callee_budget", "unresolved")
    let bytes = Array(raw)
    var words: [UInt32] = []
    for i in stride(from: 0, to: bytes.count, by: 4) { words.append(UInt32(bytes[i]) | UInt32(bytes[i+1]) << 8 | UInt32(bytes[i+2]) << 16 | UInt32(bytes[i+3]) << 24) }
    let transport = words.contains(where: swiftOutcomeIsErrorTransportInstruction)
    let leaf = transport ? false : try swiftOutcomeIndependentLeafPreservesX21(words, charge: charge)
    try need(transport || leaf, "stable_error_transport", "unresolved")
    let errorObservation: SwiftOutcomeJSON = .object(["mode": .string(transport ? "distinct_nonzero_gpr_copy" : "preserved_x21_leaf"), "register": .string("x21"), "scope": .string("instruction_effects_if_normal_return_not_incoming_state_or_object_type"), "entry_pc": hex(callee.start), "return_pc": leaf ? hex(callee.endExclusive - 4) : .null, "word_count": .integer(Int128(words.count)), "preserves_incoming_x21": leaf ? .bool(true) : .null, "incoming_state_proven": .bool(false), "error_object_type_proven": .bool(false)])
    try need(get(lowering, "callee_error_observation") == errorObservation && get(lowering, "callee_error_transport_observation") == .string(transport ? "mov_to_x21_from_distinct_nonzero_gpr_presence" : "x21_preserved_by_exact_straightline_leaf_effects") && get(lowering, "error_object_type_proven") == .bool(false), "stable_error_observation")
    if specialization != nil { try need(try swiftOutcomeFormalPrefixInputs(words, locations: arguments.flatMap { ($0["locations"].array ?? []).compactMap(\.string) }, charge: charge), "stable_specialization_formal_inputs", "unresolved") }
    let corroborated: Bool
    if cap.category == "void" { corroborated = words.contains(0xd65f03c0) }
    else if cap.indirect { corroborated = words.contains(where: swiftOutcomeIsDirectResultStore) }
    else if cap.locations == ["s0"] || cap.locations == ["d0"] {
        let double = cap.locations == ["d0"]
        let unary: [UInt32] = double ? [0x9e670000, 0x9e620000] : [0x1e270000, 0x9e220000]
        let binary: [UInt32] = (double ? [0x1e611800, 0x1e612800] : [0x1e211800, 0x1e212800]).map { $0 & 0xffe0fc00 }
        corroborated = words.contains { $0 & 31 == 0 && (unary.contains($0 & 0xfffffc00) || binary.contains($0 & 0xffe0fc00)) }
    } else { corroborated = cap.locations.allSatisfy { loc in guard let reg = Int(loc.dropFirst()) else { return false }; return words.contains { swiftOutcomeAllocatedResultGPRWrite($0, register: reg) } } }
    try need(corroborated, "stable_result_bytes", "unresolved")
    if try registry.v2Slices.contains(image.sliceSHA256) && required(lowering, "reference_slice_sha256") == .string(image.sliceSHA256) {
        for row in registry.stableLoweringObservations {
            let chars = Array(row.bytesHex.utf8)
            var expected = Data()
            for i in stride(from: 0, to: chars.count, by: 2) {
                guard i + 1 < chars.count, let byte = UInt8(String(bytes: chars[i...i+1], encoding: .utf8) ?? "", radix: 16) else { throw SwiftOutcomeValidatorStop(reason: "stable_reference_bytes", status: "unresolved") }
                expected.append(byte)
            }
            try need(try read(mapped(row.pc, expected.count), expected.count) == expected, "stable_reference_bytes", "unresolved")
        }
    }
    return (storage, .string("unproven_profile_precondition"))
}
