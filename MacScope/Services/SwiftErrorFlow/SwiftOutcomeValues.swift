import Foundation

indirect enum SwiftAbstractValue: Hashable, Sendable {
    case unknown, unavailable
    case literal(value: UInt64, width: Int)
    case registerCopy(origin: String, width: Int)
    case stackSlot(slot: Int, epoch: Int, width: Int)
    case phiMerge([SwiftAbstractValue])
    case derived(operation: String, inputs: [SwiftAbstractValue], width: Int, knownBits: [Int]?)

    static let mergeDomain = "merge_domain"
    static let knownBitsDomain = "known_bits_domain"
    static func makeLiteral(value: UInt64, width: Int) throws -> Self {
        guard [32, 64].contains(width), width == 64 || value < 1 << 32 else { throw SwiftOutcomeError(code: "literal_width") }
        return .literal(value: value, width: width)
    }
    static func makeRegisterCopy(origin: String, width: Int) throws -> Self {
        guard [32, 64].contains(width) else { throw SwiftOutcomeError(code: "register_copy_domain") }
        return .registerCopy(origin: origin, width: width)
    }
    static func makeStackSlot(slot: Int, epoch: Int, width: Int) throws -> Self {
        guard [32, 64].contains(width), epoch >= 0 else { throw SwiftOutcomeError(code: "stack_slot_domain") }
        return .stackSlot(slot: slot, epoch: epoch, width: width)
    }
    static func makeDerived(operation: String, inputs: [Self], width: Int, knownBits: [Int]?) throws -> Self {
        guard [32, 64].contains(width) else { throw SwiftOutcomeError(code: "derived_domain") }
        return .derived(operation: operation, inputs: inputs, width: width, knownBits: knownBits)
    }
    var inputs: [Self] {
        switch self { case .phiMerge(let v), .derived(_, let v, _, _): return v; default: return [] }
    }
    var literal: UInt64? { if case .literal(let value, _) = self { return value }; return nil }
    var isUnknown: Bool { self == .unknown || self == .unavailable }
    func resized(_ width: Int) -> Self {
        switch self {
        case .literal(let v, _): return .literal(value: v & valueMask(width), width: width)
        case .unknown, .unavailable: return self
        case .phiMerge(let inputs): return .phiMerge(inputs.map { $0.resized(width) })
        case .registerCopy(_, let bits), .stackSlot(_, _, let bits), .derived(_, _, let bits, _):
            return bits == width ? self : .derived(operation: width == 32 ? "truncate" : "zero_extend", inputs: [self], width: width, knownBits: nil)
        }
    }
}

private func valueMask(_ width: Int) -> UInt64 { width == 32 ? 0xffffffff : .max }
private func valueDerived(_ operation: String, _ inputs: [SwiftAbstractValue], _ width: Int) -> SwiftAbstractValue {
    .derived(operation: operation, inputs: inputs, width: width, knownBits: nil)
}
private func valueLiteral(_ value: Int128, _ width: Int) -> SwiftAbstractValue {
    .literal(value: UInt64(truncatingIfNeeded: value) & valueMask(width), width: width)
}
private func valueSigned(_ value: UInt64, width: Int = 64) -> Int128 {
    let number = Int128(value)
    return value & (UInt64(1) << (width - 1)) == 0 ? number : number - (Int128(1) << width)
}
private func valueDepthOK(_ value: SwiftAbstractValue, _ limit: Int) -> Bool {
    var todo: [(SwiftAbstractValue, Int)] = [(value, 1)], visited = 0
    while let (node, depth) = todo.popLast() {
        visited += 1
        if depth > limit || visited > 4096 { return false }
        let children = node.inputs
        if children.count > 4096 - todo.count { return false }
        todo.append(contentsOf: children.map { ($0, depth + 1) })
    }
    return true
}

struct ValueLimits: Equatable, Sendable {
    var maxStateEntries = 128
    var maxProvenanceDepth = 16
    var maxSteps = 4096
    var maxSlots = 64
    var maxMergeInputs = 8
    var maxProvenanceNodes = 4096
    var maxValueInputs = 64
}
struct SwiftRegisterValue: Hashable, Sendable { let register: Int; let value: SwiftAbstractValue }
struct SwiftRegisterEpoch: Hashable, Sendable { let register: Int; let epoch: Int }
struct StackCell: Hashable, Sendable { let slot: Int; let epoch: Int; let width: Int; let value: SwiftAbstractValue }
struct ValueState: Equatable, Sendable {
    var registers: [SwiftRegisterValue] = []
    var registerEpochs: [SwiftRegisterEpoch] = []
    var stack: [StackCell] = []
    var spOffset: Int? = 0
    var stackEpoch = 0
    var steps = 0
    var refusal: String?
    func readRegister(_ register: Int, width: Int = 64) -> SwiftAbstractValue {
        if register == 31 { return .literal(value: 0, width: width) }
        return (registers.last { $0.register == register }?.value ?? .unknown).resized(width)
    }
}
struct TransferResult: Equatable, Sendable {
    let state: ValueState
    var status = "resolved"
    var reason: String?
}

func initialState(_ registers: [Int: SwiftAbstractValue] = [:], limits: ValueLimits = ValueLimits()) throws -> ValueState {
    guard registers.count <= min(31, limits.maxStateEntries) else { throw SwiftOutcomeError(code: "state_entry_limit") }
    var result: [SwiftRegisterValue] = []
    for (register, value) in registers.sorted(by: { $0.key < $1.key }) {
        guard (0...31).contains(register) else { throw SwiftOutcomeError(code: "register") }
        guard valueDepthOK(value, limits.maxProvenanceDepth) else { throw SwiftOutcomeError(code: "value_provenance_limit") }
        if register != 31 { result.append(SwiftRegisterValue(register: register, value: value.resized(64).resized(64))) }
    }
    return ValueState(registers: result)
}

private func valueStateIssue(_ state: ValueState, _ limits: ValueLimits) -> String? {
    if let refusal = state.refusal, !refusal.isEmpty { return refusal }
    if state.registers.count + state.stack.count > limits.maxStateEntries || state.stack.count > limits.maxSlots || state.registerEpochs.count > 31 { return "value_state_limit" }
    var todo: [(SwiftAbstractValue, Int)] = state.registers.map { ($0.value, 1) } + state.stack.map { ($0.value, 1) }
    var budget = limits.maxProvenanceNodes
    while let (value, depth) = todo.popLast() {
        budget -= 1
        if depth > limits.maxProvenanceDepth || budget < 0 { return "value_provenance_limit" }
        let children = value.inputs
        if children.count > limits.maxValueInputs || children.count + todo.count > budget { return "value_provenance_limit" }
        todo.append(contentsOf: children.map { ($0, depth + 1) })
    }
    return nil
}

func transferSwiftValue(_ state: ValueState, _ instruction: SwiftOutcomeInstruction, limits: ValueLimits = ValueLimits()) -> TransferResult {
    func refuse(_ reason: String) -> TransferResult { TransferResult(state: state, status: "unresolved", reason: reason) }
    if let issue = valueStateIssue(state, limits) { return refuse(issue) }
    if state.steps >= limits.maxSteps { return refuse("value_step_limit") }
    if state.registers.contains(where: { !valueDepthOK($0.value, limits.maxProvenanceDepth) }) { return refuse("value_provenance_limit") }
    var registers: [Int: SwiftAbstractValue] = [:], epochs: [Int: Int] = [:]
    for pair in state.registers { registers[pair.register] = pair.value }
    for pair in state.registerEpochs { epochs[pair.register] = pair.epoch }
    var stack = state.stack, sp = state.spOffset, epoch = state.stackEpoch
    let kind = instruction.kind, width = instruction.kind.hasPrefix("w") ? 32 : 64
    let rd = instruction.rd, rn = instruction.rn, immediate = instruction.immediate
    func read(_ register: Int, _ bits: Int? = nil) -> SwiftAbstractValue { state.readRegister(register, width: bits ?? width) }
    func write(_ register: Int, _ value: SwiftAbstractValue, _ bits: Int? = nil) throws {
        if register == 31 { return }
        if registers[register] == nil && registers.count + stack.count >= limits.maxStateEntries { throw SwiftOutcomeError(code: "value_state_limit") }
        if !valueDepthOK(value, limits.maxProvenanceDepth) { throw SwiftOutcomeError(code: "value_provenance_limit") }
        registers[register] = value.resized(bits ?? width).resized(64)
        guard (epochs[register] ?? 0) < Int.max else { throw SwiftOutcomeError(code: "value_state_limit") }
        epochs[register] = (epochs[register] ?? 0) + 1
    }
    func advanceEpoch() throws {
        guard epoch < Int.max else { throw SwiftOutcomeError(code: "value_state_limit") }
        epoch += 1
    }
    func adjust(_ newSP: Int?) throws {
        if newSP == nil { stack = []; try advanceEpoch() }
        else if let newSP, let oldSP = sp, newSP > oldSP { stack = stack.filter { $0.slot >= newSP }; try advanceEpoch() }
        sp = newSP
    }
    func stackAddress(_ value: SwiftAbstractValue) -> Int? {
        if case .derived("entry_sp_offset", let inputs, _, _) = value, inputs.count == 1, let number = inputs[0].literal { return Int(exactly: valueSigned(number)) }
        return nil
    }
    func offset(_ base: Int, _ delta: Int128, subtract: Bool = false) throws -> Int {
        let sum = subtract ? Int128(base).subtractingReportingOverflow(delta) : Int128(base).addingReportingOverflow(delta)
        guard !sum.overflow, let value = Int(exactly: sum.partialValue) else { throw SwiftOutcomeError(code: "stack_base_unqualified") }
        return value
    }
    do {
        if SwiftOutcomeInstructionKinds.fpDestinations.contains(kind) || SwiftOutcomeInstructionKinds.fpFlags.contains(kind) {
            // FP destinations and flags cannot create a scalar GPR origin.
        } else if let size = SwiftOutcomeInstructionKinds.memoryWidths[kind] {
            let load = ["wldrb", "wldrh", "xldr_raw", "xldur", "wldr_raw", "wldur"].contains(kind)
            let base = rn == 31 ? sp : stackAddress(read(rn, 64))
            let address = try base.map { try offset($0, immediate) }
            if load {
                let cell = stack.first { $0.slot == address && $0.width == size * 8 }
                try write(rd, (size == 4 || size == 8) ? (cell?.value ?? .unknown) : .unknown, size < 8 ? 32 : 64)
            } else {
                if let address { stack = stack.filter { Int128($0.slot) + Int128($0.width / 8) <= Int128(address) || Int128($0.slot) >= Int128(address) + Int128(size) } }
                else { stack = [] }
                try advanceEpoch()
                if !SwiftOutcomeInstructionKinds.fpMemoryStores.contains(kind), [4, 8].contains(size), let address, let sp, sp <= address, Int128(address) + Int128(size) <= 0 {
                    if stack.count >= limits.maxSlots || registers.count + stack.count >= limits.maxStateEntries { return refuse("value_slot_limit") }
                    stack.append(StackCell(slot: address, epoch: epoch, width: size * 8, value: read(rd, size * 8)))
                }
            }
        } else if ["xadd_reg", "xsub_reg", "wadd_reg", "wsub_reg", "xadds_reg", "xsubs_reg", "wadds_reg", "wsubs_reg", "wand_reg", "xand_reg"].contains(kind) {
            let mode = instruction.addressing
            guard immediate >= 0, immediate < width, ["lsl", "lsr", "asr"].contains(mode) else { return refuse("register_shift_unqualified") }
            let left = read(rn); var right = read(instruction.rt2)
            if let number = right.literal {
                let shift = Int(immediate)
                let shifted = mode == "lsl" ? Int128(number) << shift : mode == "lsr" ? Int128(number) >> shift : valueSigned(number, width: width) >> shift
                right = valueLiteral(shifted, width)
            } else if immediate != 0 && !right.isUnknown { right = valueDerived(mode, [right, valueLiteral(immediate, width)], width) }
            let operation = kind.contains("and") ? "and" : kind.contains("sub") ? "sub" : "add"
            let value: SwiftAbstractValue
            if let l = left.literal, let r = right.literal {
                value = valueLiteral(operation == "and" ? Int128(l & r) : operation == "sub" ? Int128(l) - Int128(r) : Int128(l) + Int128(r), width)
            } else if left.isUnknown || right.isUnknown { value = .unknown }
            else { value = valueDerived(operation, [left, right], width) }
            try write(rd, value)
        } else if ["xadd_ext", "xsub_ext"].contains(kind) {
            let modes = ["uxtb": 8, "uxth": 16, "uxtw": 32, "uxtx": 64, "sxtb": 8, "sxth": 16, "sxtw": 32, "sxtx": 64]
            let mode = instruction.addressing
            guard let bits = modes[mode], immediate >= 0, immediate <= 4 else { return refuse("register_extend_unqualified") }
            var right = read(instruction.rt2, 64)
            if let number = right.literal {
                let narrowed = number & (bits == 64 ? UInt64.max : (UInt64(1) << bits) - 1)
                let extended = mode.hasPrefix("s") ? valueSigned(narrowed, width: bits) : Int128(narrowed)
                right = valueLiteral(extended << Int(immediate), 64)
            } else if !right.isUnknown { right = valueDerived("extend_" + mode, [right, valueLiteral(immediate, 64)], 64) }
            let frame = rn == 31 ? sp : stackAddress(read(rn, 64))
            if rn == 31 || frame != nil {
                var address: Int?
                if let frame, let number = right.literal { address = try offset(frame, kind == "xsub_ext" ? -valueSigned(number) : valueSigned(number)) }
                if rd == 31 { try adjust(address) }
                else if let address { try write(rd, valueDerived("entry_sp_offset", [valueLiteral(Int128(address), 64)], 64), 64) }
                else { try write(rd, .unknown, 64) }
            } else if rd == 31 { try adjust(nil) }
            else {
                let left = read(rn, 64), operation = kind == "xsub_ext" ? "sub" : "add"
                let value: SwiftAbstractValue
                if let l = left.literal, let r = right.literal { value = valueLiteral(operation == "sub" ? Int128(l) - Int128(r) : Int128(l) + Int128(r), 64) }
                else if left.isUnknown || right.isUnknown { value = .unknown }
                else { value = valueDerived(operation, [left, right], 64) }
                try write(rd, value, 64)
            }
        } else if SwiftOutcomeInstructionKinds.gprDestinations.contains(kind) {
            try write(rd, .unknown, kind.hasPrefix("fmov_w") || kind.hasPrefix("fcvtzs_w") ? 32 : 64)
        } else if kind == "brk" { return refuse("exception_transfer_effect_unqualified") }
        else if ["nop", "ret", "b", "bcond", "wcbz", "wcbnz", "xcbz", "xcbnz", "wtbz", "wtbnz", "xtbz", "xtbnz"].contains(kind) {
        } else if kind == "bl" {
            for register in Array(0..<19) + [30] { try write(register, .unknown, 64) }
            stack = []; try advanceEpoch()
        } else if ["mov", "wmov"].contains(kind) { try write(rd, read(rn)) }
        else if ["movz", "movn", "wmovz", "wmovn"].contains(kind) {
            guard immediate >= 0, stride(from: 0, to: width, by: 16).contains(where: { immediate & ~(Int128(0xffff) << $0) == 0 }) else { return refuse("move_immediate_unqualified") }
            try write(rd, valueLiteral(kind.hasSuffix("movn") ? ~immediate : immediate, width))
        } else if ["xmovk", "wmovk"].contains(kind) {
            guard immediate >= 0, immediate <= 0xffff else { return refuse("move_immediate_unqualified") }
            guard let shift = Int(instruction.addressing), stride(from: 0, to: width, by: 16).contains(shift) else { return refuse("move_lane_unqualified") }
            let old = read(rd)
            if let number = old.literal { try write(rd, .literal(value: (number & ~(UInt64(0xffff) << shift)) | (UInt64(immediate) << shift), width: width)) }
            else { try write(rd, valueDerived("insert_lane", [old, valueLiteral(immediate, width), valueLiteral(Int128(shift), width)], width)) }
        } else if ["add", "sub", "wadd", "wadds", "wsubs", "xadds", "xsubs", "wlsl"].contains(kind) {
            if rn == 31 && ["wadd", "wadds", "wsubs", "xadds", "xsubs"].contains(kind) { return refuse("stack_address_integer_unqualified") }
            if kind == "wadd" && rd == 31 { return refuse("wsp_adjustment_unqualified") }
            if ["add", "sub"].contains(kind) && (rn == 31 || stackAddress(read(rn)) != nil) {
                let base = rn == 31 ? sp : stackAddress(read(rn))
                let address = try base.map { try offset($0, immediate, subtract: kind == "sub") }
                if rd == 31 { try adjust(address) }
                else if let address { try write(rd, valueDerived("entry_sp_offset", [valueLiteral(Int128(address), 64)], 64)) }
                else { try write(rd, .unknown) }
            } else if rd == 31 && ["add", "sub"].contains(kind) { return refuse("unknown_stack_adjustment") }
            else {
                let source = read(rn), operation = kind == "wlsl" ? "lsl" : kind.contains("sub") ? "sub" : "add"
                if operation == "lsl" && !(immediate >= 0 && immediate < width) { return refuse("shift_unqualified") }
                let value: SwiftAbstractValue
                if let number = source.literal {
                    let modular: UInt64
                    if operation == "lsl" { modular = number << Int(immediate) }
                    else if operation == "sub" { modular = number &- UInt64(truncatingIfNeeded: immediate) }
                    else { modular = number &+ UInt64(truncatingIfNeeded: immediate) }
                    value = .literal(value: modular & valueMask(width), width: width)
                } else if source.isUnknown { value = source }
                else { value = valueDerived(operation, [source, valueLiteral(immediate, width)], width) }
                try write(rd, value)
            }
        } else if ["wand_imm", "xand_imm", "worr_imm", "xorr_imm", "weor_imm", "xeor_imm", "wands_imm", "xands_imm"].contains(kind) {
            guard immediate >= 0, immediate < Int128(1) << width else { return refuse("logical_mask_unqualified") }
            let source = read(rn), mask = UInt64(immediate), operation = kind.contains("and") ? "and" : kind.contains("orr") ? "or" : "xor"
            let value: SwiftAbstractValue
            if let number = source.literal { value = .literal(value: (operation == "and" ? number & mask : operation == "or" ? number | mask : number ^ mask) & valueMask(width), width: width) }
            else if source.isUnknown { value = source }
            else { value = valueDerived(operation, [source, valueLiteral(immediate, width)], width) }
            try write(rd, value)
        } else if ["wcsel", "xcsel", "wcsinc", "xcsinc", "wcsinv", "xcsinv", "wcsneg", "xcsneg"].contains(kind) { try write(rd, .unknown) }
        else if ["xubfm", "wubfm"].contains(kind) {
            guard let rotate = Int(instruction.addressing), (0..<width).contains(rotate), immediate >= 0, immediate < width else { return refuse("bitfield_unqualified") }
            let source = read(rn), end = Int(immediate), value: SwiftAbstractValue
            if let number = source.literal {
                let result: Int128 = end >= rotate ? (Int128(number) >> rotate) & ((Int128(1) << (end - rotate + 1)) - 1) : (Int128(number) & ((Int128(1) << (end + 1)) - 1)) << (width - rotate)
                value = valueLiteral(result, width)
            } else if source.isUnknown { value = source }
            else { value = valueDerived("unsigned_bitfield", [source, valueLiteral(Int128(rotate), width), valueLiteral(immediate, width)], width) }
            try write(rd, value)
        } else if ["xsbfm", "wsbfm"].contains(kind) {
            guard instruction.addressing == "0", immediate >= 0, immediate < width else { return refuse("bitfield_unqualified") }
            let source = read(rn), bits = Int(immediate) + 1, value: SwiftAbstractValue
            if let number = source.literal {
                let mask = bits == 64 ? UInt64.max : (UInt64(1) << bits) - 1
                value = valueLiteral(valueSigned(number & mask, width: bits), width)
            } else if source.isUnknown { value = source }
            else { value = valueDerived("sign_extend", [source, valueLiteral(Int128(bits), width)], width) }
            try write(rd, value)
        } else if ["xstr", "wstr", "xldr", "wldr", "xldr_post", "stp", "ldp"].contains(kind) {
            let pair = ["stp", "ldp"].contains(kind), load = ["xldr", "wldr", "xldr_post", "ldp"].contains(kind)
            let regs = pair ? [rd, instruction.rt2] : [rd], mode = instruction.addressing.isEmpty ? "offset" : instruction.addressing
            guard ["offset", "pre", "post"].contains(mode) else { return refuse("memory_mode_unqualified") }
            if load && Set(regs).count != regs.count { return refuse("memory_register_overlap") }
            if mode != "offset" && rn != 31 && regs.contains(rn) { return refuse("memory_register_overlap") }
            guard let base = rn == 31 ? sp : stackAddress(read(rn, 64)), sp != nil else { return refuse("stack_base_unqualified") }
            let count = pair ? 2 : 1, size = width / 8
            let address = try offset(base, mode == "post" ? 0 : immediate)
            if mode == "pre" && rn == 31 { try adjust(address) }
            guard let frame = sp, address >= frame, Int128(address) + Int128(size * count) <= 0 else { return refuse("memory_outside_frame") }
            if !load {
                let retained = stack.filter { Int128($0.slot) + Int128($0.width / 8) <= Int128(address) || Int128($0.slot) >= Int128(address) + Int128(size * count) }
                if retained.count + count > limits.maxSlots { return refuse("value_slot_limit") }
                if registers.count + retained.count + count > limits.maxStateEntries { return refuse("value_state_limit") }
                try advanceEpoch(); stack = retained
                for (index, register) in regs.enumerated() { stack.append(StackCell(slot: address + index * size, epoch: epoch, width: width, value: read(register))) }
            } else {
                for (index, register) in regs.enumerated() { try write(register, stack.first { $0.slot == address + index * size && $0.width == width }?.value ?? .unknown) }
            }
            if mode != "offset" {
                let next = try offset(base, immediate)
                if rn == 31 { if mode == "post" { try adjust(next) } }
                else { try write(rn, valueDerived("entry_sp_offset", [valueLiteral(Int128(next), 64)], 64), 64) }
            }
        } else { return refuse("instruction_effect_unqualified") }
        if registers.count + stack.count > limits.maxStateEntries { return refuse("value_state_limit") }
        if registers.values.contains(where: { !valueDepthOK($0, limits.maxProvenanceDepth) }) { return refuse("value_provenance_limit") }
        return TransferResult(state: ValueState(
            registers: registers.sorted { $0.key < $1.key }.map { SwiftRegisterValue(register: $0.key, value: $0.value) },
            registerEpochs: epochs.sorted { $0.key < $1.key }.map { SwiftRegisterEpoch(register: $0.key, epoch: $0.value) },
            stack: stack, spOffset: sp, stackEpoch: epoch, steps: state.steps + 1))
    } catch let error as SwiftOutcomeError { return refuse(error.code) }
    catch { return refuse("instruction_effect_unqualified") }
}
