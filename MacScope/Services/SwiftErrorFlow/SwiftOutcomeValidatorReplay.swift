import Foundation

/// AIRS fa5a2f3128da9134969055cebea145e2ca144214, validator lines 14–16, 651–905.
struct SwiftOutcomeValidatorStop: Error {
    let reason: String
    let status: String
    var instruction: SwiftOutcomeJSON?
    init(reason: String, status: String = "declined", instruction: SwiftOutcomeJSON? = nil) {
        self.reason = reason; self.status = status; self.instruction = instruction
    }
}

/// Independent equations, not the producer's value transfer. Unknown SP is distinct
/// from entry SP; no scalar origin survives an opaque call.
final class SwiftOutcomeScalarReplay {
    struct Cell { let size: Int; let epoch: Int; let value: SwiftOutcomeJSON? }
    var registers: [Int: SwiftOutcomeJSON]
    var cells: [Int: Cell] = [:]
    var stackPointer: Int? = 0
    /// D13 integer seam. The separate optional state retains donor unknown-SP semantics;
    /// callers deciding frame validity must inspect stackPointer, never this projection.
    var sp: Int {
        get { stackPointer ?? 0 }
        set { stackPointer = newValue }
    }
    var epoch = 0
    let limits: BroadWitnessLimits
    private let charge: (Int) throws -> Void
    private var currentInstruction: SwiftOutcomeJSON?
    init(callPC: UInt64, limits: BroadWitnessLimits, charge: @escaping (Int) throws -> Void = { _ in }) {
        registers = [0: .array([.string("call_result"), .string("0x" + String(callPC, radix: 16)), .integer(64)]),
                     21: .array([.string("error_result"), .string("0x" + String(callPC, radix: 16)), .integer(64)])]
        self.limits = limits; self.charge = charge
    }
    func clone() -> SwiftOutcomeScalarReplay {
        let other = SwiftOutcomeScalarReplay(callPC: 0, limits: limits, charge: charge)
        other.registers = registers; other.cells = cells; other.stackPointer = stackPointer; other.epoch = epoch
        other.currentInstruction = currentInstruction; return other
    }
    private func fail(_ reason: String) throws -> Never {
        throw SwiftOutcomeValidatorStop(reason: reason, status: "unresolved",
            instruction: reason == "value_transfer_unqualified" ? currentInstruction : nil)
    }
    private func tag(_ value: SwiftOutcomeJSON) -> String { value.array?.first?.string ?? "" }
    private func number(_ value: SwiftOutcomeJSON) -> Int128 { value.array?[1].integer ?? 0 }
    private func mask(_ bits: Int) -> Int128 { (Int128(1) << bits) - 1 }
    private func constant(_ n: Int128, _ bits: Int = 64) -> SwiftOutcomeJSON { .array([.string("constant"), .integer(n & mask(bits)), .integer(Int128(bits))]) }
    private func expression(_ op: String, _ inputs: [SwiftOutcomeJSON], _ bits: Int = 64) -> SwiftOutcomeJSON { .array([.string(op)] + inputs + [.integer(Int128(bits))]) }
    private func stack(_ n: Int128) -> SwiftOutcomeJSON { .array([.string("stack_address"), .integer(n), .integer(64)]) }
    func resized(_ value: SwiftOutcomeJSON?, bits: Int) -> SwiftOutcomeJSON? {
        guard let value else { return nil }
        if tag(value) == "constant" { return constant(number(value), bits) }
        let old = value.array?.last?.integer ?? 64
        return old == Int128(bits) ? value : expression(Int128(bits) < old ? "truncate" : "zero_extend", [value], bits)
    }
    func read(_ reg: Int, bits: Int = 64) -> SwiftOutcomeJSON? { reg == 31 ? constant(0, bits) : resized(registers[reg], bits: bits) }
    func write(_ reg: Int, _ value: SwiftOutcomeJSON?, bits: Int = 64) throws {
        if let value, tag(value) == "stack_address" { _ = try checkedStackOffset(number(value)) }
        if reg == 31 { return }
        registers[reg] = resized(resized(value, bits: bits), bits: 64)
        try bound()
    }
    func bound() throws {
        guard registers.count + cells.count <= limits.maxStateEntries else { try fail("value_state_limit") }
        var work = registers.keys.sorted().map { (registers[$0]!, 1) }
        work += cells.keys.sorted().compactMap { key in cells[key]!.value.map { ($0, 1) } }
        var count = 0
        while let (v, depth) = work.popLast() {
            count += 1
            if count > limits.maxProvenanceNodes || depth > limits.maxDepth { try fail("value_provenance_limit") }
            for item in v.array ?? [] { if case .array = item { work.append((item, depth + 1)) } }
        }
    }
    private func checkedStackOffset(_ n: Int128) throws -> Int {
        guard let v = Int(exactly: n), n >= -(Int128(1) << 63), n < (Int128(1) << 63) else { try fail("stack_offset_unqualified") }
        return v
    }
    private func adjust(_ n: Int128) throws {
        let next = try checkedStackOffset(n)
        guard let old = stackPointer else { try fail("unknown_stack_frame") }
        if next > old { cells = cells.filter { $0.key >= next }; epoch += 1 }
        stackPointer = next
    }
    private func shifted(_ value: SwiftOutcomeJSON?, bits: Int, mode: String, amount: Int128) throws -> SwiftOutcomeJSON? {
        guard ["lsl", "lsr", "asr", "ror"].contains(mode), amount >= 0, amount < Int128(bits) else { try fail("register_shift_unqualified") }
        guard let value else { return nil }; if amount == 0 { return value }
        if tag(value) == "constant" {
            var n = number(value) & mask(bits)
            switch mode {
            case "lsl": n <<= Int(amount)
            case "lsr": n >>= Int(amount)
            case "asr": n = (n & (Int128(1) << (bits - 1)) != 0 ? n - (Int128(1) << bits) : n) >> Int(amount)
            default: n = (n >> Int(amount)) | (n << (bits - Int(amount)))
            }
            return constant(n, bits)
        }
        return expression(mode, [value, constant(amount, bits)], bits)
    }
    private func binary(_ op: String, _ left: SwiftOutcomeJSON?, _ right: SwiftOutcomeJSON?, _ bits: Int) -> SwiftOutcomeJSON? {
        guard let left, let right else { return nil }
        if tag(left) == "constant", tag(right) == "constant" {
            let a = number(left), b = number(right), n: Int128
            switch op { case "add": n = a + b; case "sub": n = a - b; case "orr": n = a | b; case "eor": n = a ^ b; default: n = a & b }
            return constant(n, bits)
        }
        return expression(op, [left, right], bits)
    }
    func step(_ d: SwiftOutcomeInstruction) throws {
        try charge(1)
        let k = d.kind, bits = k.hasPrefix("w") ? 32 : 64, rd = d.rd, rn = d.rn
        currentInstruction = .object(["pc": .string("0x" + String(d.address, radix: 16)), "word": .string(String(format: "0x%08x", d.word)), "kind": .string(k)])
        if SwiftOutcomeInstructionKinds.fpDestinations.contains(k) || SwiftOutcomeInstructionKinds.fpFlags.contains(k) { return }
        if SwiftOutcomeInstructionKinds.gprDestinations.contains(k), !["adr", "adrp", "wldrb", "wldrh", "xadd_reg", "xsub_reg", "wadd_reg", "wsub_reg", "xadd_ext", "xsub_ext", "xldr_raw", "xldur", "wldr_raw", "wldur"].contains(k) { try write(rd, nil); return }
        if ["xadd_ext", "xsub_ext"].contains(k) {
            let extensions: [String: (Int, Bool)] = ["uxtb": (8,false), "uxth": (16,false), "uxtw": (32,false), "uxtx": (64,false), "sxtb": (8,true), "sxth": (16,true), "sxtw": (32,true), "sxtx": (64,true)]
            guard let (width, signed) = extensions[d.addressing], (0...4).contains(d.immediate) else { try fail("extended_register_unqualified") }
            var right = read(d.rt2)
            if let r = right, width < 64 {
                if tag(r) == "constant" {
                    var n = number(r) & mask(width)
                    if signed && n & (Int128(1) << (width - 1)) != 0 { n -= Int128(1) << width }
                    right = constant(n)
                } else { right = expression(signed ? "sign_extend_low_bits" : "zero_extend_low_bits", [r, constant(Int128(width))]) }
            }
            right = try shifted(right, bits: 64, mode: "lsl", amount: d.immediate)
            let left = rn == 31 ? stackPointer.map { stack(Int128($0)) } : read(rn), op = k == "xadd_ext" ? "add" : "sub"
            var value = binary(op, left, right, 64)
            if let l = left, let r = right, tag(l) == "stack_address", tag(r) == "constant" {
                let raw = number(r), n = raw & (Int128(1) << 63) != 0 ? raw - (Int128(1) << 64) : raw
                value = stack(number(l) + (op == "add" ? n : -n))
            }
            if rd == 31 {
                if let value, tag(value) == "stack_address" {
                    let next = try checkedStackOffset(number(value))
                    if stackPointer == nil { cells = [:]; epoch += 1; stackPointer = next } else { try adjust(Int128(next)) }
                } else { stackPointer = nil; cells = [:]; epoch += 1 }
            } else { try write(rd, value) }
            return
        }
        if ["nop", "ret", "b", "bcond", "wcbz", "wcbnz", "xcbz", "xcbnz", "wtbz", "wtbnz", "xtbz", "xtbnz"].contains(k) { return }
        if d.word & 0xfffffc1f == 0xf100001f { return }
        if ["adr", "adrp"].contains(k) { try write(rd, nil); return }
        if k == "bl" { registers = [:]; cells = [:]; stackPointer = nil; epoch += 1; return }
        if ["mov", "wmov"].contains(k) { try write(rd, read(rn, bits: bits), bits: bits); return }
        if ["movz", "wmovz", "movn", "wmovn"].contains(k) { try write(rd, constant(k.hasSuffix("movz") ? d.immediate : ~d.immediate, bits), bits: bits); return }
        if ["xmovk", "wmovk"].contains(k) {
            guard let shift = Int(d.addressing), shift >= 0, shift < bits, shift % 16 == 0 else { try fail("move_lane_unqualified") }
            var value: SwiftOutcomeJSON?
            if let old = read(rd, bits: bits) {
                value = tag(old) == "constant" ? constant((number(old) & ~(Int128(0xffff) << shift)) | (d.immediate << shift), bits) : expression("insert_lane", [old, constant(d.immediate, bits), constant(Int128(shift), bits)], bits)
            }
            try write(rd, value, bits: bits); return
        }
        if ["wand_imm", "worr_imm", "weor_imm", "wands_imm", "xand_imm", "xorr_imm", "xeor_imm", "xands_imm"].contains(k) {
            try write(rd, binary(k.contains("orr") ? "orr" : (k.contains("eor") ? "eor" : "and"), read(rn, bits: bits), constant(d.immediate, bits), bits), bits: bits); return
        }
        if ["wcsel", "wcsinc", "wcsinv", "wcsneg", "xcsel", "xcsinc", "xcsinv", "xcsneg"].contains(k) { try write(rd, nil, bits: bits); return }
        if ["wadds_reg", "wsubs_reg", "xadds_reg", "xsubs_reg", "wadd_reg", "wsub_reg"].contains(k) {
            let mode = d.addressing.isEmpty ? "lsl" : d.addressing
            guard ["lsl", "lsr", "asr"].contains(mode) else { try fail("register_shift_unqualified") }
            let right = try shifted(read(d.rt2, bits: bits), bits: bits, mode: mode, amount: d.immediate)
            if rd == 31 { return }
            try write(rd, binary(k.contains("sub") ? "sub" : "add", read(rn, bits: bits), right, bits), bits: bits); return
        }
        if ["wand_reg", "wbic_reg", "worr_reg", "worn_reg", "weor_reg", "weon_reg", "wands_reg", "wbics_reg", "xand_reg", "xbic_reg", "xorr_reg", "xorn_reg", "xeor_reg", "xeon_reg", "xands_reg", "xbics_reg"].contains(k) {
            var right = try shifted(read(d.rt2, bits: bits), bits: bits, mode: d.addressing, amount: d.immediate)
            if rd == 31 { return }
            let op = String(k.dropFirst().dropLast(4))
            if ["bic", "orn", "eon", "bics"].contains(op), let r = right { right = tag(r) == "constant" ? constant(~number(r), bits) : expression("bitwise_not", [r], bits) }
            try write(rd, binary(["orr", "orn"].contains(op) ? "orr" : (["eor", "eon"].contains(op) ? "eor" : "and"), read(rn, bits: bits), right, bits), bits: bits); return
        }
        if ["xadd_reg", "xsub_reg"].contains(k) {
            let left = read(rn), right = read(d.rt2), op = k == "xadd_reg" ? "add" : "sub"
            var value = binary(op, left, right, 64)
            if let l = left, let r = right {
                if tag(l) == "stack_address", tag(r) == "constant" { value = stack(number(l) + (op == "add" ? number(r) : -number(r))) }
                else if op == "add", tag(l) == "constant", tag(r) == "stack_address" { value = stack(number(l) + number(r)) }
            }
            try write(rd, value); return
        }
        if ["add", "sub", "wadd", "wadds", "wsubs", "xadds", "xsubs", "wlsl"].contains(k) {
            if ["add", "sub"].contains(k), rn == 31 {
                guard let stackPointer else { try write(rd, nil); return }
                let n = Int128(stackPointer) + (k == "add" ? d.immediate : -d.immediate)
                if rd == 31 { try adjust(n) } else { try write(rd, stack(n)) }; return
            }
            if rd == 31 { if ["wadds", "wsubs", "xadds", "xsubs"].contains(k) { return }; try fail("unsupported_stack_or_flag_effect") }
            let op = k == "wlsl" ? "lsl" : (k.contains("sub") ? "sub" : "add")
            var value: SwiftOutcomeJSON?
            if let source = read(rn, bits: bits) {
                if tag(source) == "stack_address", ["add", "sub"].contains(k) { value = stack(number(source) + (k == "add" ? d.immediate : -d.immediate)) }
                else if tag(source) == "constant" { value = constant(op == "lsl" ? number(source) << d.immediate : number(source) + (op == "add" ? d.immediate : -d.immediate), bits) }
                else { value = expression(op, [source, constant(d.immediate, bits)], bits) }
            }
            try write(rd, value, bits: bits); return
        }
        if ["xubfm", "wubfm"].contains(k) {
            guard let immr = Int(d.addressing), immr >= 0, immr < bits, d.immediate >= 0, d.immediate < Int128(bits) else { try fail("unsigned_bitfield_unqualified") }
            let imms = Int(d.immediate); var value: SwiftOutcomeJSON?
            if let source = read(rn, bits: bits) {
                if tag(source) == "constant" { value = constant(imms >= immr ? (number(source) >> immr) & mask(imms - immr + 1) : (number(source) & mask(imms + 1)) << (bits - immr), bits) }
                else { value = expression("unsigned_bitfield", [source, constant(Int128(immr), bits), constant(Int128(imms), bits)], bits) }
            }
            try write(rd, value, bits: bits); return
        }
        if ["xsbfm", "wsbfm"].contains(k), d.addressing == "0", d.immediate >= 0, d.immediate < Int128(bits) {
            let n = Int(d.immediate) + 1; var value: SwiftOutcomeJSON?
            if let source = read(rn, bits: bits) {
                if tag(source) == "constant" { var v = number(source) & mask(n); if v & (Int128(1) << (n - 1)) != 0 { v -= Int128(1) << n }; value = constant(v, bits) }
                else { value = expression("sign_extend", [source, constant(Int128(n), bits)], bits) }
            }
            try write(rd, value, bits: bits); return
        }
        if ["xstr", "wstr", "xldr", "wldr", "xldr_post", "stp", "ldp", "wstrb", "wldrb", "wstrh", "wldrh", "xstr_raw", "xldr_raw", "xstur", "xldur", "qstr", "wstr_raw", "wldr_raw", "wstur", "wldur"].contains(k) || SwiftOutcomeInstructionKinds.fpMemoryStores.contains(k) {
            try memory(d, bits: bits); return
        }
        try fail("value_transfer_unqualified")
    }
    private func memory(_ d: SwiftOutcomeInstruction, bits: Int) throws {
        let k = d.kind, rn = d.rn, mode = d.addressing.isEmpty ? "offset" : d.addressing
        let pair = ["stp", "ldp"].contains(k), load = ["xldr", "wldr", "xldr_post", "ldp", "wldrb", "wldrh", "xldr_raw", "xldur", "wldr_raw", "wldur"].contains(k)
        let regs = pair ? [d.rd, d.rt2] : [d.rd]
        guard ["offset", "pre", "post"].contains(mode) else { try fail("memory_mode_unqualified") }
        if load && Set(regs).count != regs.count { try fail("memory_register_overlap") }
        if mode != "offset", rn != 31, regs.contains(rn) { try fail("memory_writeback_overlap") }
        let source = read(rn), base: Int128? = rn == 31 ? stackPointer.map { Int128($0) } : source.flatMap { tag($0) == "stack_address" ? number($0) : nil }
        guard let base, stackPointer != nil else {
            if load { for reg in regs { try write(reg, nil) } } else { cells = [:]; epoch += 1 }
            if ["pre", "post"].contains(mode) { if rn == 31 { stackPointer = nil } else { try write(rn, nil) } }
            return
        }
        let size = pair ? 8 : (SwiftOutcomeInstructionKinds.memoryWidths[k] ?? bits / 8)
        let offset = base + (mode == "post" ? 0 : d.immediate), end = offset + Int128(size * regs.count)
        if mode == "pre", rn == 31 { try adjust(offset) }
        guard offset >= Int128(stackPointer!), end <= 0 else { try fail("memory_outside_frame") }
        let start = try checkedStackOffset(offset)
        if load {
            for (i, reg) in regs.enumerated() {
                let cell = cells[start + i * size]
                try write(reg, cell?.size == size ? cell?.value : nil, bits: size * 8)
            }
        } else {
            cells = cells.filter { Int128($0.key) + Int128($0.value.size) <= offset || Int128($0.key) >= end }; epoch += 1
            for (i, reg) in regs.enumerated() { cells[start + i * size] = Cell(size: size, epoch: epoch, value: SwiftOutcomeInstructionKinds.fpMemoryStores.contains(k) ? nil : read(reg, bits: size * 8)) }
            try bound()
        }
        if ["pre", "post"].contains(mode) {
            if rn == 31 { if mode == "post" { try adjust(base + d.immediate) } }
            else { try write(rn, stack(base + d.immediate)) }
        }
    }
}
