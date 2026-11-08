import Foundation

enum UnwindAuditValue: Hashable, Sendable {
    case original(register: Int, displacement: Int64)
    case stack(displacement: Int64)
    case constant(UInt64)
    case unknown(String)

    var known: Bool {
        if case .unknown = self { return false }
        return true
    }

    var stackDisplacement: Int64? {
        if case let .stack(displacement) = self { return displacement }
        return nil
    }

    var constant: UInt64? {
        if case let .constant(value) = self { return value }
        return nil
    }

    func add(_ amount: Int64) throws -> Self {
        switch self {
        case .unknown: return self
        case let .constant(value): return .constant(value &+ UInt64(bitPattern: amount))
        case let .stack(displacement): return .stack(displacement: try Self.displace(displacement, amount))
        case let .original(register, displacement): return .original(register: register, displacement: try Self.displace(displacement, amount))
        }
    }

    private static func displace(_ value: Int64, _ amount: Int64) throws -> Int64 {
        let (result, overflow) = value.addingReportingOverflow(amount)
        guard !overflow else { throw UnwindAuditModelError(code: "symbolic_displacement_overflow", message: "Symbolic displacement exceeds the bounded integer representation") }
        return result
    }

    func describe() -> String {
        switch self {
        case let .unknown(reason): return "unknown (\(reason))"
        case let .constant(value): return "constant 0x\(String(value, radix: 16))"
        case let .stack(displacement): return "entry SP" + Self.suffix(displacement)
        case let .original(register, displacement): return "original x\(register)" + Self.suffix(displacement)
        }
    }

    private static func suffix(_ displacement: Int64) -> String {
        displacement == 0 ? "" : displacement > 0 ? "+\(displacement)" : String(displacement)
    }
}

struct UnwindAuditNZCV: Hashable, Sendable {
    var n: Bool
    var z: Bool
    var c: Bool
    var v: Bool
}

struct UnwindAuditSnapshot: Hashable, Sendable {
    struct Slot: Hashable, Sendable {
        let offset: Int64
        let value: UnwindAuditValue
    }
    let registers: [UnwindAuditValue]
    let sp: UnwindAuditValue
    let memory: [Slot]
    let words: [Slot]
    let flags: UnwindAuditNZCV?
    let strictCallState: Bool
    let certain: Bool
    let priorCallCount: Int
}

/// Symbolic entry identities stay separate from integer constants and unknown values.
struct UnwindAuditMachine: Sendable {
    typealias Value = UnwindAuditValue
    typealias NZCV = UnwindAuditNZCV
    var registers: [Value] = (0..<31).map { .original(register: $0, displacement: 0) }
    var sp: Value = .stack(displacement: 0)
    var memory: [Int64: Value] = [:]
    var words: [Int64: Value] = [:]
    var flags: NZCV?
    var strictCallState: Bool

    init(strictCallState: Bool = false) { self.strictCallState = strictCallState }

    func snapshot(certain: Bool, priorCallCount: Int) -> UnwindAuditSnapshot {
        UnwindAuditSnapshot(registers: registers, sp: sp,
            memory: memory.sorted { $0.key < $1.key }.map { .init(offset: $0.key, value: $0.value) },
            words: words.sorted { $0.key < $1.key }.map { .init(offset: $0.key, value: $0.value) },
            flags: flags, strictCallState: strictCallState, certain: certain, priorCallCount: priorCallCount)
    }

    func readRegister(_ register: Int) -> Value { register == 31 ? .constant(0) : registers[register] }

    private mutating func writeRegister(_ register: Int, _ value: Value) {
        if register != 31 { registers[register] = value }
    }

    private func readW(_ register: Int) throws -> Value {
        let value = readRegister(register)
        if strictCallState && value.stackDisplacement != nil {
            throw UnwindAuditModelError(code: "stack_address_truncation_not_modeled", message: "W projection of a derived stack address could hide a call escape")
        }
        return value.constant.map { .constant($0 & 0xffffffff) } ?? .unknown("low32 of \(value.describe())")
    }

    private mutating func writeW(_ register: Int, _ value: Value) {
        writeRegister(register, value.constant.map { .constant($0 & 0xffffffff) } ?? .unknown("zero-extended W value with unknown low32"))
    }

    func condition(_ condition: Int) throws -> Bool? {
        guard (0..<14).contains(condition) else {
            throw UnwindAuditModelError(code: "cfg_condition_not_modeled", message: "Only condition codes EQ through LE are supported")
        }
        guard let flags else { return nil }
        let bases = [flags.z, flags.c, flags.n, flags.v, flags.c && !flags.z,
                     flags.n == flags.v, !flags.z && flags.n == flags.v]
        return condition & 1 == 0 ? bases[condition >> 1] : !bases[condition >> 1]
    }

    func branchTaken(_ instruction: UnwindAuditInstruction) throws -> Bool? {
        let kind = instruction.kind
        let compare = ["wcbz", "wcbnz", "xcbz", "xcbnz"].contains(kind)
        let testBit = ["wtbz", "wtbnz", "xtbz", "xtbnz"].contains(kind)
        func fail(_ code: String, _ message: String) -> UnwindAuditModelError {
            UnwindAuditModelError(code: code, message: message, address: instruction.address)
        }
        guard compare || testBit else {
            throw fail("cfg_condition_not_modeled", "Instruction is not a register-conditioned branch")
        }
        var bit = 0
        if testBit {
            guard let parsed = Int(instruction.addressing), (0...63).contains(parsed) else {
                throw fail("cfg_condition_not_modeled", "Test-bit branch requires a bit in 0 through 63")
            }
            bit = parsed
        }
        let source = readRegister(instruction.rn)
        if case .stack = source {
            throw fail(testBit ? "test_bit_branch_stack_address_not_modeled" : "compare_branch_stack_address_not_modeled",
                       "Register-conditioned branch cannot test a derived stack address")
        }
        guard case let .constant(raw) = source else { return nil }
        let value = kind.hasPrefix("w") ? raw & 0xffffffff : raw
        let zero = testBit ? (value & (UInt64(1) << bit)) == 0 : value == 0
        return kind.hasSuffix("nz") ? !zero : zero
    }

    mutating func resumeAfterCall() {
        registers[30] = .unknown("LR after unmodeled callee return")
        flags = nil
    }

    private mutating func setSP(_ value: Value, address: UInt64) throws {
        guard let displacement = value.stackDisplacement else {
            throw UnwindAuditModelError(code: "unknown_stack_pointer", message: "SP is not a known entry-SP displacement", address: address)
        }
        guard displacement <= 0, displacement % 16 == 0 else {
            throw UnwindAuditModelError(code: "unmodeled_stack_alignment", message: "SP must remain aligned within the allocated frame", address: address)
        }
        sp = value
        memory = memory.filter { $0.key >= displacement }
        words = words.filter { $0.key >= displacement }
    }

    private mutating func store(_ offset: Int64, _ value: Value) {
        words = words.filter { !Self.overlap($0.key, 4, offset, 8) }
        memory[offset] = value
    }

    private static func overlap(_ a: Int64, _ aSize: Int64, _ b: Int64, _ bSize: Int64) -> Bool {
        // Valid frame slots are nonpositive and have a representable end.
        a < b + bSize && b < a + aSize
    }

    private func memoryOffset(_ value: Value, size: Int64, alignment: Int64, address: UInt64) throws -> Int64 {
        guard let offset = value.stackDisplacement, let bottom = sp.stackDisplacement else {
            throw UnwindAuditModelError(code: "unknown_memory_address", message: "Memory base is not a known entry-SP displacement", address: address)
        }
        guard offset % alignment == 0, offset >= bottom, offset <= -size else {
            throw UnwindAuditModelError(code: "memory_outside_modeled_frame", message: "Memory access is outside the known allocated stack frame", address: address)
        }
        return offset
    }

    private mutating func applyXMemory(_ instruction: UnwindAuditInstruction) throws {
        let address = instruction.address
        let base = instruction.rn == 31 ? sp : readRegister(instruction.rn)
        if instruction.rn == 29 {
            _ = try memoryOffset(base, size: 8, alignment: 8, address: address)
        }
        let location = try base.add(instruction.immediate)
        let offset = try memoryOffset(location, size: 8, alignment: 8, address: address)
        if instruction.kind == "xstr" {
            store(offset, readRegister(instruction.rd))
        } else {
            guard let value = memory[offset], value.known else {
                throw UnwindAuditModelError(code: "unknown_stack_read",
                    message: "X load requires a known complete 64-bit stack cell", address: address)
            }
            writeRegister(instruction.rd, value)
        }
    }

    mutating func apply(_ instruction: UnwindAuditInstruction) throws {
        let kind = instruction.kind, address = instruction.address
        func fail(_ code: String, _ message: String) -> UnwindAuditModelError {
            UnwindAuditModelError(code: code, message: message, address: address)
        }
        switch kind {
        case "xrbit": try applyRBitX(instruction)
        case "nop", "ret": return
        case "add", "sub":
            let source = instruction.rn == 31 ? sp : readRegister(instruction.rn)
            let amount: Int64
            if kind == "sub" {
                guard instruction.immediate != Int64.min else { throw fail("symbolic_displacement_overflow", "Subtraction magnitude exceeds the symbolic range") }
                amount = -instruction.immediate
            } else { amount = instruction.immediate }
            let value = try source.add(amount)
            if instruction.rd == 31 { try setSP(value, address: address) }
            else { writeRegister(instruction.rd, value) }
        case "mov": writeRegister(instruction.rd, readRegister(instruction.rn))
        case "movz", "movn":
            let value = UInt64(bitPattern: instruction.immediate)
            writeRegister(instruction.rd, .constant(kind == "movz" ? value : ~value))
        case "wmovk", "xmovk":
            let wide = kind == "xmovk"
            guard let shift = Int(instruction.addressing),
                  (wide ? [0, 16, 32, 48] : [0, 16]).contains(shift),
                  (0...65535).contains(instruction.immediate),
                  (0...31).contains(instruction.rd) else {
                throw fail("invalid_movk_effect", "MOVK effect has an invalid lane, immediate or destination")
            }
            // Inspect the raw X value before W projection: never erase stack
            // provenance, including in leaf mode or when the destination is FP.
            let old = readRegister(instruction.rd)
            guard old.stackDisplacement == nil else {
                throw fail("movk_stack_address_not_modeled", "MOVK destination is a derived stack address")
            }
            var value = Value.unknown("MOVK retains unknown bits of its old destination")
            if let raw = old.constant {
                let laneMask = UInt64(0xffff) << shift
                let inserted = UInt64(instruction.immediate) << shift
                value = .constant((raw & ~laneMask) | inserted)
            }
            // Register 31 is ZR, never SP. W writes zero-extend; flags and
            // independently saved stack identities remain unchanged.
            if wide { writeRegister(instruction.rd, value) } else { writeW(instruction.rd, value) }
        case "wcls", "xcls", "wrev", "xrev", "wrev16", "xrev16", "xrev32", "wrbit":
            try applyOneSource(instruction)
        case "stp", "ldp":
            let base = instruction.rn == 31 ? sp : readRegister(instruction.rn)
            let adjusted = try base.add(instruction.immediate)
            let location = instruction.addressing == "post" ? base : adjusted
            if instruction.addressing == "pre" {
                if instruction.rn == 31 { try setSP(adjusted, address: address) }
                else { writeRegister(instruction.rn, adjusted) }
            }
            let offset = try memoryOffset(location, size: 16, alignment: 8, address: address)
            if kind == "stp" {
                store(offset, readRegister(instruction.rd))
                store(offset + 8, readRegister(instruction.rt2))
            } else {
                guard let first = memory[offset], let second = memory[offset + 8], first.known, second.known else {
                    throw fail("unknown_stack_read", "Pair load reads a slot without a known modeled store")
                }
                writeRegister(instruction.rd, first)
                writeRegister(instruction.rt2, second)
            }
            if instruction.addressing == "post" {
                if instruction.rn == 31 { try setSP(adjusted, address: address) }
                else { writeRegister(instruction.rn, adjusted) }
            }
        case "bl":
            guard !registers.prefix(29).contains(where: { $0.stackDisplacement != nil }),
                  !memory.values.contains(where: { $0.stackDisplacement != nil }) else {
                throw fail("stack_address_escapes_call", "A derived stack address may escape to an unmodeled callee")
            }
            let (returnPC, overflow) = address.addingReportingOverflow(4)
            guard !overflow else { throw fail("invalid_instruction_address", "Return address exceeds the address space") }
            for register in 0..<19 { registers[register] = .unknown("x\(register) after direct call") }
            registers[30] = .constant(returnPC)
        case "xstr", "xldr":
            try applyXMemory(instruction)
        case "wstr", "wldr":
            let location = try sp.add(instruction.immediate)
            let offset = try memoryOffset(location, size: 4, alignment: 4, address: address)
            if kind == "wstr" {
                for slot in Array(memory.keys) where Self.overlap(slot, 8, offset, 4) {
                    if strictCallState && memory[slot]?.stackDisplacement != nil {
                        throw fail("partial_stack_address_not_modeled", "Partial store into a derived stack address could hide a call escape")
                    }
                    memory[slot] = .unknown("saved 64-bit value overwritten by a W store")
                }
                words[offset] = try readW(instruction.rd)
            } else {
                let value: Value
                if let cached = words[offset] { value = cached }
                else {
                    // Swift remainder follows the dividend; use an aligned downward mask.
                    let slot = offset & ~Int64(7)
                    guard let saved = memory[slot] else { throw fail("unknown_stack_read", "W load has no modeled prior store") }
                    if strictCallState && saved.stackDisplacement != nil {
                        throw fail("stack_address_truncation_not_modeled", "W load projects a derived stack address")
                    }
                    value = saved.constant.map { .constant(($0 >> Int((offset - slot) * 8)) & 0xffffffff) }
                        ?? .unknown("low32 from a modeled 64-bit store")
                }
                writeW(instruction.rd, value)
            }
        case "wudiv", "xudiv", "wsdiv", "xsdiv":
            try applyDivide(instruction)
        case "b", "bcond", "wcbz", "wcbnz", "xcbz", "xcbnz", "wtbz", "wtbnz", "xtbz", "xtbnz": throw fail("cfg_edge_requires_dispatch", "Branches require CFG successor dispatch")
        default:
            try applyArithmetic(instruction)
        }
    }

    private mutating func applyOneSource(_ instruction: UnwindAuditInstruction) throws {
        let raw = readRegister(instruction.rn)
        let kind = instruction.kind
        if raw.stackDisplacement != nil {
            let operation = kind.hasSuffix("cls") ? "cls" : kind == "wrbit" ? "rbit" : "rev"
            throw UnwindAuditModelError(code: "\(operation)_stack_address_not_modeled",
                message: "One-source operand is a derived stack address", address: instruction.address)
        }
        let wide = kind.hasPrefix("x"), width = wide ? 64 : 32
        let mask: UInt64 = wide ? .max : 0xffffffff
        var value = Value.unknown("One-source operand is not a concrete width-bounded value")
        if let constant = raw.constant {
            let bits = constant & mask
            switch kind {
            case "wcls", "xcls":
                let sign = UInt64(1) << (width - 1)
                let normalized = bits & sign == 0 ? bits : (~bits & mask)
                let count = normalized == 0 ? width - 1 : normalized.leadingZeroBitCount - (64 - width) - 1
                value = .constant(UInt64(count))
            case "wrev", "xrev":
                var source = bits, result: UInt64 = 0
                for _ in 0..<(width / 8) {
                    result = (result << 8) | (source & 0xff)
                    source >>= 8
                }
                value = .constant(result)
            case "wrev16", "xrev16", "xrev32":
                let byteLow: UInt64 = wide ? 0x00ff00ff00ff00ff : 0x00ff00ff
                var result = ((bits & byteLow) << 8) | ((bits >> 8) & byteLow)
                if kind == "xrev32" {
                    let halfwordLow: UInt64 = 0x0000ffff0000ffff
                    result = ((result & halfwordLow) << 16) | ((result >> 16) & halfwordLow)
                }
                value = .constant(result)
            case "wrbit":
                var source = bits, result: UInt64 = 0
                for _ in 0..<32 {
                    result = (result << 1) | (source & 1)
                    source >>= 1
                }
                value = .constant(result)
            default:
                throw UnwindAuditModelError(code: "unsupported_instruction",
                    message: "Unknown one-source effect", address: instruction.address)
            }
        }
        if wide { writeRegister(instruction.rd, value) } else { writeW(instruction.rd, value) }
    }

    private mutating func applyDivide(_ instruction: UnwindAuditInstruction) throws {
        let left = readRegister(instruction.rn)
        let right = readRegister(instruction.rt2)
        let signed = instruction.kind == "wsdiv" || instruction.kind == "xsdiv"
        guard left.stackDisplacement == nil, right.stackDisplacement == nil else {
            throw UnwindAuditModelError(
                code: signed ? "sdiv_stack_address_not_modeled" : "udiv_stack_address_not_modeled",
                message: "Division source is a derived stack address", address: instruction.address)
        }
        let wide = instruction.kind.hasPrefix("x")
        let mask: UInt64 = wide ? .max : 0xffffffff
        var value = Value.unknown("Both division sources must be concrete")
        if let rawLeft = left.constant, let rawRight = right.constant {
            let numerator = rawLeft & mask, divisor = rawRight & mask
            let quotient: UInt64
            if divisor == 0 {
                quotient = 0
            } else if signed {
                let sign: UInt64 = wide ? 1 << 63 : 1 << 31
                let negativeLeft = numerator & sign != 0
                let negativeRight = divisor & sign != 0
                let magnitudeLeft = negativeLeft ? (0 &- numerator) & mask : numerator
                let magnitudeRight = negativeRight ? (0 &- divisor) & mask : divisor
                let magnitude = magnitudeLeft / magnitudeRight
                quotient = (negativeLeft != negativeRight ? 0 &- magnitude : magnitude) & mask
            } else {
                quotient = numerator / divisor
            }
            value = .constant(quotient)
        }
        if wide { writeRegister(instruction.rd, value) } else { writeW(instruction.rd, value) }
    }

    private mutating func applyArithmetic(_ instruction: UnwindAuditInstruction) throws {
        let kind = instruction.kind, wide = instruction.kind.hasPrefix("x")
        let mask: UInt64 = wide ? .max : 0xffffffff
        let sign: UInt64 = wide ? 1 << 63 : 1 << 31
        func fail(_ code: String, _ message: String) -> UnwindAuditModelError {
            UnwindAuditModelError(code: code, message: message, address: instruction.address)
        }
        func projected(_ register: Int) throws -> Value { wide ? readRegister(register) : try readW(register) }
        func rejectStack(_ values: Value..., code: String) throws {
            if wide && values.contains(where: { $0.stackDisplacement != nil }) {
                throw fail(code, "Arithmetic on a derived stack address is outside this subset")
            }
        }
        let arithmeticKinds: Set<String> = ["wadd", "wadds", "wsubs", "xadds", "xsubs", "wadds_reg", "wsubs_reg", "xadds_reg", "xsubs_reg", "wadds_ext", "wsubs_ext", "xadds_ext", "xsubs_ext"]
        if arithmeticKinds.contains(kind) {
            let source = try projected(instruction.rn)
            let operand = kind.hasSuffix("_reg") || kind.hasSuffix("_ext")
                ? try projected(instruction.rt2) : .constant(UInt64(bitPattern: instruction.immediate))
            try rejectStack(source, operand, code: "flag_stack_address_not_modeled")
            let producesFlags = kind != "wadd"
            var value = Value.unknown("Arithmetic operand is not a concrete width-bounded value")
            if let rawLeft = source.constant, let rawRight = operand.constant {
                let left = rawLeft & mask
                var right = rawRight & mask
                if kind.hasSuffix("_ext") {
                    let bits: [String: Int] = ["uxtb": 8, "uxth": 16, "uxtw": 32, "uxtx": 64, "sxtb": 8, "sxth": 16, "sxtw": 32, "sxtx": 64]
                    guard let width = bits[instruction.addressing] else { throw fail("cfg_extend_not_modeled", "Unknown extension") }
                    if width < 64 {
                        let narrowMask = (UInt64(1) << width) - 1
                        right &= narrowMask
                        if instruction.addressing.hasPrefix("s"), right & (UInt64(1) << (width - 1)) != 0 { right |= ~narrowMask }
                    }
                    right = (right << Int(instruction.immediate)) & mask
                } else if kind.hasSuffix("_reg") {
                    right = try Self.shift(right, addressing: instruction.addressing, amount: instruction.immediate, wide: wide)
                }
                let subtract = kind.contains("subs")
                let result = subtract ? (left &- right) & mask : (left &+ right) & mask
                if producesFlags {
                    flags = NZCV(n: result & sign != 0, z: result == 0,
                        c: subtract ? left >= right : (wide ? left.addingReportingOverflow(right).overflow : left + right > mask),
                        v: subtract ? (left ^ right) & (left ^ result) & sign != 0 : ~(left ^ right) & (left ^ result) & sign != 0)
                }
                value = .constant(result)
            } else if producesFlags { flags = nil }
            if wide { writeRegister(instruction.rd, value) } else { writeW(instruction.rd, value) }
            return
        }
        let selectKinds: Set<String> = ["wcsel", "wcsinc", "wcsinv", "wcsneg", "xcsel", "xcsinc", "xcsinv", "xcsneg"]
        if selectKinds.contains(kind) {
            let left = try projected(instruction.rn)
            var right = try projected(instruction.rt2)
            try rejectStack(left, right, code: "conditional_select_stack_address_not_modeled")
            guard let code = Int(instruction.addressing) else { throw fail("cfg_condition_not_modeled", "Missing condition") }
            let predicate = try condition(code)
            if !kind.hasSuffix("csel") {
                if let raw = right.constant {
                    let transformed = kind.hasSuffix("csinc") ? raw &+ 1 : kind.hasSuffix("csinv") ? ~raw : 0 &- raw
                    right = .constant(transformed & mask)
                } else { right = .unknown("Conditional-select transformed operand is not concrete") }
            }
            let value = predicate.map { $0 ? left : right } ?? (left == right ? left : .unknown("Conditional select alternatives differ under unknown flags"))
            if wide { writeRegister(instruction.rd, value) } else { writeW(instruction.rd, value) }
            return
        }
        let carryKinds: Set<String> = ["wadc", "wadcs", "wsbc", "wsbcs", "xadc", "xadcs", "xsbc", "xsbcs"]
        if carryKinds.contains(kind) {
            let left = try projected(instruction.rn), right = try projected(instruction.rt2)
            try rejectStack(left, right, code: "carry_stack_address_not_modeled")
            let carry = flags?.c
            let setsFlags = kind.hasSuffix("s")
            if setsFlags { flags = nil }
            var value = Value.unknown("Carry input or operands are not concrete width-bounded values")
            if let carry, let a = left.constant, let b = right.constant {
                let rhs = kind.contains("sbc") ? ~b & mask : b & mask
                let calculation = Self.addWithCarry(a & mask, rhs, carry: carry, wide: wide)
                value = .constant(calculation.0)
                if setsFlags { flags = calculation.1 }
            }
            if wide { writeRegister(instruction.rd, value) } else { writeW(instruction.rd, value) }
            return
        }
        if kind.contains("ccmp_") || kind.contains("ccmn_") {
            guard let code = Int(instruction.addressing) else { throw fail("cfg_condition_not_modeled", "Missing condition") }
            let predicate = try condition(code)
            if predicate == false {
                let bits = instruction.immediate
                flags = .init(n: bits & 8 != 0, z: bits & 4 != 0, c: bits & 2 != 0, v: bits & 1 != 0)
                return
            }
            let left = try projected(instruction.rn)
            let right = kind.hasSuffix("_imm") ? Value.constant(UInt64(instruction.rt2)) : try projected(instruction.rt2)
            try rejectStack(left, right, code: "conditional_compare_stack_address_not_modeled")
            flags = nil
            if predicate == true, let a = left.constant, let b = right.constant {
                let subtract = kind.contains("ccmp")
                flags = Self.addWithCarry(a & mask, subtract ? ~b & mask : b & mask, carry: subtract, wide: wide).1
            }
            return
        }
        throw fail("unsupported_effect", "No symbolic effect exists for this instruction")
    }

    private static func shift(_ value: UInt64, addressing: String, amount: Int64, wide: Bool) throws -> UInt64 {
        let width = wide ? 64 : 32, mask: UInt64 = wide ? .max : 0xffffffff
        guard amount >= 0, amount < Int64(width) else { throw UnwindAuditModelError(code: "cfg_shift_not_modeled", message: "Shift exceeds operand width") }
        let count = Int(amount)
        switch addressing {
        case "lsl": return (value << count) & mask
        case "lsr": return value >> count
        case "asr":
            if wide { return UInt64(bitPattern: Int64(bitPattern: value) >> count) }
            return UInt64(UInt32(bitPattern: Int32(bitPattern: UInt32(truncatingIfNeeded: value)) >> count))
        default: throw UnwindAuditModelError(code: "cfg_shift_not_modeled", message: "Shift is outside the bounded subset")
        }
    }

    private static func addWithCarry(_ a: UInt64, _ b: UInt64, carry: Bool, wide: Bool) -> (UInt64, NZCV) {
        let mask: UInt64 = wide ? .max : 0xffffffff, sign: UInt64 = wide ? 1 << 63 : 1 << 31
        let first = a.addingReportingOverflow(b)
        let second = first.partialValue.addingReportingOverflow(carry ? 1 : 0)
        let result = second.partialValue & mask
        let carryOut = wide ? first.overflow || second.overflow : a + b + (carry ? 1 : 0) > mask
        return (result, .init(n: result & sign != 0, z: result == 0, c: carryOut,
                              v: ~(a ^ b) & (a ^ result) & sign != 0))
    }
}

extension UnwindAuditMachine {
    fileprivate mutating func applyRBitX(_ instruction: UnwindAuditInstruction) throws {
        let raw = readRegister(instruction.rn)
        guard raw.stackDisplacement == nil else {
            throw UnwindAuditModelError(code: "rbit_stack_address_not_modeled",
                message: "RBIT source is a derived stack address", address: instruction.address)
        }
        var value = Value.unknown("RBIT X source must be concrete")
        if var bits = raw.constant {
            var reversed: UInt64 = 0
            for _ in 0..<64 {
                reversed = (reversed << 1) | (bits & 1)
                bits >>= 1
            }
            value = .constant(reversed)
        }
        // Register 31 is ZR. X writes retain the full mirrored value.
        writeRegister(instruction.rd, value)
    }
}
