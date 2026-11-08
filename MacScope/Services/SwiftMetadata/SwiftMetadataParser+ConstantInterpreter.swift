import Foundation

/// Shared bounded constant propagation and stub resolution; opaque metadata retains its original kills.
struct SwiftMetadataConstantInterpreter {
    let parser: SwiftMetadataParser
    enum Value: Equatable { case address(UInt64), bound(String), incoming, allocated(UInt64) }
    static func signed(_ bits: UInt32, width: Int) -> Int64 {
        Int64(Int32(bitPattern: bits << (32 - width)) >> (32 - width))
    }
    static func target(_ pc: UInt64, _ displacement: Int64) -> UInt64? {
        if displacement >= 0 {
            let (value, overflow) = pc.addingReportingOverflow(UInt64(displacement))
            return overflow ? nil : value
        }
        let (value, overflow) = pc.subtractingReportingOverflow(UInt64(-displacement))
        return overflow ? nil : value
    }
    func loaded(_ slot: UInt64) -> Value? {
        if let name = parser.bindNames[slot] { return .bound(name) }
        if let target = parser.rebaseTargets[slot] { return .address(target) }
        return rawPointer(at: slot).map { .address($0) }
    }

    /// Raw fallback only: use the shared whole-span proof, then decode exactly
    /// those file bytes. Explicit fixups do not require a raw readable footprint.
    private func rawPointer(at slot: UInt64) -> UInt64? {
        guard let span = parser.uniqueFileBackedSpan(atVA: slot, width: 8) else { return nil }
        // Do not remap independent halves through readU64/readU32 after the proof.
        var value: UInt64 = 0
        for index in 0..<8 {
            value |= UInt64(parser.bytes[span.fileOffset + index]) << (index * 8)
        }
        return value
    }
    @discardableResult
    func step(_ word: UInt32, _ pc: UInt64, _ registers: inout [Int: Value]) -> Bool {
        var supported = true
        let rd = Int(word & 31), rn = Int((word >> 5) & 31)
        if word & 0x1f000000 == 0x10000000 { // ADR / ADRP
            let immediate = Self.signed(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), width: 21)
            let page = word & 0x80000000 != 0
            registers[rd] = Self.target(page ? pc & ~0xfff : pc, page ? immediate * 4096 : immediate).map { .address($0) }
        } else if word & 0xff800000 == 0x91000000 { // ADD Xd, Xn, #imm
            if rn != 31, case let .address(base)? = registers[rn] {
                let amount = UInt64((word >> 10) & 0xfff) << (word & 0x400000 == 0 ? 0 : 12)
                let (value, overflow) = base.addingReportingOverflow(amount)
                registers[rd] = overflow ? nil : .address(value)
            } else { registers[rd] = nil }
        } else if word & 0xffc00000 == 0xf9400000 { // LDR Xt, [Xn, #imm]
            if rn != 31, case let .address(base)? = registers[rn] {
                let (slot, overflow) = base.addingReportingOverflow(UInt64((word >> 10) & 0xfff) * 8)
                registers[rd] = overflow ? nil : loaded(slot)
            } else { registers[rd] = nil }
        } else if word & 0xff000000 == 0x58000000 { // LDR Xt, label
            registers[rd] = Self.target(pc, Self.signed((word >> 5) & 0x7ffff, width: 19) * 4).flatMap(loaded)
        } else if word & 0xffe0ffe0 == 0xaa0003e0 { // MOV Xd, Xm
            registers[rd] = registers[Int((word >> 16) & 31)]
        } else if word & 0x1f800000 == 0x12800000 { // move-wide writes only Rd
            registers[rd] = nil
        } else if word == 0xd503201f { // NOP
        } else {
            registers.removeAll(keepingCapacity: true)
            supported = false
        }
        registers[31] = nil
        return supported
    }
    func runtime(_ value: Value?) -> String? {
        guard let value else { return nil }
        if case let .bound(name) = value { return name }
        guard case let .address(start) = value,
              parser.sections.contains(where: { $0.name.contains("stubs") && start >= $0.address && start - $0.address < $0.size }) else { return nil }
        var registers: [Int: Value] = [:]
        for index in 0..<8 {
            guard start <= UInt64.max - UInt64(index * 4) else { return nil }
            let pc = start + UInt64(index * 4)
            guard let word = parser.readU32(atVA: pc) else { return nil }
            if word & 0xfffffc1f == 0xd61f0000 {
                if case let .bound(name)? = registers[Int((word >> 5) & 31)] { return name }
                return nil
            }
            step(word, pc, &registers)
        }
        return nil
    }
}

/// Exact numeric facts used only for allocator arguments. Pointer and context
/// identities remain owned by the existing constant interpreter.
struct SwiftAsyncAllocationSizeState {
    private struct Fact {
        var value: UInt64
        var definition: UInt64
        var loadAddress: UInt64?
    }
    private var values: [Int: Fact] = [:]

    mutating func reset() { values.removeAll(keepingCapacity: true) }

    func argument() -> SwiftAsyncOutgoingAllocation? {
        guard let fact = values[0], fact.value >= 16, fact.value <= 1_048_576,
              fact.value % 16 == 0 else { return nil }
        return .init(size: UInt32(fact.value), sizeInstruction: fact.definition,
                     loadAddress: fact.loadAddress)
    }

    /// Returns whether this is an understood scalar instruction. The caller
    /// still gives the pointer interpreter first refusal and resets at calls.
    mutating func step(_ word: UInt32, at pc: UInt64, image: SwiftAsyncContinuationImage,
                       registers: [Int: SwiftMetadataConstantInterpreter.Value],
                       memoryUnknown: Bool) -> Bool {
        guard let (actual, decoded) = image.instruction(pc), actual == word,
              decoded.mnemonic != "unknown", decoded.mnemonic != "unavailable" else {
            reset(); return false
        }
        let rd = Int(word & 31), rn = Int((word >> 5) & 31)
        let wide = word & 0x80000000 != 0
        let width: UInt32 = wide ? 64 : 32
        let mask = wide ? UInt64.max : UInt64(UInt32.max)
        func operand(_ register: Int) -> Fact? {
            if register == 31 { return .init(value: 0, definition: pc, loadAddress: nil) }
            guard var fact = values[register] else { return nil }
            fact.value &= mask
            return fact
        }
        func result(_ value: UInt64, loadAddress: UInt64? = nil) -> Fact {
            .init(value: value, definition: pc, loadAddress: loadAddress)
        }

        if word & 0x1f800000 == 0x12800000 { // MOVN/MOVZ/MOVK, W or X
            let operation = (word >> 29) & 3, lane = (word >> 21) & 3
            guard operation != 1, lane < width / 16 else { values[rd] = nil; return false }
            let shift = lane * 16
            let immediate = UInt64((word >> 5) & 0xffff) << shift
            if operation == 0 {
                values[rd] = result((~immediate) & mask)
            } else if operation == 2 {
                values[rd] = result(immediate)
            } else if let old = operand(rd) {
                // Combining a prior value and an immediate is not a direct load.
                values[rd] = result((old.value & ~(UInt64(0xffff) << shift)) | immediate)
            } else { values[rd] = nil }
            values[31] = nil
            return true
        }

        if word & 0x7fe0ffe0 == 0x2a0003e0 { // MOV Wd,Wm / MOV Xd,Xm
            if let source = operand(Int((word >> 16) & 31)) {
                values[rd] = result(source.value, loadAddress: source.loadAddress)
            } else { values[rd] = nil }
            values[31] = nil
            return true
        }

        let immediateArithmetic = word & 0x1f800000 == 0x11000000 && word & 0x20000000 == 0
        let registerArithmetic = word & 0x1f200000 == 0x0b000000 && word & 0x20000000 == 0
        if immediateArithmetic || registerArithmetic {
            // Immediate forms name SP, not ZR; this state never invents its value.
            guard !immediateArithmetic || (rn != 31 && rd != 31) else {
                values[rd] = nil; return false
            }
            let left = operand(rn)
            var right: UInt64?
            if immediateArithmetic {
                right = UInt64((word >> 10) & 0xfff) << (word & 0x400000 == 0 ? 0 : 12)
            } else {
                let shift = (word >> 10) & 0x3f, kind = (word >> 22) & 3
                guard shift < width, kind < 3 else { values[rd] = nil; return false }
                if let source = operand(Int((word >> 16) & 31)) {
                    switch kind {
                    case 0: // LSL: discard an overflowing expression instead of wrapping.
                        if source.value <= mask >> shift { right = source.value << shift }
                    case 1: right = source.value >> shift
                    default:
                        let signed = wide ? Int64(bitPattern: source.value) : Int64(Int32(bitPattern: UInt32(source.value)))
                        right = UInt64(bitPattern: signed >> shift) & mask
                    }
                }
            }
            if let left, let right {
                let subtract = word & 0x40000000 != 0
                let (value, overflow) = subtract
                    ? left.value.subtractingReportingOverflow(right)
                    : left.value.addingReportingOverflow(right)
                values[rd] = !overflow && value <= mask ? result(value) : nil
            } else { values[rd] = nil }
            values[31] = nil
            return true
        }

        let unsignedLoad = word & 0xbfc00000 == 0xb9400000 // LDR Wt/Xt,[Xn,#imm]
        let literalLoad = word & 0xbf000000 == 0x18000000 // LDR Wt/Xt,label
        if unsignedLoad || literalLoad {
            // LDR uses bit 30 for register width, unlike the arithmetic forms.
            let bytes: UInt64 = word & 0x40000000 != 0 ? 8 : 4
            let slot: UInt64?
            if unsignedLoad, rn != 31, case let .address(base)? = registers[rn] {
                let (address, overflow) = base.addingReportingOverflow(UInt64((word >> 10) & 0xfff) * bytes)
                slot = overflow ? nil : address
            } else if literalLoad {
                slot = SwiftMetadataConstantInterpreter.target(pc,
                    SwiftMetadataConstantInterpreter.signed((word >> 5) & 0x7ffff, width: 19) * 4)
            } else { slot = nil }
            if !memoryUnknown, let slot,
               let loaded = image.allocationScalar(at: slot, byteWidth: bytes) {
                values[rd] = result(loaded, loadAddress: slot)
            } else { values[rd] = nil }
            values[31] = nil
            return true
        }

        if decoded.flow == .call || decoded.flow == .indirectCall {
            // The parent consumes the old argument before clearing at the call.
            return false
        }
        if word & 0x1f800000 == 0x12000000 {
            // Logical-immediate decoder sidecars can omit operands. Its encoded
            // destination is still exact; an unrelated frame-mask must not erase X0.
            values[rd] = nil
            return false
        }
        if let envelope = decoded.structuredOperands, envelope.coverage == .complete {
            if envelope.semantics?.memoryAccess == .write {
                for operand in envelope.operands {
                    if case let .memory(memory) = operand, memory.writeback { values[memory.base.index] = nil }
                }
                return false
            }
            if envelope.semantics?.memoryAccess == .read {
                for operand in envelope.operands {
                    if case let .register(destination) = operand { values[destination.index] = nil }
                    if case let .memory(memory) = operand, memory.writeback { values[memory.base.index] = nil }
                }
                return false
            }
            if decoded.flow == .jump || decoded.flow == .conditionalJump || decoded.flow == .indirectJump
                || decoded.flow == .return || decoded.flow == .trap { return false }
            if case let .register(destination)? = envelope.operands.first {
                values[destination.index] = nil
            }
        } else if word != 0xd503201f {
            reset()
        }
        return false
    }
}

extension SwiftAsyncContinuationImage {
    /// Exact readable scalar bytes, excluding relocation-backed pointers and
    /// overlapping/partial mappings. This assigns no metadata meaning to a slot.
    fileprivate func allocationScalar(at slot: UInt64, byteWidth: UInt64) -> UInt64? {
        guard byteWidth == 4 || byteWidth == 8, slot <= UInt64.max - (byteWidth - 1) else { return nil }
        let mappings = parser.sections.filter { section in
            guard section.size > 0 else { return false }
            return slot >= section.address ? slot - section.address < section.size : section.address - slot < byteWidth
        }
        guard mappings.count == 1, let section = mappings.first, !section.isZeroFill,
              slot >= section.address, section.size >= byteWidth,
              slot - section.address <= section.size - byteWidth else { return nil }
        func overlapsPointer(_ address: UInt64) -> Bool {
            address <= slot ? slot - address < 8 : address - slot < byteWidth
        }
        guard !parser.bindNames.keys.contains(where: overlapsPointer),
              !parser.rebaseTargets.keys.contains(where: overlapsPointer) else { return nil }
        return byteWidth == 4 ? parser.readU32(atVA: slot).map(UInt64.init) : parser.readU64(atVA: slot)
    }

    /// Resolving an allocator name alone does not prove the requested size:
    /// its executable stub must also preserve the caller's complete X0 value.
    func allocatorPreservesSizeArgument(_ target: SwiftMetadataConstantInterpreter.Value?) -> Bool {
        runtimePreservesArgument(target, names: ["_swift_task_alloc", "swift_task_alloc"])
    }

    func runtimePreservesArgument(_ target: SwiftMetadataConstantInterpreter.Value?, names: Set<String>,
                                 preserveContext: Bool = false, preserveArgument: Bool = true) -> Bool {
        guard case let .address(start)? = target,
              parser.sections.contains(where: { section in
                  section.name.contains("stubs") && start >= section.address
                      && start - section.address < section.size
              }) else { return false }
        var registers: [Int: SwiftMetadataConstantInterpreter.Value] = [0: .incoming]
        if preserveContext { for register in 19...29 { registers[register] = .allocated(UInt64(register)) } }
        for index in 0..<8 {
            guard let pc = SwiftMetadataConstantInterpreter.target(start, Int64(index * 4)),
                  let (word, decoded) = instruction(pc), decoded.mnemonic != "unknown",
                  decoded.mnemonic != "unavailable" else { return false }
            if decoded.mnemonic == "br" {
                guard !preserveArgument || registers[0] == .incoming,
                      case let .bound(name)? = registers[Int((word >> 5) & 31)] else { return false }
                return names.contains(name) && (!preserveContext || (19...29).allSatisfy {
                    registers[$0] == .allocated(UInt64($0))
                })
            }
            if preserveContext {
                guard let operands = decoded.structuredOperands, operands.coverage == .complete,
                      operands.semantics?.memoryAccess != .write,
                      !operands.operands.contains(where: { operand in
                          if case let .register(value) = operand { return value.role == .stackPointer }
                          if case let .memory(value) = operand { return value.writeback }
                          return false
                      }) else { return false }
            }
            guard decoded.branchTarget == nil, decoded.flow != .call, decoded.flow != .indirectCall,
                  decoded.flow != .jump, decoded.flow != .conditionalJump, decoded.flow != .indirectJump,
                  decoded.flow != .return, decoded.flow != .trap,
                  interpreter.step(word, pc, &registers) else { return false }
        }
        return false
    }

}
