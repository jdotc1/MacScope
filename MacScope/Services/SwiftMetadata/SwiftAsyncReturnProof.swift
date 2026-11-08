import Foundation

/// A bounded return within a separately verified invocation path. Header facts
/// refer to live context objects, never to bytes read from the static image.
enum SwiftAsyncReturnProof {
    private enum Value: Equatable {
        case current, parent, child, currentResume, childResume
        case address(UInt64), bound(String)

        var constant: SwiftMetadataConstantInterpreter.Value? {
            switch self {
            case let .address(address): return .address(address)
            case let .bound(name): return .bound(name)
            default: return nil
            }
        }
    }

    private enum Outcome { case next, returned, refused }

    private struct State {
        var registers: [Int: Value]
        let asyncRegister: Int
        let currentSize: UInt32?
        let childSize: UInt32?
        var childAlive: Bool
        var epoch = 0
        var stackOffset: Int64? = 0

        init(asyncRegister: Int, currentSize: UInt32?, returningChild: SwiftAsyncContinuationCertificate?) {
            self.asyncRegister = asyncRegister
            self.currentSize = currentSize
            childSize = returningChild?.outgoingAllocation?.size
            childAlive = returningChild != nil
            registers = [asyncRegister: returningChild == nil ? .current : .child]
        }

        /// The instruction reducer knows no certificate or producer result.
        mutating func step(_ word: UInt32, at pc: UInt64, decoded: DecodedInstruction,
                           image: SwiftAsyncContinuationImage) -> Outcome {
            if decoded.mnemonic == "br" {
                return registers[Int((word >> 5) & 31)] == .currentResume
                    && registers[asyncRegister] == .current ? .returned : .refused
            }
            if decoded.flow == .call || decoded.flow == .indirectCall {
                guard decoded.mnemonic == "bl", childAlive, registers[0] == .child,
                      registers[asyncRegister] == .current,
                      let target = decoded.branchTarget,
                      SwiftAsyncReturnProof.isPreservingDeallocator(target, image: image) else { return .refused }
                childAlive = false
                registers = registers.filter { $0.value != .child && $0.value != .childResume }
                for register in 0...18 { registers[register] = nil }
                registers[30] = nil
                epoch += 1
                return .next
            }
            if decoded.flow == .jump || decoded.flow == .conditionalJump || decoded.flow == .indirectJump
                || decoded.flow == .return || decoded.flow == .trap { return .refused }

            if (word & 0xff800000 == 0x91000000 || word & 0xff800000 == 0xd1000000),
               word & 31 == 31, decoded.structuredOperands?.coverage == .complete {
                if (word >> 5) & 31 == 31, let old = stackOffset {
                    let amount = Int64((word >> 10) & 0xfff) << (word & 0x400000 == 0 ? 0 : 12)
                    let (next, overflow) = old.addingReportingOverflow(word & 0x40000000 == 0 ? amount : -amount)
                    stackOffset = !overflow && next <= 0 && next >= -1_048_576 && next % 16 == 0 ? next : nil
                } else { stackOffset = nil }
                registers[31] = nil
                return .next
            }
            if let envelope = decoded.structuredOperands {
                if envelope.semantics?.memoryAccess != .write,
                   case let .register(destination)? = envelope.operands.first,
                   destination.role == .stackPointer { stackOffset = nil }
                for operand in envelope.operands {
                    if case let .memory(memory) = operand,
                       memory.writeback && memory.base.role == .stackPointer { stackOffset = nil }
                }
            }

            if let envelope = decoded.structuredOperands, envelope.coverage == .complete,
               let memory = envelope.operands.compactMap({ operand -> InstructionOperands.Memory? in
                   if case let .memory(value) = operand { return value }; return nil
               }).first {
                let data = envelope.operands.compactMap { operand -> InstructionOperands.Register? in
                    if case let .register(value) = operand { return value }; return nil
                }
                if envelope.semantics?.memoryAccess == .write {
                    guard ["str", "stur", "stp"].contains(decoded.mnemonic),
                          memory.index == nil, !memory.writeback, memory.indexing == .offset,
                          memory.base.width == 64, envelope.semantics?.memoryAccessWidth == 64,
                          data.count == (decoded.mnemonic == "stp" ? 2 : 1),
                          data.allSatisfy({ $0.bank == .general && $0.width == 64 }) else { return .refused }
                    let width = Int64(data.count * 8)
                    if memory.base.role == .stackPointer, let reserved = stackOffset,
                       memory.displacement >= 0 {
                        let (start, firstOverflow) = reserved.addingReportingOverflow(memory.displacement)
                        let (end, lastOverflow) = start.addingReportingOverflow(width)
                        if !firstOverflow && !lastOverflow && start >= reserved && end <= 0 { return .next }
                    }
                    guard memory.base.role == .ordinary,
                          let size = extent(of: registers[memory.base.index]),
                          memory.displacement >= 16,
                          memory.displacement <= Int64(size) - width else { return .refused }
                    return .next
                }
                if envelope.semantics?.memoryAccess == .read {
                    let base = memory.base.role == .ordinary ? registers[memory.base.index] : nil
                    if base == .current || base == .child || base == .parent {
                        guard base != .parent, base != .child || childAlive,
                              ["ldr", "ldur", "ldp"].contains(decoded.mnemonic),
                              memory.index == nil, !memory.writeback, memory.indexing == .offset,
                              memory.base.width == 64, envelope.semantics?.memoryAccessWidth == 64,
                              data.count == (decoded.mnemonic == "ldp" ? 2 : 1),
                              data.allSatisfy({ $0.bank == .general && $0.width == 64 }) else { return .refused }
                        let destinations = data.filter { $0.role == .ordinary }.map(\.index)
                        guard Set(destinations).count == destinations.count else { return .refused }
                        // Resolve every lane against the old base before changing
                        // X22 in LDR X22,[X22] or either destination in an LDP.
                        var loaded: [Value?] = []
                        for lane in data.indices {
                            let (offset, overflow) = memory.displacement.addingReportingOverflow(Int64(lane * 8))
                            guard !overflow else { return .refused }
                            if offset == 0 { loaded.append(base == .current ? .parent : .current) }
                            else if offset == 8 { loaded.append(base == .current ? .currentResume : .childResume) }
                            else {
                                guard offset >= 16, let size = extent(of: base),
                                      offset <= Int64(size) - 8 else { return .refused }
                                loaded.append(nil)
                            }
                        }
                        for (index, destination) in data.enumerated() where destination.role == .ordinary {
                            registers[destination.index] = loaded[index]
                        }
                        registers[31] = nil
                        return .next
                    }
                    // Other reads never manufacture context/header identities.
                    // Preserve ordinary constant loads for runtime-target setup.
                    if ["ldr", "ldur", "ldp", "ldpsw", "ldrsw", "ldrb", "ldrh"].contains(decoded.mnemonic),
                       word & 0xffc00000 != 0xf9400000 {
                        for destination in data where destination.bank == .general { registers[destination.index] = nil }
                        if memory.writeback { registers[memory.base.index] = nil }
                        return .next
                    }
                }
            }

            if word & 0xffe0ffe0 == 0xaa0003e0 { // MOV Xd,Xm retains identities and header tokens.
                registers[Int(word & 31)] = registers[Int((word >> 16) & 31)]
                registers[31] = nil
                return .next
            }
            if word & 0x1f800000 == 0x12000000,
               ["and", "orr", "eor", "ands", "tst", "mov"].contains(decoded.mnemonic) {
                if word & 31 == 31 && word & 0x60000000 != 0x60000000 { stackOffset = nil }
                registers[Int(word & 31)] = nil
                return .next
            }
            if let envelope = decoded.structuredOperands, envelope.coverage == .complete,
               envelope.opcodeClass == "sub", case let .register(destination)? = envelope.operands.first {
                registers[destination.index] = nil
                return .next
            }
            // Keep context tokens out of the pointer interpreter. It may only
            // define the encoded destination; unrelated tokens stay live.
            var constants = registers.compactMapValues(\.constant)
            guard image.interpreter.step(word, pc, &constants) else { return .refused }
            if word != 0xd503201f {
                let destination = Int(word & 31)
                switch constants[destination] {
                case let .address(address)?: registers[destination] = .address(address)
                case let .bound(name)?: registers[destination] = .bound(name)
                default: registers[destination] = nil
                }
            }
            registers[31] = nil
            return .next
        }

        private func extent(of value: Value?) -> UInt32? {
            if value == .current { return currentSize }
            if value == .child, childAlive { return childSize }
            return nil
        }
    }

    static func prove(source: UInt64, caller: SwiftAsyncContinuationCertificate,
                      previousReturnDigest: String?, returningChild: SwiftAsyncContinuationCertificate?,
                      currentSize: UInt32?, image: SwiftAsyncContinuationImage) -> SwiftAsyncReturnCertificate? {
        guard var state = initialState(source: source, caller: caller, previousReturnDigest: previousReturnDigest,
                                       returningChild: returningChild, currentSize: currentSize, image: image) else { return nil }
        let joins = image.joins(from: source)
        var steps: [SwiftAsyncContinuationStep] = []
        for index in 0..<512 {
            guard let pc = SwiftMetadataConstantInterpreter.target(source, Int64(index * 4)),
                  let (word, decoded) = image.instruction(pc), admitted(decoded),
                  index == 0 || !joins.contains(pc) else { return nil }
            steps.append(.init(address: pc, word: word, epoch: state.epoch))
            switch state.step(word, at: pc, decoded: decoded, image: image) {
            case .next: continue
            case .refused: return nil
            case .returned:
                return SwiftAsyncReturnCertificate(digest: "", source: source, callerDigest: caller.digest,
                    previousReturnDigest: previousReturnDigest, transfer: pc, resume: caller.resume,
                    steps: steps).withDigest()
            }
        }
        return nil
    }

    /// Replays supplied bytes and chronology independently; never calls prove or
    /// accepts a producer success flag. Path verification owns the caller inputs.
    static func verify(_ certificate: SwiftAsyncReturnCertificate, caller: SwiftAsyncContinuationCertificate,
                       previousReturnDigest: String?, returningChild: SwiftAsyncContinuationCertificate?,
                       currentSize: UInt32?, image: SwiftAsyncContinuationImage) -> Bool {
        guard certificate.digest == certificate.canonicalDigest(), certificate.callerDigest == caller.digest,
              certificate.previousReturnDigest == previousReturnDigest, certificate.resume == caller.resume,
              !certificate.steps.isEmpty, certificate.steps.count <= 512,
              var state = initialState(source: certificate.source, caller: caller,
                  previousReturnDigest: previousReturnDigest, returningChild: returningChild,
                  currentSize: currentSize, image: image) else { return false }
        let joins = image.joins(from: certificate.source)
        for (index, evidence) in certificate.steps.enumerated() {
            guard let pc = SwiftMetadataConstantInterpreter.target(certificate.source, Int64(index * 4)),
                  evidence.address == pc, evidence.epoch == state.epoch, evidence.effect == nil,
                  let (word, decoded) = image.instruction(pc), word == evidence.word, admitted(decoded),
                  index == 0 || !joins.contains(pc) else { return false }
            switch state.step(word, at: pc, decoded: decoded, image: image) {
            case .refused: return false
            case .next: break
            case .returned:
                return index == certificate.steps.count - 1 && pc == certificate.transfer
            }
        }
        return false
    }

    private static func admitted(_ decoded: DecodedInstruction) -> Bool {
        decoded.mnemonic != "unknown" && decoded.mnemonic != "unavailable"
    }

    private static func initialState(source: UInt64, caller: SwiftAsyncContinuationCertificate,
                                     previousReturnDigest: String?, returningChild: SwiftAsyncContinuationCertificate?,
                                     currentSize: UInt32?, image: SwiftAsyncContinuationImage) -> State? {
        guard currentSize == caller.outgoingAllocation?.size,
              image.partials.contains(caller.resume), image.executable(caller.resume),
              image.executable(source), let asyncRegister = image.asyncRegister else { return nil }
        if let returningChild {
            guard previousReturnDigest != nil, source == returningChild.resume,
                  image.partials.contains(source) else { return nil }
        } else {
            guard previousReturnDigest == nil, source == caller.callee,
                  image.entries.contains(source), !image.partials.contains(source) else { return nil }
        }
        return .init(asyncRegister: asyncRegister, currentSize: currentSize, returningChild: returningChild)
    }

    private static func isPreservingDeallocator(_ start: UInt64, image: SwiftAsyncContinuationImage) -> Bool {
        guard image.parser.sections.contains(where: {
            $0.name.contains("stubs") && start >= $0.address && start - $0.address < $0.size
        }) else { return false }
        var registers: [Int: SwiftMetadataConstantInterpreter.Value] = [0: .incoming]
        for register in 19...29 { registers[register] = .allocated(UInt64(register)) }
        for index in 0..<8 {
            guard let pc = SwiftMetadataConstantInterpreter.target(start, Int64(index * 4)),
                  let (word, decoded) = image.instruction(pc), admitted(decoded) else { return false }
            if decoded.mnemonic == "br" {
                guard registers[0] == .incoming,
                      (19...29).allSatisfy({ registers[$0] == .allocated(UInt64($0)) }),
                      case let .bound(name)? = registers[Int((word >> 5) & 31)] else { return false }
                return name == "_swift_task_dealloc" || name == "swift_task_dealloc"
            }
            if let envelope = decoded.structuredOperands,
               case let .register(destination)? = envelope.operands.first,
               destination.role == .stackPointer { return false }
            guard decoded.branchTarget == nil, decoded.flow != .call, decoded.flow != .indirectCall,
                  decoded.flow != .jump, decoded.flow != .conditionalJump, decoded.flow != .indirectJump,
                  decoded.flow != .return, decoded.flow != .trap,
                  image.interpreter.step(word, pc, &registers) else { return false }
        }
        return false
    }
}
