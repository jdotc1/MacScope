import Foundation

/// Independent chronological replay. No producer scan, memory fact, chain or success state is consulted.
enum SwiftAsyncContinuationCertificateVerifier {
    private enum Atom: Equatable {
        case root, child(UInt64), pointer(UInt64), importName(String)
        init(_ value: SwiftMetadataConstantInterpreter.Value) {
            switch value {
            case .incoming: self = .root
            case let .allocated(site): self = .child(site)
            case let .address(address): self = .pointer(address)
            case let .bound(name): self = .importName(name)
            }
        }
        var constant: SwiftMetadataConstantInterpreter.Value {
            switch self {
            case .root: return .incoming
            case let .child(site): return .allocated(site)
            case let .pointer(address): return .address(address)
            case let .importName(name): return .bound(name)
            }
        }
    }
    private struct Slot: Hashable { let object: UInt64; let displacement: Int64 }
    private struct Write { let atom: Atom?; let pc: UInt64; let generation: Int }

    static func verify(_ certificate: SwiftAsyncContinuationCertificate,
                       parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata) -> Bool {
        guard certificate.incomingCallerDigest == nil else { return false }
        return replay(certificate, parser: parser, metadata: metadata, callerSize: nil)
    }

    static func verifyInvocation(_ certificate: SwiftAsyncInvocationCertificate,
                                 parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata) -> Bool {
        let caller = certificate.caller, continuation = certificate.continuation
        guard certificate.digest == certificate.canonicalDigest(),
              verify(caller, parser: parser, metadata: metadata),
              let allocation = caller.outgoingAllocation,
              caller.callee == continuation.source,
              metadata.entries.filter({ $0.entryAddress == continuation.source }).count == 1,
              !metadata.resumePartialAddresses.contains(continuation.source),
              !metadata.continuationPartialAddresses.contains(continuation.source),
              continuation.incomingCallerDigest == caller.digest,
              continuation.incomingContext == nil else { return false }
        return replay(continuation, parser: parser, metadata: metadata, callerSize: allocation.size)
    }

    static func verifyInvocationChain(_ certificate: SwiftAsyncInvocationChainCertificate,
                                      parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata) -> Bool {
        guard !certificate.frames.isEmpty, certificate.frames.count <= 32,
              certificate.digest == certificate.canonicalDigest(),
              verify(certificate.frames[0], parser: parser, metadata: metadata) else { return false }
        if let transitions = certificate.transitions {
            return replayTransitions(certificate.frames, transitions: transitions, parser: parser, metadata: metadata)
        }
        for index in 1..<certificate.frames.count {
            let caller = certificate.frames[index - 1], frame = certificate.frames[index]
            guard let extent = caller.outgoingAllocation, caller.callee == frame.source,
                  frame.incomingCallerDigest == caller.digest, frame.incomingContext == nil,
                  metadata.entries.filter({ $0.entryAddress == frame.source }).count == 1,
                  !metadata.resumePartialAddresses.contains(frame.source),
                  !metadata.continuationPartialAddresses.contains(frame.source),
                  replay(frame, parser: parser, metadata: metadata, callerSize: extent.size) else { return false }
        }
        return true
    }

    /// A return-capable path must preserve heap/image state across each suspension.
    /// The old descent-only format continues to state only its narrower facts.
    static func verifyPreservingFrame(_ certificate: SwiftAsyncContinuationCertificate,
                                      parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                                      incomingSize: UInt32?, returningChild: SwiftAsyncContinuationCertificate? = nil) -> Bool {
        replay(certificate, parser: parser, metadata: metadata, callerSize: incomingSize,
               returningChild: returningChild, requirePreservedMemory: true)
    }

    private static func replayTransitions(_ frames: [SwiftAsyncContinuationCertificate],
                                          transitions: [SwiftAsyncInvocationTransition],
                                          parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata) -> Bool {
        guard transitions.count <= 64, let root = frames.first,
              verifyPreservingFrame(root, parser: parser, metadata: metadata, incomingSize: nil) else { return false }
        let image = SwiftAsyncContinuationImage(parser: parser, metadata: metadata)
        var pending: [(call: SwiftAsyncContinuationCertificate, ownerSize: UInt32?)] = [(root, root.incomingContext?.size)]
        var source = root.callee, size = root.outgoingAllocation?.size
        var binding = root.digest
        var returningChild: SwiftAsyncContinuationCertificate?
        var nextFrame = 1
        for transition in transitions {
            switch transition {
            case let .call(index):
                guard index == nextFrame, frames.indices.contains(index) else { return false }
                let frame = frames[index]
                guard frame.source == source, frame.incomingCallerDigest == binding, frame.incomingContext == nil else { return false }
                if let child = returningChild {
                    guard frame.source == child.resume, image.partials.contains(frame.source) else { return false }
                } else {
                    guard size != nil, metadata.entries.filter({ $0.entryAddress == frame.source }).count == 1,
                          !image.partials.contains(frame.source) else { return false }
                }
                guard verifyPreservingFrame(frame, parser: parser, metadata: metadata,
                    incomingSize: size, returningChild: returningChild) else { return false }
                pending.append((frame, size))
                source = frame.callee; size = frame.outgoingAllocation?.size
                binding = frame.digest; returningChild = nil
                nextFrame += 1
            case let .returnToCaller(witness):
                guard let parent = pending.last, witness.source == source,
                      SwiftAsyncReturnProof.verify(witness, caller: parent.call,
                        previousReturnDigest: returningChild == nil ? nil : binding,
                        returningChild: returningChild, currentSize: size, image: image) else { return false }
                pending.removeLast()
                source = parent.call.resume; size = parent.ownerSize
                binding = witness.digest; returningChild = parent.call
            }
        }
        return nextFrame == frames.count
    }

    private static func replay(_ certificate: SwiftAsyncContinuationCertificate,
                               parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                               callerSize: UInt32?, returningChild: SwiftAsyncContinuationCertificate? = nil,
                               requirePreservedMemory: Bool = false) -> Bool {
        guard certificate.source % 4 == 0, certificate.resume % 4 == 0,
              certificate.digest == certificate.canonicalDigest(), certificate.kind == .calleeReturn,
              certificate.parentOffset == 0, certificate.resumeOffset == 8,
              !certificate.steps.isEmpty, certificate.steps.count <= 512 else { return false }
        let image = SwiftAsyncContinuationImage(parser: parser, metadata: metadata)
        guard image.entries.union(image.partials).contains(certificate.source),
              image.partials.contains(certificate.resume), image.executable(certificate.resume),
              let asyncRegister = image.asyncRegister else { return false }
        var registers: [Int: Atom] = [asyncRegister: returningChild.map { .child($0.allocation) } ?? .root]
        var returnedChildLive = returningChild != nil
        var writes: [Slot: Write] = [:], observedResumes: [UInt64: Set<UInt64>] = [:]
        var generation = 0
        var memoryUnknown = false
        // Re-establish the bound from this image, never the certificate's size.
        let incomingBound = certificate.incomingCallerDigest == nil ? image.incomingContextBound(at: certificate.source) : nil
        guard certificate.incomingContext == incomingBound else { return false }
        let incomingSize = callerSize ?? incomingBound?.size
        var sizeState = SwiftAsyncAllocationSizeState()
        var extentsByAllocation: [UInt64: SwiftAsyncOutgoingAllocation] = [:]
        // Replay derives its own stack reservation from encoded instructions;
        // no producer annotation can exempt a memory write.
        var reservedStackDepth: Int64? = 0
        let joins = image.joins(from: certificate.source)
        for (index, evidence) in certificate.steps.enumerated() {
            guard let address = SwiftMetadataConstantInterpreter.target(certificate.source, Int64(index * 4)),
                  evidence.address == address, evidence.epoch == generation,
                  let (word, decoded) = image.instruction(address), word == evidence.word,
                  index == 0 || !joins.contains(address) else { return false }
            guard decoded.mnemonic != "unknown", decoded.mnemonic != "unavailable" else { return false }
            let suppliedSize = sizeState.argument()
            let scalarHandled = decoded.flow == .call || decoded.flow == .indirectCall ? false
                : sizeState.step(word, at: address, image: image,
                    registers: registers.mapValues(\.constant), memoryUnknown: memoryUnknown)
            let stackArithmetic = word & 0xff800000
            if (stackArithmetic == 0x91000000 || stackArithmetic == 0xd1000000), word & 31 == 31,
               decoded.structuredOperands?.coverage == .complete {
                guard evidence.effect == nil else { return false }
                if (word >> 5) & 31 == 31, let depth = reservedStackDepth {
                    let immediate = Int64((word >> 10) & 0xfff) * (word & 0x400000 == 0 ? 1 : 4096)
                    let change = stackArithmetic == 0xd1000000 ? immediate : -immediate
                    let (newDepth, overflow) = depth.addingReportingOverflow(change)
                    reservedStackDepth = !overflow && (0...1_048_576).contains(newDepth) && newDepth % 16 == 0 ? newDepth : nil
                } else { reservedStackDepth = nil }
                registers[31] = nil
                continue
            }
            if let envelope = decoded.structuredOperands {
                if envelope.semantics?.memoryAccess != .write,
                   case let .register(destination)? = envelope.operands.first,
                   destination.role == .stackPointer { reservedStackDepth = nil }
                for operand in envelope.operands {
                    if case let .memory(memory) = operand,
                       memory.writeback && memory.base.role == .stackPointer { reservedStackDepth = nil }
                }
            }
            if !memoryUnknown, returnedChildLive, let child = returningChild,
               let load = image.contextHeaderLoad(decoded), registers[load.base] == .child(child.allocation) {
                guard evidence.effect == nil else { return false }
                for (destination, offset) in load.destinations {
                    registers[destination] = offset == 0 ? .root : .pointer(child.resume)
                }
                continue
            }
            let unknownImageLoad = memoryUnknown
                && (word & 0xffc00000 == 0xf9400000 || word & 0xff000000 == 0x58000000)
            guard evidence.effect == (unknownImageLoad ? "unknownImageLoad" : nil) else { return false }
            if unknownImageLoad {
                registers[Int(word & 31)] = nil
                continue
            }
            let isCall = decoded.flow == .call || decoded.flow == .indirectCall
            if isCall || decoded.mnemonic == "b" || decoded.mnemonic == "br" {
                let destination: SwiftMetadataConstantInterpreter.Value? = (decoded.mnemonic == "b" || decoded.mnemonic == "bl")
                    ? decoded.branchTarget.map { .address($0) } : registers[Int((word >> 5) & 31)]?.constant
                if memoryUnknown, case let .address(target)? = destination,
                   parser.sections.contains(where: { $0.name.contains("stubs")
                       && target >= $0.address && target - $0.address < $0.size }) { return false }
                let runtime = image.runtime(destination)
                if ["_swift_task_switch", "swift_task_switch", "_swift_continuation_init", "swift_continuation_init",
                    "_swift_continuation_await", "swift_continuation_await"].contains(runtime ?? "") { return false }
                if isCall {
                    let deallocatesReturnedChild = decoded.mnemonic == "bl" && returnedChildLive
                        && (runtime == "_swift_task_dealloc" || runtime == "swift_task_dealloc")
                        && returningChild.map { registers[0] == .child($0.allocation) } == true
                        && image.runtimePreservesArgument(destination, names: ["_swift_task_dealloc", "swift_task_dealloc"], preserveContext: true)
                    generation += 1; writes.removeAll(); observedResumes.removeAll()
                    extentsByAllocation.removeAll()
                    sizeState.reset()
                    for register in 0...18 { registers[register] = nil }
                    registers[30] = nil
                    if decoded.mnemonic == "bl", runtime == "_swift_task_alloc" || runtime == "swift_task_alloc" {
                        guard image.runtimePreservesArgument(destination, names: ["_swift_task_alloc", "swift_task_alloc"],
                            preserveContext: true, preserveArgument: false) else { return false }
                        registers[0] = .child(address)
                        if let suppliedSize, image.allocatorPreservesSizeArgument(destination) {
                            extentsByAllocation[address] = suppliedSize
                        }
                    } else if deallocatesReturnedChild, let child = returningChild {
                        returnedChildLive = false
                        registers = registers.filter { $0.value != .child(child.allocation) }
                    } else { memoryUnknown = true }
                    continue
                }
                guard !requirePreservedMemory || !memoryUnknown,
                      certificate.allocation != returningChild?.allocation else { return false }
                guard index == certificate.steps.count - 1, address == certificate.transfer,
                      registers[asyncRegister] == .child(certificate.allocation),
                      let parent = writes[.init(object: certificate.allocation, displacement: 0)],
                      let resume = writes[.init(object: certificate.allocation, displacement: 8)],
                      parent.atom == .root, resume.atom == .pointer(certificate.resume),
                      parent.pc == certificate.parentStore, resume.pc == certificate.resumeStore,
                      parent.generation == generation, resume.generation == generation,
                      certificate.allocation < parent.pc, certificate.allocation < resume.pc,
                      parent.pc < address, resume.pc < address else { return false }
                if let claimedAllocation = certificate.outgoingAllocation {
                    guard extentsByAllocation[certificate.allocation] == claimedAllocation else { return false }
                }
                // Validate target metadata independently of the producer's target-admission routine.
                if case let .address(target)? = destination, image.entries.contains(target) {
                    return target % 4 == 0 && certificate.callee == target && certificate.boundCallee == nil
                        && certificate.calleeEvidence == "asyncEntryMetadata"
                }
                if let name = runtime, let facts = SwiftDemangler.demangleWithFacts(name)?.facts,
                   facts.isFunction, facts.isAsync, !facts.isAsyncFunctionPointer {
                    return certificate.callee == nil && certificate.boundCallee == name
                        && certificate.calleeEvidence == "demangledAsyncImport"
                }
                return false
            }
            if decoded.flow == .conditionalJump || decoded.flow == .indirectJump
                || decoded.flow == .return || decoded.flow == .trap { return false }
            if let envelope = decoded.structuredOperands, envelope.coverage == .complete,
               envelope.semantics?.memoryAccess == .write,
               let memory = envelope.operands.compactMap({ operand -> InstructionOperands.Memory? in
                   if case let .memory(value) = operand { return value }; return nil
               }).first {
                let data = envelope.operands.compactMap { operand -> InstructionOperands.Register? in
                    if case let .register(value) = operand { return value }; return nil
                }
                if let child = returningChild, registers[memory.base.index] == .child(child.allocation) {
                    memoryUnknown = true
                    extentsByAllocation.removeAll()
                    generation += 1; writes.removeAll(); observedResumes.removeAll()
                    if memory.writeback { registers[memory.base.index] = nil }
                    continue
                }
                let incomingWidth = Int64(data.count * 8)
                if let size = incomingSize, registers[memory.base.index] == .root,
                   memory.base.role == .ordinary, memory.base.width == 64,
                   ["str", "stur", "stp"].contains(decoded.mnemonic),
                   memory.index == nil, memory.indexing == .offset, !memory.writeback,
                   envelope.semantics?.memoryAccessWidth == 64,
                   data.count == (decoded.mnemonic == "stp" ? 2 : 1),
                   data.allSatisfy({ $0.bank == .general && $0.width == 64 }),
                   memory.displacement >= 16, memory.displacement <= Int64(size),
                   incomingWidth <= Int64(size) - memory.displacement {
                    continue
                }
                let stackLaneCount = decoded.mnemonic == "stp" ? 2 : 1
                if ["str", "stur", "stp"].contains(decoded.mnemonic), memory.index == nil,
                   memory.indexing == .offset, !memory.writeback,
                   memory.base.role == .stackPointer, memory.base.width == 64,
                   envelope.semantics?.memoryAccessWidth == 64, data.count == stackLaneCount,
                   data.allSatisfy({ $0.bank == .general && $0.width == 64 }),
                   let depth = reservedStackDepth, memory.displacement >= 0,
                   memory.displacement <= depth, Int64(stackLaneCount * 8) <= depth - memory.displacement {
                    continue
                }
                if ["str", "stur", "stp"].contains(decoded.mnemonic), memory.index == nil,
                   !memory.writeback, memory.indexing == .offset, envelope.semantics?.memoryAccessWidth == 64,
                   memory.base.role == .ordinary, data.count == (decoded.mnemonic == "stp" ? 2 : 1),
                   data.allSatisfy({ $0.bank == .general && $0.width == 64 }),
                   memory.displacement >= 0, memory.displacement <= 16 - Int64(data.count * 8),
                   case let .child(object)? = registers[memory.base.index] {
                    for (lane, register) in data.enumerated() {
                        let displacement = memory.displacement + Int64(lane * 8)
                        if displacement == 0 || displacement == 8 {
                            let atom = register.role == .ordinary ? registers[register.index] : nil
                            if displacement == 8, case let .pointer(candidate)? = atom {
                                observedResumes[object, default: []].insert(candidate)
                                if observedResumes[object, default: []].count > 1 { return false }
                            }
                            writes[.init(object: object, displacement: displacement)] = .init(atom: atom, pc: address, generation: generation)
                        } else { return false }
                    }
                } else {
                    memoryUnknown = true
                    extentsByAllocation.removeAll()
                    generation += 1; writes.removeAll(); observedResumes.removeAll()
                }
                if memory.writeback && memory.base.role == .ordinary { registers[memory.base.index] = nil }
                continue
            }
            // Independently discard only the destinations of admitted non-memory effects.
            if word & 0x1f800000 == 0x12000000,
               ["and", "orr", "eor", "ands", "tst", "mov"].contains(decoded.mnemonic) {
                if word & 31 == 31 && (word >> 29) & 3 != 3 { reservedStackDepth = nil }
                registers[Int(word & 31)] = nil
                continue
            }
            if let envelope = decoded.structuredOperands, envelope.coverage == .complete {
                if envelope.opcodeClass == "sub", let first = envelope.operands.first,
                   case let .register(destination) = first {
                    registers[destination.index] = nil
                    continue
                }
                if envelope.semantics?.memoryAccess == .read,
                   ["ldr", "ldur", "ldp", "ldpsw", "ldrsw", "ldrb", "ldrh"].contains(decoded.mnemonic),
                   word & 0xffc00000 != 0xf9400000 {
                    for operand in envelope.operands {
                        if case let .register(destination) = operand, destination.bank == .general {
                            registers[destination.index] = nil
                        }
                        if case let .memory(memory) = operand, memory.writeback {
                            registers[memory.base.index] = nil
                        }
                    }
                    continue
                }
            }
            // Only the pre-existing constant instruction semantics are shared. Proof atoms,
            // generations, stores, transfer admission and chronology are replay-owned.
            var constants = registers.mapValues(\.constant)
            let supported = image.interpreter.step(word, address, &constants)
            if supported { registers = constants.mapValues(Atom.init) }
            else if scalarHandled { registers[Int(word & 31)] = nil }
            else { return false }
        }
        return false
    }
}
