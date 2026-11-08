import Foundation
import CryptoKit

extension SwiftAsyncContinuationCertificate {
    /// Fixed field order and length-prefixed strings avoid encoder-dependent digests.
    func canonicalDigest() -> String {
        func text(_ value: String) -> String { "\(value.utf8.count):\(value)" }
        var fields = ["swift-async-continuation-v1", String(source), String(allocation),
            String(parentStore), String(resumeStore), String(transfer), callee.map(String.init) ?? "nil",
            text(boundCallee ?? ""), text(calleeEvidence), String(resume), kind.rawValue,
            String(parentOffset), String(resumeOffset), String(steps.count)]
        if let bound = incomingContext {
            fields += ["incoming-context-v1", String(bound.record), String(bound.size), text(bound.symbol)]
        }
        if let allocation = outgoingAllocation {
            fields += ["outgoing-allocation-v1", String(allocation.size), String(allocation.sizeInstruction),
                       allocation.loadAddress.map(String.init) ?? "nil"]
        }
        if let caller = incomingCallerDigest { fields += ["incoming-caller-v1", text(caller)] }
        let trace = steps.map { "\($0.address),\($0.word),\($0.epoch),\($0.effect.map(text) ?? "nil")" }
        return SHA256.hash(data: Data((fields + trace).joined(separator: "\n").utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
    func withDigest() -> Self {
        var copy = self
        copy.digest = canonicalDigest()
        return copy
    }
}

extension SwiftAsyncInvocationCertificate {
    func canonicalDigest() -> String {
        SHA256.hash(data: Data("swift-async-invocation-v1\n\(caller.canonicalDigest())\n\(continuation.canonicalDigest())".utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
    func withDigest() -> Self {
        var copy = self
        copy.digest = canonicalDigest()
        return copy
    }
}

extension SwiftAsyncInvocationChainCertificate {
    func canonicalDigest() -> String {
        var fields = ["swift-async-invocation-chain-v1", String(frames.count)] + frames.map { $0.canonicalDigest() }
        if let transitions {
            fields += ["execution-v1", String(transitions.count)]
            for transition in transitions {
                switch transition {
                case let .call(index): fields += ["call", String(index)]
                case let .returnToCaller(witness): fields += ["return", witness.canonicalDigest()]
                }
            }
        }
        return SHA256.hash(data: Data(fields.joined(separator: "\n").utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
    func withDigest() -> Self {
        var copy = self
        copy.digest = canonicalDigest()
        return copy
    }
}

extension SwiftAsyncReturnCertificate {
    func canonicalDigest() -> String {
        let fields = ["swift-async-return-v1", String(source), callerDigest,
                      previousReturnDigest ?? "nil", String(transfer), String(resume)]
        let trace = steps.map { "\($0.address),\($0.word),\($0.epoch),\($0.effect ?? "nil")" }
        return SHA256.hash(data: Data((fields + trace).joined(separator: "\n").utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
    func withDigest() -> Self {
        var copy = self
        copy.digest = canonicalDigest()
        return copy
    }
}

/// Image reads and decode facts contain no mutable proof state.
struct SwiftAsyncContinuationImage {
    let parser: SwiftMetadataParser
    let metadata: SwiftAsyncMetadata
    var entries: Set<UInt64> { Set(metadata.entries.map(\.entryAddress)) }
    var partials: Set<UInt64> { Set(metadata.resumePartialAddresses + metadata.continuationPartialAddresses) }
    var interpreter: SwiftMetadataConstantInterpreter { .init(parser: parser) }
    /// A blind __const scan is only candidate discovery. Require a defined
    /// async-function-pointer symbol and re-read its complete record. A partial
    /// never inherits its owner's entry allocation extent.
    func incomingContextBound(at source: UInt64) -> SwiftAsyncIncomingContextBound? {
        let records = metadata.entries.filter { $0.entryAddress == source }
        guard records.count == 1, !partials.contains(source),
              records[0].pointerRecords.count == 1,
              let candidate = records[0].pointerRecords.first,
              candidate.address % 4 == 0, candidate.address <= UInt64.max - 7,
              parser.sections.filter({ section in
                  section.name == "__const" && section.segmentName == "__TEXT"
                      && !section.isZeroFill && !section.isExecutable
                      && candidate.address >= section.address && section.size >= 8
                      && candidate.address - section.address <= section.size - 8
              }).count == 1,
              let names = parser.asyncFunctionPointerSymbols[candidate.address],
              Set(names).count == 1, let name = names.first,
              let facts = SwiftDemangler.demangleWithFacts(name)?.facts,
              facts.isAsyncFunctionPointer, facts.isFunction, facts.isAsync,
              parser.resolveRelativePointer(at: candidate.address) == source,
              let size = parser.readU32(atVA: candidate.address + 4),
              size == candidate.expectedContextSize, size >= 16, size <= 1_048_576,
              size % 16 == 0 else { return nil }
        return .init(record: candidate.address, size: size, symbol: name)
    }
    var asyncRegister: Int? {
        var evidence = SwiftBoundaryEvidence()
        evidence.isAsyncEntryRecord = true
        guard let name = SwiftConventionAdapter.decide(evidence).asyncContextIn,
              name.first == "x" else { return nil }
        return Int(name.dropFirst())
    }
    func executable(_ address: UInt64) -> Bool {
        address % 4 == 0 && parser.sections.contains { $0.isExecutable && !$0.isZeroFill && address >= $0.address
            && address - $0.address < $0.size && $0.size - (address - $0.address) >= 4 }
    }
    func instruction(_ address: UInt64) -> (UInt32, DecodedInstruction)? {
        guard executable(address), let word = parser.readU32(atVA: address) else { return nil }
        let bytes = (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) }
        guard let decoded = ARM64Decoder().decode(Data(bytes), baseAddress: address, maxInstructionCount: 1).first else { return nil }
        return (word, decoded)
    }
    func joins(from start: UInt64) -> Set<UInt64> {
        var result = Set<UInt64>()
        for index in 0..<512 {
            guard let pc = SwiftMetadataConstantInterpreter.target(start, Int64(index * 4)),
                  let (_, instruction) = instruction(pc) else { break }
            if let target = instruction.branchTarget,
               instruction.flow == .jump || instruction.flow == .conditionalJump || instruction.flow == .call {
                result.insert(target)
            }
        }
        return result
    }
    /// Header operand shape only; each proof interpreter supplies its own object identities.
    func contextHeaderLoad(_ instruction: DecodedInstruction) -> (base: Int, destinations: [(Int, Int)])? {
        guard let envelope = instruction.structuredOperands, envelope.coverage == .complete,
              envelope.semantics?.memoryAccess == .read, envelope.semantics?.memoryAccessWidth == 64,
              ["ldr", "ldur", "ldp"].contains(instruction.mnemonic),
              let memory = envelope.operands.compactMap({ operand -> InstructionOperands.Memory? in
                  if case let .memory(value) = operand { return value }; return nil
              }).first, memory.base.role == .ordinary, memory.base.width == 64,
              memory.index == nil, !memory.writeback, memory.indexing == .offset else { return nil }
        let destinations = envelope.operands.compactMap { operand -> InstructionOperands.Register? in
            if case let .register(value) = operand { return value }; return nil
        }
        guard destinations.count == (instruction.mnemonic == "ldp" ? 2 : 1),
              destinations.allSatisfy({ $0.bank == .general && $0.width == 64 && $0.role == .ordinary }),
              Set(destinations.map(\.index)).count == destinations.count,
              memory.displacement >= 0, memory.displacement % 8 == 0,
              memory.displacement + Int64(destinations.count * 8) <= 16 else { return nil }
        return (memory.base.index, destinations.enumerated().map { ($0.element.index, Int(memory.displacement) + $0.offset * 8) })
    }
    func runtime(_ value: SwiftMetadataConstantInterpreter.Value?) -> String? {
        if case let .bound(name)? = value { return name }
        guard case let .address(start)? = value,
              parser.sections.contains(where: { $0.name.contains("stubs") && start >= $0.address
                  && start - $0.address < $0.size }) else { return nil }
        var registers: [Int: SwiftMetadataConstantInterpreter.Value] = [:]
        for index in 0..<8 {
            guard let pc = SwiftMetadataConstantInterpreter.target(start, Int64(index * 4)),
                  let (word, decoded) = instruction(pc), decoded.mnemonic != "unknown",
                  decoded.mnemonic != "unavailable" else { return nil }
            if decoded.mnemonic == "br" {
                if case let .bound(name)? = registers[Int((word >> 5) & 31)] { return name }
                return nil
            }
            guard decoded.branchTarget == nil, decoded.flow != .call, decoded.flow != .indirectCall,
                  decoded.flow != .jump, decoded.flow != .conditionalJump, decoded.flow != .indirectJump,
                  decoded.flow != .return, decoded.flow != .trap else { return nil }
            // Identity only: ADD/SUB SP, SP, #imm cannot alter a non-SP target register.
            // Preservation remains a separate check; never compute or retain an SP value here.
            if word & 0xbf8003ff == 0x910003ff {
                registers[31] = nil
                continue
            }
            guard interpreter.step(word, pc, &registers) else { return nil }
        }
        return nil
    }
    func asyncTarget(_ value: SwiftMetadataConstantInterpreter.Value?) -> (UInt64?, String?, String)? {
        if case let .address(address)? = value, entries.contains(address) {
            return (address, nil, "asyncEntryMetadata")
        }
        if let name = runtime(value),
           let facts = SwiftDemangler.demangleWithFacts(name)?.facts,
           facts.isAsync && facts.isFunction && !facts.isAsyncFunctionPointer {
            return (nil, name, "demangledAsyncImport")
        }
        return nil
    }
}

enum SwiftAsyncContinuationProver {
    private typealias Value = SwiftMetadataConstantInterpreter.Value
    private struct Field: Hashable { var allocation: UInt64; var offset: Int }
    private struct Fact { var value: Value?; var instruction: UInt64; var epoch: Int }

    /// Bounded caller discovery from the image's async metadata. Context is a
    /// certificate path; the same callee reached by two callers is not merged.
    static func discoverInvocations(parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                                    maxSources: Int = 64, maxDepth: Int = 16,
                                    deadline: Date? = nil) -> SwiftAsyncInvocationDiscoveryReport {
        let image = SwiftAsyncContinuationImage(parser: parser, metadata: metadata)
        let sources = image.entries.union(image.partials).sorted()
        let sourceLimit = min(256, max(0, maxSources)), depthLimit = min(32, max(1, maxDepth))
        var chains: [SwiftAsyncInvocationChainCertificate] = []
        var frontier: [SwiftAsyncInvocationFrontier] = []
        var examined = 0
        func gap(_ source: UInt64, _ pc: UInt64, _ reason: String, caller: String? = nil) {
            frontier.append(.init(callerDigest: caller, source: source, instruction: pc, reason: reason))
        }
        for (index, source) in sources.enumerated() {
            guard index < sourceLimit else { gap(source, source, "callerDiscoveryLimit"); continue }
            if let deadline, Date() >= deadline { gap(source, source, "invocationTimeLimit"); continue }
            examined += 1
            let root = scan(source, image: image)
            guard let certificate = root.0,
                  SwiftAsyncContinuationCertificateVerifier.verify(certificate, parser: parser, metadata: metadata) else {
                gap(source, root.1?.instruction ?? source, root.1?.reason ?? "verificationFailed")
                continue
            }
            var frames = [certificate]
            var transitions: [SwiftAsyncInvocationTransition] = []
            var pending: [(call: SwiftAsyncContinuationCertificate, ownerSize: UInt32?)] = [(certificate, certificate.incomingContext?.size)]
            var nextSource = certificate.callee, incomingSize = certificate.outgoingAllocation?.size
            var binding = certificate.digest
            var returningChild: SwiftAsyncContinuationCertificate?
            var visitedContexts = Set<String>()
            let cleanRoot = SwiftAsyncContinuationCertificateVerifier.verifyPreservingFrame(certificate,
                parser: parser, metadata: metadata, incomingSize: nil)
            if !cleanRoot { gap(source, certificate.transfer, "unpreservedInvocationMemory", caller: certificate.digest) }
            while cleanRoot {
                guard transitions.count < 64 else {
                    gap(nextSource ?? source, nextSource ?? source, "invocationTransitionLimit", caller: binding); break
                }
                guard let current = nextSource else {
                    gap(frames.last?.source ?? source, frames.last?.transfer ?? source, "externalInvocationTarget", caller: binding); break
                }
                if let deadline, Date() >= deadline {
                    gap(current, current, "invocationTimeLimit", caller: binding); break
                }
                if returningChild == nil {
                    guard incomingSize != nil else {
                        gap(current, current, "unprovedOutgoingAllocation", caller: binding); break
                    }
                    guard metadata.entries.filter({ $0.entryAddress == current }).count == 1,
                          !image.partials.contains(current) else {
                        gap(current, current, "ambiguousInvocationEntry", caller: binding); break
                    }
                } else if !image.partials.contains(current) {
                    gap(current, current, "unprovedResumePartial", caller: binding); break
                }
                let context = "\(current):\(incomingSize.map(String.init) ?? "unknown"):\(returningChild?.allocation.description ?? "entry")"
                guard visitedContexts.insert(context).inserted else {
                    gap(current, current, "recursiveInvocationContext", caller: binding); break
                }
                if let parent = pending.last,
                   let returned = SwiftAsyncReturnProof.prove(source: current, caller: parent.call,
                    previousReturnDigest: returningChild == nil ? nil : binding, returningChild: returningChild,
                    currentSize: incomingSize, image: image),
                   SwiftAsyncReturnProof.verify(returned, caller: parent.call,
                    previousReturnDigest: returningChild == nil ? nil : binding, returningChild: returningChild,
                    currentSize: incomingSize, image: image) {
                    transitions.append(.returnToCaller(returned))
                    pending.removeLast()
                    nextSource = parent.call.resume; incomingSize = parent.ownerSize
                    binding = returned.digest; returningChild = parent.call
                    continue
                }
                let next = scan(current, image: image, incomingAllocationSize: incomingSize,
                                callerDigest: binding, returningChild: returningChild)
                guard let continuation = next.0 else {
                    gap(current, next.1?.instruction ?? current, next.1?.reason ?? "noInvocationContinuation", caller: binding)
                    break
                }
                guard frames.count < depthLimit else {
                    gap(current, current, "invocationDepthLimit", caller: binding); break
                }
                guard SwiftAsyncContinuationCertificateVerifier.verifyPreservingFrame(continuation,
                    parser: parser, metadata: metadata, incomingSize: incomingSize, returningChild: returningChild) else {
                    gap(current, continuation.transfer, "unpreservedInvocationMemory", caller: binding); break
                }
                transitions.append(.call(frameIndex: frames.count))
                frames.append(continuation)
                pending.append((continuation, incomingSize))
                nextSource = continuation.callee; incomingSize = continuation.outgoingAllocation?.size
                binding = continuation.digest; returningChild = nil
            }
            let chain = SwiftAsyncInvocationChainCertificate(digest: "", frames: frames,
                transitions: cleanRoot ? transitions : nil).withDigest()
            if SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: parser, metadata: metadata) {
                chains.append(chain)
            } else { gap(source, source, "invocationChainVerificationFailed") }
        }
        return .init(chains: chains, frontier: frontier, examinedSources: examined)
    }

    /// Analyze only the invocation proven by this caller. Neither the extent
    /// nor its continuation is promoted into the address-only chain graph.
    static func analyzeInvocation(parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                                  caller: SwiftAsyncContinuationCertificate) -> SwiftAsyncInvocationReport {
        guard SwiftAsyncContinuationCertificateVerifier.verify(caller, parser: parser, metadata: metadata),
              let callee = caller.callee, let allocation = caller.outgoingAllocation,
              metadata.entries.filter({ $0.entryAddress == callee }).count == 1,
              !metadata.resumePartialAddresses.contains(callee),
              !metadata.continuationPartialAddresses.contains(callee) else {
            return .init(certificate: nil, abstention: .init(source: caller.source,
                instruction: caller.transfer, reason: "unprovedCallerAllocation"))
        }
        let result = scan(callee, image: .init(parser: parser, metadata: metadata),
                          incomingAllocationSize: allocation.size, callerDigest: caller.digest)
        guard let continuation = result.0 else { return .init(certificate: nil, abstention: result.1) }
        let certificate = SwiftAsyncInvocationCertificate(digest: "", caller: caller,
                                                          continuation: continuation).withDigest()
        guard SwiftAsyncContinuationCertificateVerifier.verifyInvocation(certificate, parser: parser, metadata: metadata) else {
            return .init(certificate: nil, abstention: .init(source: callee,
                instruction: continuation.transfer, reason: "invocationVerificationFailed"))
        }
        return .init(certificate: certificate, abstention: nil)
    }

    /// The caller supplies an arm64 image and its matching metadata; no cross-architecture inference is performed.
    static func analyze(parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                        entryAddresses: Set<UInt64>? = nil, deadline: Date? = nil) -> SwiftAsyncContinuationReport {
        let image = SwiftAsyncContinuationImage(parser: parser, metadata: metadata)
        let roots = image.entries.intersection(entryAddresses ?? image.entries).sorted()
        var edges: [SwiftAsyncContinuationEdge] = []
        var refusals: [SwiftAsyncContinuationAbstention] = []
        for address in (entryAddresses ?? []).subtracting(image.entries).sorted() {
            refusals.append(.init(source: address, instruction: address, reason: "noAsyncEntryMetadata"))
        }
        var pending = entryAddresses == nil ? image.entries.union(image.partials).sorted() : roots
        var visited = Set<UInt64>()
        var cursor = 0
        while cursor < pending.count {
            if let deadline, Date() >= deadline {
                for source in Set(pending[cursor...]).subtracting(visited).sorted() {
                    refusals.append(.init(source: source, instruction: source, reason: "wallTimeLimit"))
                }
                break
            }
            let source = pending[cursor]; cursor += 1
            guard visited.insert(source).inserted else { continue }
            let result = scan(source, image: image)
            if let certificate = result.0 {
                if SwiftAsyncContinuationCertificateVerifier.verify(certificate, parser: parser, metadata: metadata) {
                    edges.append(.init(source: source, resume: certificate.resume,
                                       kind: certificate.kind, certificate: certificate))
                    if !visited.contains(certificate.resume) { pending.append(certificate.resume) }
                } else {
                    refusals.append(.init(source: source, instruction: certificate.transfer, reason: "verificationFailed"))
                }
            } else if let refusal = result.1 { refusals.append(refusal) }
        }
        let adjacency = Dictionary(grouping: edges, by: \.source)
        var ownership: [UInt64: Set<UInt64>] = [:]
        for root in roots {
            var work = [root], seen: Set<UInt64> = [root]
            while let source = work.popLast() {
                for edge in adjacency[source] ?? [] {
                    ownership[edge.resume, default: []].insert(root)
                    if seen.insert(edge.resume).inserted { work.append(edge.resume) }
                }
            }
        }
        // Rebuild without crossing shared partials; first-root order cannot hide a conflict.
        let conflicts = Set(ownership.filter { $0.value.count > 1 }.map(\.key))
        let chains = roots.map { root -> SwiftAsyncContinuationChain in
            var work = [root], seen: Set<UInt64> = [root], partials = Set<UInt64>(), blocked = Set<UInt64>()
            while let source = work.popLast() {
                for edge in adjacency[source] ?? [] {
                    if conflicts.contains(edge.resume) { blocked.insert(edge.resume); continue }
                    partials.insert(edge.resume)
                    if seen.insert(edge.resume).inserted { work.append(edge.resume) }
                }
            }
            return .init(entry: root, partials: partials.sorted(), conflicts: blocked.sorted())
        }
        for partial in conflicts.sorted() {
            refusals.append(.init(source: partial, instruction: partial, reason: "conflictingChainOwnership"))
        }
        return .init(edges: edges.sorted { $0.source < $1.source }, chains: chains,
                     abstentions: refusals.sorted { ($0.source, $0.instruction, $0.reason) < ($1.source, $1.instruction, $1.reason) },
                     unlinkedPartials: image.partials.subtracting(Set(edges.map(\.resume))).sorted())
    }

    private static func scan(_ source: UInt64, image: SwiftAsyncContinuationImage,
                             incomingAllocationSize: UInt32? = nil, callerDigest: String? = nil,
                             returningChild: SwiftAsyncContinuationCertificate? = nil)
        -> (SwiftAsyncContinuationCertificate?, SwiftAsyncContinuationAbstention?) {
        func refuse(_ pc: UInt64, _ reason: String, mnemonic: String? = nil) -> (SwiftAsyncContinuationCertificate?, SwiftAsyncContinuationAbstention?) {
            (nil, .init(source: source, instruction: pc, reason: reason, mnemonic: mnemonic))
        }
        guard let asyncRegister = image.asyncRegister else { return refuse(source, "abiUnestablished") }
        var registers: [Int: Value] = [asyncRegister: returningChild.map { .allocated($0.allocation) } ?? .incoming]
        var returnedChildLive = returningChild != nil
        var fields: [Field: Fact] = [:], candidates: [UInt64: Set<UInt64>] = [:]
        var epoch = 0, steps: [SwiftAsyncContinuationStep] = []
        var memoryUnknown = false
        let incomingBound = callerDigest == nil ? image.incomingContextBound(at: source) : nil
        let incomingSize = incomingAllocationSize ?? incomingBound?.size
        var sizeState = SwiftAsyncAllocationSizeState()
        var allocationSizes: [UInt64: SwiftAsyncOutgoingAllocation] = [:]
        // At an ABI entry, only bytes newly reserved below entry SP are owned
        // stack storage disjoint from the image and allocated async contexts.
        // Never infer that property from an arbitrary register named SP/x29.
        var stackOffset: Int64? = 0
        let joins = image.joins(from: source)
        for index in 0..<512 {
            guard let pc = SwiftMetadataConstantInterpreter.target(source, Int64(index * 4)),
                  let (word, decoded) = image.instruction(pc) else { return refuse(source, "unreadableInstruction") }
            if decoded.mnemonic == "unknown" || decoded.mnemonic == "unavailable" {
                return refuse(pc, "unsupportedInstruction", mnemonic: decoded.mnemonic)
            }
            if index > 0 && joins.contains(pc) { return refuse(pc, "controlFlowJoin") }
            steps.append(.init(address: pc, word: word, epoch: epoch))
            let argumentSize = sizeState.argument()
            let scalarHandled = decoded.flow == .call || decoded.flow == .indirectCall
                ? false : sizeState.step(word, at: pc, image: image, registers: registers, memoryUnknown: memoryUnknown)
            if (word & 0xff800000 == 0x91000000 || word & 0xff800000 == 0xd1000000),
               word & 31 == 31, decoded.structuredOperands?.coverage == .complete {
                if (word >> 5) & 31 == 31, let current = stackOffset {
                    let amount = Int64((word >> 10) & 0xfff) << (word & 0x400000 == 0 ? 0 : 12)
                    let delta = word & 0x40000000 == 0 ? amount : -amount
                    let (next, overflow) = current.addingReportingOverflow(delta)
                    stackOffset = !overflow && next <= 0 && next >= -1_048_576 && next % 16 == 0 ? next : nil
                } else { stackOffset = nil }
                registers[31] = nil
                continue
            }
            if let operands = decoded.structuredOperands {
                if operands.semantics?.memoryAccess != .write,
                   case let .register(destination)? = operands.operands.first,
                   destination.role == .stackPointer { stackOffset = nil }
                if operands.operands.contains(where: {
                    if case let .memory(memory) = $0 {
                        return memory.writeback && memory.base.role == .stackPointer
                    }
                    return false
                }) { stackOffset = nil }
            }
            if !memoryUnknown, returnedChildLive, let child = returningChild,
               let load = image.contextHeaderLoad(decoded), registers[load.base] == .allocated(child.allocation) {
                for (destination, offset) in load.destinations {
                    registers[destination] = offset == 0 ? .incoming : .address(child.resume)
                }
                continue
            }
            // A tainted slot supplies no value; unrelated proof facts remain live.
            if memoryUnknown, word & 0xffc00000 == 0xf9400000 || word & 0xff000000 == 0x58000000 {
                registers[Int(word & 31)] = nil
                steps[steps.count - 1].effect = "unknownImageLoad"
                continue
            }
            let call = decoded.flow == .call || decoded.flow == .indirectCall
            let transfer = decoded.mnemonic == "b" || decoded.mnemonic == "br"
            if call || transfer {
                let target: Value? = (decoded.mnemonic == "b" || decoded.mnemonic == "bl")
                    ? decoded.branchTarget.map { .address($0) } : registers[Int((word >> 5) & 31)]
                if decoded.mnemonic == "br" {
                    switch target {
                    case .some(.address(_)), .some(.bound(_)): break
                    default: return refuse(pc, "unsupportedBranch")
                    }
                }
                if memoryUnknown, case let .address(address)? = target,
                   image.parser.sections.contains(where: { $0.name.contains("stubs")
                       && address >= $0.address && address - $0.address < $0.size }) {
                    return refuse(pc, "mutableImageLoad")
                }
                let runtime = image.runtime(target)
                if ["_swift_task_switch", "swift_task_switch", "_swift_continuation_init", "swift_continuation_init",
                    "_swift_continuation_await", "swift_continuation_await"].contains(runtime ?? "") {
                    return refuse(pc, "abiUnestablished")
                }
                if call {
                    let deallocatesReturnedChild = decoded.mnemonic == "bl" && returnedChildLive
                        && (runtime == "_swift_task_dealloc" || runtime == "swift_task_dealloc")
                        && returningChild.map { registers[0] == .allocated($0.allocation) } == true
                        && image.runtimePreservesArgument(target, names: ["_swift_task_dealloc", "swift_task_dealloc"], preserveContext: true)
                    epoch += 1; fields.removeAll(); candidates.removeAll()
                    allocationSizes.removeAll()
                    sizeState.reset()
                    for register in 0...18 { registers[register] = nil }
                    registers[30] = nil
                    if decoded.mnemonic == "bl", runtime == "_swift_task_alloc" || runtime == "swift_task_alloc" {
                        guard image.runtimePreservesArgument(target, names: ["_swift_task_alloc", "swift_task_alloc"],
                            preserveContext: true, preserveArgument: false) else { return refuse(pc, "allocatorContextClobber") }
                        registers[0] = .allocated(pc)
                        if let argumentSize, image.allocatorPreservesSizeArgument(target) {
                            allocationSizes[pc] = argumentSize
                        }
                    } else if deallocatesReturnedChild, let child = returningChild {
                        returnedChildLive = false
                        registers = registers.filter { $0.value != .allocated(child.allocation) }
                    } else { memoryUnknown = true }
                    continue
                }
                guard let (callee, bound, evidence) = image.asyncTarget(target),
                      callee.map({ $0 % 4 == 0 }) ?? true else { return refuse(pc, "nonAsyncTransfer") }
                guard case let .allocated(allocation)? = registers[asyncRegister],
                      allocation != returningChild?.allocation else { return refuse(pc, "unprovedAsyncContext") }
                guard let parent = fields[.init(allocation: allocation, offset: 0)],
                      let resume = fields[.init(allocation: allocation, offset: 8)] else {
                    return refuse(pc, "missing or clobbered live context stores")
                }
                guard parent.value == .incoming, case let .address(resumeAddress)? = resume.value,
                      resumeAddress % 4 == 0, image.partials.contains(resumeAddress), image.executable(resumeAddress),
                      parent.epoch == epoch, resume.epoch == epoch,
                      allocation < parent.instruction, allocation < resume.instruction,
                      parent.instruction < pc, resume.instruction < pc else {
                    return refuse(pc, "unproved or conflicting resume/parent provenance")
                }
                let certificate = SwiftAsyncContinuationCertificate(digest: "", source: source,
                    allocation: allocation, parentStore: parent.instruction, resumeStore: resume.instruction,
                    transfer: pc, callee: callee, boundCallee: bound, calleeEvidence: evidence,
                    resume: resumeAddress, kind: .calleeReturn, incomingContext: incomingBound,
                    outgoingAllocation: allocationSizes[allocation], incomingCallerDigest: callerDigest,
                    steps: steps).withDigest()
                return (certificate, nil)
            }
            if decoded.flow == .conditionalJump || decoded.flow == .indirectJump { return refuse(pc, "unsupportedBranch") }
            if decoded.flow == .return || decoded.flow == .trap { return refuse(pc, "noContinuationTransfer") }
            if let operands = decoded.structuredOperands, operands.coverage == .complete,
               let memory = operands.operands.compactMap({ operand -> InstructionOperands.Memory? in
                   if case let .memory(value) = operand { return value }; return nil
               }).first, operands.semantics?.memoryAccess == .write {
                let sources = operands.operands.compactMap { operand -> InstructionOperands.Register? in
                    if case let .register(value) = operand { return value }; return nil
                }
                // Only a complete payload footprint inside the proven entry
                // allocation is disjoint from image/child-context memory.
                // MOV aliases retain identity; arithmetic/load aliases do not.
                if let size = incomingSize,
                   ["str", "stur", "stp"].contains(decoded.mnemonic), memory.index == nil,
                   !memory.writeback, memory.indexing == .offset,
                   memory.base.role == .ordinary, memory.base.width == 64,
                   registers[memory.base.index] == .incoming,
                   operands.semantics?.memoryAccessWidth == 64,
                   sources.count == (decoded.mnemonic == "stp" ? 2 : 1),
                   sources.allSatisfy({ $0.bank == .general && $0.width == 64 }),
                   memory.displacement >= 16,
                   memory.displacement <= Int64(size) - Int64(sources.count * 8) {
                    continue
                }
                if ["str", "stur", "stp"].contains(decoded.mnemonic), memory.index == nil,
                   !memory.writeback, memory.indexing == .offset,
                   memory.base.role == .stackPointer, memory.base.width == 64,
                   operands.semantics?.memoryAccessWidth == 64,
                   sources.count == (decoded.mnemonic == "stp" ? 2 : 1),
                   sources.allSatisfy({ $0.bank == .general && $0.width == 64 }),
                   let reserved = stackOffset, memory.displacement >= 0 {
                    let (start, startOverflow) = reserved.addingReportingOverflow(memory.displacement)
                    let (end, endOverflow) = start.addingReportingOverflow(Int64(sources.count * 8))
                    if !startOverflow && !endOverflow && start >= reserved && end <= 0 {
                        continue
                    }
                }
                if ["str", "stur", "stp"].contains(decoded.mnemonic), memory.index == nil,
                   !memory.writeback, memory.indexing == .offset, operands.semantics?.memoryAccessWidth == 64,
                   memory.base.role == .ordinary,
                   sources.count == (decoded.mnemonic == "stp" ? 2 : 1),
                   sources.allSatisfy({ $0.bank == .general && $0.width == 64 }),
                   memory.displacement >= 0, memory.displacement <= 16 - Int64(sources.count * 8),
                   case let .allocated(allocation)? = registers[memory.base.index],
                   allocation != returningChild?.allocation {
                    for (lane, register) in sources.enumerated() {
                        let offset = memory.displacement + Int64(lane * 8)
                        if offset == 0 || offset == 8 {
                            let value = register.role == .ordinary ? registers[register.index] : nil
                            if offset == 8, case let .address(candidate)? = value {
                                candidates[allocation, default: []].insert(candidate)
                                if candidates[allocation, default: []].count > 1 { return refuse(pc, "competingResume") }
                            }
                            fields[.init(allocation: allocation, offset: Int(offset))] = .init(value: value, instruction: pc, epoch: epoch)
                        } else { return refuse(pc, "unsupportedContextStore") }
                    }
                } else {
                    memoryUnknown = true
                    allocationSizes.removeAll()
                    epoch += 1; fields.removeAll(); candidates.removeAll()
                }
                if memory.writeback && memory.base.role == .ordinary { registers[memory.base.index] = nil }
                continue
            }
            // Decoder-admitted scalar register effects cannot write context memory.
            if word & 0x1f800000 == 0x12000000,
               ["and", "orr", "eor", "ands", "tst", "mov"].contains(decoded.mnemonic) {
                // Logical-immediate operands can be unavailable. Rd31 is SP
                // for non-flag-setting forms, so decode the role from the word.
                if word & 31 == 31 && word & 0x60000000 != 0x60000000 { stackOffset = nil }
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
            var constantResult = registers
            if image.interpreter.step(word, pc, &constantResult) {
                registers = constantResult
            } else if scalarHandled {
                registers[Int(word & 31)] = nil
            } else {
                return refuse(pc, "unsupportedInstruction", mnemonic: decoded.mnemonic)
            }
        }
        return refuse(steps.last?.address ?? source, "instructionLimit")
    }
}


extension SwiftMetadataParser {
    /// Explicit bounded analysis; ordinary metadata reads do not implicitly walk instructions.
    func parseAsyncContinuationsReport(entryAddresses: Set<UInt64>? = nil) -> SwiftAsyncContinuationReport {
        SwiftAsyncContinuationProver.analyze(parser: self, metadata: parseAsyncFunctions(),
                                            entryAddresses: entryAddresses)
    }
}
