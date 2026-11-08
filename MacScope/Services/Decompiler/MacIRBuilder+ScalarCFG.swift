import Foundation

/// Conservative whole-function scalar admission. Every edge has an exact
/// in-function target. A single natural loop may carry register phis; all
/// other effects remain on the legacy route.
struct ScalarCFGStatePlan {
    struct PhiDraft {
        let blockIndex: Int
        let registerIndex: Int
        let destination: MacIRValue
        /// x-registers by default; the region path also joins v-registers.
        var registerName: String? = nil
        var bitWidth = 64
        var register: String { registerName ?? "x\(registerIndex)" }
    }
    struct ConditionalFork {
        let register: String
        let condition: String
        let taken: Int
        let fallthroughBlock: Int
    }

    let cfg: CFG
    let blockAtStart: [Int: Int]
    let blockAtEnd: [Int: Int]
    let conditionalForks: [Int: ConditionalFork]
    let referencedXRegisters: [Int]
    /// Vector registers joined at CFG merges (region path only). Every other
    /// vector register that predecessors disagree on becomes unavailable.
    var referencedVRegisters: [Int] = []
    /// Loop headers whose natural loop writes SP. Only these, and joins whose
    /// completed predecessors disagree on SP, need an SP join; elsewhere SP
    /// (and with it the stack coordinate system) is carried unchanged.
    var spWritingLoopHeaders: Set<Int> = []
    var referencesSP = false
    /// Recovery crosses only pending blocks with no SP write. The region
    /// admission scan separately certifies every SP writer as modeled arithmetic.
    var spWritingBlocks: Set<Int> = []
    var permitsPendingSPRecovery = false

    /// Separate, default-off capability for one complete vector copy fact.
    /// Only general-region admission supplies the exact B/NOP certificates.
    var pendingVectorCopyTransparentBlocks: Set<Int> = []
    var pendingVectorCopyTraversalBudget = 0

    struct PendingVectorCopyDefinition {
        let source: MacIRSourceSpan
        let seedSource: MacIRSourceSpan
        let registerIndex: Int
        let value: MacIRValue
        let input: MacIRValue
    }

    /// Only the general-region admission may opt in. Every listed block is
    /// entirely exact NOP/direct-B control, never an inferred empty write set.
    var pendingGPRTransparentBlocks: Set<Int> = []
    var pendingGPRTraversalBudget = 0

    struct PendingGPRDefinition {
        let source: MacIRSourceSpan
        let definition: IntegerRegisterDefinition
    }

    /// A root witness must be followed only by exact modeled control effects.
    /// Destinationless intrinsics/unknowns are not assumed GPR-transparent.
    private static func isPendingGPRTransparentEffect(_ instruction: MacIRInstruction) -> Bool {
        let source = instruction.source
        guard source.syntheticPhiEdge == nil, source.tailCallEffect == nil else { return false }
        let operand = source.operands.trimmingCharacters(in: .whitespacesAndNewlines)
        switch (source.mnemonic.lowercased(), instruction.operation) {
        case let ("nop", .intrinsic(nil, "nop", arguments)):
            return operand.isEmpty && arguments.isEmpty
        case let ("b", .intrinsic(nil, "branch", arguments)):
            guard !operand.contains(","), let target = address(operand), target <= UInt64(Int64.max) else { return false }
            return arguments == [.immediate(Int64(target))]
        default:
            return false
        }
    }

    /// A unique committed assignment followed only by B/NOP is a producer
    /// witness. Inherited definitions and opaque/call/implicit-write tails do
    /// not qualify even if the final dictionary still contains the same value.
    static func snapshotPendingGPRDefinitions(
        instructions: [MacIRInstruction], state: BuilderState
    ) -> [Int: PendingGPRDefinition] {
        guard state.ssa == nil else { return [:] }
        var result: [Int: PendingGPRDefinition] = [:]
        var seen: Set<MacIRValue> = []
        var ambiguous: Set<MacIRValue> = []
        var transparentTail = true
        for instruction in instructions.reversed() {
            defer { transparentTail = transparentTail && isPendingGPRTransparentEffect(instruction) }
            guard case let .assign(destination, _) = instruction.operation else { continue }
            if !seen.insert(destination).inserted { ambiguous.insert(destination) }
            guard transparentTail,
                  instruction.source.syntheticPhiEdge == nil,
                  instruction.source.tailCallEffect == nil,
                  case let .register(name, _) = destination,
                  let view = MacIRBuilder.integerRegisterView(name),
                  let definition = state.currentIntegerDefinitionByIndex[view.index],
                  definition.value == destination, definition.width == view.width,
                  !definition.isJoinedDefinition, !definition.isSyntheticReturnPhi else { continue }
            result[view.index] = PendingGPRDefinition(source: instruction.source, definition: definition)
        }
        return result.filter { !ambiguous.contains($0.value.definition.value) }
    }

    /// This extension has a separate, small output bound. It never expands
    /// the legacy single-assignment witness or the pending-path traversal.
    static let independentPendingGPRDefinitionLimit = 4
    private static let independentPendingGPREffectLimit = 1024

    /// Exact full-register MOV-immediate only. An arbitrary `.assign` is not
    /// proof that its source instruction leaves every other GPR untouched.
    /// Match the decoded operands to the actual committed numeric operation.
    private static func independentPendingGPRImmediateWrite(
        _ instruction: MacIRInstruction
    ) -> (index: Int, width: Int, destination: MacIRValue)? {
        let source = instruction.source
        guard source.syntheticPhiEdge == nil, source.tailCallEffect == nil,
              source.mnemonic.lowercased() == "mov",
              instruction == MacIRInstruction(source: source, operation: instruction.operation),
              case let .assign(destination, .immediate(value)) = instruction.operation,
              case let .register(name, version) = destination, version > 0 else { return nil }
        let operands = source.operands.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard operands.count == 2,
              let view = MacIRBuilder.integerRegisterView(operands[0]),
              operands[0].lowercased() == "\(view.width == 32 ? "w" : "x")\(view.index)",
              name == operands[0].lowercased(), operands[1].hasPrefix("#") else { return nil }
        // The shared numeric parser is intentionally permissive. Require one
        // sign and exact ASCII digits before using it as preservation proof.
        var literal = String(operands[1].dropFirst())
        if literal.hasPrefix("-") { literal.removeFirst() }
        let hexadecimal = literal.hasPrefix("0x")
        let digits = hexadecimal ? String(literal.dropFirst(2)) : literal
        guard !digits.isEmpty,
              digits.allSatisfy({ (hexadecimal ? "0123456789abcdefABCDEF" : "0123456789").contains($0) }),
              let immediate = MacIRBuilder.parseRegisterImmediate(operands[1], bitWidth: view.width)
        else { return nil }
        let bits = UInt64(bitPattern: immediate)
        let normalized = view.width == 32 ? bits & 0xffff_ffff : bits
        guard value == Int64(bitPattern: normalized) else { return nil }
        return (view.index, view.width, destination)
    }

    /// Up to four independently witnessed physical GPR cells. Every candidate
    /// owns its MOV-immediate source and a suffix containing only exact control
    /// or other independently decoded single-register writes. W/X aliases kill
    /// the same physical cell. Unknown effects stop proof for earlier cells;
    /// they do not lend transparency merely because a later cell is valid.
    static func snapshotIndependentPendingGPRDefinitions(
        instructions: [MacIRInstruction], state: BuilderState
    ) -> [Int: PendingGPRDefinition] {
        guard state.ssa == nil, instructions.count <= independentPendingGPREffectLimit else { return [:] }
        var result: [Int: PendingGPRDefinition] = [:]
        var killedIndices: Set<Int> = []
        var seenValues: Set<MacIRValue> = []
        var ambiguousValues: Set<MacIRValue> = []
        var seenSources: Set<UInt64> = []
        var ambiguousSources: Set<UInt64> = []
        var classifiedSuffix = true
        for instruction in instructions.reversed() {
            // Complete this identity scan even after a barrier or the fact cap:
            // an earlier duplicate cannot borrow a later producer's witness.
            if !seenSources.insert(instruction.source.address).inserted {
                ambiguousSources.insert(instruction.source.address)
            }
            if case let .assign(destination, _) = instruction.operation,
               !seenValues.insert(destination).inserted {
                ambiguousValues.insert(destination)
            }
            guard classifiedSuffix else { continue }
            if isPendingGPRTransparentEffect(instruction) { continue }
            guard let write = independentPendingGPRImmediateWrite(instruction) else {
                classifiedSuffix = false
                continue
            }
            // Install the physical kill even when this particular definition
            // is poisoned or the output is full. An older alias is not a fallback.
            let firstWrite = killedIndices.insert(write.index).inserted
            guard firstWrite, result.count < independentPendingGPRDefinitionLimit,
                  let definition = state.currentIntegerDefinitionByIndex[write.index],
                  definition.value == write.destination, definition.width == write.width,
                  !definition.isJoinedDefinition, !definition.isSyntheticReturnPhi else { continue }
            result[write.index] = PendingGPRDefinition(source: instruction.source, definition: definition)
        }
        return result.filter {
            !ambiguousValues.contains($0.value.definition.value)
                && !ambiguousSources.contains($0.value.source.address)
        }
    }

    /// A witness remains a source identity, never a constant/value-equivalence
    /// claim. Check the complete physical definition and both alias projections
    /// in each participating snapshot before comparing or importing it.
    private static func matchesPendingGPRDefinition441(
        _ witness: PendingGPRDefinition, index: Int, state: BuilderState
    ) -> Bool {
        let x = "x\(index)", w = "w\(index)"
        guard state.ssa == nil, (0...30).contains(index),
              witness.source.syntheticPhiEdge == nil, witness.source.tailCallEffect == nil,
              let definition = state.currentIntegerDefinitionByIndex[index],
              definition.value == witness.definition.value,
              definition.width == witness.definition.width,
              !definition.isJoinedDefinition, !definition.isSyntheticReturnPhi,
              !witness.definition.isJoinedDefinition, !witness.definition.isSyntheticReturnPhi,
              case let .register(name, version) = definition.value, version > 0,
              let view = MacIRBuilder.integerRegisterView(name), view.index == index,
              view.width == definition.width,
              name == (definition.width == 64 ? x : w),
              state.registerVersions[name] == version,
              !state.unavailableRegisterValues.contains(x),
              !state.unavailableRegisterValues.contains(w),
              !state.callUnavailableRegisterValues.contains(x),
              !state.callUnavailableRegisterValues.contains(w) else { return false }
        let word: MacIRValue = definition.width == 32 ? definition.value
            : .unary(op: "(uint32_t)", value: definition.value)
        let wide: MacIRValue = definition.width == 64 ? definition.value
            : .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: definition.value))
        return state.readRegister(x) == wide && state.readRegister(w) == word
    }

    /// All paths retain one originating committed assignment. Equal SSA values
    /// from independent assignments do not agree unless their source witness is
    /// the same; admission has unique source addresses and witness propagation
    /// below only copies an existing witness across fully emitted control.
    private static func agreedPendingGPRDefinition441(
        index: Int, roots: [Int], outgoing: [Int: BuilderState],
        witnesses: [Int: [Int: PendingGPRDefinition]]
    ) -> PendingGPRDefinition? {
        guard let first = roots.first, let producer = outgoing[first],
              let witness = witnesses[first]?[index],
              matchesPendingGPRDefinition441(witness, index: index, state: producer) else { return nil }
        let value = witness.definition.value
        for root in roots.dropFirst() {
            guard let state = outgoing[root], let other = witnesses[root]?[index],
                  other.source == witness.source,
                  other.definition.value == witness.definition.value,
                  other.definition.width == witness.definition.width,
                  matchesPendingGPRDefinition441(other, index: index, state: state),
                  state.registerNameBindingsByValue[value] == producer.registerNameBindingsByValue[value],
                  state.valueTypeHints[value] == producer.valueTypeHints[value] else { return nil }
        }
        return witness
    }

    /// Preserve local witnesses unchanged. Inherit only through a whole block
    /// whose committed effects exactly match B/NOP/CBZ/CBNZ source rows and CFG
    /// edges. Conditional control is admitted here ONLY after emission, never in
    /// the pending-path transparent-block set. All predecessors must be earlier,
    /// emitted, and carry the same original source witness; loop headers abstain.
    func inheritedPendingGPRDefinitions441<Row: DecompilerInstructionRow>(
        for blockIndex: Int, rows: [Row], instructions: [MacIRInstruction],
        outgoing: [Int: BuilderState], witnesses: [Int: [Int: PendingGPRDefinition]],
        local: [Int: PendingGPRDefinition]
    ) -> [Int: PendingGPRDefinition] {
        guard pendingGPRTraversalBudget > 0, pendingGPRTraversalBudget <= 3 * 1024,
              (1...1024).contains(rows.count), cfg.blocks.indices.contains(blockIndex),
              !cfg.hasUnresolvedTargets, cfg.irreducibleBlocks.isEmpty,
              !cfg.backEdges.contains(where: { $0.to == blockIndex }),
              let state = outgoing[blockIndex], state.ssa == nil else { return local }
        let block = cfg.blocks[blockIndex]
        guard block.index == blockIndex, block.startIndex >= 0,
              block.startIndex < block.endIndex, block.endIndex <= rows.count,
              instructions.count == block.instructionRange.count,
              !block.predecessors.isEmpty,
              block.predecessors.count <= pendingGPRTraversalBudget,
              block.predecessors.allSatisfy({ predecessor in
                  cfg.blocks.indices.contains(predecessor) && predecessor < blockIndex
                    && cfg.blocks[predecessor].index == predecessor
                    && cfg.blocks[predecessor].successors.contains(blockIndex)
                    && outgoing[predecessor] != nil
              }) else { return local }
        for (offset, instruction) in instructions.enumerated() {
            let rowIndex = block.startIndex + offset
            let row = rows[rowIndex]
            // Match the region's actual source constructor, including its
            // omission of structured operands for these textual control rows.
            let source = MacIRSourceSpan(address: row.address, byteText: row.bytes,
                mnemonic: row.mnemonic.lowercased(), operands: row.operands, comment: row.comment)
            guard instruction.source == source else { return local }
            let mnemonic = source.mnemonic
            if mnemonic == "nop" {
                guard Self.isPendingGPRTransparentEffect(instruction) else { return local }
                if rowIndex == block.endIndex - 1 {
                    guard let fallthroughBlock = cfg.blockByStartIndex[block.endIndex],
                          block.successors == [fallthroughBlock] else { return local }
                }
                continue
            }
            guard rowIndex == block.endIndex - 1 else { return local }
            let operands = source.operands.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            let targetText: String
            if mnemonic == "b" {
                guard operands.count == 1, Self.isPendingGPRTransparentEffect(instruction) else { return local }
                targetText = operands[0]
            } else if mnemonic == "cbz" || mnemonic == "cbnz" {
                guard operands.count == 2, let view = MacIRBuilder.integerRegisterView(operands[0]),
                      operands[0] == "\(view.width == 64 ? "x" : "w")\(view.index)",
                      case let .conditionalBranch(condition, left, right, target) = instruction.operation,
                      condition == (mnemonic == "cbz" ? "==" : "!="),
                      left == state.readRegister(operands[0]), right == .immediate(0),
                      let targetAddress = Self.address(operands[1]), targetAddress <= UInt64(Int64.max),
                      target == .immediate(Int64(targetAddress)) else { return local }
                targetText = operands[1]
            } else { return local }
            guard let target = Self.address(targetText),
                  let targetRow = rows.firstIndex(where: { $0.address == target }),
                  let targetBlock = cfg.blockByStartIndex[targetRow],
                  cfg.blocks.indices.contains(targetBlock),
                  cfg.blocks[targetBlock].predecessors.contains(blockIndex) else { return local }
            if mnemonic == "b" {
                guard block.successors == [targetBlock] else { return local }
            } else {
                guard let fallthroughBlock = cfg.blockByStartIndex[block.endIndex],
                      cfg.blocks.indices.contains(fallthroughBlock),
                      cfg.blocks[fallthroughBlock].predecessors.contains(blockIndex),
                      Set(block.successors) == Set([targetBlock, fallthroughBlock]) else { return local }
            }
        }
        var result = local
        for index in 0...30 where result[index] == nil {
            guard let witness = Self.agreedPendingGPRDefinition441(index: index,
                roots: block.predecessors, outgoing: outgoing, witnesses: witnesses),
                Self.matchesPendingGPRDefinition441(witness, index: index, state: state) else { continue }
            result[index] = witness
        }
        return result
    }

    /// Collect every emitted boundary of the bounded pending cone. Different
    /// roots are permitted only by the per-cell source-witness agreement above.
    /// The pending language and all cycle/backedge/refusal limits stay unchanged.
    private func pendingGPRRoots441(entering blockIndex: Int,
                                    outgoing: [Int: BuilderState]) -> [Int]? {
        guard pendingGPRTraversalBudget > 0, pendingGPRTraversalBudget <= 3 * 1024,
              cfg.blocks.count <= 1024, cfg.blocks.indices.contains(blockIndex),
              cfg.irreducibleBlocks.isEmpty,
              !cfg.hasUnresolvedTargets, outgoing[blockIndex] == nil else { return nil }
        let backedgeTargets = Set(cfg.backEdges.map(\.to))
        guard !backedgeTargets.contains(blockIndex) else { return nil }
        var remaining = pendingGPRTraversalBudget
        let incoming = cfg.blocks[blockIndex].predecessors
        guard !incoming.isEmpty, incoming.count <= remaining, incoming.allSatisfy({
            cfg.blocks.indices.contains($0) && cfg.blocks[$0].successors.contains(blockIndex)
        }) else { return nil }
        var work = incoming.map { (index: $0, exiting: false) }
        var active: Set<Int> = [blockIndex]
        var completed: Set<Int> = []
        var roots: Set<Int> = []
        while let next = work.popLast() {
            guard remaining > 0 else { return nil }
            remaining -= 1
            let index = next.index
            guard cfg.blocks.indices.contains(index), cfg.blocks[index].index == index,
                  index != blockIndex else { return nil }
            if next.exiting {
                active.remove(index)
                completed.insert(index)
                continue
            }
            if outgoing[index] != nil {
                // Production emission is source ordered. Stale/future snapshots
                // cannot hide a pending cycle in a manually constructed plan.
                guard index < blockIndex else { return nil }
                roots.insert(index)
                continue
            }
            if completed.contains(index) { continue }
            guard pendingGPRTransparentBlocks.contains(index),
                  !backedgeTargets.contains(index), active.insert(index).inserted,
                  !cfg.blocks[index].predecessors.isEmpty else { return nil }
            let predecessors = cfg.blocks[index].predecessors
            guard work.count < remaining, predecessors.count <= remaining - work.count - 1,
                  predecessors.allSatisfy({
                      cfg.blocks.indices.contains($0) && cfg.blocks[$0].successors.contains(index)
                  }) else { return nil }
            work.append((index: index, exiting: true))
            work.append(contentsOf: predecessors.map { (index: $0, exiting: false) })
        }
        return roots.isEmpty ? nil : roots.sorted()
    }

    private func recoverPendingGPRDefinitions(
        entering blockIndex: Int, outgoing: [Int: BuilderState],
        witnesses: [Int: [Int: PendingGPRDefinition]], into state: inout BuilderState
    ) {
        guard state.ssa == nil,
              let roots = pendingGPRRoots441(entering: blockIndex, outgoing: outgoing),
              let first = roots.first, let producer = outgoing[first] else { return }
        var recovered = false
        for index in 0...30 {
            let x = "x\(index)", w = "w\(index)"
            guard let witness = Self.agreedPendingGPRDefinition441(index: index,
                roots: roots, outgoing: outgoing, witnesses: witnesses) else { continue }
            let definition = witness.definition
            let value = definition.value
            if let existing = state.registerNameBindingsByValue[value],
               existing != producer.registerNameBindingsByValue[value] { continue }
            if let existing = state.valueTypeHints[value], existing != producer.valueTypeHints[value] { continue }
            // Import only an existing all-path physical definition. No ABI,
            // caller-construction, stack, memory, or SIMD authority follows it.
            state.currentIntegerDefinitionByIndex[index] = definition
            state.unavailableRegisterValues.remove(x)
            state.unavailableRegisterValues.remove(w)
            state.callUnavailableRegisterValues.remove(x)
            state.callUnavailableRegisterValues.remove(w)
            if let binding = producer.registerNameBindingsByValue[value],
               state.registerNameBindingsByValue[value] == nil {
                state.registerNameBindingsByValue[value] = binding
                state.registerNameBindingOrder.append(value)
            }
            if let type = producer.valueTypeHints[value] { state.valueTypeHints[value] = type }
            recovered = true
        }
        if recovered {
            // Every boundary contributes allocator high-water marks, including
            // roots reached only through pending blocks and not direct edges.
            for root in roots {
                if let predecessor = outgoing[root] {
                    Self.foldAllocationCounters(from: predecessor, into: &state)
                }
            }
        }
    }

    /// Separate, default-disabled capability for exact full-register copies.
    /// An empty transfer list certifies only B/NOP; an absent block abstains.
    struct PendingGPRCopyTransfer {
        let destinationIndex: Int
        let sourceIndex: Int
        let width: Int
    }
    var pendingGPRCopyTransferBlocks: [Int: [PendingGPRCopyTransfer]] = [:]
    var pendingGPRCopyTraversalBudget = 0

    private struct PendingGPRCopyOrigin: Equatable {
        let sourceIndex: Int
        let width: Int
    }

    /// The original committed witness is the identity. A pending MOV never
    /// invents a destination SSA version or makes a new producer witness.
    private static func pendingGPRCopyRootOrigins(
        producer: BuilderState, witnesses: [Int: PendingGPRDefinition]
    ) -> [Int: PendingGPRCopyOrigin] {
        guard producer.ssa == nil else { return [:] }
        var origins: [Int: PendingGPRCopyOrigin] = [:]
        for index in 0...30 {
            let x = "x\(index)", w = "w\(index)"
            guard let witness = witnesses[index],
                  let definition = producer.currentIntegerDefinitionByIndex[index],
                  definition.value == witness.definition.value,
                  definition.width == witness.definition.width,
                  !definition.isJoinedDefinition, !definition.isSyntheticReturnPhi,
                  !witness.definition.isJoinedDefinition, !witness.definition.isSyntheticReturnPhi,
                  case let .register(name, version) = definition.value, version > 0,
                  let view = MacIRBuilder.integerRegisterView(name), view.index == index,
                  view.width == definition.width,
                  name == "\(view.width == 32 ? "w" : "x")\(index)",
                  producer.registerVersions[name] == version,
                  !producer.unavailableRegisterValues.contains(x),
                  !producer.unavailableRegisterValues.contains(w),
                  !producer.callUnavailableRegisterValues.contains(x),
                  !producer.callUnavailableRegisterValues.contains(w) else { continue }
            let word: MacIRValue = definition.width == 32 ? definition.value
                : .unary(op: "(uint32_t)", value: definition.value)
            let wide: MacIRValue = definition.width == 64 ? definition.value
                : .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: definition.value))
            guard producer.readRegister(x) == wide, producer.readRegister(w) == word else { continue }
            origins[index] = PendingGPRCopyOrigin(sourceIndex: index, width: definition.width)
        }
        return origins
    }

    /// One bounded postorder walk carries only physical-cell origins, never a
    /// cloned builder. Each pending node intersects all predecessor origins,
    /// then applies its positively decoded copies in source order.
    private func pendingGPRCopyOrigins(
        entering blockIndex: Int, outgoing: [Int: BuilderState],
        witnesses: [Int: [Int: PendingGPRDefinition]]
    ) -> (root: Int, cells: [Int: PendingGPRCopyOrigin])? {
        guard pendingGPRCopyTraversalBudget > 0,
              pendingGPRCopyTraversalBudget <= 3 * 1024,
              (1...1024).contains(cfg.blocks.count), cfg.blocks.indices.contains(blockIndex),
              cfg.irreducibleBlocks.isEmpty, !cfg.hasUnresolvedTargets,
              outgoing[blockIndex] == nil else { return nil }
        let backedgeTargets = Set(cfg.backEdges.map(\.to))
        guard !backedgeTargets.contains(blockIndex) else { return nil }
        let incoming = cfg.blocks[blockIndex].predecessors
        var remaining = pendingGPRCopyTraversalBudget
        guard !incoming.isEmpty, incoming.count <= remaining,
              incoming.allSatisfy({ cfg.blocks.indices.contains($0)
                  && cfg.blocks[$0].successors.contains(blockIndex) }) else { return nil }
        var work = incoming.map { (index: $0, exiting: false) }
        var active: Set<Int> = [blockIndex]
        var memo: [Int: [Int: PendingGPRCopyOrigin]] = [:]
        var root: Int?
        var sawCopy = false
        func agreement(_ predecessors: [Int]) -> [Int: PendingGPRCopyOrigin]? {
            guard let first = predecessors.first, var cells = memo[first] else { return nil }
            for predecessor in predecessors.dropFirst() {
                guard let other = memo[predecessor] else { return nil }
                cells = cells.filter { other[$0.key] == $0.value }
            }
            return cells
        }
        while let next = work.popLast() {
            guard remaining > 0 else { return nil }
            remaining -= 1
            let index = next.index
            guard cfg.blocks.indices.contains(index), cfg.blocks[index].index == index,
                  index != blockIndex else { return nil }
            if next.exiting {
                guard let transfers = pendingGPRCopyTransferBlocks[index],
                      var cells = agreement(cfg.blocks[index].predecessors) else { return nil }
                for transfer in transfers {
                    guard (0...30).contains(transfer.destinationIndex),
                          (0...30).contains(transfer.sourceIndex),
                          transfer.width == 32 || transfer.width == 64 else { return nil }
                    // Snapshot before replacing the destination: self-copies
                    // and overlapping chains retain the pre-write origin.
                    if let input = cells[transfer.sourceIndex], input.width == transfer.width {
                        cells[transfer.destinationIndex] = input
                    } else {
                        cells.removeValue(forKey: transfer.destinationIndex)
                    }
                }
                sawCopy = sawCopy || !transfers.isEmpty
                active.remove(index)
                memo[index] = cells
                continue
            }
            if let producer = outgoing[index] {
                guard index < blockIndex, root == nil || root == index,
                      let definitions = witnesses[index] else { return nil }
                root = index
                if memo[index] == nil {
                    memo[index] = Self.pendingGPRCopyRootOrigins(producer: producer, witnesses: definitions)
                }
                continue
            }
            if memo[index] != nil { continue }
            guard pendingGPRCopyTransferBlocks[index] != nil,
                  !backedgeTargets.contains(index), active.insert(index).inserted,
                  !cfg.blocks[index].predecessors.isEmpty else { return nil }
            let predecessors = cfg.blocks[index].predecessors
            guard work.count < remaining, predecessors.count <= remaining - work.count - 1,
                  predecessors.allSatisfy({ cfg.blocks.indices.contains($0)
                      && cfg.blocks[$0].successors.contains(index) }) else { return nil }
            work.append((index: index, exiting: true))
            work.append(contentsOf: predecessors.map { (index: $0, exiting: false) })
        }
        // Leave ordinary B/NOP-only recovery to its unchanged original path.
        guard sawCopy, let root, let cells = agreement(incoming) else { return nil }
        return (root, cells)
    }

    func recoverPendingGPRCopyDefinitions(
        entering blockIndex: Int, outgoing: [Int: BuilderState],
        witnesses: [Int: [Int: PendingGPRDefinition]], into state: inout BuilderState
    ) {
        guard state.ssa == nil,
              let proof = pendingGPRCopyOrigins(entering: blockIndex, outgoing: outgoing, witnesses: witnesses),
              let producer = outgoing[proof.root] else { return }
        var recovered = false
        for index in 0...30 {
            // Composition is additive: an earlier recovery owns its cell,
            // including an equal value. Never replace a conflicting fact.
            guard state.currentIntegerDefinitionByIndex[index] == nil,
                  state.unavailableRegisterValues.contains("x\(index)"),
                  state.unavailableRegisterValues.contains("w\(index)"),
                  let origin = proof.cells[index],
                  let definition = producer.currentIntegerDefinitionByIndex[origin.sourceIndex] else { continue }
            let value = definition.value
            if let existing = state.registerNameBindingsByValue[value],
               existing != producer.registerNameBindingsByValue[value] { continue }
            if let existing = state.valueTypeHints[value], existing != producer.valueTypeHints[value] { continue }
            // Store the original producer's complete width and value. The
            // physical cell can alias that value without allocating a write.
            state.currentIntegerDefinitionByIndex[index] = definition
            state.unavailableRegisterValues.remove("x\(index)")
            state.unavailableRegisterValues.remove("w\(index)")
            state.callUnavailableRegisterValues.remove("x\(index)")
            state.callUnavailableRegisterValues.remove("w\(index)")
            if let binding = producer.registerNameBindingsByValue[value],
               state.registerNameBindingsByValue[value] == nil {
                state.registerNameBindingsByValue[value] = binding
                state.registerNameBindingOrder.append(value)
            }
            if let type = producer.valueTypeHints[value] { state.valueTypeHints[value] = type }
            recovered = true
        }
        if recovered { Self.foldAllocationCounters(from: producer, into: &state) }
    }

    private func pendingStackPointerVersion(
        entering blockIndex: Int, outgoing: [Int: BuilderState]
    ) -> Int? {
        guard permitsPendingSPRecovery else { return nil }
        var active: Set<Int> = [blockIndex]
        var memo: [Int: Int] = [:]
        func visit(_ index: Int) -> Int? {
            if let version = memo[index] { return version }
            if let state = outgoing[index] {
                guard case let .register(name, version) = state.readRegister("sp"),
                      name == "sp" else { return nil }
                memo[index] = version
                return version
            }
            guard !spWritingBlocks.contains(index), active.insert(index).inserted else { return nil }
            defer { active.remove(index) }
            let predecessors = cfg.blocks[index].predecessors
            guard !predecessors.isEmpty else { return nil }
            var agreed: Int?
            for predecessor in predecessors {
                guard let version = visit(predecessor),
                      agreed == nil || agreed == version else { return nil }
                agreed = version
            }
            if let agreed { memo[index] = agreed }
            return agreed
        }
        var agreed: Int?
        for predecessor in cfg.blocks[blockIndex].predecessors {
            guard let version = visit(predecessor),
                  agreed == nil || agreed == version else { return nil }
            agreed = version
        }
        return agreed
    }

    /// Natural-loop headers (back-edge targets) whose loop contains a block
    /// listed in `writers`.
    static func loopHeaders(in cfg: CFG, containingAnyOf writers: Set<Int>) -> Set<Int> {
        var headers: Set<Int> = []
        for edge in cfg.backEdges {
            var loop: Set<Int> = [edge.to, edge.from]
            var work = [edge.from]
            while let block = work.popLast() {
                if block == edge.to { continue }
                for predecessor in cfg.blocks[block].predecessors where !loop.contains(predecessor) {
                    loop.insert(predecessor); work.append(predecessor)
                }
            }
            if !loop.isDisjoint(with: writers) { headers.insert(edge.to) }
        }
        return headers
    }

    static func admit<Row: DecompilerInstructionRow>(_ rows: [Row],
                                                       hasExternalFacts: Bool,
                                                       allowVectorLoop: Bool = false) -> Self? {
        guard !hasExternalFacts, rows.count >= 4, rows.count <= 64,
              rows.last?.mnemonic.lowercased() == "ret" else { return nil }
        var hasBranch = false
        var hasLoopArithmetic = false
        var vectorLoads = 0, vectorStores = 0, vectorTransforms = 0
        var targets: [UInt64] = []
        var referencedXRegisters: Set<Int> = []
        var control: [MacIRInstruction] = []
        control.reserveCapacity(rows.count)
        for (index, row) in rows.enumerated() {
            if index > 0 {
                let next = rows[index - 1].address.addingReportingOverflow(4)
                guard !next.overflow, next.partialValue == row.address else { return nil }
            }
            let mnemonic = row.mnemonic.lowercased()
            let operands = row.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            for operand in operands {
                if let index = xRegisterIndex(operand) { referencedXRegisters.insert(index) }
            }
            let operation: MacIROperation
            switch mnemonic {
            case "mov":
                guard operands.count == 2, isGPR(operands[0]),
                      isGPR(operands[1]) || immediate(operands[1]) != nil else { return nil }
                operation = .unknown(destination: nil, mnemonic: mnemonic, operands: row.operands)
            case "nop":
                guard operands.isEmpty else { return nil }
                operation = .unknown(destination: nil, mnemonic: mnemonic, operands: row.operands)
            case "ldr", "str":
                guard allowVectorLoop,
                      let transfer = MacIRBuilder.neonBufferSequence(row),
                      transfer.mode == .postIndex, transfer.delta == 16,
                      transfer.vectors.count == 1 else { return nil }
                if let index = xRegisterIndex(transfer.base) { referencedXRegisters.insert(index) }
                if transfer.effect == .load { vectorLoads += 1 } else { vectorStores += 1 }
                operation = .unknown(destination: nil, mnemonic: mnemonic, operands: row.operands)
            case "eor":
                guard allowVectorLoop,
                      let logical = MacIRBuilder.neonLogical(mnemonic: mnemonic, operandText: row.operands),
                      logical.kind == .eor, logical.width == .bytes16 else { return nil }
                vectorTransforms += 1
                operation = .unknown(destination: nil, mnemonic: mnemonic, operands: row.operands)
            case "add", "subs":
                guard operands.count == 3, operands[0] == operands[1],
                      xRegisterIndex(operands[0]) != nil,
                      (xRegisterIndex(operands[2]) != nil || immediate(operands[2]) != nil) else { return nil }
                hasLoopArithmetic = true
                operation = .unknown(destination: nil, mnemonic: mnemonic, operands: row.operands)
            case "cbz", "cbnz":
                guard operands.count == 2, isGPR(operands[0]),
                      let target = address(operands[1]), target <= UInt64(Int64.max) else { return nil }
                hasBranch = true
                targets.append(target)
                operation = .conditionalBranch(condition: mnemonic == "cbz" ? "==" : "!=",
                                               left: .immediate(0), right: .immediate(0),
                                               target: .immediate(Int64(bitPattern: target)))
            case "b.ne":
                guard operands.count == 1,
                      let target = address(operands[0]), target <= UInt64(Int64.max),
                      index > 0, rows[index - 1].mnemonic.lowercased() == "subs" else { return nil }
                hasBranch = true
                targets.append(target)
                operation = .conditionalBranch(condition: "!=", left: .immediate(0),
                                               right: .immediate(0),
                                               target: .immediate(Int64(bitPattern: target)))
            case "b":
                guard operands.count == 1, let target = address(operands[0]),
                      target <= UInt64(Int64.max) else { return nil }
                hasBranch = true
                targets.append(target)
                operation = .intrinsic(destination: nil, name: "branch",
                                       arguments: [.immediate(Int64(bitPattern: target))])
            case "ret":
                guard index == rows.count - 1, operands.isEmpty else { return nil }
                operation = .returnValue(nil)
            default:
                return nil
            }
            control.append(MacIRInstruction(
                source: MacIRSourceSpan(address: row.address, byteText: row.bytes,
                                        mnemonic: mnemonic, operands: row.operands,
                                        comment: row.comment), operation: operation))
        }
        let rowAddresses = Set(rows.map(\.address))
        guard hasBranch, targets.allSatisfy(rowAddresses.contains) else { return nil }
        let cfg = CFGBuilder.buildCFG(instructions: control)
        guard !cfg.hasUnresolvedTargets, cfg.irreducibleBlocks.isEmpty,
              cfg.backEdges.count <= 1,
              cfg.backEdges.allSatisfy({ $0.to != cfg.entryIndex }),
              cfg.blocks.allSatisfy({ block in
                  block.successors.allSatisfy {
                      $0 > block.index || cfg.backEdges.contains(CFGEdge(block.index, $0))
                  }
              }),
              !hasLoopArithmetic || cfg.backEdges.count == 1,
              cfg.backEdges.isEmpty || rows.contains(where: { $0.mnemonic.lowercased() == "b.ne" }) else { return nil }
        if allowVectorLoop {
            let vectorOrder = rows.enumerated().compactMap { index, row -> (Int, String)? in
                let mnemonic = row.mnemonic.lowercased()
                return ["ldr", "str", "eor"].contains(mnemonic) ? (index, mnemonic) : nil
            }
            guard vectorLoads == 2, vectorStores == 1, vectorTransforms == 1,
                  cfg.backEdges.count == 1,
                  rows.filter({ $0.mnemonic.lowercased() == "cbz" }).count == 1,
                  rows.filter({ $0.mnemonic.lowercased() == "b.ne" }).count == 1,
                  cfg.blocks.count == 3, cfg.entryIndex == 0,
                  cfg.blocks[0].endIndex == 1,
                  cfg.blocks[1].startIndex == 1,
                  cfg.blocks[1].endIndex == rows.count - 1,
                  cfg.blocks[2].startIndex == rows.count - 1,
                  cfg.backEdges == [CFGEdge(1, 1)],
                  Set(cfg.blocks[0].successors) == [1, 2],
                  Set(cfg.blocks[1].successors) == [1, 2],
                  rows[0].mnemonic.lowercased() == "cbz",
                  rows[rows.count - 2].mnemonic.lowercased() == "b.ne",
                  vectorOrder.map({ $0.1 }) == ["ldr", "ldr", "eor", "str"],
                  vectorOrder.allSatisfy({ cfg.blocks[1].instructionRange.contains($0.0) }) else { return nil }
        }
        // `subs` must dominate its flag-consuming b.ne within one basic block.
        // A direct target at b.ne would bypass the textual predecessor and
        // make the recovered branch condition unavailable on that edge.
        for (index, row) in rows.enumerated() where row.mnemonic.lowercased() == "b.ne" {
            guard let block = cfg.blocks.first(where: { $0.instructionRange.contains(index) }),
                  block.startIndex < index,
                  rows[index - 1].mnemonic.lowercased() == "subs" else { return nil }
        }
        var reachable: Set<Int> = [cfg.entryIndex]
        for _ in 0..<cfg.blocks.count {
            for block in cfg.blocks where reachable.contains(block.index) {
                reachable.formUnion(block.successors)
            }
        }
        guard reachable.count == cfg.blocks.count,
              cfg.blocks.last?.endIndex == rows.count,
              cfg.blocks.last?.predecessors.isEmpty == false else { return nil }
        var forks: [Int: ConditionalFork] = [:]
        for block in cfg.blocks where block.successors.count == 2 {
            let terminator = rows[block.endIndex - 1]
            let mnemonic = terminator.mnemonic.lowercased()
            guard mnemonic == "cbz" || mnemonic == "cbnz" else { continue }
            let register = terminator.operands.split(separator: ",", maxSplits: 1)
                .first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            forks[block.index] = ConditionalFork(
                register: register, condition: mnemonic == "cbz" ? "==" : "!=",
                taken: block.successors[0], fallthroughBlock: block.successors[1])
        }
        return Self(cfg: cfg,
                    blockAtStart: Dictionary(uniqueKeysWithValues: cfg.blocks.map { ($0.startIndex, $0.index) }),
                    blockAtEnd: Dictionary(uniqueKeysWithValues: cfg.blocks.map { ($0.endIndex - 1, $0.index) }),
                    conditionalForks: forks,
                    referencedXRegisters: referencedXRegisters.sorted())
    }

    /// Cached inferred returns can contain HFA fragments instead of re-reading
    /// registers. Never retain a predecessor's cached SIMD result after its
    /// producer or width authority changed at the join.
    private static func invalidateCachedSIMDResult(
        in state: inout BuilderState, affectedIndices: Set<Int>
    ) {
        func dependsOnAffectedSIMD(_ value: MacIRValue) -> Bool {
            switch value {
            case let .register(name, _):
                guard let view = BuilderState.simdViewWidth(name) else { return false }
                return affectedIndices.contains(view.index)
            case let .abiComposite(_, fragments):
                return fragments.contains(where: dependsOnAffectedSIMD)
            default: return false
            }
        }
        if let result = state.latestABIResultValue, dependsOnAffectedSIMD(result) {
            state.latestABIResultValue = .unknown("unavailable_simd_join_result")
        }
    }

    private static func reserveRegisterFloor(_ floor: Int, in state: inout BuilderState) {
        state.registerVersionFloor = max(state.registerVersionFloor, floor)
        state.nextRegisterTemporaryIndex = max(state.nextRegisterTemporaryIndex, floor)
    }

    private static func foldAllocationCounters(from predecessor: BuilderState, into state: inout BuilderState) {
        state.nextRegisterTemporaryIndex = max(state.nextRegisterTemporaryIndex, predecessor.nextRegisterTemporaryIndex)
        state.registerVersionFloor = max(state.registerVersionFloor, predecessor.registerVersionFloor)
        for (register, version) in predecessor.registerVersions {
            state.registerVersions[register] = max(state.registerVersions[register, default: 0], version)
        }
    }

    func incoming(for blockIndex: Int, entry: BuilderState,
                  outgoing: [Int: BuilderState], phis: inout [PhiDraft],
                  pendingGPRDefinitions: [Int: [Int: PendingGPRDefinition]] = [:],
                  pendingVectorCopyDefinitions: [Int: PendingVectorCopyDefinition] = [:]) -> BuilderState {
        guard blockIndex != cfg.entryIndex else { return entry }
        let floor = blockIndex * (cfg.blocks.reduce(0) { $0 + $1.instructionRange.count } + 1)
        let predecessors = cfg.blocks[blockIndex].predecessors
        let states = predecessors.compactMap { outgoing[$0] }
        guard let first = states.first,
              predecessors.allSatisfy({ outgoing[$0] != nil ||
                  cfg.backEdges.contains(CFGEdge($0, blockIndex)) }) else {
            var unavailable = entry
            // Entry SP is not a valid default at an unvisited predecessor.
            // Recover only a unanimous emitted definition across SP-free paths;
            // a cycle, missing root, pending writer or disagreement fails closed.
            // This proves the register only, never cached stack coordinates.
            unavailable.invalidateStackCoordinateSystem()
            unavailable.hasExplicitStackWriteback = true
            unavailable.callUnavailableRegisterValues.formUnion(["sp", "wsp"])
            let recoveredSPVersion = pendingStackPointerVersion(entering: blockIndex, outgoing: outgoing)
            if recoveredSPVersion != nil {
                unavailable.callUnavailableRegisterValues.remove("sp")
            }
            for index in 0...30 { unavailable.recordUnmodeledDefiniteWrite(for: "x\(index)") }
            for index in 0...31 { unavailable.callResultVectorWidth[index] = 0 }
            Self.invalidateCachedSIMDResult(in: &unavailable, affectedIndices: Set(0...31))
            for predecessor in states {
                Self.foldAllocationCounters(from: predecessor, into: &unavailable)
            }
            recoverPendingGPRDefinitions(entering: blockIndex, outgoing: outgoing,
                witnesses: pendingGPRDefinitions, into: &unavailable)
            recoverPendingGPRCopyDefinitions(entering: blockIndex, outgoing: outgoing,
                witnesses: pendingGPRDefinitions, into: &unavailable)
            recoverPendingVectorCopyDefinition(entering: blockIndex, outgoing: outgoing,
                witnesses: pendingVectorCopyDefinitions, into: &unavailable)
            if let recoveredSPVersion {
                unavailable.registerVersions["sp"] = recoveredSPVersion
            }
            Self.reserveRegisterFloor(floor, in: &unavailable)
            return unavailable
        }
        var merged = first
        for predecessor in states.dropFirst() {
            Self.foldAllocationCounters(from: predecessor, into: &merged)
            for value in predecessor.registerNameBindingOrder where merged.registerNameBindingsByValue[value] == nil {
                merged.registerNameBindingsByValue[value] = predecessor.registerNameBindingsByValue[value]
                merged.registerNameBindingOrder.append(value)
            }
            merged.valueTypeHints.merge(predecessor.valueTypeHints) { existing, _ in existing }
        }
        // Cached stack values come from one predecessor only. At a real join
        // (several predecessors, or a back edge not yet visited) another path
        // may have stored to the slot, so no fact may forward across it.
        if predecessors.count > 1 || states.count != predecessors.count {
            merged.invalidateAllStackSlotValues()
        }
        // An escape on any path stays an escape after the join.
        merged.stackAddressEscapedThroughMemory = states.contains { $0.stackAddressEscapedThroughMemory }
        // Preserve dirty entry-memory provenance across every incoming path.
        merged.entrySPIsExact = states.count == predecessors.count && states.allSatisfy { $0.entrySPIsExact }
        Self.reserveRegisterFloor(floor, in: &merged)
        for index in 0...30 {
            let x = "x\(index)"
            let w = "w\(index)"
            let disagrees = states.dropFirst().contains(where: {
                $0.readRegister(x) != first.readRegister(x) ||
                    $0.readRegister(w) != first.readRegister(w)
            })
            let hasPendingBackedge = states.count != predecessors.count
            if (disagrees || hasPendingBackedge), referencedXRegisters.contains(index),
               states.allSatisfy({ !Self.isUnavailable($0.readRegister(x)) }),
               states.allSatisfy({ !Self.isUnavailable($0.readRegister(w)) }) {
                let destination = merged.writeRegister(x)
                merged.currentIntegerDefinitionByIndex[index]?.isJoinedDefinition = true
                if index == 0 {
                    merged.currentIntegerDefinitionByIndex[0]?.isSyntheticReturnPhi = true
                    // writeRegister also caches ABI producers. This synthetic
                    // join must go through the origin-aware definition check.
                    if merged.latestABIResultValue == destination {
                        merged.latestABIResultValue = nil
                    }
                }
                phis.append(PhiDraft(blockIndex: blockIndex, registerIndex: index,
                                     destination: destination))
            } else if disagrees || hasPendingBackedge {
                merged.recordUnmodeledDefiniteWrite(for: x)
                if index == 0 {
                    // A converged RET still returns an ABI value. The join
                    // lacks a proven producer; it is not a void function.
                    merged.latestABIResultValue = .unknown("unavailable_x0")
                }
            }
        }
        // SP joins like x0-x30, but only where its value can actually differ.
        let spDisagrees = states.dropFirst().contains { $0.readRegister("sp") != first.readRegister("sp") }
        if spDisagrees || (states.count != predecessors.count && spWritingLoopHeaders.contains(blockIndex)) {
            if referencesSP, states.allSatisfy({ !Self.isUnavailable($0.readRegister("sp")) }) {
                let destination = merged.writeRegister("sp")
                phis.append(PhiDraft(blockIndex: blockIndex, registerIndex: 31,
                                     destination: destination, registerName: "sp"))
            } else {
                merged.recordUnmodeledDefiniteWrite(for: "sp")
            }
        }
        // A whole-v read is not a producer identity for partial SIMD results:
        // both an S and a D result can read as the same unavailable-upper marker.
        // Join every view even on scalar plans (whose referencedVRegisters is empty).
        let hasPendingBackedge = states.count != predecessors.count
        let vectorViews: [(name: String, width: Int)] = [
            ("b", 8), ("h", 16), ("s", 32), ("d", 64), ("q", 128), ("v", 128)
        ]
        var affectedSIMDResultIndices: Set<Int> = []
        for index in 0...31 {
            let v = "v\(index)"
            let commonWidth = states.map { state in
                let resultWidth = state.callResultVectorWidth[index] ?? 128
                let preservedWidth = state.permitsNEONBufferCarrier &&
                    state.regionUpperVectorUnavailable.contains(v) ? 64 : 128
                return min(resultWidth, preservedWidth)
            }.min() ?? 0
            if commonWidth == 0 || commonWidth < (first.callResultVectorWidth[index] ?? 128) {
                affectedSIMDResultIndices.insert(index)
            }
            if commonWidth < 128 { merged.callResultVectorWidth[index] = commonWidth }
            let disagrees = vectorViews.contains { view in
                guard view.width <= commonWidth else { return false }
                let register = "\(view.name)\(index)"
                return states.dropFirst().contains {
                    $0.readRegister(register) != first.readRegister(register)
                }
            }
            guard disagrees || hasPendingBackedge else { continue }
            affectedSIMDResultIndices.insert(index)
            if commonWidth == 128, referencedVRegisters.contains(index),
               states.allSatisfy({ !Self.isUnavailable($0.readRegister(v)) }) {
                let destination = merged.writeRegister(v)
                phis.append(PhiDraft(blockIndex: blockIndex, registerIndex: index,
                                     destination: destination, registerName: v, bitWidth: 128))
            } else {
                // Partial scalar/HFA carriers do not have a projection-aware
                // phi here. A zero-width tombstone rejects ALL aliases instead
                // of selecting the first producer. writeRegister clears it on
                // the next real SIMD definition, as for call-result width caps.
                merged.callResultVectorWidth[index] = 0
            }
        }
        Self.invalidateCachedSIMDResult(in: &merged, affectedIndices: affectedSIMDResultIndices)
        // Synthetic phi writes do not establish caller construction. Require a
        // write in every available predecessor; an unseen backedge abstains.
        merged.constructedCallArgumentGPRs = states.count == predecessors.count
            ? states.dropFirst().reduce(first.constructedCallArgumentGPRs) {
                $0.intersection($1.constructedCallArgumentGPRs)
            } : []
        merged.resolvedX0PhiReturnProducers = resolvedX0ReturnProducers(phis, outgoing: outgoing)
        return merged
    }

    /// Resolve only completed predecessor snapshots, including backedges.
    /// One real incoming write suffices under the existing producer heuristic;
    /// this is not an all-path return-contract proof. Entry-only cycles have no
    /// seed. Each node/edge is visited a bounded number of times per join,
    /// without recursive traversal or repeated whole-graph fixed-point scans.
    private func resolvedX0ReturnProducers(_ drafts: [PhiDraft],
                                           outgoing: [Int: BuilderState]) -> Set<MacIRValue> {
        var dependents: [MacIRValue: [MacIRValue]] = [:]
        var producers: Set<MacIRValue> = []
        for draft in drafts where draft.register == "x0" {
            let predecessors = cfg.blocks[draft.blockIndex].predecessors
            let states = predecessors.compactMap { outgoing[$0] }
            guard states.count == predecessors.count,
                  states.allSatisfy({ !Self.isUnavailable($0.readRegister("x0")) }) else { continue }
            for state in states {
                // An entry argument has no current definition and is not a
                // producer. A real w0 write keeps its original width/value.
                guard let definition = state.currentIntegerDefinitionByIndex[0] else { continue }
                if definition.isSyntheticReturnPhi {
                    dependents[definition.value, default: []].append(draft.destination)
                } else {
                    producers.insert(draft.destination)
                }
            }
        }
        var work = Array(producers)
        while let source = work.popLast() {
            for destination in dependents[source] ?? [] where producers.insert(destination).inserted {
                work.append(destination)
            }
        }
        return producers
    }

    struct PhiResolution {
        let phis: [MacIRPhi]
        let retainsControlPresentation: Bool

        fileprivate init(phis: [MacIRPhi], retainsControlPresentation: Bool) {
            self.phis = phis
            self.retainsControlPresentation = retainsControlPresentation
        }
    }

    func resolvedPhis<Row: DecompilerInstructionRow>(_ drafts: [PhiDraft],
                                                      rows: [Row],
                                                      outgoing: [Int: BuilderState],
                                                      instructions: [MacIRInstruction]) -> [MacIRPhi] {
        resolvePhiPresentation(drafts, rows: rows, outgoing: outgoing,
                               instructions: instructions).phis
    }

    func resolvePhiPresentation<Row: DecompilerInstructionRow>(_ drafts: [PhiDraft],
                                                              rows: [Row],
                                                              outgoing: [Int: BuilderState],
                                                              instructions: [MacIRInstruction]) -> PhiResolution {
        let all = drafts.map { draft in
            let block = cfg.blocks[draft.blockIndex]
            let incoming = block.predecessors.sorted().map { predecessor -> MacIRPhi.Incoming in
                let source = rows[cfg.blocks[predecessor].endIndex - 1].address
                let value = outgoing[predecessor]?.readRegister(draft.register)
                    ?? .unknown("unavailable_\(draft.register)")
                return .init(predecessorAddress: source, value: value)
            }
            return MacIRPhi(blockAddress: rows[block.startIndex].address,
                            destination: draft.destination, bitWidth: draft.bitWidth,
                            incoming: incoming)
        }
        var used: Set<MacIRValue> = []
        func record(_ value: MacIRValue) {
            used.insert(value)
            switch value {
            case let .bitTest(inner, _), let .unary(_, inner): record(inner)
            case let .binaryExpression(_, left, right): record(left); record(right)
            case let .signedBitfield(field): record(field.source)
            default: break
            }
        }
        for instruction in instructions {
            switch instruction.operation {
            case let .assign(_, source): record(source)
            case let .binary(_, _, left, right): record(left); record(right)
            case let .load(_, address): record(address)
            case let .store(source, address): record(source); record(address)
            case let .loadWriteback(_, _, baseSource, _, _): record(baseSource)
            case let .storeWriteback(source, _, baseSource, _, _):
                record(source); record(baseSource)
            case let .conditionalBranch(_, left, right, target):
                record(left); record(right); record(target)
            case let .select(_, _, left, right, trueValue, falseValue):
                record(left); record(right); record(trueValue); record(falseValue)
            case let .call(frame, _): frame.bindingValues.forEach(record)
            case let .returnValue(value): if let value { record(value) }
            case let .intrinsic(_, _, arguments): arguments.forEach(record)
            case let .unknown(_, inputs, _, _):
                inputs.mayRead.forEach { record($0.value) }
                inputs.definiteRead.forEach { record($0.value) }
            default: break
            }
        }
        // An incoming value may itself be a phi at a preceding block. Resolve
        // the finite dependency graph without walking source order as execution.
        for _ in 0..<all.count {
            let before = used.count
            for phi in all where used.contains(phi.destination) {
                phi.incoming.forEach { record($0.value) }
            }
            if before == used.count { break }
        }
        let unresolvedReturns = Set(instructions.compactMap { instruction -> UInt64? in
            guard case let .returnValue(.some(.unknown(marker))) = instruction.operation,
                  marker == MacIRIndirectTargetResolution.unresolvedReturnContractMarker else { return nil }
            return instruction.source.address
        })
        // Keep the control renderer when a rejected return was a phi's last
        // consumer. Its old producer identity is presentation evidence only.
        let retainsControlPresentation = cfg.blocks.contains { block in
            guard unresolvedReturns.contains(rows[block.endIndex - 1].address),
                  let state = outgoing[block.index],
                  let definition = state.currentIntegerDefinitionByIndex[0],
                  definition.isSyntheticReturnPhi,
                  state.latestABIResultValue == nil,
                  !state.hasUnmodeledABIResultWrite,
                  !Self.isUnavailable(state.readRegister("x0")),
                  state.resolvedX0PhiReturnProducers.contains(definition.value),
                  !used.contains(definition.value) else { return false }
            return all.contains { $0.destination == definition.value }
        }
        return PhiResolution(phis: all.filter { used.contains($0.destination) },
                             retainsControlPresentation: retainsControlPresentation)
    }

    /// Lower one exact two-arm diamond at its first use. The select's source
    /// is the real join move, so no synthetic instruction or duplicate source
    /// identity is introduced. Other conflicting uses remain unavailable.
    func selectForJoinMove<Row: DecompilerInstructionRow>(
        rowIndex: Int, row: Row, outgoing: [Int: BuilderState],
        state: inout BuilderState
    ) -> MacIROperation? {
        guard let joinIndex = blockAtStart[rowIndex],
              row.mnemonic.lowercased() == "mov" else { return nil }
        let operands = row.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard operands.count == 2, Self.isGPR(operands[0]), Self.isGPR(operands[1]) else { return nil }
        let predecessors = cfg.blocks[joinIndex].predecessors
        let matchingForks = conditionalForks.filter { _, fork in
            Set([fork.taken, fork.fallthroughBlock]) == Set(predecessors)
        }
        guard predecessors.count == 2,
              matchingForks.count == 1,
              let forkEntry = matchingForks.first,
              cfg.blocks[forkEntry.value.taken].predecessors == [forkEntry.key],
              cfg.blocks[forkEntry.value.fallthroughBlock].predecessors == [forkEntry.key],
              CFGBuilder.dominates(forkEntry.key, joinIndex, domTree: cfg.domTree),
              let forkState = outgoing[forkEntry.key],
              let takenState = outgoing[forkEntry.value.taken],
              let fallthroughState = outgoing[forkEntry.value.fallthroughBlock] else { return nil }
        let trueValue = takenState.readRegister(operands[1])
        let falseValue = fallthroughState.readRegister(operands[1])
        guard trueValue != falseValue,
              !Self.isUnavailable(trueValue), !Self.isUnavailable(falseValue) else { return nil }
        let destination = state.writeRegister(operands[0])
        return .select(destination: destination, condition: forkEntry.value.condition,
                       left: forkState.readRegister(forkEntry.value.register),
                       right: .immediate(0), trueValue: trueValue, falseValue: falseValue)
    }

    private static func isUnavailable(_ value: MacIRValue) -> Bool {
        if case .unknown = value { return true }
        return false
    }

    private static func isGPR(_ text: String) -> Bool {
        guard let prefix = text.first, prefix == "x" || prefix == "w",
              let index = Int(text.dropFirst()) else { return false }
        return (0...30).contains(index) && text == "\(prefix)\(index)"
    }

    private static func xRegisterIndex(_ text: String) -> Int? {
        guard text.first == "x", let index = Int(text.dropFirst()),
              (0...30).contains(index), text == "x\(index)" else { return nil }
        return index
    }

    private static func address(_ text: String) -> UInt64? {
        if text.hasPrefix("0x") { return UInt64(text.dropFirst(2), radix: 16) }
        return UInt64(text)
    }

    private static func immediate(_ text: String) -> Int64? {
        guard text.hasPrefix("#") else { return nil }
        let number = String(text.dropFirst())
        if number.hasPrefix("0x") { return Int64(number.dropFirst(2), radix: 16) }
        return Int64(number)
    }
}

/// Safety floor for functions outside the phi composer's admission. A source
/// definition is usable only when every reaching predecessor agrees and the
/// linear builder holds that definition or can recover its lifted producer.
/// Disagreement never selects one
/// predecessor and never rewinds SSA allocation or accumulated function metadata.
// Passive census observations of the original execution, never proof inputs.
// Only an explicitly scoped test sink enables copying; the default is nil.
enum RejectedCFGDiagnostics {
    struct Entry: Sendable {
        let unavailable: Set<Int>
        let nonlexical: Bool
        let producers: [Int: Int]
    }
    struct Snapshot: Sendable {
        let value: MacIRValue
        let width: Int
        let isJoinedDefinition: Bool
        let isSyntheticReturnPhi: Bool

        init(value: MacIRValue, width: Int, isJoinedDefinition: Bool = false,
             isSyntheticReturnPhi: Bool = false) {
            self.value = value
            self.width = width
            self.isJoinedDefinition = isJoinedDefinition
            self.isSyntheticReturnPhi = isSyntheticReturnPhi
        }
    }
    struct OrdinaryDefinition {
        let value: MacIRValue
        let width: Int
        let type: String
        let zeroHigh: Bool
    }
    // Events are delivered synchronously. Planner value records are copied,
    // never planner instances or mutable BuilderState references.
    enum Event {
        case plan(id: UUID, addresses: [UInt64], ranges: [Range<Int>],
                  successors: [[Int]], predecessors: [[Int]], precedingRows: [[Int]],
                  effects: [[Int]], entries: [Int: Entry], incoming: [[Int]?],
                  callRows: Set<Int>, hasUnenumeratedTransfer: Bool)
        case modeled(id: UUID, row: Int)
        case snapshot(id: UUID, row: Int, cell: Int, definition: Snapshot)
        case missingSnapshot(id: UUID, row: Int, cell: Int, producer: Int)
        case comparison(id: UUID, row: Int, cell: Int, producer: Int,
                        snapshot: Snapshot, current: Snapshot?, needsRepair: Bool)
        case preservationVisit(id: UUID, row: Int, cell: Int, producer: Int,
                               prior: Int, outcome: String, modeled: Bool?,
                               writesCell: Bool?, predecessors: [Int]?)
        case preservationResult(id: UUID, row: Int, cell: Int, producer: Int, preserved: Bool)
        case restored(id: UUID, row: Int, cell: Int, definition: Snapshot)
        case physicalAttempt(id: UUID, start: UInt64, addresses: [UInt64],
                             ranges: [Range<Int>], predecessors: [[Int]], successors: [[Int]],
                             backEdges: [CFGEdge], file: String, line: Int)
        case physicalRows(id: UUID, rows: [RegionalPhysicalStatePlan.Row])
        case physicalCertificate(id: UUID, provedPositions: Set<RegionalProvedPosition>,
                                 liveIncoming: [[UInt8]], liveAfter: [[UInt8]])
        case physicalEnd(id: UUID, succeeded: Bool)
        case ordinaryProofBegin(id: UUID, start: UInt64, file: String, line: Int)
        case ordinaryProofEnd(id: UUID, succeeded: Bool)
        case ordinaryAttempt(id: UUID, start: UInt64, addresses: [UInt64],
                             parameters: [MacIRFunctionParameter], file: String, line: Int)
        case ordinaryFacts(id: UUID, plannerCompleted: Bool,
                           definitions: [RegionalOrdinaryValuePlan.DefinitionID: OrdinaryDefinition],
                           uses: [RegionalOrdinaryValuePlan.UseBinding],
                           edges: [RegionalOrdinaryValuePlan.EdgeBinding],
                           phiInputs: [RegionalOrdinaryValuePlan.DefinitionID: [CFGEdge: RegionalOrdinaryValuePlan.DefinitionID]],
                           before: [[RegionalOrdinaryValuePlan.DefinitionID?]],
                           after: [[RegionalOrdinaryValuePlan.DefinitionID?]],
                           replacements: [RegionalOrdinaryValuePlan.DefinitionID: RegionalOrdinaryValuePlan.DefinitionID])
        case nativeProofBegin(id: UUID, start: UInt64, file: String, line: Int)
        case nativeProofEnd(id: UUID, succeeded: Bool)
        case nativeAttempt(id: UUID, start: UInt64, addresses: [UInt64],
                           ranges: [Range<Int>], predecessors: [[Int]], successors: [[Int]],
                           backEdges: [CFGEdge], parameters: [MacIRFunctionParameter], file: String, line: Int)
        case nativeUse(id: UUID, binding: DecodedScalarNativeValuePlan.UseBinding)
        case nativeFacts(id: UUID, plannerCompleted: Bool,
                         definitions: [DecodedScalarNativeValuePlan.DefinitionID: OrdinaryDefinition],
                         edges: [DecodedScalarNativeValuePlan.EdgeBinding],
                         phiInputs: [DecodedScalarNativeValuePlan.DefinitionID: [CFGEdge: DecodedScalarNativeValuePlan.DefinitionID]],
                         before: [[DecodedScalarNativeValuePlan.DefinitionID?]],
                         after: [[DecodedScalarNativeValuePlan.DefinitionID?]],
                         replacements: [DecodedScalarNativeValuePlan.DefinitionID: DecodedScalarNativeValuePlan.DefinitionID])
        case guardObserved(kind: String, name: String, recorded: Bool, file: String, line: Int)
        case classificationBegin(id: UUID, file: String, line: Int)
        case classificationEnd(id: UUID, refusal: RegionalRefusal?)
        case buildBegin(id: UUID, name: String, start: UInt64)
        case buildEnd(id: UUID)
        case rowBegin(buildID: UUID, row: Int, address: UInt64)
        case rowEnd(buildID: UUID, row: Int)
        case entryRead(register: String, parameter: MacIRFunctionParameter,
                       sourceWidth: Int?, requestedWidth: Int?, projectedValue: MacIRValue,
                       file: String, line: Int)
    }
    @TaskLocal static var sink: (@Sendable (Event) -> Void)?
}

struct RejectedCFGStatePlan {
    private struct Entry {
        let unavailable: Set<Int>
        let nonlexical: Bool
        var producers: [Int: Int] = [:]
    }

    // Physical integer registers, SP, SIMD low/high halves, NZCV and memory.
    // Separating the SIMD halves preserves ABI-saved D8-D15 across calls.
    private static let flags = 96
    private static let memory = 97
    private static let cellCount = 98
    private static let entryDefinition = -1
    private static let mixedDefinition = -2
    private let entries: [Int: Entry]
    private var effects: [[Int]] = []
    private var precedingRows: [[Int]] = []
    private var modeledRows: Set<Int> = []
    private var callRows: Set<Int> = []
    private var producerSnapshots: [Int: [Int: IntegerRegisterDefinition]] = [:]
    // No identifier or diagnostic collection is allocated while capture is off.
    private var diagnosticID: UUID? = nil

    init<Row: DecompilerInstructionRow>(rows: [Row], jumpTables: [UInt64: [UInt64]]) {
        guard !rows.isEmpty else { entries = [:]; return }
        var indexByAddress: [UInt64: Int] = [:]
        for (index, row) in rows.enumerated() where indexByAddress[row.address] == nil {
            indexByAddress[row.address] = index
        }
        var leaders: Set<Int> = [0]
        var transfers: [Int: [Int]] = [:]
        var effects: [[Int]] = []
        var undecoded: Set<Int> = []
        var opaqueFlags: Set<Int> = []
        var hasUnenumeratedTransfer = false
        for (index, row) in rows.enumerated() {
            let mnemonic = row.mnemonic.lowercased()
            let operands = MacIRBuilder.splitOperands(row.operands)
            if ["bl", "blr", "blraa", "blrab", "blraaz", "blrabz"].contains(mnemonic) {
                callRows.insert(index)
            }
            effects.append(Self.writes(mnemonic: mnemonic, operands: operands))
            if Self.hasOpaqueFlagWrite(mnemonic: mnemonic, operands: operands) { opaqueFlags.insert(index) }
            if mnemonic == "unknown" || mnemonic == "unavailable" {
                undecoded.insert(index)
            }
            let conditional = mnemonic.hasPrefix("b.") || mnemonic.hasPrefix("bc.")
                || ["cbz", "cbnz", "tbz", "tbnz"].contains(mnemonic)
            let indirect = ["br", "braa", "brab", "braaz", "brabz"].contains(mnemonic)
            let returning = mnemonic.hasPrefix("ret") || mnemonic.hasPrefix("eret")
            let noReturn = mnemonic == "bl" && operands.first.map { NoReturnCatalog.isNoReturn($0) } == true
            guard conditional || mnemonic == "b" || indirect || returning || noReturn else { continue }
            if index + 1 < rows.count { leaders.insert(index + 1) }
            var targets: [Int] = []
            if conditional || mnemonic == "b" {
                if let operand = operands.last, let address = Self.address(operand) {
                    if let target = indexByAddress[address] { targets.append(target) }
                } else {
                    hasUnenumeratedTransfer = true
                }
            } else if indirect {
                if let addresses = jumpTables[row.address], !addresses.isEmpty {
                    for address in addresses {
                        if let target = indexByAddress[address] { targets.append(target) }
                        else { hasUnenumeratedTransfer = true }
                    }
                } else {
                    hasUnenumeratedTransfer = true
                }
            }
            if conditional, index + 1 < rows.count { targets.append(index + 1) }
            transfers[index] = Array(Set(targets)).sorted()
            leaders.formUnion(targets)
        }
        // Only enumerated in-function destinations contribute incoming edges.
        // External destinations and opaque indirect transfers leave this graph.
        let starts = leaders.sorted()
        let blockByStart = Dictionary(uniqueKeysWithValues: starts.enumerated().map { ($1, $0) })
        let ranges = starts.enumerated().map { block, start in
            start..<(block + 1 < starts.count ? starts[block + 1] : rows.count)
        }
        var successors = Array(repeating: [Int](), count: starts.count)
        var predecessors = successors
        var generated = Array(repeating: [Int: Int](), count: starts.count)
        for (block, range) in ranges.enumerated() {
            let last = range.upperBound - 1
            let targets = transfers[last] ?? (last + 1 < rows.count ? [last + 1] : [])
            successors[block] = targets.compactMap { blockByStart[$0] }
            for successor in successors[block] { predecessors[successor].append(block) }
            for row in range {
                for cell in effects[row] {
                    generated[block][cell] = undecoded.contains(row)
                        || (cell == Self.flags && opaqueFlags.contains(row)) ? Self.mixedDefinition : row
                }
            }
        }
        self.effects = effects
        precedingRows = Array(repeating: [], count: rows.count)
        for (block, range) in ranges.enumerated() {
            for row in range {
                precedingRows[row] = row == range.lowerBound
                    ? predecessors[block].map { ranges[$0].upperBound - 1 } : [row - 1]
            }
        }
        let initial = Array(repeating: Self.entryDefinition, count: Self.cellCount)
        // nil is unreachable, not a missing predecessor to be guessed. The
        // fixed point includes backedges before any body operand is captured.
        var incoming = Array<[Int]?>(repeating: nil, count: starts.count)
        var outgoing = incoming
        var work = [0]
        var queued: Set<Int> = [0]
        var cursor = 0
        while cursor < work.count {
            let block = work[cursor]
            cursor += 1
            queued.remove(block)
            var merged: [Int]? = block == 0 ? initial : nil
            for predecessor in predecessors[block] {
                guard let values = outgoing[predecessor] else { continue }
                if merged == nil {
                    merged = values
                } else {
                    for cell in 0..<Self.cellCount where merged?[cell] != values[cell] {
                        merged?[cell] = Self.mixedDefinition
                    }
                }
            }
            guard var values = merged else { continue }
            incoming[block] = values
            for (cell, definition) in generated[block] { values[cell] = definition }
            if outgoing[block] != values {
                outgoing[block] = values
                for successor in successors[block] where queued.insert(successor).inserted {
                    work.append(successor)
                }
            }
        }
        var lexical = initial
        var result: [Int: Entry] = [:]
        var poisonedStarts: [UInt64] = []
        for (block, start) in starts.enumerated() {
            let nonlexical = block == 0 ? !predecessors[block].isEmpty : predecessors[block] != [block - 1]
            if predecessors[block].count > 1 || nonlexical, let values = incoming[block] {
                let unavailable = Set((0..<Self.cellCount).filter {
                    values[$0] == Self.mixedDefinition || values[$0] != lexical[$0]
                })
                // Retain equal nominal identities too: a skipped textual join
                // may have tombstoned the actual physical register meanwhile.
                let producers = hasUnenumeratedTransfer ? [:] : Dictionary(
                    uniqueKeysWithValues: (0...30).compactMap { cell -> (Int, Int)? in
                        values[cell] >= 0 ? (cell, values[cell]) : nil
                    })
                if !unavailable.isEmpty || !producers.isEmpty {
                    result[start] = Entry(unavailable: unavailable, nonlexical: nonlexical,
                                          producers: producers)
                }
            } else if block != 0, incoming[block] == nil, hasUnenumeratedTransfer {
                // An opaque transfer may enter otherwise unreachable code. Do
                // not carry the preceding textual block's facts into that block.
                result[start] = Entry(unavailable: Set(0..<Self.cellCount), nonlexical: true)
                poisonedStarts.append(rows[start].address)
            }
            for (cell, definition) in generated[block] { lexical[cell] = definition }
        }
        entries = result
        // Copy the already computed fixed point and graph; do not rerun either.
        if let sink = RejectedCFGDiagnostics.sink {
            let id = UUID()
            diagnosticID = id
            sink(.plan(id: id, addresses: rows.map(\.address), ranges: ranges,
                successors: successors, predecessors: predecessors, precedingRows: precedingRows,
                effects: effects, entries: result.mapValues {
                    .init(unavailable: $0.unavailable, nonlexical: $0.nonlexical, producers: $0.producers)
                }, incoming: incoming, callRows: callRows,
                hasUnenumeratedTransfer: hasUnenumeratedTransfer))
        }
        if hasUnenumeratedTransfer,
           ProcessInfo.processInfo.environment["MACSCOPE_C2_OUT"] != nil {
            let poisoned = poisonedStarts.map { String($0, radix: 16) }.joined(separator: ",")
            print("REJECTED_CFG_UNENUMERATED start=\(String(rows[0].address, radix: 16)) end=\(String(rows[rows.count - 1].address, radix: 16)) rows=\(rows.count) poisoned=\(poisonedStarts.count) blocks=\(poisoned)")
        }
    }

    /// Capture only lifted values, never a BuilderState or memory facts.
    mutating func capture(at row: Int, operation: MacIROperation, state: BuilderState) {
        guard !callRows.contains(row) else { return }
        switch operation {
        case .unknown, .call: return
        default: break
        }
        modeledRows.insert(row)
        if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
            sink(.modeled(id: id, row: row))
        }
        for cell in effects[row] where cell <= 30 {
            guard !state.unavailableRegisterValues.contains("x\(cell)"),
                  !state.unavailableRegisterValues.contains("w\(cell)"),
                  let definition = state.currentIntegerDefinitionByIndex[cell],
                  definition.width == 32 || definition.width == 64 else { continue }
            producerSnapshots[row, default: [:]][cell] = definition
            if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                sink(.snapshot(id: id, row: row, cell: cell,
                    definition: .init(value: definition.value, width: definition.width,
                        isJoinedDefinition: definition.isJoinedDefinition, isSyntheticReturnPhi: definition.isSyntheticReturnPhi)))
            }
        }
    }

    /// The fixed point proves producer agreement. This walk additionally proves
    /// that every edge since that producer has actually been lifted and contains
    /// neither an opaque operation, a call, nor a physical alias write. Future
    /// (not yet lifted) paths cannot supply preservation authority.
    private func preserves(_ cell: Int, producer: Int, entering row: Int) -> Bool {
        var work = precedingRows[row]
        var visited: Set<Int> = []
        guard !work.isEmpty else {
            if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                sink(.preservationResult(id: id, row: row, cell: cell, producer: producer, preserved: false))
            }
            return false
        }
        while let prior = work.popLast() {
            if prior == producer {
                if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                    sink(.preservationVisit(id: id, row: row, cell: cell, producer: producer,
                        prior: prior, outcome: "producer", modeled: nil,
                        writesCell: nil, predecessors: nil))
                }
                continue
            }
            guard visited.insert(prior).inserted else {
                if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                    sink(.preservationVisit(id: id, row: row, cell: cell, producer: producer,
                        prior: prior, outcome: "alreadyVisited", modeled: nil,
                        writesCell: nil, predecessors: nil))
                }
                continue
            }
            // Preserve the original guard order and short-circuit behavior.
            // Unevaluated predicates are nil, not extra diagnostic queries.
            guard modeledRows.contains(prior) else {
                if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                    sink(.preservationVisit(id: id, row: row, cell: cell, producer: producer,
                        prior: prior, outcome: "unmodeled", modeled: false,
                        writesCell: nil, predecessors: nil))
                    sink(.preservationResult(id: id, row: row, cell: cell, producer: producer, preserved: false))
                }
                return false
            }
            guard !effects[prior].contains(cell) else {
                if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                    sink(.preservationVisit(id: id, row: row, cell: cell, producer: producer,
                        prior: prior, outcome: "write", modeled: true,
                        writesCell: true, predecessors: nil))
                    sink(.preservationResult(id: id, row: row, cell: cell, producer: producer, preserved: false))
                }
                return false
            }
            guard !precedingRows[prior].isEmpty else {
                if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                    sink(.preservationVisit(id: id, row: row, cell: cell, producer: producer,
                        prior: prior, outcome: "noPredecessor", modeled: true,
                        writesCell: false, predecessors: []))
                    sink(.preservationResult(id: id, row: row, cell: cell, producer: producer, preserved: false))
                }
                return false
            }
            if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                sink(.preservationVisit(id: id, row: row, cell: cell, producer: producer,
                    prior: prior, outcome: "preserved", modeled: true,
                    writesCell: false, predecessors: precedingRows[prior]))
            }
            work.append(contentsOf: precedingRows[prior])
        }
        if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
            sink(.preservationResult(id: id, row: row, cell: cell, producer: producer, preserved: true))
        }
        return true
    }

    /// Return true at a boundary so adjacency-only arithmetic rewrites reset.
    func reconcile(at row: Int, state: inout BuilderState) -> Bool {
        guard let entry = entries[row] else { return false }
        var restored: [Int: IntegerRegisterDefinition] = [:]
        var unavailable = entry.unavailable
        for (cell, producer) in entry.producers {
            guard let snapshot = producerSnapshots[producer]?[cell] else {
                if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                    sink(.missingSnapshot(id: id, row: row, cell: cell, producer: producer))
                }
                continue
            }
            let current = state.currentIntegerDefinitionByIndex[cell]
            let needsRepair = entry.unavailable.contains(cell)
                || state.unavailableRegisterValues.contains("x\(cell)")
                || state.unavailableRegisterValues.contains("w\(cell)")
                || current?.value != snapshot.value || current?.width != snapshot.width
            if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                sink(.comparison(id: id, row: row, cell: cell, producer: producer,
                    snapshot: .init(value: snapshot.value, width: snapshot.width,
                        isJoinedDefinition: snapshot.isJoinedDefinition, isSyntheticReturnPhi: snapshot.isSyntheticReturnPhi),
                    current: current.map { .init(value: $0.value, width: $0.width,
                        isJoinedDefinition: $0.isJoinedDefinition, isSyntheticReturnPhi: $0.isSyntheticReturnPhi) }, needsRepair: needsRepair))
            }
            guard needsRepair else { continue }
            // A prior restoration can change the physical value without a
            // nominal write. Failed preservation must tombstone that mismatch.
            unavailable.insert(cell)
            if preserves(cell, producer: producer, entering: row) {
                restored[cell] = snapshot
            }
        }
        guard !unavailable.isEmpty else { return false }
        // Invalidate stale ancillary facts even for a repaired physical cell.
        // Cached return/selector/memory evidence is not part of the snapshot.
        let cachedResult = state.latestABIResultValue
        // Stack-argument values lose their carrier in their expression. Retain
        // that ownership before invalidating the register/binding dictionaries.
        let cachedCarrierUnavailable = cachedResult.map { value in
            (unavailable.contains(0) && state.currentIntegerDefinitionByIndex[0]?.value == value)
                || (unavailable.contains(32) && ["s0", "d0"].contains {
                    state.currentEntryStackArgumentByScalarFPRegister[$0] == value
                })
        } ?? false
        for index in 0...30 where unavailable.contains(index) {
            let prior = state.currentIntegerDefinitionByIndex[index]
            let marker = MacIRValue.unknown("unavailable_x\(index)")
            let wasAvailable = !state.unavailableRegisterValues.contains("x\(index)")
                && !state.unavailableRegisterValues.contains("w\(index)")
            let retainArgumentSlot = index < 8 && (
                prior?.value == marker
                    || (wasAvailable && (prior != nil
                        || state.parameters.contains { $0.bindingID == .gpr(index) }))
            )
            state.recordUnmodeledDefiniteWrite(for: "x\(index)")
            if retainArgumentSlot {
                // The physical tombstone still governs every ordinary read.
                // Call binding alone retains this slot as explicit uncertainty;
                // real writes and call clobbers already replace/remove the record.
                state.currentIntegerDefinitionByIndex[index] = IntegerRegisterDefinition(
                    value: marker, width: 64)
            }
        }
        for (index, snapshot) in restored {
            state.currentIntegerDefinitionByIndex[index] = snapshot
            if let sink = RejectedCFGDiagnostics.sink, let id = diagnosticID {
                sink(.restored(id: id, row: row, cell: index,
                    definition: .init(value: snapshot.value, width: snapshot.width,
                        isJoinedDefinition: snapshot.isJoinedDefinition, isSyntheticReturnPhi: snapshot.isSyntheticReturnPhi)))
            }
            for prefix in ["x", "w"] {
                state.unavailableRegisterValues.remove("\(prefix)\(index)")
                state.callUnavailableRegisterValues.remove("\(prefix)\(index)")
            }
        }
        if unavailable.contains(31) {
            state.recordUnmodeledDefiniteWrite(for: "sp")
            state.callUnavailableRegisterValues.formUnion(["sp", "wsp"])
            // Plain [sp,#offset] must not fold through a lexical stack depth.
            state.hasExplicitStackWriteback = true
        }
        for index in 0...31 {
            if unavailable.contains(32 + index) {
                for prefix in ["b", "h", "s", "d", "q", "v"] {
                    let register = "\(prefix)\(index)"
                    state.unavailableRegisterValues.insert(register)
                    state.callUnavailableRegisterValues.insert(register)
                    state.vectorScalarCallUnavailableRegisterValues.insert(register)
                    state.currentEntryStackArgumentByScalarFPRegister.removeValue(forKey: register)
                }
                state.callResultVectorWidth[index] = 0
            } else if unavailable.contains(64 + index) {
                state.callResultVectorWidth[index] = min(state.callResultVectorWidth[index] ?? 128, 64)
                for prefix in ["q", "v"] {
                    state.callUnavailableRegisterValues.insert("\(prefix)\(index)")
                    state.vectorScalarCallUnavailableRegisterValues.insert("\(prefix)\(index)")
                }
            }
        }
        if unavailable.contains(Self.memory) { state.invalidateAllStackSlotValues() }
        if unavailable.contains(Self.flags) {
            state.lastComparison = nil
            state.lastAdjacentComparison = nil
            state.pendingConditionalCompare = nil
            state.sawConditionalCompareSinceComparison = true
        } else if entry.nonlexical {
            state.lastAdjacentComparison = nil
            state.pendingConditionalCompare = nil
        }
        if entry.nonlexical { state.lastDivision = nil }
        // Register invalidation must not turn a missing result into proof of
        // void, or leave a cached return referring to a bypassed definition.
        if let cachedResult {
            if cachedCarrierUnavailable || Self.depends(cachedResult, on: unavailable) {
                state.latestABIResultValue = .unknown(
                    state.callerReturnWidth == nil && state.authoritativeReturnLocation == nil
                        && !state.admitsInstructionReturnProducer
                        ? MacIRIndirectTargetResolution.unresolvedReturnContractMarker
                        : "unavailable_join_result")
            } else {
                state.latestABIResultValue = cachedResult
            }
        } else if unavailable.contains(0) {
            state.latestABIResultValue = .unknown(
                state.callerReturnWidth == nil && state.authoritativeReturnLocation == nil
                    && !state.admitsInstructionReturnProducer
                    ? MacIRIndirectTargetResolution.unresolvedReturnContractMarker : "unavailable_join_result")
        }
        state.provenSwitchSelectors = state.provenSwitchSelectors.filter {
            !Self.depends($0.value, on: unavailable)
        }
        return row != 0 || !unavailable.isEmpty
    }

    private static func depends(_ value: MacIRValue, on cells: Set<Int>) -> Bool {
        switch value {
        case let .register(name, _): return registerCells(name).contains(where: cells.contains)
        case let .argument(binding):
            switch binding.kind {
            case .gpr: return cells.contains(binding.value)
            case .simd: return cells.contains(32 + binding.value)
            case .entryStack: return cells.contains(memory) || cells.contains(31)
            }
        case .argumentFragment: return !cells.isEmpty
        case let .abiComposite(_, fragments): return fragments.contains { depends($0, on: cells) }
        case let .unary(_, inner), let .bitTest(inner, _): return depends(inner, on: cells)
        case let .binaryExpression(_, left, right): return depends(left, on: cells) || depends(right, on: cells)
        case let .signedBitfield(field): return depends(field.source, on: cells)
        case .stackSlot: return cells.contains(memory) || cells.contains(31)
        default: return false
        }
    }

    private static func registerCells(_ register: String) -> [Int] {
        let name = register.lowercased()
        if name == "sp" || name == "wsp" { return [31] }
        if name == "fp" { return [29] }
        if name == "lr" { return [30] }
        if let view = MacIRBuilder.integerRegisterView(name) { return [view.index] }
        if let view = BuilderState.simdViewWidth(name) {
            return view.width > 64 ? [32 + view.index, 64 + view.index] : [32 + view.index]
        }
        if let index = MacIRBuilder.vectorRegisterIndex(name) { return [32 + index, 64 + index] }
        return []
    }

    private static func writes(mnemonic: String, operands: [String]) -> [Int] {
        if mnemonic == "unknown" || mnemonic == "unavailable" { return Array(0..<cellCount) }
        var registers = MacIRBuilder.argumentRegisterWrites(mnemonic: mnemonic, operands: operands)
        if let writeback = MacIRBuilder.explicitMemoryWritebackBase(operands: operands) {
            registers.append(writeback)
        }
        if MacIRBuilder.unknownClaimsFirstOperandWrite(mnemonic: mnemonic),
           let destination = MacIRBuilder.firstOperandWriteForUnknown(mnemonic: mnemonic, operands: operands) {
            registers.append(destination)
        }
        var cells = Set(registers.flatMap(registerCells))
        // Any SIMD write changes the physical carrier, even when the legacy
        // lifter keeps only one scalar view available to later reads.
        for register in registers {
            if let view = BuilderState.simdViewWidth(register) { cells.insert(64 + view.index) }
        }
        if MacIRBuilder.writesNZCVFlags(mnemonic) || ["ccmp", "ccmn", "fccmp", "fccmpe"].contains(mnemonic)
            || hasOpaqueFlagWrite(mnemonic: mnemonic, operands: operands) {
            cells.insert(flags)
        }
        if ["bl", "blr", "blraa", "blrab", "blraaz", "blrabz"].contains(mnemonic) {
            cells.formUnion(0...18)
            cells.insert(30)
            cells.insert(flags)
            cells.insert(memory)
            for index in 0...31 {
                if !(8...15).contains(index) { cells.insert(32 + index) }
                cells.insert(64 + index)
            }
        }
        if MacIRBuilder.unmodeledMemoryWritePrefixes.contains(where: mnemonic.hasPrefix) {
            cells.insert(memory)
        }
        return cells.sorted()
    }

    private static func hasOpaqueFlagWrite(mnemonic: String, operands: [String]) -> Bool {
        ["rmif", "setf8", "setf16", "cfinv", "axflag", "xaflag"].contains(mnemonic)
            || (mnemonic == "msr" && operands.first?.lowercased() == "nzcv")
    }

    private static func address(_ operand: String) -> UInt64? {
        let text = operand.trimmingCharacters(in: .whitespaces)
        let number = text.hasPrefix("#") ? String(text.dropFirst()) : text
        if number.hasPrefix("0x") { return UInt64(number.dropFirst(2), radix: 16) }
        return UInt64(number)
    }
}

extension ScalarCFGStatePlan {
    /// Effect expansion can exceed the source-row count. Bound witness work
    /// independently before scanning tails or counting definition ownership.
    private static let pendingVectorCopyWitnessEffectLimit = 4096

    /// Metadata-bearing control effects are not silently treated as no-ops.
    private static func isPendingVectorCopyTransparentEffect(_ instruction: MacIRInstruction) -> Bool {
        let source = instruction.source
        guard source.syntheticPhiEdge == nil, source.tailCallEffect == nil,
              instruction == MacIRInstruction(source: source, operation: instruction.operation) else { return false }
        let operand = source.operands.trimmingCharacters(in: .whitespacesAndNewlines)
        switch (source.mnemonic.lowercased(), instruction.operation) {
        case let ("nop", .intrinsic(nil, "nop", arguments)):
            return operand.isEmpty && arguments.isEmpty
        case let ("b", .intrinsic(nil, "branch", arguments)):
            guard !operand.contains(","), let target = address(operand), target <= UInt64(Int64.max) else { return false }
            return arguments == [.immediate(Int64(target))]
        default:
            return false
        }
    }

    /// RegisterVersions is both a current carrier and an allocator. A width
    /// dictionary alone is not proof: INS also writes a vN carrier. The exact
    /// seed/copy effects below provide completeness; this checks their ownership.
    private static func ownsPendingVectorCopyValue(_ value: MacIRValue, in state: BuilderState) -> Bool {
        guard state.ssa == nil, state.permitsNEONBufferCarrier,
              state.permitsNEONScalarViewCarrier, !state.permitsNEONBitViewCarrier,
              case let .register(name, version) = value, version > 0,
              let index = MacIRBuilder.vectorRegisterIndex(name), name == "v\(index)",
              state.registerVersions[name] == version,
              state.vectorViewWidthByIndex[index] == 128,
              (state.callResultVectorWidth[index] ?? 128) == 128,
              !state.regionUpperVectorUnavailable.contains(name),
              !state.unavailableRegisterValues.contains(name),
              !state.unavailableRegisterValues.contains("q\(index)"),
              !state.callUnavailableRegisterValues.contains(name),
              !state.callUnavailableRegisterValues.contains("q\(index)"),
              state.readRegister(name) == value,
              state.readRegister("q\(index)") == value else { return false }
        return true
    }

    /// Reject duplicate ownership even if a malformed effect list reuses a
    /// value with a different operation. Destinationless implicit definitions
    /// cannot be seeds or copies and cannot occur between them or in their tail.
    private static func pendingVectorCopyExplicitOutputs(_ instruction: MacIRInstruction) -> [MacIRValue] {
        switch instruction.operation {
        case let .assign(destination, _), let .binary(destination, _, _, _),
             let .load(destination, _), let .stackSlotRead(destination, _, _),
             let .select(destination, _, _, _, _, _), let .compareToBool(destination, _, _, _):
            return [destination]
        case let .loadWriteback(destination, base, _, _, _): return [destination, base]
        case let .storeWriteback(_, base, _, _, _): return [base]
        case let .stackSlotPairRead(first, _, _, second, _, _): return [first, second]
        case let .call(_, result): return result.map { [$0] } ?? []
        case let .intrinsic(destination, name, arguments):
            if let destination { return [destination] }
            return name == "restore_pair" ? Array(arguments.prefix(2)) : []
        case let .unknown(destination, _, _, _): return destination.map { [$0] } ?? []
        default: return []
        }
    }

    /// One fact only: a 128-bit ORR same-source copy of a complete 128-bit
    /// MOVI/MVNI value in this committed block. Between seed and copy, and
    /// after copy, only exact B/NOP effects are accepted. This is deliberately
    /// not a generic vector-definition, lane-write, or numeric-ancestry solver.
    static func snapshotPendingVectorCopyDefinition(
        instructions: [MacIRInstruction], state: BuilderState
    ) -> PendingVectorCopyDefinition? {
        guard state.ssa == nil,
              (2...pendingVectorCopyWitnessEffectLimit).contains(instructions.count) else { return nil }
        var tail = instructions.count
        while tail > 0, isPendingVectorCopyTransparentEffect(instructions[tail - 1]) { tail -= 1 }
        guard tail > 0 else { return nil }
        let copy = instructions[tail - 1]
        let operands = copy.source.operands.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard copy.source.syntheticPhiEdge == nil, copy.source.tailCallEffect == nil,
              copy.source.mnemonic.lowercased() == "orr", operands.count == 3,
              operands.allSatisfy({ !$0.isEmpty }),
              operands[1] == operands[2], operands[0] != operands[1],
              let semantics = MacIRBuilder.neonLogical(mnemonic: "orr", operandText: copy.source.operands),
              semantics.width == .bytes16,
              case let .intrinsic(destination?, name, arguments) = copy.operation,
              name == semantics.intrinsicName, arguments.count == 2,
              arguments[0] == arguments[1],
              case let .register(destinationName, _) = destination,
              case let .register(inputName, _) = arguments[0],
              operands[0] == destinationName + ".16b", operands[1] == inputName + ".16b",
              ownsPendingVectorCopyValue(destination, in: state),
              ownsPendingVectorCopyValue(arguments[0], in: state),
              copy == MacIRInstruction(source: copy.source, operation: copy.operation, neonLogical: semantics)
        else { return nil }
        var seedEnd = tail - 1
        while seedEnd > 0, isPendingVectorCopyTransparentEffect(instructions[seedEnd - 1]) { seedEnd -= 1 }
        guard seedEnd > 0 else { return nil }
        let seed = instructions[seedEnd - 1]
        guard seed.source.syntheticPhiEdge == nil, seed.source.tailCallEffect == nil,
              let constant = MacIRBuilder.neonMoveImmediate(mnemonic: seed.source.mnemonic.lowercased(),
                                                           operandText: seed.source.operands),
              constant.destination == inputName, constant.semantics.activeBytes == 16,
              seed.operation == .intrinsic(destination: arguments[0], name: "neon_integer_constant", arguments: []),
              seed == MacIRInstruction(source: seed.source, operation: seed.operation, neonImmediate: constant.semantics),
              let index = MacIRBuilder.vectorRegisterIndex(destinationName) else { return nil }
        var destinationDefinitions = 0, inputDefinitions = 0
        for instruction in instructions {
            for output in pendingVectorCopyExplicitOutputs(instruction) {
                if output == destination { destinationDefinitions += 1 }
                if output == arguments[0] { inputDefinitions += 1 }
            }
        }
        guard destinationDefinitions == 1, inputDefinitions == 1 else { return nil }
        return PendingVectorCopyDefinition(source: copy.source, seedSource: seed.source,
            registerIndex: index, value: destination, input: arguments[0])
    }

    /// A separate single-root proof: all pending paths must reach the same
    /// committed block. No equal-value multi-root merge or cycle is inferred.
    private func pendingVectorCopyRoot(entering blockIndex: Int,
                                       outgoing: [Int: BuilderState]) -> Int? {
        guard pendingVectorCopyTraversalBudget > 0, pendingVectorCopyTraversalBudget <= 3 * 1024,
              cfg.blocks.count <= 1024, cfg.blocks.indices.contains(blockIndex),
              cfg.blocks[blockIndex].index == blockIndex,
              cfg.irreducibleBlocks.isEmpty, !cfg.hasUnresolvedTargets,
              outgoing[blockIndex] == nil else { return nil }
        let backedgeTargets = Set(cfg.backEdges.map(\.to))
        guard !backedgeTargets.contains(blockIndex) else { return nil }
        var remaining = pendingVectorCopyTraversalBudget
        let incoming = cfg.blocks[blockIndex].predecessors
        guard !incoming.isEmpty, incoming.count <= remaining, incoming.allSatisfy({
            cfg.blocks.indices.contains($0) && cfg.blocks[$0].successors.contains(blockIndex)
        }) else { return nil }
        var work = incoming.map { (index: $0, exiting: false) }
        var active: Set<Int> = [blockIndex]
        var completed: Set<Int> = []
        var root: Int?
        while let next = work.popLast() {
            guard remaining > 0 else { return nil }
            remaining -= 1
            let index = next.index
            guard cfg.blocks.indices.contains(index), cfg.blocks[index].index == index,
                  index != blockIndex else { return nil }
            if next.exiting {
                active.remove(index); completed.insert(index)
                continue
            }
            if outgoing[index] != nil {
                guard index < blockIndex, root == nil || root == index else { return nil }
                root = index
                continue
            }
            if completed.contains(index) { continue }
            guard pendingVectorCopyTransparentBlocks.contains(index),
                  !backedgeTargets.contains(index), active.insert(index).inserted,
                  !cfg.blocks[index].predecessors.isEmpty else { return nil }
            let predecessors = cfg.blocks[index].predecessors
            guard work.count < remaining, predecessors.count <= remaining - work.count - 1,
                  predecessors.allSatisfy({
                      cfg.blocks.indices.contains($0) && cfg.blocks[$0].successors.contains(index)
                  }) else { return nil }
            work.append((index: index, exiting: true))
            work.append(contentsOf: predecessors.map { (index: $0, exiting: false) })
        }
        return root
    }

    private func recoverPendingVectorCopyDefinition(
        entering blockIndex: Int, outgoing: [Int: BuilderState],
        witnesses: [Int: PendingVectorCopyDefinition], into state: inout BuilderState
    ) {
        guard state.ssa == nil, state.permitsNEONBufferCarrier,
              state.permitsNEONScalarViewCarrier, !state.permitsNEONBitViewCarrier,
              let root = pendingVectorCopyRoot(entering: blockIndex, outgoing: outgoing),
              let producer = outgoing[root], let witness = witnesses[root],
              Self.ownsPendingVectorCopyValue(witness.value, in: producer),
              Self.ownsPendingVectorCopyValue(witness.input, in: producer),
              case let .register(name, version) = witness.value,
              name == "v\(witness.registerIndex)",
              state.registerVersions[name, default: 0] <= version else { return }
        let value = witness.value
        if let existing = state.registerNameBindingsByValue[value],
           existing != producer.registerNameBindingsByValue[value] { return }
        if let existing = state.valueTypeHints[value], existing != producer.valueTypeHints[value] { return }
        // Import existing identity; do not call writeRegister, create a phi,
        // fabricate a new definition, or copy ABI/stack/caller authority.
        Self.foldAllocationCounters(from: producer, into: &state)
        state.registerVersions[name] = version
        state.vectorViewWidthByIndex[witness.registerIndex] = 128
        state.callResultVectorWidth.removeValue(forKey: witness.registerIndex)
        state.regionUpperVectorUnavailable.remove(name)
        state.unavailableRegisterValues.remove(name)
        state.unavailableRegisterValues.remove("q\(witness.registerIndex)")
        state.callUnavailableRegisterValues.remove(name)
        state.callUnavailableRegisterValues.remove("q\(witness.registerIndex)")
        // A full vector copy does not construct scalar FP call arguments.
        state.vectorScalarCallUnavailableRegisterValues.insert("s\(witness.registerIndex)")
        state.vectorScalarCallUnavailableRegisterValues.insert("d\(witness.registerIndex)")
        if let binding = producer.registerNameBindingsByValue[value],
           state.registerNameBindingsByValue[value] == nil {
            state.registerNameBindingsByValue[value] = binding
            state.registerNameBindingOrder.append(value)
        }
        if let type = producer.valueTypeHints[value] { state.valueTypeHints[value] = type }
    }
}
