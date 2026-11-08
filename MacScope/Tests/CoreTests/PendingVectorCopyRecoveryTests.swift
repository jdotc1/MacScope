import Foundation
import XCTest
@testable import MacScope

/// Source-authored regression cases. Execution is intentionally left to the
/// receiving build owner; no test result is asserted by this delivery.
final class PendingVectorCopyRecoveryTests: XCTestCase {
    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        .init(address: address, bytes: "", mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil)
    }

    private func source(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> MacIRSourceSpan {
        .init(address: address, byteText: "", mnemonic: mnemonic, operands: operands)
    }

    private func entry() -> BuilderState {
        var state = BuilderState(parameters: [])
        state.permitsNEONBufferCarrier = true
        state.permitsNEONScalarViewCarrier = true
        return state
    }

    private func producer(floor: Int = 0, address: UInt64 = 0x1000) throws
        -> (state: BuilderState, effects: [MacIRInstruction], witness: ScalarCFGStatePlan.PendingVectorCopyDefinition) {
        var state = entry()
        state.registerVersionFloor = floor
        state.nextRegisterTemporaryIndex = floor + 20
        let seedSource = source(address, "movi", "v8.16b, #7")
        let constant = try XCTUnwrap(MacIRBuilder.neonMoveImmediate(
            mnemonic: seedSource.mnemonic, operandText: seedSource.operands))
        let input = state.writeRegister(constant.destination)
        let seed = MacIRInstruction(source: seedSource, operation: .intrinsic(
            destination: input, name: "neon_integer_constant", arguments: []), neonImmediate: constant.semantics)
        let copySource = source(address + 4, "orr", "v9.16b, v8.16b, v8.16b")
        let logical = try XCTUnwrap(MacIRBuilder.neonLogical(mnemonic: "orr", operandText: copySource.operands))
        let operation = MacIRBuilder.liftNEONLogical(logical,
            operands: MacIRBuilder.splitOperands(copySource.operands), state: &state)
        let copy = MacIRInstruction(source: copySource, operation: operation, neonLogical: logical)
        let branch = MacIRInstruction(source: source(address + 8, "b", "0x1014"),
            operation: .intrinsic(destination: nil, name: "branch", arguments: [.immediate(0x1014)]))
        let effects = [seed, copy, branch]
        return (state, effects, try XCTUnwrap(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
            instructions: effects, state: state)))
    }

    private func topology(_ predecessors: [[Int]], transparent: Set<Int>,
                          backEdges: Set<CFGEdge> = [], unresolved: Bool = false) -> ScalarCFGStatePlan {
        let blocks = predecessors.enumerated().map { index, incoming in
            BasicBlock(index: index, startIndex: index, endIndex: index + 1,
                successors: predecessors.indices.filter { predecessors[$0].contains(index) },
                predecessors: incoming, isLoopHeader: backEdges.contains { $0.to == index })
        }
        let cfg = CFG(blocks: blocks, entryIndex: 0, domTree: [:], postDomTree: [:],
            loopHeaders: Set(backEdges.map(\.to)), backEdges: backEdges, irreducibleBlocks: [],
            blockByStartIndex: Dictionary(uniqueKeysWithValues: blocks.map { ($0.startIndex, $0.index) }),
            hasUnresolvedTargets: unresolved)
        var plan = ScalarCFGStatePlan(cfg: cfg, blockAtStart: [:], blockAtEnd: [:],
                                      conditionalForks: [:], referencedXRegisters: [])
        plan.pendingVectorCopyTransparentBlocks = transparent
        plan.pendingVectorCopyTraversalBudget = blocks.count * 3
        return plan
    }

    /// A real nonbackedge reverse-address path, with exact row certificates.
    private func fixture(middle: (String, String) = ("nop", "")) -> ScalarCFGStatePlan {
        let rows = [row(0x1000, "movi", "v8.16b, #7"), row(0x1004, "orr", "v9.16b, v8.16b, v8.16b"),
                    row(0x1008, "b", "0x1014"), row(0x100c, "umov", "x0, v9.d[1]"),
                    row(0x1010, "ret"), row(0x1014, middle.0, middle.1), row(0x1018, "b", "0x100c")]
        let blocks = [
            BasicBlock(index: 0, startIndex: 0, endIndex: 3, successors: [2], predecessors: [], isLoopHeader: false),
            BasicBlock(index: 1, startIndex: 3, endIndex: 5, successors: [], predecessors: [2], isLoopHeader: false),
            BasicBlock(index: 2, startIndex: 5, endIndex: 7, successors: [1], predecessors: [0], isLoopHeader: false)
        ]
        let cfg = CFG(blocks: blocks, entryIndex: 0, domTree: [:], postDomTree: [:],
            loopHeaders: [], backEdges: [], irreducibleBlocks: [],
            blockByStartIndex: [0: 0, 3: 1, 5: 2], hasUnresolvedTargets: false)
        var plan = ScalarCFGStatePlan(cfg: cfg, blockAtStart: [:], blockAtEnd: [:],
                                      conditionalForks: [:], referencedXRegisters: [])
        plan.pendingVectorCopyTransparentBlocks = MacIRBuilder.pendingGPRTransparentBlocks(in: plan.cfg, rows: rows)
        plan.pendingVectorCopyTraversalBudget = rows.count * 3
        return plan
    }

    private func incoming(_ plan: ScalarCFGStatePlan, producer: BuilderState,
                          witness: ScalarCFGStatePlan.PendingVectorCopyDefinition?,
                          initial: BuilderState? = nil) -> BuilderState {
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        let result = plan.incoming(for: 1, entry: initial ?? entry(), outgoing: [0: producer], phis: &phis,
            pendingVectorCopyDefinitions: witness.map { [0: $0] } ?? [:])
        XCTAssertTrue(phis.isEmpty)
        return result
    }

    func testCompleteCopyRestoresOnePhysicalVectorAndNotItsSeed() throws {
        let root = try producer()
        let plan = fixture()
        XCTAssertEqual(plan.pendingVectorCopyTransparentBlocks, [2])
        let result = incoming(plan, producer: root.state, witness: root.witness)
        for prefix in ["b", "h", "s", "d", "q", "v"] {
            XCTAssertEqual(result.readRegister("\(prefix)9"), root.witness.value)
        }
        XCTAssertEqual(result.readRegister("v8"), .unknown("unavailable_upper_v8"))
        XCTAssertEqual(result.readRegister("q10"), .unknown("unavailable_upper_v10"))
        XCTAssertEqual(result.readRegister("x9"), .unknown("unavailable_x9"))
        XCTAssertTrue(result.vectorScalarCallUnavailableRegisterValues.contains("s9"))
        XCTAssertTrue(result.vectorScalarCallUnavailableRegisterValues.contains("d9"))
        XCTAssertNil(result.latestABIResultValue)
        XCTAssertTrue(result.constructedCallArgumentGPRs.isEmpty)
    }

    func testRegionConsumerUsesCopiedValueAcrossUnseenPredecessor() throws {
        let rows = [row(0x4000, "mov", "x12, #2"), row(0x4004, "subs", "x12, x12, #1"),
                    row(0x4008, "b.ne", "0x4004"), row(0x400c, "movi", "v8.16b, #7"),
                    row(0x4010, "orr", "v9.16b, v8.16b, v8.16b"), row(0x4014, "b", "0x4020"),
                    row(0x4018, "umov", "x0, v9.d[1]"), row(0x401c, "b", "0x4028"),
                    row(0x4020, "nop"), row(0x4024, "b", "0x4018"), row(0x4028, "ret")]
        let function = try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "pending_vector_copy", startAddress: 0x4000,
                rows: rows, initialState: BuilderState(parameters: []), hasExternalFacts: false, isVariadic: false))
        let copy = try XCTUnwrap(function.instructions.first { $0.source.address == 0x4010 })
        let use = try XCTUnwrap(function.instructions.first { $0.source.address == 0x4018 })
        guard case let .intrinsic(value?, _, _) = copy.operation,
              case let .intrinsic(_, _, arguments) = use.operation else { return XCTFail("expected typed copy and UMOV") }
        XCTAssertNotNil(copy.neonLogical)
        XCTAssertNotNil(use.neonBitView)
        XCTAssertEqual(arguments, [value], "accepted baseline supplied unavailable_upper_v9 here")
        let rendered = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024)).print(function: function)
        let renderedUse = rendered.lines(sourcedAt: 0x4018).map(\.text)
        XCTAssertFalse(renderedUse.isEmpty)
        XCTAssertFalse(renderedUse.joined(separator: "\n").contains("unavailable_upper_v9"))

        // The same instruction fixture with a partial writer in the pending
        // block must retain the unknown rather than recover the previous copy.
        var blockedRows = rows
        blockedRows[8] = row(0x4020, "ins", "v9.d[0], x3")
        let blocked = try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "pending_vector_partial_write", startAddress: 0x4000,
                rows: blockedRows, initialState: BuilderState(parameters: []), hasExternalFacts: false, isVariadic: false))
        let blockedUse = try XCTUnwrap(blocked.instructions.first { $0.source.address == 0x4018 })
        guard case let .intrinsic(_, _, blockedArguments) = blockedUse.operation else {
            return XCTFail("expected typed UMOV after refused preservation")
        }
        XCTAssertEqual(blockedArguments, [.unknown("unavailable_upper_v9")])
        let blockedPrinted = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024)).print(function: blocked)
        XCTAssertTrue(blockedPrinted.lines(sourcedAt: 0x4018).map(\.text)
            .joined(separator: "\n").contains("unavailable_upper_v9"))
    }

    func testPendingPathRequiresPositiveNoWriterCertificate() throws {
        let root = try producer()
        for middle in [("ins", "v9.d[0], x3"), ("fmov", "d9, d8"), ("movi", "v9.16b, #7"),
                       ("orr", "v9.16b, v8.16b, v8.16b"), ("bl", "_callee"),
                       ("mystery", ""), ("paciasp", ""), ("ldr", "q9, [x3], #16"),
                       ("nop", "x9"), ("b", "0x100c,")] {
            let plan = fixture(middle: middle)
            XCTAssertFalse(plan.pendingVectorCopyTransparentBlocks.contains(2), middle.0)
            XCTAssertEqual(incoming(plan, producer: root.state, witness: root.witness).readRegister("v9"),
                           .unknown("unavailable_upper_v9"), middle.0)
        }
    }

    func testRootTailAndSeedGapRejectOpaqueImplicitAndPartialEffects() throws {
        let root = try producer()
        let seed = root.effects[0], copy = root.effects[1], branch = root.effects[2]
        let opaque = MacIRInstruction(source: source(0x1006, "mystery"),
            operation: .unknown(destination: nil, mnemonic: "mystery", operands: ""))
        let implicit = MacIRInstruction(source: source(0x1006, "pacia1716"),
            operation: .intrinsic(destination: nil, name: "pacia1716", arguments: []))
        let partial = MacIRInstruction(source: source(0x1006, "fmov", "d9, d8"),
            operation: .assign(destination: root.witness.value, source: root.witness.input))
        for barrier in [opaque, implicit, partial] {
            XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
                instructions: [seed, copy, barrier, branch], state: root.state))
            XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
                instructions: [seed, barrier, copy, branch], state: root.state))
        }
        let nop = MacIRInstruction(source: source(0x1006, "nop"),
            operation: .intrinsic(destination: nil, name: "nop", arguments: []))
        XCTAssertNotNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
            instructions: [opaque, seed, nop, copy, nop, branch], state: root.state))
        var decorated = nop
        decorated.memoryAccess = .init(byteWidth: 16)
        XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
            instructions: [seed, copy, decorated, branch], state: root.state))
    }

    func testIncompleteOrMismatchedProducerCannotBecomeWholeVectorWitness() throws {
        let root = try producer()
        var narrowSeed = root.effects[0]
        narrowSeed.source.operands = "v8.8b, #7"
        var narrowCopy = root.effects[1]
        narrowCopy.source.operands = "v9.8b, v8.8b, v8.8b"
        var mixedCopy = root.effects[1]
        mixedCopy.source.operands = "v9.16b, v8.16b, v7.16b"
        var laneCopy = root.effects[1]
        laneCopy.source.mnemonic = "ins"; laneCopy.source.operands = "v9.d[0], x3"
        var unknownInput = root.effects[1]
        unknownInput.operation = .intrinsic(destination: root.witness.value,
            name: try XCTUnwrap(root.effects[1].neonLogical).intrinsicName,
            arguments: [.unknown("unavailable_upper_v8"), .unknown("unavailable_upper_v8")])
        for effects in [[narrowSeed, root.effects[1], root.effects[2]],
                        [root.effects[0], narrowCopy, root.effects[2]],
                        [root.effects[0], mixedCopy, root.effects[2]],
                        [root.effects[0], laneCopy, root.effects[2]],
                        [root.effects[0], unknownInput, root.effects[2]],
                        [root.effects[1], root.effects[2]]] {
            XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(instructions: effects, state: root.state))
        }
        let duplicate = MacIRInstruction(source: source(0x0ffc, "ldr", "q9, [x3]"),
            operation: .load(destination: root.witness.value, address: .register(name: "x3", version: 0)))
        XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
            instructions: [duplicate] + root.effects, state: root.state))
    }

    func testMalformedCopyFieldsAndOversizedWitnessEffectsFailClosed() throws {
        let root = try producer()
        for text in ["v9.16b, v8.16b, v8.16b,", "v9.16b,, v8.16b, v8.16b",
                     ",v9.16b, v8.16b, v8.16b", "v9.16b, , v8.16b"] {
            var copy = root.effects[1]
            copy.source.operands = text
            XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
                instructions: [root.effects[0], copy, root.effects[2]], state: root.state), text)
        }
        let nop = MacIRInstruction(source: source(0x100c, "nop"),
            operation: .intrinsic(destination: nil, name: "nop", arguments: []))
        XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
            instructions: root.effects + Array(repeating: nop, count: 4096), state: root.state))
    }

    func testLaneOrLowHalfSeedCannotClaimFullInputDespiteVCarrierWidth() throws {
        for kind in ["ins", "movi"] {
            var state = entry()
            let seed: MacIRInstruction
            if kind == "ins" {
                let span = source(0x1000, "ins", "v8.d[0], x3")
                let parsed = try XCTUnwrap(MacIRBuilder.neonCopy(mnemonic: "ins", operandText: span.operands))
                seed = MacIRBuilder.liftNEONCopy(parsed, source: span, state: &state)
            } else {
                let span = source(0x1000, "movi", "v8.8b, #7")
                let parsed = try XCTUnwrap(MacIRBuilder.neonMoveImmediate(mnemonic: "movi", operandText: span.operands))
                seed = MacIRInstruction(source: span, operation: .intrinsic(
                    destination: state.writeRegister(parsed.destination), name: "neon_integer_constant", arguments: []),
                    neonImmediate: parsed.semantics)
            }
            let span = source(0x1004, "orr", "v9.16b, v8.16b, v8.16b")
            let logical = try XCTUnwrap(MacIRBuilder.neonLogical(mnemonic: "orr", operandText: span.operands))
            let copy = MacIRInstruction(source: span, operation: MacIRBuilder.liftNEONLogical(logical,
                operands: MacIRBuilder.splitOperands(span.operands), state: &state), neonLogical: logical)
            XCTAssertEqual(state.vectorViewWidthByIndex[8], 128,
                           "the retained vN carrier width alone does not prove a complete seed")
            XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(instructions: [seed, copy], state: state))
        }
    }

    func testPoisonedPartialAndStaleOwnershipRefuseImport() throws {
        let root = try producer()
        var cases: [BuilderState] = []
        var state = root.state; state.callResultVectorWidth[9] = 64; cases.append(state)
        state = root.state; state.vectorViewWidthByIndex[9] = 32; cases.append(state)
        state = root.state; state.regionUpperVectorUnavailable.insert("v9"); cases.append(state)
        state = root.state; state.unavailableRegisterValues.insert("q9"); cases.append(state)
        state = root.state; state.callUnavailableRegisterValues.insert("v9"); cases.append(state)
        state = root.state; state.registerVersions["v9", default: 0] += 1; cases.append(state)
        state = root.state; state.callResultVectorWidth[8] = 0; cases.append(state)
        state = root.state; state.registerVersions["v8", default: 0] += 1; cases.append(state)
        state = root.state; state.permitsNEONBitViewCarrier = true; cases.append(state)
        state = root.state; state.permitsNEONScalarViewCarrier = false; cases.append(state)
        for poisoned in cases {
            XCTAssertEqual(incoming(fixture(), producer: poisoned, witness: root.witness).readRegister("q9"),
                           .unknown("unavailable_upper_v9"))
        }
        XCTAssertEqual(incoming(fixture(), producer: root.state, witness: nil).readRegister("v9"),
                       .unknown("unavailable_upper_v9"))
    }

    func testCallPoisonAndScalarFPAuthorityAreNotClearedByFullVectorRecovery() throws {
        let root = try producer()
        var afterCall = root.state
        afterCall.invalidateGeneralVectorRegionAtCall(returning: nil)
        XCTAssertTrue(afterCall.regionUpperVectorUnavailable.contains("v9"),
                      "v8-v15 retain only their low 64 bits across a returning call")
        XCTAssertEqual(afterCall.readRegister("q9"), .unknown("unavailable_upper_v9"))
        XCTAssertNil(ScalarCFGStatePlan.snapshotPendingVectorCopyDefinition(
            instructions: root.effects, state: afterCall))
        XCTAssertEqual(incoming(fixture(), producer: afterCall, witness: root.witness).readRegister("v9"),
                       .unknown("unavailable_upper_v9"))

        var initial = entry()
        initial.callUnavailableRegisterValues.formUnion(["s9", "d9"])
        initial.vectorScalarCallUnavailableRegisterValues.formUnion(["s9", "d9"])
        initial.latestABIResultValue = .register(name: "d9", version: 99)
        let result = incoming(fixture(), producer: root.state, witness: root.witness, initial: initial)
        XCTAssertEqual(result.readRegister("q9"), root.witness.value)
        XCTAssertEqual(result.readRegister("d9"), root.witness.value,
                       "only the pre-existing region low-view projection uses the proven full carrier")
        XCTAssertTrue(result.callUnavailableRegisterValues.isSuperset(of: ["s9", "d9"]))
        XCTAssertTrue(result.vectorScalarCallUnavailableRegisterValues.isSuperset(of: ["s9", "d9"]))
        XCTAssertNil(result.latestABIResultValue)
        XCTAssertTrue(result.hasUnmodeledABIResultWrite)
    }

    func testSingleRootCycleBudgetAndDefaultOffBoundaries() throws {
        let root = try producer()
        for plan in [topology([[], [2], []], transparent: [2]),
                     topology([[], [2], [2]], transparent: [2]),
                     topology([[], [2], [1]], transparent: [2]),
                     topology([[], [2], [99]], transparent: [2]),
                     topology([[], [2], [0]], transparent: [2], unresolved: true),
                     topology([[], [0, 2], [0]], transparent: [2], backEdges: [CFGEdge(2, 1)])] {
            XCTAssertEqual(incoming(plan, producer: root.state, witness: root.witness).readRegister("v9"),
                           .unknown("unavailable_upper_v9"))
        }
        var disabled = fixture(); disabled.pendingVectorCopyTraversalBudget = 0
        var exhausted = fixture(); exhausted.pendingVectorCopyTraversalBudget = 1
        var uncertified = fixture(); uncertified.pendingVectorCopyTransparentBlocks = []
        for plan in [disabled, exhausted, uncertified] {
            XCTAssertEqual(incoming(plan, producer: root.state, witness: root.witness).readRegister("v9"),
                           .unknown("unavailable_upper_v9"))
        }
        let ordinary = BuilderState(parameters: [])
        XCTAssertEqual(incoming(fixture(), producer: root.state, witness: root.witness, initial: ordinary).readRegister("q9"),
                       .unknown("unavailable_upper_v9"))
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        XCTAssertEqual(disabled.incoming(for: 1, entry: entry(), outgoing: [0: root.state, 2: root.state],
            phis: &phis).readRegister("v9"), root.witness.value, "completed-predecessor behavior is unchanged")
    }

    func testIndependentEqualRootsDoNotMergeAndPendingDiamondCanAgree() throws {
        let left = try producer(), right = try producer(address: 0x2000)
        XCTAssertEqual(left.witness.value, right.witness.value)
        XCTAssertNotEqual(left.witness.source, right.witness.source)
        let distinct = topology([[], [], [0, 3], [1]], transparent: [3])
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        XCTAssertEqual(distinct.incoming(for: 2, entry: entry(), outgoing: [0: left.state, 1: right.state],
            phis: &phis, pendingVectorCopyDefinitions: [0: left.witness, 1: right.witness]).readRegister("v9"),
            .unknown("unavailable_upper_v9"))
        let diamond = topology([[], [2, 3], [0], [0]], transparent: [2, 3])
        XCTAssertEqual(incoming(diamond, producer: left.state, witness: left.witness).readRegister("v9"), left.witness.value)
    }

    func testAllocatorFloorsMetadataAndAncillaryAuthorityRemainSeparate() throws {
        let root = try producer(floor: 200)
        var producer = root.state
        producer.registerVersions["x18"] = 350
        producer.valueTypeHints[root.witness.value] = "__uint128_t"
        producer.valueTypeHints[root.witness.input] = "seed_type_must_not_import"
        producer.stackSlotValues[8] = StackSlotValueFact(value: .immediate(7), byteWidth: 8, carrierKind: .integer)
        producer.outgoingCallStackStores[16] = StackSlotValueFact(value: .immediate(9), byteWidth: 8, carrierKind: .integer)
        producer.constructedCallArgumentGPRs = [0, 7]
        producer.latestABIResultValue = root.witness.value
        var result = incoming(fixture(), producer: producer, witness: root.witness)
        XCTAssertEqual(result.readRegister("v9"), root.witness.value)
        XCTAssertGreaterThanOrEqual(result.registerVersionFloor, producer.registerVersionFloor)
        XCTAssertGreaterThanOrEqual(result.nextRegisterTemporaryIndex, producer.nextRegisterTemporaryIndex)
        XCTAssertEqual(result.registerVersions["x18"], 350)
        XCTAssertEqual(result.valueTypeHints[root.witness.value], "__uint128_t")
        XCTAssertNil(result.valueTypeHints[root.witness.input])
        XCTAssertTrue(result.stackSlotValues.isEmpty)
        XCTAssertTrue(result.outgoingCallStackStores.isEmpty)
        XCTAssertTrue(result.constructedCallArgumentGPRs.isEmpty)
        XCTAssertFalse(result.entrySPIsExact)
        XCTAssertTrue(result.hasExplicitStackWriteback)
        XCTAssertNil(result.latestABIResultValue)
        XCTAssertNotEqual(result.writeRegister("q9"), root.witness.value)
        var collision = entry(); collision.registerVersions["v9"] = 900
        XCTAssertEqual(incoming(fixture(), producer: producer, witness: root.witness, initial: collision).readRegister("v9"),
                       .unknown("unavailable_upper_v9"))
        var conflict = entry(); conflict.valueTypeHints[root.witness.value] = "conflicting_type"
        XCTAssertEqual(incoming(fixture(), producer: producer, witness: root.witness, initial: conflict).readRegister("v9"),
                       .unknown("unavailable_upper_v9"))
    }
}
