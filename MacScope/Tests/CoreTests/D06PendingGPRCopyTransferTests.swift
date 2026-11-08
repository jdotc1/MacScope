import Foundation
import XCTest
@testable import MacScope

final class D06PendingGPRCopyTransferTests: XCTestCase {
    private func gprRow(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        .init(address: address, bytes: "", mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil)
    }

    /// Models one committed assignment, with source identity kept separately
    /// from its register value. No definition is inferred from rendered text.
    private func pendingGPRProducer(_ register: String = "w9", floor: Int = 0, address: UInt64 = 0x1000)
        -> (BuilderState, [Int: ScalarCFGStatePlan.PendingGPRDefinition], MacIRValue) {
        var state = BuilderState(parameters: [])
        state.registerVersionFloor = floor
        state.nextRegisterTemporaryIndex = floor + 20
        let value = state.writeRegister(register)
        let source = MacIRSourceSpan(address: address, byteText: "", mnemonic: "mov", operands: "\(register), #7")
        let effect = MacIRInstruction(source: source, operation: .assign(destination: value, source: .immediate(7)))
        let branch = MacIRInstruction(source: MacIRSourceSpan(address: address + 4, byteText: "",
            mnemonic: "b", operands: "0x1010"),
            operation: .intrinsic(destination: nil, name: "branch", arguments: [.immediate(0x1010)]))
        return (state, ScalarCFGStatePlan.snapshotPendingGPRDefinitions(instructions: [effect, branch], state: state), value)
    }

    private func pendingGPRTopology(_ predecessors: [[Int]], transparent: Set<Int>,
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
        plan.pendingGPRTransparentBlocks = transparent
        plan.pendingGPRTraversalBudget = blocks.count * 3
        return plan
    }

    /// Source-order target precedes the exact-copy chain that reaches it.
    private func pendingGPRCopyFixture(_ copies: [(String, String)], rootRegister: String = "w9")
        -> (ScalarCFGStatePlan, [InstructionRow]) {
        var rows = [gprRow(0x1000, "mov", "\(rootRegister), #7"),
                    gprRow(0x1004, "b", "0x1010"),
                    gprRow(0x1008, "mov", "x13, x11"), gprRow(0x100c, "ret")]
        for copy in copies {
            rows.append(gprRow(0x1000 + UInt64(rows.count * 4), copy.0, copy.1))
        }
        rows.append(gprRow(0x1000 + UInt64(rows.count * 4), "b", "0x1008"))
        let blocks = [
            BasicBlock(index: 0, startIndex: 0, endIndex: 2, successors: [2], predecessors: [], isLoopHeader: false),
            BasicBlock(index: 1, startIndex: 2, endIndex: 4, successors: [], predecessors: [2], isLoopHeader: false),
            BasicBlock(index: 2, startIndex: 4, endIndex: rows.count, successors: [1], predecessors: [0], isLoopHeader: false)
        ]
        let cfg = CFG(blocks: blocks, entryIndex: 0, domTree: [:], postDomTree: [:],
            loopHeaders: [], backEdges: [], irreducibleBlocks: [],
            blockByStartIndex: [0: 0, 2: 1, 4: 2], hasUnresolvedTargets: false)
        var plan = ScalarCFGStatePlan(cfg: cfg, blockAtStart: [:], blockAtEnd: [:],
            conditionalForks: [:], referencedXRegisters: [9, 10, 11, 13])
        plan.pendingGPRTransparentBlocks = MacIRBuilder.pendingGPRTransparentBlocks(in: cfg, rows: rows)
        plan.pendingGPRTraversalBudget = rows.count * 3
        plan.pendingGPRCopyTransferBlocks = MacIRBuilder.pendingGPRCopyTransferBlocks(in: cfg, rows: rows)
        plan.pendingGPRCopyTraversalBudget = rows.count * 3
        return (plan, rows)
    }

    func testPendingGPRCopyChainPreservesWidthProducerAndAllocator() throws {
        for prefix in ["w", "x"] {
            let (plan, _) = pendingGPRCopyFixture([
                ("mov", "\(prefix)10, \(prefix)9"), ("nop", ""),
                ("mov", "\(prefix)11, \(prefix)10"), ("mov", "\(prefix)11, \(prefix)11")
            ], rootRegister: "\(prefix)9")
            let (producer, witnesses, value) = pendingGPRProducer("\(prefix)9", floor: 200)
            var phis: [ScalarCFGStatePlan.PhiDraft] = []
            var result = plan.incoming(for: 1, entry: BuilderState(parameters: []),
                outgoing: [0: producer], phis: &phis, pendingGPRDefinitions: [0: witnesses])
            let definition = try XCTUnwrap(result.currentIntegerDefinitionByIndex[11])
            XCTAssertEqual(definition.value, value, "copy aliases the emitted producer, not a future destination")
            XCTAssertEqual(definition.width, prefix == "w" ? 32 : 64)
            XCTAssertFalse(definition.isJoinedDefinition)
            XCTAssertFalse(definition.isSyntheticReturnPhi)
            XCTAssertEqual(result.readRegister("x11"), producer.readRegister("x9"))
            XCTAssertEqual(result.readRegister("w11"), producer.readRegister("w9"))
            XCTAssertEqual(result.registerNameBindingsByValue[value], producer.registerNameBindingsByValue[value])
            XCTAssertGreaterThanOrEqual(result.registerVersionFloor, producer.registerVersionFloor)
            XCTAssertGreaterThanOrEqual(result.nextRegisterTemporaryIndex, producer.nextRegisterTemporaryIndex)
            XCTAssertEqual(result.registerVersions["\(prefix)11"], producer.registerVersions["\(prefix)11"])
            XCTAssertNotEqual(result.writeRegister("\(prefix)11"), value)
            XCTAssertTrue(phis.isEmpty)
            var disabled = plan
            disabled.pendingGPRCopyTraversalBudget = 0
            XCTAssertEqual(disabled.incoming(for: 1, entry: BuilderState(parameters: []),
                outgoing: [0: producer], phis: &phis, pendingGPRDefinitions: [0: witnesses])
                .readRegister("w11"), .unknown("unavailable_w11"))
        }
    }

    func testPendingGPRCopyChainCrossesMultiplePendingBlocks() {
        let (producer, witnesses, value) = pendingGPRProducer()
        var plan = pendingGPRTopology([[], [2], [3], [0]], transparent: [])
        plan.pendingGPRCopyTransferBlocks = [
            2: [.init(destinationIndex: 11, sourceIndex: 10, width: 32)],
            3: [.init(destinationIndex: 10, sourceIndex: 9, width: 32)]
        ]
        plan.pendingGPRCopyTraversalBudget = 12
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        let result = plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses])
        XCTAssertEqual(result.readRegister("w11"), value)
        XCTAssertEqual(result.readRegister("x11"), producer.readRegister("x9"))
        XCTAssertEqual(result.readRegister("w10"), value)
        XCTAssertTrue(phis.isEmpty)
    }

    func testPendingGPRCopyChainUsesSnapshotBeforeOverlappingWrites() {
        let (producer, witnesses, value) = pendingGPRProducer()
        let (plan, _) = pendingGPRCopyFixture([
            ("mov", "w10, w9"), ("mov", "w9, w8"), ("mov", "w11, w10")
        ])
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        let result = plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses])
        XCTAssertEqual(result.readRegister("w11"), value)
        XCTAssertEqual(result.readRegister("w10"), value)
        XCTAssertEqual(result.readRegister("w9"), .unknown("unavailable_w9"), "unknown source kills only its destination")
        let (killed, _) = pendingGPRCopyFixture([("mov", "w11, w9"), ("mov", "w11, w8")])
        XCTAssertEqual(killed.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w11"), .unknown("unavailable_w11"))
        let (wrongView, _) = pendingGPRCopyFixture([("mov", "x11, x9")])
        XCTAssertEqual(wrongView.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("x11"), .unknown("unavailable_x11"),
            "a W root is not silently relabelled as an X definition")
    }

    func testPendingGPRCopyDecoderRejectsAliasesPartialCopiesAndOpaqueEffects() {
        let (producer, witnesses, _) = pendingGPRProducer()
        let refusals: [(String, String)] = [
            ("mov", "w11, w9,"), ("mov", "w11,, w9"), ("mov", "w11, x9"),
            ("mov", "w11, #7"), ("mov", "x11, sp"), ("mov", "w11, wzr"),
            ("mov", "x11, fp"), ("mov", "x11, lr"), ("mov", "w011, w9"),
            ("mov", "w11, w31"), ("mov", "w11, w9, lsl #0"),
            ("movz", "w11, w9"), ("orr", "w11, wzr, w9"),
            ("uxtw", "x11, w9"), ("fmov", "x11, d9"), ("movk", "w11, #7"),
            ("bl", "_callee"), ("paciasp", ""), ("mystery", "w8"),
            ("ldr", "q0, [x9], #16"), ("cbz", "w8, 0x1008"), ("b", "0x1008,")
        ]
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        for refused in refusals {
            let (plan, _) = pendingGPRCopyFixture([("mov", "w11, w9"), refused])
            XCTAssertNil(plan.pendingGPRCopyTransferBlocks[2], "\(refused)")
            XCTAssertEqual(plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
                phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w11"),
                .unknown("unavailable_w11"), "\(refused)")
        }
    }

    func testPendingGPRCopyChainRequiresValidatedWitnessAndAllPaths() {
        let (producer, witnesses, value) = pendingGPRProducer()
        let (plan, _) = pendingGPRCopyFixture([("mov", "w11, w9")])
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        var poisoned = producer
        poisoned.callUnavailableRegisterValues.insert("x9")
        var badAllocator = producer
        badAllocator.registerVersions["w9"] = 0
        var joined = producer
        joined.currentIntegerDefinitionByIndex[9]?.isJoinedDefinition = true
        var synthetic = producer
        synthetic.currentIntegerDefinitionByIndex[9]?.isSyntheticReturnPhi = true
        var badWidth = producer
        badWidth.currentIntegerDefinitionByIndex[9]?.width = 64
        for invalid in [poisoned, badAllocator, joined, synthetic, badWidth] {
            XCTAssertEqual(plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: invalid],
                phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w11"), .unknown("unavailable_w11"))
        }
        XCTAssertEqual(plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis).readRegister("w11"), .unknown("unavailable_w11"))
        var exhausted = plan
        exhausted.pendingGPRCopyTraversalBudget = 1
        XCTAssertEqual(exhausted.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w11"), .unknown("unavailable_w11"))
        XCTAssertEqual(plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer, 1: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w11"), .unknown("unavailable_w11"))
        let transfer = ScalarCFGStatePlan.PendingGPRCopyTransfer(destinationIndex: 11, sourceIndex: 9, width: 32)
        for malformed in [pendingGPRTopology([[], [2], []], transparent: []),
                          pendingGPRTopology([[], [2], [2]], transparent: []),
                          pendingGPRTopology([[], [2], [1]], transparent: []),
                          pendingGPRTopology([[], [2], [99]], transparent: []),
                          pendingGPRTopology([[], [2], [0]], transparent: [], unresolved: true),
                          pendingGPRTopology([[], [2], [0]], transparent: [], backEdges: [CFGEdge(2, 1)])] {
            var candidate = malformed
            candidate.pendingGPRCopyTransferBlocks = [2: [transfer]]
            candidate.pendingGPRCopyTraversalBudget = 9
            XCTAssertEqual(candidate.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
                phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w11"), .unknown("unavailable_w11"))
        }
        let (other, otherWitnesses, equalValue) = pendingGPRProducer(address: 0x2000)
        XCTAssertEqual(value, equalValue)
        var independent = pendingGPRTopology([[], [], [3, 4], [0], [1]], transparent: [])
        independent.pendingGPRCopyTransferBlocks = [3: [transfer], 4: [transfer]]
        independent.pendingGPRCopyTraversalBudget = 15
        XCTAssertEqual(independent.incoming(for: 2, entry: BuilderState(parameters: []), outgoing: [0: producer, 1: other],
            phis: &phis, pendingGPRDefinitions: [0: witnesses, 1: otherWitnesses]).readRegister("w11"),
            .unknown("unavailable_w11"))
    }

    func testPendingGPRCopyChainDoesNotRestoreAncillaryAuthority() {
        let (plan, _) = pendingGPRCopyFixture([("mov", "w0, w9"), ("mov", "w1, w0"), ("mov", "w11, w1")])
        let (root, witnesses, value) = pendingGPRProducer(floor: 200)
        var producer = root
        producer.stackSlotValues[8] = StackSlotValueFact(value: .immediate(7), byteWidth: 8, carrierKind: .integer)
        producer.outgoingCallStackStores[16] = StackSlotValueFact(value: .immediate(9), byteWidth: 8, carrierKind: .integer)
        producer.constructedCallArgumentGPRs = [0, 1, 7]
        producer.latestABIResultValue = value
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        var result = plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses])
        XCTAssertEqual(result.readRegister("w0"), value)
        XCTAssertEqual(result.readRegister("w1"), value)
        XCTAssertEqual(result.readRegister("w11"), value)
        XCTAssertTrue(result.constructedCallArgumentGPRs.isEmpty)
        XCTAssertTrue(result.stackSlotValues.isEmpty)
        XCTAssertTrue(result.outgoingCallStackStores.isEmpty)
        XCTAssertFalse(result.entrySPIsExact)
        XCTAssertTrue(result.hasExplicitStackWriteback)
        XCTAssertEqual(result.readRegister("sp"), .unknown("unavailable_sp"))
        XCTAssertEqual(result.readRegister("v0"), .unknown("unavailable_upper_v0"))
        XCTAssertNil(result.latestABIResultValue)
        XCTAssertTrue(result.hasUnmodeledABIResultWrite)
        XCTAssertEqual(result.preferredReturnValue(), .unknown(MacIRIndirectTargetResolution.unresolvedReturnContractMarker))
    }

    func testPendingGPRCopyTransferDoesNotOverwriteExistingRecoveredCell() {
        let (plan, _) = pendingGPRCopyFixture([("mov", "w11, w9")])
        let (producer, witnesses, value) = pendingGPRProducer()
        var state = BuilderState(parameters: [])
        for index in 0...30 { state.recordUnmodeledDefiniteWrite(for: "x\(index)") }
        let existing = state.writeRegister("w11")
        XCTAssertNotEqual(existing, value)
        plan.recoverPendingGPRCopyDefinitions(entering: 1, outgoing: [0: producer],
            witnesses: [0: witnesses], into: &state)
        XCTAssertEqual(state.readRegister("w11"), existing)
        XCTAssertEqual(state.readRegister("w9"), value, "unclaimed cells may still recover")
        // A prior path can own a readable cell without a dictionary definition.
        var readable = BuilderState(parameters: [])
        readable.registerVersions["w11"] = 55
        plan.recoverPendingGPRCopyDefinitions(entering: 1, outgoing: [0: producer],
            witnesses: [0: witnesses], into: &readable)
        XCTAssertEqual(readable.readRegister("w11"), .register(name: "w11", version: 55))
    }

    func testPendingGPRCopyTransferPreservesControlOnlyAndCompletedPaths() {
        let (producer, witnesses, value) = pendingGPRProducer()
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        let (control, _) = pendingGPRCopyFixture([])
        XCTAssertEqual(control.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w9"), value)
        var copyOnly = control
        copyOnly.pendingGPRTraversalBudget = 0
        XCTAssertEqual(copyOnly.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
            phis: &phis, pendingGPRDefinitions: [0: witnesses]).readRegister("w9"), .unknown("unavailable_w9"),
            "the copy capability alone does not replay B/NOP-only recovery")
        var completed = control
        completed.pendingGPRTraversalBudget = 0
        completed.pendingGPRCopyTraversalBudget = 0
        XCTAssertEqual(completed.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer, 2: producer],
            phis: &phis).readRegister("w9"), value, "normal completed-predecessor merge is unchanged")
    }

    func testPendingGPRCopyChainChangesActualRegionConsumerAndPseudocode() throws {
        let rows = [
            gprRow(0x4000, "mov", "x12, #2"), gprRow(0x4004, "subs", "x12, x12, #1"),
            gprRow(0x4008, "b.ne", "0x4004"), gprRow(0x400c, "eor", "v2.16b, v2.16b, v3.16b"),
            gprRow(0x4010, "mov", "w9, #7"), gprRow(0x4014, "b", "0x4020"),
            gprRow(0x4018, "mov", "x13, x11"), gprRow(0x401c, "b", "0x402c"),
            gprRow(0x4020, "mov", "w10, w9"), gprRow(0x4024, "mov", "w11, w10"),
            gprRow(0x4028, "b", "0x4018"), gprRow(0x402c, "ret")
        ]
        let function = try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "pending_copy_chain", startAddress: 0x4000,
                rows: rows, initialState: BuilderState(parameters: []), hasExternalFacts: false, isVariadic: false))
        let producer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x4010 })
        let consumer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x4018 })
        guard case let .assign(value, _) = producer.operation,
              case let .assign(_, input) = consumer.operation else { return XCTFail("expected assignments") }
        XCTAssertEqual(input, .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: value)))
        let text = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1_024)).print(function: function)
            .lines(sourcedAt: 0x4018).map(\.text).joined(separator: "\n")
        XCTAssertFalse(text.isEmpty, "the actual consumer has sourced pseudocode")
        XCTAssertFalse(text.contains("unavailable_x11"), text)
        XCTAssertTrue(function.instructions.contains { $0.source.address == 0x4024 }, "copy rows remain emitted normally")
    }

}
