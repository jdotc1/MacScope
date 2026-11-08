import Foundation
import XCTest
@testable import MacScope

/// Newly authored source-only fixtures. No test execution is claimed.
final class MacIRIndependentPendingGPRTests: XCTestCase {
    private func source(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> MacIRSourceSpan {
        .init(address: address, byteText: "", mnemonic: mnemonic, operands: operands)
    }

    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        .init(address: address, bytes: "", mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil)
    }

    private func producer(_ writes: [(String, Int64)])
        -> (state: BuilderState, effects: [MacIRInstruction], values: [MacIRValue]) {
        var state = BuilderState(parameters: [])
        var effects: [MacIRInstruction] = []
        var values: [MacIRValue] = []
        for (offset, write) in writes.enumerated() {
            let value = state.writeRegister(write.0)
            values.append(value)
            let width = MacIRBuilder.integerRegisterView(write.0)?.width ?? 64
            let bits = UInt64(bitPattern: write.1)
            let normalized = Int64(bitPattern: width == 32 ? bits & 0xffff_ffff : bits)
            effects.append(.init(source: source(UInt64(0x7000 + offset * 4), "mov", "\(write.0), #\(write.1)"),
                                 operation: .assign(destination: value, source: .immediate(normalized))))
        }
        effects.append(.init(source: source(UInt64(0x7000 + writes.count * 4), "b", "0x7800"),
                             operation: .intrinsic(destination: nil, name: "branch", arguments: [.immediate(0x7800)])))
        return (state, effects, values)
    }

    /// Source order 0, 1, 2; control flow 0 -> 2 -> 1. No backedge and no
    /// already-emitted direct predecessor can hide the pending-only branch.
    private func plan() -> ScalarCFGStatePlan {
        let blocks = [
            BasicBlock(index: 0, startIndex: 0, endIndex: 3, successors: [2], predecessors: [], isLoopHeader: false),
            BasicBlock(index: 1, startIndex: 3, endIndex: 4, successors: [], predecessors: [2], isLoopHeader: false),
            BasicBlock(index: 2, startIndex: 4, endIndex: 5, successors: [1], predecessors: [0], isLoopHeader: false)
        ]
        let cfg = CFG(blocks: blocks, entryIndex: 0, domTree: [:], postDomTree: [:],
            loopHeaders: [], backEdges: [], irreducibleBlocks: [],
            blockByStartIndex: [0: 0, 3: 1, 4: 2], hasUnresolvedTargets: false)
        var result = ScalarCFGStatePlan(cfg: cfg, blockAtStart: [:], blockAtEnd: [:],
                                       conditionalForks: [:], referencedXRegisters: [9, 10])
        result.pendingGPRTransparentBlocks = [2]
        result.pendingGPRTraversalBudget = 15
        return result
    }

    private func incoming(_ plan: ScalarCFGStatePlan, producer: BuilderState,
                          witnesses: [Int: ScalarCFGStatePlan.PendingGPRDefinition]) -> BuilderState {
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        return plan.incoming(for: 1, entry: BuilderState(parameters: []), outgoing: [0: producer],
                             phis: &phis, pendingGPRDefinitions: [0: witnesses])
    }

    func testTwoIndependentWitnessesImprovePendingConsumerAndKeepLegacySnapshot() throws {
        let fixture = producer([("w9", 7), ("x10", 13)])
        let legacy = ScalarCFGStatePlan.snapshotPendingGPRDefinitions(instructions: fixture.effects, state: fixture.state)
        let independent = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
            instructions: fixture.effects, state: fixture.state)
        XCTAssertEqual(Set(legacy.keys), Set([10]), "the accepted single-witness helper is unchanged")
        XCTAssertEqual(Set(independent.keys), Set([9, 10]))
        XCTAssertEqual(independent[9]?.source.address, 0x7000)
        XCTAssertEqual(independent[10]?.source.address, 0x7004)
        XCTAssertNotEqual(independent[9]?.source, independent[10]?.source)
        XCTAssertEqual(incoming(plan(), producer: fixture.state, witnesses: legacy).readRegister("x9"),
                       .unknown("unavailable_x9"))
        let recovered = incoming(plan(), producer: fixture.state, witnesses: independent)
        XCTAssertEqual(recovered.readRegister("w9"), fixture.values[0])
        XCTAssertEqual(recovered.readRegister("x9"),
                       .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: fixture.values[0])))
        XCTAssertEqual(recovered.readRegister("x10"), fixture.values[1])
        XCTAssertEqual(recovered.readRegister("w10"), .unary(op: "(uint32_t)", value: fixture.values[1]))
        XCTAssertEqual(recovered.readRegister("x8"), .unknown("unavailable_x8"))

        let rows = [
            row(0x6000, "mov", "x12, #2"), row(0x6004, "subs", "x12, x12, #1"),
            row(0x6008, "b.ne", "0x6004"), row(0x600c, "eor", "v2.16b, v2.16b, v3.16b"),
            row(0x6010, "mov", "w9, #7"), row(0x6014, "mov", "x10, #13"),
            row(0x6018, "b", "0x6028"), row(0x601c, "mov", "x11, x9"),
            row(0x6020, "mov", "x13, x10"), row(0x6024, "b", "0x602c"),
            row(0x6028, "b", "0x601c"), row(0x602c, "ret")
        ]
        let function = try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "two_independent_pending_gprs", startAddress: 0x6000,
                rows: rows, initialState: BuilderState(parameters: []), hasExternalFacts: false, isVariadic: false))
        let first = try XCTUnwrap(function.instructions.first { $0.source.address == 0x6010 })
        let second = try XCTUnwrap(function.instructions.first { $0.source.address == 0x6014 })
        let firstConsumer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x601c })
        let secondConsumer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x6020 })
        guard case let .assign(word, _) = first.operation,
              case let .assign(wide, _) = second.operation,
              case let .assign(_, firstInput) = firstConsumer.operation,
              case let .assign(_, secondInput) = secondConsumer.operation else {
            return XCTFail("expected two committed producers and two emitted consumer assignments")
        }
        XCTAssertEqual(firstInput, .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: word)))
        XCTAssertEqual(secondInput, wide)
        let rendered = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024)).print(function: function)
        let firstOutput = rendered.lines(sourcedAt: 0x601c).map(\.text).joined(separator: "\n")
        let secondOutput = rendered.lines(sourcedAt: 0x6020).map(\.text).joined(separator: "\n")
        XCTAssertFalse(firstOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        XCTAssertFalse(secondOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        XCTAssertFalse(firstOutput.contains("unavailable_x9"))
        XCTAssertFalse(firstOutput.contains("unavailable_w9"))
        XCTAssertFalse(secondOutput.contains("unavailable_x10"))
        XCTAssertFalse(secondOutput.contains("unavailable_w10"))
    }

    func testIndependentFactsDoNotBorrowMissingOrConflictingWitnesses() {
        let fixture = producer([("w9", 7), ("x10", 13)])
        var missing = fixture.effects
        missing.removeFirst()
        let partial = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: missing, state: fixture.state)
        XCTAssertEqual(Set(partial.keys), Set([10]))
        XCTAssertEqual(incoming(plan(), producer: fixture.state, witnesses: partial).readRegister("w9"),
                       .unknown("unavailable_w9"), "a live dictionary entry without its own producer is insufficient")

        var wrongWidth = fixture.state
        wrongWidth.currentIntegerDefinitionByIndex[9]?.width = 64
        let widths = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: fixture.effects, state: wrongWidth)
        XCTAssertEqual(Set(widths.keys), Set([10]))
        let widthResult = incoming(plan(), producer: wrongWidth, witnesses: widths)
        XCTAssertEqual(widthResult.readRegister("w9"), .unknown("unavailable_w9"))
        XCTAssertEqual(widthResult.readRegister("x10"), fixture.values[1])
        var invalidLaterCell = fixture.state
        invalidLaterCell.currentIntegerDefinitionByIndex[10]?.width = 32
        let earlierOnly = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
            instructions: fixture.effects, state: invalidLaterCell)
        XCTAssertEqual(Set(earlierOnly.keys), Set([9]),
                       "the later MOV's independently decoded write set is not its invalid value witness")
        let earlierResult = incoming(plan(), producer: invalidLaterCell, witnesses: earlierOnly)
        XCTAssertEqual(earlierResult.readRegister("w9"), fixture.values[0])
        XCTAssertEqual(earlierResult.readRegister("x10"), .unknown("unavailable_x10"))

        // A second emission of one value has a different source. Its sibling
        // cannot supply source identity for this ambiguous producer.
        var conflict = fixture.effects
        var duplicate = fixture.effects[0]
        duplicate.source.address = 0x6ffc
        conflict.insert(duplicate, at: 0)
        let conflicted = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: conflict, state: fixture.state)
        XCTAssertEqual(Set(conflicted.keys), Set([10]))
        XCTAssertEqual(incoming(plan(), producer: fixture.state, witnesses: conflicted).readRegister("w9"),
                       .unknown("unavailable_w9"))

        var sharedSource = fixture.effects
        sharedSource[1].source.address = sharedSource[0].source.address
        XCTAssertTrue(ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
            instructions: sharedSource, state: fixture.state).isEmpty,
            "one architectural source cannot witness two distinct MOV destinations")
    }

    func testPerPhysicalRegisterKillsAndPerCellPoisoningRemainIndependent() {
        let fixture = producer([("x9", 7), ("x10", 13), ("w9", 3)])
        let witnesses = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: fixture.effects, state: fixture.state)
        XCTAssertEqual(Set(witnesses.keys), Set([9, 10]))
        XCTAssertEqual(witnesses[9]?.definition.value, fixture.values[2])
        XCTAssertEqual(witnesses[9]?.definition.width, 32)
        XCTAssertEqual(witnesses[9]?.source.address, 0x7008)
        let recovered = incoming(plan(), producer: fixture.state, witnesses: witnesses)
        XCTAssertNotEqual(recovered.readRegister("x9"), fixture.values[0])
        XCTAssertEqual(recovered.readRegister("x9"),
                       .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: fixture.values[2])))
        XCTAssertEqual(recovered.readRegister("x10"), fixture.values[1])

        // Even a poisoned final W write kills the earlier X definition.
        var stale = fixture.state
        stale.currentIntegerDefinitionByIndex[9] = .init(value: fixture.values[0], width: 64)
        let staleWitnesses = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: fixture.effects, state: stale)
        XCTAssertNil(staleWitnesses[9])
        XCTAssertEqual(staleWitnesses[10]?.definition.value, fixture.values[1])

        var poisoned = fixture.state
        poisoned.unavailableRegisterValues.insert("w9")
        let poisonedResult = incoming(plan(), producer: poisoned, witnesses: witnesses)
        XCTAssertEqual(poisonedResult.readRegister("x9"), .unknown("unavailable_x9"))
        XCTAssertEqual(poisonedResult.readRegister("x10"), fixture.values[1])
        poisoned = fixture.state
        poisoned.callUnavailableRegisterValues.insert("x10")
        let callPoisoned = incoming(plan(), producer: poisoned, witnesses: witnesses)
        XCTAssertEqual(callPoisoned.readRegister("w9"), fixture.values[2])
        XCTAssertEqual(callPoisoned.readRegister("x10"), .unknown("unavailable_x10"))
    }

    func testOnlyExactImmediateWritesExtendAnIndependentSuffix() {
        let fixture = producer([("w9", 7), ("x10", 13)])
        let opaque = MacIRInstruction(source: source(0x7002, "mystery", ""),
                                      operation: .unknown(destination: nil, mnemonic: "mystery", operands: ""))
        let implicit = MacIRInstruction(source: source(0x7002, "paciasp"),
                                        operation: .intrinsic(destination: nil, name: "paciasp", arguments: []))
        let arbitrary = MacIRInstruction(source: source(0x7002, "mystery", "x20, #1"),
            operation: .assign(destination: .register(name: "x20", version: 1), source: .immediate(1)))
        let copy = MacIRInstruction(source: source(0x7002, "mov", "x20, x10"),
            operation: .assign(destination: .register(name: "x20", version: 1), source: fixture.values[1]))
        let partial = MacIRInstruction(source: source(0x7002, "movk", "x20, #1"),
            operation: .assign(destination: .register(name: "x20", version: 1), source: .immediate(1)))
        for barrier in [opaque, implicit, arbitrary, copy, partial] {
            var effects = fixture.effects
            effects.insert(barrier, at: 1)
            let witnesses = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: effects, state: fixture.state)
            XCTAssertNil(witnesses[9], barrier.source.mnemonic)
            XCTAssertEqual(witnesses[10]?.definition.value, fixture.values[1],
                           "a later fresh producer is independent of the earlier barrier")
            effects = fixture.effects
            effects.insert(barrier, at: effects.count - 1)
            XCTAssertTrue(ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
                instructions: effects, state: fixture.state).isEmpty, barrier.source.mnemonic)
        }
        for invalid in ["x10, #13,", "x10, #13, lsl #0", "x10, #14", "w10, #13", "sp, #13", "x010, #13", "x10, #--13", "x10, #-+13"] {
            var effects = fixture.effects
            effects[1].source.operands = invalid
            XCTAssertTrue(ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
                instructions: effects, state: fixture.state).isEmpty, invalid)
        }
        var annotated = fixture.effects
        annotated[1].memoryAccess = .init(byteWidth: 8)
        XCTAssertTrue(ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
            instructions: annotated, state: fixture.state).isEmpty, "additional effect metadata is not an exact plain MOV")
    }

    func testReturningCallIsABarrierEvenForAnOtherwisePreservedRegister() throws {
        let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
        var state = BuilderState(parameters: [])
        var effects: [MacIRInstruction] = []
        for span in [source(0x7100, "mov", "x19, #7"), source(0x7104, "bl", "_callee"),
                     source(0x7108, "mov", "x20, #13"), source(0x710c, "b", "0x7800")] {
            effects.append(.init(source: span, operation: builder.operationForVectorRegion(for: span, state: &state)))
        }
        guard case let .assign(earlier, _) = effects[0].operation,
              case .call = effects[1].operation,
              case let .assign(later, _) = effects[2].operation else {
            return XCTFail("expected a real returning call between immediate assignments")
        }
        XCTAssertEqual(state.readRegister("x19"), earlier, "ABI preservation is not suffix transparency")
        let witnesses = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: effects, state: state)
        XCTAssertNil(witnesses[19])
        XCTAssertEqual(witnesses[20]?.definition.value, later)
        let recovered = incoming(plan(), producer: state, witnesses: witnesses)
        XCTAssertEqual(recovered.readRegister("x19"), .unknown("unavailable_x19"))
        XCTAssertEqual(recovered.readRegister("x20"), later)
    }

    func testIndependentWitnessSetAndScanStayExplicitlyBounded() {
        let fixture = producer([("x5", 5), ("w6", 6), ("x7", 7), ("w8", 8), ("x9", 9)])
        let witnesses = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: fixture.effects, state: fixture.state)
        XCTAssertEqual(ScalarCFGStatePlan.independentPendingGPRDefinitionLimit, 4)
        XCTAssertEqual(Set(witnesses.keys), Set([6, 7, 8, 9]), "newest four independently committed physical cells")
        var conflictingBeyondCap = fixture.effects
        var duplicate = fixture.effects[4]
        duplicate.source.address = 0x6ffc
        conflictingBeyondCap.insert(duplicate, at: 0)
        let boundedConflict = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
            instructions: conflictingBeyondCap, state: fixture.state)
        XCTAssertEqual(Set(boundedConflict.keys), Set([6, 7, 8]),
                       "the identity scan must not stop when four candidates have been selected")
        var oversized = fixture.effects
        for offset in 0..<1024 {
            oversized.insert(.init(source: source(UInt64(0x8000 + offset * 4), "nop"),
                                   operation: .intrinsic(destination: nil, name: "nop", arguments: [])), at: 0)
        }
        XCTAssertTrue(ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(
            instructions: oversized, state: fixture.state).isEmpty)
        var exhausted = plan()
        exhausted.pendingGPRTraversalBudget = 1
        let unavailable = incoming(exhausted, producer: fixture.state, witnesses: witnesses)
        XCTAssertEqual(unavailable.readRegister("x9"), .unknown("unavailable_x9"))
        XCTAssertEqual(unavailable.readRegister("w8"), .unknown("unavailable_w8"))
    }

    func testSeveralRestoredDataCellsDoNotRestoreAncillaryAuthority() {
        let fixture = producer([("w0", 7), ("x1", 13)])
        let witnesses = ScalarCFGStatePlan.snapshotIndependentPendingGPRDefinitions(instructions: fixture.effects, state: fixture.state)
        var state = fixture.state
        state.stackSlotValues[8] = .init(value: .immediate(7), byteWidth: 8, carrierKind: .integer)
        state.outgoingCallStackStores[16] = .init(value: .immediate(13), byteWidth: 8, carrierKind: .integer)
        state.registerVersions["x0"] = 350
        state.registerVersionFloor = 300
        state.nextRegisterTemporaryIndex = 400
        var recovered = incoming(plan(), producer: state, witnesses: witnesses)
        XCTAssertEqual(recovered.readRegister("w0"), fixture.values[0])
        XCTAssertEqual(recovered.readRegister("x1"), fixture.values[1])
        XCTAssertTrue(recovered.constructedCallArgumentGPRs.isEmpty)
        XCTAssertTrue(recovered.stackSlotValues.isEmpty)
        XCTAssertTrue(recovered.outgoingCallStackStores.isEmpty)
        XCTAssertFalse(recovered.entrySPIsExact)
        XCTAssertNil(recovered.latestABIResultValue)
        XCTAssertTrue(recovered.hasUnmodeledABIResultWrite)
        XCTAssertEqual(recovered.readRegister("v0"), .unknown("unavailable_upper_v0"))
        XCTAssertEqual(recovered.preferredReturnValue(), .unknown(MacIRIndirectTargetResolution.unresolvedReturnContractMarker))
        XCTAssertGreaterThanOrEqual(recovered.nextRegisterTemporaryIndex, 400)
        XCTAssertEqual(recovered.writeRegister("x0"), .register(name: "x0", version: 351))
    }
}
