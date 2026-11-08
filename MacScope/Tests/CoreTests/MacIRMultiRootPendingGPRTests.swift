import Foundation
import XCTest
@testable import MacScope

/// Source-authored only. These focused tests have not been compiled or run.
final class MacIRMultiRootPendingGPRTests: XCTestCase {
    private func row441(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        .init(address: address, bytes: "", mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil)
    }

    private func source441(_ row: InstructionRow) -> MacIRSourceSpan {
        .init(address: row.address, byteText: row.bytes, mnemonic: row.mnemonic.lowercased(),
              operands: row.operands, comment: row.comment)
    }

    private struct Fixture441 {
        var plan: ScalarCFGStatePlan
        var rows: [InstructionRow]
        var outgoing: [Int: BuilderState]
        var witnesses: [Int: [Int: ScalarCFGStatePlan.PendingGPRDefinition]]
        var value: MacIRValue
    }

    /// P0 -> fork1 -> emitted roots2/3 -> pending5/6 -> consumer4.
    /// The roots inherit one source, rather than defining equal-looking values.
    private func fixture441(_ register: String = "w9") -> Fixture441 {
        let rows = [
            row441(0x6000, "mov", "\(register), #7"), row441(0x6004, "b", "0x6008"),
            row441(0x6008, "cbz", "x2, 0x6010"), row441(0x600c, "b", "0x601c"),
            row441(0x6010, "b", "0x6020"), row441(0x6014, "mov", "x11, x9"),
            row441(0x6018, "b", "0x6024"), row441(0x601c, "b", "0x6014"),
            row441(0x6020, "b", "0x6014"), row441(0x6024, "ret")
        ]
        let spans = [0..<2, 2..<3, 3..<4, 4..<5, 5..<7, 7..<8, 8..<9, 9..<10]
        let predecessors = [[], [0], [1], [1], [5, 6], [2], [3], [4]]
        let blocks = spans.enumerated().map { index, span in
            BasicBlock(index: index, startIndex: span.lowerBound, endIndex: span.upperBound,
                successors: predecessors.indices.filter { predecessors[$0].contains(index) },
                predecessors: predecessors[index], isLoopHeader: false)
        }
        let cfg = CFG(blocks: blocks, entryIndex: 0, domTree: [:], postDomTree: [:],
            loopHeaders: [], backEdges: [], irreducibleBlocks: [],
            blockByStartIndex: Dictionary(uniqueKeysWithValues: blocks.map { ($0.startIndex, $0.index) }),
            hasUnresolvedTargets: false)
        var plan = ScalarCFGStatePlan(cfg: cfg, blockAtStart: [:], blockAtEnd: [:],
            conditionalForks: [:], referencedXRegisters: [9, 11])
        plan.pendingGPRTransparentBlocks = MacIRBuilder.pendingGPRTransparentBlocks(in: cfg, rows: rows)
        plan.pendingGPRTraversalBudget = rows.count * 3
        var state = BuilderState(parameters: [])
        let value = state.writeRegister(register)
        let producer = MacIRInstruction(source: source441(rows[0]),
            operation: .assign(destination: value, source: .immediate(7)))
        let branch = MacIRInstruction(source: source441(rows[1]),
            operation: .intrinsic(destination: nil, name: "branch", arguments: [.immediate(0x6008)]))
        var outgoing = [0: state]
        var witnesses = [0: ScalarCFGStatePlan.snapshotPendingGPRDefinitions(
            instructions: [producer, branch], state: state)]
        let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        for index in 1...3 {
            state = plan.incoming(for: index, entry: BuilderState(parameters: []),
                outgoing: outgoing, phis: &phis, pendingGPRDefinitions: witnesses)
            let effects = cfg.blocks[index].instructionRange.map { rowIndex -> MacIRInstruction in
                let source = source441(rows[rowIndex])
                return .init(source: source, operation: builder.operationForVectorRegion(for: source, state: &state))
            }
            outgoing[index] = state
            let local = ScalarCFGStatePlan.snapshotPendingGPRDefinitions(instructions: effects, state: state)
            witnesses[index] = plan.inheritedPendingGPRDefinitions441(for: index, rows: rows,
                instructions: effects, outgoing: outgoing, witnesses: witnesses, local: local)
        }
        return Fixture441(plan: plan, rows: rows, outgoing: outgoing, witnesses: witnesses, value: value)
    }

    /// CFG is immutable in the production plan. Negative fixtures rebuild the
    /// plan around a separately edited value without weakening that contract.
    private func changingCFG441(_ plan: ScalarCFGStatePlan, _ change: (inout CFG) -> Void) -> ScalarCFGStatePlan {
        var cfg = plan.cfg
        change(&cfg)
        var result = ScalarCFGStatePlan(cfg: cfg, blockAtStart: plan.blockAtStart,
            blockAtEnd: plan.blockAtEnd, conditionalForks: plan.conditionalForks,
            referencedXRegisters: plan.referencedXRegisters)
        result.pendingGPRTransparentBlocks = plan.pendingGPRTransparentBlocks
        result.pendingGPRTraversalBudget = plan.pendingGPRTraversalBudget
        return result
    }

    private func incoming441(_ fixture: Fixture441) -> BuilderState {
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        return fixture.plan.incoming(for: 4, entry: BuilderState(parameters: []),
            outgoing: fixture.outgoing, phis: &phis, pendingGPRDefinitions: fixture.witnesses)
    }

    func test441TwoEmittedRootsRetainOneProducerAndBothPhysicalViews() throws {
        for register in ["w9", "x9"] {
            let fixture = fixture441(register)
            XCTAssertEqual(fixture.plan.cfg.blocks[4].predecessors, [5, 6])
            XCTAssertNil(fixture.outgoing[5]); XCTAssertNil(fixture.outgoing[6])
            XCTAssertTrue(fixture.plan.cfg.backEdges.isEmpty)
            XCTAssertFalse(fixture.plan.pendingGPRTransparentBlocks.contains(1),
                "the conditional fork is not certified for pending traversal")
            XCTAssertEqual(fixture.witnesses[2]?[9]?.source, fixture.witnesses[0]?[9]?.source)
            XCTAssertEqual(fixture.witnesses[3]?[9]?.source, fixture.witnesses[0]?[9]?.source)
            XCTAssertEqual(fixture.witnesses[2]?[9]?.source.address, 0x6000)
            let result = incoming441(fixture)
            let wide: MacIRValue = register == "x9" ? fixture.value
                : .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: fixture.value))
            let word: MacIRValue = register == "w9" ? fixture.value : .unary(op: "(uint32_t)", value: fixture.value)
            XCTAssertEqual(result.readRegister("x9"), wide)
            XCTAssertEqual(result.readRegister("w9"), word)
            XCTAssertEqual(result.currentIntegerDefinitionByIndex[9]?.width, register == "w9" ? 32 : 64)
            XCTAssertEqual(result.readRegister("x10"), .unknown("unavailable_x10"))
            // Root-local assignment snapshots alone cannot establish inheritance.
            var absent = fixture
            absent.witnesses[2] = [:]; absent.witnesses[3] = [:]
            XCTAssertEqual(incoming441(absent).readRegister("x9"), .unknown("unavailable_x9"))
        }
    }

    func test441GeneralRegionRecoversActualAdditionalScalarConsumerAndPseudocode() throws {
        // The initial natural loop satisfies the existing region admission;
        // the later reverse-address edges are DAG edges, not loop backedges.
        let rows = [
            row441(0x5000, "mov", "x12, #2"), row441(0x5004, "subs", "x12, x12, #1"),
            row441(0x5008, "b.ne", "0x5004"), row441(0x500c, "eor", "v2.16b, v2.16b, v3.16b"),
            row441(0x5010, "mov", "w9, #7"), row441(0x5014, "b", "0x5018"),
            row441(0x5018, "cbz", "x2, 0x5020"), row441(0x501c, "b", "0x502c"),
            row441(0x5020, "b", "0x5030"), row441(0x5024, "mov", "x11, x9"),
            row441(0x5028, "b", "0x5034"), row441(0x502c, "b", "0x5024"),
            row441(0x5030, "b", "0x5024"), row441(0x5034, "ret")
        ]
        let function = try XCTUnwrap(MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
            .buildGeneralVectorRegion(name: "multi_root_same_origin", startAddress: 0x5000,
                rows: rows, initialState: BuilderState(parameters: []), hasExternalFacts: false, isVariadic: false))
        let producer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x5010 })
        let consumer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x5024 })
        guard case let .assign(value, _) = producer.operation,
              case let .assign(_, input) = consumer.operation else { return XCTFail("expected scalar producer and consumer") }
        XCTAssertEqual(input, .unary(op: "(uint64_t)", value: .unary(op: "(uint32_t)", value: value)))
        XCTAssertNotEqual(input, .unknown("unavailable_x9"))
        // Use the supplied scalar-test printer API. The negative renderer
        // control substitutes only
        // the early-branch unavailable operand; it is not a baseline rerun.
        let printer = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024))
        let rendered = printer.print(function: function).lines(sourcedAt: 0x5024)
            .map(\.text).joined(separator: "\n")
        XCTAssertFalse(rendered.isEmpty)
        XCTAssertFalse(rendered.contains("unavailable_x9"), rendered)
        var unavailableControl = function
        let consumerIndex = try XCTUnwrap(unavailableControl.instructions.firstIndex { $0.source.address == 0x5024 })
        guard case let .assign(destination, _) = consumer.operation else { return XCTFail("expected assignment") }
        unavailableControl.instructions[consumerIndex].operation = .assign(
            destination: destination, source: .unknown("unavailable_x9"))
        let controlText = printer.print(function: unavailableControl).lines(sourcedAt: 0x5024)
            .map(\.text).joined(separator: "\n")
        XCTAssertTrue(controlText.contains("unavailable_x9"), controlText)
        XCTAssertNotEqual(rendered, controlText)
        // Current renderer SOURCE1 supplies the actual assign/unary/name
        // bodies. Presentation-only overrides avoid assuming allocator IDs.
        let names = PseudocodeNameContext(function: function,
            registerNameOverrides: ["w9": "producer", "x11": "consumer"])
        XCTAssertEqual(printer.render(operation: consumer.operation, names: names),
            "consumer = (uint64_t)((uint32_t)(producer))")
        XCTAssertEqual(printer.render(operation: unavailableControl.instructions[consumerIndex].operation,
            names: names), "consumer = unavailable_x9")
    }

    func test441EqualValueAndEqualVersionWithoutSameSourceAreNotAgreement() throws {
        let fixture = fixture441()
        var different = fixture
        let original = try XCTUnwrap(fixture.witnesses[3]?[9])
        var otherSource = original.source
        otherSource.address = 0x7000
        different.witnesses[3]?[9] = .init(source: otherSource, definition: original.definition)
        XCTAssertEqual(different.outgoing[2]?.readRegister("x9"), different.outgoing[3]?.readRegister("x9"))
        XCTAssertEqual(different.witnesses[2]?[9]?.definition.value, different.witnesses[3]?[9]?.definition.value)
        XCTAssertNotEqual(different.witnesses[2]?[9]?.source, different.witnesses[3]?[9]?.source)
        XCTAssertEqual(incoming441(different).readRegister("x9"), .unknown("unavailable_x9"))
        var missing = fixture
        missing.witnesses[3] = [:]
        XCTAssertEqual(incoming441(missing).readRegister("x9"), .unknown("unavailable_x9"))
        // A second independently committed immediate assignment can print the
        // same RHS and allocate the same register version, but has another source.
        var independent = BuilderState(parameters: [])
        let equalValue = independent.writeRegister("w9")
        XCTAssertEqual(equalValue, fixture.value)
        let assignment = MacIRInstruction(source: otherSource,
            operation: .assign(destination: equalValue, source: .immediate(7)))
        different.outgoing[3] = independent
        different.witnesses[3] = ScalarCFGStatePlan.snapshotPendingGPRDefinitions(
            instructions: [assignment], state: independent)
        XCTAssertEqual(incoming441(different).readRegister("w9"), .unknown("unavailable_w9"))
    }

    func test441EveryRootMustHaveUnpoisonedFullWidthDefinition() {
        let fixture = fixture441()
        let poisons: [(inout BuilderState) -> Void] = [
            { $0.unavailableRegisterValues.insert("w9") },
            { $0.callUnavailableRegisterValues.insert("x9") },
            { $0.currentIntegerDefinitionByIndex[9]?.width = 64 },
            { $0.currentIntegerDefinitionByIndex[9]?.isJoinedDefinition = true },
            { $0.currentIntegerDefinitionByIndex[9]?.isSyntheticReturnPhi = true },
            { $0.currentIntegerDefinitionByIndex[9]?.value = .unknown("opaque") },
            { $0.registerVersions["w9"] = 900 },
            { $0.writeRegister("w9") },
            { $0.invalidateAppleCallerSavedState() }
        ]
        for poison in poisons {
            var poisoned = fixture
            if var root = poisoned.outgoing[3] { poison(&root); poisoned.outgoing[3] = root }
            XCTAssertEqual(incoming441(poisoned).readRegister("w9"), .unknown("unavailable_w9"))
            XCTAssertEqual(incoming441(poisoned).readRegister("x9"), .unknown("unavailable_x9"))
        }
        var metadataConflict = fixture
        metadataConflict.outgoing[3]?.valueTypeHints[fixture.value] = "incompatible_type"
        XCTAssertEqual(incoming441(metadataConflict).readRegister("w9"), .unknown("unavailable_w9"))
    }

    func test441OneBadPendingRouteCannotBeHiddenByAnAgreeingRoot() {
        let fixture = fixture441()
        let plans: [(inout ScalarCFGStatePlan) -> Void] = [
            { $0.pendingGPRTransparentBlocks.remove(6) },
            { $0.pendingGPRTraversalBudget = 1 },
            { $0 = self.changingCFG441($0) { $0.hasUnresolvedTargets = true } },
            { $0 = self.changingCFG441($0) { $0.blocks[6].predecessors = [] } },
            { $0 = self.changingCFG441($0) { $0.blocks[6].predecessors = [6]; $0.blocks[6].successors.append(6) } },
            { $0 = self.changingCFG441($0) { $0.blocks[6].predecessors = [4]; $0.blocks[4].successors.append(6) } },
            { $0 = self.changingCFG441($0) { $0.blocks[6].predecessors = [99] } },
            { $0 = self.changingCFG441($0) { $0.backEdges.insert(CFGEdge(6, 4)) } }
        ]
        for modify in plans {
            var invalid = fixture
            modify(&invalid.plan)
            XCTAssertEqual(incoming441(invalid).readRegister("x9"), .unknown("unavailable_x9"))
        }
        for rejected in [("mov", "w9, #7"), ("mov", "x9, #7"), ("bl", "_callee"),
                         ("mystery", "x9"), ("paciasp", ""), ("ldr", "q0, [x9], #16"),
                         ("cbz", "x2, 0x6014")] {
            var invalid = fixture
            invalid.rows[8] = row441(0x6020, rejected.0, rejected.1)
            invalid.plan.pendingGPRTransparentBlocks = MacIRBuilder.pendingGPRTransparentBlocks(
                in: invalid.plan.cfg, rows: invalid.rows)
            XCTAssertEqual(incoming441(invalid).readRegister("x9"), .unknown("unavailable_x9"), rejected.0)
        }
    }

    func test441EmittedControlInheritanceRejectsUnknownEffectsAndIncompletePaths() throws {
        let fixture = fixture441()
        let state = try XCTUnwrap(fixture.outgoing[1])
        let source = source441(fixture.rows[2])
        let branch = MacIRInstruction(source: source, operation: .conditionalBranch(condition: "==",
            left: state.readRegister("x2"), right: .immediate(0), target: .immediate(0x6010)))
        func inherit(_ plan: ScalarCFGStatePlan, _ rows: [InstructionRow], _ effects: [MacIRInstruction],
                     _ outgoing: [Int: BuilderState]) -> [Int: ScalarCFGStatePlan.PendingGPRDefinition] {
            plan.inheritedPendingGPRDefinitions441(for: 1, rows: rows, instructions: effects,
                outgoing: outgoing, witnesses: fixture.witnesses, local: [:])
        }
        XCTAssertEqual(inherit(fixture.plan, fixture.rows, [branch], fixture.outgoing)[9]?.source.address, 0x6000)
        let unknown = MacIRInstruction(source: source,
            operation: .unknown(destination: nil, mnemonic: "cbz", operands: source.operands))
        let write = MacIRInstruction(source: source, operation: .assign(destination: fixture.value, source: .immediate(7)))
        for effects in [[], [unknown], [write], [branch, branch]] {
            XCTAssertTrue(inherit(fixture.plan, fixture.rows, effects, fixture.outgoing).isEmpty)
        }
        var missing = fixture.outgoing; missing.removeValue(forKey: 0)
        XCTAssertTrue(inherit(fixture.plan, fixture.rows, [branch], missing).isEmpty)
        let pending = changingCFG441(fixture.plan) { $0.blocks[1].predecessors.append(2) }
        XCTAssertTrue(inherit(pending, fixture.rows, [branch], fixture.outgoing).isEmpty)
        let loop = changingCFG441(fixture.plan) { $0.backEdges.insert(CFGEdge(3, 1)) }
        XCTAssertTrue(inherit(loop, fixture.rows, [branch], fixture.outgoing).isEmpty)
        var malformedRows = fixture.rows
        malformedRows[2] = row441(0x6008, "cbz", "x2, 0x6010,")
        var malformed = branch; malformed.source = source441(malformedRows[2])
        XCTAssertTrue(inherit(fixture.plan, malformedRows, [malformed], fixture.outgoing).isEmpty)
        let wrongEdge = changingCFG441(fixture.plan) { $0.blocks[1].successors = [2] }
        XCTAssertTrue(inherit(wrongEdge, fixture.rows, [branch], fixture.outgoing).isEmpty)
        var notEqualRows = fixture.rows; notEqualRows[2] = row441(0x6008, "cbnz", "x2, 0x6010")
        let notEqual = MacIRInstruction(source: source441(notEqualRows[2]), operation: .conditionalBranch(
            condition: "!=", left: state.readRegister("x2"), right: .immediate(0), target: .immediate(0x6010)))
        XCTAssertEqual(inherit(fixture.plan, notEqualRows, [notEqual], fixture.outgoing)[9]?.source.address, 0x6000)
        // Non-control blocks preserve another local witness collector's output,
        // but never turn a local assignment into inherited predecessor evidence.
        let local = try XCTUnwrap(fixture.witnesses[0])
        let unchanged = fixture.plan.inheritedPendingGPRDefinitions441(for: 1, rows: fixture.rows,
            instructions: [write], outgoing: fixture.outgoing, witnesses: fixture.witnesses, local: local)
        XCTAssertEqual(unchanged[9]?.source, local[9]?.source)
    }

    func test441EmittedControlJoinRequiresWitnessFromEveryCompletedPredecessor() throws {
        let fixture = fixture441()
        var rows = Array(fixture.rows.prefix(7)) + [row441(0x601c, "ret")]
        rows[3] = row441(0x600c, "b", "0x6014")
        rows[4] = row441(0x6010, "b", "0x6014")
        rows[5] = row441(0x6014, "nop")
        rows[6] = row441(0x6018, "b", "0x601c")
        let spans = [0..<2, 2..<3, 3..<4, 4..<5, 5..<7, 7..<8]
        let predecessors = [[], [0], [1], [1], [2, 3], [4]]
        let plan = changingCFG441(fixture.plan) { cfg in
            cfg.blocks = spans.enumerated().map { index, span in
                BasicBlock(index: index, startIndex: span.lowerBound, endIndex: span.upperBound,
                    successors: predecessors.indices.filter { predecessors[$0].contains(index) },
                    predecessors: predecessors[index], isLoopHeader: false)
            }
            cfg.blockByStartIndex = Dictionary(uniqueKeysWithValues: cfg.blocks.map { ($0.startIndex, $0.index) })
        }
        // Only the arm B targets changed. Their physical snapshots still carry
        // the same source-proven definition; the new join is NOP followed by B.
        var outgoing = fixture.outgoing
        var phis: [ScalarCFGStatePlan.PhiDraft] = []
        var state = plan.incoming(for: 4, entry: BuilderState(parameters: []),
            outgoing: outgoing, phis: &phis, pendingGPRDefinitions: fixture.witnesses)
        let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
        let effects = [5, 6].map { index -> MacIRInstruction in
            let source = source441(rows[index])
            return .init(source: source, operation: builder.operationForVectorRegion(for: source, state: &state))
        }
        outgoing[4] = state
        func inherited(_ witnesses: [Int: [Int: ScalarCFGStatePlan.PendingGPRDefinition]])
            -> [Int: ScalarCFGStatePlan.PendingGPRDefinition] {
            plan.inheritedPendingGPRDefinitions441(for: 4, rows: rows, instructions: effects,
                outgoing: outgoing, witnesses: witnesses, local: [:])
        }
        XCTAssertEqual(inherited(fixture.witnesses)[9]?.source.address, 0x6000)
        var missing = fixture.witnesses; missing[3] = [:]
        XCTAssertTrue(inherited(missing).isEmpty)
        var different = fixture.witnesses
        let witness = try XCTUnwrap(different[3]?[9])
        var otherSource = witness.source; otherSource.address = 0x7000
        different[3]?[9] = .init(source: otherSource, definition: witness.definition)
        XCTAssertTrue(inherited(different).isEmpty)
        XCTAssertTrue(phis.isEmpty, "the existing completed-state merge is unchanged")
    }

    func test441EmittedCallsImplicitWritesAndWritebackNeverPropagateWitnesses() throws {
        let fixture = fixture441("x19")
        let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
        for rejected in [("bl", "_callee"), ("paciasp", ""), ("ldr", "x20, [x19], #8"),
                         ("mov", "w19, #7"), ("mystery", "x19")] {
            var rows = fixture.rows
            rows[2] = row441(0x6008, rejected.0, rejected.1)
            var state = try XCTUnwrap(fixture.outgoing[0])
            let source = source441(rows[2])
            let operation = builder.operationForVectorRegion(for: source, state: &state)
            if rejected.0 == "bl" {
                guard case .call = operation else { return XCTFail("expected real returning call") }
                XCTAssertEqual(state.readRegister("x19"), fixture.value,
                    "even an ABI-preserved same value is not an emitted-control certificate")
            }
            var outgoing = fixture.outgoing; outgoing[1] = state
            let inherited = fixture.plan.inheritedPendingGPRDefinitions441(for: 1, rows: rows,
                instructions: [.init(source: source, operation: operation)], outgoing: outgoing,
                witnesses: fixture.witnesses, local: [:])
            XCTAssertTrue(inherited.isEmpty, rejected.0)
        }
    }

    func test441FoldsEveryRootFloorWithoutImportingAncillaryAuthority() {
        var fixture = fixture441("w0")
        fixture.outgoing[2]?.registerVersionFloor = 500
        fixture.outgoing[3]?.registerVersionFloor = 900
        fixture.outgoing[3]?.nextRegisterTemporaryIndex = 1100
        fixture.outgoing[3]?.registerVersions["x20"] = 1200
        for index in [2, 3] {
            fixture.outgoing[index]?.constructedCallArgumentGPRs = [0]
            fixture.outgoing[index]?.stackSlotValues[8] = .init(value: .immediate(99), byteWidth: 8, carrierKind: .integer)
            fixture.outgoing[index]?.latestABIResultValue = fixture.value
        }
        var result = incoming441(fixture)
        XCTAssertEqual(result.readRegister("w0"), fixture.value)
        XCTAssertGreaterThanOrEqual(result.registerVersionFloor, 900)
        XCTAssertGreaterThanOrEqual(result.nextRegisterTemporaryIndex, 1100)
        XCTAssertEqual(result.registerVersions["x20"], 1200)
        XCTAssertTrue(result.constructedCallArgumentGPRs.isEmpty)
        XCTAssertTrue(result.stackSlotValues.isEmpty)
        XCTAssertFalse(result.entrySPIsExact)
        XCTAssertTrue(result.hasUnmodeledABIResultWrite)
        XCTAssertNotEqual(result.latestABIResultValue, fixture.value)
        XCTAssertEqual(result.callResultVectorWidth[0], 0)
        let next = result.writeRegister("w0")
        guard case let .register(_, version) = next else { return XCTFail("expected fresh integer register") }
        XCTAssertGreaterThan(version, 900)
    }
}
