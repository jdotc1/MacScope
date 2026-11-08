import Foundation
import XCTest
@testable import MacScope

final class UnwindAuditRegisterBranchTests: XCTestCase {
    private let earlierModels: [UnwindAuditModel] = [
        .boundedLoops, .boundedLoopCalls, .boundedLoopCallsMOVK, .boundedCFIControls,
        .boundedOneSource, .boundedOneSourceDivide, .boundedOneSourceRBitX, .boundedXStack
    ]
    private let branchWords: [UInt32] = [
        0xb4000040, 0x34000040, 0xb5000040, 0x35000040,
        0x36180040, 0x37180040, 0xb6000040, 0xb7f80040
    ]

    private func decode(_ words: [UInt32], model: UnwindAuditModel = .boundedRegisterBranches)
        throws -> [UnwindAuditInstruction] {
        let bytes = Data(words.flatMap { word in
            (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) }
        })
        return try UnwindAuditInstruction.decode(data: bytes, start: 0x1000,
            maximum: words.count, model: model)
    }

    private func instruction(_ word: UInt32) throws -> UnwindAuditInstruction {
        try XCTUnwrap(decode([word]).first)
    }

    private func assertCode<T>(_ code: String, file: StaticString = #filePath, line: UInt = #line,
                               _ operation: () throws -> T) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, code, file: file, line: line)
        }
    }

    private func assertFailure<T>(_ code: String, _ address: UInt64,
                                  file: StaticString = #filePath, line: UInt = #line,
                                  _ operation: () throws -> T) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, code, file: file, line: line)
            XCTAssertEqual((error as? UnwindAuditModelError)?.address, address, file: file, line: line)
        }
    }

    private func cbWord(x: Bool, nz: Bool, rt: Int, offset: Int) -> UInt32 {
        UInt32(0x34000000) | (x ? UInt32(0x80000000) : 0)
            | (nz ? UInt32(0x01000000) : 0)
            | ((UInt32(truncatingIfNeeded: offset / 4) & 0x7ffff) << 5) | UInt32(rt)
    }

    private func tbWord(bit: Int, nz: Bool, rt: Int, offset: Int) -> UInt32 {
        UInt32(0x36000000) | (UInt32(bit & 32) << 26) | (UInt32(bit & 31) << 19)
            | (nz ? UInt32(0x01000000) : 0)
            | ((UInt32(truncatingIfNeeded: offset / 4) & 0x3fff) << 5) | UInt32(rt)
    }

    private func words(rt: Int) -> [UInt32] {
        [cbWord(x: false, nz: false, rt: rt, offset: 8),
         cbWord(x: false, nz: true, rt: rt, offset: 8),
         cbWord(x: true, nz: false, rt: rt, offset: 8),
         cbWord(x: true, nz: true, rt: rt, offset: 8),
         tbWord(bit: 3, nz: false, rt: rt, offset: 8),
         tbWord(bit: 3, nz: true, rt: rt, offset: 8),
         tbWord(bit: 40, nz: false, rt: rt, offset: 8),
         tbWord(bit: 40, nz: true, rt: rt, offset: 8)]
    }

    private func run(_ words: [UInt32], mode: String = "frameless", callees: Set<UInt64> = [],
                     limits: UnwindAuditLimits = .init(), model: UnwindAuditModel = .boundedRegisterBranches,
                     recover: (UnwindAuditMachine, UInt64) throws -> [String: UnwindAuditValue] = {
                         state, _ in ["x19": state.registers[19]]
                     }) throws -> UnwindAuditExecutionResult {
        try UnwindAuditExecution.run(instructions: decode(words, model: model), mode: mode,
            calleeEntries: callees, limits: limits, model: model, recover: recover)
    }

    private func frame(_ b1: UInt32, _ b2: UInt32, _ b3: UInt32, _ b4: UInt32) -> [UInt32] {
        [0xa9bd7bfd, 0xa90153f3, 0x910003fd, b1, b2, b3, b4,
         0x940003f9, 0xa94153f3, 0xa8c37bfd, 0xd65f03c0]
    }

    private func key(modelID: String) throws -> UnwindAuditResultKey {
        .init(imageID: UUID(), slot: .primary, generation: UUID(),
              identity: try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
                  rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "a", count: 64),
                  selectedSliceByteCount: 64), modelID: modelID, configuration: .init())
    }

    private func op(_ code: UInt8, _ values: [UInt64] = []) -> DWARFStructuredCFAOperation {
        .init(sectionOffset: 0, opcode: code, operands: values.map { .unsigned($0) }, rawBytes: [code])
    }

    private func program(_ operations: [DWARFStructuredCFAOperation],
                         status: DWARFStructuredCFADecodeStatus = .complete) -> DWARFStructuredCFAProgram {
        .init(sectionOffset: 0, rawBytes: operations.flatMap(\.rawBytes), operations: operations, status: status)
    }

    private func table(initial: DWARFStructuredCFAProgram? = nil,
                       body: DWARFStructuredCFAProgram? = nil) -> DWARFStructuredCallFrameTable {
        let cie = DWARFStructuredCIE(sectionOffset: 0, version: 1, augmentation: "zR",
            augmentationData: [0x10], codeAlignmentFactor: 1, dataAlignmentFactor: -8,
            returnAddressRegister: 30, fdePointerEncoding: 0x10,
            initialProgram: initial ?? program([op(12, [31, 16]), op(0x9d, [29, 2]), op(0x9e, [30, 1])]))
        let fde = DWARFStructuredFDE(sectionOffset: 20, cieSectionOffset: 0,
            initialLocation: 0x100, rangeSize: 8, augmentationData: [],
            program: body ?? program([op(13, [29])]))
        return .init(cies: [cie], fdes: [fde])
    }

    private func twoFDEs(_ body: DWARFStructuredCFAProgram? = nil) -> DWARFStructuredCallFrameTable {
        var result = table()
        result.fdes.append(.init(sectionOffset: 40, cieSectionOffset: 0,
            initialLocation: 0x200, rangeSize: 8, augmentationData: [],
            program: body ?? program([op(10), op(0)])))
        return result
    }

    func testUC01CompareDecodeFields() throws {
        let rows: [(UInt32, String, Int, Int64)] = [
            (0xb4000040, "xcbz", 0, 8), (0x34000040, "wcbz", 0, 8),
            (0xb5000040, "xcbnz", 0, 8), (0x35000040, "wcbnz", 0, 8),
            (0xb4fffff4, "xcbz", 20, -4), (0x35ffffff, "wcbnz", 31, -4),
            (0xb4800000, "xcbz", 0, -1048576), (0xb57ffffe, "xcbnz", 30, 1048572),
            (0x34000005, "wcbz", 5, 0)
        ]
        for (word, kind, rn, offset) in rows {
            let ins = try instruction(word)
            XCTAssertEqual(ins.kind, kind)
            XCTAssertEqual(ins.rn, rn)
            XCTAssertEqual(ins.immediate, offset)
            XCTAssertEqual(ins.rd, Int(0))
            XCTAssertEqual(ins.rt2, Int(0))
            XCTAssertEqual(ins.addressing, "")
            XCTAssertEqual(ins.word, word)
            XCTAssertEqual(ins.address, UInt64(0x1000))
            XCTAssertFalse(ins.changesSP)
            XCTAssertFalse(ins.changesFP)
            XCTAssertTrue(ins.isConditionalBranch)
        }
    }

    func testUC02TestBitDecodeFields() throws {
        let rows: [(UInt32, String, Int, Int64, String)] = [
            (0x36180040, "wtbz", 0, 8, "3"), (0x37180040, "wtbnz", 0, 8, "3"),
            (0xb6000040, "xtbz", 0, 8, "32"), (0xb6f80040, "xtbz", 0, 8, "63"),
            (0xb7fffffe, "xtbnz", 30, -4, "63"), (0x36f80040, "wtbz", 0, 8, "31"),
            (0x3704001f, "wtbnz", 31, -32768, "0"), (0x3603ffe7, "wtbz", 7, 32764, "0"),
            (0xb708000c, "xtbnz", 12, 0, "33")
        ]
        for (word, kind, rn, offset, bit) in rows {
            let ins = try instruction(word)
            XCTAssertEqual(ins.kind, kind)
            XCTAssertEqual(ins.rn, rn)
            XCTAssertEqual(ins.immediate, offset)
            XCTAssertEqual(ins.addressing, bit)
            XCTAssertEqual(ins.rd, Int(0))
            XCTAssertEqual(ins.rt2, Int(0))
            XCTAssertEqual(ins.word, word)
            XCTAssertEqual(ins.address, UInt64(0x1000))
            XCTAssertFalse(ins.changesSP)
            XCTAssertFalse(ins.changesFP)
            XCTAssertTrue(ins.isConditionalBranch)
        }
    }

    func testUC03RegisterSweep() throws {
        XCTAssertEqual(cbWord(x: true, nz: false, rt: 0, offset: 8), UInt32(0xb4000040))
        XCTAssertEqual(tbWord(bit: 3, nz: false, rt: 0, offset: 8), UInt32(0x36180040))
        for rt in 0...31 {
            for x in [false, true] {
                for nz in [false, true] {
                    let ins = try instruction(cbWord(x: x, nz: nz, rt: rt, offset: 4 * rt))
                    let expected: String = x ? (nz ? "xcbnz" : "xcbz") : (nz ? "wcbnz" : "wcbz")
                    XCTAssertEqual(ins.kind, expected)
                    XCTAssertEqual(ins.rn, rt)
                    XCTAssertEqual(ins.rd, Int(0))
                    XCTAssertEqual(ins.rt2, Int(0))
                    XCTAssertEqual(ins.immediate, Int64(4 * rt))
                    XCTAssertEqual(ins.addressing, "")
                }
            }
            for bit in [rt, rt + 32] {
                for nz in [false, true] {
                    let ins = try instruction(tbWord(bit: bit, nz: nz, rt: rt, offset: 4 * rt))
                    let expected: String = bit < 32 ? (nz ? "wtbnz" : "wtbz") : (nz ? "xtbnz" : "xtbz")
                    XCTAssertEqual(ins.kind, expected)
                    XCTAssertEqual(ins.rn, rt)
                    XCTAssertEqual(ins.rd, Int(0))
                    XCTAssertEqual(ins.rt2, Int(0))
                    XCTAssertEqual(ins.immediate, Int64(4 * rt))
                    XCTAssertEqual(ins.addressing, String(bit))
                }
            }
        }
    }

    func testUC04OffsetExtremesAndFixedBits() throws {
        for offset in [-1048576, -4, 0, 4, 1048572] {
            XCTAssertEqual(try instruction(cbWord(x: true, nz: false, rt: 0, offset: offset)).immediate, Int64(offset))
        }
        for offset in [-32768, -4, 0, 4, 32764] {
            XCTAssertEqual(try instruction(tbWord(bit: 3, nz: false, rt: 0, offset: offset)).immediate, Int64(offset))
        }
        let changed: [UInt32] = [0x34180040, 0x32180040, 0x3e180040, 0x26180040, 0x16180040, 0x76180040]
        for word in changed {
            if let ins = try? decode([word]).first {
                XCTAssertFalse(["wtbz", "wtbnz", "xtbz", "xtbnz"].contains(ins.kind))
            }
        }
        let compare = try instruction(0x34180040)
        XCTAssertEqual(compare.kind, "wcbz")
        XCTAssertEqual(compare.rn, Int(0))
        XCTAssertEqual(compare.immediate, Int64(196616))
    }

    func testUC05DecodeGating() throws {
        for model in earlierModels {
            for word in branchWords {
                assertFailure("unsupported_control_flow", 0x1000) { try decode([word], model: model) }
            }
        }
        assertFailure("unsupported_control_flow", 0x1000) {
            try UnwindAuditInstruction.decode(data: Data([0x40, 0x00, 0x00, 0xb4]), start: 0x1000, maximum: 1)
        }
        assertFailure("unsupported_control_flow", 0x1004) {
            try decode([0xd503201f, 0xb4000040], model: .boundedXStack)
        }
    }

    func testUC06NeighborsUnderV9() throws {
        assertCode("unsupported_instruction") { try decode([0x54000010]) }
        assertCode("unsupported_control_flow") { try decode([0xd61f0000]) }
        let conditional = try instruction(0x54000020)
        XCTAssertEqual(conditional.kind, "bcond")
        XCTAssertEqual(conditional.addressing, "0")
        XCTAssertEqual(conditional.immediate, Int64(4))
        XCTAssertTrue(conditional.isConditionalBranch)
        let branch = try instruction(0x14000002)
        XCTAssertEqual(branch.kind, "b")
        XCTAssertEqual(branch.immediate, Int64(8))
        XCTAssertFalse(branch.isConditionalBranch)
        XCTAssertEqual(try instruction(0xd65f03c0).kind, "ret")
        for word in [UInt32(0x54000020), 0x14000002] {
            let old = try XCTUnwrap(decode([word], model: .boundedXStack).first)
            let new = try instruction(word)
            XCTAssertEqual(new.kind, old.kind)
            XCTAssertEqual(new.immediate, old.immediate)
            XCTAssertEqual(new.addressing, old.addressing)
        }
    }

    func testUC07ModelIdentityAndFlags() throws {
        let models = earlierModels + [.boundedRegisterBranches]
        let expectedIDs: [String] = [
            "arm64-bounded-loops-cfa-register-v1", "arm64-bounded-loop-calls-cfa-register-v2",
            "arm64-bounded-loop-calls-movk-cfa-register-v3", "arm64-bounded-cfi-controls-v4",
            "arm64-bounded-one-source-v5", "arm64-bounded-one-source-v6",
            "arm64-bounded-one-source-v7", "arm64-bounded-x-stack-v8",
            "arm64-bounded-register-branches-v9"
        ]
        XCTAssertEqual(models.map(\.rawValue), expectedIDs)
        XCTAssertEqual(Set(models.map(\.rawValue)).count, Int(9))
        XCTAssertEqual(UnwindAuditModel(rawValue: "arm64-bounded-register-branches-v9"), .boundedRegisterBranches)
        let flags: [[Bool]] = [
            [false, false, false, false, false, false, false, false, false],
            [true, false, false, false, false, false, false, false, false],
            [true, true, false, false, false, false, false, false, false],
            [false, false, true, false, false, false, false, false, false],
            [false, false, false, true, false, false, false, false, false],
            [false, false, false, true, true, false, false, false, false],
            [false, false, false, true, true, true, false, false, false],
            [false, false, false, true, true, true, true, false, false],
            [false, false, false, true, true, true, true, true, true]
        ]
        for (model, expected) in zip(models, flags) {
            XCTAssertEqual([model.permitsLoopCalls, model.permitsMOVK, model.permitsCFIControls,
                model.permitsOneSource, model.permitsDivide, model.permitsRBitX, model.permitsXStack,
                model.permitsRegisterBranches, model.permitsLocalFDERefusal], expected, model.rawValue)
        }
    }

    func testUC08InteractiveRouting() throws {
        for model in [UnwindAuditModel.boundedLoops, .boundedCFIControls, .boundedOneSource,
            .boundedOneSourceDivide, .boundedOneSourceRBitX, .boundedXStack, .boundedRegisterBranches] {
            XCTAssertTrue(UnwindAuditResultKey.supportsInteractive(model))
        }
        for model in [UnwindAuditModel.boundedLoopCalls, .boundedLoopCallsMOVK] {
            XCTAssertFalse(UnwindAuditResultKey.supportsInteractive(model))
        }
        XCTAssertEqual(try key(modelID: UnwindAuditModel.boundedRegisterBranches.rawValue).model, .boundedRegisterBranches)
        XCTAssertNil(try key(modelID: "unknown-model").model)
    }

    func testUC09ReportAndComparator() throws {
        let input = try key(modelID: UnwindAuditModel.boundedRegisterBranches.rawValue)
        let original = UnwindAuditReport(identity: input.identity, analysisModelVersion: input.modelID,
            configuration: input.configuration, findings: [])
        try original.validate()
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.analysisModelVersion, "arm64-bounded-register-branches-v9")
        let finding = UnwindAuditFinding(identity: input.identity,
            function: .init(id: "owned", address: 0x1000, symbolName: "_owned", size: 4),
            endAddress: 0x1004, verdict: "unresolved", coverage: "dwarf_reference",
            mode: "dwarf", scope: "metadata_only")
        let baseline = UnwindAuditReport(identity: input.identity, findings: [finding])
        var current = baseline
        current.analysisModelVersion = UnwindAuditModel.boundedRegisterBranches.rawValue
        var v8 = baseline
        v8.analysisModelVersion = UnwindAuditModel.boundedXStack.rawValue
        for before in [baseline, v8] {
            let comparison = try UnwindAuditComparator.compare(baseline: before, current: current)
            XCTAssertFalse(comparison.modelCompatible)
            XCTAssertEqual(comparison.changes.map(\.change), [.incompatible])
        }
    }

    func testUC10CompareOutcomes() throws {
        let rows: [(UInt64, [Bool])] = [
            (0, [true, false, true, false]), (1, [false, true, false, true]),
            (0x100000000, [true, false, false, true]),
            (0xffffffffffffffff, [false, true, false, true]),
            (0xffffffff00000000, [true, false, false, true])
        ]
        for (value, expected) in rows {
            var state = UnwindAuditMachine()
            state.registers[5] = .constant(value)
            let registers = state.registers
            let sp = state.sp
            for (word, taken) in zip(Array(words(rt: 5).prefix(4)), expected) {
                XCTAssertEqual(try state.branchTaken(instruction(word)), Optional<Bool>(taken))
                XCTAssertEqual(state.registers, registers)
                XCTAssertEqual(state.sp, sp)
            }
        }
    }

    func testUC11TestBitOutcomes() throws {
        for bit in 0...63 {
            let rows: [(UInt64, [Bool])] = [
                (0, [true, false]), (UInt64(1) << UInt64(bit), [false, true]),
                (UInt64.max, [false, true]),
                (bit < 32 ? 0xffffffff00000000 : 0x00000000ffffffff, [true, false])
            ]
            for (value, expected) in rows {
                var state = UnwindAuditMachine()
                state.registers[7] = .constant(value)
                for (nz, taken) in zip([false, true], expected) {
                    XCTAssertEqual(try state.branchTaken(instruction(tbWord(bit: bit, nz: nz, rt: 7, offset: 8))), Optional<Bool>(taken))
                }
            }
        }
    }

    func testUC12ZeroRegisterAndNoFlagReads() throws {
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -16)
        let zeroWords: [UInt32] = [cbWord(x: true, nz: false, rt: 31, offset: 8),
            cbWord(x: true, nz: true, rt: 31, offset: 8),
            tbWord(bit: 5, nz: false, rt: 31, offset: 8), tbWord(bit: 5, nz: true, rt: 31, offset: 8)]
        for (word, expected) in zip(zeroWords, [true, false, true, false]) {
            XCTAssertEqual(try state.branchTaken(instruction(word)), Optional<Bool>(expected))
        }
        var fresh = UnwindAuditMachine()
        fresh.registers[0] = .constant(1)
        XCTAssertEqual(try fresh.branchTaken(instruction(0xb4000040)), Optional<Bool>(false))
        var flagged = fresh
        try flagged.apply(instruction(0xf100041f))
        XCTAssertEqual(try flagged.branchTaken(instruction(0xb4000040)), Optional<Bool>(false))
    }

    func testUC13UnknownTestedValue() throws {
        let original = UnwindAuditMachine()
        XCTAssertEqual(original.registers[3], .original(register: 3, displacement: 0))
        var unknown = original
        unknown.registers[3] = .unknown("t")
        for state in [original, unknown] {
            for word in words(rt: 3) {
                XCTAssertNil(try state.branchTaken(instruction(word)))
            }
        }
    }

    func testUC14StackTestedValue() throws {
        for strict in [false, true] {
            var state = UnwindAuditMachine(strictCallState: strict)
            state.registers[4] = .stack(displacement: -16)
            for (index, word) in words(rt: 4).enumerated() {
                let code: String = index < 4 ? "compare_branch_stack_address_not_modeled" : "test_bit_branch_stack_address_not_modeled"
                assertFailure(code, 0x1000) { try state.branchTaken(instruction(word)) }
            }
        }
    }

    func testUC15DispatchRefusal() throws {
        for word in branchWords {
            var state = UnwindAuditMachine()
            state.sp = .stack(displacement: -16)
            state.memory[-16] = .constant(7)
            let registers = state.registers
            let sp = state.sp
            let memory = state.memory
            assertFailure("cfg_edge_requires_dispatch", 0x1000) { try state.apply(instruction(word)) }
            XCTAssertEqual(state.registers, registers)
            XCTAssertEqual(state.sp, sp)
            XCTAssertEqual(state.memory, memory)
        }
    }

    func testUC16WrongKindOrBadBit() throws {
        let state = UnwindAuditMachine()
        for word in [UInt32(0xd503201f), 0x54000020] {
            assertFailure("cfg_condition_not_modeled", 0x1000) { try state.branchTaken(instruction(word)) }
        }
        for bit in ["64", "-1", "", "x"] {
            var ins = try instruction(0x36180040)
            ins.addressing = bit
            assertFailure("cfg_condition_not_modeled", 0x1000) { try state.branchTaken(ins) }
        }
        var permitted = try instruction(0x36180040)
        permitted.addressing = "63"
        XCTAssertNoThrow(try state.branchTaken(permitted))
    }

    func testUC17ExecutionAdmission() throws {
        for branch in [UInt32(0xb4000040), 0x36180040] {
            let instructions = try decode([branch, 0xd503201f, 0xd65f03c0])
            for model in earlierModels {
                assertFailure("unsupported_instruction", 0x1000) {
                    try UnwindAuditExecution.run(instructions: instructions, mode: "frameless",
                        calleeEntries: [], limits: .init(), model: model) { state, _ in
                        ["x19": state.registers[19]]
                    }
                }
            }
            XCTAssertNoThrow(try UnwindAuditExecution.run(instructions: instructions, mode: "frameless",
                calleeEntries: [], limits: .init(), model: .boundedRegisterBranches) { state, _ in
                ["x19": state.registers[19]]
            })
        }
    }

    func testUC18KnownBranchTakenAndNotTaken() throws {
        let result = try run([0xd2800000, 0xb4000040, 0xd2800033, 0xd65f03c0])
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1000), UInt64(0x1004)])
        XCTAssertEqual(result.observations.map(\.certain), [true, true])
        for observation in result.observations {
            XCTAssertEqual(observation.recovered["x19"], .original(register: 19, displacement: 0))
        }
        XCTAssertEqual(result.steps, Int(3))
        assertFailure("unmodeled_return_state", 0x100c) {
            try run([0xd2800000, 0xb5000040, 0xd2800033, 0xd65f03c0])
        }
    }

    func testUC19UnknownValueForks() throws {
        let result = try run([0xb4000040, 0xd503201f, 0xd65f03c0])
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1000), UInt64(0x1004)])
        XCTAssertEqual(result.observations.map(\.certain), [true, false])
        for observation in result.observations {
            XCTAssertEqual(observation.recovered["x19"], .original(register: 19, displacement: 0))
        }
        XCTAssertEqual(result.steps, Int(4))
        XCTAssertNil(result.loopHeader)
        XCTAssertEqual(result.loopMemberCount, Int(0))
        XCTAssertEqual(result.loopVisits, Int(0))
        XCTAssertEqual(result.loopClosures, Int(0))
        XCTAssertEqual(result.instructionCount, Int(3))
        XCTAssertEqual(result.scope, "modeled_leaf_body")
    }

    func testUC20ForkBudget() throws {
        var limits = UnwindAuditLimits()
        limits.maxPaths = 1
        assertFailure("cfg_path_limit", 0x1000) {
            try run([0xb4000040, 0xd503201f, 0xd65f03c0], limits: limits)
        }
    }

    func testUC21ZeroRegisterBranches() throws {
        let taken = try run([0xb400005f, 0xd503201f, 0xd65f03c0])
        XCTAssertEqual(taken.observations.map(\.pc), [UInt64(0x1000)])
        XCTAssertEqual(taken.observations.map(\.certain), [true])
        XCTAssertEqual(taken.steps, Int(2))
        let fallthroughResult = try run([0xb500005f, 0xd503201f, 0xd65f03c0])
        XCTAssertEqual(fallthroughResult.observations.map(\.pc), [UInt64(0x1000), UInt64(0x1004)])
        XCTAssertEqual(fallthroughResult.observations.map(\.certain), [true, true])
        XCTAssertEqual(fallthroughResult.steps, Int(3))
        var onePath = UnwindAuditLimits()
        onePath.maxPaths = 1
        XCTAssertNoThrow(try run([0xb400005f, 0xd503201f, 0xd65f03c0], limits: onePath))
        XCTAssertNoThrow(try run([0xb500005f, 0xd503201f, 0xd65f03c0], limits: onePath))
    }

    func testUC22CountedLoop() throws {
        let words: [UInt32] = [0xd10043ff, 0xd2800040, 0xf1000400, 0xb5ffffe0, 0x910043ff, 0xd65f03c0]
        let result = try run(words, recover: { state, _ in ["x0": state.registers[0]] })
        XCTAssertEqual(result.loopHeader, UInt64(0x1008))
        XCTAssertEqual(result.loopMemberCount, Int(2))
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1004), UInt64(0x1008), UInt64(0x100c), UInt64(0x1008), UInt64(0x100c)])
        let values: [UnwindAuditValue?] = [.original(register: 0, displacement: 0), .constant(2), .constant(1), .constant(1), .constant(0)]
        XCTAssertEqual(result.observations.map { $0.recovered["x0"] }, values)
        XCTAssertEqual(result.observations.map(\.certain), [true, true, true, true, true])
        XCTAssertEqual(result.steps, Int(8))
        XCTAssertEqual(result.loopVisits, Int(2))
        XCTAssertEqual(result.loopClosures, Int(0))
        var limits = UnwindAuditLimits()
        limits.maxSteps = 7
        assertCode("cfg_work_limit") { try run(words, limits: limits, recover: { state, _ in ["x0": state.registers[0]] }) }
        limits.maxSteps = 8
        XCTAssertNoThrow(try run(words, limits: limits, recover: { state, _ in ["x0": state.registers[0]] }))
    }

    func testUC23RecurrenceWithoutExit() throws {
        assertCode("no_supported_observation") { try run([0xd2800000, 0xb4ffffe0, 0xd65f03c0]) }
        assertCode("cfg_loop_shape_not_modeled") { try run([0xb4000000, 0xd65f03c0]) }
    }

    func testUC24ForkWithCertaintyInFrame() throws {
        let fixtures = [frame(0xb4000060, 0xb400003f, 0xd28000d3, 0xd503201f),
                        frame(0xb4000060, 0xd28000d3, 0xd503201f, 0xd503201f)]
        for fixture in fixtures {
            let result = try run(fixture, mode: "frame", callees: [0x2000])
            XCTAssertEqual(result.observations.count, Int(2))
            XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x101c), UInt64(0x101c)])
            XCTAssertEqual(result.observations.map(\.certain), [false, false])
            let values = try result.observations.map { try XCTUnwrap($0.recovered["x19"]) }
            XCTAssertEqual(Set(values), Set<UnwindAuditValue>([.constant(6), .original(register: 19, displacement: 0)]))
        }
    }

    func testUC25BranchTargetErrors() throws {
        for word in [UInt32(0xb4800000), 0xb4ffffe0] {
            assertFailure("cfg_edge_not_modeled", 0x1000) { try run([word, 0xd65f03c0]) }
        }
    }

    func testUC26BCondRegressionUnderV9() throws {
        let result = try run([0xf100011f, 0x54ffffe1, 0xd65f03c0])
        XCTAssertEqual(Set(result.observations.map(\.pc)), Set<UInt64>([0x1000, 0x1004]))
        XCTAssertEqual(result.loopVisits, Int(2))
        XCTAssertEqual(result.loopClosures, Int(1))
        XCTAssertTrue(result.observations.contains { !$0.certain })
    }

    func testUC27CFILocalRefusal() throws {
        let cfi = try UnwindAuditCFI(table: twoFDEs(), enableCFIControls: false, localFDERefusal: true)
        let a = try XCTUnwrap(cfi.fdes[20])
        let b = try XCTUnwrap(cfi.fdes[40])
        XCTAssertEqual(a.rows.count, Int(1))
        XCTAssertNil(a.refusal)
        XCTAssertTrue(b.rows.isEmpty)
        XCTAssertNotNil(b.refusal)
        XCTAssertEqual(try cfi.select(offset: 20, start: 0x100, end: 0x108).offset, Int(20))
        assertCode("dwarf_cfi_unsupported") { try cfi.select(offset: 40, start: 0x200, end: 0x208) }
        assertCode("dwarf_cfi_unsupported") { try b.row(at: 0x200) }
    }

    func testUC28CFIGlobalRefusals() throws {
        assertCode("dwarf_cfi_unsupported") { try UnwindAuditCFI(table: twoFDEs(), localFDERefusal: false) }
        assertCode("dwarf_cfi_unsupported") { try UnwindAuditCFI(table: twoFDEs()) }
        let initial = program([op(12, [31, 16]), op(0x9d, [29, 2]), op(0x9e, [30, 1]), op(10)])
        assertCode("dwarf_cfi_unsupported") {
            try UnwindAuditCFI(table: table(initial: initial), localFDERefusal: true)
        }
        assertCode("dwarf_cfi_unsupported") {
            try UnwindAuditCFI(table: table(body: program([op(15), op(10)])), localFDERefusal: true)
        }
        let tail = try UnwindAuditCFI(table: table(body: program([op(10), op(15)])), localFDERefusal: true)
        XCTAssertNotNil(try XCTUnwrap(tail.fdes[20]).refusal)
        for status in [DWARFStructuredCFADecodeStatus.unsupported(opcode: 0x3f), .malformed(offset: 45)] {
            assertCode("dwarf_cfi_unsupported") {
                try UnwindAuditCFI(table: table(body: program([op(10)], status: status)), localFDERefusal: true)
            }
        }
        assertCode("dwarf_cfi_unsupported") {
            try UnwindAuditCFI(table: table(body: program([op(2, [4])])), localFDERefusal: true)
        }
        var invalid = twoFDEs()
        invalid.fdes.append(.init(sectionOffset: 60, cieSectionOffset: 0,
            initialLocation: 0x300, rangeSize: 3, augmentationData: [], program: program([op(13, [29])])))
        assertCode("dwarf_cfi_unsupported") { try UnwindAuditCFI(table: invalid, localFDERefusal: true) }
    }

    func testUC29CFIControlsOn() throws {
        let cfi = try UnwindAuditCFI(table: twoFDEs(program([op(10), op(13, [29]), op(11)])),
            enableCFIControls: true, localFDERefusal: true)
        let b = try XCTUnwrap(cfi.fdes[40])
        XCTAssertNil(b.refusal)
        XCTAssertEqual(b.rows.count, Int(1))
        let row = try XCTUnwrap(b.rows.first)
        XCTAssertEqual(row.register, Int(31))
        XCTAssertEqual(row.offset, Int64(16))
    }

    func testUC30RefusedRangeOverlaps() throws {
        var overlapping = twoFDEs()
        overlapping.fdes.append(.init(sectionOffset: 60, cieSectionOffset: 0,
            initialLocation: 0x204, rangeSize: 8, augmentationData: [], program: program([op(13, [29])])))
        let cfi = try UnwindAuditCFI(table: overlapping, localFDERefusal: true)
        assertCode("dwarf_cfi_unsupported") { try cfi.select(offset: 60, start: 0x204, end: 0x20c) }
        assertCode("dwarf_cfi_unsupported") { try cfi.select(offset: 40, start: 0x200, end: 0x208) }
        XCTAssertNoThrow(try cfi.select(offset: 20, start: 0x100, end: 0x108))
    }

    func testUC31BudgetBoundary() throws {
        let accepted = twoFDEs(program([op(10)] + Array(repeating: op(0), count: 49_997)))
        XCTAssertNoThrow(try UnwindAuditCFI(table: accepted, localFDERefusal: true))
        let refused = twoFDEs(program([op(10)] + Array(repeating: op(0), count: 49_998)))
        assertCode("dwarf_cfi_unsupported") { try UnwindAuditCFI(table: refused, localFDERefusal: true) }
    }

    func testUC32CumulativeDecodeUnderV9() throws {
        let rows: [(UInt32, String)] = [
            (0x5ac000a4, "wrbit"), (0x5ac008a4, "wrev"), (0xdac014a4, "xcls"),
            (0x1ac608a4, "wudiv"), (0x9ac60ca4, "xsdiv"), (0xdac000a4, "xrbit"),
            (0xf90003e0, "xstr"), (0xf94003e0, "xldr"),
            (0xb90003e0, "wstr"), (0xb94003e0, "wldr")
        ]
        for (word, kind) in rows { XCTAssertEqual(try instruction(word).kind, kind) }
        for word in [UInt32(0xf297dde0), 0x7297dde0, 0x5ac010a4, 0xdac010a4] {
            assertCode("unsupported_instruction") { try decode([word]) }
        }
    }

    func testUC33ServiceWiringAtTableLevel() throws {
        let models: [UnwindAuditModel] = [.boundedLoops, .boundedLoopCalls, .boundedLoopCallsMOVK,
            .boundedOneSource, .boundedOneSourceDivide, .boundedOneSourceRBitX, .boundedXStack]
        let t = twoFDEs()
        for model in models {
            assertCode("dwarf_cfi_unsupported") {
                try UnwindAuditCFI(table: t, enableCFIControls: model.permitsCFIControls,
                    localFDERefusal: model.permitsLocalFDERefusal)
            }
        }
        let model = UnwindAuditModel.boundedRegisterBranches
        let cfi = try UnwindAuditCFI(table: t, enableCFIControls: model.permitsCFIControls,
            localFDERefusal: model.permitsLocalFDERefusal)
        XCTAssertNotNil(try XCTUnwrap(cfi.fdes[40]).refusal)
        XCTAssertNil(try XCTUnwrap(cfi.fdes[20]).refusal)
    }
}
