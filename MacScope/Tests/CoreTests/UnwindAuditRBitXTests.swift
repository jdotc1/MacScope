import Foundation
import XCTest
@testable import MacScope

final class UnwindAuditRBitXTests: XCTestCase {
    private func decode(_ words: [UInt32],
                        model: UnwindAuditModel = .boundedOneSourceRBitX) throws -> [UnwindAuditInstruction] {
        let bytes = Data(words.flatMap { word in
            (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) }
        })
        return try UnwindAuditInstruction.decode(data: bytes, start: 0x1000,
                                                 maximum: words.count, model: model)
    }

    private func assertCode<T>(_ code: String, file: StaticString = #filePath, line: UInt = #line,
                               _ operation: () throws -> T) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, code, file: file, line: line)
        }
    }

    private func word(rd: Int, rn: Int) -> UInt32 {
        0xdac00000 | UInt32(rn) << 5 | UInt32(rd)
    }

    private func frame(_ s1: UInt32, _ s2: UInt32, _ operation: UInt32) -> [UInt32] {
        [0xa9be7bfd, 0xa90153f3, 0x910003fd, s1, s2, operation,
         0x940003fa, 0xa94153f3, 0xa8c27bfd, 0xd65f03c0]
    }

    private func leaf(_ s1: UInt32, _ s2: UInt32, _ operation: UInt32) -> [UInt32] {
        [s1, s2, operation, 0xd503201f, 0xd65f03c0]
    }

    private func run(_ words: [UInt32], mode: String = "frameless", callees: Set<UInt64> = [],
                     limits: UnwindAuditLimits = .init(),
                     model: UnwindAuditModel = .boundedOneSourceRBitX,
                     decodeModel: UnwindAuditModel? = nil) throws -> UnwindAuditExecutionResult {
        let instructions = try decode(words, model: decodeModel ?? model)
        return try UnwindAuditExecution.run(instructions: instructions, mode: mode,
            calleeEntries: callees, limits: limits, model: model) { state, _ in
                mode == "frame" ? ["x19": state.registers[19]] : ["x0": state.registers[0]]
            }
    }

    private func key(modelID: String) throws -> UnwindAuditResultKey {
        .init(imageID: UUID(), slot: .primary, generation: UUID(),
              identity: try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
                  rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "a", count: 64),
                  selectedSliceByteCount: 64),
              modelID: modelID, configuration: .init())
    }

    private func report(_ key: UnwindAuditResultKey) -> UnwindAuditReport {
        .init(identity: key.identity, analysisModelVersion: key.modelID,
              configuration: key.configuration, findings: [])
    }

    func testUC01DecodeFields() throws {
        let cases: [(UInt32, Int, Int, Bool)] = [
            (0xdac000a4, 4, 5, false), (0xdac0003d, 29, 1, true),
            (0xdac0003f, 31, 1, false), (0xdac003e0, 0, 31, false),
            (0xdac003ff, 31, 31, false)
        ]
        for (encoded, rd, rn, changesFP) in cases {
            let instruction = try XCTUnwrap(decode([encoded]).first)
            XCTAssertEqual(instruction.kind, String("xrbit"))
            XCTAssertEqual(instruction.rd, rd)
            XCTAssertEqual(instruction.rn, rn)
            XCTAssertEqual(instruction.rt2, Int(0))
            XCTAssertEqual(instruction.immediate, Int64(0))
            XCTAssertEqual(instruction.addressing, String(""))
            XCTAssertEqual(instruction.word, encoded)
            XCTAssertEqual(instruction.address, UInt64(0x1000))
            XCTAssertFalse(instruction.changesSP)
            XCTAssertEqual(instruction.changesFP, changesFP)
        }
    }

    func testUC02RegisterFieldSweep() throws {
        for rd in 0...31 {
            let rn = (rd * 7 + 3) % 32
            let instruction = try XCTUnwrap(decode([word(rd: rd, rn: rn)]).first)
            XCTAssertEqual(instruction.kind, String("xrbit"))
            XCTAssertEqual(instruction.rd, rd)
            XCTAssertEqual(instruction.rn, rn)
            XCTAssertEqual(instruction.rt2, Int(0))
        }
    }

    func testUC03RefusalsAndUnreachableNeighbor() throws {
        let refused: [UInt32] = [0xfac00020, 0x9ac00020, 0xdac10020, 0xdac01820,
            0xdac02020, 0xdac01020, 0xdac01100, 0x5ac01020, 0xfac00408,
            0xfac00808, 0x5ac00c08, 0xfac01408, 0x3ac10c00]
        for encoded in refused {
            assertCode("unsupported_instruction") { try decode([encoded]) }
        }
        XCTAssertThrowsError(try decode([0x14000002, 0xfac01408, 0xdac00020,
                                        0xd503201f, 0xd65f03c0])) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, String("unsupported_instruction"))
            XCTAssertEqual((error as? UnwindAuditModelError)?.address, UInt64(0x1004))
        }
    }

    func testUC04ControlBitFlips() throws {
        for bit in 10...31 {
            do {
                let decoded = try decode([UInt32(0xdac00020) ^ (UInt32(1) << bit)])
                XCTAssertNotEqual(decoded.first?.kind, "xrbit")
            } catch is UnwindAuditModelError {
                // A neighboring encoding may be refused instead of modeled.
            }
        }
        let accepted: [(UInt32, String)] = [
            (0x5ac00020, "wrbit"), (0xdac00420, "xrev16"), (0xdac00820, "xrev32")
        ]
        for (encoded, kind) in accepted {
            XCTAssertEqual(try XCTUnwrap(decode([encoded]).first).kind, kind)
        }
        for encoded in [UInt32(0xdac01020), 0xfac00020, 0x9ac00020] {
            assertCode("unsupported_instruction") { try decode([encoded]) }
        }
    }

    func testUC05LiteralValues() throws {
        let vectors: [(UInt64, UInt64)] = [
            (0x0000000000000000, 0x0000000000000000),
            (0x0000000000000001, 0x8000000000000000),
            (0x8000000000000000, 0x0000000000000001),
            (0xffffffffffffffff, 0xffffffffffffffff),
            (0x00000000ffffffff, 0xffffffff00000000),
            (0x0000000000000080, 0x0100000000000000),
            (0x0123456789abcdef, 0xf7b3d591e6a2c480),
            (0x0000000100000000, 0x0000000080000000),
            (0xffffffff00000000, 0x00000000ffffffff),
            (0x8000000000000001, 0x8000000000000001),
            (0xaaaaaaaaaaaaaaaa, 0x5555555555555555),
            (0x5555555555555555, 0xaaaaaaaaaaaaaaaa),
            (0xffffffffffffedcb, 0xd3b7ffffffffffff),
            (0x13579bdf2468ace0, 0x07351624fbd9eac8),
            (0x123456789abcdef0, 0x0f7b3d591e6a2c48)
        ]
        let instruction = try XCTUnwrap(decode([0xdac00020]).first)
        for (source, expected) in vectors {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(source)
            try state.apply(instruction)
            XCTAssertEqual(state.registers[0], UnwindAuditValue.constant(expected))
            if source == UInt64(0x0123456789abcdef) {
                XCTAssertNotEqual(state.registers[0], UnwindAuditValue.constant(0xefcdab8967452301))
            }
        }
    }

    func testUC06EverySingleBitMirrors() throws {
        let vectors: [(UInt64, UInt64)] = [
            (0x0000000000000001, 0x8000000000000000),
            (0x0000000000000002, 0x4000000000000000),
            (0x0000000000000004, 0x2000000000000000),
            (0x0000000000000008, 0x1000000000000000),
            (0x0000000000000010, 0x0800000000000000),
            (0x0000000000000020, 0x0400000000000000),
            (0x0000000000000040, 0x0200000000000000),
            (0x0000000000000080, 0x0100000000000000),
            (0x0000000000000100, 0x0080000000000000),
            (0x0000000000000200, 0x0040000000000000),
            (0x0000000000000400, 0x0020000000000000),
            (0x0000000000000800, 0x0010000000000000),
            (0x0000000000001000, 0x0008000000000000),
            (0x0000000000002000, 0x0004000000000000),
            (0x0000000000004000, 0x0002000000000000),
            (0x0000000000008000, 0x0001000000000000),
            (0x0000000000010000, 0x0000800000000000),
            (0x0000000000020000, 0x0000400000000000),
            (0x0000000000040000, 0x0000200000000000),
            (0x0000000000080000, 0x0000100000000000),
            (0x0000000000100000, 0x0000080000000000),
            (0x0000000000200000, 0x0000040000000000),
            (0x0000000000400000, 0x0000020000000000),
            (0x0000000000800000, 0x0000010000000000),
            (0x0000000001000000, 0x0000008000000000),
            (0x0000000002000000, 0x0000004000000000),
            (0x0000000004000000, 0x0000002000000000),
            (0x0000000008000000, 0x0000001000000000),
            (0x0000000010000000, 0x0000000800000000),
            (0x0000000020000000, 0x0000000400000000),
            (0x0000000040000000, 0x0000000200000000),
            (0x0000000080000000, 0x0000000100000000),
            (0x0000000100000000, 0x0000000080000000),
            (0x0000000200000000, 0x0000000040000000),
            (0x0000000400000000, 0x0000000020000000),
            (0x0000000800000000, 0x0000000010000000),
            (0x0000001000000000, 0x0000000008000000),
            (0x0000002000000000, 0x0000000004000000),
            (0x0000004000000000, 0x0000000002000000),
            (0x0000008000000000, 0x0000000001000000),
            (0x0000010000000000, 0x0000000000800000),
            (0x0000020000000000, 0x0000000000400000),
            (0x0000040000000000, 0x0000000000200000),
            (0x0000080000000000, 0x0000000000100000),
            (0x0000100000000000, 0x0000000000080000),
            (0x0000200000000000, 0x0000000000040000),
            (0x0000400000000000, 0x0000000000020000),
            (0x0000800000000000, 0x0000000000010000),
            (0x0001000000000000, 0x0000000000008000),
            (0x0002000000000000, 0x0000000000004000),
            (0x0004000000000000, 0x0000000000002000),
            (0x0008000000000000, 0x0000000000001000),
            (0x0010000000000000, 0x0000000000000800),
            (0x0020000000000000, 0x0000000000000400),
            (0x0040000000000000, 0x0000000000000200),
            (0x0080000000000000, 0x0000000000000100),
            (0x0100000000000000, 0x0000000000000080),
            (0x0200000000000000, 0x0000000000000040),
            (0x0400000000000000, 0x0000000000000020),
            (0x0800000000000000, 0x0000000000000010),
            (0x1000000000000000, 0x0000000000000008),
            (0x2000000000000000, 0x0000000000000004),
            (0x4000000000000000, 0x0000000000000002),
            (0x8000000000000000, 0x0000000000000001)
        ]
        XCTAssertEqual(vectors.count, Int(64))
        let instruction = try XCTUnwrap(decode([0xdac00020]).first)
        for (source, expected) in vectors {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(source)
            try state.apply(instruction)
            XCTAssertEqual(state.registers[0], UnwindAuditValue.constant(expected))
        }
    }

    func testUC07AliasedDestination() throws {
        let vectors: [(UInt32, Int, UInt64, UInt64)] = [
            (0xdac00000, 0, 0x0123456789abcdef, 0xf7b3d591e6a2c480),
            (0xdac00021, 1, 0x0000000000000001, 0x8000000000000000),
            (0xdac00021, 1, 0x8000000000000000, 0x0000000000000001)
        ]
        for (encoded, register, source, expected) in vectors {
            var state = UnwindAuditMachine()
            state.registers[register] = .constant(source)
            try state.apply(XCTUnwrap(decode([encoded]).first))
            XCTAssertEqual(state.registers[register], UnwindAuditValue.constant(expected))
        }
    }

    func testUC08ZeroRegisterAndDiscard() throws {
        var state = UnwindAuditMachine()
        state.registers[0] = .unknown("preset")
        state.sp = .stack(displacement: -16)
        try state.apply(XCTUnwrap(decode([0xdac003e0]).first))
        XCTAssertEqual(state.registers[0], UnwindAuditValue.constant(0))
        XCTAssertEqual(state.sp, UnwindAuditValue.stack(displacement: -16))
        for encoded in [UInt32(0xdac0003f), 0xdac003ff] {
            var discard = UnwindAuditMachine()
            discard.registers[1] = .constant(1)
            discard.flags = UnwindAuditNZCV(n: true, z: false, c: true, v: false)
            discard.memory[-16] = .constant(0x55)
            discard.sp = .stack(displacement: -32)
            let before = discard.snapshot(certain: true, priorCallCount: 0)
            try discard.apply(XCTUnwrap(decode([encoded]).first))
            XCTAssertEqual(discard.snapshot(certain: true, priorCallCount: 0), before)
        }
    }

    func testUC09RawStackAddressRefusal() throws {
        for strict in [false, true] {
            for encoded in [UInt32(0xdac00020), 0xdac0003f] {
                var state = UnwindAuditMachine(strictCallState: strict)
                state.registers[1] = .stack(displacement: -16)
                let before = state.snapshot(certain: true, priorCallCount: 0)
                let instruction = try XCTUnwrap(decode([encoded]).first)
                assertCode("rbit_stack_address_not_modeled") { try state.apply(instruction) }
                XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
            }
        }
        assertCode("rbit_stack_address_not_modeled") {
            try run(frame(0xd503201f, 0xd503201f, 0xdac003b3), mode: "frame", callees: [0x2000])
        }
    }

    func testUC10UnknownStaysUnknown() throws {
        let sources: [UnwindAuditValue] = [.original(register: 1, displacement: 0),
            .unknown("test"), .original(register: 5, displacement: 8)]
        for strict in [false, true] {
            for source in sources {
                var state = UnwindAuditMachine(strictCallState: strict)
                state.registers[1] = source
                try state.apply(XCTUnwrap(decode([0xdac00020]).first))
                XCTAssertFalse(state.registers[0].known)
                XCTAssertNotEqual(state.registers[0], UnwindAuditValue.original(register: 0, displacement: 0))
            }
            var aliased = UnwindAuditMachine(strictCallState: strict)
            try aliased.apply(XCTUnwrap(decode([0xdac00000]).first))
            XCTAssertFalse(aliased.registers[0].known)
            XCTAssertNotEqual(aliased.registers[0], UnwindAuditValue.original(register: 0, displacement: 0))
        }
    }

    func testUC11StatePreserved() throws {
        let presets: [UnwindAuditNZCV?] = [nil,
            .init(n: false, z: true, c: true, v: false),
            .init(n: true, z: false, c: false, v: true)]
        for preset in presets {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(1)
            state.flags = preset
            state.sp = .stack(displacement: -16)
            state.memory = [-16: .original(register: 29, displacement: 0),
                            -8: .original(register: 30, displacement: 0)]
            state.words = [-16: .constant(7)]
            let before = state
            let conditionBefore: Bool? = try state.condition(0)
            try state.apply(XCTUnwrap(decode([0xdac00020]).first))
            XCTAssertEqual(state.registers[0], UnwindAuditValue.constant(0x8000000000000000))
            for register in 1...30 { XCTAssertEqual(state.registers[register], before.registers[register]) }
            XCTAssertEqual(state.flags, preset)
            XCTAssertEqual(state.sp, before.sp)
            XCTAssertEqual(state.memory, before.memory)
            XCTAssertEqual(state.words, before.words)
            if preset != nil { XCTAssertEqual(try state.condition(0), conditionBefore) }
        }
    }

    func testUC12ModelIdentityAndFlags() throws {
        let models: [(UnwindAuditModel, String, [Bool])] = [
            (.boundedLoops, "arm64-bounded-loops-cfa-register-v1", [false, false, false, false, false, false]),
            (.boundedLoopCalls, "arm64-bounded-loop-calls-cfa-register-v2", [true, false, false, false, false, false]),
            (.boundedLoopCallsMOVK, "arm64-bounded-loop-calls-movk-cfa-register-v3", [true, true, false, false, false, false]),
            (.boundedCFIControls, "arm64-bounded-cfi-controls-v4", [false, false, true, false, false, false]),
            (.boundedOneSource, "arm64-bounded-one-source-v5", [false, false, false, true, false, false]),
            (.boundedOneSourceDivide, "arm64-bounded-one-source-v6", [false, false, false, true, true, false]),
            (.boundedOneSourceRBitX, "arm64-bounded-one-source-v7", [false, false, false, true, true, true])
        ]
        XCTAssertEqual(Set(models.map { $0.0.rawValue }).count, Int(7))
        for (model, identity, flags) in models {
            XCTAssertEqual(model.rawValue, identity)
            XCTAssertEqual([model.permitsLoopCalls, model.permitsMOVK, model.permitsCFIControls,
                            model.permitsOneSource, model.permitsDivide, model.permitsRBitX], flags)
        }
        XCTAssertEqual(UnwindAuditModel(rawValue: "arm64-bounded-one-source-v7"),
                       UnwindAuditModel.boundedOneSourceRBitX)
    }

    func testUC13DecodeAndExecutionGating() throws {
        let earlier: [UnwindAuditModel] = [.boundedLoops, .boundedLoopCalls,
            .boundedLoopCallsMOVK, .boundedCFIControls, .boundedOneSource, .boundedOneSourceDivide]
        for model in earlier {
            assertCode("unsupported_instruction") { try decode([0xdac000a4], model: model) }
        }
        assertCode("unsupported_instruction") {
            try UnwindAuditInstruction.decode(data: Data([0xa4, 0x00, 0xc0, 0xda]),
                                              start: 0x1000, maximum: 1)
        }
        let admitted: [(UInt32, String)] = [(0x5ac000a4, "wrbit"), (0x5ac008a4, "wrev"),
            (0xdac014a4, "xcls"), (0x1ac608a4, "wudiv"), (0x9ac60ca4, "xsdiv")]
        for (encoded, kind) in admitted {
            XCTAssertEqual(try XCTUnwrap(decode([encoded]).first).kind, kind)
        }
        for encoded in [UInt32(0xf297dde0), 0x7297dde0, 0x5ac010a4, 0xdac010a4] {
            assertCode("unsupported_instruction") { try decode([encoded]) }
        }
        let instructions = try decode([0xdac00020, 0xd503201f, 0xd65f03c0])
        for model in earlier {
            XCTAssertThrowsError(try UnwindAuditExecution.run(instructions: instructions,
                mode: "frameless", calleeEntries: [], limits: .init(), model: model) { state, _ in
                    ["x0": state.registers[0]]
                }) { error in
                    XCTAssertEqual((error as? UnwindAuditModelError)?.code, String("unsupported_instruction"))
                    XCTAssertEqual((error as? UnwindAuditModelError)?.address, UInt64(0x1000))
                }
        }
        XCTAssertNoThrow(try UnwindAuditExecution.run(instructions: instructions,
            mode: "frameless", calleeEntries: [], limits: .init(), model: .boundedOneSourceRBitX) { state, _ in
                ["x0": state.registers[0]]
            })
        let division = try decode([0x1ac20820, 0xd503201f, 0xd65f03c0])
        for model in [UnwindAuditModel.boundedOneSourceDivide, .boundedOneSourceRBitX] {
            XCTAssertNoThrow(try UnwindAuditExecution.run(instructions: division,
                mode: "frameless", calleeEntries: [], limits: .init(), model: model) { state, _ in
                    ["x0": state.registers[0]]
                })
        }
    }

    func testUC14InteractiveRouting() throws {
        let cases: [(UnwindAuditModel, Bool)] = [(.boundedLoops, true),
            (.boundedLoopCalls, false), (.boundedLoopCallsMOVK, false),
            (.boundedCFIControls, true), (.boundedOneSource, true),
            (.boundedOneSourceDivide, true), (.boundedOneSourceRBitX, true)]
        for (model, expected) in cases {
            XCTAssertEqual(UnwindAuditResultKey.supportsInteractive(model), expected)
        }
        XCTAssertEqual(try key(modelID: UnwindAuditModel.boundedOneSourceRBitX.rawValue).model,
                       UnwindAuditModel.boundedOneSourceRBitX)
        XCTAssertNil(try key(modelID: "unknown-model").model)
    }

    func testUC15LeafAgreementAndWorkLimits() throws {
        let vectors: [(UInt32, UInt64)] = [(0x92824681, 0xd3b7ffffffffffff),
            (0xd2800021, 0x8000000000000000), (0xd2801001, 0x0100000000000000),
            (0x92800001, 0xffffffffffffffff)]
        let pcs: [UInt64] = [0x1000, 0x1004, 0x1008, 0x100c]
        for (setup, expected) in vectors {
            let result = try run(leaf(setup, 0xd503201f, 0xdac00020))
            XCTAssertEqual(result.observations.map(\.pc), pcs)
            XCTAssertEqual(result.scope, String("modeled_leaf_body"))
            let after = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x100c) })
            XCTAssertEqual(after.recovered["x0"], UnwindAuditValue.constant(expected))
            let before = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x1008) })
            XCTAssertEqual(before.recovered["x0"], UnwindAuditValue.original(register: 0, displacement: 0))
        }
        let words = leaf(0xd2800021, 0xd503201f, 0xdac00020)
        var limits = UnwindAuditLimits()
        limits.maxSteps = 2
        assertCode("cfg_work_limit") { try run(words, limits: limits) }
        limits = .init(); limits.maxObservations = 1
        assertCode("observation_limit") { try run(words, limits: limits) }
        limits = .init(); limits.maxInstructions = 2
        assertCode("function_instruction_limit") { try run(words, limits: limits) }
        limits = .init(); limits.maxPaths = 0
        assertCode("cfg_path_limit") { try run(words, limits: limits) }
    }

    func testUC16FrameAndCalleeSavedWriteRefusals() throws {
        assertCode("cfg_frame_transition_not_modeled") {
            try run(frame(0x92824681, 0xd503201f, 0xdac0003d), mode: "frame", callees: [0x2000])
        }
        assertCode("unmodeled_return_state") {
            try run(frame(0x92824681, 0xd503201f, 0xdac00035), mode: "frame", callees: [0x2000])
        }
        for setup in [UInt32(0x92824681), 0xd503201f] {
            assertCode("unmodeled_return_state") {
                try run(leaf(setup, 0xd503201f, 0xdac00033))
            }
        }
    }

    func testUC17CallSiteValueWitness() throws {
        let vectors: [(UInt32, UInt64)] = [(0x92824681, 0xd3b7ffffffffffff),
            (0xd2800021, 0x8000000000000000), (0xd2801001, 0x0100000000000000),
            (0xd2800c81, 0x2600000000000000), (0x928000c1, 0x9fffffffffffffff)]
        for (setup, expected) in vectors {
            let result = try run(frame(setup, 0xd503201f, 0xdac00033), mode: "frame", callees: [0x2000])
            XCTAssertEqual(result.observations.count, Int(1))
            let observation = try XCTUnwrap(result.observations.first)
            XCTAssertEqual(observation.pc, UInt64(0x1018))
            XCTAssertEqual(observation.recovered["x19"], UnwindAuditValue.constant(expected))
        }
    }

    func testUC18UnknownCallSiteValue() throws {
        for operation in [UInt32(0xdac00033), 0xdac00273] {
            let result = try run(frame(0xd503201f, 0xd503201f, operation), mode: "frame", callees: [0x2000])
            XCTAssertEqual(result.observations.count, Int(1))
            let observation = try XCTUnwrap(result.observations.first)
            XCTAssertEqual(observation.pc, UInt64(0x1018))
            XCTAssertFalse(try XCTUnwrap(observation.recovered["x19"]).known)
        }
    }

    func testUC19PossibleOnlyFork() throws {
        let words: [UInt32] = [0xa9be7bfd, 0xa90153f3, 0x910003fd, 0x54000080,
            0xd2800021, 0xd503201f, 0xdac00033, 0x940003f9,
            0xa94153f3, 0xa8c27bfd, 0xd65f03c0]
        let result = try run(words, mode: "frame", callees: [0x2000])
        XCTAssertEqual(result.observations.count, Int(2))
        for observation in result.observations {
            XCTAssertEqual(observation.pc, UInt64(0x101c))
            XCTAssertFalse(observation.certain)
        }
        let recovered = try result.observations.map { try XCTUnwrap($0.recovered["x19"]) }
        let expected: Set<UnwindAuditValue> = [.original(register: 19, displacement: 0),
                                              .constant(0x8000000000000000)]
        XCTAssertEqual(Set(recovered), expected)
    }

    func testUC20ReportAndComparator() throws {
        let key = try key(modelID: UnwindAuditModel.boundedOneSourceRBitX.rawValue)
        let original = report(key)
        XCTAssertNoThrow(try original.validate())
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self,
            from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.analysisModelVersion, String("arm64-bounded-one-source-v7"))
        let finding = UnwindAuditFinding(identity: key.identity,
            function: .init(id: "owned", address: 0x1000, symbolName: "_owned", size: 4),
            endAddress: 0x1004, verdict: "unresolved", coverage: "dwarf_reference",
            mode: "dwarf", scope: "metadata_only")
        let historical = UnwindAuditReport(identity: key.identity, findings: [finding])
        var v6 = historical
        v6.analysisModelVersion = UnwindAuditModel.boundedOneSourceDivide.rawValue
        var v7 = historical
        v7.analysisModelVersion = UnwindAuditModel.boundedOneSourceRBitX.rawValue
        for baseline in [historical, v6] {
            let comparison = try UnwindAuditComparator.compare(baseline: baseline, current: v7)
            XCTAssertFalse(comparison.modelCompatible)
            XCTAssertEqual(comparison.changes.map(\.change), [UnwindAuditChangeKind.incompatible])
        }
    }
}
