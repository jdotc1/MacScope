import Foundation
import XCTest
@testable import MacScope

final class UnwindAuditXStackTests: XCTestCase {
    private let earlierModels: [UnwindAuditModel] = [
        .boundedLoops, .boundedLoopCalls, .boundedLoopCallsMOVK, .boundedCFIControls,
        .boundedOneSource, .boundedOneSourceDivide, .boundedOneSourceRBitX
    ]

    private func decode(_ words: [UInt32],
                        model: UnwindAuditModel = .boundedXStack) throws -> [UnwindAuditInstruction] {
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

    private func assertAddress<T>(_ code: String, _ address: UInt64,
                                  file: StaticString = #filePath, line: UInt = #line,
                                  _ operation: () throws -> T) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, code, file: file, line: line)
            XCTAssertEqual((error as? UnwindAuditModelError)?.address, address, file: file, line: line)
        }
    }

    private func xmem(_ load: Bool, rt: Int, rn: Int, offset: Int) -> UInt32 {
        (load ? 0xf9400000 : 0xf9000000) | UInt32(offset / 8) << 10 | UInt32(rn) << 5 | UInt32(rt)
    }

    private func apply(_ word: UInt32, to state: inout UnwindAuditMachine) throws {
        try state.apply(XCTUnwrap(decode([word]).first))
    }

    private func run(_ words: [UInt32], mode: String = "frameless", callees: Set<UInt64> = [],
                     limits: UnwindAuditLimits = .init(), model: UnwindAuditModel = .boundedXStack,
                     recover: (UnwindAuditMachine, UInt64) throws -> [String: UnwindAuditValue]
    ) throws -> UnwindAuditExecutionResult {
        let bytes = Data(words.flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) } })
        let instructions = try UnwindAuditInstruction.decode(data: bytes, start: 0x1000,
            maximum: limits.maxInstructions, model: model)
        return try UnwindAuditExecution.run(instructions: instructions, mode: mode,
            calleeEntries: callees, limits: limits, model: model, recover: recover)
    }

    private func assertFailure(_ code: String, file: StaticString = #filePath, line: UInt = #line,
                               _ body: () throws -> UnwindAuditExecutionResult) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, code, file: file, line: line)
        }
    }

    private func leaf(_ b1: UInt32, _ b2: UInt32, _ b3: UInt32) -> [UInt32] {
        [0xd10043ff, b1, b2, b3, 0xd503201f, 0x910043ff, 0xd65f03c0]
    }

    private func frame(_ b1: UInt32, _ b2: UInt32, _ b3: UInt32, _ b4: UInt32) -> [UInt32] {
        [0xa9bd7bfd, 0xa90153f3, 0x910003fd, b1, b2, b3, b4,
         0x940003f9, 0xa94153f3, 0xa8c37bfd, 0xd65f03c0]
    }

    private func runFrame(_ words: [UInt32]) throws -> UnwindAuditExecutionResult {
        try run(words, mode: "frame", callees: [0x2000]) { state, _ in ["x19": state.registers[19]] }
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
        let vectors: [(UInt32, String, Int, Int, Int64, Bool)] = [
            (0xf90003e0, "xstr", 0, 31, 0, false),
            (0xf97ffffe, "xldr", 30, 31, 32760, false),
            (0xf90007fd, "xstr", 29, 31, 8, false),
            (0xf94007fd, "xldr", 29, 31, 8, true),
            (0xf9000ba0, "xstr", 0, 29, 16, false),
            (0xf9400ba0, "xldr", 0, 29, 16, false),
            (0xf90003ff, "xstr", 31, 31, 0, false),
            (0xf94003ff, "xldr", 31, 31, 0, false)
        ]
        for (word, kind, rd, rn, immediate, changesFP) in vectors {
            let ins = try XCTUnwrap(decode([word]).first)
            XCTAssertEqual(ins.kind, kind)
            XCTAssertEqual(ins.rd, rd)
            XCTAssertEqual(ins.rn, rn)
            XCTAssertEqual(ins.rt2, Int(0))
            XCTAssertEqual(ins.immediate, immediate)
            XCTAssertEqual(ins.addressing, String(""))
            XCTAssertEqual(ins.word, word)
            XCTAssertEqual(ins.address, UInt64(0x1000))
            XCTAssertFalse(ins.changesSP)
            XCTAssertEqual(ins.changesFP, changesFP)
        }
    }

    func testUC02RegisterAndBaseSweep() throws {
        for rt in 0...31 {
            let rn = rt % 2 == 0 ? 31 : 29
            for load in [false, true] {
                let ins = try XCTUnwrap(decode([xmem(load, rt: rt, rn: rn, offset: 8 * rt)]).first)
                XCTAssertEqual(ins.kind, load ? "xldr" : "xstr")
                XCTAssertEqual(ins.rd, rt)
                XCTAssertEqual(ins.rn, rn)
                XCTAssertEqual(ins.immediate, Int64(8 * rt))
                XCTAssertEqual(ins.rt2, Int(0))
            }
        }
    }

    func testUC03ScaledOffsets() throws {
        for offset: Int in [0, 8, 16, 4088, 32752, 32760] {
            for load in [false, true] {
                let word = xmem(load, rt: 0, rn: 31, offset: offset)
                let ins = try XCTUnwrap(decode([word]).first)
                XCTAssertEqual(ins.immediate, Int64(offset))
                XCTAssertEqual((word >> 10) & 0xfff, UInt32(offset / 8))
            }
        }
    }

    func testUC04DecodeRefusals() throws {
        for rn in [0, 28, 30] {
            for load in [false, true] {
                assertCode("cfg_memory_base_not_modeled") { try decode([xmem(load, rt: 0, rn: rn, offset: 0)]) }
            }
        }
        for word: UInt32 in [0xf80003e0, 0xf84003e0, 0xf80087e0, 0xf84087e0, 0xf8206be0,
                             0x390003e0, 0x794003e0, 0xfd0003e0, 0xf98003e0, 0xf9c003e0] {
            assertCode("unsupported_instruction") { try decode([word]) }
        }
        assertAddress("unsupported_instruction", 0x1004) { try decode([0xf90003e0, 0xf80003e0]) }
    }

    func testUC05ControlBitFlips() throws {
        for word: UInt32 in [0xf90003e0, 0xf94003e0] {
            for bit in 23...31 {
                do {
                    let decoded = try decode([word ^ (UInt32(1) << bit)])
                    XCTAssertFalse(decoded.contains { ["xstr", "xldr"].contains($0.kind) })
                } catch is UnwindAuditModelError { }
            }
        }
        XCTAssertEqual(try decode([0xb90003e0]).first?.kind, String("wstr"))
        XCTAssertEqual(try decode([0xb94003e0]).first?.kind, String("wldr"))
        XCTAssertEqual(try decode([0xf90003e0 ^ (UInt32(1) << 22)]).first?.kind, String("xldr"))
    }

    func testUC06DecodeGating() throws {
        for model in earlierModels {
            for word: UInt32 in [0xf90003e0, 0xf94003e0] {
                assertCode("unsupported_instruction") { try decode([word], model: model) }
            }
        }
        for bytes in [Data([0xe0, 0x03, 0x00, 0xf9]), Data([0xe0, 0x03, 0x40, 0xf9])] {
            assertCode("unsupported_instruction") {
                try UnwindAuditInstruction.decode(data: bytes, start: 0x1000, maximum: 1)
            }
        }
        let vectors: [(UInt32, String)] = [
            (0x5ac000a4, "wrbit"), (0x5ac008a4, "wrev"), (0xdac014a4, "xcls"),
            (0x1ac608a4, "wudiv"), (0x9ac60ca4, "xsdiv"), (0xdac000a4, "xrbit"),
            (0xb90003e0, "wstr"), (0xb94003e0, "wldr")
        ]
        for (word, kind) in vectors { XCTAssertEqual(try decode([word]).first?.kind, kind) }
        for word: UInt32 in [0xf297dde0, 0x7297dde0, 0x5ac010a4, 0xdac010a4] {
            assertCode("unsupported_instruction") { try decode([word]) }
        }
    }

    func testUC07ExecutionAdmission() throws {
        let instructions = try decode([0xd10043ff, 0xf90007e1, 0xd503201f, 0x910043ff, 0xd65f03c0])
        for model in earlierModels {
            assertAddress("unsupported_instruction", 0x1004) {
                try UnwindAuditExecution.run(instructions: instructions, mode: "frameless",
                    calleeEntries: [], limits: .init(), model: model) { state, _ in ["x0": state.registers[0]] }
            }
        }
        _ = try UnwindAuditExecution.run(instructions: instructions, mode: "frameless",
            calleeEntries: [], limits: .init(), model: .boundedXStack) { state, _ in ["x0": state.registers[0]] }
        for word: UInt32 in [0xdac00020, 0x1ac20820] {
            _ = try run([word, 0xd503201f, 0xd65f03c0]) { state, _ in ["x0": state.registers[0]] }
        }
    }

    func testUC08ModelIdentityAndFlags() throws {
        let models = earlierModels + [.boundedXStack]
        let raw: [String] = ["arm64-bounded-loops-cfa-register-v1", "arm64-bounded-loop-calls-cfa-register-v2",
            "arm64-bounded-loop-calls-movk-cfa-register-v3", "arm64-bounded-cfi-controls-v4",
            "arm64-bounded-one-source-v5", "arm64-bounded-one-source-v6", "arm64-bounded-one-source-v7",
            "arm64-bounded-x-stack-v8"]
        XCTAssertEqual(models.map(\.rawValue), raw)
        XCTAssertEqual(Set(models.map(\.rawValue)).count, Int(8))
        XCTAssertEqual(UnwindAuditModel(rawValue: "arm64-bounded-x-stack-v8"), .boundedXStack)
        let expected: [[Bool]] = [
            [false, false, false, false, false, false, false],
            [true, false, false, false, false, false, false],
            [true, true, false, false, false, false, false],
            [false, false, true, false, false, false, false],
            [false, false, false, true, false, false, false],
            [false, false, false, true, true, false, false],
            [false, false, false, true, true, true, false],
            [false, false, false, true, true, true, true]
        ]
        for (model, flags) in zip(models, expected) {
            XCTAssertEqual([model.permitsLoopCalls, model.permitsMOVK, model.permitsCFIControls,
                model.permitsOneSource, model.permitsDivide, model.permitsRBitX, model.permitsXStack], flags)
        }
    }

    func testUC09InteractiveRouting() throws {
        for model: UnwindAuditModel in [.boundedXStack, .boundedLoops, .boundedCFIControls,
                                       .boundedOneSource, .boundedOneSourceDivide, .boundedOneSourceRBitX] {
            XCTAssertTrue(UnwindAuditResultKey.supportsInteractive(model))
        }
        for model: UnwindAuditModel in [.boundedLoopCalls, .boundedLoopCallsMOVK] {
            XCTAssertFalse(UnwindAuditResultKey.supportsInteractive(model))
        }
        XCTAssertEqual(try key(modelID: UnwindAuditModel.boundedXStack.rawValue).model, .boundedXStack)
        XCTAssertNil(try key(modelID: "unknown-model").model)
    }

    func testUC10ReportAndComparator() throws {
        let key = try key(modelID: UnwindAuditModel.boundedXStack.rawValue)
        let original = report(key)
        try original.validate()
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.analysisModelVersion, String("arm64-bounded-x-stack-v8"))
        let finding = UnwindAuditFinding(identity: key.identity,
            function: .init(id: "owned", address: 0x1000, symbolName: "_owned", size: 4),
            endAddress: 0x1004, verdict: "unresolved", coverage: "dwarf_reference", mode: "dwarf", scope: "metadata_only")
        let baseline = UnwindAuditReport(identity: key.identity, findings: [finding])
        var current = baseline
        current.analysisModelVersion = UnwindAuditModel.boundedXStack.rawValue
        var v7 = baseline
        v7.analysisModelVersion = UnwindAuditModel.boundedOneSourceRBitX.rawValue
        for before in [baseline, v7] {
            let comparison = try UnwindAuditComparator.compare(baseline: before, current: current)
            XCTAssertFalse(comparison.modelCompatible)
            XCTAssertEqual(comparison.changes.map(\.change), [.incompatible])
        }
    }

    func testUC11StoreLoadRoundTrip() throws {
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -32)
        state.registers[1] = .constant(0x1122334455667788)
        try apply(0xf90007e1, to: &state)
        XCTAssertEqual(state.memory[-24], .constant(0x1122334455667788))
        XCTAssertTrue(state.words.isEmpty)
        try apply(0xf94007e2, to: &state)
        XCTAssertEqual(state.registers[2], .constant(0x1122334455667788))
        for r in [0, 19, 29, 30] {
            for offset in [0, 24] {
                var original = UnwindAuditMachine()
                original.sp = .stack(displacement: -32)
                try apply(xmem(false, rt: r, rn: 31, offset: offset), to: &original)
                try apply(xmem(true, rt: 1, rn: 31, offset: offset), to: &original)
                XCTAssertEqual(original.registers[1], .original(register: r, displacement: 0))
            }
        }
        for strict in [false, true] {
            var pointer = UnwindAuditMachine(strictCallState: strict)
            pointer.sp = .stack(displacement: -32)
            pointer.registers[1] = .stack(displacement: -16)
            try apply(0xf90007e1, to: &pointer)
            try apply(0xf94007e2, to: &pointer)
            XCTAssertEqual(pointer.registers[2], .stack(displacement: -16))
        }
    }

    func testUC12BaseX29() throws {
        for (base, slot): (Int64, Int64) in [(-32, -24), (-24, -16)] {
            var state = UnwindAuditMachine()
            state.sp = .stack(displacement: -32)
            state.registers[29] = .stack(displacement: base)
            state.registers[1] = .constant(0x1122334455667788)
            try apply(0xf90007a1, to: &state)
            XCTAssertEqual(state.memory[slot], .constant(0x1122334455667788))
            try apply(0xf94007a2, to: &state)
            XCTAssertEqual(state.registers[2], .constant(0x1122334455667788))
        }
        let invalid: [(UnwindAuditValue, String)] = [
            (.stack(displacement: -48), "memory_outside_modeled_frame"),
            (.stack(displacement: 0), "memory_outside_modeled_frame"),
            (.stack(displacement: -36), "memory_outside_modeled_frame"),
            (.original(register: 29, displacement: 0), "unknown_memory_address"),
            (.unknown("test"), "unknown_memory_address"), (.constant(0x1000), "unknown_memory_address")
        ]
        for (base, code) in invalid {
            for word: UInt32 in [0xf90007a1, 0xf9400ba0] {
                var state = UnwindAuditMachine()
                state.sp = .stack(displacement: -32)
                state.registers[29] = base
                let before = state.snapshot(certain: true, priorCallCount: 0)
                assertAddress(code, 0x1000) { try apply(word, to: &state) }
                XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
            }
        }
        var state = UnwindAuditMachine()
        state.sp = .unknown("test")
        let before = state.snapshot(certain: true, priorCallCount: 0)
        assertAddress("unknown_memory_address", 0x1000) { try apply(0xf90003e0, to: &state) }
        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
    }

    func testUC13Bounds() throws {
        let vectors: [(UnwindAuditValue, Int, String)] = [
            (.stack(displacement: 0), 0, "memory_outside_modeled_frame"),
            (.stack(displacement: -16), 16, "memory_outside_modeled_frame"),
            (.stack(displacement: -16), 32760, "memory_outside_modeled_frame"),
            (.unknown("test"), 0, "unknown_memory_address"),
            (.stack(displacement: -15), 0, "memory_outside_modeled_frame")
        ]
        for load in [false, true] {
            for (sp, offset, code) in vectors {
                var state = UnwindAuditMachine()
                state.sp = sp
                let before = state.snapshot(certain: true, priorCallCount: 0)
                assertAddress(code, 0x1000) { try apply(xmem(load, rt: 0, rn: 31, offset: offset), to: &state) }
                XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
            }
        }
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -16)
        try apply(0xf90007e0, to: &state)
        XCTAssertEqual(state.memory[-8], .original(register: 0, displacement: 0))
    }

    func testUC14ZeroRegister() throws {
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -16)
        let empty = state.snapshot(certain: true, priorCallCount: 0)
        assertAddress("unknown_stack_read", 0x1000) { try apply(0xf94003ff, to: &state) }
        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), empty)
        try apply(0xf90003ff, to: &state)
        XCTAssertEqual(state.memory[-16], .constant(0))
        let before = state.snapshot(certain: true, priorCallCount: 0)
        try apply(0xf94003ff, to: &state)
        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
        state.memory[-16] = .unknown("preset")
        let unknown = state.snapshot(certain: true, priorCallCount: 0)
        assertAddress("unknown_stack_read", 0x1000) { try apply(0xf94003ff, to: &state) }
        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), unknown)
    }

    func testUC15XOverwriteAndWordCache() throws {
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -32)
        state.registers[0] = .constant(0xdeadbeef)
        for word: UInt32 in [0xb90003e0, 0xb90007e0, 0xb9000be0] { try apply(word, to: &state) }
        state.registers[0] = .constant(0x1122334455667788)
        try apply(0xf90003e0, to: &state)
        let expectedWords: [Int64: UnwindAuditValue] = [-24: .constant(0xdeadbeef)]
        XCTAssertEqual(state.words, expectedWords)
        XCTAssertEqual(state.memory[-32], .constant(0x1122334455667788))
        let vectors: [(UInt32, UInt64)] = [(0xb94003e1, 0x55667788), (0xb94007e1, 0x11223344), (0xb9400be1, 0xdeadbeef)]
        for (word, expected) in vectors {
            try apply(word, to: &state)
            XCTAssertEqual(state.registers[1], .constant(expected))
        }
    }

    func testUC16WHalvesInvalidateXIdentity() throws {
        var saved = UnwindAuditMachine()
        saved.sp = .stack(displacement: -32)
        try apply(0xf90003f3, to: &saved)
        try apply(0xf90007f4, to: &saved)
        for word: UInt32 in [0xb90003e0, 0xb90007e0] {
            var state = saved
            try apply(word, to: &state)
            XCTAssertEqual(state.memory[-32]?.known, Bool(false))
            XCTAssertEqual(state.memory[-24], .original(register: 20, displacement: 0))
            assertCode("unknown_stack_read") { try apply(0xf94003f3, to: &state) }
            assertCode("unknown_stack_read") { try apply(0xa94053f3, to: &state) }
        }
        var state = saved
        try apply(0xb90003f3, to: &state)
        try apply(0xb90007f3, to: &state)
        assertCode("unknown_stack_read") { try apply(0xf94003f3, to: &state) }
    }

    func testUC17PairXInterop() throws {
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -32)
        try apply(0xa90053f3, to: &state)
        try apply(0xf94003e1, to: &state)
        XCTAssertEqual(state.registers[1], .original(register: 19, displacement: 0))
        try apply(0xf94007e2, to: &state)
        XCTAssertEqual(state.registers[2], .original(register: 20, displacement: 0))
        var reverse = UnwindAuditMachine()
        reverse.sp = .stack(displacement: -32)
        try apply(0xf90003f3, to: &reverse)
        try apply(0xf90007f4, to: &reverse)
        try apply(0xa94007e0, to: &reverse)
        XCTAssertEqual(reverse.registers[0], .original(register: 19, displacement: 0))
        XCTAssertEqual(reverse.registers[1], .original(register: 20, displacement: 0))
    }

    func testUC18StrictPointerCell() throws {
        var state = UnwindAuditMachine(strictCallState: true)
        state.sp = .stack(displacement: -32)
        state.registers[0] = .stack(displacement: -16)
        try apply(0xf90003e0, to: &state)
        state.registers[0] = .constant(0)
        assertCode("stack_address_escapes_call") { try apply(0x94000001, to: &state) }
        for word: UInt32 in [0xb90003ff, 0xb90007ff] {
            var copy = state
            let before = copy.snapshot(certain: true, priorCallCount: 0)
            assertCode("partial_stack_address_not_modeled") { try apply(word, to: &copy) }
            XCTAssertEqual(copy.snapshot(certain: true, priorCallCount: 0), before)
        }
        try apply(0xf90003ff, to: &state)
        state.registers[0] = .constant(0)
        try apply(0x94000001, to: &state)
        XCTAssertEqual(state.registers[30], .constant(0x1004))
    }

    func testUC19PointerLoadIdentity() throws {
        var state = UnwindAuditMachine(strictCallState: true)
        state.sp = .stack(displacement: -32)
        state.registers[0] = .stack(displacement: -16)
        try apply(0xf90003e0, to: &state)
        state.registers[0] = .constant(0)
        try apply(0xf94003e1, to: &state)
        XCTAssertEqual(state.registers[1], .stack(displacement: -16))
        assertCode("stack_address_truncation_not_modeled") { try apply(0xb94003ff, to: &state) }
        assertCode("stack_address_escapes_call") { try apply(0x94000001, to: &state) }
    }

    func testUC20DeallocateReallocate() throws {
        var state = UnwindAuditMachine(strictCallState: true)
        state.sp = .stack(displacement: -16)
        state.registers[0] = .stack(displacement: -8)
        try apply(0xf90003e0, to: &state)
        state.registers[0] = .constant(9)
        try apply(0xb9000be0, to: &state)
        try apply(0x910043ff, to: &state)
        try apply(0xd10043ff, to: &state)
        XCTAssertTrue(state.memory.isEmpty)
        XCTAssertTrue(state.words.isEmpty)
        assertCode("unknown_stack_read") { try apply(0xf94003f3, to: &state) }
        assertCode("unknown_stack_read") { try apply(0xb9400be1, to: &state) }
    }

    func testUC21PreserveOtherState() throws {
        let presets: [UnwindAuditNZCV?] = [nil, .init(n: false, z: true, c: true, v: false),
                                         .init(n: true, z: false, c: false, v: true)]
        for preset in presets {
            var state = UnwindAuditMachine()
            state.sp = .stack(displacement: -16)
            state.registers[1] = .constant(5)
            state.flags = preset
            let registers = state.registers
            let sp = state.sp
            let condition = try state.condition(0)
            try apply(0xf90003e1, to: &state)
            XCTAssertEqual(state.registers, registers)
            XCTAssertEqual(state.sp, sp)
            XCTAssertEqual(state.flags, preset)
            let memory = state.memory, words = state.words
            try apply(0xf94003e2, to: &state)
            XCTAssertEqual(state.registers[2], .constant(5))
            for r in 0..<31 where r != 2 { XCTAssertEqual(state.registers[r], registers[r]) }
            XCTAssertEqual(state.sp, sp)
            XCTAssertEqual(state.flags, preset)
            XCTAssertEqual(state.memory, memory)
            XCTAssertEqual(state.words, words)
            XCTAssertEqual(try state.condition(0), condition)
        }
    }

    func testUC22SnapshotDistinctness() throws {
        var state = UnwindAuditMachine()
        state.sp = .stack(displacement: -16)
        state.registers[0] = .constant(1)
        state.memory[-16] = .constant(2)
        let before = state.snapshot(certain: true, priorCallCount: 0)
        try apply(0xf90003e0, to: &state)
        let stored = state.snapshot(certain: true, priorCallCount: 0)
        XCTAssertNotEqual(stored, before)
        try apply(0xf90003e0, to: &state)
        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), stored)
        var copy = state
        try apply(0xf90003ff, to: &copy)
        XCTAssertNotEqual(copy.snapshot(certain: true, priorCallCount: 0), stored)
        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), stored)
    }

    func testUC23LeafAgreementThroughCells() throws {
        let vectors: [(UInt32, UnwindAuditValue)] = [
            (0xd2800021, .constant(1)), (0x92824681, .constant(0xffffffffffffedcb)),
            (0xd2801001, .constant(0x80)), (0xd503201f, .original(register: 1, displacement: 0))
        ]
        for (first, expected) in vectors {
            let result = try run(leaf(first, 0xf90007e1, 0xf94007e0)) { state, _ in ["x0": state.registers[0]] }
            XCTAssertEqual(result.scope, String("modeled_leaf_body"))
            XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1004), 0x1008, 0x100c, 0x1010])
            XCTAssertEqual(result.observations.last?.recovered["x0"], expected)
            XCTAssertEqual(result.observations.prefix(3).map { $0.recovered["x0"] },
                [UnwindAuditValue?](repeating: .original(register: 0, displacement: 0), count: 3))
        }
    }

    func testUC24LeafCalleeSaved() throws {
        let result = try run(leaf(0xf90003f3, 0xd28000d3, 0xf94003f3)) { state, _ in ["x19": state.registers[19]] }
        let expected: [UnwindAuditValue?] = [.original(register: 19, displacement: 0),
            .original(register: 19, displacement: 0), .constant(6), .original(register: 19, displacement: 0)]
        XCTAssertEqual(result.observations.map { $0.recovered["x19"] }, expected)
        assertFailure("unmodeled_return_state") {
            try run(leaf(0xf90003f3, 0xd28000d3, 0xd503201f)) { state, _ in ["x19": state.registers[19]] }
        }
    }

    func testUC25LeafStackValueThroughCell() throws {
        let result = try run(leaf(0x910003e0, 0xf90003e0, 0xf94003e1)) { state, _ in ["x1": state.registers[1]] }
        let observed = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x1010) })
        XCTAssertEqual(observed.recovered["x1"], .stack(displacement: -16))
    }

    func testUC26Limits() throws {
        let words = leaf(0xd2800021, 0xf90007e1, 0xf94007e0)
        var limits = UnwindAuditLimits()
        limits.maxSteps = 2
        assertFailure("cfg_work_limit") { try run(words, limits: limits) { state, _ in ["x0": state.registers[0]] } }
        limits = .init(); limits.maxObservations = 1
        assertFailure("observation_limit") { try run(words, limits: limits) { state, _ in ["x0": state.registers[0]] } }
        limits = .init(); limits.maxInstructions = 2
        assertFailure("function_instruction_limit") { try run(words, limits: limits) { state, _ in ["x0": state.registers[0]] } }
        limits = .init(); limits.maxPaths = 0
        assertFailure("cfg_path_limit") { try run(words, limits: limits) { state, _ in ["x0": state.registers[0]] } }
    }

    func testUC27FrameCallSiteWitnesses() throws {
        let vectors: [(UInt32, UnwindAuditValue)] = [
            (0xf94013f3, .original(register: 19, displacement: 0)), (0xd503201f, .constant(6))
        ]
        for (third, expected) in vectors {
            let result = try runFrame(frame(0xf90013f3, 0xd28000d3, third, 0xd503201f))
            XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x101c)])
            XCTAssertEqual(result.observations.first?.recovered["x19"], expected)
        }
        assertAddress("unknown_stack_read", 0x1014) {
            try runFrame(frame(0xf90013f3, 0xb90023e0, 0xf94013f3, 0xd503201f))
        }
    }

    func testUC28FramePointerRegister() throws {
        for word: UInt32 in [0xf94013bd, 0xf94007fd] {
            assertFailure("cfg_frame_transition_not_modeled") {
                try runFrame(frame(word, 0xd503201f, 0xd503201f, 0xd503201f))
            }
        }
        let result = try runFrame(frame(0xf90013fd, 0xf90013f4, 0xd503201f, 0xd503201f))
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x101c)])
        XCTAssertEqual(result.observations.first?.recovered["x19"], .original(register: 19, displacement: 0))
        assertFailure("stack_address_escapes_call") {
            try runFrame(frame(0xf90013fd, 0xd503201f, 0xd503201f, 0xd503201f))
        }
    }

    func testUC29FramePointerCell() throws {
        assertFailure("stack_address_escapes_call") {
            try runFrame(frame(0x910003e0, 0xf90013e0, 0xd2800000, 0xd503201f))
        }
        assertAddress("partial_stack_address_not_modeled", 0x1018) {
            try runFrame(frame(0x910003e0, 0xf90013e0, 0xd2800000, 0xb90023ff))
        }
        let result = try runFrame(frame(0x910003e0, 0xf90013e0, 0xd2800000, 0xf90013f4))
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x101c)])
        XCTAssertEqual(result.observations.first?.recovered["x19"], .original(register: 19, displacement: 0))
    }

    func testUC30CountedLoopThroughCell() throws {
        let words: [UInt32] = [0xd10043ff, 0xd2800040, 0xf90003e0, 0xf94003e0,
            0xf1000400, 0xf90003e0, 0x54ffffa1, 0x910043ff, 0xd65f03c0]
        let result = try run(words) { state, _ in ["x0": state.registers[0]] }
        XCTAssertEqual(result.scope, String("modeled_leaf_body"))
        XCTAssertEqual(result.loopHeader, UInt64(0x100c))
        XCTAssertEqual(result.loopMemberCount, Int(4))
        XCTAssertEqual(result.loopVisits, Int(2))
        XCTAssertEqual(result.loopClosures, Int(0))
        XCTAssertEqual(result.steps, Int(13))
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1004), 0x1008, 0x100c, 0x1010, 0x1014,
            0x1018, 0x100c, 0x1010, 0x1014, 0x1018])
        let expected: [UnwindAuditValue?] = [.original(register: 0, displacement: 0), .constant(2),
            .constant(2), .constant(2), .constant(1), .constant(1), .constant(1), .constant(1), .constant(0), .constant(0)]
        XCTAssertEqual(result.observations.map { $0.recovered["x0"] }, expected)
        var limits = UnwindAuditLimits(); limits.maxSteps = 12
        assertFailure("cfg_work_limit") { try run(words, limits: limits) { state, _ in ["x0": state.registers[0]] } }
        limits.maxSteps = 13
        _ = try run(words, limits: limits) { state, _ in ["x0": state.registers[0]] }
    }

    func testUC31PossibleOnlyFork() throws {
        let words: [UInt32] = [0xa9bd7bfd, 0xa90153f3, 0x910003fd, 0x54000080, 0xd2800021,
            0xf90013e1, 0xf94013f3, 0x940003f9, 0xa94153f3, 0xa8c37bfd, 0xd65f03c0]
        let result = try runFrame(words)
        XCTAssertEqual(result.observations.count, Int(2))
        for observation in result.observations {
            XCTAssertEqual(observation.pc, UInt64(0x101c))
            XCTAssertFalse(observation.certain)
        }
        let actual = try Set(result.observations.map { try XCTUnwrap($0.recovered["x19"]) })
        let expected: Set<UnwindAuditValue> = [.original(register: 19, displacement: 0), .constant(1)]
        XCTAssertEqual(actual, expected)
    }

    func testUC32UnoptimizedDivisionSpillShape() throws {
        let words: [UInt32] = [0xd10043ff, 0xf90007e0, 0xf90003e1, 0xf94007e8,
            0xf94003e9, 0x9ac90900, 0x910043ff, 0xd65f03c0]
        let result = try run(words) { state, _ in
            ["x0": state.registers[0], "x8": state.registers[8], "x9": state.registers[9]]
        }
        XCTAssertEqual(result.scope, String("modeled_leaf_body"))
        XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1004), 0x1008, 0x100c, 0x1010, 0x1014])
        XCTAssertEqual(result.observations.last?.recovered["x8"], .original(register: 0, displacement: 0))
        XCTAssertEqual(result.observations.last?.recovered["x9"], .original(register: 1, displacement: 0))
    }
}
