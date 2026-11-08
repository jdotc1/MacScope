import Foundation
import XCTest
@testable import MacScope

final class UnwindAuditDataProcessing1SourceTests: XCTestCase {
    private let kinds: [String] = [
        "wcls", "xcls", "wrev", "xrev", "wrev16", "xrev16", "xrev32", "wrbit"
    ]
    private let bases: [UInt32] = [
        0x5ac01400, 0xdac01400, 0x5ac00800, 0xdac00c00,
        0x5ac00400, 0xdac00400, 0xdac00800, 0x5ac00000
    ]
    private let wordsA: [UInt32] = [
        0x5ac014a4, 0xdac014a4, 0x5ac008a4, 0xdac00ca4,
        0x5ac004a4, 0xdac004a4, 0xdac008a4, 0x5ac000a4
    ]
    private let wordsB: [UInt32] = [
        0x5ac01420, 0xdac01420, 0x5ac00820, 0xdac00c20,
        0x5ac00420, 0xdac00420, 0xdac00820, 0x5ac00020
    ]
    private let wordsC: [UInt32] = [
        0x5ac0143f, 0xdac0143f, 0x5ac0083f, 0xdac00c3f,
        0x5ac0043f, 0xdac0043f, 0xdac0083f, 0x5ac0003f
    ]
    private let wordsD: [UInt32] = [
        0x5ac017e0, 0xdac017e0, 0x5ac00be0, 0xdac00fe0,
        0x5ac007e0, 0xdac007e0, 0xdac00be0, 0x5ac003e0
    ]
    private let wordsE: [UInt32] = [
        0x5ac01413, 0xdac01413, 0x5ac00813, 0xdac00c13,
        0x5ac00413, 0xdac00413, 0xdac00813, 0x5ac00013
    ]
    private let wordsG: [UInt32] = [
        0x5ac017b3, 0xdac017b3, 0x5ac00bb3, 0xdac00fb3,
        0x5ac007b3, 0xdac007b3, 0xdac00bb3, 0x5ac003b3
    ]
    private let wordsH: [UInt32] = [
        0x5ac0141d, 0xdac0141d, 0x5ac0081d, 0xdac00c1d,
        0x5ac0041d, 0xdac0041d, 0xdac0081d, 0x5ac0001d
    ]
    private let wordsJ: [UInt32] = [
        0x5ac01415, 0xdac01415, 0x5ac00815, 0xdac00c15,
        0x5ac00415, 0xdac00415, 0xdac00815, 0x5ac00015
    ]
    private let historicalModels: [UnwindAuditModel] = [
        .boundedLoops, .boundedLoopCalls, .boundedLoopCallsMOVK, .boundedCFIControls
    ]

    private func decode(_ words: [UInt32],
                        model: UnwindAuditModel = .boundedOneSource) throws -> [UnwindAuditInstruction] {
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

    private func assertValues(_ word: UInt32, _ vectors: [(UInt64, UnwindAuditValue)],
                              file: StaticString = #filePath, line: UInt = #line) throws {
        let instruction = try XCTUnwrap(decode([word]).first, file: file, line: line)
        for (input, expected) in vectors {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(input)
            try state.apply(instruction)
            XCTAssertEqual(state.registers[0], expected,
                           "word=\(String(word, radix: 16)), input=\(String(input, radix: 16))",
                           file: file, line: line)
        }
    }

    private func frameWords(_ setup: UInt32, _ operation: UInt32) -> [UInt32] {
        [0xa9be7bfd, 0xa90153f3, 0x910003fd, setup, operation, 0x940003fb,
         0xa94153f3, 0xa8c27bfd, 0xd65f03c0]
    }

    private func frameRecovery(_ state: UnwindAuditMachine) throws -> [String: UnwindAuditValue] {
        var recovered = Dictionary(uniqueKeysWithValues: (19...30).map { ("x\($0)", state.registers[$0]) })
        recovered["SP"] = try state.registers[29].add(16)
        if let slot = state.registers[29].stackDisplacement {
            recovered["x29"] = state.memory[slot]
            recovered["x30"] = state.memory[slot + 8]
        }
        return recovered
    }

    private func run(_ words: [UInt32], mode: String = "frameless", callees: Set<UInt64> = [],
                     limits: UnwindAuditLimits = .init(),
                     model: UnwindAuditModel = .boundedOneSource,
                     recover: ((UnwindAuditMachine, UInt64) throws -> [String: UnwindAuditValue])? = nil
    ) throws -> UnwindAuditExecutionResult {
        let bytes = Data(words.flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) } })
        let instructions = try UnwindAuditInstruction.decode(data: bytes, start: 0x1000,
                                                             maximum: limits.maxInstructions, model: model)
        return try UnwindAuditExecution.run(instructions: instructions, mode: mode,
            calleeEntries: callees, limits: limits, model: model) { state, pc in
            if let recover { return try recover(state, pc) }
            var recovered = Dictionary(uniqueKeysWithValues: (19...30).map { ("x\($0)", state.registers[$0]) })
            recovered["SP"] = state.sp
            return recovered
        }
    }

    private func runFrame(_ setup: UInt32, _ operation: UInt32) throws -> UnwindAuditExecutionResult {
        try run(frameWords(setup, operation), mode: "frame", callees: [0x2000],
                model: .boundedOneSource) { state, _ in ["x19": state.registers[19]] }
    }

    @MainActor
    private func input(modelID: String = UnwindAuditModel.boundedOneSource.rawValue)
        throws -> (LoadedBinary, UnwindAuditResultKey) {
        let identity = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
            rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "a", count: 64),
            selectedSliceByteCount: 64)
        let key = UnwindAuditResultKey(imageID: UUID(), slot: .primary, generation: UUID(),
            identity: identity, modelID: modelID, configuration: .init())
        let binary = LoadedBinary(name: "authored", path: "", isBundle: false,
            cpuType: 0x0100000c, cpuSubtype: 0, fileTypeName: "Mach-O",
            architectureDisplayName: "arm64", metadata: .empty,
            artifactIdentity: identity, artifactIntegrityState: .verified,
            bytes: Data(repeating: 0, count: 64), sliceOffset: 0, sections: [],
            executableTextSection: nil, entryPointAddress: nil, symbols: [], imports: [],
            indirectSymbols: [], exports: [], stringLiterals: [], functionStarts: [], objcSelectors: [:])
        return (binary, key)
    }

    private func report(_ key: UnwindAuditResultKey) -> UnwindAuditReport {
        .init(identity: key.identity, analysisModelVersion: key.modelID,
              configuration: key.configuration, findings: [])
    }

    func testUC01DecodeFields() throws {
        for (index, word) in wordsA.enumerated() {
            let instruction = try XCTUnwrap(decode([word]).first)
            XCTAssertEqual(instruction.kind, kinds[index])
            XCTAssertEqual(instruction.rd, Int(4))
            XCTAssertEqual(instruction.rn, Int(5))
            XCTAssertEqual(instruction.rt2, Int(0))
            XCTAssertEqual(instruction.immediate, Int64(0))
            XCTAssertEqual(instruction.addressing, "")
            XCTAssertEqual(instruction.word, word)
            XCTAssertEqual(instruction.address, UInt64(0x1000))
            XCTAssertFalse(instruction.changesSP)
            XCTAssertFalse(instruction.changesFP)
        }
        for (index, word) in wordsH.enumerated() {
            let instruction = try XCTUnwrap(decode([word]).first)
            XCTAssertEqual(instruction.kind, kinds[index])
            XCTAssertEqual(instruction.rd, Int(29))
            XCTAssertEqual(instruction.rn, Int(0))
            XCTAssertTrue(instruction.changesFP)
            XCTAssertFalse(instruction.changesSP)
        }
        for word in wordsC {
            let instruction = try XCTUnwrap(decode([word]).first)
            XCTAssertEqual(instruction.rd, Int(31))
            XCTAssertEqual(instruction.rn, Int(1))
        }
        for word in wordsD {
            let instruction = try XCTUnwrap(decode([word]).first)
            XCTAssertEqual(instruction.rd, Int(0))
            XCTAssertEqual(instruction.rn, Int(31))
        }
    }

    func testUC02RegisterFieldSweep() throws {
        for (index, base) in bases.enumerated() {
            for rd in 0...31 {
                let rn = (rd * 7 + 3) % 32
                let word = base | (UInt32(rn) << 5) | UInt32(rd)
                let instruction = try XCTUnwrap(decode([word]).first)
                XCTAssertEqual(instruction.kind, kinds[index])
                XCTAssertEqual(instruction.rd, rd)
                XCTAssertEqual(instruction.rn, rn)
            }
        }
    }

    func testUC03ReservedAndOutOfSliceEncodingsRefuse() throws {
        let words: [UInt32] = [
            0x7ac004a4, 0xfac004a4, 0xfac008a4, 0x5ac00ca4,
            0x7ac014a4, 0xfac014a4, 0x5ac018a4, 0xdac018a4,
            0x4e2008a4, 0x5ac010a4, 0xdac010a4, 0xdac000a4
        ]
        for model in historicalModels + [.boundedOneSource] {
            for word in words {
                assertCode("unsupported_instruction") { try decode([word], model: model) }
            }
        }
    }

    func testUC04CLSValues() throws {
        try assertValues(wordsB[0], [
            (0x0000000000000000, .constant(31)),
            (0xffffffffffffffff, .constant(31)),
            (0x0000000000000001, .constant(30)),
            (0xfffffffffffffffe, .constant(30)),
            (0x0000000080000000, .constant(0)),
            (0x000000007fffffff, .constant(0)),
            (0x0000000100000000, .constant(31)),
            (0xffffffffffffedcb, .constant(18)),
            (0x1234567800000001, .constant(30))
        ])
        try assertValues(wordsB[1], [
            (0x0000000000000000, .constant(63)),
            (0xffffffffffffffff, .constant(63)),
            (0x0000000000000001, .constant(62)),
            (0xfffffffffffffffe, .constant(62)),
            (0x8000000000000000, .constant(0)),
            (0x7fffffffffffffff, .constant(0)),
            (0xffffffffffffedcb, .constant(50)),
            (0x0123456789abcdef, .constant(6))
        ])
    }

    func testUC05REVValues() throws {
        try assertValues(wordsB[2], [
            (0x0000000001234567, .constant(0x67452301)),
            (0x1234567889abcdef, .constant(0xefcdab89)),
            (0xfffffffffffffffe, .constant(0xfeffffff)),
            (0x0000000080000000, .constant(0x80)),
            (0, .constant(0))
        ])
        try assertValues(wordsB[3], [
            (0x0123456789abcdef, .constant(0xefcdab8967452301)),
            (0xfffffffffffffffe, .constant(0xfeffffffffffffff)),
            (0x8000000000000000, .constant(0x80)),
            (0xffffffffffffffff, .constant(0xffffffffffffffff))
        ])
    }

    func testUC06REV16Values() throws {
        try assertValues(wordsB[4], [
            (0x0000000001234567, .constant(0x23016745)),
            (0x1234567889abcdef, .constant(0xab89efcd)),
            (0xfffffffffffffffe, .constant(0xfffffeff)),
            (0x0000000080000000, .constant(0x00800000)),
            (0, .constant(0))
        ])
        try assertValues(wordsB[5], [
            (0x0123456789abcdef, .constant(0x23016745ab89efcd)),
            (0xfffffffffffffffe, .constant(0xfffffffffffffeff)),
            (0x8000000000000000, .constant(0x0080000000000000)),
            (0xffffffffffffffff, .constant(0xffffffffffffffff))
        ])
    }

    func testUC07REV32Values() throws {
        try assertValues(wordsB[6], [
            (0x0123456789abcdef, .constant(0x67452301efcdab89)),
            (0x8000000000000000, .constant(0x0000008000000000)),
            (0xfffffffffffffffe, .constant(0xfffffffffeffffff)),
            (0x0000000100000002, .constant(0x0100000002000000)),
            (0x0000000001234567, .constant(0x0000000067452301)),
            (0x0000000080000000, .constant(0x80)),
            (0xffffffffffffedcb, .constant(0xffffffffcbedffff)),
            (0, .constant(0)),
            (0xffffffffffffffff, .constant(0xffffffffffffffff))
        ])
    }

    func testUC08RBITWValues() throws {
        try assertValues(wordsB[7], [
            (0x0000000000000000, .constant(0)),
            (0x0000000000000001, .constant(0x80000000)),
            (0x0000000080000000, .constant(1)),
            (0xffffffffffffffff, .constant(0xffffffff)),
            (0x0000000001234567, .constant(0xe6a2c480)),
            (0x0000000100000000, .constant(0)),
            (0x0000010000000001, .constant(0x80000000)),
            (0xffff000000000001, .constant(0x80000000))
        ])
    }

    func testUC09ZeroRegisterAndPreservedState() throws {
        let expected: [UnwindAuditValue] = [
            .constant(31), .constant(63), .constant(0), .constant(0),
            .constant(0), .constant(0), .constant(0), .constant(0)
        ]
        for (index, word) in wordsD.enumerated() {
            var state = UnwindAuditMachine()
            state.registers[0] = .unknown("preset")
            try state.apply(XCTUnwrap(decode([word]).first))
            XCTAssertEqual(state.registers[0], expected[index])
        }
        let presetFlags = UnwindAuditNZCV(n: true, z: false, c: true, v: false)
        let presetSP = UnwindAuditValue.stack(displacement: -32)
        for word in wordsC {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(5)
            state.flags = presetFlags
            state.memory[-16] = .constant(0x55)
            state.words[-24] = .constant(0x66)
            state.sp = presetSP
            let before = state.snapshot(certain: true, priorCallCount: 0)
            try state.apply(XCTUnwrap(decode([word]).first))
            XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
        }
        for word in wordsB {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(7)
            state.flags = presetFlags
            state.sp = presetSP
            state.memory[-16] = .constant(0x55)
            state.words[-24] = .constant(0x66)
            let memory = state.memory
            let words = state.words
            try state.apply(XCTUnwrap(decode([word]).first))
            XCTAssertEqual(state.flags, presetFlags)
            XCTAssertEqual(state.sp, presetSP)
            XCTAssertEqual(state.memory, memory)
            XCTAssertEqual(state.words, words)
        }
    }

    func testUC10RawStackAddressRefusalIsAtomic() throws {
        let codes: [String] = [
            "cls_stack_address_not_modeled", "cls_stack_address_not_modeled",
            "rev_stack_address_not_modeled", "rev_stack_address_not_modeled",
            "rev_stack_address_not_modeled", "rev_stack_address_not_modeled",
            "rev_stack_address_not_modeled", "rbit_stack_address_not_modeled"
        ]
        for strict in [false, true] {
            for words in [wordsB, wordsC] {
                for (index, word) in words.enumerated() {
                    var state = UnwindAuditMachine(strictCallState: strict)
                    state.registers[1] = .stack(displacement: -16)
                    state.flags = .init(n: true, z: false, c: true, v: false)
                    state.sp = .stack(displacement: -32)
                    state.memory[-16] = .constant(0x55)
                    state.words[-24] = .constant(0x66)
                    let before = state.snapshot(certain: true, priorCallCount: 0)
                    let instruction = try XCTUnwrap(decode([word]).first)
                    assertCode(codes[index]) { try state.apply(instruction) }
                    XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
                }
            }
        }
        for (index, word) in wordsG.enumerated() {
            assertCode(codes[index]) { try runFrame(0xd503201f, word) }
        }
    }

    func testUC11OriginalAndUnknownInputsStayUnknown() throws {
        let inputs: [UnwindAuditValue?] = [
            nil, .unknown("test"), .original(register: 5, displacement: 8)
        ]
        for strict in [false, true] {
            for initial in inputs {
                for word in wordsB {
                    var state = UnwindAuditMachine(strictCallState: strict)
                    if let initial { state.registers[1] = initial }
                    else {
                        XCTAssertEqual(state.registers[1], .original(register: 1, displacement: 0))
                    }
                    try state.apply(XCTUnwrap(decode([word]).first))
                    XCTAssertFalse(state.registers[0].known)
                    if case let .unknown(message) = state.registers[0] {
                        XCTAssertFalse(message.isEmpty)
                    } else {
                        XCTFail("One-source transfer must produce an unknown value from a symbolic input")
                    }
                }
            }
        }
    }

    func testUC12ModelIdentityFlagsAndAdmission() throws {
        let historicalIDs: [String] = [
            "arm64-bounded-loops-cfa-register-v1",
            "arm64-bounded-loop-calls-cfa-register-v2",
            "arm64-bounded-loop-calls-movk-cfa-register-v3",
            "arm64-bounded-cfi-controls-v4"
        ]
        XCTAssertEqual(historicalModels.map(\.rawValue), historicalIDs)
        XCTAssertEqual(UnwindAuditModel.boundedOneSource.rawValue, "arm64-bounded-one-source-v5")
        XCTAssertEqual(UnwindAuditModel(rawValue: "arm64-bounded-one-source-v5"), .boundedOneSource)
        let allModels = historicalModels + [.boundedOneSource]
        XCTAssertEqual(Set(allModels.map(\.rawValue)).count, Int(5))
        let expectedFlags: [(Bool, Bool, Bool, Bool)] = [
            (false, false, false, false),
            (true, false, false, false),
            (true, true, false, false),
            (false, false, true, false),
            (false, false, false, true)
        ]
        for (index, model) in allModels.enumerated() {
            XCTAssertEqual(model.permitsLoopCalls, expectedFlags[index].0)
            XCTAssertEqual(model.permitsMOVK, expectedFlags[index].1)
            XCTAssertEqual(model.permitsCFIControls, expectedFlags[index].2)
            XCTAssertEqual(model.permitsOneSource, expectedFlags[index].3)
        }
        for word in wordsA {
            for model in historicalModels {
                assertCode("unsupported_instruction") { try decode([word], model: model) }
            }
            let bytes = Data((0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) })
            assertCode("unsupported_instruction") {
                try UnwindAuditInstruction.decode(data: bytes, start: 0x1000, maximum: 1)
            }
        }
        for word in [UInt32(0xf297dde0), 0x7297dde0] {
            assertCode("unsupported_instruction") { try decode([word], model: .boundedOneSource) }
        }
        for word in wordsA {
            let instructions = try decode([word, 0xd503201f, 0xd65f03c0], model: .boundedOneSource)
            for model in historicalModels {
                XCTAssertThrowsError(try UnwindAuditExecution.run(instructions: instructions,
                    mode: "frameless", calleeEntries: [], limits: .init(), model: model) { _, _ in [:] }) { error in
                    XCTAssertEqual((error as? UnwindAuditModelError)?.code, "unsupported_instruction")
                    XCTAssertEqual((error as? UnwindAuditModelError)?.address, UInt64(0x1000))
                }
            }
        }
    }

    @MainActor
    func testUC13InteractiveRouting() throws {
        XCTAssertTrue(UnwindAuditResultKey.supportsInteractive(.boundedOneSource))
        XCTAssertTrue(UnwindAuditResultKey.supportsInteractive(.boundedLoops))
        XCTAssertTrue(UnwindAuditResultKey.supportsInteractive(.boundedCFIControls))
        XCTAssertFalse(UnwindAuditResultKey.supportsInteractive(.boundedLoopCalls))
        XCTAssertFalse(UnwindAuditResultKey.supportsInteractive(.boundedLoopCallsMOVK))
        XCTAssertEqual(UnwindAuditResultKey.currentModelID, "arm64-bounded-loops-cfa-register-v1")
        let (_, key) = try input(modelID: UnwindAuditModel.boundedOneSource.rawValue)
        XCTAssertEqual(key.model, .boundedOneSource)
        let (_, unknownKey) = try input(modelID: "unknown-model")
        XCTAssertNil(unknownKey.model)
    }

    func testUC14LeafValuesObservationTimingAndWorkLimit() throws {
        let expected: [UnwindAuditValue] = [
            .constant(18), .constant(50), .constant(0xcbedffff), .constant(0xcbedffffffffffff),
            .constant(0xffffcbed), .constant(0xffffffffffffcbed),
            .constant(0xffffffffcbedffff), .constant(0xd3b7ffff)
        ]
        for (index, word) in wordsB.enumerated() {
            let words: [UInt32] = [0x92824681, word, 0xd503201f, 0xd65f03c0]
            let result = try run(words, model: .boundedOneSource) { state, _ in
                ["x0": state.registers[0]]
            }
            XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1000), 0x1004, 0x1008])
            XCTAssertEqual(result.scope, "modeled_leaf_body")
            let after = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x1008) })
            XCTAssertEqual(after.recovered["x0"], expected[index])
            let before = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x1004) })
            XCTAssertEqual(before.recovered["x0"], .original(register: 0, displacement: 0))
            var limits = UnwindAuditLimits()
            limits.maxSteps = 2
            assertCode("cfg_work_limit") {
                try run(words, limits: limits, model: .boundedOneSource) { state, _ in
                    ["x0": state.registers[0]]
                }
            }
        }
    }

    func testUC15FrameAndCalleeSavedWriteRefusals() throws {
        for word in wordsH {
            assertCode("cfg_frame_transition_not_modeled") { try runFrame(0x92824680, word) }
        }
        for word in wordsJ {
            assertCode("unmodeled_return_state") { try runFrame(0x92824680, word) }
        }
    }

    func testUC16CallSiteValueWitnesses() throws {
        let expected: [UnwindAuditValue] = [
            .constant(0x12), .constant(0x32), .constant(0xcbedffff), .constant(0xcbedffffffffffff),
            .constant(0xffffcbed), .constant(0xffffffffffffcbed),
            .constant(0xffffffffcbedffff), .constant(0xd3b7ffff)
        ]
        for (index, word) in wordsE.enumerated() {
            let result = try runFrame(0x92824680, word)
            XCTAssertEqual(result.observations.count, Int(1))
            let observation = try XCTUnwrap(result.observations.first)
            XCTAssertEqual(observation.pc, UInt64(0x1014))
            XCTAssertEqual(observation.recovered["x19"], expected[index])
        }
        let additional: [(UInt32, UInt32, UnwindAuditValue)] = [
            (0xd2824680, 0x5ac00813, .constant(0x34120000)),
            (0xd2824680, 0xdac00c13, .constant(0x3412000000000000)),
            (0xd2800020, 0x5ac00013, .constant(0x80000000))
        ]
        for (setup, operation, expected) in additional {
            let result = try runFrame(setup, operation)
            XCTAssertEqual(result.observations.count, Int(1))
            let observation = try XCTUnwrap(result.observations.first)
            XCTAssertEqual(observation.pc, UInt64(0x1014))
            XCTAssertEqual(observation.recovered["x19"], expected)
        }
        for word in wordsE {
            let result = try runFrame(0xd503201f, word)
            XCTAssertEqual(result.observations.count, Int(1))
            let observation = try XCTUnwrap(result.observations.first)
            XCTAssertEqual(observation.pc, UInt64(0x1014))
            let recovered = try XCTUnwrap(observation.recovered["x19"])
            XCTAssertFalse(recovered.known)
        }
    }

    func testUC17PossibleOnlyForkKeepsBothValues() throws {
        let words: [UInt32] = [
            0xa9be7bfd, 0xa90153f3, 0x910003fd, 0x54000060, 0x92824680,
            wordsE[2], 0x940003fa, 0xa94153f3, 0xa8c27bfd, 0xd65f03c0
        ]
        let result = try run(words, mode: "frame", callees: [0x2000],
                             model: .boundedOneSource) { state, _ in ["x19": state.registers[19]] }
        XCTAssertEqual(result.observations.count, Int(2))
        for observation in result.observations {
            XCTAssertEqual(observation.pc, UInt64(0x1018))
            XCTAssertFalse(observation.certain)
        }
        let values = try result.observations.map { try XCTUnwrap($0.recovered["x19"]) }
        let expected: Set<UnwindAuditValue> = [
            .original(register: 19, displacement: 0), .constant(0xcbedffff)
        ]
        XCTAssertEqual(Set(values), expected)
    }

    @MainActor
    func testUC18ReportRoundTripAndComparatorIsolation() throws {
        let (_, key) = try input(modelID: UnwindAuditModel.boundedOneSource.rawValue)
        let original = report(key)
        XCTAssertEqual(original.analysisModelVersion, "arm64-bounded-one-source-v5")
        XCTAssertTrue(original.findings.isEmpty)
        XCTAssertNoThrow(try original.validate())
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self,
            from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        let finding = UnwindAuditFinding(identity: key.identity,
            function: .init(id: "owned", address: 0x1000, symbolName: "_owned", size: 4),
            endAddress: 0x1004, verdict: "unresolved", coverage: "dwarf_reference",
            mode: "dwarf", scope: "metadata_only")
        let before = UnwindAuditReport(identity: key.identity, findings: [finding])
        XCTAssertEqual(before.analysisModelVersion, "arm64-bounded-loops-cfa-register-v1")
        var after = before
        after.analysisModelVersion = UnwindAuditModel.boundedOneSource.rawValue
        let comparison = try UnwindAuditComparator.compare(baseline: before, current: after)
        XCTAssertFalse(comparison.modelCompatible)
        XCTAssertEqual(comparison.changes.map(\.change), [.incompatible])
    }
}
