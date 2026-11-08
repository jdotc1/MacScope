import Foundation
import XCTest
@testable import MacScope

final class UnwindAuditDivideTests: XCTestCase {
    private let kinds: [String] = ["wudiv", "xudiv", "wsdiv", "xsdiv"]
    private let twA: [UInt32] = [0x1ac608a4, 0x9ac608a4, 0x1ac60ca4, 0x9ac60ca4]
    private let twB: [UInt32] = [0x1ac20820, 0x9ac20820, 0x1ac20c20, 0x9ac20c20]
    private let twC: [UInt32] = [0x1ac2083f, 0x9ac2083f, 0x1ac20c3f, 0x9ac20c3f]
    private let twD: [UInt32] = [0x1ac20be0, 0x9ac20be0, 0x1ac20fe0, 0x9ac20fe0]
    private let twE: [UInt32] = [0x1adf0820, 0x9adf0820, 0x1adf0c20, 0x9adf0c20]
    private let twF: [UInt32] = [0x1ac20833, 0x9ac20833, 0x1ac20c33, 0x9ac20c33]
    private let twG: [UInt32] = [0x1ac20bb3, 0x9ac20bb3, 0x1ac20fb3, 0x9ac20fb3]
    private let twG2: [UInt32] = [0x1add0833, 0x9add0833, 0x1add0c33, 0x9add0c33]
    private let twH: [UInt32] = [0x1ac2083d, 0x9ac2083d, 0x1ac20c3d, 0x9ac20c3d]
    private let twJ: [UInt32] = [0x1ac20835, 0x9ac20835, 0x1ac20c35, 0x9ac20c35]

    private func decode(_ words: [UInt32],
                        model: UnwindAuditModel = .boundedOneSourceDivide) throws -> [UnwindAuditInstruction] {
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

    private func word(_ kind: Int, rd: Int, rn: Int, rm: Int) -> UInt32 {
        let base: [UInt32] = [0x1ac00800, 0x9ac00800, 0x1ac00c00, 0x9ac00c00]
        return base[kind] | UInt32(rm) << 16 | UInt32(rn) << 5 | UInt32(rd)
    }

    func testUC01DecodeFields() throws {
        for k in 0..<4 {
            let a = try XCTUnwrap(decode([twA[k]]).first)
            XCTAssertEqual(a.kind, kinds[k])
            XCTAssertEqual(a.rd, Int(4)); XCTAssertEqual(a.rn, Int(5)); XCTAssertEqual(a.rt2, Int(6))
            XCTAssertEqual(a.immediate, Int64(0)); XCTAssertEqual(a.addressing, String(""))
            XCTAssertEqual(a.word, twA[k]); XCTAssertEqual(a.address, UInt64(0x1000))
            XCTAssertFalse(a.changesSP); XCTAssertFalse(a.changesFP)
            let h = try XCTUnwrap(decode([twH[k]]).first)
            XCTAssertEqual(h.rd, Int(29)); XCTAssertEqual(h.rn, Int(1)); XCTAssertEqual(h.rt2, Int(2))
            XCTAssertTrue(h.changesFP)
            let c = try XCTUnwrap(decode([twC[k]]).first)
            XCTAssertEqual(c.rd, Int(31)); XCTAssertEqual(c.rn, Int(1)); XCTAssertEqual(c.rt2, Int(2))
            let d = try XCTUnwrap(decode([twD[k]]).first)
            XCTAssertEqual(d.rd, Int(0)); XCTAssertEqual(d.rn, Int(31))
            let e = try XCTUnwrap(decode([twE[k]]).first)
            XCTAssertEqual(e.rt2, Int(31))
        }
    }

    func testUC02RegisterFieldSweep() throws {
        for k in 0..<4 {
            for rd in 0...31 {
                let rn: Int = (rd * 7 + 3) % 32, rm: Int = (rd * 5 + 11) % 32
                let instruction = try XCTUnwrap(decode([word(k, rd: rd, rn: rn, rm: rm)]).first)
                XCTAssertEqual(instruction.kind, kinds[k])
                XCTAssertEqual(instruction.rd, rd); XCTAssertEqual(instruction.rn, rn)
                XCTAssertEqual(instruction.rt2, rm)
            }
        }
    }

    func testUC03NeighborRefusals() {
        let words: [UInt32] = [0x3ac20820, 0x3ac20c20, 0xbac20820, 0xbac20c20,
                              0x1ae20820, 0x9ae20c20, 0x1ac20420, 0x1ac21820, 0x4e2008a4]
        for word in words { assertCode("unsupported_instruction") { try decode([word]) } }
    }

    private func assertValues(_ opcode: UInt32, _ vectors: [(UInt64, UInt64, UInt64)],
                              file: StaticString = #filePath, line: UInt = #line) throws {
        let instruction = try XCTUnwrap(decode([opcode]).first)
        for (left, right, expected) in vectors {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(left); state.registers[2] = .constant(right)
            try state.apply(instruction)
            XCTAssertEqual(state.registers[0], UnwindAuditValue.constant(expected), file: file, line: line)
        }
    }

    func testUC04UnsignedWValues() throws {
        let vectors: [(UInt64, UInt64, UInt64)] = [
            (0, 0, 0), (0x13, 0, 0), (0, 9, 0), (0x13, 3, 6),
            (0xffffffff, 2, 0x7fffffff), (0x80000000, 3, 0x2aaaaaaa),
            (0xffffffffffffffff, 0xffffffff, 1), (0x0000010000000000, 3, 0),
            (0x100000013, 0x100000003, 6), (0x13, 0x100000000, 0),
            (0xffffffff, 1, 0xffffffff), (0x1234567800000013, 3, 6)
        ]
        try assertValues(twB[0], vectors)
    }

    func testUC05UnsignedXValues() throws {
        let vectors: [(UInt64, UInt64, UInt64)] = [
            (0, 0, 0), (0x13, 0, 0), (0, 9, 0), (0x13, 3, 6),
            (0xffffffffffffffff, 1, 0xffffffffffffffff),
            (0xffffffffffffffff, 2, 0x7fffffffffffffff),
            (0x8000000000000000, 3, 0x2aaaaaaaaaaaaaaa),
            (0xffffffffffffffff, 0xffffffffffffffff, 1),
            (0x123456789abcdef0, 0x11, 0x0112233445566777),
            (0x8000000000000000, 0x100000000, 0x80000000),
            (0xffffffffffffffff, 0x8000000000000001, 1)
        ]
        try assertValues(twB[1], vectors)
    }

    func testUC06SignedWValues() throws {
        let vectors: [(UInt64, UInt64, UInt64)] = [
            (7, 3, 2), (0xfffffffffffffff9, 3, 0xfffffffe),
            (7, 0xfffffffffffffffd, 0xfffffffe), (0xfffffffffffffff9, 0xfffffffffffffffd, 2),
            (0x13, 0, 0), (0xffffffffffffffed, 0, 0), (0xfffffffffffffffe, 3, 0),
            (0x80000000, 0xffffffff, 0x80000000), (0x80000000, 1, 0x80000000),
            (0x7fffffff, 0xffffffff, 0x80000001), (0x0000010000000013, 3, 6),
            (0x100000013, 0x1fffffffd, 0xfffffffa), (0x80000000, 3, 0xd5555556)
        ]
        try assertValues(twB[2], vectors)
    }

    func testUC07SignedXValues() throws {
        let vectors: [(UInt64, UInt64, UInt64)] = [
            (7, 3, 2), (0xfffffffffffffff9, 3, 0xfffffffffffffffe),
            (7, 0xfffffffffffffffd, 0xfffffffffffffffe), (0xfffffffffffffff9, 0xfffffffffffffffd, 2),
            (0x13, 0, 0), (0xffffffffffffffed, 0, 0), (0xfffffffffffffffe, 3, 0),
            (2, 0xfffffffffffffffd, 0), (0xfffffffffffffff7, 9, 0xffffffffffffffff),
            (0xffffffffffffffff, 1, 0xffffffffffffffff),
            (0x8000000000000000, 0xffffffffffffffff, 0x8000000000000000),
            (0x8000000000000000, 1, 0x8000000000000000),
            (0x8000000000000000, 3, 0xd555555555555556),
            (0x7fffffffffffffff, 0xffffffffffffffff, 0x8000000000000001),
            (0x923456789abcdef0, 0x11, 0xf98a9bacbdcedff0),
            (0xffffffffffffffff, 0x8000000000000001, 0),
            (0x8000000000000000, 0x100000000, 0xffffffff80000000)
        ]
        try assertValues(twB[3], vectors)
    }

    func testUC08AliasesCaptureOldOperands() throws {
        let cases: [(Int, Int, Int, UInt64, UInt64, UInt64)] = [
            (1, 1, 2, 19, 3, 6), (2, 1, 2, 19, 3, 6),
            (1, 1, 1, 9, 3, 1), (1, 1, 1, 0, 3, 0)
        ]
        for k in 0..<4 {
            for (rd, rn, rm, left, right, expected) in cases {
                var state = UnwindAuditMachine()
                state.registers[1] = .constant(left); state.registers[2] = .constant(right)
                try state.apply(XCTUnwrap(decode([word(k, rd: rd, rn: rn, rm: rm)]).first))
                XCTAssertEqual(state.registers[rd], UnwindAuditValue.constant(expected))
            }
        }
        let signed: [(Int, UInt64)] = [(2, 0xfffffffa), (3, 0xfffffffffffffffa)]
        for (k, expected) in signed {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(0xffffffffffffffed); state.registers[2] = .constant(3)
            try state.apply(XCTUnwrap(decode([word(k, rd: 1, rn: 1, rm: 2)]).first))
            XCTAssertEqual(state.registers[1], UnwindAuditValue.constant(expected))
        }
    }

    private func preset(_ state: inout UnwindAuditMachine) {
        state.flags = UnwindAuditNZCV(n: true, z: false, c: true, v: false)
        state.memory[-16] = .constant(0x55)
        state.sp = .stack(displacement: -32)
    }

    func testUC09ZeroRegisterAndDiscard() throws {
        for k in 0..<4 {
            var dividendZero = UnwindAuditMachine()
            dividendZero.registers[0] = .unknown("preset"); dividendZero.registers[2] = .constant(3)
            try dividendZero.apply(XCTUnwrap(decode([twD[k]]).first))
            XCTAssertEqual(dividendZero.registers[0], UnwindAuditValue.constant(0))
            var divisorZero = UnwindAuditMachine()
            divisorZero.registers[0] = .unknown("preset"); divisorZero.registers[1] = .constant(19)
            try divisorZero.apply(XCTUnwrap(decode([twE[k]]).first))
            XCTAssertEqual(divisorZero.registers[0], UnwindAuditValue.constant(0))
            var discard = UnwindAuditMachine()
            discard.registers[1] = .constant(19); discard.registers[2] = .constant(3)
            preset(&discard)
            let before = discard.snapshot(certain: true, priorCallCount: 0)
            try discard.apply(XCTUnwrap(decode([twC[k]]).first))
            XCTAssertEqual(discard.snapshot(certain: true, priorCallCount: 0), before)
        }
    }

    func testUC10RawStackRefusalIsAtomic() throws {
        for k in 0..<4 {
            let code: String = k < 2 ? "udiv_stack_address_not_modeled" : "sdiv_stack_address_not_modeled"
            for opcode in [twB[k], twC[k]] {
                let instruction = try XCTUnwrap(decode([opcode]).first)
                for strict in [false, true] {
                    for position in 0..<3 {
                        var state = UnwindAuditMachine(strictCallState: strict)
                        state.registers[1] = position == 1 ? .constant(3) : .stack(displacement: -16)
                        state.registers[2] = position == 0 ? .constant(3) : .stack(displacement: -16)
                        let before = state.snapshot(certain: true, priorCallCount: 0)
                        assertCode(code) { try state.apply(instruction) }
                        XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
                    }
                }
            }
            for opcode in [twG[k], twG2[k]] {
                assertCode(code) { try runFrame(frame(0xd503201f, 0xd503201f, opcode)) }
            }
        }
    }

    func testUC11UnknownStaysUnknown() throws {
        for strict in [false, true] {
            for k in 0..<4 {
                let instruction = try XCTUnwrap(decode([twB[k]]).first)
                for source in [Int(1), 2] {
                    let values: [UnwindAuditValue] = [.original(register: source, displacement: 0),
                        .unknown("test"), .original(register: 5, displacement: 8)]
                    for value in values {
                        for other in [UInt64(0), 3] {
                            var state = UnwindAuditMachine(strictCallState: strict)
                            state.registers[source] = value
                            state.registers[source == 1 ? 2 : 1] = .constant(other)
                            try state.apply(instruction)
                            XCTAssertFalse(state.registers[0].known)
                        }
                    }
                }
                var state = UnwindAuditMachine(strictCallState: strict)
                try state.apply(XCTUnwrap(decode([word(k, rd: 0, rn: 1, rm: 1)]).first))
                XCTAssertFalse(state.registers[0].known)
            }
        }
    }

    func testUC12UnrelatedStatePreserved() throws {
        for opcode in twB {
            var state = UnwindAuditMachine()
            state.registers[1] = .constant(19); state.registers[2] = .constant(3)
            preset(&state)
            state.words[-24] = .constant(0x66)
            let flags = state.flags, sp = state.sp, memory = state.memory, words = state.words
            let registers = state.registers
            try state.apply(XCTUnwrap(decode([opcode]).first))
            XCTAssertEqual(state.flags, flags); XCTAssertEqual(state.sp, sp)
            XCTAssertEqual(state.memory, memory); XCTAssertEqual(state.words, words)
            for register in 1..<31 { XCTAssertEqual(state.registers[register], registers[register]) }
        }
    }

    func testUC13ModelIdentityAndGating() throws {
        let rows: [(UnwindAuditModel, String, Bool, Bool, Bool, Bool, Bool)] = [
            (.boundedLoops, "arm64-bounded-loops-cfa-register-v1", false, false, false, false, false),
            (.boundedLoopCalls, "arm64-bounded-loop-calls-cfa-register-v2", true, false, false, false, false),
            (.boundedLoopCallsMOVK, "arm64-bounded-loop-calls-movk-cfa-register-v3", true, true, false, false, false),
            (.boundedCFIControls, "arm64-bounded-cfi-controls-v4", false, false, true, false, false),
            (.boundedOneSource, "arm64-bounded-one-source-v5", false, false, false, true, false),
            (.boundedOneSourceDivide, "arm64-bounded-one-source-v6", false, false, false, true, true)
        ]
        XCTAssertEqual(Set(rows.map { $0.0.rawValue }).count, Int(6))
        for (model, raw, loops, movk, cfi, oneSource, divide) in rows {
            XCTAssertEqual(model.rawValue, raw)
            XCTAssertEqual(model.permitsLoopCalls, loops); XCTAssertEqual(model.permitsMOVK, movk)
            XCTAssertEqual(model.permitsCFIControls, cfi); XCTAssertEqual(model.permitsOneSource, oneSource)
            XCTAssertEqual(model.permitsDivide, divide)
        }
        XCTAssertEqual(UnwindAuditModel(rawValue: "arm64-bounded-one-source-v6"),
                       UnwindAuditModel.boundedOneSourceDivide)
        let historical: [UnwindAuditModel] = [.boundedLoops, .boundedLoopCalls,
            .boundedLoopCallsMOVK, .boundedCFIControls, .boundedOneSource]
        for opcode in twA {
            for model in historical {
                assertCode("unsupported_instruction") { try decode([opcode], model: model) }
            }
            let bytes = Data((0..<4).map { UInt8(truncatingIfNeeded: opcode >> ($0 * 8)) })
            assertCode("unsupported_instruction") {
                try UnwindAuditInstruction.decode(data: bytes, start: 0x1000, maximum: 1)
            }
        }
        let inherited: [(UInt32, String)] = [(0x5ac008a4, "wrev"), (0xdac014a4, "xcls"), (0x5ac000a4, "wrbit")]
        for (opcode, kind) in inherited {
            let instruction = try XCTUnwrap(decode([opcode]).first)
            XCTAssertEqual(instruction.kind, kind)
            XCTAssertEqual(instruction.rd, Int(4)); XCTAssertEqual(instruction.rn, Int(5))
        }
        for opcode in [UInt32(0xf297dde0), 0x7297dde0, 0x5ac010a4] {
            assertCode("unsupported_instruction") { try decode([opcode]) }
        }
        let divided = try decode([twA[2], 0xd503201f, 0xd65f03c0])
        for model in historical {
            XCTAssertThrowsError(try UnwindAuditExecution.run(instructions: divided, mode: "frameless",
                calleeEntries: [], limits: .init(), model: model) { state, _ in
                    ["x0": state.registers[0]]
                }) { error in
                    XCTAssertEqual((error as? UnwindAuditModelError)?.code, String("unsupported_instruction"))
                    XCTAssertEqual((error as? UnwindAuditModelError)?.address, UInt64(0x1000))
                }
        }
        let inheritedInstructions = try decode([0x5ac008a4, 0xd503201f, 0xd65f03c0])
        for model in [UnwindAuditModel.boundedOneSource, .boundedOneSourceDivide] {
            XCTAssertNoThrow(try UnwindAuditExecution.run(instructions: inheritedInstructions,
                mode: "frameless", calleeEntries: [], limits: .init(), model: model) { state, _ in
                    ["x0": state.registers[0]]
                })
        }
    }

    func testUC14InteractiveRouting() throws {
        let rows: [(UnwindAuditModel, Bool)] = [(.boundedLoops, true), (.boundedLoopCalls, false),
            (.boundedLoopCallsMOVK, false), (.boundedCFIControls, true),
            (.boundedOneSource, true), (.boundedOneSourceDivide, true)]
        for (model, expected) in rows {
            XCTAssertEqual(UnwindAuditResultKey.supportsInteractive(model), expected)
        }
        let key = try key(modelID: UnwindAuditModel.boundedOneSourceDivide.rawValue)
        XCTAssertEqual(key.model, UnwindAuditModel.boundedOneSourceDivide)
        XCTAssertNil(try self.key(modelID: "unknown-model").model)
    }

    func testUC15LeafAgreementAndWorkLimit() throws {
        let expected: [UnwindAuditValue] = [.constant(0x0ccccbe3), .constant(0x0ccccccccccccbe3),
            .constant(0xffffff17), .constant(0xffffffffffffff17)]
        for k in 0..<4 {
            let words: [UInt32] = [0x92824681, 0xd2800282, twB[k], 0xd503201f, 0xd65f03c0]
            let result = try run(words, recover: { state, _ in ["x0": state.registers[0]] })
            XCTAssertEqual(result.observations.map(\.pc), [UInt64(0x1000), 0x1004, 0x1008, 0x100c])
            XCTAssertEqual(result.scope, String("modeled_leaf_body"))
            let before = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x1008) })
            let after = try XCTUnwrap(result.observations.first { $0.pc == UInt64(0x100c) })
            XCTAssertEqual(before.recovered["x0"], UnwindAuditValue.original(register: 0, displacement: 0))
            XCTAssertEqual(after.recovered["x0"], expected[k])
            var limits = UnwindAuditLimits()
            limits.maxSteps = 2
            assertCode("cfg_work_limit") {
                try run(words, limits: limits, recover: { state, _ in ["x0": state.registers[0]] })
            }
        }
    }

    func testUC16FrameAndCalleeSavedRefusals() {
        for k in 0..<4 {
            assertCode("cfg_frame_transition_not_modeled") {
                try runFrame(frame(0x92824681, 0xd2800282, twH[k]))
            }
            assertCode("unmodeled_return_state") {
                try runFrame(frame(0x92824681, 0xd2800282, twJ[k]))
            }
        }
    }

    func testUC17CallSiteValueWitness() throws {
        let vectors: [(UInt32, UInt32, UInt32, UInt64)] = [
            (0x92824681, 0xd2800282, 0x1ac20833, 0x0ccccbe3),
            (0x92824681, 0xd2800282, 0x9ac20833, 0x0ccccccccccccbe3),
            (0x92824681, 0xd2800282, 0x1ac20c33, 0xffffff17),
            (0x92824681, 0xd2800282, 0x9ac20c33, 0xffffffffffffff17),
            (0xd2800c81, 0xd28000e2, 0x1ac20833, 14),
            (0xd2800c81, 0xd28000e2, 0x9ac20833, 14),
            (0xd2800c81, 0xd2800002, 0x1ac20c33, 0),
            (0xd2800c81, 0xd2800002, 0x9ac20c33, 0),
            (0x928000c1, 0xd2800062, 0x1ac20c33, 0xfffffffe),
            (0x928000c1, 0xd2800062, 0x9ac20c33, 0xfffffffffffffffe)
        ]
        for (s1, s2, opcode, expected) in vectors {
            let result = try runFrame(frame(s1, s2, opcode))
            XCTAssertEqual(result.observations.count, Int(1))
            let observation = try XCTUnwrap(result.observations.first)
            XCTAssertEqual(observation.pc, UInt64(0x1018))
            XCTAssertEqual(observation.recovered["x19"], UnwindAuditValue.constant(expected))
        }
    }

    func testUC18UnknownCallSiteValue() throws {
        for opcode in twF {
            for s1 in [UInt32(0xd503201f), 0x92824681] {
                let result = try runFrame(frame(s1, 0xd503201f, opcode))
                XCTAssertEqual(result.observations.count, Int(1))
                let observation = try XCTUnwrap(result.observations.first)
                XCTAssertFalse(try XCTUnwrap(observation.recovered["x19"]).known)
            }
        }
    }

    func testUC19PossibleOnlyFork() throws {
        let words: [UInt32] = [0xa9be7bfd, 0xa90153f3, 0x910003fd, 0x54000080,
            0x92824681, 0xd2800282, 0x1ac20c33, 0x940003f9, 0xa94153f3, 0xa8c27bfd, 0xd65f03c0]
        let result = try runFrame(words)
        XCTAssertEqual(result.observations.count, Int(2))
        for observation in result.observations {
            XCTAssertEqual(observation.pc, UInt64(0x101c))
            XCTAssertFalse(observation.certain)
        }
        let actual = try Set(result.observations.map { try XCTUnwrap($0.recovered["x19"]) })
        let expected: Set<UnwindAuditValue> = [.original(register: 19, displacement: 0), .constant(0xffffff17)]
        XCTAssertEqual(actual, expected)
    }

    func testUC20ReportAndComparator() throws {
        let key = try key(modelID: UnwindAuditModel.boundedOneSourceDivide.rawValue)
        let original = report(key)
        XCTAssertNoThrow(try original.validate())
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        let finding = UnwindAuditFinding(identity: key.identity,
            function: .init(id: "owned", address: 0x1000, symbolName: "_owned", size: 4),
            endAddress: 0x1004, verdict: "unresolved", coverage: "dwarf_reference",
            mode: "dwarf", scope: "metadata_only")
        let historical = UnwindAuditReport(identity: key.identity, findings: [finding])
        var v5 = historical
        v5.analysisModelVersion = UnwindAuditModel.boundedOneSource.rawValue
        var v6 = historical
        v6.analysisModelVersion = UnwindAuditModel.boundedOneSourceDivide.rawValue
        for before in [historical, v5] {
            let comparison = try UnwindAuditComparator.compare(baseline: before, current: v6)
            XCTAssertFalse(comparison.modelCompatible)
            XCTAssertEqual(comparison.changes.map(\.change), [.incompatible])
        }
    }

    private func frame(_ s1: UInt32, _ s2: UInt32, _ operation: UInt32) -> [UInt32] {
        [0xa9be7bfd, 0xa90153f3, 0x910003fd, s1, s2, operation, 0x940003fa,
         0xa94153f3, 0xa8c27bfd, 0xd65f03c0]
    }

    private func runFrame(_ words: [UInt32]) throws -> UnwindAuditExecutionResult {
        try run(words, mode: "frame", callees: [0x2000], recover: { state, _ in
            ["x19": state.registers[19]]
        })
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
                     model: UnwindAuditModel = .boundedOneSourceDivide,
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
}
