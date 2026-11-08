import Foundation
import XCTest
@testable import MacScope

/// Literal expectations are hand-derived, not computed by the implementation.
final class UnwindAuditMOVKTests: XCTestCase {
    private func decode(_ words: [UInt32],
                        model: UnwindAuditModel = .boundedLoopCallsMOVK) throws -> [UnwindAuditInstruction] {
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

    // Break: MOVK admission silently changes historical model contracts.
    func testHistoricalModelsAndDefaultRejectMOVK() throws {
        for model in [UnwindAuditModel.boundedLoops, .boundedLoopCalls] {
            for word in [UInt32(0xf297dde0), 0x7297dde0] {
                assertCode("unsupported_instruction") { try decode([word], model: model) }
            }
        }
        assertCode("unsupported_instruction") {
            try UnwindAuditInstruction.decode(data: Data([0xe0, 0xdd, 0x97, 0xf2]),
                                               start: 0x1000, maximum: 1)
        }
    }

    // Break: v3-decoded effects execute under a historical model label.
    func testExecutionRejectsCrossModelAdmission() throws {
        let instructions = try decode([0xf297dde0, 0xd65f03c0])
        for model in [UnwindAuditModel.boundedLoops, .boundedLoopCalls] {
            assertCode("unsupported_instruction") {
                try UnwindAuditExecution.run(instructions: instructions, mode: "frameless",
                    calleeEntries: [], limits: .init(), model: model) { _, _ in [:] }
            }
        }
    }

    // Break: wrong halfword, lost retained bits, or missing W zero extension.
    func testLiteralLaneResultsAndFields() throws {
        let vectors: [(UInt32, String, String, UInt64)] = [
            (0xf297dde0, "xmovk", "0",  0x0123456789abbeef),
            (0xf2b7dde0, "xmovk", "16", 0x01234567beefcdef),
            (0xf2d7dde0, "xmovk", "32", 0x0123beef89abcdef),
            (0xf2f7dde0, "xmovk", "48", 0xbeef456789abcdef),
            (0x7297dde0, "wmovk", "0",  0x0000000089abbeef),
            (0x72b7dde0, "wmovk", "16", 0x00000000beefcdef)
        ]
        for (word, kind, shift, expected) in vectors {
            let instruction = try XCTUnwrap(decode([word]).first)
            XCTAssertEqual(instruction.kind, kind)
            XCTAssertEqual(instruction.rd, 0)
            XCTAssertEqual(instruction.immediate, 48879)
            XCTAssertEqual(instruction.addressing, shift)
            var state = UnwindAuditMachine()
            state.registers[0] = .constant(0x0123456789abcdef)
            state.flags = .init(n: true, z: false, c: true, v: false)
            let flags = state.flags
            try state.apply(instruction)
            XCTAssertEqual(state.registers[0], .constant(expected))
            XCTAssertEqual(state.flags, flags)
        }
    }

    // Break: lane clear becomes OR-only or the top lane becomes signed.
    func testZeroAllOnesAndHighBitBoundaries() throws {
        let vectors: [(UInt32, UInt64, UInt64)] = [
            (0xf2a00000, 0xffffffffffffffff, 0xffffffff0000ffff),
            (0x72a00000, 0xffffffffffffffff, 0x000000000000ffff),
            (0xf2f00000, 0, 0x8000000000000000),
            (0xf29fffe0, 0, 0x000000000000ffff)
        ]
        for (word, initial, expected) in vectors {
            var state = UnwindAuditMachine()
            state.registers[0] = .constant(initial)
            try state.apply(XCTUnwrap(decode([word]).first))
            XCTAssertEqual(state.registers[0], .constant(expected))
        }
    }

    // Break: reserved shifts or adjacent opcode families are misclassified.
    func testReservedWShiftsAndNeighboringEncodings() throws {
        for word in [UInt32(0x72c00000), 0x72e00000] {
            assertCode("invalid_movk_shift") { try decode([word]) }
        }
        for bit in 23...30 {
            do {
                let instructions = try decode([0xf297dde0 ^ (UInt32(1) << bit)])
                XCTAssertEqual(instructions.count, 1)
                if let instruction = instructions.first {
                    XCTAssertFalse(["wmovk", "xmovk"].contains(instruction.kind))
                }
            } catch is UnwindAuditModelError {
                // Neighbor may be supported as another effect, or rejected.
            }
        }
        for word in [UInt32(0xffffffff), 0xd503233f, 0xd63f0000, 0xb4000000,
                            0x36000000, 0x5ac00800, 0x1ac00c00] {
            XCTAssertThrowsError(try decode([word]))
        }
    }

    // Break: partial updates recover an unknown/original full-X identity.
    func testUnknownAndOriginalStayUnknownAfterAllLanes() throws {
        let sequences: [[UInt32]] = [
            [0xf2800013, 0xf2a00013, 0xf2c00013, 0xf2e00013],
            [0x72800013, 0x72a00013]
        ]
        for sequence in sequences {
            for initial in [UnwindAuditValue.original(register: 19, displacement: 0),
                            .unknown("external input")] {
                var state = UnwindAuditMachine()
                state.registers[19] = initial
                for instruction in try decode(sequence) {
                    try state.apply(instruction)
                    XCTAssertFalse(state.registers[19].known)
                    XCTAssertNotEqual(state.registers[19], .original(register: 19, displacement: 0))
                }
            }
        }
    }

    // Break: projection/masking erases stack-address provenance.
    func testStackDestinationRefusesWithoutMutation() throws {
        for word in [UInt32(0xf297dde0), 0x7297dde0] {
            for strict in [false, true] {
                var state = UnwindAuditMachine(strictCallState: strict)
                state.registers[0] = .stack(displacement: -16)
                let before = state.snapshot(certain: true, priorCallCount: 0)
                let instruction = try XCTUnwrap(decode([word]).first)
                assertCode("movk_stack_address_not_modeled") { try state.apply(instruction) }
                XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
            }
        }
    }

    // Break: Rd31 addresses SP or modifies flags/memory/saved LR.
    func testZeroRegisterDiscardPreservesCompleteState() throws {
        for word in [UInt32(0xf297ddff), 0x7297ddff] {
            var state = UnwindAuditMachine()
            state.memory[-16] = .original(register: 29, displacement: 0)
            state.memory[-8] = .original(register: 30, displacement: 0)
            state.flags = .init(n: true, z: false, c: true, v: false)
            let before = state.snapshot(certain: true, priorCallCount: 0)
            try state.apply(XCTUnwrap(decode([word]).first))
            XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
        }
    }

    // Break: v3 bypasses body FP-transition and terminal original-register checks.
    func testFPTransitionAndUnrestoredRegistersStillReject() throws {
        assertCode("cfg_frame_transition_not_modeled") { try run([0xf280001d, 0xd65f03c0]) }
        assertCode("unmodeled_return_state") { try run([0xf280001e, 0xd65f03c0]) }
        assertCode("unmodeled_return_state") { try run([0xf2800013, 0xd65f03c0]) }
    }

    // Break: a live LR update destroys an independent saved original identity.
    func testSavedLRRestoresAfterMOVK() throws {
        let result = try run([0xa9bf7bfd, 0xf280001e, 0xa8c17bfd, 0xd65f03c0])
        XCTAssertEqual(result.observations.map(\.pc), [0x1004])
        XCTAssertEqual(result.observations.first?.recovered["savedLR"],
                       .original(register: 30, displacement: 0))
    }

    // Break: new transfer skips budgets.
    func testBudgetsStillBoundNewTransfer() throws {
        var limits = UnwindAuditLimits()
        limits.maxSteps = 1
        assertCode("cfg_work_limit") { try run([0xf2800000, 0xd65f03c0], limits: limits) }
        limits = .init(); limits.maxObservations = 0
        assertCode("observation_limit") { try run([0xf2800000, 0xd65f03c0], limits: limits) }
        limits = .init(); limits.maxPaths = 0
        assertCode("cfg_path_limit") { try run([0xf2800000, 0xd65f03c0], limits: limits) }
    }

    // Break: manually assembled invalid effects perform out-of-width shifts.
    func testMalformedEffectRefusesWithoutMutation() throws {
        let cases: [(String, Int64)] = [("64", 0), ("-16", 0), ("oops", 0),
                                       ("0", -1), ("0", 65536)]
        for (shift, immediate) in cases {
            var state = UnwindAuditMachine()
            let before = state.snapshot(certain: true, priorCallCount: 0)
            let instruction = UnwindAuditInstruction(address: 0x1000, word: 0xf2800000,
                kind: "xmovk", immediate: immediate, addressing: shift)
            assertCode("invalid_movk_effect") { try state.apply(instruction) }
            XCTAssertEqual(state.snapshot(certain: true, priorCallCount: 0), before)
        }
    }

    // Break: v3 loses v2 call summaries or closes on an incomplete header state.
    func testV3PreservesCallLoopRecurrenceAndOriginalCallPC() throws {
        let instructions = try decode([0xa9bf7bfd, 0x910003fd, 0xf297dde0,
                                       0x940003fd, 0x54ffffc1, 0xa8c17bfd, 0xd65f03c0])
        let result = try UnwindAuditExecution.run(instructions: instructions, mode: "frame",
            calleeEntries: [0x2000], limits: .init(), model: .boundedLoopCallsMOVK) { state, pc in
                XCTAssertEqual(pc, 0x100c)
                XCTAssertEqual(state.registers[30], .constant(0x1010))
                XCTAssertFalse(state.registers[0].known)
                return ["SP": try state.registers[29].add(16),
                        "x30": state.memory[-8] ?? .unknown("no saved LR")]
            }
        XCTAssertEqual(result.loopVisits, 2)
        XCTAssertEqual(result.loopClosures, 1)
        XCTAssertEqual(Set(result.observations.map(\.pc)), [0x100c])
        XCTAssertTrue(result.observations.contains { !$0.certain })
        for observation in result.observations {
            XCTAssertEqual(observation.recovered["SP"], .stack(displacement: 0))
            XCTAssertEqual(observation.recovered["x30"], .original(register: 30, displacement: 0))
        }
    }

    private func run(_ words: [UInt32], limits: UnwindAuditLimits = .init()) throws -> UnwindAuditExecutionResult {
        try UnwindAuditExecution.run(instructions: decode(words), mode: "frameless",
            calleeEntries: [], limits: limits, model: .boundedLoopCallsMOVK) { state, _ in
                ["SP": state.sp, "savedLR": state.memory[-8] ?? .unknown("no saved LR")]
            }
    }
}
