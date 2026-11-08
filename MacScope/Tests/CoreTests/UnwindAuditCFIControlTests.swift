import Foundation
import XCTest
@testable import MacScope

/// Literal row expectations exercise the evaluator independently of byte decoding.
final class UnwindAuditCFIControlTests: XCTestCase {
    private func op(_ code: UInt8, _ values: [UInt64] = []) -> DWARFStructuredCFAOperation {
        .init(sectionOffset: 0, opcode: code, operands: values.map { .unsigned($0) }, rawBytes: [code])
    }

    private func program(_ operations: [DWARFStructuredCFAOperation],
                         status: DWARFStructuredCFADecodeStatus = .complete) -> DWARFStructuredCFAProgram {
        .init(sectionOffset: 0, rawBytes: operations.flatMap(\.rawBytes), operations: operations, status: status)
    }

    private func table(_ operations: [DWARFStructuredCFAOperation],
                       initial: [DWARFStructuredCFAOperation]? = nil,
                       start: UInt64 = 0x100, size: UInt64 = 0x40) -> DWARFStructuredCallFrameTable {
        let cie = DWARFStructuredCIE(sectionOffset: 0, version: 1, augmentation: "zR",
            augmentationData: [0x10], codeAlignmentFactor: 1, dataAlignmentFactor: -8,
            returnAddressRegister: 30, fdePointerEncoding: 0x10,
            initialProgram: program(initial ?? [op(12, [31, 0])]))
        let fde = DWARFStructuredFDE(sectionOffset: 20, cieSectionOffset: 0,
            initialLocation: start, rangeSize: size, augmentationData: [], program: program(operations))
        return .init(cies: [cie], fdes: [fde])
    }

    private func fde(_ operations: [DWARFStructuredCFAOperation],
                     initial: [DWARFStructuredCFAOperation]? = nil,
                     start: UInt64 = 0x100, size: UInt64 = 0x40) throws -> UnwindAuditCFI.FDE {
        let evaluator = try UnwindAuditCFI(
            table: table(operations, initial: initial, start: start, size: size), enableCFIControls: true)
        return try evaluator.select(offset: 20, start: start, end: start + size)
    }

    private func assertRule(_ actual: UnwindAuditCFI.Rule?, _ expected: UnwindAuditCFI.Rule,
                            file: StaticString = #filePath, line: UInt = #line) {
        switch (actual, expected) {
        case (.some(.same), .same), (.some(.undefined), .undefined): break
        case (.some(.offset(let value)), .offset(let wanted)):
            XCTAssertEqual(value, wanted, file: file, line: line)
        default: XCTFail("Unexpected or missing recovery rule", file: file, line: line)
        }
    }

    private func assertRefusal(_ table: DWARFStructuredCallFrameTable,
                               containing message: String? = nil,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try UnwindAuditCFI(table: table, enableCFIControls: true), file: file, line: line) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, "dwarf_cfi_unsupported", file: file, line: line)
            if let message {
                XCTAssertTrue((error as? UnwindAuditModelError)?.message.contains(message) == true,
                              "Expected refusal containing \(message)", file: file, line: line)
            }
        }
    }

    func testModelIdentityKeepsV1MachineSemanticsAndHistoricalCapabilities() {
        XCTAssertEqual(UnwindAuditModel.boundedCFIControls.rawValue, "arm64-bounded-cfi-controls-v4")
        let models: [(UnwindAuditModel, Bool, Bool, Bool)] = [
            (.boundedLoops, false, false, false), (.boundedLoopCalls, true, false, false),
            (.boundedLoopCallsMOVK, true, true, false), (.boundedCFIControls, false, false, true)
        ]
        for (model, calls, movk, controls) in models {
            XCTAssertEqual(model.permitsLoopCalls, calls, model.rawValue)
            XCTAssertEqual(model.permitsMOVK, movk, model.rawValue)
            XCTAssertEqual(model.permitsCFIControls, controls, model.rawValue)
        }
    }

    func testDefaultAndHistoricalEvaluatorsRejectEveryNewControl() throws {
        let bodies = [
            [op(2, [4])], [op(3, [4])], [op(4, [4])], [op(10)], [op(10), op(11)]
        ]
        for body in bodies {
            let source = table(body)
            XCTAssertThrowsError(try UnwindAuditCFI(table: source))
            for model in [UnwindAuditModel.boundedLoops, .boundedLoopCalls, .boundedLoopCallsMOVK] {
                XCTAssertThrowsError(try UnwindAuditCFI(table: source, enableCFIControls: model.permitsCFIControls))
            }
            XCTAssertNoThrow(try UnwindAuditCFI(table: source, enableCFIControls: true))
        }
    }

    func testEveryFixedAdvanceProducesExactRowsAtTheCurrentPC() throws {
        for opcode in [UInt8(2), 3, 4] {
            let result = try fde([op(opcode, [4]), op(14, [16]), op(opcode, [4]), op(14, [0])])
            XCTAssertEqual(result.rows.map(\.pc), [0x100, 0x104, 0x108])
            XCTAssertEqual(result.rows.map(\.offset), [0, 16, 0])
            XCTAssertEqual(try result.row(at: 0x107).offset, 16)
        }
    }

    func testFixedAdvancesAcceptLargestAlignedUnsignedValues() throws {
        let cases: [(UInt8, UInt64)] = [(2, 0xfc), (3, 0xfffc), (4, 0xffff_fffc)]
        for (opcode, delta) in cases {
            let result = try fde([op(opcode, [delta]), op(14, [8])], start: 0, size: delta + 4)
            XCTAssertEqual(result.rows.map(\.pc), [0, delta])
            XCTAssertEqual(try result.row(at: delta).offset, 8)
        }
    }

    func testNestedSnapshotsRestoreCFARegisterOffsetAndRulesAtCurrentPC() throws {
        let result = try fde([
            op(10), op(12, [31, 16]), op(0x93, [19, 1]), op(0x44, [4]),
            op(10), op(12, [29, 32]), op(7, [19]), op(0x44, [4]),
            op(11), op(0x44, [4]), op(11)
        ])
        XCTAssertEqual(result.rows.map(\.pc), [0x100, 0x104, 0x108, 0x10c])
        XCTAssertEqual(result.rows.map(\.register), [31, 29, 31, 31])
        XCTAssertEqual(result.rows.map(\.offset), [16, 32, 16, 0])
        assertRule(result.rows[0].rules[19], .offset(-8))
        assertRule(result.rows[1].rules[19], .undefined)
        assertRule(result.rows[2].rules[19], .offset(-8))
        assertRule(result.rows[3].rules[19], .same)
    }

    func testSnapshotsAndPreviouslyEmittedRowsDoNotAliasRuleDictionaries() throws {
        var result = try fde([
            op(10), op(7, [19]), op(2, [4]), op(11), op(2, [4]), op(0x93, [19, 3])
        ])
        assertRule(result.rows[0].rules[19], .undefined)
        assertRule(result.rows[1].rules[19], .same)
        assertRule(result.rows[2].rules[19], .offset(-24))
        result.rows[2].rules[19] = .undefined
        assertRule(result.rows[0].rules[19], .undefined)
        assertRule(result.rows[1].rules[19], .same)
    }

    func testSnapshotRestoresAllTwelveRequiredRegisterRules() throws {
        let changes = (19...30).map { op(7, [UInt64($0)]) }
        let result = try fde([op(10)] + changes + [op(2, [4]), op(11)])
        for register in 19...30 {
            assertRule(result.rows[0].rules[register], .undefined)
            assertRule(result.rows[1].rules[register], .same)
        }
    }

    func testPrimaryRegisterRestoreUsesCIEInitialRulesIndependentlyOfStateStack() throws {
        let result = try fde([
            op(7, [19]), op(10), op(0xd3, [19]), op(2, [4]), op(11),
            op(2, [4]), op(0xd3, [19])
        ], initial: [op(12, [31, 0]), op(0x93, [19, 2])])
        XCTAssertEqual(result.rows.map(\.pc), [0x100, 0x104, 0x108])
        assertRule(result.rows[0].rules[19], .offset(-16))
        assertRule(result.rows[1].rules[19], .undefined)
        assertRule(result.rows[2].rules[19], .offset(-16))
    }

    func testRestoreAtSamePCReplacesPendingStateWithoutAddingARow() throws {
        let result = try fde([op(10), op(14, [24]), op(7, [30]), op(11)])
        XCTAssertEqual(result.rows.count, 1)
        XCTAssertEqual(result.rows[0].pc, 0x100)
        XCTAssertEqual(result.rows[0].offset, 0)
        assertRule(result.rows[0].rules[30], .same)
    }

    func testDepth64SucceedsAndDepth65RefusesTheCompleteTable() throws {
        let pushes = Array(repeating: op(10), count: 64)
        let pops = Array(repeating: op(11), count: 64)
        XCTAssertNoThrow(try fde(pushes + pops))
        XCTAssertNoThrow(try fde(pushes))
        assertRefusal(table(pushes + [op(10)]), containing: "state depth")
        XCTAssertNoThrow(try fde(pushes + pops + pushes + pops))
    }

    func testRestoreUnderflowAndSecondPopRefuseTheCompleteTable() {
        assertRefusal(table([op(11)]), containing: "remembered FDE state")
        assertRefusal(table([op(10), op(11), op(11)]), containing: "remembered FDE state")
    }

    func testPendingStateAtFDEEndIsValidAndDoesNotChangeCurrentRecovery() throws {
        let result = try fde([op(14, [16]), op(10), op(14, [32]), op(2, [4])], size: 4)
        XCTAssertEqual(result.rows.map(\.pc), [0x100, 0x104])
        XCTAssertEqual(try result.row(at: 0x100).offset, 32)
        XCTAssertThrowsError(try result.row(at: 0x104))
    }

    func testStateAndCIEInitialRulesDoNotLeakBetweenFDEs() throws {
        var source = table([op(10), op(14, [32]), op(7, [19])])
        var second = source.fdes[0]
        second.sectionOffset = 80
        second.initialLocation = 0x200
        second.program = program([])
        source.fdes.append(second)
        let evaluator = try UnwindAuditCFI(table: source, enableCFIControls: true)
        let row = try evaluator.select(offset: 80, start: 0x200, end: 0x240).row(at: 0x200)
        XCTAssertEqual(row.register, 31)
        XCTAssertEqual(row.offset, 0)
        assertRule(row.rules[19], .same)
        source.fdes[1].program = program([op(11)])
        assertRefusal(source, containing: "remembered FDE state")
    }

    func testEveryAdvanceMayReachExactEndButEndIsNotAnObservation() throws {
        for opcode in [UInt8(0x44), 2, 3, 4] {
            let result = try fde([op(opcode, [4]), op(14, [16])], size: 4)
            XCTAssertEqual(result.rows.map(\.pc), [0x100, 0x104])
            XCTAssertEqual(try result.row(at: 0x100).offset, 0)
            XCTAssertThrowsError(try result.row(at: 0x104))
            XCTAssertThrowsError(try result.row(at: 0xfc))
        }
    }

    func testAllAdvancesRejectZeroMisalignmentAndOutOfRange() {
        for opcode in [UInt8(2), 3, 4] {
            for delta in [UInt64(0), 1, 3, 8] { assertRefusal(table([op(opcode, [delta])], size: 4)) }
        }
        for (opcode, delta) in [(UInt8(0x40), UInt64(0)), (0x41, 1), (0x43, 3), (0x48, 8)] {
            assertRefusal(table([op(opcode, [delta])], size: 4))
        }
    }

    func testAllAdvanceFormsRejectUInt64WrapAndAcceptLastRepresentableGridPoint() throws {
        let start = UInt64.max - 7
        for opcode in [UInt8(0x48), 2, 3, 4] {
            assertRefusal(table([op(opcode, [8])], start: start, size: 4))
        }
        let result = try fde([op(4, [4])], start: start, size: 4)
        XCTAssertEqual(result.rows.last?.pc, UInt64.max - 3)
        assertRefusal(table([], start: UInt64.max - 3, size: 4))
    }

    func testFixedAdvanceOperandShapeTypeAndWidthAreValidated() {
        for (opcode, maximum) in [(UInt8(2), UInt64(UInt8.max)), (3, UInt64(UInt16.max)), (4, UInt64(UInt32.max))] {
            var malformed = op(opcode)
            let operandCases: [[DWARFStructuredCFAOperand]] = [
                [], [.unsigned(4), .unsigned(0)], [.signed(4)], [.signed(-4)],
                [.block([4])], [.unsigned(maximum + 1)]
            ]
            for operands in operandCases {
                malformed.operands = operands
                assertRefusal(table([malformed], size: 0x1_0000_0004))
            }
        }
    }

    func testStateControlsDoNotAcceptOperands() {
        assertRefusal(table([op(10, [0])]))
        assertRefusal(table([op(10), op(11, [0])]))
    }

    func testCIERejectsEveryAdvanceAndStateControlWithOrWithoutPriorCFA() {
        let controls = [op(0x44, [4]), op(2, [4]), op(3, [4]), op(4, [4]), op(10), op(11)]
        for control in controls {
            assertRefusal(table([], initial: [op(12, [31, 0]), control]))
            assertRefusal(table([], initial: [control, op(12, [31, 0])]))
        }
    }

    func testCIECodeAlignmentGateStillRequiresExactlyOne() {
        var source = table([op(2, [4])])
        for alignment in [UInt64(0), 2, UInt64.max] {
            source.cies[0].codeAlignmentFactor = alignment
            assertRefusal(source)
        }
    }

    func testMalformedUnsupportedOrLateUnknownProgramCannotPublishPrefix() {
        var source = table([op(2, [4]), op(10), op(11)])
        for status in [DWARFStructuredCFADecodeStatus.malformed(offset: 99), .unsupported(opcode: 0x3f)] {
            source.fdes[0].program.status = status
            assertRefusal(source)
        }
        assertRefusal(table([op(2, [4]), op(10), op(11), op(0x3f)]))
        assertRefusal(table([op(2, [4]), op(11)], size: 4))
        assertRefusal(table([op(2, [4]), op(10), op(11), op(15)], size: 4))
    }

    func testRestorationCannotHideAnUnsupportedInterveningEffect() {
        let effects = [op(7, [18]), op(8, [31]), op(13, [28]), op(12, [32, 0]),
                       op(14, [UInt64(Int64.max) + 1]), op(0x93, [19, UInt64.max])]
        for effect in effects { assertRefusal(table([op(10), effect, op(11)])) }
    }

    func testFailureInAnUnselectedFDEStillRefusesTheWholeTable() {
        var source = table([op(2, [4])])
        var second = source.fdes[0]
        second.sectionOffset = 80
        second.initialLocation = 0x200
        second.program = program([op(2, [4]), op(11)])
        source.fdes.append(second)
        assertRefusal(source)
        source.fdes[1].program = program([op(2, [4]), op(0x3f)])
        assertRefusal(source)
    }

    func testControlOperationsConsumeTheSharedTableInstructionBudget() throws {
        // CIE: 1; first FDE: 100,000 pushes/pops; second FDE: 99,999 NOPs.
        let pairs = Array(repeating: [op(10), op(11)], count: 50_000).flatMap { $0 }
        var source = table(pairs)
        var second = source.fdes[0]
        second.sectionOffset = 80
        second.initialLocation = 0x200
        second.program = program(Array(repeating: op(0), count: 99_999))
        source.fdes.append(second)
        XCTAssertNoThrow(try UnwindAuditCFI(table: source, enableCFIControls: true))
        source.fdes[1].program = program(source.fdes[1].program.operations + [op(10)])
        assertRefusal(source, containing: "instruction budget")
    }

    func testFixedAdvancesConsumeTheSharedTableRowBudget() throws {
        // CIE: 1 row; FDEs: 25,000 and 24,999 rows, including each final row.
        var source = table(Array(repeating: op(2, [4]), count: 24_999), size: 100_000)
        var second = source.fdes[0]
        second.sectionOffset = 80
        second.initialLocation = 0x10_0000
        second.program = program(Array(repeating: op(2, [4]), count: 24_998))
        source.fdes.append(second)
        XCTAssertNoThrow(try UnwindAuditCFI(table: source, enableCFIControls: true))
        source.fdes[1].program = program(source.fdes[1].program.operations + [op(2, [4])])
        assertRefusal(source, containing: "row budget")
    }

    func testControlModelStillRejectsMOVKAtDecodeAndExecution() throws {
        let bytes = Data([0xe0, 0xdd, 0x97, 0xf2, 0xc0, 0x03, 0x5f, 0xd6])
        XCTAssertThrowsError(try UnwindAuditInstruction.decode(data: bytes, start: 0x1000,
            maximum: 2, model: .boundedCFIControls)) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, "unsupported_instruction")
        }
        let admitted = try UnwindAuditInstruction.decode(data: bytes, start: 0x1000,
            maximum: 2, model: .boundedLoopCallsMOVK)
        XCTAssertThrowsError(try UnwindAuditExecution.run(instructions: admitted, mode: "frameless",
            calleeEntries: [], limits: .init(), model: .boundedCFIControls) { _, _ in [:] }) { error in
            XCTAssertEqual((error as? UnwindAuditModelError)?.code, "unsupported_instruction")
        }
    }
}
