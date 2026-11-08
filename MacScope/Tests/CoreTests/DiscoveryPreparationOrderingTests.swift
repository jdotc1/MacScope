// Authored, unrun.
import Foundation
import XCTest
@testable import MacScope

final class DiscoveryPreparationOrderingTests: XCTestCase {
    private let base: UInt64 = 0x1000

    private func row(_ offset: UInt64, _ mnemonic: String = "nop",
                     _ flow: InstructionFlow = .normal, target: UInt64? = nil,
                     operands: String = "") -> DecodedInstruction {
        DecodedInstruction(address: base + offset, bytes: [0, 0, 0, 0],
            mnemonic: mnemonic, operands: operands, branchTarget: target,
            comment: nil, flow: flow)
    }

    private func recoveryRows() -> [DecodedInstruction] {
        [row(0, "b", .jump, target: base + 20), row(4, "ret", .return),
         row(8, "sub", operands: "sp, sp, #16"), row(12, "ret", .return),
         row(16, "ret", .return), row(20)]
    }

    private func summaries(_ rows: [DecodedInstruction], engine: AnalysisEngine) -> [FunctionSummary] {
        let loaded = ReadyFixture.binary(instructions: rows)
        return engine.functionSummariesForTesting(from: loaded,
            codeSection: loaded.executableTextSection, decodedInstructions: rows,
            preparation: DiscoveryPreparationStore())
    }

    private func pointers(_ rows: [DecodedInstruction], engine: AnalysisEngine) -> Set<UInt64> {
        engine.recoverDataPointerStarts(candidates: [base + 16], from: rows,
            codeStart: base, codeEnd: base + 24, existingStarts: [base],
            decodedInstructionAddresses: Set(rows.map(\.address)), dataAddresses: [])
    }

    private func trampolines(_ rows: [DecodedInstruction], engine: AnalysisEngine) -> Set<UInt64> {
        engine.recoverTrampolineTargets(from: rows, knownStarts: [base],
            codeStart: base, codeEnd: base + 24,
            decodedInstructionAddresses: Set(rows.map(\.address)), dataAddresses: [])
    }

    private func assertCounts(_ recorder: AnalysisAttribution, skipped: Int, run: Int,
                              copies: Int = 0, file: StaticString = #filePath, line: UInt = #line) {
        let counts = recorder.snapshot().counters
        XCTAssertEqual(counts[.sortsSkipped, default: 0], skipped, file: file, line: line)
        XCTAssertEqual(counts[.sortsRun, default: 0], run, file: file, line: line)
        XCTAssertEqual(counts[.sliceCopiesAvoided, default: 0], copies, file: file, line: line)
    }

    func testSortedInputTakesFastPathForAllThreeRecoverers() {
        let recorder = AnalysisAttribution(now: { 0 })
        var engine = AnalysisEngine(); engine.attribution = recorder
        let rows = recoveryRows()
        XCTAssertEqual(summaries(rows, engine: engine).map(\.startAddress),
                       [base, base + 8, base + 20])
        assertCounts(recorder, skipped: 2, run: 0)
        XCTAssertEqual(pointers(rows, engine: engine), [base + 16])
        XCTAssertEqual(trampolines(rows, engine: engine), [base + 20])
        assertCounts(recorder, skipped: 4, run: 0)
    }

    func testShuffledInputMatchesPresortedInput() {
        let ascending = recoveryRows()
        let rows = [ascending[4], ascending[0], ascending[5], ascending[2], ascending[1], ascending[3]]
        let reference = rows.sorted { $0.address < $1.address }
        let recorder = AnalysisAttribution(now: { 0 })
        var engine = AnalysisEngine(); engine.attribution = recorder
        let actual = summaries(rows, engine: engine)
        XCTAssertEqual(actual, summaries(reference, engine: AnalysisEngine()))
        XCTAssertEqual(actual.map(\.startAddress), [base, base + 8, base + 20])
        XCTAssertEqual(pointers(rows, engine: engine), pointers(reference, engine: AnalysisEngine()))
        XCTAssertEqual(pointers(reference, engine: AnalysisEngine()), [base + 16])
        XCTAssertEqual(trampolines(rows, engine: engine), trampolines(reference, engine: AnalysisEngine()))
        XCTAssertEqual(trampolines(reference, engine: AnalysisEngine()), [base + 20])
        assertCounts(recorder, skipped: 0, run: 4)
    }

    func testDuplicateAddressesKeepOriginalTieOrder() {
        let rows = [row(0, "b", .jump, target: base + 20), row(0, "nop"),
                    row(4, "ret", .return), row(8), row(12), row(16, "ret", .return), row(20)]
        // Only the original sort and first-entry-wins map are transcribed.
        // Target +20 is decoded, in bounds, unknown and preceded by ret for either winner.
        let sorted = rows.sorted { $0.address < $1.address }
        var first: [UInt64: DecodedInstruction] = [:]
        for instruction in sorted where first[instruction.address] == nil {
            first[instruction.address] = instruction
        }
        let expected: Set<UInt64> = first[base]?.flow == .jump ? [base + 20] : []
        let recorder = AnalysisAttribution(now: { 0 })
        var engine = AnalysisEngine(); engine.attribution = recorder
        XCTAssertEqual(trampolines(rows, engine: engine), expected)
        assertCounts(recorder, skipped: 0, run: 1)
        _ = summaries(rows, engine: engine) // A and C reach their fallback.
        _ = pointers(rows, engine: engine) // B reaches its fallback too.
        assertCounts(recorder, skipped: 0, run: 4)
    }

    func testBoundaryInputsEmptySingleAndTwoRows() {
        let cases: [[DecodedInstruction]] = [[], [row(0, "ret", .return)],
            [row(0, "ret", .return), row(4, "sub", operands: "sp, sp, #16")]]
        let expected: [[UInt64]] = [[], [base], [base, base + 4]]
        for (index, rows) in cases.enumerated() {
            let recorder = AnalysisAttribution(now: { 0 })
            var engine = AnalysisEngine(); engine.attribution = recorder
            let loaded = ReadyFixture.binary(instructions: rows)
            let functions = engine.functionSummariesForTesting(from: loaded,
                codeSection: loaded.executableTextSection, decodedInstructions: rows,
                preparation: DiscoveryPreparationStore())
            XCTAssertEqual(functions.map(\.startAddress), expected[index])
            let starts = engine.recoverDataPointerStarts(candidates: [base], from: rows,
                codeStart: base, codeEnd: base + 8, existingStarts: [],
                decodedInstructionAddresses: Set(rows.map(\.address)), dataAddresses: [])
            XCTAssertEqual(starts, rows.isEmpty ? [] : [base])
            assertCounts(recorder, skipped: rows.isEmpty ? 0 : 3, run: 0)
        }
    }

    func testSliceOverloadsEqualArrayOverloadsAtNonZeroBase() throws {
        var rows = [row(100), row(104), row(108)] + recoveryRows()
        rows[7].mnemonic = "unavailable"
        rows[5].flow = .call; rows[5].branchTarget = base + 16
        let slice = rows[3..<9]
        let copy = Array(rows[3..<9]) // Original per-section copy reference.
        XCTAssertEqual(slice.startIndex, 3)
        let addresses = Set(copy.map(\.address))
        for budget in [0, 18] {
            let borrowed = DiscoveryPreparationStore(entryLimit: budget)
            let owned = DiscoveryPreparationStore(entryLimit: budget)
            let left = borrowed.prepare(sectionOrdinal: 0, rows: slice,
                codeStart: base, codeEnd: base + 24, existingStarts: [base])
            let right = owned.prepare(sectionOrdinal: 0, instructions: copy,
                codeStart: base, codeEnd: base + 24, existingStarts: [base])
            XCTAssertEqual(left?.decodedAddresses, right?.decodedAddresses)
            XCTAssertEqual(left?.baselineDirectCalls, right?.baselineDirectCalls)
            XCTAssertEqual(borrowed.unavailable(sectionOrdinal: 0, rows: slice),
                           owned.unavailable(sectionOrdinal: 0, instructions: copy))
            if budget == 18 {
                XCTAssertEqual(try XCTUnwrap(left).decodedAddresses, addresses)
                XCTAssertEqual(left?.baselineDirectCalls, [base + 16])
                XCTAssertEqual(borrowed.unavailable(sectionOrdinal: 0, rows: slice), [base + 16])
            } else { XCTAssertNil(left); XCTAssertNil(right) }
        }
        XCTAssertEqual(DiscoveryPreparationStore.directCalls(rows: slice, addresses: addresses,
            codeStart: base, codeEnd: base + 24, existingStarts: [base]),
            DiscoveryPreparationStore.directCalls(instructions: copy, addresses: addresses,
                codeStart: base, codeEnd: base + 24, existingStarts: [base]))
        let engine = AnalysisEngine()
        XCTAssertEqual(engine.recoverDataPointerStarts(candidates: [base + 16], rows: slice,
            codeStart: base, codeEnd: base + 24, existingStarts: [base],
            decodedInstructionAddresses: addresses, dataAddresses: []), pointers(copy, engine: engine))
        XCTAssertEqual(engine.recoverTrampolineTargets(rows: slice, knownStarts: [base],
            codeStart: base, codeEnd: base + 24, decodedInstructionAddresses: addresses,
            dataAddresses: []), trampolines(copy, engine: engine))
        XCTAssertEqual(pointers(copy, engine: engine), [base + 16])
        XCTAssertEqual(trampolines(copy, engine: engine), [base + 20])
    }

    func testFunctionSummariesEqualWithSliceAndArrayAcrossThresholds() {
        for count in [4095, 4096, 4097, 8192] {
            var ascending = ReadyFixture.instructions(count: count)
            ascending[2].mnemonic = "unavailable"
            ascending[4].mnemonic = "sub"
            ascending[4].operands = "sp, sp, #16"
            let loaded = ReadyFixture.binary(instructions: ascending)
            for rows in [ascending, Array(ascending.reversed())] {
                let parent = [row(0), row(0), row(0)] + rows
                let slice = parent[3..<parent.endIndex]
                let copied = Array(slice)
                let sorted = copied.sorted { $0.address < $1.address }
                for budget in [0, DiscoveryPreparationStore.defaultEntryLimit] {
                    let engine = AnalysisEngine()
                    let actual = engine.functionSummariesForTesting(from: loaded,
                        codeSection: loaded.executableTextSection, rows: slice,
                        dataAddresses: [base + 12], procedureAddresses: [base + 4, base + 8, base + 12, base + 1],
                        preparation: DiscoveryPreparationStore(entryLimit: budget))
                    let reference = engine.functionSummariesForTesting(from: loaded,
                        codeSection: loaded.executableTextSection, decodedInstructions: sorted,
                        dataAddresses: [base + 12], procedureAddresses: [base + 4, base + 8, base + 12, base + 1],
                        preparation: DiscoveryPreparationStore(entryLimit: budget))
                    let array = engine.functionSummariesForTesting(from: loaded,
                        codeSection: loaded.executableTextSection, decodedInstructions: copied,
                        dataAddresses: [base + 12], procedureAddresses: [base + 4, base + 8, base + 12, base + 1],
                        preparation: DiscoveryPreparationStore(entryLimit: budget))
                    XCTAssertEqual(actual, reference)
                    XCTAssertEqual(actual, array)
                    XCTAssertEqual(actual.map(\.startAddress), [base, base + 4, base + 16])
                }
            }
        }
    }

    func testAnalyzeTakesFastPathOnAscendingFixture() throws {
        let rows = ReadyFixture.instructions(count: 6)
        let recorder = AnalysisAttribution(now: { 0 })
        var engine = AnalysisEngine(loader: ReadyFixture.Loader(binary:
            ReadyFixture.binary(instructions: rows)), decoder: ReadyFixture.Decoder(rows: rows))
        engine.attribution = recorder
        _ = try engine.analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        XCTAssertEqual(recorder.snapshot().counters[.discoveryInvocations], 1)
        assertCounts(recorder, skipped: 2, run: 0, copies: 1)
    }

    func testCountersSortsSkippedAndRun() throws {
        let probe = Probe()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        var engine = AnalysisEngine(); engine.attribution = recorder
        let rows = recoveryRows()
        _ = summaries(rows, engine: engine)
        XCTAssertEqual(probe.clockCalls, 4) // Two existing discoveryPrepare intervals.
        _ = summaries(Array(rows.reversed()), engine: engine)
        XCTAssertEqual(probe.clockCalls, 8)
        _ = pointers(rows, engine: engine)
        _ = trampolines(Array(rows.reversed()), engine: engine)
        XCTAssertEqual(probe.clockCalls, 8) // Direct recovery has no intervals.
        assertCounts(recorder, skipped: 3, run: 3)
        let state = recorder.snapshot()
        XCTAssertEqual(state.records.count, 1)
        XCTAssertEqual(state.records.first?.opened, 4)
        XCTAssertEqual(state.records.first?.closed, 4)
        let line = try XCTUnwrap(recorder.summary())
        XCTAssertTrue(line.contains("sortsSkipped=3,sortsRun=3,sliceCopiesAvoided=0"))
        XCTAssertEqual(probe.clockCalls, 8)
    }

    func testCountersSliceCopiesAvoided() throws {
        let rows = ReadyFixture.instructions(count: 6)
        var loaded = ReadyFixture.binary(instructions: rows)
        loaded.sections = [
            BinarySection(name: ".text", address: base, size: 12, fileOffset: 0, isExecutable: true),
            BinarySection(name: ".text.more", address: base + 12, size: 12, fileOffset: 12, isExecutable: true)]
        loaded.executableTextSection = loaded.sections[0]
        loaded.functionStarts = [base, base + 12]
        let probe = Probe()
        let recorder = AnalysisAttribution(now: { probe.tick() })
        var engine = AnalysisEngine(loader: ReadyFixture.Loader(binary: loaded),
                                    decoder: ReadyFixture.Decoder(rows: rows))
        engine.attribution = recorder
        _ = try engine.analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        let state = recorder.snapshot()
        XCTAssertEqual(state.counters[.sections], 2)
        XCTAssertEqual(state.counters[.discoveryInvocations], 1)
        assertCounts(recorder, skipped: 4, run: 0, copies: 2)
        XCTAssertTrue(state.records.allSatisfy { $0.opened == $0.closed })
        XCTAssertEqual(probe.clockCalls, state.records.reduce(0) { $0 + $1.opened + $1.closed })
        let calls = probe.clockCalls
        XCTAssertNotNil(recorder.summary())
        XCTAssertEqual(probe.clockCalls, calls)
    }

    func testDisabledAttributionRecordsNothing() {
        let probe = Probe()
        let available = AnalysisAttribution(now: { probe.tick() })
        var engine = AnalysisEngine(); engine.attribution = nil
        XCTAssertEqual(summaries(recoveryRows(), engine: engine).map(\.startAddress),
                       [base, base + 8, base + 20])
        _ = pointers(recoveryRows(), engine: engine)
        _ = trampolines(recoveryRows(), engine: engine)
        XCTAssertEqual(probe.clockCalls, 0)
        XCTAssertTrue(available.snapshot().records.isEmpty)
        XCTAssertTrue(available.snapshot().counters.isEmpty)
    }

    private class Probe: @unchecked Sendable {
        private let lock = NSLock()
        private var calls = 0
        func tick() -> UInt64 {
            lock.lock(); defer { lock.unlock() }
            calls += 1
            return UInt64(calls) * 10
        }
        var clockCalls: Int { lock.lock(); defer { lock.unlock() }; return calls }
    }
}
