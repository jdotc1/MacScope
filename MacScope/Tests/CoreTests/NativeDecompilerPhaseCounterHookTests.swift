// Authored, unrun.
import Foundation
import XCTest
@testable import MacScope

#if DEBUG
@MainActor
final class NativeDecompilerPhaseCounterHookTests: XCTestCase {
    private typealias Record = NativeDecompilerPhaseRecord
    private let newCounters: [Record.Counter] = [
        .facetMemoHits, .facetMemoMisses, .xrefsVisited,
        .blocksVisited, .overridesVisited, .functionsConsidered,
    ]

    // Group A: requires FIX only. Every capture checks F9's two clock reads.
    func testBlocksVisitedDiffersFromMatches() throws {
        let small = blockFixture(matches: 3, bytes: 12)
        let (_, admitted) = try capture { try sizeCheck(small) }
        expect(admitted, [.blocksVisited: 5])
        let large = blockFixture(matches: 8_193, bytes: 32_772)
        let (_, refused) = try capture {
            XCTAssertThrowsError(try sizeCheck(large)) {
                XCTAssertEqual($0 as? DecompileBudgetRefusal, .tooLarge(bytes: 32_772, blocks: 8_193))
            }
        }
        expect(refused, [.blocksVisited: 8_195])
    }

    func testBlocksVisitedOnCancellation() throws {
        let fixture = blockFixture(matches: 2_047, bytes: 32_772)
        var checkpoints = 0
        let (_, summary) = try capture {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.decompileSizeCheck(
                fixture.0, in: .primary, snapshot: fixture.1, checkpoint: {
                    checkpoints += 1
                    if checkpoints == 2 { throw CancellationError() }
                })) { XCTAssertTrue($0 is CancellationError) }
        }
        XCTAssertEqual(checkpoints, 2)
        expect(summary, [.blocksVisited: 2_048]) // 2,046 matches; two outside rows precede them.
    }

    func testBlocksVisitedOnTailCancellation() throws {
        let fixture = blockFixture(matches: 3, bytes: 12)
        let (_, summary) = try capture {
            XCTAssertThrowsError(try WorkspaceScriptingAPI.decompileSizeCheck(
                fixture.0, in: .primary, snapshot: fixture.1,
                checkpoint: { throw CancellationError() })) { XCTAssertTrue($0 is CancellationError) }
        }
        expect(summary, [.blocksVisited: 5])
    }

    func testOverridesVisitedEmptyAndNoComment() throws {
        let fixture = blockFixture(matches: 3, bytes: 12)
        var checkpoints = 0
        let (found, summary) = try capture {
            try WorkspaceScriptingAPI.functionHasUserComments(
                fixture.0, in: .primary, snapshot: fixture.1, checkpoint: { checkpoints += 1 })
        }
        XCTAssertFalse(found)
        XCTAssertEqual(checkpoints, 0)
        expect(summary, [.overridesVisited: 0])
        // F7 is intentionally not authored: AddressOverride's complete initializer is absent (O5).
    }

    func testCountersFollowObservedRule() throws {
        XCTAssertEqual(Record.Counter.visitedCalls.rawValue, 28)
        XCTAssertEqual(newCounters.map(\.rawValue), Array(29...34))
        XCTAssertEqual(Record.Counter.allCases.count, 35)
        let (_, absent) = try capture {}
        expect(absent, [:])
        let (_, zero) = try capture { for counter in newCounters { Record.current()?.add(counter, 0) } }
        expect(zero, Dictionary(uniqueKeysWithValues: newCounters.map { ($0, UInt64(0)) }))
        let (_, added) = try capture {
            for counter in newCounters { Record.current()?.add(counter, 2); Record.current()?.add(counter, 3) }
        }
        expect(added, Dictionary(uniqueKeysWithValues: newCounters.map { ($0, UInt64(5)) }))
    }

    func testNoExtraClockReads() throws {
        let binary = self.binary(), analysis = self.analysis(), fixture = blockFixture(matches: 3, bytes: 12)
        let (_, summary) = try capture {
            _ = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
            try sizeCheck(fixture)
            _ = try comments(fixture)
        }
        expect(summary, [.blocksVisited: 5, .overridesVisited: 0])
    }

    func testResultsEqualWithAndWithoutTrace() throws {
        let binary = self.binary(), analysis = self.analysis()
        let offFingerprint = try Record.withTrace(nil) {
            try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
        }
        let (onFingerprint, _) = try capture { try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis) }
        XCTAssertEqual(offFingerprint, onFingerprint)
        for fixture in [blockFixture(matches: 3, bytes: 12), blockFixture(matches: 8_193, bytes: 32_772)] {
            let off = try Record.withTrace(nil) { try sizeOutcome(fixture) }
            let (on, _) = try capture { try sizeOutcome(fixture) }
            XCTAssertEqual(off, on)
            XCTAssertEqual(off?.errorDescription, on?.errorDescription)
            let offComments = try Record.withTrace(nil) { try comments(fixture) }
            let (onComments, _) = try capture { try comments(fixture) }
            XCTAssertEqual(offComments, onComments)
        }
    }

    func testHooksWithoutTraceLeaveRecordUntouched() throws {
        let binary = self.binary(), analysis = self.analysis(), fixture = blockFixture(matches: 3, bytes: 12)
        let (_, summary) = try capture(install: false) {
            _ = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
            try sizeCheck(fixture)
            _ = try comments(fixture)
        }
        XCTAssertTrue(summary.counterObserved.allSatisfy { !$0 })
        XCTAssertTrue(summary.counts.allSatisfy { $0 == 0 })
    }

    // Group B: both assertions are intentionally red with FIX alone; requires W3 and W4.
    func testFunctionsConsidered() throws {
        let fixture = blockFixture(matches: 3, bytes: 12)
        let functions = try XCTUnwrap(fixture.1.analysis(in: .primary)).functions
        let (named, nameSummary) = try capture {
            try WorkspaceScriptingAPI.resolveFunctionName("target", in: functions) { $0.name }
        }
        XCTAssertEqual(named, fixture.0)
        expect(nameSummary, [.functionsConsidered: 2]) // One matching name, two considered.
        let (addressed, addressSummary) = try capture {
            try WorkspaceScriptingAPI.resolveFunction(.object(["address": .hex(0x1000)]), fixture.1)
        }
        XCTAssertEqual(addressed, fixture.0)
        expect(addressSummary, [.functionsConsidered: 2]) // One containing function, two considered.
    }

    private func capture<T>(install: Bool = true, _ body: () throws -> T) throws -> (T, Record.Summary) {
        let probe = CounterHookProbe()
        let record = Record(clock: { probe.read() }, sink: { probe.append($0) })
        let result = Result { try Record.withTrace(install ? record : nil, operation: body) }
        record.finish()
        XCTAssertEqual(probe.readCount, 2)
        let summary = try XCTUnwrap(probe.values.first)
        XCTAssertEqual(probe.values.count, 1)
        XCTAssertEqual(summary.elapsedNanoseconds, 10)
        XCTAssertEqual(summary.coveredNanoseconds, 0)
        XCTAssertEqual(summary.residualNanoseconds, 10)
        XCTAssertTrue(summary.completedSpans.allSatisfy { $0 == 0 })
        return (try result.get(), summary)
    }

    private func expect(_ summary: Record.Summary, _ observed: [Record.Counter: UInt64],
                        file: StaticString = #filePath, line: UInt = #line) {
        for counter in newCounters {
            XCTAssertEqual(summary.counterObserved[counter.rawValue], observed[counter] != nil, file: file, line: line)
            XCTAssertEqual(summary.counts[counter.rawValue], observed[counter] ?? 0, file: file, line: line)
        }
    }

    private func binary() -> BinaryImage {
        BinaryImage(id: UUID(), name: "counter-fixture", path: "/fixture/counters",
                    kind: "Mach-O executable", architecture: "arm64", slot: .primary)
    }

    private func analysis(instructions: Int = 2, xrefs: Int = 0) -> ImageAnalysis {
        var result = ImageAnalysis()
        result.imageBytes = Data([0, 1, 2, 3, 4, 5])
        result.instructions = (0..<instructions).map {
            InstructionRow(address: 0x1000 + UInt64($0) * 4, bytes: "1f 20 03 d5", mnemonic: "nop",
                           operands: "", hasBreakpoint: false, comment: nil)
        }
        result.xrefs = (0..<xrefs).map {
            XRef(id: UUID(), from: 0x1000 + UInt64($0) * 4, to: 0x8000, kind: XRefKind.data)
        }
        return result
    }

    private func blockFixture(matches: Int, bytes: UInt64) -> (FunctionSummary, WorkspaceSnapshot) {
        let function = FunctionSummary(id: UUID(), name: "target", startAddress: 0x1000,
                                       endAddress: 0x1000 + bytes, confidence: 1)
        var analysis = ImageAnalysis()
        analysis.functions = [function, FunctionSummary(id: UUID(), name: "other", startAddress: 0x100000,
                                                       endAddress: 0x100004, confidence: 1)]
        let starts: [UInt64] = [0, 4] + (0..<matches).map { 0x1000 + UInt64($0) * 4 }
        analysis.basicBlocks = starts.map {
            BasicBlockSummary(id: UUID(), functionID: function.id, startAddress: $0,
                              endAddress: $0 + 4, instructionCount: 1)
        }
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: binary(), analysis: analysis)
        return (function, snapshot)
    }

    private func sizeCheck(_ fixture: (FunctionSummary, WorkspaceSnapshot)) throws {
        try WorkspaceScriptingAPI.decompileSizeCheck(fixture.0, in: .primary, snapshot: fixture.1, checkpoint: {})
    }

    private func sizeOutcome(_ fixture: (FunctionSummary, WorkspaceSnapshot)) throws -> DecompileBudgetRefusal? {
        do { try sizeCheck(fixture); return nil }
        catch let refusal as DecompileBudgetRefusal { return refusal }
    }

    private func comments(_ fixture: (FunctionSummary, WorkspaceSnapshot)) throws -> Bool {
        try WorkspaceScriptingAPI.functionHasUserComments(fixture.0, in: .primary, snapshot: fixture.1, checkpoint: {})
    }
}
#endif

private final class CounterHookProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0
    private var summaries: [NativeDecompilerPhaseRecord.Summary] = []
    var readCount: Int { lock.withLock { reads } }
    var values: [NativeDecompilerPhaseRecord.Summary] { lock.withLock { summaries } }
    func read() -> UInt64 { lock.withLock { reads += 1; return UInt64(reads) * 10 } }
    func append(_ summary: NativeDecompilerPhaseRecord.Summary) { lock.withLock { summaries.append(summary) } }
}
