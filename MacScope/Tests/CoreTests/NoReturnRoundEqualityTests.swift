import Foundation
import XCTest
@testable import MacScope

// T3 complete document and round guards, F3. Authored, unrun. Propagation iterations are NOT
// confused with outer discovery repeats. Exact 0/1/2 and cross-section 3 traces below.
final class NoReturnRoundEqualityTests: XCTestCase {
    override class func tearDown() {
        XCTAssertNoThrow(try ReadyCanonicalGoldens.finish(ReadyCanonicalGoldens.noReturnIDs))
        super.tearDown()
    }
    @MainActor
    func testGuardAuthoredNoReturnSignatureSurvivesAnalysis() throws {
        let fixture = TinyMachO.make(code: Data([0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]))
        let url = try fixture.write()
        defer { try? FileManager.default.removeItem(at: url) }
        let engine = AnalysisEngine()
        let store = WorkspaceStore(workspaceName: "ready-authored-signature",
            snapshot: try engine.analyze(url: url), engine: engine)
        for state in ["noReturn", "returns"] {
            _ = try WorkspaceScriptingAPI(store: store).execute("set-signature", arguments: .object([
                "address": .hex(fixture.baseAddress), "noReturnState": .string(state)]))
            let overrides = store.snapshot.primaryOverrides
            XCTAssertEqual(overrides[fixture.baseAddress]?.signature?.noReturnState.rawValue, state)
            let new = try engine.analyze(url: url, overrides: overrides)
            XCTAssertEqual(new.primaryOverrides[fixture.baseAddress]?.signature?.noReturnState.rawValue, state)
            let inputIDs = try AnalysisSnapshotCanonicalizer.inputUUIDs(in: overrides)
            let id = state == "noReturn" ? "authored-noreturn" : "authored-returns"
            try ReadyCanonicalGoldens.snapshot(id, current: new, sourceURL: url, inputUUIDs: inputIDs)
            // This guards authored signature preservation, not a signature-driven change
            // to discovery's catalog + SDK + propagated known-target set.
        }
    }

    func testGuardThreeProductiveRepeatsAcrossSections() throws {
        var a = ReadyFixture.instructions(count: 1); a[0].flow = .trap
        var b = ReadyFixture.instructions(count: 3)
        var c = ReadyFixture.instructions(count: 3)
        for index in b.indices { b[index].address += 0x1000; c[index].address += 0x2000 }
        b[0].flow = .call; b[0].branchTarget = 0x1000
        c[0].flow = .call; c[0].branchTarget = 0x2004
        for index in [1] {
            b[index].mnemonic = "sub"; b[index].operands = "sp, sp, #0x10"; b[index].flow = .normal
            c[index].mnemonic = "sub"; c[index].operands = "sp, sp, #0x10"; c[index].flow = .normal
        }
        b[2].flow = .trap; c[2].flow = .trap
        let all = a + b + c
        var binary = ReadyFixture.binary(instructions: all)
        binary.functionStarts = [0x1000, 0x2000, 0x3000]
        let sections = [a, b, c].map { rows in
            BinarySection(name: ".text", address: rows[0].address, size: UInt64(rows.count * 4),
                fileOffset: rows[0].address - 0x1000, isExecutable: true)
        }
        binary.sections = sections
        binary.executableTextSection = sections[0]
        func trace(_ store: DiscoveryPreparationStore) -> ([[UInt64]], [[FunctionSummary]], [[UInt64]]) {
            let engine = AnalysisEngine()
            var known: Set<UInt64> = []
            var sets: [[UInt64]] = []; var functions: [[FunctionSummary]] = []
            var derivedSets: [[UInt64]] = []
            for round in 0...3 {
                let result = [a, b, c].enumerated().flatMap { ordinal, rows in
                    engine.functionSummariesForTesting(from: binary, codeSection: sections[ordinal],
                        decodedInstructions: rows, noReturnTargets: known, preparation: store, sectionOrdinal: ordinal)
                }
                sets.append(known.sorted()); functions.append(result)
                if round == 3 { break }
                let derived = NoReturnAnalysis.propagate(functions: result, instructions: all, known: known)
                derivedSets.append(derived.sorted())
                XCTAssertFalse(derived.isEmpty)
                known.formUnion(derived)
            }
            return (sets, functions, derivedSets)
        }
        let cached = trace(DiscoveryPreparationStore()), uncached = trace(DiscoveryPreparationStore(entryLimit: 0))
        XCTAssertEqual(cached.0, uncached.0); XCTAssertEqual(cached.1, uncached.1)
        XCTAssertEqual(cached.2, uncached.2)
        XCTAssertEqual(cached.2, [[0x1000, 0x2000, 0x3000], [0x2004], [0x3004]])
        XCTAssertEqual(cached.0, [[], [0x1000, 0x2000, 0x3000],
            [0x1000, 0x2000, 0x2004, 0x3000], [0x1000, 0x2000, 0x2004, 0x3000, 0x3004]])
        XCTAssertEqual(cached.1.last?.map(\.startAddress), [0x1000, 0x2000, 0x2004, 0x3000, 0x3004])
        let new = try AnalysisEngine(loader: ReadyFixture.Loader(binary: binary),
            decoder: ReadyFixture.Decoder(rows: all)).analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        XCTAssertEqual(new.functions.map(\.noReturnProvenance), Array(repeating: .propagated, count: 5))
        XCTAssertFalse(new.basicBlocks.isEmpty)
        XCTAssertFalse(new.controlFlowEdges.isEmpty)
        try ReadyCanonicalGoldens.snapshot("repeats-three", current: new)
    }

    func testGuardConditionalReturnAndDataGapPreventPromotion() {
        var rows = ReadyFixture.instructions(count: 3)
        rows[0].flow = .conditionalJump; rows[0].branchTarget = 0x1008
        rows[2].flow = .trap
        let function = FunctionSummary(id: AnalysisStableIdentity.functionID(slot: .primary, startAddress: 0x1000),
            name: "mixed", startAddress: 0x1000, endAddress: 0x100c, confidence: 1)
        XCTAssertEqual(NoReturnAnalysis.propagate(functions: [function], instructions: rows, known: []), [])
        rows[1].flow = .trap
        XCTAssertEqual(NoReturnAnalysis.propagate(functions: [function], instructions: rows, known: []), [0x1000])
        rows[0].flow = .normal; rows[0].branchTarget = nil
        rows.remove(at: 1)
        XCTAssertEqual(rows.map(\.address), [0x1000, 0x1008])
        XCTAssertEqual(NoReturnAnalysis.propagate(functions: [function], instructions: rows, known: []), [])
        rows[0].flow = .call; rows[0].branchTarget = 0x2000
        // An authored no-return fact is supplied as known; its precedence is input to
        // this pass, not inferred from the trap beyond a physically missing row.
        XCTAssertEqual(NoReturnAnalysis.propagate(functions: [function], instructions: rows, known: [0x2000]),
                       [0x1000])
    }

    func testGuardZeroOneAndTwoProductiveDiscoveryRepeats() throws {
        for expectedRepeats in 0...2 {
            var rows = ReadyFixture.instructions(count: 8)
            if expectedRepeats == 1 { rows[0].flow = .trap }
            if expectedRepeats == 2 {
                rows[0].flow = .call; rows[0].branchTarget = 0x1010
                rows[1].mnemonic = "sub"; rows[1].operands = "sp, sp, #0x10"; rows[1].flow = .normal
                rows[2].flow = .trap; rows[4].flow = .trap
            }
            let loaded = ReadyFixture.binary(instructions: rows)
            func trace(_ store: DiscoveryPreparationStore) -> ([[UInt64]], [[FunctionSummary]], [[UInt64]]) {
                let engine = AnalysisEngine()
                var known: Set<UInt64> = []
                var knownTrace: [[UInt64]] = []
                var functionTrace: [[FunctionSummary]] = []
                var derivedTrace: [[UInt64]] = []
                for round in 0...3 {
                    let functions = engine.functionSummariesForTesting(from: loaded,
                        codeSection: loaded.executableTextSection, decodedInstructions: rows,
                        noReturnTargets: known, preparation: store)
                    knownTrace.append(known.sorted()); functionTrace.append(functions)
                    if round == 3 { break }
                    let derived = NoReturnAnalysis.propagate(functions: functions, instructions: rows, known: known)
                    derivedTrace.append(derived.sorted())
                    if derived.isEmpty { break }
                    known.formUnion(derived)
                }
                return (knownTrace, functionTrace, derivedTrace)
            }
            let cached = trace(DiscoveryPreparationStore())
            let uncached = trace(DiscoveryPreparationStore(entryLimit: 0))
            XCTAssertEqual(cached.0, uncached.0)
            XCTAssertEqual(cached.1, uncached.1)
            XCTAssertEqual(cached.2, uncached.2)
            let expectedDerived: [[UInt64]] = expectedRepeats == 0 ? [[]] :
                expectedRepeats == 1 ? [[0x1000], []] : [[0x1000, 0x1010], [0x1004], []]
            XCTAssertEqual(cached.2, expectedDerived)
            XCTAssertEqual(cached.0.count - 1, expectedRepeats)
            let expected: [[UInt64]] = expectedRepeats == 0 ? [[]] :
                expectedRepeats == 1 ? [[], [0x1000]] : [[], [0x1000, 0x1010], [0x1000, 0x1004, 0x1010]]
            XCTAssertEqual(cached.0, expected)
            if expectedRepeats == 2 {
                XCTAssertEqual(cached.1[0].map(\.startAddress), [0x1000, 0x1010])
                XCTAssertEqual(cached.1[1].map(\.startAddress), [0x1000, 0x1004, 0x1010])
            }
            let new = try AnalysisEngine(loader: ReadyFixture.Loader(binary: loaded),
                decoder: ReadyFixture.Decoder(rows: rows)).analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
            let id = ["repeats-zero", "repeats-one", "repeats-two"][expectedRepeats]
            try ReadyCanonicalGoldens.snapshot(id, current: new)
            XCTAssertEqual(new.functions.map(\.noReturnProvenance),
                Array(repeating: expectedRepeats == 0 ? nil : .propagated, count: new.functions.count))
        }
    }

    func testGuardKnownSetsAreRecomputedWhilePreparationIsReused() {
        var rows = ReadyFixture.instructions(count: 8)
        rows[0].flow = .call; rows[0].branchTarget = 0x1010
        rows[1].mnemonic = "sub"; rows[1].operands = "sp, sp, #0x10"; rows[1].flow = .normal
        rows[4].flow = .trap; rows[4].mnemonic = "brk"
        let loaded = ReadyFixture.binary(instructions: rows)
        let cached = DiscoveryPreparationStore()
        let engine = AnalysisEngine()
        let rounds: [Set<UInt64>] = [[], [0x1010], [0x1010, 0x1000], []]
        for known in rounds {
            let a = engine.functionSummariesForTesting(from: loaded,
                codeSection: loaded.executableTextSection, decodedInstructions: rows,
                noReturnTargets: known, preparation: cached)
            let b = engine.functionSummariesForTesting(from: loaded,
                codeSection: loaded.executableTextSection, decodedInstructions: rows,
                noReturnTargets: known, preparation: DiscoveryPreparationStore(entryLimit: 0))
            XCTAssertFalse(a.isEmpty)
            XCTAssertEqual(a, b)
            XCTAssertEqual(NoReturnAnalysis.propagate(functions: a, instructions: rows, known: known),
                           NoReturnAnalysis.propagate(functions: b, instructions: rows, known: known))
        }
        XCTAssertEqual(cached.statistics.decodedAddressBuilds, 1)
    }
    func testGuardChainsPropagateButBareLoopsAndReturnsDoNot() {
        for length in 1...4 {
            var rows = ReadyFixture.instructions(count: length)
            for i in rows.indices {
                rows[i].flow = i == length - 1 ? .trap : .call
                rows[i].branchTarget = i == length - 1 ? nil : rows[i + 1].address
            }
            let functions = rows.map {
                FunctionSummary(id: AnalysisStableIdentity.functionID(slot: .primary, startAddress: $0.address),
                    name: "chain", startAddress: $0.address, endAddress: $0.address + 4, confidence: 1)
            }
            XCTAssertEqual(NoReturnAnalysis.propagate(functions: functions, instructions: rows, known: []),
                           Set(rows.map(\.address)))
        }
        var loop = ReadyFixture.instructions(count: 1)
        let function = FunctionSummary(id: AnalysisStableIdentity.functionID(slot: .primary, startAddress: 0x1000),
            name: "loop", startAddress: 0x1000, endAddress: 0x1004, confidence: 1)
        XCTAssertEqual(NoReturnAnalysis.propagate(functions: [function], instructions: loop, known: []), [])
        loop[0].flow = .jump; loop[0].branchTarget = 0x1000
        XCTAssertEqual(NoReturnAnalysis.propagate(functions: [function], instructions: loop, known: []), [])
    }
    func testGuardCatalogWinsSDKOverlapInCallerSubtraction() {
        let symbol = SymbolSummary(id: UUID(), name: "_abort", address: 0x1000,
            kind: "function", libraryName: nil)
        let catalog = NoReturnAnalysis.catalogTargets(symbols: [symbol], stubNamesByAddress: [:])
        let sdk = NoReturnAnalysis.sdkPackTargets(symbols: [symbol], stubNamesByAddress: [:], noReturnNames: ["abort"])
        XCTAssertEqual(catalog, [0x1000])
        XCTAssertEqual(sdk, [0x1000])
        XCTAssertEqual(sdk.subtracting(catalog), [])
    }
}
