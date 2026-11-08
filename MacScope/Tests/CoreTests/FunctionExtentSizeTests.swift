import Foundation
import XCTest
@testable import MacScope

/// Oversized extents are advisory frontier items, independent of start proof and run completion.
@MainActor
final class FunctionExtentSizeTests: XCTestCase {
    private func fixture() -> (bytes: Data, base: UInt64) {
        var value = MachOFixture.makeExecutableWithFunctionStarts()
        let offset = (value.codeOffset + value.code.count + 7) & ~7
        precondition(value.bytes[value.bytes.startIndex + offset + 2] == 0x1c)
        value.bytes[value.bytes.startIndex + offset + 2] = 0
        return (value.bytes, value.baseAddress)
    }

    private func function(_ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: "fixture", startAddress: start, endAddress: end, confidence: 1)
    }

    private func generation() -> NavigatorGeneration {
        NavigatorGeneration(imageIdentity: "fixture", inputKey: "input", knowledgeVersion: "knowledge")
    }

    private func input(bytes: Data, functions: [FunctionSummary]) -> NavigatorProofProducerInput {
        NavigatorProofProducerInput(
            runID: UUID(), slot: .primary, imageBytes: bytes, identity: nil,
            generation: generation(),
            fence: NavigatorLandingFence(documentInstallationID: UUID(), workspaceEpoch: 0,
                                         landingEpoch: 0, binaryID: nil),
            functions: functions)
    }

    private func results(_ outcome: NavigatorProofProducerOutcome) -> [NavigatorPrimitiveResult] {
        guard case .landed(let results, _, _, let refusals) = outcome else {
            XCTFail("expected landed, got \(outcome)")
            return []
        }
        XCTAssertTrue(refusals.isEmpty, "\(refusals)")
        return results
    }

    private func sizeItems(_ results: [NavigatorPrimitiveResult]) -> [NavigatorFrontierItem] {
        results.flatMap(\.frontier).filter {
            $0.gap == "boundaryUncertain" && $0.detail.hasSuffix("; extent boundary is uncertain")
        }
    }

    private func detail(_ start: UInt64, _ extent: UInt64) -> String {
        "\(NavigatorSubjectRef.address(start)): extent \(extent) bytes exceeds 65536 bytes; extent boundary is uncertain"
    }

    func testOneByteAboveThresholdAddsExactItem() throws {
        let f = fixture()
        let request = input(bytes: f.bytes, functions: [function(f.base, f.base + 65_537)])
        let output = results(NavigatorStateBridge.runProofProducer(request, clock: { 0 }))
        let item = try XCTUnwrap(sizeItems(output).first)
        XCTAssertEqual(sizeItems(output).count, 1)
        XCTAssertEqual(item.subject.ref, NavigatorSubjectRef.function(entry: f.base))
        XCTAssertEqual(item.detail, detail(f.base, 65_537))
        XCTAssertEqual(item.cost, ["bytes": 65_537])
        XCTAssertEqual(item.generation, request.generation)
        XCTAssertEqual(item.dependsOn, NavigatorStateBridge.derivationDependsOn.uniqueSortedByScalars())
        XCTAssertTrue(item.blockedBy.isEmpty)
        XCTAssertTrue(NavigatorContractValidator.validateFrontier(item.json).isEmpty)
        for result in output {
            XCTAssertTrue(NavigatorContractValidator.validateResult(result.json).isEmpty)
        }
    }

    func testThresholdAndSmallerExtentAddNoSizeItems() {
        let f = fixture()
        let request = input(bytes: f.bytes, functions: [
            function(f.base, f.base + 65_536),
            function(f.base + 0x1c, f.base + 0x1c + 1_000)
        ])
        let output = results(NavigatorStateBridge.runProofProducer(request, clock: { 0 }))
        XCTAssertTrue(sizeItems(output).isEmpty)
    }

    func testProvenStartAndOverlappingExtentDisclosureCoexist() throws {
        let f = fixture()
        let request = input(bytes: f.bytes, functions: [
            function(f.base, f.base + 65_537),
            function(f.base + 0x1c, f.base + 0x20)
        ])
        let outcome = NavigatorStateBridge.runProofProducer(request, clock: { 0 })
        let output = results(outcome)
        let proof = try XCTUnwrap(output.first { $0.primitive == FunctionStartStructuralProof.rule })
        let fact = try XCTUnwrap(proof.facts.first { $0.subject.ref == NavigatorSubjectRef.function(entry: f.base) })
        XCTAssertEqual(fact.predicate, "isFunctionStart")
        XCTAssertEqual(fact.value, .bool(true))
        XCTAssertEqual(fact.status, "proven")
        let item = try XCTUnwrap(sizeItems(output).first)
        XCTAssertEqual(sizeItems(output).count, 1)
        XCTAssertEqual(item.subject, fact.subject)
        XCTAssertEqual(item.detail, detail(f.base, 65_537))
        XCTAssertFalse(item.detail.contains("no function start inside"))
        XCTAssertTrue(output.flatMap(\.facts).contains {
            $0.subject.ref == NavigatorSubjectRef.function(entry: f.base + 0x1c)
                && $0.status == "derived"
        })
        guard case .landed(_, let certificates, _, _) = outcome else { return XCTFail("expected landed") }
        XCTAssertTrue(certificates.contains { $0.supports(fact) })
    }

    func testExpiredClockStillAddsSizeAndBudgetItems() throws {
        let f = fixture()
        let request = input(bytes: f.bytes, functions: [function(f.base, f.base + 65_537)])
        var reads = 0
        let outcome = NavigatorStateBridge.runProofProducer(request, clock: {
            reads += 1
            return reads == 1 ? 0 : 2_001
        })
        let output = results(outcome)
        let proof = try XCTUnwrap(output.first { $0.primitive == FunctionStartStructuralProof.rule })
        XCTAssertTrue(proof.facts.isEmpty)
        XCTAssertEqual(proof.outcome, "narrowed")
        XCTAssertEqual(sizeItems(output).map(\.detail), [detail(f.base, 65_537)])
        XCTAssertEqual(proof.frontier.filter { $0.gap == "budgetExceeded" }.count, 1)
        XCTAssertEqual(proof.frontier.count, 2)
        XCTAssertTrue(NavigatorContractValidator.validateResult(proof.json).isEmpty)
    }

    func testMaximumExtentPerStartAndOrderAreDeterministic() throws {
        let f = fixture()
        let evidence = try XCTUnwrap(NavigatorImageEvidence(slice: f.bytes, image: nil))
        let functions = [
            function(f.base + 0x1c, f.base + 0x1c + 80_000),
            function(f.base, f.base + 70_000),
            function(f.base, f.base + 65_537),
            function(f.base, f.base + 70_000)
        ]
        let forward = NavigatorStateBridge.oversizedExtentItems(
            functions: functions, evidence: evidence, toolchain: "test", generation: generation())
        let reversed = NavigatorStateBridge.oversizedExtentItems(
            functions: Array(functions.reversed()), evidence: evidence, toolchain: "test", generation: generation())
        XCTAssertEqual(forward, reversed)
        XCTAssertEqual(forward.map(\.detail), [detail(f.base, 70_000), detail(f.base + 0x1c, 80_000)])
        XCTAssertEqual(Set(forward.map(\.id)).count, 2)
        XCTAssertEqual(forward.map { $0.cost["bytes"] }, [70_000, 80_000])
    }

    func testZeroAndInvertedExtentsAreSkippedWithoutSubtraction() throws {
        let f = fixture()
        let evidence = try XCTUnwrap(NavigatorImageEvidence(slice: f.bytes, image: nil))
        let items = NavigatorStateBridge.oversizedExtentItems(
            functions: [function(0, 0), function(UInt64.max, 0), function(UInt64.max, UInt64.max)],
            evidence: evidence, toolchain: "test", generation: generation())
        XCTAssertTrue(items.isEmpty)
    }

    func testUInt64MaximumExtentKeepsExactDetailAndSaturatesCost() throws {
        let f = fixture()
        let evidence = try XCTUnwrap(NavigatorImageEvidence(slice: f.bytes, image: nil))
        let items = NavigatorStateBridge.oversizedExtentItems(
            functions: [function(0, UInt64.max)], evidence: evidence,
            toolchain: "test", generation: generation())
        let item = try XCTUnwrap(items.first)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(item.detail,
            NavigatorSubjectRef.address(0) + ": extent 18446744073709551615 bytes exceeds 65536 bytes; extent boundary is uncertain")
        XCTAssertEqual(item.cost["bytes"], Int64.max)
        XCTAssertTrue(NavigatorContractValidator.validateFrontier(item.json).isEmpty)
    }

    func testSmallFixtureStillProvesAndDerivesWithoutSizeDisclosure() throws {
        let f = fixture()
        let request = input(bytes: f.bytes, functions: [
            function(f.base, f.base + 0x1c), function(f.base + 0x1c, f.base + 0x20)
        ])
        let output = results(NavigatorStateBridge.runProofProducer(request, clock: { 0 }))
        XCTAssertEqual(output.map(\.primitive),
            [FunctionStartStructuralProof.rule, FunctionStartCallTargetDerivation.rule])
        XCTAssertTrue(sizeItems(output).isEmpty)
        let proof = try XCTUnwrap(output.first)
        XCTAssertTrue(proof.frontier.isEmpty)
        XCTAssertEqual(proof.facts.count, 1)
        XCTAssertEqual(proof.facts.first?.status, "proven")
        let derived = try XCTUnwrap(output.last)
        XCTAssertTrue(derived.frontier.isEmpty)
        XCTAssertEqual(derived.facts.count, 1)
        XCTAssertEqual(derived.facts.first?.status, "derived")
    }

    func testUnparseableSliceStillSkipsEvenWithOversizedSummary() {
        let request = input(bytes: Data(repeating: 0xff, count: 64),
                            functions: [function(0, 65_537)])
        guard case .skipped(let reason) = NavigatorStateBridge.runProofProducer(request, clock: { 0 }) else {
            return XCTFail("invalid evidence must not manufacture frontier items")
        }
        XCTAssertEqual(reason, "slice does not parse as a thin Mach-O image")
    }

    func testUnprovedStartKeepsItsOriginalUncertaintyBesideTheSizeItem() throws {
        let f = fixture()
        let start = f.base + 1
        let output = results(NavigatorStateBridge.runProofProducer(
            input(bytes: f.bytes, functions: [function(start, start + 65_537)]), clock: { 0 }))
        let proof = try XCTUnwrap(output.first { $0.primitive == FunctionStartStructuralProof.rule })
        XCTAssertTrue(proof.facts.isEmpty)
        XCTAssertEqual(proof.frontier.count, 2)
        XCTAssertEqual(sizeItems(output).map(\.detail), [detail(start, 65_537)])
        let original = proof.frontier.filter { !$0.detail.hasSuffix("; extent boundary is uncertain") }
        XCTAssertEqual(original.count, 1)
        XCTAssertEqual(original.first?.gap, "boundaryUncertain")
        XCTAssertTrue(original.first?.missingEvidence.contains("alignment") == true)
    }

    func testSizeDisclosureLandsWithTheProvenFact() throws {
        let f = fixture()
        let binary = BinaryImage(id: UUID(), name: "fixture", path: "/not-opened/fixture",
                                 kind: "raw fixture", architecture: "arm64")
        let store = WorkspaceStore(workspaceName: "extent landing",
            snapshot: .init(binaries: [binary], analysisBySlot: [.primary: ImageAnalysis()]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        var request = input(bytes: f.bytes, functions: [function(f.base, f.base + 65_537)])
        request.fence = store.navigatorLandingFence(for: .primary)
        let outcome = NavigatorStateBridge.runProofProducer(request, clock: { 0 })
        store.navigatorProducerRunsBySlot[.primary] = NavigatorProducerRun(id: request.runID, task: Task {})
        store.landNavigatorProofOutcome(outcome, input: request)
        let state = try XCTUnwrap(store.navigatorState(for: .primary))
        let fact = try XCTUnwrap(state.liveFacts().values.first {
            $0.subject.ref == NavigatorSubjectRef.function(entry: f.base)
        })
        XCTAssertEqual(fact.status, "proven")
        XCTAssertTrue(state.frontier().contains {
            $0.subject == fact.subject && $0.detail == detail(f.base, 65_537)
        })
        XCTAssertTrue(store.navigatorCertificates(in: .primary).contains { $0.supports(fact) })
        XCTAssertNil(store.navigatorProducerRunsBySlot[.primary])
    }

    func testBinaryLaunchFinalizerSchedulesAndReplacesProducer() throws {
        let f = fixture()
        let slot = ImageSlot.primary
        let binary = BinaryImage(id: UUID(), name: "fixture", path: "/not-opened/fixture",
                                 kind: "Mach-O executable", architecture: "arm64", slot: slot)
        var analysis = ImageAnalysis()
        analysis.imageBytes = f.bytes
        analysis.functions = [function(f.base, f.base + 65_537)]
        let snapshot = WorkspaceSnapshot(binaries: [binary], analysisBySlot: [slot: analysis])
        let store = WorkspaceStore(workspaceName: "extent launch", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        store.dropNavigatorState(in: slot)
        defer { store.dropNavigatorState(in: slot) }
        XCTAssertEqual(store.snapshot.primarySlot, slot)
        let oldID = UUID()
        store.navigatorProducerRunsBySlot[slot] = NavigatorProducerRun(id: oldID, task: Task {})
        MCPLauncher.scheduleNavigatorForBinaryLaunch(in: store)
        let scheduled = try XCTUnwrap(store.navigatorProducerRunsBySlot[slot])
        XCTAssertNotEqual(scheduled.id, oldID)
        XCTAssertNotNil(store.navigatorGenerations[slot])
        // No await: this main-actor assertion observes admission, not asynchronous completion.
    }
}
