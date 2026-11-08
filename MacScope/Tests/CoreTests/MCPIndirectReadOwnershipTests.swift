import Foundation
import XCTest
@testable import MacScope

@MainActor
final class MCPIndirectReadOwnershipTests: XCTestCase {
    func testIndexedIndirectReportPreservesOrderAndGenerationOwnership() throws {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot(includingLocalCaller: false)
        let report = try XCTUnwrap(snapshot.imageWideIndirectCalls(in: .primary, compute: true))
        for start: UInt64 in [0x4000, 0x5000, 0xdead] {
            let indexed = try XCTUnwrap(snapshot.indexedIndirectReport(in: .primary, start: start))
            XCTAssertEqual(indexed.report.resolutions, report.resolutions.filter { $0.functionStart == start })
            XCTAssertEqual(indexed.report.refusals, report.refusals.filter { $0.functionStart == start })
            XCTAssertEqual(indexed.totalCount, report.resolutions.count + report.refusals.count)
        }
        var changed = snapshot
        changed.addressOverrides[.primary(0x9040)] = AddressOverride(customName: "new_handler")
        XCTAssertNil(changed.indexedIndirectReport(in: .primary, start: 0x4000))
        XCTAssertNotNil(snapshot.indexedIndirectReport(in: .primary, start: 0x4000))
    }

    func testWarmIndirectSelectorsReuseAdmittedGeneration() throws {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot(includingLocalCaller: false)
        let arguments = ScriptValue.object(["function": .string("_dispatch")])
        var first = 0
        let cold = try WorkspaceScriptingAPI.boundedIndirectCallTargets(arguments: arguments, snapshot: snapshot) { first += 1 }
        var second = 0
        let warm = try WorkspaceScriptingAPI.boundedIndirectCallTargets(arguments: arguments, snapshot: snapshot) { second += 1 }
        XCTAssertEqual(try cold.jsonData(), try warm.jsonData())
        XCTAssertGreaterThan(first, second)
        XCTAssertNotNil(snapshot.admittedIndirectSelector(.name("_dispatch"), slot: .primary))
        var changed = snapshot
        changed.addressOverrides[.primary(0x9040)] = AddressOverride(customName: "new_handler")
        XCTAssertNil(changed.admittedIndirectSelector(.name("_dispatch"), slot: .primary))
        XCTAssertNil(snapshot.admittedIndirectSelector(.name("_dispatch"), slot: ImageSlot(rawValue: 1)))
    }

    func testInterruptedIndirectIndexPublishesNoPartialReport() throws {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot(includingLocalCaller: false)
        let report = try XCTUnwrap(snapshot.imageWideIndirectCalls(in: .primary, compute: true))
        let memo = IndirectCallResolutionMemo()
        let key = IndirectCallResolutionMemo.Key(snapshotID: UUID(), slot: .primary)
        XCTAssertTrue(memo.beginAttempt(for: key))
        XCTAssertNil(memo.completeAttempt(for: key, checkpoint: { false }) { .init(indirectCalls: report) })
        XCTAssertNil(memo.report(for: key))
        XCTAssertNil(memo.functionReport(for: key, start: 0x4000))
        XCTAssertNil(memo.imageReport(for: key) { XCTFail("interrupted builds do not retry"); return .init(indirectCalls: report) })
    }

    func testColdAnalysisAllowsSentinelAndRevocationBeforeRelease() async throws {
        let snapshot = WorkspaceSnapshot(binaries: [], functions: [
            FunctionSummary(id: UUID(), name: "f", startAddress: 0x1000, endAddress: 0x1004, confidence: 1)
        ], instructions: [InstructionRow(address: 0x1000, bytes: "c0 03 5f d6", mnemonic: "ret",
                                         operands: "", hasBreakpoint: false, comment: nil)], xrefs: [], hexBytes: Data())
        let store = WorkspaceStore(workspaceName: "B9", snapshot: snapshot, engine: AnalysisEngine())
        let ownedSnapshot = store.snapshot
        let gate = IndirectReadCheckpoint()
        let executor = MCPAttachExecutor(store: store, api: {
            WorkspaceScriptingAPI(store: $0, snapshotReadCheckpoint: { gate.park() })
        })
        executor.setConsent(.allowed)
        let read = Task { try await executor.execute("indirect-call-targets", .object(["function": .string("f")])) }
        let parked = await Task.detached { gate.awaitParked() }.value
        defer { gate.release() }
        guard parked else {
            read.cancel()
            _ = try? await read.value
            return XCTFail("cold indirect analysis never reached its owned worker checkpoint")
        }
        // Reaching this actor-isolated continuation while the cold memo owns its build is
        // the sentinel. The nonblocking read must still use try(), never wait for that build.
        XCTAssertNil(ownedSnapshot.imageWideIndirectCalls(in: .primary, compute: false))
        executor.setConsent(.revoked)
        gate.release()
        do { _ = try await read.value; XCTFail("revoked analysis released a result") } catch {}
        XCTAssertEqual(gate.parkedThreadName, "Pseudocode rendering")
        XCTAssertNil(ownedSnapshot.imageWideIndirectCalls(in: .primary, compute: false))
        XCTAssertNil(ownedSnapshot.imageWideIndirectCalls(in: .primary, compute: true), "cancelled cold build stays attempted")
    }

    func testInBudgetIndirectEncodingMatchesLegacyReport() async throws {
        let baseline = IndirectTargetResolutionTests.typedSnapshot()
        let report = WorkspaceScriptingAPI.indirectCallTargets(snapshot: baseline, function: baseline.functions[1])
        let expected = WorkspaceScriptingAPI.functionReply(
            report, arguments: .object(["function": .string("_dispatch")]), function: baseline.functions[1])
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        let store = WorkspaceStore(workspaceName: "B9", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let actual = try await executor.execute("indirect-call-targets", .object(["function": .string("_dispatch")]))
        XCTAssertEqual(try actual.jsonData(), try expected.jsonData())
    }

    func testInterruptedColdMemoMarksAttemptAndDoesNotRetry() {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        var checkpoints = 0
        var phases: [IndirectCallResolutionMemo.CheckpointPhase?] = []
        let report = snapshot.imageWideIndirectCalls(in: .primary, compute: true, checkpoint: {
            checkpoints += 1
            phases.append(IndirectCallResolutionMemo.checkpointPhase)
            return false
        })
        XCTAssertNil(report)
        XCTAssertEqual(checkpoints, 1)
        XCTAssertEqual(phases, [.typedPrototypePrerequisite])
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true), "interrupted attempt stays attempted for this identity")
    }

    func testAlreadyCancelledColdRequestMarksAttemptBeforePrerequisites() async {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return snapshot.imageWideIndirectCalls(in: .primary, compute: true)
        }
        let report = await task.value
        XCTAssertNil(report)
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true, checkpoint: {
            XCTFail("an already-cancelled cold request must not retry its prerequisites")
            return true
        }))
    }

    func testPrerequisiteInstructionRefusalDoesNotRetry() {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        var admissions = 0
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true, admitInstructions: { _ in
            admissions += 1
            return false
        }))
        XCTAssertEqual(admissions, 1)
        XCTAssertNil(snapshot.slotTypedPrototypeReport(in: .primary, compute: false))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true, checkpoint: {
            XCTFail("a refused prerequisite must not retry any phase of the cold request")
            return true
        }, admitInstructions: { _ in
            XCTFail("a refused prerequisite must not admit instructions again")
            return true
        }))
    }

    func testPrerequisiteCheckpointDoesNotHoldIndirectMemoLock() {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        var inspectedClaim = false
        let report = snapshot.imageWideIndirectCalls(in: .primary, compute: true, checkpoint: {
            if !inspectedClaim,
               IndirectCallResolutionMemo.checkpointPhase == .typedPrototypePrerequisite {
                inspectedClaim = true
                XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true, checkpoint: {
                    XCTFail("a claimed request must not start a second build")
                    return true
                }))
            }
            return true
        })
        XCTAssertTrue(inspectedClaim)
        XCTAssertNotNil(report)
        XCTAssertNotNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func testBusyPrerequisiteDoesNotRefuseIndirectResolution() throws {
        let baseline = IndirectTargetResolutionTests.typedSnapshot()
        let expected = try XCTUnwrap(baseline.imageWideIndirectCalls(in: .primary, compute: true))
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        var requestedIndirect = false
        var indirectReport: MacIRIndirectTargetResolution.Report?
        let typedReport = snapshot.slotTypedPrototypeReport(in: .primary, compute: true, checkpoint: {
            if !requestedIndirect {
                requestedIndirect = true
                // The typed-only build owns its memo lock here. That prerequisite is
                // unavailable to this request, but it has not refused or been cancelled.
                indirectReport = snapshot.imageWideIndirectCalls(in: .primary, compute: true)
            }
            return true
        })
        XCTAssertTrue(requestedIndirect)
        XCTAssertNotNil(typedReport)
        let actual = try XCTUnwrap(indirectReport)
        XCTAssertEqual(actual.resolutions, expected.resolutions)
        XCTAssertEqual(actual.refusals, expected.refusals)
        XCTAssertNotNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func testPreviouslyInterruptedPrerequisiteDoesNotStartIndirectResolution() {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        XCTAssertNil(snapshot.slotTypedPrototypeReport(in: .primary, compute: true, checkpoint: { false }))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true, checkpoint: {
            XCTFail("an interrupted prerequisite must not enter indirect resolution")
            return true
        }, admitInstructions: { _ in
            XCTFail("an interrupted prerequisite must not admit more instructions")
            return true
        }))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true))
    }

    func testFunctionInstructionBudgetRefusesBeforeLift() throws {
        let snapshot = WorkspaceSnapshot(binaries: [], functions: [
            FunctionSummary(id: UUID(), name: "f", startAddress: 0x1000, endAddress: 0x1000 + 2_049 * 4, confidence: 1)
        ], instructions: (0..<2_049).map {
            InstructionRow(address: 0x1000 + UInt64($0 * 4), bytes: "1f 20 03 d5", mnemonic: "nop",
                           operands: "", hasBreakpoint: false, comment: nil)
        }, xrefs: [], hexBytes: Data())
        XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedIndirectCallTargets(
            arguments: .object(["function": .string("f")]), snapshot: snapshot, checkpoint: {}))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    private func bigImage899(pad: Int = 32_768, ranges: Int = 0) -> WorkspaceSnapshot {
        var snapshot = IndirectTargetResolutionTests.typedSnapshot()
        snapshot.instructions += (0..<pad).map { index in
            InstructionRow(address: 0x100000 + UInt64(index * 4), bytes: "1f 20 03 d5", mnemonic: "nop",
                           operands: "", hasBreakpoint: false, comment: nil)
        }
        snapshot.codeDataRanges = (0..<ranges).map { index in
            CodeDataRangeSummary(id: UUID(), address: 0x100000 + UInt64(index * 0x100), size: 4, kind: "data")
        }
        return snapshot
    }

    private func overCap899() -> WorkspaceSnapshot {
        var snapshot = IndirectTargetResolutionTests.typedSnapshot()
        snapshot.functions += (0..<WorkspaceSnapshot.maximumImageWideIndirectCallFunctions).map { index in
            FunctionSummary(id: UUID(), name: "f", startAddress: 0x10000 + UInt64(index * 4),
                            endAddress: 0x10004 + UInt64(index * 4), confidence: 1)
        }
        return snapshot
    }

    private func legacy899(_ snapshot: WorkspaceSnapshot, name: String) throws -> ScriptValue {
        let function = try XCTUnwrap(snapshot.functions.first { $0.name == name })
        return WorkspaceScriptingAPI.functionReply(
            WorkspaceScriptingAPI.indirectCallTargets(snapshot: snapshot, function: function),
            arguments: .object(["function": .string(name)]), function: function)
    }

    private func comparator899(_ name: String) throws -> ScriptValue {
        try legacy899(overCap899(), name: name)
    }

    private func read899(_ snapshot: WorkspaceSnapshot, name: String = "_local",
                         checkpoint: () throws -> Void = {}) throws -> ScriptValue {
        try WorkspaceScriptingAPI.boundedIndirectCallTargets(arguments: .object(["function": .string(name)]),
                                                             snapshot: snapshot, checkpoint: checkpoint)
    }

    func test899F1LargeImageLocalAnswerDoesNotWarmMemo() throws {
        let snapshot = bigImage899()
        XCTAssertEqual(snapshot.instructions.count, 32_782)
        let actual = try read899(snapshot)
        XCTAssertEqual(try actual.jsonData(), try comparator899("_local").jsonData())
        XCTAssertEqual(actual["imageWide"], .bool(false))
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func test899F2AsyncAndAttachedUseLocalFallback() async throws {
        let expected = try comparator899("_local").jsonData()
        for attached in [false, true] {
            let store = WorkspaceStore(workspaceName: "899", snapshot: bigImage899(), engine: AnalysisEngine(), autosaveScheduler: nil)
            let api = WorkspaceScriptingAPI(store: store)
            let args = ScriptValue.object(["function": .string("_local")])
            let actual: ScriptValue
            if attached {
                let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
                executor.setConsent(.allowed)
                actual = try await executor.execute("indirect-call-targets", args)
            } else { actual = try await api.executeAsync("indirect-call-targets", arguments: args) }
            XCTAssertEqual(try actual.jsonData(), expected)
            XCTAssertNil(store.snapshot.imageWideIndirectCalls(in: .primary, compute: false))
        }
    }

    func test899F3DispatchDoesNotInventTypeScope() throws {
        let actual = try read899(bigImage899(), name: "_dispatch")
        XCTAssertEqual(try actual.jsonData(), try comparator899("_dispatch").jsonData())
        XCTAssertEqual(actual["imageWide"], .bool(false))
        XCTAssertFalse(actual["resolved"]?.arrayValue?.contains { $0["scope"]?.stringValue?.hasPrefix("type:") == true } ?? true)
    }

    func test899F4RangeCrossProductFallsBackWithoutWarmingMemo() throws {
        let snapshot = bigImage899(pad: 18_000, ranges: 59)
        XCTAssertEqual(snapshot.instructions.count * snapshot.codeDataRanges.count, 1_062_826)
        XCTAssertEqual(try read899(snapshot).jsonData(), try comparator899("_local").jsonData())
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func test899F5CompleteMemoRemainsImageWide() throws {
        let snapshot = bigImage899()
        XCTAssertNotNil(snapshot.imageWideIndirectCalls(in: .primary, compute: true))
        let actual = try read899(snapshot, name: "_dispatch")
        XCTAssertEqual(actual["imageWide"], .bool(true))
        XCTAssertEqual(try actual.jsonData(), try legacy899(snapshot, name: "_dispatch").jsonData())
    }

    private func sweep899(_ make: () -> WorkspaceSnapshot, expected: ScriptValue,
                          file: StaticString = #filePath, line: UInt = #line) throws {
        var count = 0
        let complete = try read899(make(), checkpoint: { count += 1 })
        XCTAssertEqual(try complete.jsonData(), try expected.jsonData(), file: file, line: line)
        XCTAssertGreaterThan(count, 0, file: file, line: line)
        for k in 0..<count {
            let fresh = make()
            var visits = 0
            XCTAssertThrowsError(try read899(fresh, checkpoint: {
                visits += 1
                if visits == k + 1 { throw CancellationError() }
            }), "checkpoint \(k + 1) of \(count)", file: file, line: line) { error in
                XCTAssertTrue(error is CancellationError, "\(error)", file: file, line: line)
            }
            XCTAssertEqual(visits, k + 1, file: file, line: line)
        }
    }

    func test899F6EveryLocalCheckpointPropagatesOneShotCancellation() throws {
        try sweep899({ self.bigImage899() }, expected: comparator899("_local"))
    }

    private func imageTextFailure899(_ kind: Int) -> WorkspaceSnapshot {
        var snapshot = IndirectTargetResolutionTests.typedSnapshot()
        switch kind {
        case 0:
            snapshot.instructions.append(InstructionRow(address: 0x100000, bytes: "1f 20 03 d5", mnemonic: "nop",
                operands: String(repeating: "a", count: 4_097), hasBreakpoint: false, comment: nil))
        case 1: snapshot.objcSelectors = [0x200000: String(repeating: "s", count: 4_097)]
        default: snapshot.jumpTables = [0x200000: Array(repeating: 0x5000, count: 65_537)]
        }
        return snapshot
    }

    func test899F7LateImagePolicyFailuresAlsoFallBackAndRemainCancellable() throws {
        let expected = try comparator899("_local")
        for kind in 0..<3 {
            let snapshot = imageTextFailure899(kind)
            XCTAssertEqual(try read899(snapshot).jsonData(), try expected.jsonData())
            XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
            try sweep899({ self.imageTextFailure899(kind) }, expected: expected)
        }
    }

    func test899C3LocalFunctionRowCapStillRefuses() throws {
        var snapshot = bigImage899()
        snapshot.functions.append(FunctionSummary(id: UUID(), name: "g", startAddress: 0x100000,
            endAddress: 0x100000 + 2_049 * 4, confidence: 1))
        XCTAssertThrowsError(try read899(snapshot, name: "g")) {
            XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused)
        }
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func test899C4OtherLiftingReadsKeepBothWholeImageRefusals() throws {
        for snapshot in [bigImage899(), bigImage899(pad: 18_000, ranges: 59)] {
            let args = ScriptValue.object(["function": .string("_local"), "parameter": .int(0)])
            XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedStackLocals(arguments: args, snapshot: snapshot, checkpoint: {})) {
                XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused)
            }
            XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedStructCandidate(arguments: args, snapshot: snapshot, checkpoint: {})) {
                XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused)
            }
        }
    }

    func test899C5OverFunctionMemoCapKeepsExistingLocalReply() throws {
        XCTAssertEqual(try read899(overCap899()).jsonData(), try comparator899("_local").jsonData())
    }

    func test899C6EveryFullRouteCheckpointPropagatesOneShotCancellation() throws {
        let baseline = IndirectTargetResolutionTests.typedSnapshot()
        try sweep899({ IndirectTargetResolutionTests.typedSnapshot() }, expected: legacy899(baseline, name: "_local"))
    }

    func test899C7TypesNeverFallBack() throws {
        var snapshot = bigImage899()
        snapshot.typeDefinitions = (0..<4_097).map { TypeDefinition(kind: .struct, name: "T\($0)") }
        XCTAssertThrowsError(try read899(snapshot)) {
            XCTAssertEqual($0 as? ScriptingError, AttachedTypeReadBudget.refused)
        }
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func test899C8RangeBoundaryStillUsesFullRoute() throws {
        let snapshot = bigImage899(pad: 18_000, ranges: 58)
        XCTAssertEqual(snapshot.instructions.count * snapshot.codeDataRanges.count, 1_044_812)
        let actual = try read899(snapshot)
        XCTAssertEqual(actual["imageWide"], .bool(true))
        XCTAssertEqual(try actual.jsonData(), try legacy899(snapshot, name: "_local").jsonData())
    }

    func test899C10LocalOverrideTableAndRowTextCharges() throws {
        for kind in 0..<3 {
            var snapshot = bigImage899()
            switch kind {
            case 0:
                snapshot.addressOverrides[ImageAddress(slot: .primary, address: 0x9040)] =
                    AddressOverride(customName: String(repeating: "x", count: 4_097))
            case 1: snapshot.jumpTables = [0x5004: Array(repeating: 0x5000, count: 65_537)]
            default:
                let index = try XCTUnwrap(snapshot.instructions.firstIndex { $0.address == 0x5000 })
                snapshot.instructions[index].operands = String(repeating: "x", count: 4_097)
            }
            XCTAssertThrowsError(try read899(snapshot)) {
                XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused)
            }
            XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
        }
    }

    func test899F8ExactStartJumpTableIsChargedIncludingUInt64Max() throws {
        let ranges: [(UInt64, UInt64)] = [(0x6000, 0x6000), (0x6000, 0x5ffc), (UInt64.max, UInt64.max)]
        for (start, end) in ranges {
            var snapshot = bigImage899()
            snapshot.functions = [FunctionSummary(id: UUID(), name: "zero", startAddress: start, endAddress: end, confidence: 1)]
            snapshot.instructions.append(InstructionRow(address: start, bytes: "c0 03 5f d6", mnemonic: "ret",
                                                       operands: "", hasBreakpoint: false, comment: nil))
            snapshot.addressOverrides = [:]
            snapshot.jumpTables = [start: Array(repeating: 0x5000, count: 65_537)]
            var visits = 0
            XCTAssertThrowsError(try read899(snapshot, name: "zero", checkpoint: { visits += 1 })) {
                XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused)
            }
            XCTAssertEqual(visits, 5, "pin stops at two type-preparation visits; local table charging is visit five")
            XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
        }
    }

    func test899F9OverlappingTargetRangeSuppliesTheTableBudget() throws {
        var snapshot = bigImage899()
        let outer = FunctionSummary(id: UUID(), name: "outer", startAddress: 0x4ff0, endAddress: 0x5018, confidence: 1)
        snapshot.functions.insert(outer, at: 0)
        snapshot.instructions.append(InstructionRow(address: 0x4ff0, bytes: "c0 03 5f d6", mnemonic: "ret",
                                                   operands: "", hasBreakpoint: false, comment: nil))
        snapshot.addressOverrides = [:]
        snapshot.jumpTables = [0x4ff0: Array(repeating: 0x5000, count: 65_537)]
        XCTAssertEqual(snapshot.pseudocodeTarget(selectedAddress: 0x5000, in: .primary)?.function.id, outer.id)
        var visits = 0
        XCTAssertThrowsError(try read899(snapshot, checkpoint: { visits += 1 })) {
            XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused)
        }
        XCTAssertEqual(visits, 5, "the table before the selected start belongs to the actual slice")
        XCTAssertNil(snapshot.imageWideIndirectCalls(in: .primary, compute: false))
    }

    func test899C11ImageCheckpointErrorsCannotBecomePolicyFalse() throws {
        let snapshot = IndirectTargetResolutionTests.typedSnapshot()
        var visits = 0
        XCTAssertThrowsError(try read899(snapshot, checkpoint: {
            visits += 1
            if visits == 3 { throw SnapshotAnalysisReadBudget.refused }
        })) { XCTAssertEqual($0 as? ScriptingError, SnapshotAnalysisReadBudget.refused) }
        XCTAssertEqual(visits, 3)
    }
}

private final class IndirectReadCheckpoint: @unchecked Sendable {
    private let lock = NSLock()
    private let parked = DispatchSemaphore(value: 0)
    private let resume = DispatchSemaphore(value: 0)
    private var didPark = false
    private var sawCancellation = false
    private var firstThreadName: String?
    var parkedThreadName: String? { lock.withLock { firstThreadName } }
    var cancelled: Bool { lock.withLock { sawCancellation } }
    func park() {
        guard IndirectCallResolutionMemo.checkpointPhase == .typedPrototypePrerequisite else { return }
        let first = lock.withLock {
            guard !didPark else { return false }
            firstThreadName = Thread.current.name
            didPark = true
            return true
        }
        guard first else { return }
        parked.signal()
        // Timeout is only a broken-test failsafe, never a latency assertion.
        _ = resume.wait(timeout: .now() + 5)
        lock.withLock { sawCancellation = Task.isCancelled }
    }
    func awaitParked() -> Bool { parked.wait(timeout: .now() + 2) == .success }
    func release() { resume.signal() }
}
