import Foundation
import XCTest
@testable import MacScope

private final class XRefTestGate: @unchecked Sendable {
    let entered = XCTestExpectation(description: "index builder entered")
    private let release = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var first = true

    func checkpoint() throws {
        lock.lock()
        let block = first
        first = false
        lock.unlock()
        if block { entered.fulfill(); release.wait() }
        try Task.checkCancellation()
    }
    func open() { release.signal() }
}

private final class XRefAttemptCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.withLock { value += 1 } }
    func read() -> Int { lock.withLock { value } }
}

@MainActor
final class XRefEndpointMemoTests: XCTestCase {
    private func ref(_ from: UInt64, _ to: UInt64) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: XRefKind.call)
    }

    func testWarmupRetirementKeepsAdmissionUntilCancelledWorkExits() async {
        let firstOwner = NSObject(), nextOwner = NSObject()
        let firstGate = XRefTestGate(), nextGate = XRefTestGate()
        let preparation = XRefIndexPreparation(maxJobs: 2, maxOrdinals: 4)
        defer { preparation.cancel(); firstGate.open(); nextGate.open() }
        let first = XRefIndexPreparation.Request(owner: ObjectIdentifier(firstOwner), ordinalCount: 4) {
            try firstGate.checkpoint()
        }
        let next = XRefIndexPreparation.Request(owner: ObjectIdentifier(nextOwner), ordinalCount: 4) {
            try nextGate.checkpoint()
        }
        preparation.update([first])
        let firstEntered = await XCTWaiter.fulfillment(of: [firstGate.entered], timeout: 3)
        XCTAssertEqual(firstEntered, .completed)
        preparation.update([next])
        XCTAssertEqual(preparation.admissionForTesting().jobs, 1)
        XCTAssertEqual(preparation.admissionForTesting().ordinals, 4)
        firstGate.open()
        let nextEntered = await XCTWaiter.fulfillment(of: [nextGate.entered], timeout: 3)
        XCTAssertEqual(nextEntered, .completed)
        nextGate.open()
        await preparation.waitUntilIdle()
        XCTAssertEqual(preparation.admissionForTesting().jobs, 0)
        withExtendedLifetime((firstOwner, nextOwner)) { }
    }

    func testWarmupSelectionKeepsUnchangedMemoGeneration() throws {
        var primary = ImageAnalysis(), sibling = ImageAnalysis()
        primary.xrefs = [ref(1, 9)]; sibling.xrefs = [ref(2, 9)]
        let slot = ImageSlot(rawValue: 1)
        let images = [BinaryImage(id: UUID(), name: "a", path: "/tmp/a", kind: "Mach-O executable", architecture: "arm64", slot: .primary),
                      BinaryImage(id: UUID(), name: "b", path: "/tmp/b", kind: "Mach-O executable", architecture: "arm64", slot: slot)]
        let original = WorkspaceSnapshot(binaries: images, analysisBySlot: [.primary: primary, slot: sibling])
        var changed = original
        changed.mutateAnalysis(in: slot) { $0.xrefs = [ref(3, 9)] }
        let before = original.xrefIndexPreparationRequests(), after = changed.xrefIndexPreparationRequests()
        XCTAssertEqual(before.count, 2); XCTAssertEqual(after.count, 2)
        guard before.count == 2, after.count == 2 else { return }
        XCTAssertEqual(before[0].owner, after[0].owner)
        XCTAssertNotEqual(before[1].owner, after[1].owner)
    }

    func testReintroducedWarmupStartsAfterPriorCancellationRetires() async {
        let owner = NSObject(), gate = XRefTestGate(), counter = XRefAttemptCounter()
        let preparation = XRefIndexPreparation()
        defer { preparation.cancel(); gate.open() }
        let request = XRefIndexPreparation.Request(owner: ObjectIdentifier(owner), ordinalCount: 2) {
            counter.increment()
            try gate.checkpoint()
        }
        preparation.update([request])
        let entered = await XCTWaiter.fulfillment(of: [gate.entered], timeout: 3)
        XCTAssertEqual(entered, .completed)
        preparation.update([])
        preparation.update([request])
        XCTAssertEqual(counter.read(), 1)
        gate.open()
        await preparation.waitUntilIdle()
        XCTAssertEqual(counter.read(), 2)
        withExtendedLifetime(owner) { }
    }

    func testMemoSurvivesUnrelatedMutationAndProjection() throws {
        let sibling = ImageSlot(rawValue: 1)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "image\(slot.rawValue)", path: "/tmp/xref-memo-\(slot.rawValue)",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        var bucket = ImageAnalysis()
        bucket.xrefs = [ref(4, 8)]
        var snapshot = WorkspaceSnapshot(binaries: [image(.primary), image(sibling)],
            analysisBySlot: [.primary: ImageAnalysis(), sibling: bucket])
        let original = try XCTUnwrap(snapshot.analysis(in: sibling)).xrefEndpointMemo
        let first = try XCTUnwrap(try bucket.xrefEndpointIndex(checkpoint: {}))
        XCTAssertEqual(first.candidates(.to, lower: 8, upperInclusive: 8), bucket.xrefs)
        snapshot.mutateAnalysis(in: sibling) {
            $0.functions = [FunctionSummary(id: UUID(), name: "f", startAddress: 4, endAddress: 8, confidence: 1)]
        }
        XCTAssertTrue(try XCTUnwrap(snapshot.analysis(in: sibling)).xrefEndpointMemo === original)
        let projected = WorkspaceScriptingAPI.imageProjection(of: snapshot, in: sibling)
        XCTAssertEqual(projected.primarySlot, sibling)
        let projectedBucket = try XCTUnwrap(projected.analysis(in: projected.primarySlot))
        XCTAssertTrue(projectedBucket.xrefEndpointMemo === original)
        let projectedIndex = try XCTUnwrap(try projectedBucket.xrefEndpointIndex(checkpoint: {
            XCTFail("the unchanged memo should already be cached")
        }))
        XCTAssertEqual(projectedIndex.candidates(.from, lower: 4, upperInclusive: 4), bucket.xrefs)
        snapshot.mutateAnalysis(in: sibling) { $0.xrefs.append(ref(5, 8)) }
        let changed = try XCTUnwrap(snapshot.analysis(in: sibling))
        XCTAssertFalse(changed.xrefEndpointMemo === original)
        let changedIndex = try XCTUnwrap(try changed.xrefEndpointIndex(checkpoint: {}))
        XCTAssertEqual(changedIndex.candidates(.to, lower: 8, upperInclusive: 8).map(\.from), [4, 5])
        XCTAssertEqual(first.candidates(.to, lower: 8, upperInclusive: 8).map(\.from), [4])
    }

    func testBuildRefusesAboveMaximumCount() throws {
        let refs = [ref(1, 9), ref(2, 8), ref(3, 7)]
        XCTAssertNil(try XRefEndpointIndex.build(refs, maximumCount: 2, checkpoint: {}))
        let index = try XCTUnwrap(try XRefEndpointIndex.build(refs, maximumCount: 3, checkpoint: {}))
        XCTAssertEqual(index.candidates(.from, lower: 0, upperInclusive: UInt64.max), refs)
        XCTAssertEqual(XRefEndpointIndex.maximumIndexedXRefs, 16_777_216)
        XCTAssertEqual(XRefEndpointIndex.maximumInlineIndexedXRefs, 131_072)
    }

    func testStreamedBucketStopsAndRangeAdmissionPreservesOrder() throws {
        let refs = [ref(4, 9), ref(1, 8), ref(2, 9), ref(3, 7)]
        let index = try XCTUnwrap(try XRefEndpointIndex.build(refs, checkpoint: {}))
        var rows: [XRef] = []
        try index.visitCandidates(.to, lower: 9, upperInclusive: 9, checkpoint: {}) {
            rows.append($0); return false
        }
        XCTAssertEqual(rows, [refs[0]])
        rows.removeAll()
        XCTAssertThrowsError(try index.visitCandidates(.to, lower: 7, upperInclusive: 9,
            maximumCandidates: 3, checkpoint: {}) { rows.append($0); return true })
        XCTAssertTrue(rows.isEmpty)
        try index.visitCandidates(.to, lower: 7, upperInclusive: 9,
            maximumCandidates: 4, checkpoint: {}) { rows.append($0); return true }
        XCTAssertEqual(rows, refs)
    }

    func testManualMemoIsGenerationAndSlotBound() throws {
        let sibling = ImageSlot(rawValue: 1)
        var snapshot = WorkspaceSnapshot(binaries: [], functions: [], instructions: [], xrefs: [], hexBytes: Data())
        snapshot.manualXRefs = [
            ManualXRef(from: 1, to: 9, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 2, to: 9, kind: XRefKind.call, isSuppression: false, imageSlot: sibling),
            ManualXRef(from: 3, to: 9, kind: XRefKind.call, isSuppression: true),
        ]
        let old = snapshot
        let memo = snapshot.manualXRefEndpointMemo
        let index = try XCTUnwrap(try memo.index(edits: snapshot.manualXRefs, checkpoint: {}))
        var seen: [UInt64] = []
        try index.visit(.to, address: 9, slot: .primary, checkpoint: {}) { seen.append($0.from); return true }
        XCTAssertEqual(seen, [1, 3])
        snapshot.manualXRefs.removeFirst()
        XCTAssertFalse(snapshot.manualXRefEndpointMemo === memo)
        XCTAssertEqual(old.manualXRefs.count, 3)
        seen.removeAll()
        try index.visit(.to, address: 9, slot: sibling, checkpoint: {}) { seen.append($0.from); return true }
        XCTAssertEqual(seen, [2])
    }

    func testCancelledBuilderWakesWaitingReader() async throws {
        var value = ImageAnalysis()
        value.xrefs = [ref(1, 9), ref(2, 9)]
        let image = value
        let firstGate = XRefTestGate(), secondGate = XRefTestGate()
        defer { firstGate.open(); secondGate.open() }
        let first = Task.detached { try image.xrefEndpointIndex(checkpoint: firstGate.checkpoint) }
        let firstEntered = await XCTWaiter.fulfillment(of: [firstGate.entered], timeout: 3)
        XCTAssertEqual(firstEntered, .completed)
        XCTAssertNil(try image.xrefEndpointIndex(checkpoint: { XCTFail("main thread must not block") }))
        let second = Task.detached { try image.xrefEndpointIndex(checkpoint: secondGate.checkpoint) }
        let secondEntered = await XCTWaiter.fulfillment(of: [secondGate.entered], timeout: 3)
        XCTAssertEqual(secondEntered, .completed)
        first.cancel()
        firstGate.open()
        do { _ = try await first.value; XCTFail("expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        secondGate.open()
        let result = try await second.value
        let index = try XCTUnwrap(result)
        XCTAssertEqual(index.candidates(.to, lower: 9, upperInclusive: 9).map(\.from), [1, 2])
    }

    func testGraphCursorLeaseRejectsBusyAndInvalidatedPublication() throws {
        let session = GraphPageSession()
        let context = session.capture(workspace: UUID(), document: UUID())
        let request = GraphPageRequest(command: "xrefs", slot: .primary, owner: nil,
                                       function: nil, address: 9, incoming: true)
        let initial = try session.begin(context, cursor: nil, request: request)
        let state = GraphPageState(request: request, lower: 9, upper: 9,
                                   storage: .none, phase: .recovered)
        let token = try XCTUnwrap(session.commit(initial.lease, context: context, state: state))
        let held = try session.begin(context, cursor: .string(token), request: request)
        XCTAssertThrowsError(try session.begin(context, cursor: .string(token), request: request))
        session.abandon(held.lease)
        let retry = try session.begin(context, cursor: .string(token), request: request)
        session.invalidate()
        XCTAssertThrowsError(try session.commit(retry.lease, context: context, state: state))
        session.abandon(retry.lease)
    }

    func testCandidatesEqualFilterInSourceOrder() throws {
        let refs = [ref(9, 5), ref(2, 7), ref(9, 5), ref(3, 4),
                    ref(0, UInt64.max), ref(UInt64.max, 0), ref(1, 6)]
        let index = try XCTUnwrap(try XRefEndpointIndex.build(refs, checkpoint: {}))
        let ranges: [(UInt64, UInt64)] = [(5, 5), (2, 9), (0, UInt64.max),
                                        (UInt64.max, UInt64.max), (10, 11)]
        for side in [XRefEndpointSide.to, .from] {
            for (lower, upper) in ranges {
                let expected = refs.filter {
                    let endpoint = side == .to ? $0.to : $0.from
                    return endpoint >= lower && endpoint <= upper
                }
                XCTAssertEqual(index.candidates(side, lower: lower, upperInclusive: upper), expected)
            }
        }
        XCTAssertEqual(index.candidates(.to, lower: 9, upperInclusive: 2), [])
    }

    func testCancelledBuildPublishesNothing() throws {
        var bucket = ImageAnalysis()
        bucket.xrefs = [ref(3, 9), ref(1, 8), ref(2, 9)]
        var checkpoints = 0
        XCTAssertThrowsError(try bucket.xrefEndpointIndex(checkpoint: {
            checkpoints += 1
            if checkpoints == 2 { throw CancellationError() }
        })) {
            XCTAssertTrue($0 is CancellationError)
        }
        XCTAssertEqual(checkpoints, 2)
        var retryCheckpoints = 0
        let index = try XCTUnwrap(try bucket.xrefEndpointIndex(checkpoint: { retryCheckpoints += 1 }))
        XCTAssertGreaterThan(retryCheckpoints, 0)
        XCTAssertEqual(index.candidates(.to, lower: 9, upperInclusive: 9).map(\.from), [3, 2])
        let cached = try XCTUnwrap(try bucket.xrefEndpointIndex(checkpoint: {
            XCTFail("a completed index should be reused")
        }))
        XCTAssertEqual(cached.candidates(.to, lower: 9, upperInclusive: 9).map(\.from), [3, 2])
    }
}
