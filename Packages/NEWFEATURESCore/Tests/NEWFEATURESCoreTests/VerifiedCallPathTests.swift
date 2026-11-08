import Foundation
import XCTest
@testable import NEWFEATURESCore

final class VerifiedCallPathTests: XCTestCase {
    private func image(slot: Int = 0, revision: UInt64 = 1) throws -> NEWFEATURESImageKey {
        try NEWFEATURESImageKey(
            documentInstance: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
            workspaceInstance: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)),
            slot: slot,
            binaryID: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3)),
            ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: String(repeating: "a", count: 64), analysisRevision: revision,
            analysisInputFingerprintSHA256: String(repeating: "b", count: 64)
        )
    }

    private func key(_ address: UInt64, image: NEWFEATURESImageKey) -> NEWFEATURESFunctionKey {
        NEWFEATURESFunctionKey(image: image, address: address)
    }

    private func edge(_ from: UInt64, _ to: UInt64, site: UInt64? = nil,
                      confidence: NEWFEATURESCallConfidence = .confirmedDirect,
                      image: NEWFEATURESImageKey) -> NEWFEATURESCallEdge {
        NEWFEATURESCallEdge(caller: key(from, image: image), callee: key(to, image: image),
                           callSite: site ?? from, confidence: confidence)
    }

    private func graph(_ addresses: [UInt64], edges: [NEWFEATURESCallEdge],
                       image: NEWFEATURESImageKey, operation: NEWFEATURESGraphOperation? = nil,
                       limits: NEWFEATURESGraphInputLimits = .standard) throws -> NEWFEATURESGraphSnapshot {
        try NEWFEATURESGraphSnapshot(
            functions: addresses.map { key($0, image: image) }, edges: edges,
            operation: operation ?? NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget()), limits: limits
        )
    }

    private func path(_ from: UInt64, _ to: UInt64, in graph: NEWFEATURESGraphSnapshot,
                      budget: NEWFEATURESReadBudget? = nil,
                      operation: NEWFEATURESGraphOperation? = nil) throws -> NEWFEATURESPathReport {
        let budget = try budget ?? NEWFEATURESReadBudget()
        return try NEWFEATURESPathfinder.shortestVerifiedPath(
            from: key(from, image: graph.image), to: key(to, image: graph.image), graph: graph,
            budget: budget, operation: operation ?? NEWFEATURESGraphOperation(budget: budget)
        )
    }

    func testShortestPathTieIsDeterministicAcrossInputOrder() throws {
        let image = try image()
        let edges = [edge(10, 30, site: 11, image: image), edge(10, 20, site: 12, image: image),
                     edge(20, 40, image: image), edge(30, 40, image: image)]
        let first = try graph([40, 20, 30, 10], edges: edges, image: image)
        let second = try graph([10, 30, 20, 40], edges: Array(edges.reversed()), image: image)
        let one = try path(10, 40, in: first)
        XCTAssertEqual(one, try path(10, 40, in: second))
        XCTAssertEqual(one.status, .found)
        XCTAssertEqual(one.path.map(\.address), [10, 20, 40])
    }

    func testShorterPathWinsOverLexicallyEarlierLongerBranch() throws {
        let image = try image()
        let input = try graph([10, 20, 30, 40, 50], edges: [
            edge(10, 20, site: 11, image: image), edge(10, 40, site: 12, image: image),
            edge(20, 30, image: image), edge(30, 50, image: image), edge(40, 50, image: image),
        ], image: image)
        XCTAssertEqual(try path(10, 50, in: input).path.map(\.address), [10, 40, 50])
    }

    func testSameEndpointNeedsNoEdgeOrExtraFunction() throws {
        let image = try image()
        let input = try graph([10], edges: [edge(10, 10, image: image)], image: image)
        let report = try path(10, 10, in: input, budget: NEWFEATURESReadBudget(maxFunctions: 1, maxDepth: 0))
        XCTAssertEqual(report.status, .found)
        XCTAssertEqual(report.path.map(\.address), [10])
        XCTAssertEqual(report.visitedEdges, 0)
    }

    func testCyclesTerminateAndExpansionUsesTheSameBoundedWalk() throws {
        let image = try image()
        let input = try graph([10, 20, 30], edges: [
            edge(10, 20, image: image), edge(20, 30, image: image), edge(30, 10, image: image),
        ], image: image)
        let budget = try NEWFEATURESReadBudget()
        let result = try NEWFEATURESCallGraphTraversal.expand(
            root: key(10, image: image), graph: input, budget: budget,
            operation: NEWFEATURESGraphOperation(budget: budget)
        )
        XCTAssertEqual(result.orderedFunctions.map(\.address), [10, 20, 30])
        XCTAssertEqual(result.edgeVisits, 3)
        XCTAssertEqual(result.depthByFunction[key(30, image: image)], 2)
        XCTAssertTrue(result.isCompleteWithinObservedGraph)
    }

    func testUnverifiedCallsRemainVisibleWithoutCreatingAPath() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [
            edge(10, 20, confidence: .unverified, image: image),
        ], image: image)
        let report = try path(10, 20, in: input)
        XCTAssertEqual(report.status, .notFoundInObservedGraph)
        XCTAssertEqual(report.visitedEdges, 1)
        XCTAssertEqual(report.examinedUnverifiedEdges, 1)
        XCTAssertEqual(report.observedUnverifiedEdges, 1)
        XCTAssertTrue(report.path.isEmpty)
    }

    func testUnverifiedEdgesConsumeTheTraversalBudget() throws {
        let image = try image()
        let input = try graph([10, 20, 30], edges: [
            edge(10, 20, confidence: .unverified, image: image), edge(10, 30, site: 11, image: image),
        ], image: image)
        let report = try path(10, 30, in: input, budget: NEWFEATURESReadBudget(maxEdgeVisits: 1))
        XCTAssertEqual(report.status, .edgeVisitLimit)
        XCTAssertEqual(report.visitedEdges, 1)
        XCTAssertEqual(report.examinedUnverifiedEdges, 1)
    }

    func testDepthBoundaryFanoutIsChargedBeforeInspectingEveryNeighbour() throws {
        let image = try image()
        let input = try graph([10, 20, 30, 40], edges: [
            edge(10, 20, site: 11, image: image), edge(10, 30, site: 12, image: image),
            edge(10, 40, site: 13, image: image),
        ], image: image)
        let report = try path(10, 40, in: input,
                              budget: NEWFEATURESReadBudget(maxDepth: 0, maxEdgeVisits: 2))
        XCTAssertEqual(report.status, .edgeVisitLimit)
        XCTAssertEqual(report.visitedEdges, 2)
        XCTAssertEqual(report.visitedFunctions, 1)
    }

    func testDepthBoundaryWithUnseenNeighbourReportsPartial() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [edge(10, 20, image: image)], image: image)
        let report = try path(10, 20, in: input, budget: NEWFEATURESReadBudget(maxDepth: 0))
        XCTAssertEqual(report.status, .depthLimit)
        XCTAssertEqual(report.visitedEdges, 1)
    }

    func testDepthBoundaryContainingOnlyVisitedCyclesIsComplete() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [edge(10, 10, image: image)], image: image)
        let report = try path(10, 20, in: input, budget: NEWFEATURESReadBudget(maxDepth: 0))
        XCTAssertEqual(report.status, .notFoundInObservedGraph)
        XCTAssertEqual(report.visitedEdges, 1)
    }

    func testFunctionLimitIsNotReportedAsAbsence() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [edge(10, 20, image: image)], image: image)
        let report = try path(10, 20, in: input, budget: NEWFEATURESReadBudget(maxFunctions: 1))
        XCTAssertEqual(report.status, .functionLimit)
        XCTAssertEqual(report.visitedFunctions, 1)
    }

    func testEveryDistinctCallSiteConsumesAnEdgeVisit() throws {
        let image = try image()
        let input = try graph([10, 20, 30], edges: [
            edge(10, 20, site: 11, image: image), edge(10, 20, site: 12, image: image),
            edge(10, 20, site: 13, image: image),
        ], image: image)
        let report = try path(10, 30, in: input, budget: NEWFEATURESReadBudget(maxEdgeVisits: 2))
        XCTAssertEqual(report.status, .edgeVisitLimit)
        XCTAssertEqual(report.visitedEdges, 2)
    }

    func testIdenticalObservationDeduplicatesWithoutInventingAnotherCall() throws {
        let image = try image()
        let call = edge(10, 20, image: image)
        let input = try graph([10, 20, 30], edges: [call, call], image: image)
        let report = try path(10, 30, in: input)
        XCTAssertEqual(input.observedEdgeCount, 1)
        XCTAssertEqual(report.visitedEdges, 1)
        XCTAssertEqual(report.status, .notFoundInObservedGraph)
    }

    func testMixedImagesWithEqualAddressesAreRefused() throws {
        let first = key(10, image: try image(slot: 0))
        let second = key(10, image: try image(slot: 1))
        XCTAssertThrowsError(try NEWFEATURESGraphSnapshot(
            functions: [first, second], edges: [],
            operation: NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget())
        )) { XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("mixed image or analysis identity")) }
    }

    func testMixedAnalysisGenerationsCannotJoin() throws {
        let first = key(10, image: try image(revision: 1))
        let second = key(20, image: try image(revision: 2))
        XCTAssertThrowsError(try NEWFEATURESGraphSnapshot(
            functions: [first, second], edges: [],
            operation: NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget())
        )) { XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("mixed image or analysis identity")) }
    }

    func testDuplicateFunctionAddressIsRefused() throws {
        let image = try image()
        XCTAssertThrowsError(try graph([10, 10], edges: [], image: image)) {
            XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("duplicate function address"))
        }
    }

    func testEdgeWithMissingFunctionIsRefused() throws {
        let image = try image()
        XCTAssertThrowsError(try graph([10], edges: [edge(10, 20, image: image)], image: image)) {
            XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("edge without exact single-image function identity"))
        }
    }

    func testStaleEdgeCannotEnterCurrentSnapshot() throws {
        let current = try image(revision: 2)
        let old = try image(revision: 1)
        XCTAssertThrowsError(try graph([10, 20], edges: [edge(10, 20, image: old)], image: current)) {
            XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("edge without exact single-image function identity"))
        }
    }

    func testContradictoryDirectTargetsAreRefusedInEitherOrder() throws {
        let image = try image()
        let edges = [edge(10, 20, image: image), edge(10, 30, image: image)]
        for input in [edges, Array(edges.reversed())] {
            XCTAssertThrowsError(try graph([10, 20, 30], edges: input, image: image)) {
                XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("contradictory verified call site"))
            }
        }
    }

    func testDirectAndProvenIndirectCannotShareOneCallSite() throws {
        let image = try image()
        let edges = [edge(10, 20, image: image), edge(10, 30, confidence: .provenIndirect, image: image)]
        for input in [edges, Array(edges.reversed())] {
            XCTAssertThrowsError(try graph([10, 20, 30], edges: input, image: image)) {
                XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("contradictory verified call site"))
            }
        }
    }

    func testProvenIndirectTargetsRemainDistinctSupportedObservations() throws {
        let image = try image()
        let input = try graph([10, 20, 30], edges: [
            edge(10, 20, confidence: .provenIndirect, image: image),
            edge(10, 30, confidence: .provenIndirect, image: image),
        ], image: image)
        XCTAssertEqual(try path(10, 30, in: input).path.map(\.address), [10, 30])
    }

    func testMissingPathEndpointIsARefusal() throws {
        let image = try image()
        let input = try graph([10], edges: [], image: image)
        XCTAssertThrowsError(try path(10, 20, in: input)) {
            XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("path endpoint absent or stale"))
        }
    }

    func testConstructionFunctionLimitIsIndependentOfTraversalLimit() throws {
        let image = try image()
        XCTAssertThrowsError(try graph([10, 20], edges: [], image: image,
                                      limits: NEWFEATURESGraphInputLimits(maxFunctions: 1, maxEdges: 10))) {
            XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("input size limit"))
        }
    }

    func testConstructionCountsDuplicateInputBeforeDeduplication() throws {
        let image = try image()
        let call = edge(10, 20, image: image)
        XCTAssertThrowsError(try graph([10, 20], edges: [call, call], image: image,
                                      limits: NEWFEATURESGraphInputLimits(maxFunctions: 2, maxEdges: 1))) {
            XCTAssertEqual($0 as? NEWFEATURESError, .malformedGraph("input size limit"))
        }
    }

    func testCancellationBeforeConstructionPreventsGraphPublication() throws {
        let image = try image()
        let operation = try NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget(), cancellationRequested: { true })
        XCTAssertThrowsError(try graph([10], edges: [], image: image, operation: operation)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphInterruption, .cancelled)
        }
    }

    func testElapsedProjectionTimeIsNotResetAtConstruction() throws {
        let image = try image()
        let operation = try NEWFEATURESGraphOperation(
            budget: NEWFEATURESReadBudget(maxElapsedSeconds: 1), startedAt: .now.advanced(by: .seconds(-2))
        )
        XCTAssertThrowsError(try graph([10], edges: [], image: image, operation: operation)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphInterruption, .timedOut)
        }
    }

    func testCancelledPathIsNotReportedAsNotFound() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [edge(10, 20, image: image)], image: image)
        let operation = try NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget(), cancellationRequested: { true })
        let report = try path(10, 20, in: input, operation: operation)
        XCTAssertEqual(report.status, .cancelled)
        XCTAssertEqual(report.visitedEdges, 0)
    }

    func testDeadlineIsCarriedIntoTraversal() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [edge(10, 20, image: image)], image: image)
        let operation = try NEWFEATURESGraphOperation(
            budget: NEWFEATURESReadBudget(maxElapsedSeconds: 1), startedAt: .now.advanced(by: .seconds(-2))
        )
        XCTAssertEqual(try path(10, 20, in: input, operation: operation).status, .timedOut)
    }

    func testCancellationIsObservedInsideTheEdgeLoop() throws {
        let image = try image()
        let input = try graph([10, 20, 30, 40], edges: [
            edge(10, 20, site: 11, image: image), edge(10, 30, site: 12, image: image),
            edge(10, 40, site: 13, image: image),
        ], image: image)
        let counter = CancellationCounter(cancelAt: 5)
        let operation = try NEWFEATURESGraphOperation(
            budget: NEWFEATURESReadBudget(), cancellationRequested: { counter.shouldCancel() }
        )
        let report = try path(10, 40, in: input, operation: operation)
        XCTAssertEqual(report.status, .cancelled)
        XCTAssertEqual(report.visitedEdges, 2)
        XCTAssertTrue(report.path.isEmpty)
    }

    func testConstructionObservesCancellationDuringInputProcessing() throws {
        let image = try image()
        let counter = CancellationCounter(cancelAt: 4)
        let operation = try NEWFEATURESGraphOperation(
            budget: NEWFEATURESReadBudget(), cancellationRequested: { counter.shouldCancel() }
        )
        XCTAssertThrowsError(try graph([10, 20, 30, 40], edges: [], image: image, operation: operation)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphInterruption, .cancelled)
        }
    }

    func testOutputBudgetIsSeparateFromSuccessfulTraversal() throws {
        let image = try image()
        let input = try graph([10, 20], edges: [edge(10, 20, image: image)], image: image)
        let report = try path(10, 20, in: input)
        XCTAssertEqual(report.status, .found)
        let operation = try NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget())
        XCTAssertThrowsError(try report.encoded(maximumUTF8Bytes: 32, operation: operation)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphOutputFailure, .byteLimit)
        }
        XCTAssertGreaterThan(try report.encoded(maximumUTF8Bytes: 10_000, operation: operation).count, 32)
    }

    func testSerializedAddressRemainsExactAboveJavaScriptIntegerRange() throws {
        let image = try image()
        let input = try graph([UInt64.max], edges: [], image: image)
        let report = try path(UInt64.max, UInt64.max, in: input)
        let bytes = try report.encoded(maximumUTF8Bytes: 10_000,
                                       operation: NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget()))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let source = try XCTUnwrap(object["source"] as? [String: Any])
        XCTAssertEqual(source["address"] as? String, "0xffffffffffffffff")
    }

    func testCancelledSerializationCannotPublishPreviouslyFoundPath() throws {
        let image = try image()
        let input = try graph([10], edges: [], image: image)
        let report = try path(10, 10, in: input)
        let operation = try NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget(), cancellationRequested: { true })
        XCTAssertThrowsError(try report.encoded(maximumUTF8Bytes: 10_000, operation: operation)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphInterruption, .cancelled)
        }
    }

    func testUnresolvedCallCoexistsWithAnIndependentlyVerifiedPath() throws {
        let image = try image()
        let operation = try NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget())
        let input = try NEWFEATURESGraphSnapshot(
            functions: [key(10, image: image), key(20, image: image)],
            edges: [edge(10, 20, site: 12, image: image)],
            unresolvedEdges: [.init(caller: key(10, image: image), callSite: 11, observedTarget: 15)],
            operation: operation
        )
        let report = try path(10, 20, in: input)
        XCTAssertEqual(report.path.map(\.address), [10, 20])
        XCTAssertEqual(report.status, .found)
        XCTAssertEqual(report.examinedUnverifiedEdges, 1)
        XCTAssertEqual(report.observedUnverifiedEdges, 1)
        XCTAssertEqual(report.visitedEdges, 2)
    }

    func testUnresolvedIndirectCallIsRetainedWhenNoPathIsObserved() throws {
        let image = try image()
        let input = try NEWFEATURESGraphSnapshot(
            functions: [key(10, image: image), key(20, image: image)], edges: [],
            unresolvedEdges: [.init(caller: key(10, image: image), callSite: 11)],
            operation: NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget())
        )
        let report = try path(10, 20, in: input)
        XCTAssertEqual(report.status, .notFoundInObservedGraph)
        XCTAssertEqual(report.examinedUnverifiedEdges, 1)
        XCTAssertEqual(report.observedUnverifiedEdges, 1)
        XCTAssertEqual(report.visitedEdges, 1)
    }

    func testUnresolvedEdgesAtDepthBoundaryConsumeTheEdgeBudget() throws {
        let image = try image()
        let input = try NEWFEATURESGraphSnapshot(
            functions: [key(10, image: image), key(20, image: image)], edges: [],
            unresolvedEdges: [
                .init(caller: key(10, image: image), callSite: 11),
                .init(caller: key(10, image: image), callSite: 12),
            ], operation: NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget())
        )
        let report = try path(10, 20, in: input,
                              budget: NEWFEATURESReadBudget(maxDepth: 0, maxEdgeVisits: 1))
        XCTAssertEqual(report.status, .edgeVisitLimit)
        XCTAssertEqual(report.visitedEdges, 1)
        XCTAssertEqual(report.examinedUnverifiedEdges, 1)
    }
}

private final class CancellationCounter: @unchecked Sendable {
    private let lock = NSLock()
    private let cancelAt: Int
    private var calls = 0

    init(cancelAt: Int) { self.cancelAt = cancelAt }

    func shouldCancel() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        calls += 1
        return calls >= cancelAt
    }
}
