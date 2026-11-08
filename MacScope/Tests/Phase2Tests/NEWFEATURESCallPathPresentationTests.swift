import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope
@testable import MacScopeAnalysisCore

/// Drives the call-path presentation model with injected closures only. No document is opened and
/// no analysis runs: contexts come from one empty store and the runner is a test-owned closure
/// that signals entry, optionally suspends on a continuation, and signals when it returns.
@MainActor
final class NEWFEATURESCallPathPresentationTests: XCTestCase {
    private typealias Model = NEWFEATURESCallPathPresentation

    private let sessionID = WorkspaceDocumentSessionID(rawValue: UUID())
    private var store: WorkspaceStore!
    private var context: NEWFEATURESCallPathViewContext?
    private var runnerCalls = 0
    private var gate: CheckedContinuation<Void, Never>?
    private var navigated: [(NEWFEATURESCallPathRow, NEWFEATURESImageKey)] = []
    private var imageKey: NEWFEATURESImageKey!

    override func setUp() async throws {
        store = WorkspaceStore(workspaceName: "Call path presentation", snapshot: .init(binaries: [], analysisBySlot: [:]),
                               engine: AnalysisEngine(), autosaveScheduler: nil)
        context = makeContext(slot: .primary)
        runnerCalls = 0
        gate = nil
        navigated = []
        imageKey = try NEWFEATURESImageKey(
            documentInstance: UUID(), workspaceInstance: UUID(), slot: 0, binaryID: UUID(),
            ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: String(repeating: "a", count: 64), analysisRevision: 1,
            analysisInputFingerprintSHA256: String(repeating: "b", count: 64)
        )
    }

    // MARK: Helpers

    private func makeContext(slot: ImageSlot, selection: ImageAddress? = nil) -> NEWFEATURESCallPathViewContext {
        NEWFEATURESCallPathViewContext(source: .init(
            scene: EditorSceneIdentity(store: store), sessionID: sessionID, focusedSlot: slot,
            state: store.phase2ReadCurrentState(for: slot)
        ), selection: selection)
    }

    private func makeModel(run: @escaping Model.Runner) -> Model {
        let model = Model(
            currentContext: { [unowned self] in self.context },
            run: run,
            navigate: { [unowned self] row, image in
                self.navigated.append((row, image))
                return true
            }
        )
        model.sourceText = "0x1000"
        model.destinationText = "0x2000"
        return model
    }

    /// A real two-function report from the package pathfinder; the report has no public initializer.
    private func makeDelivery(ids: [UUID], unresolved: Int = 3) throws -> NEWFEATURESCallPathDelivery {
        let first = NEWFEATURESFunctionKey(image: imageKey, address: 0x1000)
        let second = NEWFEATURESFunctionKey(image: imageKey, address: 0x2000)
        let budget = try NEWFEATURESReadBudget()
        let operation = NEWFEATURESGraphOperation(budget: budget)
        let graph = try NEWFEATURESGraphSnapshot(
            functions: [first, second],
            edges: [NEWFEATURESCallEdge(caller: first, callee: second, callSite: 0x1004, confidence: .confirmedDirect)],
            operation: operation
        )
        let report = try NEWFEATURESPathfinder.shortestVerifiedPath(
            from: first, to: second, graph: graph, budget: budget, operation: operation
        )
        let result = NEWFEATURESCallPathResult(
            report: report, pathFunctionIDs: ids, unresolvedObservationCount: unresolved,
            unresolvedSamples: [], unresolvedSamplesTruncated: false, constructionWork: 0
        )
        return NEWFEATURESCallPathDelivery(result: result, encoded: try JSONEncoder().encode(result))
    }

    /// Bounded wait for retirement of the model's private task.
    private func settle(_ model: Model, file: StaticString = #filePath, line: UInt = #line) async {
        for _ in 0..<100 where model.isBusy { await Task.yield() }
        XCTAssertFalse(model.isBusy, "model did not retire within 100 yields", file: file, line: line)
    }

    private func resumeGate() {
        let continuation = gate
        gate = nil
        continuation?.resume()
    }

    // MARK: parseAddress

    func testP1ParseAddressAcceptsHexWithOrWithoutPrefixAndWhitespace() {
        XCTAssertEqual(Model.parseAddress("0x1f"), 0x1f)
        XCTAssertEqual(Model.parseAddress("1F"), 0x1f)
        XCTAssertEqual(Model.parseAddress(" 0x10 \n"), 0x10)
    }

    func testP2ParseAddressRejectsMalformedAndOversizedText() {
        XCTAssertNil(Model.parseAddress(""))
        XCTAssertNil(Model.parseAddress("0x"))
        XCTAssertNil(Model.parseAddress("g1"))
        XCTAssertNil(Model.parseAddress(String(repeating: "1", count: 17)))
        XCTAssertNil(Model.parseAddress(String(repeating: "1", count: 33)))
    }

    // MARK: start() refusals

    func testP3StartWithoutContextIsRefusedUnavailable() {
        let model = makeModel { [unowned self] _, _ in self.runnerCalls += 1 }
        context = nil
        model.start()
        XCTAssertEqual(model.phase, .refused(.unavailable))
        XCTAssertEqual(runnerCalls, 0)
        XCTAssertFalse(model.isBusy)
    }

    func testP4StartWithInvalidDestinationIsRefusedInvalidAddress() {
        let model = makeModel { [unowned self] _, _ in self.runnerCalls += 1 }
        model.destinationText = "zz"
        model.start()
        XCTAssertEqual(model.phase, .refused(.invalidAddress))
        XCTAssertEqual(runnerCalls, 0)
        XCTAssertFalse(model.isBusy)
    }

    // MARK: Runs

    func testP5PublishedDeliveryBecomesFinishedRowsAndSummary() async throws {
        let ids = [UUID(), UUID()]
        let delivery = try makeDelivery(ids: ids)
        let returned = expectation(description: "runner returned")
        let model = makeModel { [unowned self] _, publish in
            defer { returned.fulfill() }
            self.runnerCalls += 1
            publish(delivery)
        }
        model.start()
        await fulfillment(of: [returned], timeout: 5)
        await settle(model)

        XCTAssertEqual(model.phase, .finished)
        XCTAssertEqual(model.rows.map(\.id), ids)
        XCTAssertEqual(model.rows.map(\.address), [0x1000, 0x2000])
        let report = delivery.result.report
        XCTAssertEqual(model.summary, Model.Summary(
            status: report.status, visitedFunctions: report.visitedFunctions, visitedEdges: report.visitedEdges,
            unresolvedObservations: 3, examinedUnverifiedEdges: report.examinedUnverifiedEdges
        ))
        XCTAssertEqual(model.summary?.status, .found)
    }

    func testP6RunnerOutputLimitFailureIsRefusedWithoutRows() async {
        let returned = expectation(description: "runner returned")
        let model = makeModel { _, _ in
            defer { returned.fulfill() }
            throw NEWFEATURESCallPathFailure.outputLimit
        }
        model.start()
        await fulfillment(of: [returned], timeout: 5)
        await settle(model)

        XCTAssertEqual(model.phase, .refused(.outputLimit))
        XCTAssertTrue(model.rows.isEmpty)
        XCTAssertNil(model.summary)
    }

    func testP7CancelWhileSuspendedRetiresAsCancelled() async {
        let entered = expectation(description: "runner entered")
        let returned = expectation(description: "runner returned")
        let model = makeModel { [unowned self] _, _ in
            defer { returned.fulfill() }
            self.runnerCalls += 1
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                self.gate = continuation
                entered.fulfill()
            }
        }
        model.start()
        await fulfillment(of: [entered], timeout: 5)
        XCTAssertTrue(model.isBusy)

        model.cancel()
        XCTAssertEqual(model.phase, .cancelling)
        resumeGate()
        await fulfillment(of: [returned], timeout: 5)
        await settle(model)

        XCTAssertEqual(model.phase, .refused(.cancelled))
        XCTAssertFalse(model.isBusy)
        XCTAssertTrue(model.rows.isEmpty)
    }

    func testP8SourceChangeBeforePublishCancelsAndDiscardsTheResult() async throws {
        let delivery = try makeDelivery(ids: [UUID(), UUID()])
        let entered = expectation(description: "runner entered")
        let returned = expectation(description: "runner returned")
        var phaseAfterPublish: Model.Phase?
        var rowsAfterPublish: [NEWFEATURESCallPathRow]?
        var model: Model!
        model = makeModel { [unowned self] _, publish in
            defer { returned.fulfill() }
            self.runnerCalls += 1
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                self.gate = continuation
                entered.fulfill()
            }
            publish(delivery)
            phaseAfterPublish = model.phase
            rowsAfterPublish = model.rows
        }
        model.start()
        await fulfillment(of: [entered], timeout: 5)

        context = makeContext(slot: ImageSlot(rawValue: 1))
        resumeGate()
        await fulfillment(of: [returned], timeout: 5)
        await settle(model)

        XCTAssertEqual(phaseAfterPublish, .cancelling)
        XCTAssertEqual(rowsAfterPublish, [])
        XCTAssertEqual(model.phase, .refused(.sourceChanged))
        XCTAssertTrue(model.rows.isEmpty)
        XCTAssertNil(model.summary)
    }

    func testP9StartWhileBusyDoesNotInvokeTheRunnerAgain() async {
        let entered = expectation(description: "runner entered")
        let returned = expectation(description: "runner returned")
        let model = makeModel { [unowned self] _, _ in
            defer { returned.fulfill() }
            self.runnerCalls += 1
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                self.gate = continuation
                entered.fulfill()
            }
        }
        model.start()
        await fulfillment(of: [entered], timeout: 5)
        model.start()
        XCTAssertEqual(runnerCalls, 1)

        resumeGate()
        await fulfillment(of: [returned], timeout: 5)
        await settle(model)
        XCTAssertEqual(runnerCalls, 1)
    }

    func testP10SelectingARowNavigatesWithTheResultImage() async throws {
        let ids = [UUID(), UUID()]
        let delivery = try makeDelivery(ids: ids)
        let returned = expectation(description: "runner returned")
        let model = makeModel { _, publish in
            defer { returned.fulfill() }
            publish(delivery)
        }
        model.start()
        await fulfillment(of: [returned], timeout: 5)
        await settle(model)
        XCTAssertEqual(model.phase, .finished)

        let row = try XCTUnwrap(model.rows.first)
        model.select(row)
        XCTAssertEqual(navigated.count, 1)
        XCTAssertEqual(navigated.first?.0, row)
        XCTAssertEqual(navigated.first?.1, imageKey)
    }
}
