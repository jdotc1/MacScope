import Foundation
import XCTest
@testable import NEWFEATURESCore

private actor FixedProvider: NEWFEATURESNativeDecompiling {
    private var seen: [NEWFEATURESFunctionKey] = []
    let responseKeyOverride: NEWFEATURESFunctionKey?
    let output: String
    init(responseKeyOverride: NEWFEATURESFunctionKey? = nil, output: String = "return 1;") {
        self.responseKeyOverride = responseKeyOverride
        self.output = output
    }

    func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse {
        seen.append(request.function)
        let observed = responseKeyOverride ?? request.function
        let witness = try! NEWFEATURESNativeWorkerReceipt(
            observedFunction: observed, artifactID: UUID(), nativeFunctionID: UUID(),
            requestDigestSHA256: String(repeating: "d", count: 64)
        )
        return NEWFEATURESDecompileResponse(
            function: observed,
            backend: .nativeSleigh, text: output, complete: true,
            workerReceipt: witness
        )
    }
    func count() -> Int { seen.count }
}

private actor FixedSourceChecker: NEWFEATURESSourceChecking {
    var isValid: Bool
    var expiryAfterReads: Int?
    private var readCount = 0
    init(_ isValid: Bool) { self.isValid = isValid }
    func expire(afterReads: Int) { expiryAfterReads = afterReads }
    func isCurrent(_ admission: NEWFEATURESLedgerAdmission) async -> Bool {
        readCount += 1
        return isValid && (expiryAfterReads.map { readCount <= $0 } ?? true)
    }
    func admits(
        _ response: NEWFEATURESDecompileResponse,
        for request: NEWFEATURESDecompileRequest,
        admission: NEWFEATURESLedgerAdmission
    ) async -> Bool {
        guard request.function.image == admission.image else { return false }
        switch response.backend {
        case .nativeSleigh: return response.workerReceipt?.observedFunction == request.function
        case .macIRFallback: return response.fallbackReceipt?.observedFunction == request.function
        case .unavailable: return false
        }
    }
}

final class RecursiveDecompilationTests: XCTestCase {
    private func fixture() throws -> (NEWFEATURESGraphSnapshot, NEWFEATURESFunctionKey, NEWFEATURESFunctionKey) {
        let i = try NEWFEATURESImageKey(
            slot: 0, binaryID: UUID(), sha256: String(repeating: "b", count: 64),
            analysisRevision: 5
        )
        let a = NEWFEATURESFunctionKey(image: i, address: 100)
        let b = NEWFEATURESFunctionKey(image: i, address: 200)
        let graph = try NEWFEATURESGraphSnapshot(functions: [a, b], edges: [
            .init(caller: a, callee: b, callSite: 104, confidence: .confirmedDirect),
            .init(caller: b, callee: a, callSite: 204, confidence: .confirmedDirect),
        ], operation: NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget()))
        return (graph, a, b)
    }

    private func admission(_ function: NEWFEATURESFunctionKey) throws -> NEWFEATURESLedgerAdmission {
        NEWFEATURESLedgerAdmission(image: function.image)
    }

    func testCyclesDecompileEachFunctionOnce() async throws {
        let (graph, a, _) = try fixture()
        let provider = FixedProvider()
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: NEWFEATURESReadBudget(),
            provider: provider, sourceChecker: FixedSourceChecker(true)
        )
        XCTAssertEqual(report.results.count, 2)
        XCTAssertEqual(report.acceptedNativeFunctionCount, 2)
        let observed = await provider.count()
        XCTAssertEqual(observed, 2)
    }

    func testStaleWorkerEchoRejected() async throws {
        let (graph, a, b) = try fixture()
        let provider = FixedProvider(responseKeyOverride: b)
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: NEWFEATURESReadBudget(),
            provider: provider, sourceChecker: FixedSourceChecker(true)
        )
        XCTAssertEqual(report.termination, .sourceChanged)
        XCTAssertEqual(report.results.first?.outcome, .stale)
        XCTAssertNil(report.results.first?.text)
    }

    func testNoSourceAuthorityMeansNoWorkerOperation() async throws {
        let (graph, a, _) = try fixture()
        let provider = FixedProvider()
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: NEWFEATURESReadBudget(),
            provider: provider, sourceChecker: FixedSourceChecker(false)
        )
        XCTAssertEqual(report.termination, .sourceChanged)
        XCTAssertEqual(report.results.count, 0)
        let count = await provider.count()
        XCTAssertEqual(count, 0)
    }

    func testRevocationAtFinalReadPurgesEarlierText() async throws {
        let (graph, a, _) = try fixture()
        let checker = FixedSourceChecker(true)
        // Two functions: before/after each (4 checks), then final (5th).
        await checker.expire(afterReads: 4)
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: NEWFEATURESReadBudget(),
            provider: FixedProvider(), sourceChecker: checker
        )
        XCTAssertEqual(report.termination, .sourceChanged)
        XCTAssertFalse(report.internallyValidatedAtReturn)
        XCTAssertTrue(report.results.allSatisfy { $0.text == nil })
    }

    func testAggregateOutputBudgetStopsAndClassifiesPartial() async throws {
        let (graph, a, _) = try fixture()
        let budget = try NEWFEATURESReadBudget(
            maxOutputBytesPerFunction: 128,
            maxTotalUTF8Bytes: 12
        )
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: budget,
            provider: FixedProvider(output: "return 1;"), sourceChecker: FixedSourceChecker(true)
        )
        XCTAssertEqual(report.termination, .outputLimit)
        XCTAssertEqual(report.results.filter { $0.text != nil }.count, 1)
    }

    func testWorkerDeadlineBoundsCoordinatorWait() async throws {
        let (graph, a, _) = try fixture()
        let provider = DelayedProvider()
        let budget = try NEWFEATURESReadBudget(maxElapsedSeconds: 1)
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: budget,
            provider: provider, sourceChecker: FixedSourceChecker(true)
        )
        XCTAssertEqual(report.termination, .deadlineExceeded)
        XCTAssertTrue(report.results.allSatisfy { $0.text == nil })
    }

    func testTimedOutCoordinatorRefusesNewNativeBatch() async throws {
        let (graph, a, _) = try fixture()
        let coordinator = NEWFEATURESRecursiveCoordinator()
        let budget = try NEWFEATURESReadBudget(maxElapsedSeconds: 1)
        let report = try await coordinator.execute(
            root: a, graph: graph, admission: admission(a), budget: budget,
            provider: DelayedProvider(), sourceChecker: FixedSourceChecker(true)
        )
        XCTAssertEqual(report.termination, .deadlineExceeded)
        do {
            _ = try await coordinator.execute(
                root: a, graph: graph, admission: admission(a),
                budget: budget, provider: FixedProvider(), sourceChecker: FixedSourceChecker(true)
            )
            XCTFail("a poisoned coordinator must not re-use a possibly live native XPC request")
        } catch {
            XCTAssertEqual(error as? NEWFEATURESError, .nativeWorkerNeedsRecovery)
        }
    }

    func testSourceBoundMacIRFallbackIsNotNativeSuccess() async throws {
        let (graph, a, _) = try fixture()
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: a, graph: graph, admission: admission(a), budget: NEWFEATURESReadBudget(),
            provider: MacIRProvider(), sourceChecker: FixedSourceChecker(true)
        )
        XCTAssertEqual(report.results.count, 2)
        XCTAssertTrue(report.results.allSatisfy { $0.outcome == .fallback })
        XCTAssertEqual(report.acceptedNativeFunctionCount, 0)
    }
}

private actor DelayedProvider: NEWFEATURESNativeDecompiling {
    func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse {
        try? await Task.sleep(for: .seconds(30))
        return NEWFEATURESDecompileResponse(
            function: request.function, backend: .unavailable, text: nil,
            complete: false, refusalCode: "delayed"
        )
    }
}

private actor MacIRProvider: NEWFEATURESNativeDecompiling {
    func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse {
        let receipt = try! NEWFEATURESMacIRReceipt(
            observedFunction: request.function, macIRArtifactID: UUID(),
            sourceSHA256: request.function.image.sha256
        )
        return NEWFEATURESDecompileResponse(
            function: request.function, backend: .macIRFallback, text: "return 0;",
            complete: false, fallbackReceipt: receipt
        )
    }
}
