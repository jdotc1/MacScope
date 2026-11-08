import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

final class NEWFEATURESScriptValueProjectionTests: XCTestCase {
    private var image: NEWFEATURESImageKey!
    private var admission: NEWFEATURESLedgerAdmission!
    private var budget: NEWFEATURESReadBudget!

    override func setUpWithError() throws {
        image = try NEWFEATURESImageKey(
            documentInstance: UUID(), workspaceInstance: UUID(), slot: 0, binaryID: UUID(),
            ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: String(repeating: "a", count: 64), analysisRevision: 7,
            analysisInputFingerprintSHA256: String(repeating: "b", count: 64)
        )
        admission = NEWFEATURESLedgerAdmission(image: image)
        budget = try NEWFEATURESReadBudget()
    }

    private func key(_ address: UInt64) -> NEWFEATURESFunctionKey {
        NEWFEATURESFunctionKey(image: image, address: address)
    }

    private func chainGraph() throws -> NEWFEATURESGraphSnapshot {
        let edges = [
            NEWFEATURESCallEdge(caller: key(0x1000), callee: key(0x2000), callSite: 0x1004, confidence: .confirmedDirect),
            NEWFEATURESCallEdge(caller: key(0x2000), callee: key(0x3000), callSite: 0x2004, confidence: .confirmedDirect),
        ]
        return try NEWFEATURESGraphSnapshot(
            functions: [key(0x1000), key(0x2000), key(0x3000)], edges: edges,
            operation: NEWFEATURESGraphOperation(budget: budget)
        )
    }

    private func pathReport() throws -> NEWFEATURESPathReport {
        try NEWFEATURESPathfinder.shortestVerifiedPath(
            from: key(0x1000), to: key(0x3000), graph: try chainGraph(), budget: budget,
            operation: NEWFEATURESGraphOperation(budget: budget)
        )
    }

    func testPathProjectionShapeAndTotals() throws {
        let report = try pathReport()
        XCTAssertEqual(report.status, .found)
        let value = NEWFEATURESScriptValueProjection.path(report, admission: admission, currentLedgerAdmission: true)
        XCTAssertEqual(value["status"]?.stringValue, "found")
        XCTAssertEqual(value["pathLength"]?.intValue, 3)
        XCTAssertEqual(value["pathTruncated"]?.boolValue, false)
        let path = try XCTUnwrap(value["path"]?.arrayValue)
        XCTAssertEqual(path.compactMap { $0["address"]?.stringValue }, ["0x1000", "0x2000", "0x3000"])
        XCTAssertEqual(path.first?["imageSlot"]?.intValue, 0)
        XCTAssertEqual(path.first?["analysisRevision"]?.stringValue, "7")
        XCTAssertEqual(path.first?["sha256"]?.stringValue, String(repeating: "a", count: 64))
        XCTAssertEqual(path.first?["imageID"]?.stringValue, image.binaryID.uuidString)
        XCTAssertEqual(value["source"]?["address"]?.stringValue, "0x1000")
        XCTAssertEqual(value["destination"]?["address"]?.stringValue, "0x3000")
    }

    func testPathProjectionRevokedAdmissionPublishesNothing() throws {
        let report = try pathReport()
        let stale = NEWFEATURESScriptValueProjection.path(report, admission: admission, currentLedgerAdmission: false)
        XCTAssertEqual(stale["status"]?.stringValue, "source-or-publication-admission-revoked")
        XCTAssertEqual(stale["path"]?.arrayValue?.count, 0)

        let foreign = NEWFEATURESLedgerAdmission(image: try NEWFEATURESImageKey(
            documentInstance: image.documentInstance, workspaceInstance: image.workspaceInstance, slot: 1,
            binaryID: UUID(), ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: String(repeating: "c", count: 64), analysisRevision: 7,
            analysisInputFingerprintSHA256: String(repeating: "b", count: 64)
        ))
        let mismatched = NEWFEATURESScriptValueProjection.path(report, admission: foreign, currentLedgerAdmission: true)
        XCTAssertEqual(mismatched["status"]?.stringValue, "source-or-publication-admission-revoked")
    }

    private struct Provider: NEWFEATURESNativeDecompiling {
        let image: NEWFEATURESImageKey
        func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse {
            let receipt = try? NEWFEATURESNativeWorkerReceipt(
                observedFunction: request.function, artifactID: UUID(), nativeFunctionID: UUID(),
                requestDigestSHA256: String(repeating: "d", count: 64)
            )
            return NEWFEATURESDecompileResponse(
                function: request.function, backend: .nativeSleigh,
                text: "void f_\(String(request.function.address, radix: 16))(void) {}",
                complete: true, workerReceipt: receipt
            )
        }
    }

    private struct Checker: NEWFEATURESSourceChecking {
        func isCurrent(_ admission: NEWFEATURESLedgerAdmission) async -> Bool { true }
        func admits(_ response: NEWFEATURESDecompileResponse, for request: NEWFEATURESDecompileRequest,
                    admission: NEWFEATURESLedgerAdmission) async -> Bool { true }
    }

    func testRecursiveProjectionIsBoundedWithTotals() async throws {
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: key(0x1000), graph: try chainGraph(), admission: admission, budget: budget,
            provider: Provider(image: image), sourceChecker: Checker()
        )
        XCTAssertEqual(report.acceptedNativeFunctionCount, 3)
        let value = NEWFEATURESScriptValueProjection.recursive(report, currentLedgerAdmission: true)
        XCTAssertEqual(value["termination"]?.stringValue, "exhaustedObservedPlan")
        XCTAssertEqual(value["acceptedNativeFunctions"]?.intValue, 3)
        XCTAssertEqual(value["totalResults"]?.intValue, 3)
        XCTAssertEqual(value["resultsTruncated"]?.boolValue, false)
        let results = try XCTUnwrap(value["results"]?.arrayValue)
        XCTAssertEqual(results.count, 3)
        XCTAssertEqual(results.first?["outcome"]?.stringValue, "nativeComplete")
        XCTAssertEqual(results.first?["backend"]?.stringValue, "nativeSleigh")
        XCTAssertNotNil(results.first?["text"]?.stringValue)
        XCTAssertEqual(results.first?["function"]?["address"]?.stringValue, "0x1000")
    }

    func testRecursiveProjectionRevokedPublishesNoText() async throws {
        let report = try await NEWFEATURESRecursiveCoordinator().execute(
            root: key(0x1000), graph: try chainGraph(), admission: admission, budget: budget,
            provider: Provider(image: image), sourceChecker: Checker()
        )
        let value = NEWFEATURESScriptValueProjection.recursive(report, currentLedgerAdmission: false)
        XCTAssertEqual(value["termination"]?.stringValue, "source-or-publication-admission-revoked")
        XCTAssertEqual(value["acceptedNativeFunctions"]?.intValue, 0)
        XCTAssertEqual(value["results"]?.arrayValue?.count, 0)
    }

    func testUnwiredProviderRefusesWithoutTextAndAppCheckerGatesAdmission() async throws {
        let coordinator = NEWFEATURESRecursiveCoordinator()
        let unwired = try await coordinator.execute(
            root: key(0x1000), graph: try chainGraph(), admission: admission, budget: budget,
            provider: NEWFEATURESUnwiredNativeProvider(), sourceChecker: Checker()
        )
        XCTAssertEqual(unwired.acceptedNativeFunctionCount, 0)
        XCTAssertTrue(unwired.results.allSatisfy { $0.outcome == .unavailable && $0.text == nil })
        XCTAssertEqual(unwired.results.first?.reason, "native-batch-admission-not-wired")

        // The app checker refuses a native response whose validator rejects it.
        let rejecting = NEWFEATURESAppSourceChecker(
            currentLedgerAdmission: { _ in true },
            validateNativeExport: { _, _, _ in false },
            validateMacIRArtifact: { _, _, _ in false }
        )
        let rejected = try await NEWFEATURESRecursiveCoordinator().execute(
            root: key(0x1000), graph: try chainGraph(), admission: admission, budget: budget,
            provider: Provider(image: image), sourceChecker: rejecting
        )
        XCTAssertEqual(rejected.acceptedNativeFunctionCount, 0)
        XCTAssertEqual(rejected.termination, .sourceChanged)
        let value = NEWFEATURESScriptValueProjection.recursive(rejected, currentLedgerAdmission: true)
        XCTAssertEqual(value["acceptedNativeFunctions"]?.intValue, 0)
    }
}
