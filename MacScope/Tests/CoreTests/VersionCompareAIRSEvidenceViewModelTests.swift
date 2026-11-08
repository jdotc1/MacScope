import Foundation
import XCTest
@testable import MacScope

private actor VersionCompareAIRSSuspendedWorker {
    private var continuation: CheckedContinuation<UnwindAuditComparison, any Error>?
    private var started: CheckedContinuation<Void, Never>?
    func run() async throws -> UnwindAuditComparison {
        try await withCheckedThrowingContinuation {
            continuation = $0
            started?.resume()
            started = nil
        }
    }
    func waitUntilStarted() async {
        if continuation != nil { return }
        await withCheckedContinuation { started = $0 }
    }
    func finish(_ comparison: UnwindAuditComparison) {
        continuation?.resume(returning: comparison)
        continuation = nil
    }
}

@MainActor
final class VersionCompareAIRSEvidenceViewModelTests: XCTestCase {
    private func envelope(named: Bool = true) throws -> AIRSEvidenceEnvelope {
        .init(records: [try VersionCompareAIRSFixture.record(VersionCompareAIRSFixture.report(named: named)),
                        try VersionCompareAIRSFixture.record(VersionCompareAIRSFixture.report(named: named))])
    }

    private func settle(_ model: VersionCompareAIRSEvidenceViewModel) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while model.phase == .running, clock.now < deadline {
            try? await clock.sleep(for: .milliseconds(5))
        }
        return model.phase == .ready
    }

    func testSavedPairWorksWithoutLoadedImagesAndRejectsSameRecord() async throws {
        let records = try envelope()
        let model = VersionCompareAIRSEvidenceViewModel()
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: UUID())
        model.run()
        let ready = await settle(model)
        XCTAssertTrue(ready)
        XCTAssertEqual(model.comparison?.changes.map(\.change), [.unchanged])
        XCTAssertNotEqual(model.baselineID, model.currentID)
        model.selectCurrent(model.baselineID)
        XCTAssertNil(model.comparison)
        XCTAssertEqual(model.phase, .idle)
    }

    func testWorkspaceReplacementAndRecordRemovalDiscardPublishedComparison() async throws {
        let records = try envelope()
        let installation = UUID()
        let model = VersionCompareAIRSEvidenceViewModel()
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
        model.run()
        let ready = await settle(model)
        XCTAssertTrue(ready)
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: UUID())
        XCTAssertNil(model.comparison)
        XCTAssertEqual(model.phase, .idle)
        model.run()
        let readyAgain = await settle(model)
        XCTAssertTrue(readyAgain)
        model.bind(.init(records: [records.records[0]]), workspaceID: VersionCompareAIRSFixture.workspace,
                   installationID: installation)
        XCTAssertNil(model.comparison)
        XCTAssertNil(model.currentID)
        XCTAssertFalse(model.canCompare)
    }

    func testCancelledOrReplacedRequestCannotPublishLateWorkerResult() async throws {
        for replacement in 0...3 {
            let records = try envelope()
            let paused = VersionCompareAIRSSuspendedWorker()
            let model = VersionCompareAIRSEvidenceViewModel(worker: { _, _, _ in try await paused.run() })
            let installation = UUID()
            model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
            let task = try XCTUnwrap(model.run())
            await paused.waitUntilStarted()
            switch replacement {
            case 1:
                model.bind(.init(), workspaceID: UUID(), installationID: UUID())
            case 2:
                model.bind(.init(records: [records.records[0]]),
                    workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
            case 3: model.selectCurrent(model.baselineID)
            default: model.cancel()
            }
            let report = try VersionCompareAIRSFixture.report()
            await paused.finish(try UnwindAuditComparator.compare(baseline: report, current: report))
            await task.value
            XCTAssertNil(model.comparison)
            XCTAssertEqual(model.phase, .idle)
        }
    }

    func testPinsUseExistingValidationAndResetWhenPairChanges() async throws {
        let records = try envelope(named: false)
        let model = VersionCompareAIRSEvidenceViewModel()
        let installation = UUID()
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
        model.run()
        let ready = await settle(model)
        XCTAssertTrue(ready)
        model.pin(oldID: "missing", newID: "f0")
        XCTAssertNotNil(model.pinError)
        XCTAssertEqual(model.comparison?.matching.manualPins, [])
        model.pin(oldID: "f0", newID: "f0")
        let pinned = await settle(model)
        XCTAssertTrue(pinned)
        XCTAssertEqual(model.comparison?.matching.matches.first?.basis, .manual)
        XCTAssertEqual(model.comparison?.matching.matches.first?.confidence, .userConfirmed)
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
        XCTAssertEqual(model.comparison?.matching.manualPins, [.init(oldID: "f0", newID: "f0")])
        XCTAssertEqual(model.phase, .ready)
        model.pin(oldID: "f0", newID: "f0")
        XCTAssertNotNil(model.pinError)
        model.selectBaseline(model.currentID)
        XCTAssertNil(model.comparison)
        XCTAssertNil(model.pinError)
    }

    func testInvalidEnvelopeFailsWithoutLeavingOldComparisonOrInventory() async throws {
        let records = try envelope()
        let model = VersionCompareAIRSEvidenceViewModel()
        let installation = UUID()
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
        model.run()
        let ready = await settle(model)
        XCTAssertTrue(ready)
        model.bind(records, workspaceID: UUID(), installationID: installation)
        XCTAssertNil(model.comparison)
        XCTAssertTrue(model.inventory.entries.isEmpty)
        guard case .failed = model.phase else { return XCTFail("Wrong-workspace evidence must fail") }
    }

    func testUnresolvedPairsAppearFirstAndUnchangedBindRetainsPublishedComparison() async throws {
        let report = try VersionCompareAIRSFixture.report(["agreement", "unresolved"])
        let records = AIRSEvidenceEnvelope(records: [try VersionCompareAIRSFixture.record(report),
                                                    try VersionCompareAIRSFixture.record(report)])
        let installation = UUID()
        let model = VersionCompareAIRSEvidenceViewModel()
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
        model.run()
        let ready = await settle(model)
        XCTAssertTrue(ready)
        XCTAssertEqual(model.orderedChanges.map(\.match.oldID), ["f1", "f0"])
        let published = model.comparison
        model.bind(records, workspaceID: VersionCompareAIRSFixture.workspace, installationID: installation)
        XCTAssertEqual(model.comparison, published)
        XCTAssertEqual(model.phase, .ready)
    }
}
