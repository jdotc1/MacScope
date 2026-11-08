import XCTest
@testable import MacScope

final class RegenerationProgressPresentationTests: XCTestCase {
    func testDashboardOffersRegenerationCardAndHostKeepsFolderWindowLocal() throws {
        let dashboard = try source("Features/Reconstruction/ReconstructionDashboardView.swift")
        XCTAssertTrue(dashboard.contains("if let regenerationProjection"))
        XCTAssertTrue(dashboard.contains("RegenerationProgressCard("))
        let host = try source("Features/Workspace/WorkspaceRootView.swift")
        XCTAssertTrue(host.contains("@State private var regenerationFolder"))
        XCTAssertTrue(host.contains("onChooseExportFolder:"))
        XCTAssertTrue(host.contains("onNavigateToAddress:"))
        let state = try source("Features/Reconstruction/ReconstructionPresentationState.swift")
        XCTAssertFalse(state.contains("regenerationFolder"))
    }

    func testCardRetainsCaveatAndMetricIdentifiers() throws {
        let card = try source("Features/Reconstruction/RegenerationProgressCard.swift")
        XCTAssertTrue(card.contains("ReconstructionSummaryCard("))
        XCTAssertTrue(card.contains("ReconstructionMetricGrid("))
        XCTAssertTrue(card.contains("Compiles means compiles, not correct. Accepted comes only from the Reconstruction pipeline."))
        XCTAssertTrue(card.contains(".accessibilityValue("))
        XCTAssertTrue(card.contains(".accessibilityIdentifier("))
        XCTAssertTrue(card.contains("regeneration.chooseFolder"))
        XCTAssertTrue(card.contains("regeneration.function.search"))
    }

    func testHostMemoUsesCurrentValuesAtBothCallSites() throws {
        let host = try source("Features/Workspace/WorkspaceRootView.swift")
        XCTAssertTrue(host.contains("@State private var regenerationProjectionMemo = RegenerationProjectionMemo()"))
        XCTAssertTrue(host.contains("regenerationProjection: regenerationProjectionMemo.projection("))
        XCTAssertTrue(host.contains("let projection = regenerationProjectionMemo.projection(export: regenerationExport, openImages: regenerationOpenImages)"))
        XCTAssertTrue(host.contains("regenerationExport = export"))
    }

    private func source(_ path: String) throws -> String {
        try String(contentsOf: TestSourceRoot.url.appendingPathComponent("MacScope/" + path), encoding: .utf8)
    }
}
