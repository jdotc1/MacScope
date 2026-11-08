import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

@MainActor
final class NEWFEATURESSubsystemsLinkTests: XCTestCase {
    private var previousResolver: NEWFEATURESSessionLookup.Resolver?

    override func setUp() {
        super.setUp()
        previousResolver = NEWFEATURESSessionLookup.resolver
    }

    override func tearDown() {
        NEWFEATURESSessionLookup.install(previousResolver)
        super.tearDown()
    }

    // MARK: (a) browser case list

    func testSubsystemsIsTheLastBrowserPaneExactlyOnce() {
        let names = BrowserPane.allCases.map(\.displayName)
        XCTAssertEqual(names.filter { $0 == "Subsystems" }.count, 1, "\(names)")
        XCTAssertEqual(BrowserPane.allCases.last, .subsystems)
        XCTAssertEqual(BrowserPane.allCases.count, 4)
        XCTAssertFalse(BrowserPane.subsystems.systemImage.isEmpty)
    }

    // MARK: (b) host model over a fixture projection

    private func fixture(edges: (UInt64, UInt64, UInt64, NEWFEATURESCallConfidence)...) throws
        -> (graph: NEWFEATURESGraphSnapshot, key: (UInt64) -> NEWFEATURESFunctionKey, budget: NEWFEATURESReadBudget) {
        let image = try NEWFEATURESImageKey(
            documentInstance: UUID(), workspaceInstance: UUID(), slot: 0, binaryID: UUID(),
            ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: String(repeating: "a", count: 64), analysisRevision: 7,
            analysisInputFingerprintSHA256: String(repeating: "b", count: 64))
        let budget = try NEWFEATURESReadBudget()
        let key = { (address: UInt64) in NEWFEATURESFunctionKey(image: image, address: address) }
        let graph = try NEWFEATURESGraphSnapshot(
            functions: [0x1000, 0x2000, 0x3000].map(key),
            edges: edges.map { NEWFEATURESCallEdge(caller: key($0.0), callee: key($0.1), callSite: $0.2, confidence: $0.3) },
            operation: NEWFEATURESGraphOperation(budget: budget))
        return (graph, key, budget)
    }

    func testHostModelBuildsViewInputFromFixtureProjection() throws {
        let f = try fixture(edges: (0x1000, 0x2000, 0x1004, .confirmedDirect),
                            (0x2000, 0x3000, 0x2008, .confirmedDirect))
        let input = try NEWFEATURESSubsystemExplorerHostModel.input(
            graph: f.graph, source: f.key(0x1000), destination: f.key(0x3000), budget: f.budget)
        XCTAssertEqual(input.path?.status, .found)
        XCTAssertEqual(input.path?.path.map(\.address), [0x1000, 0x2000, 0x3000])
        XCTAssertNil(input.batch)
        XCTAssertFalse(input.isWorking)
    }

    func testHostModelNeverTraversesUnverifiedEdgeAndAnalyzeStaysDisabled() throws {
        let f = try fixture(edges: (0x1000, 0x3000, 0x1004, .unverified))
        let input = try NEWFEATURESSubsystemExplorerHostModel.input(
            graph: f.graph, source: f.key(0x1000), destination: f.key(0x3000), budget: f.budget)
        XCTAssertEqual(input.path?.status, .notFoundInObservedGraph)
        XCTAssertEqual(input.path?.path.count, 0)
        XCTAssertFalse(NEWFEATURESSubsystemExplorerHostModel.analyzeEnabled)
        XCTAssertNil(NEWFEATURESSubsystemExplorerHostModel.idle.path)
        XCTAssertNil(NEWFEATURESSubsystemExplorerHostModel.idle.batch)
    }

    // MARK: (c) attached exposure

    func testAttachAllowlistIncludesVerifiedCallPath() {
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains(NEWFEATURESMCPReads.callPathCommand))
        XCTAssertTrue(NavigatorMCPCommands.attachable.isSubset(of: MCPAttachExecutor.attachCommands))
    }

    func testAttachedCallWithNoDocumentSessionGetsNamedRefusal() async {
        NEWFEATURESSessionLookup.install(nil)
        let store = WorkspaceStore(workspaceName: "Attach", snapshot: AnalysisEngine.previewSnapshot(),
                                   engine: AnalysisEngine())
        defer { withExtendedLifetime(store) {} }
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let arguments = ScriptValue.object(["imageSlot": .int(0), "source": .string("0x1000"),
                                            "target": .string("0x2000")])
        do {
            let value = try await executor.execute(NEWFEATURESMCPReads.callPathCommand, arguments)
            XCTAssertEqual(value["error"], .string("refused"))
            XCTAssertEqual(value["refusal"]?["code"]?.stringValue, "preconditionFailed")
            XCTAssertEqual(value["refusal"]?["detail"]?.stringValue, "document session unavailable")
            XCTAssertEqual(value["refusal"]?["retryable"], .bool(false))
        } catch {
            XCTFail("expected a refusal envelope, got thrown error \(error)")
        }
    }
}
