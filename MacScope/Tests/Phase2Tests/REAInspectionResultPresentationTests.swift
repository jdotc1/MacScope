import Foundation
import XCTest
@testable import MacScope

final class REAInspectionResultPresentationTests: XCTestCase {
    func testTraceRequiresExactUniqueSupportedCandidate() throws {
        let address = "0xfffffffffffffff0"
        let implementation: [String: Any] = ["class_name": "Controller", "selector": "perform:",
            "method_type": "instance", "implementation_address": address, "decode": ["status": "decoded"]]
        let request: [String: Any] = ["input": ["metadata": ["value": [
            "objc_dispatch_implementations": [implementation], "coverage": []]]]]
        let nodes: [[String: Any]] = [
            ["id": "action", "kind": "action", "attributes": ["selector": "perform:"]],
            ["id": "source", "kind": "view"],
            ["id": "selector", "kind": "objc_selector", "name": "perform:"],
            ["id": "owner", "kind": "view_controller", "attributes": ["class_name": "Controller"]],
            ["id": "function", "kind": "function", "attributes": ["class_name": "Controller", "selector": "perform:", "method_type": "instance"], "location": ["address": address]]
        ]
        let edges: [[String: Any]] = [
            ["from": "source", "to": "action", "relation": "target_action", "resolution": "observed"],
            ["from": "action", "to": "selector", "relation": "target_action", "resolution": "observed"],
            ["from": "action", "to": "owner", "relation": "target_action", "resolution": "observed"],
            ["from": "selector", "to": "function", "relation": "objc_dispatch", "resolution": "resolved"]
        ]
        func result(_ candidates: [[String: Any]], truncated: Bool = false) -> [String: Any] {
            ["analysis": ["graph": ["nodes": nodes, "edges": edges, "truncated": truncated]], "dispatchCandidates": candidates]
        }
        let requestData = try JSONSerialization.data(withJSONObject: request)
        let valid = try JSONSerialization.data(withJSONObject: ["result": result([implementation])])
        let duplicate = try JSONSerialization.data(withJSONObject: ["result": result([implementation, implementation])])
        let truncated = try JSONSerialization.data(withJSONObject: ["result": result([implementation], truncated: true)])
        let omittedRequest = try JSONSerialization.data(withJSONObject: ["input": ["metadata": ["value": [
            "objc_dispatch_implementations": [implementation], "coverage": [["reason": "method_projection_budget_exhausted"]]]]]])
        var inferredEdges = edges
        inferredEdges[3]["resolution"] = "inferred"
        let inferred = try JSONSerialization.data(withJSONObject: ["result": ["analysis": ["graph": ["nodes": nodes, "edges": inferredEdges, "truncated": false]], "dispatchCandidates": [implementation]]])
        var unknownNodes = nodes
        unknownNodes[1]["kind"] = "unknown"
        let unknownSource = try JSONSerialization.data(withJSONObject: ["result": ["analysis": ["graph": ["nodes": unknownNodes, "edges": edges, "truncated": false]], "dispatchCandidates": [implementation]]])
        XCTAssertEqual(REAUITraceProjection.destinations(requestJSON: requestData, responseJSON: valid)["action"]?.address, UInt64.max - 15)
        XCTAssertNil(REAUITraceProjection.destinations(requestJSON: requestData, responseJSON: duplicate)["action"])
        XCTAssertNil(REAUITraceProjection.destinations(requestJSON: requestData, responseJSON: truncated)["action"])
        XCTAssertNil(REAUITraceProjection.destinations(requestJSON: omittedRequest, responseJSON: valid)["action"])
        XCTAssertNil(REAUITraceProjection.destinations(requestJSON: requestData, responseJSON: inferred)["action"])
        XCTAssertNil(REAUITraceProjection.destinations(requestJSON: requestData, responseJSON: unknownSource)["action"])
    }
    private func data(_ operation: REAInspectionOperation, _ result: [String: Any], ok: Bool = true) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["ok": ok, "operation": operation.rawValue, "requestID": "accepted-request", "implementationIdentity": "verified-resource", "result": result])
    }
    func testIncompleteComparisonDoesNotDisplayEquality() throws {
        let result: [String: Any] = ["status": "unknown", "dimensions": [["source": "stdout", "status": "equal"], ["source": "exit", "status": "unknown"]]]
        let presentation = try REAInspectionResultPresentation.make(operation: .processComparison, title: "Comparison", resultData: data(.processComparison, result))
        XCTAssertEqual(presentation.summary, "Comparison is incomplete")
        XCTAssertEqual(presentation.sections[0].rows[1].status, "Unknown")
        XCTAssertEqual(presentation.provenance.first?.detail, "accepted-request")
    }
    func testComparisonShowsActualFirstDivergence() throws {
        let result: [String: Any] = ["status": "different", "dimensions": [["source": "stdout", "status": "different", "comparison": ["first_divergence": ["status": "found", "index": 2, "left": "original output", "right": "changed output"]]]]]
        let presentation = try REAInspectionResultPresentation.make(operation: .processComparison, title: "Comparison", resultData: data(.processComparison, result))
        XCTAssertEqual(presentation.summary, "Captured behavior differs")
        XCTAssertTrue(presentation.sections[0].rows[0].detail.contains("original output"))
        XCTAssertTrue(presentation.sections[0].rows[0].detail.contains("changed output"))
    }
    func testUIResolvedJoinIsPresentedAsCandidateAndCoverageSurvives() throws {
        let result: [String: Any] = ["analysis": ["documents": [], "graph": ["nodes": [["id": "selector", "name": "perform:"]], "edges": [["relation": "objc_dispatch", "resolution": "resolved", "from": "selector", "to": "native:function:0xfffffffffffffff0"]], "coverage": []]], "coverage": [["facet": "objc_metadata", "status": "partial", "reason": "loader_metadata_projection_not_exhaustive", "examined": 1, "omitted": 0]], "dispatchCandidates": [], "assetCatalogs": NSNull()]
        let presentation = try REAInspectionResultPresentation.make(operation: .uiResources, title: "UI", resultData: data(.uiResources, result))
        XCTAssertEqual(presentation.sections.first { $0.id == "handlers" }?.rows.first?.status, "Candidate handler")
        XCTAssertTrue(presentation.explanation.contains("Runtime dispatch was not observed"))
        XCTAssertTrue(presentation.coverage.contains { $0.status == "partial" })
    }
    func testConditionalNativeLoadRemainsConditional() throws {
        let result: [String: Any] = ["bundles": [], "trace": ["edges": [["install_name": "@rpath/Helper.dylib", "loader": "Main", "root": "Main", "resolution": ["status": "conditional", "image": "Helper.dylib"], "loader_conditional": true]], "coverage": ["status": "partial", "unparsed_images": [], "roots_without_architecture": []]]]
        let presentation = try REAInspectionResultPresentation.make(operation: .nativeApplication, title: "Native", resultData: data(.nativeApplication, result))
        XCTAssertEqual(presentation.sections.first { $0.id == "loads" }?.rows.first?.status, "conditional")
        XCTAssertTrue(presentation.summary.contains("gaps"))
    }
    func testFailureAndWrongOperationEnvelopesReject() throws {
        let comparison: [String: Any] = ["status": "equal", "dimensions": []]
        XCTAssertThrowsError(try REAInspectionResultPresentation.make(operation: .processComparison, title: "Invalid", resultData: data(.processComparison, comparison, ok: false)))
        XCTAssertThrowsError(try REAInspectionResultPresentation.make(operation: .uiResources, title: "Wrong operation", resultData: data(.processComparison, comparison)))
    }
}
