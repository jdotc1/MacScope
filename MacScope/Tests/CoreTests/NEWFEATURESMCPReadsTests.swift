import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

final class NEWFEATURESMCPReadsTests: XCTestCase {
    private var image: NEWFEATURESImageKey!
    private var budget: NEWFEATURESReadBudget!

    override func setUpWithError() throws {
        image = try NEWFEATURESImageKey(
            documentInstance: UUID(), workspaceInstance: UUID(), slot: 0, binaryID: UUID(),
            ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: String(repeating: "a", count: 64), analysisRevision: 7,
            analysisInputFingerprintSHA256: String(repeating: "b", count: 64)
        )
        budget = try NEWFEATURESReadBudget()
    }

    private func key(_ address: UInt64) -> NEWFEATURESFunctionKey {
        NEWFEATURESFunctionKey(image: image, address: address)
    }

    private func edge(_ from: UInt64, _ to: UInt64, site: UInt64,
                      _ confidence: NEWFEATURESCallConfidence = .confirmedDirect) -> NEWFEATURESCallEdge {
        NEWFEATURESCallEdge(caller: key(from), callee: key(to), callSite: site, confidence: confidence)
    }

    private func graph(_ addresses: [UInt64], _ edges: [NEWFEATURESCallEdge]) throws -> NEWFEATURESGraphSnapshot {
        try NEWFEATURESGraphSnapshot(
            functions: addresses.map(key), edges: edges, operation: NEWFEATURESGraphOperation(budget: budget)
        )
    }

    private func read(_ graph: NEWFEATURESGraphSnapshot, _ source: UInt64, _ target: UInt64,
                      extra: [String: ScriptValue] = [:], cap: Int? = nil) throws -> ScriptValue {
        var fields: [String: ScriptValue] = ["source": .string("0x" + String(source, radix: 16)),
                                             "target": .int(Int64(target))]
        for (name, value) in extra { fields[name] = value }
        let request = try NEWFEATURESMCPReads.parseCallPath(.object(fields))
        return try NEWFEATURESMCPReads.callPath(
            request: request, graph: graph, source: key(source), destination: key(target), budget: budget,
            operation: NEWFEATURESGraphOperation(budget: budget),
            maximumResponseBytes: cap ?? NEWFEATURESMCPReads.maximumResponseBytes
        )
    }

    func testThreeNodeChainReturnsKnownPathWithPerEdgeEvidenceAndTotals() throws {
        let g = try graph([0x1000, 0x2000, 0x3000], [
            edge(0x1000, 0x2000, site: 0x1004), edge(0x2000, 0x3000, site: 0x2008),
            edge(0x1000, 0x3000, site: 0x100c, .unverified),
        ])
        let value = try read(g, 0x1000, 0x3000)
        XCTAssertEqual(value["status"]?.stringValue, "found")
        XCTAssertEqual(value["totalPaths"]?.intValue, 1)
        XCTAssertEqual(value["totalIsLowerBound"]?.boolValue, false)
        XCTAssertEqual(value["isTruncated"]?.boolValue, false)
        XCTAssertEqual(value["nextCursor"], .null)
        let path = try XCTUnwrap(value["paths"]?.arrayValue?.first)
        XCTAssertEqual(path["functions"]?.arrayValue?.compactMap { $0["address"]?.stringValue },
                       ["0x1000", "0x2000", "0x3000"])
        let edges = try XCTUnwrap(path["edges"]?.arrayValue)
        XCTAssertEqual(edges.count, 2)
        XCTAssertEqual(edges[0]["evidence"]?.arrayValue?.first?["callSite"]?.stringValue, "0x1004")
        XCTAssertEqual(edges[1]["evidence"]?.arrayValue?.first?["callSite"]?.stringValue, "0x2008")
        XCTAssertEqual(edges[0]["evidence"]?.arrayValue?.first?["confidence"]?.stringValue, "confirmedDirect")
        XCTAssertNotNil(edges[0]["evidence"]?.arrayValue?.first?["proof"]?.stringValue)
        // The unverified shortcut is counted but never traversed.
        XCTAssertEqual(value["searchBound"]?["unverifiedEdgesObservedNotTraversed"]?.intValue, 1)
    }

    func testLimitOneOnTwoPathGraphTruncatesAndCursorYieldsSecondPath() throws {
        let g = try graph([0x1000, 0x2000, 0x3000, 0x4000], [
            edge(0x1000, 0x2000, site: 0x1004), edge(0x2000, 0x4000, site: 0x2004),
            edge(0x1000, 0x3000, site: 0x1008), edge(0x3000, 0x4000, site: 0x3004),
        ])
        let first = try read(g, 0x1000, 0x4000, extra: ["limit": .int(1)])
        XCTAssertEqual(first["totalPaths"]?.intValue, 2)
        XCTAssertEqual(first["isTruncated"]?.boolValue, true)
        XCTAssertEqual(first["returnedPaths"]?.intValue, 1)
        XCTAssertEqual(first["paths"]?.arrayValue?.first?["functions"]?.arrayValue?.compactMap { $0["address"]?.stringValue },
                       ["0x1000", "0x2000", "0x4000"])
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let second = try read(g, 0x1000, 0x4000, extra: ["limit": .int(1), "cursor": .string(cursor)])
        XCTAssertEqual(second["paths"]?.arrayValue?.first?["functions"]?.arrayValue?.compactMap { $0["address"]?.stringValue },
                       ["0x1000", "0x3000", "0x4000"])
        XCTAssertEqual(second["isTruncated"]?.boolValue, false)
        XCTAssertEqual(second["nextCursor"], .null)
        XCTAssertEqual(second["paths"]?.arrayValue?.first?["index"]?.intValue, 1)
    }

    func testNoPathAnswerNamesBoundRevisionAndSearchBound() throws {
        let g = try graph([0x1000, 0x2000, 0x3000], [
            edge(0x1000, 0x2000, site: 0x1004), edge(0x2000, 0x3000, site: 0x2004, .unverified),
        ])
        let value = try read(g, 0x1000, 0x3000, extra: ["maxDepth": .int(4)])
        XCTAssertEqual(value["status"]?.stringValue, "notFoundInObservedGraph")
        XCTAssertEqual(value["paths"]?.arrayValue?.count, 0)
        XCTAssertEqual(value["totalPaths"]?.intValue, 0)
        XCTAssertEqual(value["totalIsLowerBound"]?.boolValue, false)
        XCTAssertEqual(value["boundTo"]?["analysisRevision"]?.stringValue, "7")
        XCTAssertEqual(value["boundTo"]?["sha256"]?.stringValue, String(repeating: "a", count: 64))
        XCTAssertNotNil(value["boundTo"]?["ledger"]?.stringValue)
        XCTAssertEqual(value["searchBound"]?["maxDepth"]?.intValue, 4)
        XCTAssertEqual(value["searchBound"]?["maxEdgeVisits"]?.intValue, Int64(budget.maxEdgeVisits))
        XCTAssertEqual(value["searchBound"]?["unverifiedEdgesObservedNotTraversed"]?.intValue, 1)
    }

    func testArgumentValidationNamesTheOffendingField() throws {
        func field(_ arguments: ScriptValue) -> String? {
            do { _ = try NEWFEATURESMCPReads.parseCallPath(arguments); return nil }
            catch let error as ToolArgumentError { return error.refusal.field }
            catch { return "unexpected:\(error)" }
        }
        XCTAssertEqual(field(.object(["target": .string("0x3000")])), "source")
        XCTAssertEqual(field(.object(["source": .string("0x1000")])), "target")
        XCTAssertEqual(field(.object(["source": .string("0x1000"), "target": .string("0x3000"),
                                      "limit": .int(-1)])), "limit")
        XCTAssertEqual(field(.object(["source": .string("0x1000"), "target": .string("0x3000"),
                                      "maxDepth": .int(17)])), "maxDepth")
        XCTAssertEqual(field(.object(["source": .string("zz"), "target": .string("0x3000")])), "source")
        // A cursor issued for other selectors is refused with a named field.
        let foreign = NEWFEATURESMCPReads.encodeCursor(offset: 1, image: image, source: 0x9000, target: 0x3000,
                                                       maxDepth: 5)
        XCTAssertEqual(field(.object(["source": .string("0x1000"), "target": .string("0x3000"),
                                      "cursor": .string(foreign)])), "cursor")
        XCTAssertNil(field(.object(["source": .string("0x1000"), "target": .string("0x3000")])))
        // The page ceiling matches the shared navigator schema (256).
        XCTAssertEqual(NEWFEATURESMCPReads.maximumLimit, NavigatorMCPCommands.maximumPageLimit)
        XCTAssertNil(field(.object(["source": .string("0x1000"), "target": .string("0x3000"),
                                    "limit": .int(256)])))
        XCTAssertEqual(field(.object(["source": .string("0x1000"), "target": .string("0x3000"),
                                      "limit": .int(257)])), "limit")
    }

    func testStaleRevisionCursorIsRefused() throws {
        let g = try graph([0x1000, 0x2000, 0x3000, 0x4000], [
            edge(0x1000, 0x2000, site: 0x1004), edge(0x2000, 0x4000, site: 0x2004),
            edge(0x1000, 0x3000, site: 0x1008), edge(0x3000, 0x4000, site: 0x3004),
        ])
        let other = try NEWFEATURESImageKey(
            documentInstance: image.documentInstance, workspaceInstance: image.workspaceInstance, slot: 0,
            binaryID: image.binaryID, ownerGeneration: 1, architecture: "arm64", sliceIndex: nil,
            sha256: image.sha256, analysisRevision: 8,
            analysisInputFingerprintSHA256: image.analysisInputFingerprintSHA256
        )
        let stale = NEWFEATURESMCPReads.encodeCursor(offset: 1, image: other, source: 0x1000, target: 0x4000,
                                                     maxDepth: 5)
        XCTAssertThrowsError(try read(g, 0x1000, 0x4000, extra: ["cursor": .string(stale)])) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.field, "cursor")
        }
    }

    func testLargeFixtureStaysUnderMCPResponseCapAndShrinksToFit() throws {
        // 8 diamond layers: 2^8 = 256 simple paths of 16 hops each.
        var addresses: [UInt64] = []
        var edges: [NEWFEATURESCallEdge] = []
        var joint: UInt64 = 0x10000
        addresses.append(joint)
        for _ in 0..<8 {
            let a = joint + 0x100, b = joint + 0x200, next = joint + 0x1000
            addresses += [a, b, next]
            edges += [edge(joint, a, site: joint + 4), edge(joint, b, site: joint + 8),
                      edge(a, next, site: a + 4), edge(b, next, site: b + 4)]
            joint = next
        }
        let g = try graph(addresses, edges)
        let cap = NEWFEATURESMCPReads.maximumResponseBytes
        XCTAssertEqual(cap, MCPServer.Configuration.production.maximumOutputBytes / 2)
        let full = try read(g, 0x10000, joint, extra: ["maxDepth": .int(16), "limit": .int(100)])
        XCTAssertEqual(full["totalPaths"]?.intValue, 256)
        XCTAssertEqual(full["returnedPaths"]?.intValue, 100)
        XCTAssertEqual(full["isTruncated"]?.boolValue, true)
        XCTAssertLessThanOrEqual(try full.jsonData().count, cap)

        let tiny = try read(g, 0x10000, joint, extra: ["maxDepth": .int(16), "limit": .int(100)], cap: 40_000)
        let tinySize = try tiny.jsonData().count
        XCTAssertLessThanOrEqual(tinySize, 40_000)
        XCTAssertLessThan(try XCTUnwrap(tiny["returnedPaths"]?.intValue), 100)
        XCTAssertEqual(tiny["isTruncated"]?.boolValue, true)
        XCTAssertNotNil(tiny["nextCursor"]?.stringValue)

        // A full-page request (limit 256 over 256 paths) cut down only by the byte cap is marked
        // truncated, keeps the true total, and hands out a cursor for the remainder.
        let capped = try read(g, 0x10000, joint, extra: ["maxDepth": .int(16), "limit": .int(256)], cap: 40_000)
        XCTAssertLessThanOrEqual(try capped.jsonData().count, 40_000)
        XCTAssertEqual(capped["totalPaths"]?.intValue, 256)
        XCTAssertLessThan(try XCTUnwrap(capped["returnedPaths"]?.intValue), 256)
        XCTAssertEqual(capped["isTruncated"]?.boolValue, true)
        XCTAssertNotNil(capped["nextCursor"]?.stringValue)
    }
}
