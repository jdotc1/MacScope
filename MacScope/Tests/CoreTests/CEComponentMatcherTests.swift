// Component matching over pure-value inventories: exact path bytes first, then unique (kind, id) candidates, and
// absence only where the other scope genuinely covers the path.

import Foundation
import XCTest
@testable import MacScope

final class CEComponentMatcherTests: XCTestCase {
    private typealias H = CEHarness

    private func rawKey(_ bytes: [UInt8]) -> CE.ExactUTF8Key { CE.ExactUTF8Key(rawBytes: bytes) }

    private func exclusion(_ state: CE.ExclusionState, _ range: CE.PathRange) -> CE.ExclusionRecord {
        CE.ExclusionRecord(range: range, rawPath: rawKey(range.path?.bytes ?? []), state: state, canonicalPath: nil, omittedCount: 0)
    }

    private func scope(_ completion: CE.InventoryCompletion = .complete, exclusions: [CE.ExclusionRecord] = [],
                       overflow: CE.OverflowFact? = nil, remainderUnknown: Bool = false,
                       locations: [CE.SearchLocation] = []) -> CE.InventoryScope {
        CE.InventoryScope(searchedLocations: locations, completion: completion, exclusions: exclusions, exclusionOverflow: overflow,
                          issues: [], issueOverflow: nil, visited: 0, headerBytes: 0, remainderUnknown: remainderUnknown,
                          limitEntries: 4096, limitDepth: 12, limitCandidates: 128, limitHeaderBytes: 1_048_576)
    }

    private func match(_ previous: [CE.ComponentRecord], _ current: [CE.ComponentRecord], previousScope: CE.InventoryScope? = nil,
                       currentScope: CE.InventoryScope? = nil) -> [CE.ComponentMatch] {
        CE.ComponentMatcher().match(previous: H.inventory(previous, previousScope), current: H.inventory(current, currentScope))
    }

    // SPEC-CASE: CM-EXACT-PATH-PRESERVES-ID-CHANGE
    func testExactPathMatchPreservesIdentifierChange() {
        let old = H.record("Contents/Helpers/helper", id: "com.example.old")
        let new = H.record("Contents/Helpers/helper", id: "com.example.new")
        let previous = H.inventory([old]), current = H.inventory([new])
        let first = CE.ComponentMatcher().match(previous: previous, current: current)
        XCTAssertEqual(first.count, 1)
        XCTAssertEqual(first[0].status, .sameLocation)
        XCTAssertEqual(first[0].previousID, old.id)
        XCTAssertEqual(first[0].currentID, new.id)
        XCTAssertEqual(first[0].candidateIDs, [])
        XCTAssertEqual(first[0].id, CE.ComponentMatcher.matchID(.sameLocation, old.id, new.id, []))
        // The records still carry their own, different labels.
        XCTAssertNotEqual(old.declaredBundleID, new.declaredBundleID)
        // Deterministic for identical inventory values.
        let second = CE.ComponentMatcher().match(previous: previous, current: current)
        XCTAssertEqual(first, second)
        // A different pair yields a different id.
        XCTAssertNotEqual(first[0].id, CE.ComponentMatcher.matchID(.sameLocation, new.id, old.id, []))
    }

    // SPEC-CASE: CM-DUPLICATE-IDS-AMBIGUOUS
    func testDuplicateIdentifiersRemainAmbiguous() {
        let a = H.record("Contents/Helpers/a", kind: "helper", id: "com.example.dup")
        let b = H.record("Contents/Helpers/b", kind: "helper", id: "com.example.dup")
        let c = H.record("Contents/Helpers/c", kind: "helper", id: "com.example.dup")
        let results = match([a, b], [c])
        XCTAssertEqual(results.count, 2)
        XCTAssertEqual(results.map(\.status), [.ambiguous, .ambiguous])
        XCTAssertEqual(results.map(\.previousID), [a.id, b.id])
        XCTAssertEqual(results.map(\.currentID), [nil, nil])
        XCTAssertEqual(results.map(\.candidateIDs), [[c.id], [c.id]])
        XCTAssertFalse(results.contains { $0.status == .sameLocation || $0.status == .uniqueIdentifierCandidate })
        // The candidate is not also reported as a separate added component.
        XCTAssertFalse(results.contains { $0.currentID == c.id })
        XCTAssertEqual(results[0].id, CE.ComponentMatcher.matchID(.ambiguous, a.id, nil, [c.id]))
    }

    // SPEC-CASE: CM-UNIQUE-ID-MOVE-CANDIDATE-ONLY
    func testUniqueIdentifierMoveIsCandidateOnly() {
        let old = H.record("Contents/Helpers/old", kind: "helper", id: "com.example.moved")
        let new = H.record("Contents/Helpers/new", kind: "helper", id: "com.example.moved")
        let results = match([old], [new])
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].status, .uniqueIdentifierCandidate)
        XCTAssertEqual(results[0].previousID, old.id)
        XCTAssertEqual(results[0].currentID, new.id)
        XCTAssertEqual(results[0].candidateIDs, [])
        XCTAssertFalse(results.contains { $0.status == .sameLocation })
        // The same identifier under a different kind is not a candidate.
        let other = H.record("Contents/Helpers/new", kind: "xpc", id: "com.example.moved")
        XCTAssertEqual(match([old], [other]).map(\.status), [.unmatchedPrevious, .unmatchedCurrent])
    }

    // SPEC-CASE: CM-UTF8-DISTINCT-PATHS
    func testUTF8DistinctPathsDoNotMerge() throws {
        let prefix = Array("Contents/Helpers/caf".utf8)
        func record(_ suffix: [UInt8]) throws -> CE.ComponentRecord {
            let components = (prefix + suffix).split(separator: 0x2f, omittingEmptySubsequences: false).map { rawKey(Array($0)) }
            return CE.ComponentRecord(id: UUID(), parentID: nil, path: try CE.RelativePath(components: components), kind: H.key("helper"),
                                      declaredBundleID: nil, declaredVersion: nil, architectures: [], minimumOS: [], slices: [],
                                      issues: [], issueOverflow: nil, metadataAvailable: true, isDeclarationOnly: false)
        }
        let composed = try record([0xc3, 0xa9])
        let decomposed = try record([0x65, 0xcc, 0x81])
        XCTAssertNotEqual(composed.path, decomposed.path)
        let results = match([composed], [decomposed])
        XCTAssertEqual(results.count, 2)
        XCTAssertFalse(results.contains { $0.status == .sameLocation })
        XCTAssertEqual(results.map(\.status), [.unmatchedPrevious, .unmatchedCurrent])
        XCTAssertEqual(results[0].previousID, composed.id)
        XCTAssertEqual(results[1].currentID, decomposed.id)
    }

    // SPEC-CASE: CM-PARTIAL-CANNOT-PROVE-REMOVAL
    func testPartialTraversalCannotProveRemoval() {
        let helper = H.record("Contents/Helpers/helper")
        let unrelated = CE.SearchLocation(range: .subtree(H.path("Contents/XPCServices")), role: .codeRegion, status: .searched)
        let unreadable = exclusion(.unreadable, .subtree(H.path("Contents/Helpers")))
        let scenarios: [(String, CE.InventoryScope)] = [
            ("partial", scope(.partial)),
            ("partial with unrelated searched range", scope(.partial, locations: [unrelated])),
            ("partial with unreadable enclosing subtree", scope(.partial, exclusions: [unreadable])),
            ("forged complete with unreadable enclosing subtree", scope(.complete, exclusions: [unreadable])),
        ]
        for (name, current) in scenarios {
            let results = match([helper], [], currentScope: current)
            XCTAssertEqual(results.count, 1, name)
            XCTAssertEqual(results.first?.status, .unobservedInOtherScope, name)
            XCTAssertEqual(results.first?.previousID, helper.id, name)
            XCTAssertNil(results.first?.currentID, name)
            // The same holds for an addition against a partial earlier scope.
            let added = match([], [helper], previousScope: current)
            XCTAssertEqual(added.map(\.status), [.unobservedInOtherScope], name)
            XCTAssertEqual(added.first?.currentID, helper.id, name)
        }
        // Control: a complete scope without exclusions does prove the removal.
        XCTAssertEqual(match([helper], []).map(\.status), [.unmatchedPrevious])
    }

    // SPEC-CASE: MATCH-COVERS-USES-TYPED-EXCLUSIONS
    func test_MATCH_COVERS_USES_TYPED_EXCLUSIONS() {
        func covers(_ s: CE.InventoryScope, _ path: String) -> Bool { H.inventory([], s).covers(H.path(path)) }

        XCTAssertTrue(covers(scope(), "Contents/Helpers/x"))

        // A typed exclusion at an exact leaf means the path is occupied by a non-component: removal is unprovable there.
        let nonHiding = scope(exclusions: [
            exclusion(.nonImage, .leaf(H.path("Contents/Helpers/readme.txt"))),
            exclusion(.outsideCodeLocations, .leaf(H.path("Contents/Resources/tool"))),
            exclusion(.duplicateFile, .leaf(H.path("Contents/Helpers/alias"))),
        ])
        XCTAssertFalse(covers(nonHiding, "Contents/Helpers/readme.txt"))
        XCTAssertFalse(covers(nonHiding, "Contents/Resources/tool"))
        XCTAssertFalse(covers(nonHiding, "Contents/Helpers/alias"))
        XCTAssertTrue(covers(nonHiding, "Contents/Helpers/other"))

        // A skipped link blocks its whole subtree, never a sibling that only shares a name prefix.
        let link = scope(exclusions: [exclusion(.skippedLink, .subtree(H.path("Contents/Helpers")))])
        XCTAssertFalse(covers(link, "Contents/Helpers"))
        XCTAssertFalse(covers(link, "Contents/Helpers/x"))
        XCTAssertFalse(covers(link, "Contents/Helpers/deep/er/x"))
        XCTAssertTrue(covers(link, "Contents/HelpersExtra/x"))
        XCTAssertTrue(covers(link, "Contents/MacOS/Main"))

        // An exact-leaf hiding state blocks that leaf only.
        let leaf = scope(exclusions: [exclusion(.skippedSpecial, .leaf(H.path("Contents/Helpers/fifo")))])
        XCTAssertFalse(covers(leaf, "Contents/Helpers/fifo"))
        XCTAssertTrue(covers(leaf, "Contents/Helpers/fifo2"))
        XCTAssertTrue(covers(leaf, "Contents/Helpers"))

        // Every state blocks its own exact leaf and nothing beside it.
        let all: [CE.ExclusionState] = [.skippedLink, .skippedSpecial, .invalidName, .unreadable, .changed, .entryLimit,
                                        .depthLimit, .candidateLimit, .headerLimit, .pathLimit, .nonImage, .outsideCodeLocations, .duplicateFile]
        for state in all {
            let one = scope(exclusions: [exclusion(state, .leaf(H.path("Contents/Helpers/z")))])
            XCTAssertFalse(covers(one, "Contents/Helpers/z"), state.rawValue)
            XCTAssertTrue(covers(one, "Contents/Helpers/z2"), state.rawValue)
        }

        // Unreadable leaf and subtree under a partial scope: nothing is covered.
        let unreadableLeaf = exclusion(.unreadable, .leaf(H.path("Contents/Helpers/bad")))
        let unreadableTree = exclusion(.unreadable, .subtree(H.path("Contents/Helpers")))
        XCTAssertFalse(covers(scope(.partial, exclusions: [unreadableLeaf]), "Contents/Helpers/bad"))
        XCTAssertFalse(covers(scope(.partial, exclusions: [unreadableLeaf]), "Contents/MacOS/Main"))
        XCTAssertFalse(covers(scope(.partial, exclusions: [unreadableTree]), "Contents/Helpers/x"))
        XCTAssertFalse(covers(scope(.partial), "Contents/MacOS/Main"))

        // Forged complete scope with unreadable records: the affected range is still not covered.
        XCTAssertFalse(covers(scope(.complete, exclusions: [unreadableLeaf]), "Contents/Helpers/bad"))
        XCTAssertFalse(covers(scope(.complete, exclusions: [unreadableTree]), "Contents/Helpers/x"))
        XCTAssertTrue(covers(scope(.complete, exclusions: [unreadableTree]), "Contents/HelpersExtra/x"))

        // Unknown-range or global facts: nothing is covered.
        XCTAssertFalse(covers(scope(.cancelled), "Contents/MacOS/Main"))
        XCTAssertFalse(covers(scope(.complete, exclusions: [exclusion(.entryLimit, .wholeRoot)]), "Contents/MacOS/Main"))
        XCTAssertFalse(covers(scope(.complete, overflow: CE.OverflowFact(observed: 300, retained: 255)), "Contents/MacOS/Main"))
        XCTAssertFalse(covers(scope(.complete, remainderUnknown: true), "Contents/MacOS/Main"))

        // Through the matcher: removal is provable beside the link subtree but not inside it.
        let inside = H.record("Contents/Helpers/helper"), beside = H.record("Contents/HelpersExtra/helper")
        let current = scope(exclusions: [exclusion(.skippedLink, .subtree(H.path("Contents/Helpers")))])
        XCTAssertEqual(match([inside], [], currentScope: current).map(\.status), [.unobservedInOtherScope])
        XCTAssertEqual(match([beside], [], currentScope: current).map(\.status), [.unmatchedPrevious])
    }

    // SPEC-CASE: MATCH-PATH-CASE-SENSITIVE
    func test_MATCH_PATH_CASE_SENSITIVE() {
        let upper = H.record("Contents/Helpers/Helper", kind: "helper", id: "Com.Example.Tool")
        let lower = H.record("Contents/Helpers/helper", kind: "Helper", id: "com.example.tool")
        XCTAssertNotEqual(upper.path, lower.path)
        let results = match([upper], [lower])
        XCTAssertEqual(results.map(\.status), [.unmatchedPrevious, .unmatchedCurrent])
        XCTAssertEqual(results[0].previousID, upper.id)
        XCTAssertEqual(results[1].currentID, lower.id)

        // Case-varied identifier only (same kind) at distinct paths: no grouping.
        let a = H.record("Contents/Helpers/one", kind: "helper", id: "Com.Example")
        let b = H.record("Contents/Helpers/two", kind: "helper", id: "com.example")
        XCTAssertEqual(match([a], [b]).map(\.status), [.unmatchedPrevious, .unmatchedCurrent])

        // Case-varied kind only (same identifier) at distinct paths: no grouping.
        let c = H.record("Contents/Helpers/one", kind: "helper", id: "com.example")
        let d = H.record("Contents/Helpers/two", kind: "Helper", id: "com.example")
        XCTAssertEqual(match([c], [d]).map(\.status), [.unmatchedPrevious, .unmatchedCurrent])

        // Exactly equal bytes still group.
        let e = H.record("Contents/Helpers/two", kind: "helper", id: "com.example")
        XCTAssertEqual(match([c], [e]).map(\.status), [.uniqueIdentifierCandidate])
    }
}
