// Component review binding tests: observations, reviews, comparisons and differences built directly as values.

import Darwin
import Foundation
import XCTest
@testable import MacScope

final class CEComponentReviewTests: XCTestCase {
    private let arm = CEHarness.key("arm64")
    private let x86 = CEHarness.key("x86_64")

    // MARK: Helpers

    private struct Side {
        let inventory: CE.ComponentInventory
        let main: CE.ComponentRecord
        let helper: CE.ComponentRecord
    }

    private func side() -> Side {
        let main = CEHarness.record("Contents/MacOS/OwnedMain", kind: "app", architectures: ["arm64"])
        let helper = CEHarness.record("Contents/Helpers/helper", kind: "helper", architectures: ["arm64"])
        return Side(inventory: CEHarness.inventory([main, helper]), main: main, helper: helper)
    }

    private func dictionary(_ pairs: [(String, EntitlementValue)]) throws -> EntitlementDictionary {
        try EntitlementDictionary(entries: pairs.map { EntitlementEntry(key: $0.0, value: $0.1) })
    }

    private func source(_ path: String, _ architecture: CE.ExactUTF8Key? = nil) -> CE.DeclarationSource {
        CE.DeclarationSource(path: CEHarness.path(path), architecture: architecture)
    }

    private let infoSource = "Contents/Info.plist"
    private let privacySource = "Contents/Resources/PrivacyInfo.xcprivacy"
    private let mainPath = "Contents/MacOS/OwnedMain"

    private func present(_ inventory: CE.ComponentInventory, _ component: CE.ComponentRecord, _ category: CE.DeclarationCategory,
                         architecture: CE.ExactUTF8Key? = nil, values: EntitlementDictionary,
                         source: CE.DeclarationSource?) throws -> CE.DeclarationObservation {
        try CE.DeclarationObservation(inventoryID: inventory.id, componentID: component.id, category: category,
                                      architecture: architecture, state: .present, values: values, source: source)
    }

    private func absent(_ inventory: CE.ComponentInventory, _ component: CE.ComponentRecord) throws -> CE.DeclarationObservation {
        try CE.DeclarationObservation(inventoryID: inventory.id, componentID: component.id, category: .privacy, state: .notPresent,
                                      source: source(privacySource))
    }

    private func unavailable(_ inventory: CE.ComponentInventory, _ component: CE.ComponentRecord, _ category: CE.DeclarationCategory,
                             architecture: CE.ExactUTF8Key? = nil, code: Int32) throws -> CE.DeclarationObservation {
        let range = CE.PathRange.leaf(component.path)
        return try CE.DeclarationObservation(inventoryID: inventory.id, componentID: component.id, category: category,
                                             architecture: architecture, state: .unavailable,
                                             issue: CE.EvidenceIssue(.io(.read, errno: code, range), range: range))
    }

    private func expect<T>(_ expected: CE.EvidenceError, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> T) {
        do {
            _ = try body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? CE.EvidenceError, expected, file: file, line: line)
        }
    }

    private func match(_ old: Side, _ new: Side) -> [CE.ComponentMatch] {
        CE.ComponentMatcher().match(previous: old.inventory, current: new.inventory)
    }

    // MARK: CR-RESULTS-REQUIRE-KNOWN-MATCH-SLICE-SOURCE

    func testResultsRequireKnownMatchSliceAndSourceBinding() throws {
        // SPEC-CASE: CR-RESULTS-REQUIRE-KNOWN-MATCH-SLICE-SOURCE
        let old = side(), new = side()
        let infoBinding = source(infoSource)
        let loadBinding = source(mainPath, arm)
        let privacyBinding = source(privacySource)

        func review(_ s: Side, flag: EntitlementValue, includePrivacy: Bool = true) throws -> CE.ComponentReview {
            var observations = [
                try present(s.inventory, s.main, .info, values: dictionary([("flag", flag), ("ignored", .string("same"))]), source: infoBinding),
                try present(s.inventory, s.main, .loadCommands, architecture: arm, values: dictionary([("commands", .array([]))]),
                            source: loadBinding),
            ]
            if includePrivacy {
                observations.append(try present(s.inventory, s.main, .privacy, values: dictionary([]), source: privacyBinding))
            }
            return try CE.ComponentReview(inventory: s.inventory, observations: observations)
        }

        // Correctly bound exact-location results are accepted and expose their observations by exact slice.
        let previousReview = try review(old, flag: .boolean(true))
        XCTAssertEqual(previousReview.observations.count, 3)
        XCTAssertNotNil(previousReview.observation(component: old.main.id, category: .loadCommands, architecture: arm))
        XCTAssertNil(previousReview.observation(component: old.main.id, category: .loadCommands, architecture: x86))
        XCTAssertNil(previousReview.observation(component: old.main.id, category: .loadCommands), "no first-slice fallback")

        // Unknown component record, foreign inventory, duplicate and wrong slice are typed rejections.
        let goodInfo = try present(old.inventory, old.main, .info, values: dictionary([]), source: infoBinding)
        expect(.invalidObservation(.unknownComponentRecord)) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try CE.DeclarationObservation(inventoryID: old.inventory.id, componentID: UUID(), category: .info, state: .present,
                                              values: dictionary([]), source: infoBinding)])
        }
        expect(.invalidObservation(.inventoryMismatch)) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try CE.DeclarationObservation(inventoryID: UUID(), componentID: old.main.id, category: .info, state: .present,
                                              values: dictionary([]), source: infoBinding)])
        }
        expect(.invalidObservation(.duplicateObservation)) {
            try CE.ComponentReview(inventory: old.inventory, observations: [goodInfo, goodInfo])
        }
        expect(.invalidObservation(.architectureNotEnumerated)) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .loadCommands, architecture: x86, values: dictionary([]), source: source(mainPath, x86))])
        }
        expect(.invalidObservation(.architectureNotEnumerated)) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .loadCommands, architecture: CEHarness.key("arm64e"), values: dictionary([]),
                            source: source(mainPath, CEHarness.key("arm64e")))])
        }

        // Wrong source bindings: path, owner component, slice label and category location.
        expect(.sourceMismatch) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .info, values: dictionary([]), source: source("Contents/Resources/Info.plist"))])
        }
        expect(.sourceMismatch) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .loadCommands, architecture: arm, values: dictionary([]),
                            source: source("Contents/Helpers/helper", arm))])
        }
        expect(.sourceMismatch) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .loadCommands, architecture: arm, values: dictionary([]), source: source(mainPath))])
        }
        expect(.sourceMismatch) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .privacy, values: dictionary([]), source: source(infoSource))])
        }
        expect(.sourceMismatch) {
            try CE.ComponentReview(inventory: old.inventory, observations: [
                try present(old.inventory, old.main, .info, values: dictionary([]), source: source(infoSource, arm))])
        }
        // A source is optional only for unavailable observations; those carry a typed issue instead.
        let issueOnly = try unavailable(old.inventory, old.helper, .info, code: EIO)
        XCTAssertNil(issueOnly.source)
        XCTAssertNoThrow(try CE.ComponentReview(inventory: old.inventory, observations: [issueOnly]))

        // Comparison requires a known match with both sides known to its two reviews.
        let currentReview = try review(new, flag: .integer(1), includePrivacy: false)
        let matches = match(old, new)
        let mainMatch = try XCTUnwrap(matches.first { $0.previousID == old.main.id })
        XCTAssertEqual(mainMatch.status, .sameLocation)
        XCTAssertEqual(mainMatch.currentID, new.main.id)
        let unknownPrevious = CE.ComponentMatch(id: "x", status: .sameLocation, previousID: UUID(), currentID: new.main.id, candidateIDs: [])
        let unknownCurrent = CE.ComponentMatch(id: "y", status: .sameLocation, previousID: old.main.id, currentID: UUID(), candidateIDs: [])
        let unmatched = CE.ComponentMatch(id: "z", status: .unmatchedPrevious, previousID: old.main.id, currentID: nil, candidateIDs: [])
        let ambiguous = CE.ComponentMatch(id: "w", status: .ambiguous, previousID: nil, currentID: nil, candidateIDs: [new.main.id])
        for bad in [unknownPrevious, unknownCurrent, unmatched, ambiguous] {
            expect(.unknownMatch) { try CE.ComponentComparison(previous: previousReview, current: currentReview, match: bad) }
        }
        // A previous-side id given as a current id (sides swapped) is unknown to the other review.
        let swapped = CE.ComponentMatch(id: "s", status: .sameLocation, previousID: new.main.id, currentID: old.main.id, candidateIDs: [])
        expect(.unknownMatch) { try CE.ComponentComparison(previous: previousReview, current: currentReview, match: swapped) }

        let comparison = try CE.ComponentComparison(previous: previousReview, current: currentReview, match: mainMatch)
        // The privacy result was not supplied on the current side: no difference is invented, in particular no absence.
        XCTAssertEqual(comparison.differences.map { $0.category }, [.info, .loadCommands])
        XCTAssertNil(currentReview.observation(component: new.main.id, category: .privacy))
        XCTAssertFalse(comparison.differences.contains { $0.kind == .becameAbsent || $0.kind == .bothAbsent })
        let info = try XCTUnwrap(comparison.differences.first { $0.category == .info })
        XCTAssertEqual(info.kind, .comparedPresent)
        let changes = (info.rows ?? []).filter { $0.kind != .unchanged }
        XCTAssertEqual(changes.map { $0.key }, ["flag"])
        XCTAssertEqual(changes.first?.previous, .boolean(true))
        XCTAssertEqual(changes.first?.current, .integer(1))
        let load = try XCTUnwrap(comparison.differences.first { $0.category == .loadCommands })
        XCTAssertEqual(load.architecture, arm)
        XCTAssertEqual((load.rows ?? []).filter { $0.kind != .unchanged }.count, 0)

        // A matched pair with no supplied results on either side yields no differences at all.
        let helperMatch = try XCTUnwrap(matches.first { $0.previousID == old.helper.id })
        let helperComparison = try CE.ComponentComparison(
            previous: previousReview, current: currentReview, match: helperMatch)
        XCTAssertTrue(helperComparison.differences.isEmpty)

        // Differences refuse mismatched categories and slices.
        let armLoad = try present(old.inventory, old.main, .loadCommands, architecture: arm, values: dictionary([]), source: loadBinding)
        let x86Load = try present(new.inventory, new.main, .loadCommands, architecture: x86, values: dictionary([]), source: source(mainPath, x86))
        let infoOnly = try present(new.inventory, new.main, .info, values: dictionary([]), source: infoBinding)
        expect(.architectureMismatch) { try CE.DeclarationDifference(previous: armLoad, current: x86Load) }
        expect(.invalidObservation(.componentMismatch)) { try CE.DeclarationDifference(previous: armLoad, current: infoOnly) }
    }

    // MARK: CR-DECLARATION-TYPES-DISTINCT

    func testDeclarationTypesMissingPrivacyAndUnavailableStayDistinct() throws {
        // SPEC-CASE: CR-DECLARATION-TYPES-DISTINCT
        let old = side(), new = side()
        let infoBinding = source(infoSource)

        // Boolean true and integer 1 are different typed values.
        XCTAssertNotEqual(EntitlementValue.boolean(true), EntitlementValue.integer(1))
        XCTAssertNotEqual(EntitlementValue.boolean(false), EntitlementValue.integer(0))

        func review(_ s: Side, flag: EntitlementValue, privacy: CE.DeclarationObservation?, loadCode: Int32?) throws -> CE.ComponentReview {
            var observations = [try present(s.inventory, s.main, .info,
                values: dictionary([("selected", flag), ("ignored", .string("same"))]), source: infoBinding)]
            if let privacy { observations.append(privacy) }
            if let loadCode { observations.append(try unavailable(s.inventory, s.main, .loadCommands, architecture: arm, code: loadCode)) }
            return try CE.ComponentReview(inventory: s.inventory, observations: observations)
        }

        // Privacy absent on both sides, load commands uncaptured on both sides.
        let previousReview = try review(old, flag: .boolean(true), privacy: try absent(old.inventory, old.main), loadCode: nil)
        let currentReview = try review(new, flag: .integer(1), privacy: try absent(new.inventory, new.main), loadCode: nil)
        let main = try XCTUnwrap(match(old, new).first { $0.previousID == old.main.id })
        let comparison = try CE.ComponentComparison(previous: previousReview, current: currentReview, match: main)

        XCTAssertEqual(comparison.differences.map { $0.category }, [.info, .privacy])
        XCTAssertFalse(comparison.differences.contains { $0.category == .loadCommands }, "an uncaptured load is not compared")
        let info = try XCTUnwrap(comparison.differences.first { $0.category == .info })
        let changes = (info.rows ?? []).filter { $0.kind != .unchanged }
        XCTAssertEqual(changes.count, 1, "exactly one selected Info change")
        XCTAssertEqual(changes.first?.key, "selected")
        XCTAssertEqual(changes.first?.kind, .changed)
        XCTAssertEqual(changes.first?.previous, .boolean(true))
        XCTAssertEqual(changes.first?.current, .integer(1))
        XCTAssertEqual((info.rows ?? []).first { $0.key == "ignored" }?.kind, .unchanged)

        let privacy = try XCTUnwrap(comparison.differences.first { $0.category == .privacy })
        XCTAssertEqual(privacy.kind, .bothAbsent)
        XCTAssertNil(privacy.rows, "absent on both sides compares nothing")
        XCTAssertEqual(privacy.previous.state, .notPresent)
        XCTAssertEqual(privacy.current.state, .notPresent)
        XCTAssertNil(privacy.previous.values)

        // Unavailable on both sides is its own kind: no rows, never absence, and the side-specific issues survive.
        let unavailablePrevious = try review(old, flag: .boolean(true), privacy: nil, loadCode: EIO)
        let unavailableCurrent = try review(new, flag: .boolean(true), privacy: nil, loadCode: EACCES)
        let both = try CE.ComponentComparison(previous: unavailablePrevious, current: unavailableCurrent, match: main)
        let load = try XCTUnwrap(both.differences.first { $0.category == .loadCommands })
        XCTAssertEqual(load.kind, .unavailable)
        XCTAssertNil(load.rows)
        XCTAssertEqual(load.architecture, arm)
        XCTAssertEqual(load.previous.issue?.errno, EIO)
        XCTAssertEqual(load.current.issue?.errno, EACCES)
        XCTAssertEqual(load.previous.state, .unavailable)
        XCTAssertEqual(both.differences.first { $0.category == .info }?.rows?.filter { $0.kind != .unchanged }.count, 0)

        // Present-empty privacy against absent is a state transition, not a zero-change agreement.
        let emptyPrivacy = try present(old.inventory, old.main, .privacy, values: dictionary([]), source: source(privacySource))
        let missingPrivacy = try absent(new.inventory, new.main)
        let transition = try CE.DeclarationDifference(previous: emptyPrivacy, current: missingPrivacy)
        XCTAssertEqual(transition.kind, .becameAbsent)
        XCTAssertNil(transition.rows)
        let reverse = try CE.DeclarationDifference(previous: missingPrivacy, current: emptyPrivacy)
        XCTAssertEqual(reverse.kind, .becamePresent)
        // Present-empty on both sides compares with zero changes yet stays a present/present comparison.
        let samePresent = try CE.DeclarationDifference(previous: emptyPrivacy, current: emptyPrivacy)
        XCTAssertEqual(samePresent.kind, .comparedPresent)
        XCTAssertEqual(samePresent.rows?.count, 0)

        // Unavailable against present or absent never becomes an empty-dictionary comparison.
        let unavailablePrivacy = try unavailable(new.inventory, new.main, .privacy, code: EIO)
        for pair in [(emptyPrivacy, unavailablePrivacy), (unavailablePrivacy, emptyPrivacy),
                     (missingPrivacy, unavailablePrivacy), (unavailablePrivacy, missingPrivacy)] {
            let difference = try CE.DeclarationDifference(previous: pair.0, current: pair.1)
            XCTAssertEqual(difference.kind, .unavailable)
            XCTAssertNil(difference.rows)
        }
    }
}
