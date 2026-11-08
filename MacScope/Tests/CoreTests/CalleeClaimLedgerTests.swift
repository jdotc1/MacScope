import Foundation
import XCTest
@testable import MacScope

/// VI3 slice A: pure value-type tests for the callee claim ledger. All fixtures are synthetic; there is no app,
/// workspace, binary or journal. The real-app acceptance (`open-claim 0x100157ebc` on TG Pro) is NOT RUN.
final class CalleeClaimLedgerTests: XCTestCase {
    private let owner = UUID()
    private let generation1 = UUID()
    private let generation2 = UUID()
    private let function = VAAddress64(0x1000)

    private func entry(_ address: UInt64, kind: VACalleeKind = .function, name: String? = nil,
                       sites: [UInt64]? = nil) -> VACalleeInventoryEntry {
        let siteList = sites ?? [address &+ 0x10_000]
        let capped = addrs(Array(siteList.prefix(16)))
        return VACalleeInventoryEntry(callee: VAAddress64(address), kind: kind, name: name ?? "f_\(address)",
                                      callSiteCount: siteList.count, callSites: capped,
                                      callSitesTruncated: siteList.count > capped.count)
    }

    private func inventory(_ callees: [UInt64], limitations: [String] = [], unresolved: Int = 0,
                           indirect: [VACalleeIndirectEntry] = [],
                           completeness: VAObservationCompleteness = .complete,
                           function: VAAddress64? = nil) throws -> VACalleeInventory {
        let sorted = callees.sorted()
        let edges = sorted.map { (site: VAAddress64($0 &+ 0x10_000), target: VAAddress64($0)) }
        return VACalleeInventory(function: function ?? self.function, completeness: completeness,
                                 callees: sorted.map { entry($0) }, indirect: indirect,
                                 unresolvedIndirectCallSites: unresolved, limitations: limitations,
                                 inventoryDigest: try VACalleeInventory.digest(callEdges: edges, limitations: limitations))
    }

    private func binding(_ inventory: VACalleeInventory, generation: UUID? = nil, owner: UUID? = nil,
                         slot: Int = 0, epoch: VAProjectionStamp? = nil) -> VACalleeClaimBinding {
        VACalleeClaimBinding(imageOwner: owner ?? self.owner, slot: slot, function: inventory.function,
                             analysisGeneration: generation ?? generation1, projectionEpoch: epoch,
                             inventoryDigest: inventory.inventoryDigest)
    }

    private func observe(_ inventory: VACalleeInventory?, generation: UUID? = nil, owner: UUID? = nil,
                         epoch: VAProjectionStamp? = nil) -> VACalleeClaimObservation {
        VACalleeClaimObservation(imageOwner: owner ?? self.owner, generation: generation ?? generation1,
                                 projectionEpoch: epoch, inventory: inventory)
    }

    private func openLedger(_ callees: [UInt64], claim: UUID = UUID(),
                            limitations: [String] = []) throws -> (CalleeClaimLedger, UUID, VACalleeInventory) {
        var ledger = CalleeClaimLedger()
        let inv = try inventory(callees, limitations: limitations)
        try ledger.open(claimID: claim, inventory: inv, binding: binding(inv), atMilliseconds: 1)
        return (ledger, claim, inv)
    }

    private func record(_ ledger: inout CalleeClaimLedger, _ claim: UUID, _ callee: UInt64,
                        _ outcome: VACalleeOutcomeKind, reason: String = "because", bearing: VACalleeBearing? = nil,
                        inv: VACalleeInventory, generation: UUID? = nil) throws {
        try ledger.recordOutcome(claimID: claim, callee: VAAddress64(callee), outcome: outcome, reason: reason,
                                 bearing: bearing, observed: observe(inv, generation: generation), atMilliseconds: 2)
    }

    private func addrs(_ values: [UInt64]) -> [VAAddress64] { values.map { VAAddress64($0) } }

    private func sha(_ ch: Character) -> String { String(repeating: ch, count: 64) }

    // MARK: close rules

    func testOpenThenRecordAllThreeKindsCloses() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000, 0x4000])
        var report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .open)
        XCTAssertEqual(report.openCallees, addrs([0x2000, 0x3000, 0x4000]))
        XCTAssertEqual(report.coverage.required, 3)
        try record(&ledger, claim, 0x2000, .examined, bearing: .supports, inv: inv)
        try record(&ledger, claim, 0x3000, .irrelevant, inv: inv)
        report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .open, "one callee still has no outcome")
        XCTAssertEqual(report.openCallees, [VAAddress64(0x4000)])
        try record(&ledger, claim, 0x4000, .deferred, inv: inv)
        report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed)
        XCTAssertEqual(report.coverage.examined, 1)
        XCTAssertEqual(report.coverage.irrelevant, 1)
        XCTAssertEqual(report.coverage.deferred, 1)
        XCTAssertEqual(report.coverage.open, 0)
        XCTAssertTrue(report.openCallees.isEmpty)
    }

    func testEmptyCompleteInventoryOpensClosedAsLeaf() throws {
        let (ledger, claim, inv) = try openLedger([])
        let report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed)
        XCTAssertTrue(report.leaf)
        XCTAssertEqual(report.coverage.required, 0)
        XCTAssertFalse(report.closedWithDeferrals)
    }

    func testEmptyInventoryWithLimitationIsNotALeaf() throws {
        let (ledger, claim, inv) = try openLedger([], limitations: ["tailCallsNotInventoried"])
        let report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertFalse(report.leaf, "an empty list with a limitation is not proof of a leaf")
        XCTAssertEqual(report.coverage.limitations, ["tailCallsNotInventoried"])
        XCTAssertEqual(report.status, .closed, "no required callee is open; the limitation is reported, not blocking")
        // Unresolved indirect sites and advisory indirect targets also disqualify the leaf flag.
        XCTAssertFalse(try inventory([], unresolved: 1).isLeaf)
        let advisory = VACalleeIndirectEntry(callSite: VAAddress64(0x1010), target: VAAddress64(0x9000), scope: "function")
        XCTAssertFalse(try inventory([], indirect: [advisory]).isLeaf)
        XCTAssertTrue(try inventory([]).isLeaf)
    }

    func testClosedWithDeferralsFlag() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000])
        try record(&ledger, claim, 0x2000, .examined, inv: inv)
        try record(&ledger, claim, 0x3000, .deferred, inv: inv)
        var report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed)
        XCTAssertTrue(report.closedWithDeferrals)
        XCTAssertEqual(report.deferredCallees, [VAAddress64(0x3000)])
        try record(&ledger, claim, 0x3000, .examined, reason: "read it later", inv: inv)
        report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed)
        XCTAssertFalse(report.closedWithDeferrals)
        XCTAssertTrue(report.deferredCallees.isEmpty)
    }

    func testReRecordAmendsAndReDerivesKeepingHistory() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        try record(&ledger, claim, 0x2000, .irrelevant, reason: "first", inv: inv)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv)).status, .closed)
        try record(&ledger, claim, 0x2000, .examined, reason: "second", bearing: .contradicts, inv: inv)
        let report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed, "amending a closed claim keeps it derivable as closed")
        XCTAssertEqual(report.coverage.irrelevant, 0)
        XCTAssertEqual(report.coverage.examined, 1)
        XCTAssertEqual(report.contradictingCallees, [VAAddress64(0x2000)])
        let history = ledger.outcomeHistory(claimID: claim, callee: VAAddress64(0x2000))
        XCTAssertEqual(history.map(\.outcome), [.irrelevant, .examined])
        XCTAssertEqual(history.map(\.reason), ["first", "second"])
        XCTAssertEqual(ledger.events.count, 3)
    }

    func testNeutralBearingAcceptedAndNeverBlocksClosure() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000])
        try record(&ledger, claim, 0x2000, .examined, bearing: .neutral, inv: inv)
        try record(&ledger, claim, 0x3000, .examined, bearing: .contradicts, inv: inv)
        let report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed)
        XCTAssertEqual(report.contradictingCallees, [VAAddress64(0x3000)])
    }

    func testUnknownCalleeRejectedAndAdvisoryIndirectTargetAccepted() throws {
        var ledger = CalleeClaimLedger()
        let advisory = VACalleeIndirectEntry(callSite: VAAddress64(0x1010), target: VAAddress64(0x9000), scope: "type:Foo")
        let inv = try inventory([0x2000], indirect: [advisory])
        let claim = UUID()
        try ledger.open(claimID: claim, inventory: inv, binding: binding(inv), atMilliseconds: 1)
        XCTAssertThrowsError(try record(&ledger, claim, 0x7777, .examined, inv: inv)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .calleeNotInClaim(VAAddress64(0x7777)))
        }
        XCTAssertEqual(ledger.events.count, 1, "a refused outcome appends nothing")
        // An advisory indirect target may take an outcome but is not needed to close.
        try record(&ledger, claim, 0x9000, .deferred, inv: inv)
        var report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .open)
        XCTAssertEqual(report.coverage.advisoryRecorded, 1)
        XCTAssertEqual(report.coverage.required, 1)
        try record(&ledger, claim, 0x2000, .irrelevant, inv: inv)
        report = try ledger.report(claimID: claim, observed: observe(inv))
        XCTAssertEqual(report.status, .closed)
        XCTAssertThrowsError(try ledger.report(claimID: UUID(), observed: observe(inv))) {
            XCTAssertEqual($0 as? VACalleeClaimError, .unknownClaim)
        }
    }

    func testReasonAndBearingBounds() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        func expectInvalid(_ reason: String, _ outcome: VACalleeOutcomeKind = .examined,
                           bearing: VACalleeBearing? = nil, line: UInt = #line) {
            XCTAssertThrowsError(try record(&ledger, claim, 0x2000, outcome, reason: reason, bearing: bearing, inv: inv),
                                 line: line) {
                guard let error = $0 as? VACalleeClaimError, case .outcomeInvalid = error else { return XCTFail("\($0)", line: line) }
            }
        }
        expectInvalid("")
        expectInvalid(String(repeating: "x", count: 2_049))
        expectInvalid("ok", .irrelevant, bearing: .supports)
        expectInvalid("ok", .deferred, bearing: .neutral)
        XCTAssertEqual(ledger.events.count, 1)
        try record(&ledger, claim, 0x2000, .irrelevant, reason: "x", inv: inv)
        try record(&ledger, claim, 0x2000, .irrelevant, reason: String(repeating: "y", count: 2_048), inv: inv)
        // Bytes, not characters: 683 three-byte scalars are 2,049 bytes.
        expectInvalid(String(repeating: "\u{20AC}", count: 683), .irrelevant)
        try record(&ledger, claim, 0x2000, .irrelevant, reason: String(repeating: "\u{20AC}", count: 682), inv: inv)
        XCTAssertEqual(ledger.events.count, 4)
    }

    // MARK: caps

    func testEventCapRefusesAndLeavesLedgerUnchanged() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        while ledger.events.count < VACalleeClaimLimits.maximumEvents {
            try record(&ledger, claim, 0x2000, .deferred, inv: inv)
        }
        XCTAssertEqual(ledger.events.count, 16_384)
        XCTAssertThrowsError(try record(&ledger, claim, 0x2000, .deferred, inv: inv)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .eventLimit)
        }
        XCTAssertEqual(ledger.events.count, 16_384)
        // The full ledger still round-trips; one more event in the payload does not.
        let again = try CalleeClaimLedger(events: ledger.events)
        XCTAssertEqual(again, ledger)
        XCTAssertThrowsError(try CalleeClaimLedger(events: ledger.events + [ledger.events[1]])) {
            XCTAssertEqual($0 as? VACalleeClaimError, .eventLimit)
        }
    }

    func testClaimCapRefusesThe257thClaim() throws {
        var ledger = CalleeClaimLedger()
        for index in 0..<VACalleeClaimLimits.maximumClaims {
            let inv = try inventory([], function: VAAddress64(0x10_000 + UInt64(index) * 0x100))
            try ledger.open(claimID: UUID(), inventory: inv, binding: binding(inv), atMilliseconds: 1)
        }
        XCTAssertEqual(ledger.claimIDs.count, 256)
        let extra = try inventory([], function: VAAddress64(0x90_0000))
        XCTAssertThrowsError(try ledger.open(claimID: UUID(), inventory: extra, binding: binding(extra), atMilliseconds: 1)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .claimLimit)
        }
        XCTAssertEqual(ledger.events.count, 256)
    }

    func testCalleeCapAndInventoryValidation() throws {
        let many = (0..<8_193).map { entry(0x10_000 + UInt64($0) * 8) }
        let digest = sha("a")
        XCTAssertThrowsError(try VACalleeInventory(function: function, callees: many, inventoryDigest: digest).validate())
        let ok = Array(many.prefix(8_192))
        XCTAssertNoThrow(try VACalleeInventory(function: function, callees: ok, inventoryDigest: digest).validate())
        XCTAssertThrowsError(try VACalleeInventory(function: function, callees: [entry(0x3000), entry(0x2000)],
                                                   inventoryDigest: digest).validate(), "callees must ascend")
        XCTAssertThrowsError(try VACalleeInventory(function: function, callees: [entry(0x2000), entry(0x2000)],
                                                   inventoryDigest: digest).validate(), "callees must be unique")
        XCTAssertThrowsError(try VACalleeInventory(function: function, callees: [], inventoryDigest: "nothex").validate())
        XCTAssertThrowsError(try VACalleeInventory(function: function, completeness: .partial, callees: [],
                                                   inventoryDigest: digest).validate(), "partial needs a limitation")
        XCTAssertThrowsError(try VACalleeInventory(function: function, completeness: .unavailable,
                                                   callees: [entry(0x2000)], limitations: ["x"],
                                                   inventoryDigest: digest).validate(), "unavailable reports no callees")
        XCTAssertThrowsError(try VACalleeInventory(function: function, callees: [], unresolvedIndirectCallSites: 1_000_001,
                                                   inventoryDigest: digest).validate())
        XCTAssertThrowsError(try VACalleeInventory(function: function, callees: [], limitations: ["b", "a"],
                                                   inventoryDigest: digest).validate(), "limitations must be sorted")
    }

    func testClaimIsNeverOpenedOverAnIncompleteInventory() throws {
        var ledger = CalleeClaimLedger()
        let partial = VACalleeInventory(function: function, completeness: .partial, callees: [entry(0x2000)],
                                        limitations: ["workBudgetPartial"], inventoryDigest: sha("c"))
        XCTAssertThrowsError(try ledger.open(claimID: UUID(), inventory: partial, binding: binding(partial), atMilliseconds: 1)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .inventoryUnavailable)
        }
        XCTAssertTrue(ledger.events.isEmpty)
    }

    func testEntryValidationCallSitesAndKinds() throws {
        let sites = (0..<20).map { UInt64(0x5000 + $0 * 4) }
        let capped = entry(0x2000, sites: sites)
        XCTAssertEqual(capped.callSites.count, 16)
        XCTAssertEqual(capped.callSiteCount, 20)
        XCTAssertTrue(capped.callSitesTruncated)
        XCTAssertNoThrow(try capped.validate())
        let wrongTruncation = VACalleeInventoryEntry(callee: VAAddress64(0x2000), kind: .function, name: "f", callSiteCount: 20,
                                                     callSites: capped.callSites, callSitesTruncated: false)
        XCTAssertThrowsError(try wrongTruncation.validate())
        let descending = VACalleeInventoryEntry(callee: VAAddress64(0x2000), kind: .function, callSiteCount: 2,
                                                callSites: [VAAddress64(0x20), VAAddress64(0x10)], callSitesTruncated: false)
        XCTAssertThrowsError(try descending.validate())
        let named = VACalleeInventoryEntry(callee: VAAddress64(0x2000), kind: .unnamed, name: "guess", callSiteCount: 1,
                                           callSites: [VAAddress64(0x10)], callSitesTruncated: false)
        XCTAssertThrowsError(try named.validate(), "an unnamed callee carries no name")
        let interior = VACalleeInventoryEntry(callee: VAAddress64(0x2010), kind: .interior, name: "f+0x10", callSiteCount: 1,
                                              callSites: [VAAddress64(0x10)], callSitesTruncated: false,
                                              containingFunction: VAAddress64(0x2000), offsetInFunction: 0x10)
        XCTAssertNoThrow(try interior.validate())
        let badOffset = VACalleeInventoryEntry(callee: VAAddress64(0x2010), kind: .interior, callSiteCount: 1,
                                               callSites: [VAAddress64(0x10)], callSitesTruncated: false,
                                               containingFunction: VAAddress64(0x2000), offsetInFunction: 0x20)
        XCTAssertThrowsError(try badOffset.validate())
        let strayContainer = VACalleeInventoryEntry(callee: VAAddress64(0x2010), kind: .stub, callSiteCount: 1,
                                                    callSites: [VAAddress64(0x10)], callSitesTruncated: false,
                                                    containingFunction: VAAddress64(0x2000), offsetInFunction: 0x10)
        XCTAssertThrowsError(try strayContainer.validate())
        for kind in [VACalleeKind.function, .stub, .external, .unnamed] {
            let one = VACalleeInventoryEntry(callee: VAAddress64(0x2000), kind: kind, callSiteCount: 1,
                                             callSites: [VAAddress64(0x10)], callSitesTruncated: false)
            XCTAssertNoThrow(try one.validate())
        }
    }

    func testInventoryDigestIsOrderIndependentAndEdgeSensitive() throws {
        let a = (site: VAAddress64(0x10), target: VAAddress64(0x2000))
        let b = (site: VAAddress64(0x20), target: VAAddress64(0x3000))
        let forward = try VACalleeInventory.digest(callEdges: [a, b], limitations: ["a", "b"])
        XCTAssertEqual(forward, try VACalleeInventory.digest(callEdges: [b, a], limitations: ["b", "a"]))
        XCTAssertNotEqual(forward, try VACalleeInventory.digest(callEdges: [a], limitations: ["a", "b"]))
        XCTAssertNotEqual(forward, try VACalleeInventory.digest(callEdges: [a, b], limitations: ["a"]))
        XCTAssertTrue(VACanonicalJSON.isSHA256(forward))
    }

    // MARK: Codable and strict validation

    func testCodableRoundTripAndStrictRejection() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000])
        let witness = VACalleeWitnessSummary(command: "instructions", generation: generation1, sequence: 7)
        try ledger.recordOutcome(claimID: claim, callee: VAAddress64(0x2000), outcome: .examined, reason: "read",
                                 bearing: .supports, bodyDigest: sha("b"), witness: witness,
                                 observed: observe(inv), atMilliseconds: 5)
        try record(&ledger, claim, 0x3000, .deferred, inv: inv)
        let data = try VACanonicalJSON.encode(ledger)
        let decoded = try CalleeClaimLedger.decode(from: data)
        XCTAssertEqual(decoded, ledger)
        XCTAssertEqual(try VACanonicalJSON.encode(decoded), data)
        XCTAssertEqual(try decoded.report(claimID: claim, observed: observe(inv)),
                       try ledger.report(claimID: claim, observed: observe(inv)))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))

        func mutate(_ transform: (String) -> String, line: UInt = #line) {
            let edited = transform(text)
            XCTAssertNotEqual(edited, text, "the mutation must change the payload", line: line)
            XCTAssertThrowsError(try CalleeClaimLedger.decode(from: Data(edited.utf8)), line: line)
        }
        mutate { $0.replacingOccurrences(of: "{\"events\"", with: "{\"extra\":1,\"events\"") }       // unknown top-level key
        mutate { $0.replacingOccurrences(of: "\"kind\":\"claimOpened\"", with: "\"kind\":\"claimOpened\",\"x\":0") } // unknown event key
        mutate { $0.replacingOccurrences(of: inv.inventoryDigest, with: "zz" + inv.inventoryDigest.dropFirst(2)) } // bad digest
        mutate { $0.replacingOccurrences(of: "\"schemaVersion\":1", with: "\"schemaVersion\":2") }
        mutate { $0.replacingOccurrences(of: "\"outcome\":\"deferred\"", with: "\"outcome\":\"banished\"") }
        mutate { $0.replacingOccurrences(of: "\"sequence\":3", with: "\"sequence\":4") }
        // A duplicate JSON key is rejected before decoding.
        XCTAssertThrowsError(try CalleeClaimLedger.decode(from: Data(#"{"events":[],"events":[],"schemaVersion":1}"#.utf8)))
        XCTAssertNoThrow(try CalleeClaimLedger.decode(from: Data(#"{"events":[],"schemaVersion":1}"#.utf8)))
    }

    func testDuplicateAndSkippedEventSequencesAreRejected() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        try record(&ledger, claim, 0x2000, .irrelevant, inv: inv)
        let first = ledger.events[0], second = ledger.events[1]
        XCTAssertThrowsError(try CalleeClaimLedger(events: [first, first]))
        let skipped = VACalleeClaimEvent(sequence: 3, atMilliseconds: second.atMilliseconds, claimID: claim,
                                         kind: .outcomeRecorded, revision: 1, callee: second.callee,
                                         outcome: second.outcome, reason: second.reason)
        XCTAssertThrowsError(try CalleeClaimLedger(events: [first, skipped]))
        XCTAssertThrowsError(try CalleeClaimLedger(events: [second]), "sequence must start at 1")
        XCTAssertNoThrow(try CalleeClaimLedger(events: [first, second]))
    }

    func testEventShapeIsClosedPerKind() throws {
        let claim = UUID()
        let inv = try inventory([0x2000])
        let b = binding(inv)
        // Outcome without a reason, opened without an inventory, bearing on an opened event, and witness on a deferral.
        let noReason = VACalleeClaimEvent(sequence: 2, atMilliseconds: 0, claimID: claim, kind: .outcomeRecorded,
                                          revision: 1, callee: VAAddress64(0x2000), outcome: .examined)
        XCTAssertThrowsError(try noReason.validateShape())
        let noInventory = VACalleeClaimEvent(sequence: 1, atMilliseconds: 0, claimID: claim, kind: .claimOpened,
                                             revision: 1, binding: b)
        XCTAssertThrowsError(try noInventory.validateShape())
        let strayBearing = VACalleeClaimEvent(sequence: 1, atMilliseconds: 0, claimID: claim, kind: .claimOpened,
                                              revision: 1, binding: b, inventory: inv, bearing: .supports)
        XCTAssertThrowsError(try strayBearing.validateShape())
        let witness = VACalleeWitnessSummary(command: "decompile", generation: generation1, sequence: 1)
        let strayWitness = VACalleeClaimEvent(sequence: 2, atMilliseconds: 0, claimID: claim, kind: .outcomeRecorded,
                                              revision: 1, callee: VAAddress64(0x2000), outcome: .deferred,
                                              reason: "later", witness: witness)
        XCTAssertThrowsError(try strayWitness.validateShape())
        let mismatchedBinding = VACalleeClaimBinding(imageOwner: owner, slot: 0, function: function,
                                                     analysisGeneration: generation1, inventoryDigest: sha("d"))
        let digestMismatch = VACalleeClaimEvent(sequence: 1, atMilliseconds: 0, claimID: claim, kind: .claimOpened,
                                                revision: 1, binding: mismatchedBinding, inventory: inv)
        XCTAssertThrowsError(try digestMismatch.validateShape())
    }

    func testDuplicateClaimForTheSameTargetIsRefused() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        XCTAssertThrowsError(try ledger.open(claimID: claim, inventory: inv, binding: binding(inv), atMilliseconds: 3)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .duplicateClaim)
        }
        XCTAssertThrowsError(try ledger.open(claimID: UUID(), inventory: inv, binding: binding(inv), atMilliseconds: 3)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .duplicateClaim)
        }
        // A different slot of the same image is a different target.
        XCTAssertNoThrow(try ledger.open(claimID: UUID(), inventory: inv, binding: binding(inv, slot: 1), atMilliseconds: 3))
        XCTAssertEqual(ledger.claimIDs.count, 2)
        _ = claim
    }

    // MARK: stale classification (the five rows of DESIGN 2.4)

    func testStaleClassificationTableAllFiveRows() throws {
        let (ledger, claim, inv) = try openLedger([0x2000, 0x3000])
        let epochA = VAProjectionStamp(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
                                       revision: 1, digest: sha("a"))
        let epochB = VAProjectionStamp(workspaceID: epochA.workspaceID, documentID: epochA.documentID,
                                       installationID: epochA.installationID, revision: 2, digest: sha("b"))

        // Row 1: generation equals stored.
        var result = try ledger.classify(claimID: claim, observed: observe(inv))
        XCTAssertNil(result.kind)
        XCTAssertFalse(result.rebindable)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv)).status, .open)

        // Row 2: generation advanced, same root digest (annotation-only change).
        result = try ledger.classify(claimID: claim, observed: observe(inv, generation: generation2))
        XCTAssertEqual(result.kind, .generationAdvanced)
        XCTAssertTrue(result.rebindable)
        XCTAssertFalse(result.projectionEpochMoved, "both epochs are nil")
        XCTAssertTrue(result.addedCallees.isEmpty && result.removedCallees.isEmpty)
        result = try ledger.classify(claimID: claim, observed: observe(inv, generation: generation2, epoch: epochB))
        XCTAssertTrue(result.projectionEpochMoved, "epoch is reported even though it never gates")

        // Row 3: generation advanced and the root digest differs.
        let changed = try inventory([0x3000, 0x4000])
        result = try ledger.classify(claimID: claim, observed: observe(changed, generation: generation2))
        XCTAssertEqual(result.kind, .inventoryChanged)
        XCTAssertFalse(result.rebindable)
        XCTAssertEqual(result.addedCallees, [VAAddress64(0x4000)])
        XCTAssertEqual(result.removedCallees, [VAAddress64(0x2000)])

        // Row 4: image identity differs (reopen); wins over generation and inventory.
        result = try ledger.classify(claimID: claim, observed: observe(inv, generation: generation2, owner: UUID()))
        XCTAssertEqual(result.kind, .imageChanged)
        XCTAssertFalse(result.rebindable)
        result = try ledger.classify(claimID: claim, observed: observe(nil, owner: UUID()))
        XCTAssertEqual(result.kind, .imageChanged)

        // Row 5: the function no longer resolves.
        result = try ledger.classify(claimID: claim, observed: observe(nil, generation: generation2))
        XCTAssertEqual(result.kind, .functionGone)
        XCTAssertFalse(result.rebindable)

        // An inventory for another function is a caller error, not a classification.
        let other = try inventory([0x2000, 0x3000], function: VAAddress64(0x9999))
        XCTAssertThrowsError(try ledger.classify(claimID: claim, observed: observe(other, generation: generation2)))
    }

    func testStaleClaimNeverDerivesClosedAndRefusesOutcomes() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        try record(&ledger, claim, 0x2000, .examined, inv: inv)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv)).status, .closed)
        let before = ledger.events.count
        let observations: [(VACalleeClaimObservation, VACalleeStaleKind)] = [
            (observe(inv, generation: generation2), .generationAdvanced),
            (observe(try inventory([0x2000, 0x3000]), generation: generation2), .inventoryChanged),
            (observe(inv, owner: UUID()), .imageChanged),
            (observe(nil, generation: generation2), .functionGone)
        ]
        for (observed, kind) in observations {
            let report = try ledger.report(claimID: claim, observed: observed)
            XCTAssertEqual(report.status, .stale, "\(kind)")
            XCTAssertEqual(report.staleKind, kind)
            XCTAssertFalse(report.closedWithDeferrals)
            XCTAssertThrowsError(try ledger.recordOutcome(claimID: claim, callee: VAAddress64(0x2000), outcome: .examined,
                                                          reason: "again", observed: observed, atMilliseconds: 9)) {
                XCTAssertEqual($0 as? VACalleeClaimError, .claimStale(kind))
            }
        }
        XCTAssertEqual(ledger.events.count, before, "refused outcomes append nothing")
        // Outcomes already recorded stay visible on the stale report.
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv, generation: generation2)).coverage.examined, 1)
    }

    // MARK: rebind and supersede

    func testRebindPreservesOutcomesAndReturnsInvalidatedCalleesToOpen() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000, 0x4000])
        try record(&ledger, claim, 0x2000, .examined, inv: inv)
        try record(&ledger, claim, 0x3000, .examined, inv: inv)
        try record(&ledger, claim, 0x4000, .irrelevant, inv: inv)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv)).status, .closed)
        let moved = observe(inv, generation: generation2)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: moved).status, .stale)

        XCTAssertThrowsError(try ledger.rebind(claimID: claim, observed: moved, invalidatedCallees: [VAAddress64(0x4000)],
                                               atMilliseconds: 7), "only examined callees can be invalidated")
        XCTAssertThrowsError(try ledger.rebind(claimID: claim, observed: observe(inv), atMilliseconds: 7)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .notRebindable(nil))
        }
        XCTAssertThrowsError(try ledger.rebind(claimID: claim, observed: observe(try inventory([0x2000]), generation: generation2),
                                               atMilliseconds: 7)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .notRebindable(.inventoryChanged))
        }
        try ledger.rebind(claimID: claim, observed: moved, invalidatedCallees: [VAAddress64(0x3000)], atMilliseconds: 8)
        let rebound = ledger.events.last
        XCTAssertEqual(rebound?.kind, .claimRebound)
        XCTAssertEqual(rebound?.previousGeneration, generation1)
        XCTAssertEqual(rebound?.binding?.analysisGeneration, generation2)

        let report = try ledger.report(claimID: claim, observed: moved)
        XCTAssertEqual(report.status, .open, "the invalidated callee is open again")
        XCTAssertEqual(report.openCallees, [VAAddress64(0x3000)])
        XCTAssertEqual(report.coverage.examined, 1)
        XCTAssertEqual(report.coverage.irrelevant, 1)
        XCTAssertEqual(report.reboundCount, 1)
        XCTAssertEqual(report.binding.analysisGeneration, generation2)
        // Old-generation observations are now stale, and the full history survives a replay.
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv)).staleKind, .generationAdvanced)
        XCTAssertEqual(try CalleeClaimLedger(events: ledger.events), ledger)
        try ledger.recordOutcome(claimID: claim, callee: VAAddress64(0x3000), outcome: .examined, reason: "re-read",
                                 observed: moved, atMilliseconds: 9)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: moved).status, .closed)
    }

    func testSupersedeOpensNextRevisionAndPriorOutcomesNeverSatisfy() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000])
        try record(&ledger, claim, 0x2000, .examined, reason: "old a", inv: inv)
        try record(&ledger, claim, 0x3000, .irrelevant, reason: "old b", inv: inv)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observe(inv)).status, .closed)

        let changed = try inventory([0x3000, 0x4000])
        let observed = observe(changed, generation: generation2)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observed).staleKind, .inventoryChanged)
        try ledger.supersede(claimID: claim, inventory: changed, binding: binding(changed, generation: generation2),
                             atMilliseconds: 10)
        let report = try ledger.report(claimID: claim, observed: observed)
        XCTAssertEqual(report.revision, 2)
        XCTAssertEqual(report.status, .open)
        XCTAssertEqual(report.openCallees, addrs([0x3000, 0x4000]), "every callee is open again")
        let prior = try ledger.priorOutcomes(claimID: claim)
        XCTAssertEqual(prior.map(\.callee), addrs([0x2000, 0x3000]))
        XCTAssertEqual(prior.map(\.revision), [1, 1])
        XCTAssertEqual(ledger.claimIDs, [claim], "supersede keeps the claim identity")
        // The removed callee can no longer take an outcome; a new revision callee can.
        XCTAssertThrowsError(try ledger.recordOutcome(claimID: claim, callee: VAAddress64(0x2000), outcome: .deferred,
                                                      reason: "gone", observed: observed, atMilliseconds: 11)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .calleeNotInClaim(VAAddress64(0x2000)))
        }
        try ledger.recordOutcome(claimID: claim, callee: VAAddress64(0x4000), outcome: .deferred, reason: "later",
                                 observed: observed, atMilliseconds: 11)
        XCTAssertEqual(try CalleeClaimLedger(events: ledger.events), ledger)

        // Wrong revision, a different function, and an unknown claim are refused.
        XCTAssertThrowsError(try CalleeClaimLedger(events: Array(ledger.events.prefix(ledger.events.count - 1)) + [
            VACalleeClaimEvent(sequence: UInt64(ledger.events.count), atMilliseconds: 0, claimID: claim, kind: .claimSuperseded,
                               revision: 5, binding: binding(changed, generation: generation2), inventory: changed)]))
        let otherFunction = try inventory([0x3000], function: VAAddress64(0x7000))
        XCTAssertThrowsError(try ledger.supersede(claimID: claim, inventory: otherFunction,
                                                  binding: binding(otherFunction, generation: generation2), atMilliseconds: 12))
        XCTAssertThrowsError(try ledger.supersede(claimID: UUID(), inventory: changed, binding: binding(changed), atMilliseconds: 12)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .unknownClaim)
        }
    }

    func testSupersedeAfterImageChangeBindsTheNewImageOwner() throws {
        var (ledger, claim, inv) = try openLedger([0x2000])
        let newOwner = UUID()
        let observed = observe(inv, generation: generation2, owner: newOwner)
        XCTAssertEqual(try ledger.report(claimID: claim, observed: observed).staleKind, .imageChanged)
        XCTAssertThrowsError(try ledger.rebind(claimID: claim, observed: observed, atMilliseconds: 3)) {
            XCTAssertEqual($0 as? VACalleeClaimError, .notRebindable(.imageChanged))
        }
        try ledger.supersede(claimID: claim, inventory: inv, binding: binding(inv, generation: generation2, owner: newOwner),
                             atMilliseconds: 4)
        let report = try ledger.report(claimID: claim, observed: observed)
        XCTAssertEqual(report.status, .open)
        XCTAssertEqual(report.binding.imageOwner, newOwner)
    }

    func testReplayedLedgerReproducesEveryDerivedReport() throws {
        var (ledger, claim, inv) = try openLedger([0x2000, 0x3000])
        try record(&ledger, claim, 0x2000, .examined, bearing: .supports, inv: inv)
        let second = UUID()
        let other = try inventory([0x5000], function: VAAddress64(0x8000))
        try ledger.open(claimID: second, inventory: other, binding: binding(other), atMilliseconds: 3)
        let data = try VACanonicalJSON.encode(ledger)
        let decoded = try CalleeClaimLedger.decode(from: data)
        XCTAssertEqual(decoded.claimIDs, [claim, second])
        for (id, observed) in [(claim, observe(inv)), (second, observe(other))] {
            XCTAssertEqual(try decoded.report(claimID: id, observed: observed), try ledger.report(claimID: id, observed: observed))
        }
    }
}
