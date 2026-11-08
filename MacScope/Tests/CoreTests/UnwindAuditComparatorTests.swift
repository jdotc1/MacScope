import Foundation
import XCTest
@testable import MacScope

final class UnwindAuditComparatorTests: XCTestCase {
    private func identity(_ digit: String = "a", subtype: Int32 = 0) throws -> MachOSliceArtifactIdentity {
        try MachOSliceArtifactIdentity(
            uuid: nil, rawCPUType: 0x0100000c, rawCPUSubtype: subtype,
            selectedSliceSHA256: String(repeating: digit, count: 64), selectedSliceByteCount: 0x8000
        )
    }

    private func finding(
        _ id: String = "old", address: UInt64 = 0x1000, name: String? = "_owned",
        body: String? = nil, semantic: String? = nil,
        image: MachOSliceArtifactIdentity
    ) -> UnwindAuditFinding {
        UnwindAuditFinding(
            identity: image,
            function: FunctionVersionFingerprint(
                id: id, address: address, symbolName: name, size: 0x40,
                normalizedBodyHash: body, semanticBodyHash: semantic, instructionCount: 16
            ),
            endAddress: address + 0x40,
            verdict: "agreement", coverage: "compact", mode: "frameless", scope: "modeled_leaf_body",
            encoding: 0x02000000, reasonCodes: ["supported_model_agreement", "bounded"],
            checkedPCs: [address + 8],
            evidence: [.init(code: "caller_state_recovered", message: "original prose", address: address + 12,
                             expected: "entry SP", observed: "entry SP")],
            limitations: ["Bounded modeled states only."], instructionCount: 16
        )
    }

    private func report(_ findings: [UnwindAuditFinding], image: MachOSliceArtifactIdentity) -> UnwindAuditReport {
        UnwindAuditReport(identity: image, findings: findings)
    }

    func testSavedReportRoundTripPreservesQualifiedEvidence() throws {
        let image = try identity()
        let original = report([finding(image: image)], image: image)
        let encoded = try JSONEncoder().encode(original)
        XCTAssertEqual(try JSONDecoder().decode(UnwindAuditReport.self, from: encoded), original)
        var invalid = original
        invalid.schemaVersion = 2
        XCTAssertThrowsError(try invalid.validate()) {
            XCTAssertEqual($0 as? UnwindAuditReportError, .unsupportedSchema(2))
        }
        XCTAssertThrowsError(try JSONDecoder().decode(UnwindAuditReport.self, from: JSONEncoder().encode(invalid)))
        invalid = original
        invalid.findings.append(original.findings[0])
        XCTAssertThrowsError(try invalid.validate()) {
            XCTAssertEqual($0 as? UnwindAuditReportError, .duplicateFunctionID("old"))
        }
        invalid = original
        invalid.findings[0].identity = try identity("b")
        XCTAssertThrowsError(try invalid.validate()) {
            XCTAssertEqual($0 as? UnwindAuditReportError, .identityMismatch("old"))
        }
        invalid = original
        invalid.findings[0].endAddress = 0x1000
        XCTAssertThrowsError(try invalid.validate())
        invalid = original
        invalid.findings[0].endAddress = 0x103c
        XCTAssertThrowsError(try invalid.validate())
        invalid = original
        invalid.findings[0].checkedPCs = [0x1040]
        XCTAssertThrowsError(try invalid.validate()) {
            XCTAssertEqual($0 as? UnwindAuditReportError, .addressOutsideFunction("old", 0x1040))
        }
        invalid = original
        invalid.findings[0].evidence[0].address = 0xffc
        XCTAssertThrowsError(try invalid.validate()) {
            XCTAssertEqual($0 as? UnwindAuditReportError, .addressOutsideFunction("old", 0xffc))
        }
    }

    func testRelocationAndEvidenceProseDoNotChangeAudit() throws {
        let oldImage = try identity(), newImage = try identity("b")
        let before = report([finding(image: oldImage)], image: oldImage)
        var relocated = finding("new", address: 0x5000, image: newImage)
        relocated.reasonCodes.reverse()
        relocated.evidence[0].message = "revised explanatory prose"
        let result = try UnwindAuditComparator.compare(
            baseline: before, current: report([relocated], image: newImage)
        )
        XCTAssertEqual(result.changes.map(\.change), [.unchanged])
        XCTAssertEqual(result.changes.first?.match.basis, .symbolName)
        XCTAssertEqual(result.changes.first?.match.confidence, .high)
        XCTAssertFalse(result.sameSlice)
        XCTAssertTrue(result.modelCompatible)
    }

    func testEachAuditSignatureFieldIsSignificant() throws {
        let image = try identity()
        let original = finding(image: image)
        let mutations: [(inout UnwindAuditFinding) -> Void] = [
            { $0.verdict = "inconsistency" }, { $0.coverage = "dwarf" }, { $0.mode = "frame" },
            { $0.scope = "modeled_call_sites" }, { $0.encoding = 0x02001000 },
            { $0.reasonCodes.append("additional_reason") }, { $0.checkedPCs = [0x1010] },
            { $0.evidence[0].code = "caller_state_mismatch" },
            { $0.evidence[0].expected = "entry x30" }, { $0.evidence[0].observed = "unknown" },
            { $0.evidence[0].address = 0x1010 }
        ]
        for (index, mutate) in mutations.enumerated() {
            var changed = original
            mutate(&changed)
            let result = try UnwindAuditComparator.compare(
                baseline: report([original], image: image), current: report([changed], image: image)
            )
            XCTAssertEqual(result.changes.map(\.change), [.changed], "signature mutation \(index)")
        }
    }

    func testNormalizedBodyMatchRetainsMatcherEvidence() throws {
        let image = try identity(), newImage = try identity("b")
        let old = finding("old", name: nil, body: "shared-body", image: image)
        let new = finding("new", address: 0x5000, name: nil, body: "shared-body", image: newImage)
        let result = try UnwindAuditComparator.compare(
            baseline: report([old], image: image), current: report([new], image: newImage)
        )
        XCTAssertEqual(result.changes.map(\.change), [.unchanged])
        XCTAssertEqual(result.changes.first?.match.basis, .normalizedBody)
        XCTAssertEqual(result.changes.first?.match.confidence, .high)
        XCTAssertEqual(result.changes.first?.match, result.matching.matches.first)
    }

    func testDuplicateCandidatesRemainUnresolved() throws {
        let image = try identity(), newImage = try identity("b")
        let old = [finding("o1", name: nil, body: "duplicate", image: image),
                   finding("o2", address: 0x2000, name: nil, body: "duplicate", image: image)]
        let new = [finding("n1", address: 0x3000, name: nil, body: "duplicate", image: newImage),
                   finding("n2", address: 0x4000, name: nil, body: "duplicate", image: newImage)]
        let result = try UnwindAuditComparator.compare(
            baseline: report(old, image: image), current: report(new, image: newImage)
        )
        XCTAssertTrue(result.changes.isEmpty)
        XCTAssertEqual(result.matching.unresolved, [.init(
            oldIDs: ["o1", "o2"], newIDs: ["n1", "n2"], bases: [.duplicateNormalizedBody]
        )])
        XCTAssertTrue(result.matching.addedIDs.isEmpty)
        XCTAssertTrue(result.matching.removedIDs.isEmpty)
    }

    func testEqualAddressesWithoutEvidenceDoNotMatch() throws {
        let image = try identity(), newImage = try identity("b")
        let result = try UnwindAuditComparator.compare(
            baseline: report([finding("old", name: nil, image: image)], image: image),
            current: report([finding("new", name: nil, image: newImage)], image: newImage)
        )
        XCTAssertTrue(result.changes.isEmpty)
        XCTAssertEqual(result.matching.addedIDs, ["new"])
        XCTAssertEqual(result.matching.removedIDs, ["old"])
    }

    func testIncompatibleModelAndArchitectureAreExplicitlyIncompatible() throws {
        let image = try identity()
        let baseline = report([finding(image: image)], image: image)
        var modelChange = baseline
        modelChange.analysisModelVersion = "different-model"
        let otherArchitecture = try identity(subtype: 2)
        let architectureChange = report([finding(image: otherArchitecture)], image: otherArchitecture)
        for current in [modelChange, architectureChange] {
            let result = try UnwindAuditComparator.compare(baseline: baseline, current: current)
            XCTAssertEqual(result.changes.map(\.change), [.incompatible])
            XCTAssertEqual(result.matching.matches.count, 1)
            XCTAssertFalse(result.modelCompatible)
        }
    }

    func testConfigurationDifferenceIsDisclosed() throws {
        let image = try identity()
        let original = report([finding(image: image)], image: image)
        var current = original
        current.configuration.maxSteps = 100
        let result = try UnwindAuditComparator.compare(baseline: original, current: current)
        XCTAssertTrue(result.configurationChanged)
        XCTAssertTrue(result.limitations.contains { $0.contains("budget-related scope") })
        XCTAssertEqual(result.changes.map(\.change), [.incompatible])
        XCTAssertTrue(result.modelCompatible)
        XCTAssertEqual(result.changes.first?.beforeVerdict, "agreement")
        XCTAssertEqual(result.changes.first?.afterVerdict, "agreement")
    }

    func testRawCPUTypeMismatchAndManualPinRemainIncompatibleWithoutChangingSourceVerdicts() throws {
        let oldImage = try identity()
        let newImage = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x01000007, rawCPUSubtype: 0,
            selectedSliceSHA256: String(repeating: "b", count: 64), selectedSliceByteCount: 0x8000)
        let before = report([finding("old", name: nil, image: oldImage)], image: oldImage)
        var after = report([finding("new", name: nil, image: newImage)], image: newImage)
        after.findings[0].verdict = "unresolved"
        let result = try UnwindAuditComparator.compare(baseline: before, current: after,
            pins: [.init(oldID: "old", newID: "new")])
        XCTAssertFalse(result.modelCompatible)
        XCTAssertEqual(result.changes.map(\.change), [.incompatible])
        XCTAssertEqual(result.changes.first?.beforeVerdict, "agreement")
        XCTAssertEqual(result.changes.first?.afterVerdict, "unresolved")
        XCTAssertEqual(result.matching.matches.first?.basis, .manual)
        XCTAssertEqual(result.matching.manualPins, [.init(oldID: "old", newID: "new")])
        XCTAssertEqual(before.findings[0].verdict, "agreement")
        XCTAssertEqual(after.findings[0].verdict, "unresolved")
    }

    func testCodeDifferencesStaySeparateAndOrderIsDeterministic() throws {
        let image = try identity(), newImage = try identity("b")
        var old = report([
            finding("o1", name: "_first", body: "same", semantic: "before", image: image),
            finding("o2", address: 0x2000, name: "_second", image: image)
        ], image: image)
        var new = report([
            finding("n1", address: 0x5000, name: "_first", body: "same", semantic: "after", image: newImage),
            finding("n2", address: 0x6000, name: "_second", image: newImage)
        ], image: newImage)
        let reference = try UnwindAuditComparator.compare(baseline: old, current: new)
        XCTAssertEqual(reference.matching.matches.first?.differences, [.body])
        XCTAssertEqual(reference.changes.map(\.change), [.unchanged, .unchanged])
        old.findings.reverse()
        new.findings.reverse()
        XCTAssertEqual(try UnwindAuditComparator.compare(baseline: old, current: new), reference)
    }

    func testManualPinsUseExistingValidation() throws {
        let image = try identity()
        let old = report([finding("old", name: nil, image: image)], image: image)
        let new = report([finding("new", name: nil, image: image)], image: image)
        let pinned = try UnwindAuditComparator.compare(
            baseline: old, current: new, pins: [.init(oldID: "old", newID: "new")]
        )
        XCTAssertEqual(pinned.changes.first?.match.basis, .manual)
        XCTAssertEqual(pinned.changes.first?.match.confidence, .userConfirmed)
        XCTAssertThrowsError(try UnwindAuditComparator.compare(
            baseline: old, current: new, pins: [.init(oldID: "missing", newID: "new")]
        )) {
            XCTAssertEqual($0 as? FunctionVersionMatcherError, .unknownOldID("missing"))
        }
    }

    // Removing offset precedence incorrectly pairs the deliberately crossed names.
    func testSameSliceOffsetsOutrankRenamedSymbols() throws {
        let image = try identity()
        let old = report([finding("o1", address: 0x1000, name: "_a", image: image),
                          finding("o2", address: 0x2000, name: "_b", image: image)], image: image)
        let new = report([finding("n2", address: 0x2000, name: "_a", image: image),
                          finding("n1", address: 0x1000, name: "_b", image: image)], image: image)
        let result = try UnwindAuditComparator.compare(baseline: old, current: new)
        XCTAssertEqual(result.matching.matches.map(\.newID), ["n1", "n2"])
        XCTAssertEqual(result.matching.matches.map(\.basis), [.sameSliceOffset, .sameSliceOffset])
        XCTAssertEqual(result.changes.map(\.change), [.unchanged, .unchanged])
        XCTAssertTrue(result.matching.manualPins.isEmpty)
    }

    // A same-slice name/body fallback would wrongly consume this addition/removal.
    func testSameSliceDifferentOffsetsRemainAddedAndRemoved() throws {
        let image = try identity()
        let result = try UnwindAuditComparator.compare(
            baseline: report([finding("old", address: 0x1000, body: "same", image: image)], image: image),
            current: report([finding("new", address: 0x2000, body: "same", image: image)], image: image))
        XCTAssertTrue(result.changes.isEmpty)
        XCTAssertEqual(result.matching.removedIDs, ["old"])
        XCTAssertEqual(result.matching.addedIDs, ["new"])
    }

    // Duplicates must not become guessed pairs or vanish, including one-sided groups.
    func testSameSliceDuplicateAndOneSidedOffsetsAreExhaustivelyAccounted() throws {
        let image = try identity()
        let old = report([finding("o1", address: 0x1000, image: image),
                          finding("o2", address: 0x1000, image: image),
                          finding("removed", address: 0x3000, image: image)], image: image)
        let new = report([finding("n1", address: 0x1000, image: image),
                          finding("n2", address: 0x2000, image: image),
                          finding("n3", address: 0x2000, image: image),
                          finding("added", address: 0x4000, image: image)], image: image)
        let result = try UnwindAuditComparator.compare(baseline: old, current: new)
        XCTAssertEqual(result.matching.unresolved, [
            .init(oldIDs: ["o1", "o2"], newIDs: ["n1"], bases: [.duplicateSameSliceOffset]),
            .init(oldIDs: [], newIDs: ["n2", "n3"], bases: [.duplicateSameSliceOffset])
        ])
        XCTAssertEqual(result.matching.removedIDs, ["removed"])
        XCTAssertEqual(result.matching.addedIDs, ["added"])
        XCTAssertTrue(result.changes.isEmpty)
        XCTAssertNoThrow(try UnwindAuditComparator.validateAccounting(
            result.matching, baseline: old, current: new))
        var reversedOld = old, reversedNew = new
        reversedOld.findings.reverse()
        reversedNew.findings.reverse()
        XCTAssertEqual(try UnwindAuditComparator.compare(
            baseline: reversedOld, current: reversedNew), result)
        let reverse = try UnwindAuditComparator.compare(baseline: new, current: old)
        XCTAssertEqual(reverse.matching.unresolved[1].oldIDs, ["n2", "n3"])
        XCTAssertEqual(reverse.matching.unresolved[1].newIDs, [])
    }

    // Automatic identity must not override explicit user selection.
    func testSameSliceManualPinWinsAndDisclosesOffsetConflict() throws {
        let image = try identity()
        let old = report([finding("o1", address: 0x1000, image: image),
                          finding("o2", address: 0x2000, image: image)], image: image)
        let new = report([finding("n1", address: 0x1000, image: image),
                          finding("n2", address: 0x2000, image: image)], image: image)
        let pin = FunctionVersionManualPin(oldID: "o1", newID: "n2")
        let result = try UnwindAuditComparator.compare(baseline: old, current: new, pins: [pin])
        XCTAssertEqual(result.matching.matches.map(\.basis), [.manual])
        XCTAssertEqual(result.matching.manualPins, [pin])
        XCTAssertEqual(result.matching.removedIDs, ["o2"])
        XCTAssertEqual(result.matching.addedIDs, ["n1"])
        XCTAssertTrue(result.limitations.contains { $0.contains("manual pin overrides") })
        XCTAssertThrowsError(try UnwindAuditComparator.compare(
            baseline: old, current: new, pins: [pin, .init(oldID: "o1", newID: "n1")]))
    }

    // Any one identity component changing must disable offset evidence.
    func testSameSliceRequiresExactArchitectureSubtypeHashAndSize() throws {
        let image = try identity()
        let identities = [
            try identity("b"), try identity(subtype: 2),
            try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x01000007, rawCPUSubtype: 0,
                selectedSliceSHA256: String(repeating: "a", count: 64), selectedSliceByteCount: 0x8000),
            try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c, rawCPUSubtype: 0,
                selectedSliceSHA256: String(repeating: "a", count: 64), selectedSliceByteCount: 0x9000)
        ]
        for other in identities {
            let result = try UnwindAuditComparator.compare(
                baseline: report([finding("old", name: nil, image: image)], image: image),
                current: report([finding("new", name: nil, image: other)], image: other))
            XCTAssertFalse(result.sameSlice)
            XCTAssertTrue(result.matching.matches.isEmpty)
            XCTAssertEqual(result.matching.removedIDs, ["old"])
            XCTAssertEqual(result.matching.addedIDs, ["new"])
        }
    }

    // Pair identity is independent from audit-model/budget comparability.
    func testSameSliceOffsetMatchStillRequiresCompatibleModelAndConfiguration() throws {
        let image = try identity()
        let baseline = report([finding("old", name: nil, image: image)], image: image)
        let current = report([finding("new", name: nil, image: image)], image: image)
        var model = current, config = current
        model.analysisModelVersion = "another-model"
        config.configuration.maxSteps += 1
        for after in [model, config] {
            let result = try UnwindAuditComparator.compare(baseline: baseline, current: after)
            XCTAssertTrue(result.sameSlice)
            XCTAssertEqual(result.matching.matches.map(\.basis), [.sameSliceOffset])
            XCTAssertEqual(result.changes.map(\.change), [.incompatible])
        }
    }

    // Missing, duplicated or foreign endpoints must reject, not shrink coverage.
    func testAccountingValidatorRejectsMissingDuplicatedAndForeignEndpoints() throws {
        let image = try identity()
        let old = report([finding("old", image: image)], image: image)
        let new = report([finding("new", image: image)], image: image)
        let invalidResults: [FunctionVersionMatchResult] = [
            .init(matches: [], addedIDs: ["new"], removedIDs: [], unresolved: [], manualPins: []),
            .init(matches: [], addedIDs: ["new"], removedIDs: ["old", "old"], unresolved: [], manualPins: []),
            .init(matches: [], addedIDs: ["foreign"], removedIDs: ["old"], unresolved: [], manualPins: []),
            .init(matches: [], addedIDs: ["new"], removedIDs: ["old"],
                  unresolved: [.init(oldIDs: [], newIDs: [], bases: [.duplicateSameSliceOffset])],
                  manualPins: []),
            .init(matches: [], addedIDs: ["new"], removedIDs: ["old"], unresolved: [],
                  manualPins: [.init(oldID: "old", newID: "new")]),
            .init(matches: [.init(
                oldID: "old", newID: "new", oldAddress: 0x2000, newAddress: 0x1000,
                basis: .sameSliceOffset, confidence: .high,
                propagatedFromOldCallerID: nil, propagatedFromNewCallerID: nil,
                differences: [], symbolNameChanged: false
            )], addedIDs: [], removedIDs: [], unresolved: [], manualPins: [])
        ]
        for result in invalidResults {
            XCTAssertThrowsError(try UnwindAuditComparator.validateAccounting(
                result, baseline: old, current: new))
        }
        let empty = report([], image: image)
        let result = try UnwindAuditComparator.compare(baseline: empty, current: empty)
        XCTAssertTrue(result.changes.isEmpty)
    }
}
