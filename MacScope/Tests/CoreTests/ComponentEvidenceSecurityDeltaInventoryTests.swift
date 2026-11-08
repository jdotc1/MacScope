// AR3 slice 2 (NF11, NF13, NF15, NF20). Expected outcomes are literal tables. Reviews, observations and signature
// evidence are built directly as values; nothing here opens a bundle or executes anything.

import Foundation
import XCTest
@testable import MacScope

typealias SDelta = ComponentEvidenceSecurityDelta

enum SDFx {
    enum Decl { case unobserved, absent, unavailable, present(EntitlementDictionary) }

    struct Spec {
        var path: String
        var kind = "helper"
        var id: String?
        var version: String?
        var architectures = ["arm64"]
        var evidence: CE.SignatureEvidence?
        var info: Decl = .unobserved
        var privacy: Decl = .unobserved
        var loaders: [String: Decl] = [:]
    }

    static let main = "Contents/MacOS/OwnedMain"
    static let helper = "Contents/Helpers/helper"
    static let xpc = "Contents/XPCServices/Svc.xpc/Contents/MacOS/Svc"

    static func dict(_ pairs: KeyValuePairs<String, EntitlementValue>) -> EntitlementDictionary {
        EntitlementDictionary(Dictionary(uniqueKeysWithValues: pairs.map { ($0.key, $0.value) }))
    }

    static func loader(_ commands: [(String, String)]) -> EntitlementDictionary {
        let rows = commands.map {
            EntitlementValue.dictionary(dict(["architecture": .string("arm64"), "command": .string($0.0), "path": .string($0.1)]))
        }
        return dict(["commands": .array(rows)])
    }

    static func sliceRecords(_ evidence: CE.SignatureEvidence?) -> [CE.Slice] {
        (evidence?.slices ?? []).map {
            CE.Slice(index: $0.key.index, cpuType: $0.key.cpuType, cpuSubtype: $0.key.cpuSubtype, headerMagic: $0.key.headerMagic,
                     offset: $0.key.sliceOffset, size: $0.key.sliceSize, isUniversal: (evidence?.slices.count ?? 0) > 1,
                     architecture: CEHarness.key("arm64"), minimumOS: nil, loadDeclarations: [])
        }
    }

    static func record(_ spec: Spec) -> CE.ComponentRecord {
        CE.ComponentRecord(id: UUID(), parentID: nil, path: CEHarness.path(spec.path), kind: CEHarness.key(spec.kind),
                           declaredBundleID: spec.id.map(CEHarness.key), declaredVersion: spec.version.map(CEHarness.key),
                           architectures: spec.architectures.map(CEHarness.key), minimumOS: [], slices: sliceRecords(spec.evidence),
                           issues: [], issueOverflow: nil, metadataAvailable: true, isDeclarationOnly: false)
    }

    static func observation(_ decl: Decl, _ inventory: CE.ComponentInventory, _ record: CE.ComponentRecord,
                            _ category: CE.DeclarationCategory, architecture: CE.ExactUTF8Key? = nil,
                            source: CE.RelativePath) throws -> CE.DeclarationObservation? {
        let origin = CE.DeclarationSource(path: source, architecture: architecture)
        switch decl {
        case .unobserved: return nil
        case .absent:
            return try CE.DeclarationObservation(inventoryID: inventory.id, componentID: record.id, category: category,
                                                 architecture: architecture, state: .notPresent, source: origin)
        case .present(let values):
            return try CE.DeclarationObservation(inventoryID: inventory.id, componentID: record.id, category: category,
                                                 architecture: architecture, state: .present, values: values, source: origin)
        case .unavailable:
            let range = CE.PathRange.leaf(record.path)
            return try CE.DeclarationObservation(inventoryID: inventory.id, componentID: record.id, category: category,
                                                 architecture: architecture, state: .unavailable,
                                                 issue: CE.EvidenceIssue(.io(.read, errno: 13, range), range: range))
        }
    }

    static func input(_ side: SDelta.Side, _ specs: [Spec], scope: CE.InventoryScope? = nil,
                      partial: [SDelta.PartialDetail] = []) throws -> SDelta.Input {
        let records = specs.map(record)
        let inventory = CEHarness.inventory(records, scope)
        var observations: [CE.DeclarationObservation] = []
        var entries: [(componentID: CE.RelativePath, evidence: CE.SignatureEvidence)] = []
        for (spec, record) in zip(specs, records) {
            let locations = CE.CodeUnitDeclarationLocations.locations(for: record.path)
            if let item = try observation(spec.info, inventory, record, .info, source: locations?.infoPath ?? record.path) {
                observations.append(item)
            }
            if let item = try observation(spec.privacy, inventory, record, .privacy,
                                          source: locations?.privacyPath ?? record.path) {
                observations.append(item)
            }
            for (architecture, decl) in spec.loaders.sorted(by: { $0.key < $1.key }) {
                let key = CEHarness.key(architecture)
                if let item = try observation(decl, inventory, record, .loadCommands, architecture: key, source: record.path) {
                    observations.append(item)
                }
            }
            if let evidence = spec.evidence { entries.append((componentID: record.path, evidence: evidence)) }
        }
        let review = try CE.ComponentReview(inventory: inventory, observations: observations)
        let attachment = entries.isEmpty ? nil : try CE.SignatureEvidenceAttachment(inventoryID: inventory.id, entries: entries)
        return try SDelta.Input(side: side, review: review, signatures: attachment, partialDetails: partial)
    }

    static func analyze(_ previous: [Spec], _ current: [Spec], previousScope: CE.InventoryScope? = nil,
                        currentScope: CE.InventoryScope? = nil, options: SDelta.Options? = nil,
                        control: SDelta.Control = .none) throws -> SDelta.Outcome {
        try SDelta.Analyzer.analyze(previous: input(.previous, previous, scope: previousScope),
                                    current: input(.current, current, scope: currentScope), options: options, control: control)
    }

    static func report(_ outcome: SDelta.Outcome, file: StaticString = #filePath, line: UInt = #line) -> SDelta.Report {
        switch outcome {
        case .complete(let report), .partial(let report): return report
        case .refused(let refusal):
            XCTFail("refused: \(refusal.code)", file: file, line: line)
            preconditionFailure("refused")
        }
    }

    static func isPartial(_ outcome: SDelta.Outcome) -> Bool { if case .partial = outcome { true } else { false } }

    static func text(_ key: SDelta.ExactKey) -> String { String(data: key.utf8, encoding: .utf8) ?? "?" }

    static func rows(_ report: SDelta.Report, _ category: SDelta.Category, path: String? = nil) -> [SDelta.Observation] {
        report.observations.filter { $0.category == category && (path == nil || text($0.componentPath) == path) }
    }

    static func row(_ report: SDelta.Report, _ category: SDelta.Category, _ subject: String, path: String? = nil) -> SDelta.Observation? {
        rows(report, category, path: path).first { text($0.subject) == subject }
    }

    static func string(_ text: String) -> SDelta.Value { .string(SDelta.ExactKey(text: text)) }
}

final class ComponentEvidenceSecurityDeltaInventoryTests: XCTestCase {
    private typealias F = SDFx

    func testAddedRemovedAndVersionChangeAreObservedWithCompleteScopes() throws {
        let previous = [F.Spec(path: F.main, kind: "app", version: "1"), F.Spec(path: F.helper)]
        let current = [F.Spec(path: F.main, kind: "app", version: "2"), F.Spec(path: F.xpc, kind: "xpc")]
        let outcome = try F.analyze(previous, current)
        guard case .complete(let report) = outcome else { return XCTFail("expected complete, got \(outcome)") }
        XCTAssertEqual(F.row(report, .componentInventory, "declaredVersion", path: F.main)?.disposition, .observedChange)
        XCTAssertEqual(F.row(report, .componentInventory, "declaredVersion", path: F.main)?.previousValue, F.string("1"))
        XCTAssertEqual(F.row(report, .componentInventory, "declaredVersion", path: F.main)?.currentValue, F.string("2"))
        XCTAssertEqual(F.row(report, .componentInventory, "kind", path: F.main)?.disposition, .unchanged)
        XCTAssertEqual(F.row(report, .componentInventory, "component", path: F.helper)?.disposition, .observedRemoval)
        XCTAssertEqual(F.row(report, .componentInventory, "component", path: F.xpc)?.disposition, .observedAddition)
        XCTAssertTrue(report.findings.contains { $0.kind == .componentRemoved })
    }

    func testPartialScopeNeverTurnsAnAdditionIntoProof() throws {
        let outcome = try F.analyze([F.Spec(path: F.main, kind: "app")],
                                    [F.Spec(path: F.main, kind: "app"), F.Spec(path: F.helper)],
                                    previousScope: CEHarness.scope(.partial))
        XCTAssertTrue(F.isPartial(outcome))
        let report = F.report(outcome)
        let added = F.rows(report, .componentInventory, path: F.helper)
        XCTAssertFalse(added.isEmpty)
        XCTAssertTrue(added.allSatisfy { $0.disposition == .unresolved })
        XCTAssertEqual(report.coverage.previousScope, .partial)
        XCTAssertEqual(report.coverage.status, .partial)
    }

    func testIdentifierCandidateIsNeverAcceptedAsTheSameComponent() throws {
        let outcome = try F.analyze([F.Spec(path: F.main, kind: "app", id: "com.example.x")],
                                    [F.Spec(path: "Contents/MacOS/Renamed", kind: "app", id: "com.example.x")])
        XCTAssertTrue(F.isPartial(outcome))
        let report = F.report(outcome)
        XCTAssertFalse(report.observations.isEmpty)
        XCTAssertTrue(report.observations.allSatisfy { $0.disposition == .unresolved })
        XCTAssertTrue(report.observations.allSatisfy { $0.limitations.contains { $0.code == .componentCorrespondenceUnaccepted } })
        XCTAssertTrue(report.findings.contains { $0.kind == .coverageIncomplete })
        XCTAssertFalse(report.findings.contains { $0.kind == .componentAdded || $0.kind == .componentRemoved })
    }

    func testRowsAreDeterministicAndOrdinalsMatchPosition() throws {
        let previous = [F.Spec(path: F.main, kind: "app", version: "1"), F.Spec(path: F.helper, version: "1")]
        let current = [F.Spec(path: F.main, kind: "app", version: "2"), F.Spec(path: F.helper, version: "2")]
        let id = UUID()
        let a = try SDelta.Analyzer.analyze(previous: F.input(.previous, previous), current: F.input(.current, current), evidenceBasisID: id)
        XCTAssertEqual(F.report(a).observations.enumerated().map { $0.offset == $0.element.id.ordinal }, Array(repeating: true, count: F.report(a).observations.count))
        XCTAssertEqual(F.report(a).reportID, id)
        let keys = F.report(a).observations.map { "\($0.category.rawValue)|\(F.text($0.componentPath))" }
        XCTAssertEqual(keys, keys.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) })
    }
}

final class ComponentEvidenceSecurityDeltaDeclarationTests: XCTestCase {
    private typealias F = SDFx

    func testInfoKeysAreAddedRemovedChangedAndIntegersAreNormalized() throws {
        let before = F.dict(["CFBundleVersion": .string("1"), "Gone": .boolean(true), "Same": .string("s")])
        let after = F.dict(["CFBundleVersion": .string("2"), "New": .integer(5), "Same": .string("s")])
        let report = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(before))],
                                            [F.Spec(path: F.main, kind: "app", info: .present(after))]))
        let category = SDelta.Category.informationPropertyList
        XCTAssertEqual(F.row(report, category, "CFBundleVersion")?.disposition, .observedChange)
        XCTAssertEqual(F.row(report, category, "Gone")?.disposition, .observedRemoval)
        XCTAssertEqual(F.row(report, category, "New")?.disposition, .observedAddition)
        XCTAssertEqual(F.row(report, category, "New")?.currentValue, .normalizedInteger("5"))
        XCTAssertEqual(F.row(report, category, "Same")?.disposition, .unchanged)
        XCTAssertEqual(F.row(report, category, "Same")?.previousState, .observed)
    }

    func testPrivacyTransitionsKeepAbsentAndUnavailableApart() throws {
        let present = Dictionary(uniqueKeysWithValues: [("NSPrivacyTracking", EntitlementValue.boolean(false))])
        let values = EntitlementDictionary(present)
        let cases: [(SDFx.Decl, SDFx.Decl, SDelta.Disposition, SDelta.SourceState, SDelta.SourceState)] = [
            (.present(values), .absent, .observedRemoval, .observed, .absent),
            (.absent, .present(values), .observedAddition, .absent, .observed),
            (.absent, .absent, .unchanged, .absent, .absent),
            (.unavailable, .absent, .unresolved, .unavailable, .absent),
            (.present(values), .unavailable, .unresolved, .observed, .unavailable),
        ]
        for (before, after, disposition, previousState, currentState) in cases {
            let report = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", privacy: before)],
                                                [F.Spec(path: F.main, kind: "app", privacy: after)]))
            let row = F.row(report, .privacyManifest, "[declaration]")
            XCTAssertEqual(row?.disposition, disposition)
            XCTAssertEqual(row?.previousState, previousState)
            XCTAssertEqual(row?.currentState, currentState)
        }
    }

    func testMissingObservationsAreSymmetricUnexaminedOrUnresolved() throws {
        let values = F.dict(["k": .boolean(true)])
        let none = F.report(try F.analyze([F.Spec(path: F.main, kind: "app")], [F.Spec(path: F.main, kind: "app")]))
        let both = F.row(none, .informationPropertyList, "[declaration]")
        XCTAssertEqual(both?.disposition, .unchanged)
        XCTAssertEqual(both?.previousState, .unexamined)
        XCTAssertEqual(both?.currentState, .unexamined)
        XCTAssertEqual(none.coverage.denominators.categories.symmetricUnexamined > 0, true)
        let one = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(values))], [F.Spec(path: F.main, kind: "app")]))
        XCTAssertEqual(F.row(one, .informationPropertyList, "[declaration]")?.disposition, .unresolved)
    }

    func testLoadCommandDependenciesAreAnOrderFreeMultisetAndRunPathsAreOrdered() throws {
        let before = F.loader([("load", "/a"), ("load", "/b"), ("rpath", "@r1"), ("rpath", "@r2")])
        let after = F.loader([("load", "/b"), ("load", "/a"), ("load", "/c"), ("rpath", "@r2"), ("rpath", "@r1")])
        let report = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", loaders: ["arm64": .present(before)])],
                                            [F.Spec(path: F.main, kind: "app", loaders: ["arm64": .present(after)])]))
        let category = SDelta.Category.loadCommands
        let prefix = "arch=arm64/"
        XCTAssertEqual(F.row(report, category, prefix + "dependency:load|/a|-|-|-")?.disposition, .unchanged)
        XCTAssertEqual(F.row(report, category, prefix + "dependency:load|/b|-|-|-")?.disposition, .unchanged)
        XCTAssertEqual(F.row(report, category, prefix + "dependency:load|/c|-|-|-")?.disposition, .observedAddition)
        XCTAssertEqual(F.row(report, category, prefix + "rpath[0]")?.disposition, .observedChange)
        XCTAssertEqual(F.row(report, category, prefix + "rpath[1]")?.disposition, .observedChange)
    }

    func testUnknownLoadCommandIsUnresolvedNotGuessed() throws {
        let odd = F.loader([("mystery", "/x")])
        let report = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", loaders: ["arm64": .present(odd)])],
                                            [F.Spec(path: F.main, kind: "app", loaders: ["arm64": .present(odd)])]))
        let row = F.row(report, .loadCommands, "arch=arm64/[loader]")
        XCTAssertEqual(row?.disposition, .unresolved)
        XCTAssertEqual(row?.limitations.first?.code, .loaderInterpretationUnavailable)
    }
}

final class ComponentEvidenceSecurityDeltaRelatedRulesTests: XCTestCase {
    private typealias F = SDFx

    func testRepeatedDeclarationAndMultiCategoryAndRelatedComponents() throws {
        let before = F.dict(["Flag": .boolean(false)]), after = F.dict(["Flag": .boolean(true)])
        let nested = "Contents/MacOS/OwnedMain/Nested"
        _ = nested
        let previous = [F.Spec(path: F.main, kind: "app", info: .present(before), privacy: .absent),
                        F.Spec(path: F.helper, info: .present(before))]
        let current = [F.Spec(path: F.main, kind: "app", info: .present(after), privacy: .present(F.dict(["k": .boolean(true)]))),
                       F.Spec(path: F.helper, info: .present(after))]
        let report = F.report(try F.analyze(previous, current))
        let kinds = report.findings.map(\.kind)
        XCTAssertTrue(kinds.contains(.repeatedDeclaration))
        XCTAssertTrue(kinds.contains(.componentMultiCategory))
        XCTAssertEqual(kinds.filter { $0 == .declarationChanged }.count, 3)
        let repeated = report.findings.first { $0.kind == .repeatedDeclaration }
        XCTAssertEqual(repeated?.observationIDs.count, 2)
        for finding in report.findings { XCTAssertTrue(finding.observationIDs.allSatisfy { $0.ordinal < report.observations.count }) }
    }

    func testRelatedComponentsRequireBothAcceptedPathsAndNesting() {
        XCTAssertTrue(SDelta.Rules.isAncestor(SDelta.ExactKey(text: "a/b"), of: SDelta.ExactKey(text: "a/b/c")))
        XCTAssertFalse(SDelta.Rules.isAncestor(SDelta.ExactKey(text: "a/b"), of: SDelta.ExactKey(text: "a/bc")))
        XCTAssertFalse(SDelta.Rules.isAncestor(SDelta.ExactKey(text: "a/b"), of: SDelta.ExactKey(text: "a/b")))
    }

    func testNoFindingWhenNothingChanged() throws {
        let values = F.dict(["k": .string("v")])
        let report = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(values), privacy: .absent)],
                                            [F.Spec(path: F.main, kind: "app", info: .present(values), privacy: .absent)]))
        XCTAssertTrue(report.findings.isEmpty)
        XCTAssertTrue(report.observations.allSatisfy { $0.disposition == .unchanged })
    }
}

final class ComponentEvidenceSecurityDeltaCoverageTests: XCTestCase {
    private typealias F = SDFx

    func testCompleteReportCarriesNoOmissionAndAccountedCountsAddUp() throws {
        let values = F.dict(["k": .string("v")])
        let outcome = try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(values), privacy: .absent)],
                                    [F.Spec(path: F.main, kind: "app", info: .present(values), privacy: .absent)])
        guard case .complete(let report) = outcome else { return XCTFail("\(outcome)") }
        let counts = report.coverage.denominators.categories
        XCTAssertEqual(counts.accounted, report.observations.count)
        XCTAssertEqual(counts.accounted, counts.compared + counts.provenAbsent + counts.symmetricUnexamined + counts.unresolved + counts.excluded)
        XCTAssertEqual(report.coverage.omissions.count, 0)
        XCTAssertEqual(report.coverage.previousScope, .completeWithinScope)
        XCTAssertTrue(report.coverage.limitations.contains { $0.code == .staticEvidenceOnly })
    }

    func testObservationCapNamesTheCapAndKeepsFindingsClosed() throws {
        let before = F.dict(["a": .boolean(true), "b": .boolean(true), "c": .boolean(true)])
        let after = F.dict(["a": .boolean(false), "b": .boolean(false), "c": .boolean(false)])
        let options = try SDelta.Options(maximumObservations: 3, maximumFindings: 2048)
        let outcome = try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(before))],
                                    [F.Spec(path: F.main, kind: "app", info: .present(after))], options: options)
        XCTAssertTrue(F.isPartial(outcome))
        let report = F.report(outcome)
        XCTAssertEqual(report.observations.count, 3)
        let omission = report.coverage.omissions.first { $0.domain == .observations }
        XCTAssertEqual(omission?.cap, .observationLimit)
        XCTAssertEqual(report.coverage.status, .partial)
        let retained = Set(report.observations.map(\.id))
        for finding in report.findings { XCTAssertTrue(finding.observationIDs.allSatisfy(retained.contains)) }
    }

    func testFindingCapDropsWholeFindingsOnly() throws {
        let before = F.dict(["a": .boolean(true)]), after = F.dict(["a": .boolean(false)])
        let options = try SDelta.Options(maximumObservations: 8192, maximumFindings: 1)
        let report = F.report(try F.analyze([F.Spec(path: F.main, kind: "app", info: .present(before), privacy: .absent),
                                              F.Spec(path: F.helper, info: .present(before))],
                                             [F.Spec(path: F.main, kind: "app", info: .present(after), privacy: .present(F.dict(["k": .boolean(true)]))),
                                              F.Spec(path: F.helper, info: .present(after))], options: options))
        XCTAssertEqual(report.findings.count, 1)
        XCTAssertEqual(report.coverage.omissions.first { $0.domain == .findings }?.cap, .findingLimit)
        XCTAssertEqual(report.coverage.status, .partial)
    }

    func testCancellationAndDeadlineRefuseWithoutAReport() throws {
        let specs = [F.Spec(path: F.main, kind: "app")]
        do {
            _ = try F.analyze(specs, specs, control: SDelta.Control(isCancelled: { true }, deadlineReached: { false }))
            XCTFail("expected a refusal")
        } catch let refusal as SDelta.Refusal { XCTAssertEqual(refusal.code, .cancelled) }
        do {
            _ = try F.analyze(specs, specs, control: SDelta.Control(isCancelled: { false }, deadlineReached: { true }))
            XCTFail("expected a refusal")
        } catch let refusal as SDelta.Refusal { XCTAssertEqual(refusal.code, .deadlineExceeded) }
    }

    func testCallerKnownLossForcesPartialAndNamesTheDetail() throws {
        let detail = try SDelta.PartialDetail(cap: .sourceRecordLimit, reason: SDelta.Analyzer.reason(.cap(.sourceRecordLimit), "caller cap"),
                                              side: .previous, knownMismatchIDs: [], boundedRange: nil, omissionCount: nil,
                                              remainderUnknown: true)
        let specs = [F.Spec(path: F.main, kind: "app")]
        let outcome = try SDelta.Analyzer.analyze(previous: F.input(.previous, specs, partial: [detail]), current: F.input(.current, specs))
        XCTAssertTrue(F.isPartial(outcome))
        let report = F.report(outcome)
        XCTAssertGreaterThanOrEqual(report.coverage.partialDetails.count, 1)
    }
}
