import Foundation
import XCTest
@testable import MacScope

// Packet 1320, pin d677ed99694984423c9fc4d1b8dc5e731d105fac.
// Authored and static-reviewed only. Apply WIRING, FIX and TEST before the one focused run.
@MainActor
final class TypeAtlasRefusalFieldsTests: XCTestCase {
    private let emptyLinks = WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks()
    private let sentinelDetail = "Type read exceeds the finite preparation or nested-result budget; narrow the workspace type catalog."

    private func small() -> TypeAtlasEntry { TypeAtlasReplyTestHarness.small(0) }

    private func snapshot(_ entries: [TypeAtlasEntry] = [], definitions: [TypeDefinition] = [],
                          uncached: ImageAnalysis? = nil) -> WorkspaceSnapshot {
        var analysis = uncached ?? ImageAnalysis()
        if uncached == nil { analysis.typeCatalog = .init(slot: .primary, entries: entries) }
        return WorkspaceSnapshot(binaries: [BinaryImage(id: TypeAtlasReplyTestHarness.owner,
            name: "synthetic-atlas", path: "/unused/synthetic-atlas", kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: analysis], typeDefinitions: definitions)
    }

    private func store(_ snapshot: WorkspaceSnapshot) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "Refusal fields", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func failure(_ body: () throws -> Void) throws -> ScriptingError {
        do { try body() }
        catch let error as ScriptingError { return error }
        XCTFail("Expected a ScriptingError refusal")
        throw ScriptingError.invalidArgument("test expected refusal")
    }

    private func carried(_ error: ScriptingError) throws -> MCPToolRefusal {
        guard case .structuredRefusal(let value) = error else {
            XCTFail("Expected structured refusal")
            throw error
        }
        return value
    }

    @discardableResult
    private func assertP1(_ error: ScriptingError, budget: MCPRefusalBudget, used: Int64,
                          narrowing: [String], prefix: Bool = false) throws -> MCPToolRefusal {
        let raw = try carried(error)
        XCTAssertEqual(raw.code, .budgetExceeded)
        XCTAssertEqual(raw.budget, budget)
        XCTAssertEqual(raw.used, used)
        XCTAssertEqual(raw.narrowing, narrowing)
        if prefix { XCTAssertTrue(raw.detail.contains(TypeAtlasDefaultReplyPolicy.observedPrefixNote)) }
        let mapped = try XCTUnwrap(MCPToolRefusal.executionRefusal(error))
        XCTAssertEqual(mapped.code, raw.code)
        XCTAssertEqual(mapped.budget, raw.budget)
        XCTAssertEqual(mapped.used, raw.used)
        XCTAssertEqual(mapped.narrowing, raw.narrowing)
        XCTAssertEqual(mapped.detail, String(raw.detail.prefix(1_024)))
        XCTAssertEqual(mapped.value["refusal"]?["budget"], .object([
            "unit": .string(budget.unit.rawValue), "limit": .int(budget.limit)]))
        XCTAssertEqual(mapped.value["refusal"]?["used"], .int(used))
        XCTAssertEqual(mapped.value["refusal"]?["narrowing"], .array(narrowing.map { .string($0) }))
        return raw
    }

    private func direct(_ entries: [TypeAtlasEntry], mode: TypeAtlasUnpagedMode = .publicPrefix,
                        limit: Int = 5_000,
                        links: WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks? = nil) throws -> ScriptValue {
        try WorkspaceScriptingAPI.typeAtlasUnpagedReply(entries, links: links ?? emptyLinks, slot: .primary,
            snapshot: snapshot(entries), kind: nil, limit: limit, mode: mode)
    }

    // Measure with the same work methods and order as the reached throw site, not a guessed charge.
    private func measuredWork(before: (inout TypeAtlasDefaultReplyWork) throws -> Void = { _ in },
                              _ body: (inout TypeAtlasDefaultReplyWork) throws -> Void) throws -> MCPToolRefusal {
        var work = TypeAtlasDefaultReplyWork()
        try before(&work) // Must succeed; do not mistake an earlier failure for the intended site.
        let error = try failure { try body(&work) }
        XCTAssertEqual(error, AttachedTypeReadBudget.refused)
        return try carried(work.reportingRefusal(error))
    }

    private func compareWork(_ actual: ScriptingError, _ expected: MCPToolRefusal,
                             page: Bool, prefix: Bool = false) throws {
        _ = try assertP1(actual, budget: XCTUnwrap(expected.budget), used: XCTUnwrap(expected.used),
                         narrowing: page ? ["page"] : [], prefix: prefix)
        let value = try carried(actual)
        if page { XCTAssertTrue(value.detail.hasSuffix(WorkspaceScriptingAPI.typeAtlasPageHint)) }
        else { XCTAssertEqual(value.detail, expected.detail) }
    }

    private func assertDefaultDetail(_ detail: String, name: String, includeName: Bool,
                                     prefix: Bool = false) throws {
        let note = TypeAtlasDefaultReplyPolicy.observedPrefixNote
        if prefix { XCTAssertTrue(detail.hasPrefix(note)) }
        let bare = prefix ? String(detail.dropFirst(note.count)) : detail
        let identity = String(name.prefix(256)) // Test names here are ASCII.
        let begin = "Type Atlas row at original index 0, name \(identity), exceeds the default reply allowance after summary. Use list-image-types "
        let selection = includeName ? " Compare the returned id if names repeat."
            : " Stream full pages and compare the original row id; the name exceeds the exact-name filter or is empty."
        let end = "." + selection + " " + WorkspaceScriptingAPI.typeAtlasPageHint
        XCTAssertTrue(bare.hasPrefix(begin)); XCTAssertTrue(bare.hasSuffix(end))
        guard bare.hasPrefix(begin), bare.hasSuffix(end), bare.count >= begin.count + end.count else { return }
        let routeText = String(bare.dropFirst(begin.count).dropLast(end.count))
        let route = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(routeText.utf8)) as? [String: Any])
        var keys: Set<String> = ["page", "fields", "limit", "image"]
        if includeName { keys.insert("name") }
        XCTAssertEqual(Set(route.keys), keys)
        XCTAssertEqual(route["page"] as? Bool, true)
        XCTAssertEqual(route["fields"] as? String, "full")
        XCTAssertEqual(route["limit"] as? Int, 1)
        XCTAssertEqual(route["image"] as? Int, 0)
        XCTAssertEqual(route["name"] as? String, includeName ? name : nil)
    }

    // DEFAULT-ROW-REFUSAL-P1-WORK, R1. Both visits fit; second 600,000-byte text charge does not.
    func testR1FirstRowPassTwoWork() throws {
        var entry = small(); entry.name = String(repeating: "a", count: 600_000)
        let expected = try measuredWork(before: { work in
            try work.visit(); try work.row(entry, link: nil, checkpoint: {})
            try work.visit()
        }) { work in try work.row(entry, link: nil, checkpoint: {}) }
        let error = try failure { _ = try direct([entry]) }
        try compareWork(error, expected, page: true)
        try assertDefaultDetail(carried(error).detail, name: entry.name, includeName: false)
    }

    // DEFAULT-ROW-REFUSAL-P1-ADMISSION, R2; internalComplete candidate rethrow R11.
    func testR2AndR11CandidateOwnsNodeMeasurement() throws {
        var entry = small(); entry.users = Array(repeating: 0x1000, count: 4_096)
        var candidate = AttachedTypeReadBudget()
        let sentinel = try failure { try candidate.entries([entry], checkpoint: {}) }
        XCTAssertEqual(sentinel, AttachedTypeReadBudget.refused)
        let measured = try carried(candidate.reportingRefusal(sentinel))
        for mode in [TypeAtlasUnpagedMode.publicPrefix, .internalComplete] {
            let error = try failure { _ = try direct([entry], mode: mode) }
            _ = try assertP1(error, budget: XCTUnwrap(measured.budget), used: XCTUnwrap(measured.used),
                             narrowing: mode == .publicPrefix ? ["page"] : [])
            if mode == .internalComplete { XCTAssertEqual(try carried(error).detail, sentinelDetail) }
            else { try assertDefaultDetail(carried(error).detail, name: entry.name, includeName: true) }
        }
    }

    // USED-LOWER-BOUND: the 2,049-byte prefix must not claim a 4,000-byte full string was measured.
    func testR2AndR11CandidateTextPrefixIsLabelled() throws {
        var entry = small(); entry.name = String(repeating: "a", count: 4_000)
        var candidate = AttachedTypeReadBudget()
        let sentinel = try failure { try candidate.entries([entry], checkpoint: {}) }
        let measured = try carried(candidate.reportingRefusal(sentinel))
        for mode in [TypeAtlasUnpagedMode.publicPrefix, .internalComplete] {
            let error = try failure { _ = try direct([entry], mode: mode) }
            let value = try assertP1(error, budget: XCTUnwrap(measured.budget), used: XCTUnwrap(measured.used),
                narrowing: mode == .publicPrefix ? ["page"] : [], prefix: true)
            if mode == .publicPrefix {
                XCTAssertTrue(value.detail.hasSuffix(WorkspaceScriptingAPI.typeAtlasPageHint))
                try assertDefaultDetail(value.detail, name: entry.name, includeName: false, prefix: true)
            } else {
                XCTAssertEqual(value.detail, TypeAtlasDefaultReplyPolicy.observedPrefixNote + sentinelDetail)
            }
        }
    }

    private func wireRow() -> TypeAtlasEntry {
        var entry = small(); entry.name = "Wire"
        entry.methods = (0..<100).map { _ in
            TypeAtlasMethod(name: String(repeating: "n", count: 2_000), implementation: nil)
        }
        return entry
    }

    // DEFAULT-ROW-REFUSAL-P1-WIRE-ROW, R3. used is the measured row, without separator +1.
    func testR3WireRowAndSyncAsyncParity() async throws {
        let entry = wireRow()
        let row = try WorkspaceScriptingAPI.applyingTypeAtlasLink(
            WorkspaceScriptingAPI.typeAtlasEntryValue(entry), link: nil, checkpoint: {})
        let charge = try WorkspaceScriptingAPI.listPageWireBytes(row)
        XCTAssertGreaterThanOrEqual(charge, defaultTypeAtlasEscapedRowCap)
        var admission = AttachedTypeReadBudget()
        try admission.entries([entry], checkpoint: {}) // proves R2 does not mask R3
        let directError = try failure { _ = try direct([entry]) }
        _ = try assertP1(directError, budget: .init(unit: .bytes, limit: 166_000),
                         used: Int64(charge), narrowing: ["page"])
        let api = WorkspaceScriptingAPI(store: store(snapshot([entry])))
        let sync = try failure { _ = try api.execute("list-image-types") }
        let asynchronous: ScriptingError
        do {
            _ = try await api.executeAsync("list-image-types", arguments: .object([:]))
            XCTFail("Expected async R3 refusal")
            return
        } catch let error as ScriptingError { asynchronous = error }
        XCTAssertEqual(try carried(sync), try carried(directError))
        XCTAssertEqual(try carried(asynchronous), try carried(sync))
    }

    // Fill remaining work with visits measured from production; no hidden additive-text assumption.
    private func visitFixture() throws -> (entry: TypeAtlasEntry, padding: Int, refusal: MCPToolRefusal) {
        var entry = small(); entry.name = String(repeating: "a", count: 900_000)
        var work = TypeAtlasDefaultReplyWork()
        try work.visit(); try work.row(entry, link: nil, checkpoint: {}) // Must succeed.
        var padding = 0
        for _ in 0...1_000_000 {
            do { try work.visit(); padding += 1 }
            catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                return (entry, padding, try carried(work.reportingRefusal(error)))
            }
        }
        XCTFail("Finite work ledger did not refuse")
        throw ScriptingError.invalidArgument("test expected finite work limit")
    }

    // R7: limit=1 skips later row projections; one extra visit fails in pass 1.
    func testR7PassOneVisitUsesOwningLedger() throws {
        let measured = try visitFixture()
        let entries = [measured.entry] + Array(repeating: small(), count: measured.padding + 1)
        let error = try failure { _ = try direct(entries, limit: 1) }
        try compareWork(error, measured.refusal, page: false)
    }

    func testR8PassOneRowTextUsesLabelledPrefix() throws {
        var entry = small(); entry.name = String(repeating: "a", count: 1_000_100)
        let expected = try measuredWork(before: { try $0.visit() }) { work in
            try work.row(entry, link: nil, checkpoint: {})
        }
        let error = try failure { _ = try direct([entry]) }
        try compareWork(error, expected, page: false, prefix: true)
    }

    // R9: exactly the measured successful padding visits fill pass 1; first pass-2 visit fails.
    func testR9PassTwoVisitUsesOwningLedger() throws {
        let measured = try visitFixture()
        let entries = [measured.entry] + Array(repeating: small(), count: measured.padding)
        let error = try failure { _ = try direct(entries, limit: 1) }
        try compareWork(error, measured.refusal, page: false)
    }

    // OUTPUT-WORK-SENTINEL-P1-INTERNAL-COMPLETE: R10 skips the pass-1 row charge.
    func testR10InternalWorkRethrowUsesOwningLedger() throws {
        var entry = small(); entry.name = String(repeating: "a", count: 1_000_100)
        let expected = try measuredWork(before: { work in try work.visit(); try work.visit() }) { work in
            try work.row(entry, link: nil, checkpoint: {})
        }
        let error = try failure { _ = try direct([entry], mode: .internalComplete) }
        try compareWork(error, expected, page: false, prefix: true)
    }

    // A cached identity key is not source-text charged, but its derived link is work charged.
    // Supplement:499 supplies the ObjC spelling; production link construction must confirm the pair.
    private func linkedEntries(identityBytes: Int) -> [TypeAtlasEntry] {
        var objc = small(); objc.name = "_TtC6TG_Pro14SMCKeyRegistry"
        var swift = small(); swift.kind = .swiftClass
        swift.id = .init(slot: .primary, kind: .swiftClass, key: .name(String(repeating: "a", count: identityBytes)))
        swift.name = "SMCKeyRegistry"; swift.qualifiedName = "TG_Pro.SMCKeyRegistry"
        swift.isPrivateOrLocal = false; swift.isGeneric = false
        return [objc, swift]
    }

    private func checkedLinks(_ entries: [TypeAtlasEntry]) throws -> WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks {
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        XCTAssertEqual(links.counts?.linked, 1)
        XCTAssertEqual(try XCTUnwrap(links.byIndex[0]).otherID, entries[1].id)
        return links
    }

    private func assertPublicParity(_ entries: [TypeAtlasEntry], arguments: ScriptValue = .object([:]),
                                    expected: ScriptingError) async throws {
        var source = AttachedTypeReadBudget()
        try source.definitions([], includeLayout: true, checkpoint: {})
        try source.take(1)
        try source.entries(entries, checkpoint: {}) // The public witness must pass source preflight.
        let api = WorkspaceScriptingAPI(store: store(snapshot(entries)))
        let sync = try failure { _ = try api.execute("list-image-types", arguments: arguments) }
        XCTAssertEqual(try carried(sync), try carried(expected))
        do {
            _ = try await api.executeAsync("list-image-types", arguments: arguments)
            XCTFail("Expected public asynchronous refusal")
        } catch let error as ScriptingError {
            XCTAssertEqual(try carried(error), try carried(sync))
            XCTAssertEqual(MCPToolRefusal.executionRefusal(error), MCPToolRefusal.executionRefusal(sync))
        }
    }

    func testPublicR1LinkedIdentityWorkAndParity() async throws {
        let entries = linkedEntries(identityBytes: 600_000)
        let links = try checkedLinks(entries)
        let link = try XCTUnwrap(links.byIndex[0])
        let measured = try measuredWork(before: { work in
            try work.visit(); try work.row(entries[0], link: link, checkpoint: {})
            try work.visit() // Swift row is visited but summary is already selected.
            try work.visit() // First pass-2 row.
        }) { work in try work.row(entries[0], link: link, checkpoint: {}) }
        let error = try failure { _ = try direct(entries, links: links) }
        try compareWork(error, measured, page: true)
        try await assertPublicParity(entries, expected: error)
    }

    func testPublicR2CandidateLinkedIdentityAndParity() async throws {
        let entries = linkedEntries(identityBytes: 4_000)
        let links = try checkedLinks(entries)
        var candidate = AttachedTypeReadBudget()
        try candidate.take(2); try candidate.framing(256) // Initial counts envelope, input2:38–39.
        try candidate.entries([entries[0]], checkpoint: {})
        var selectedLinks = WorkspaceScriptingAPI.TypeAtlasSwiftObjCLinks()
        selectedLinks.byIndex[0] = try XCTUnwrap(links.byIndex[0])
        let sentinel = try failure { try candidate.links(selectedLinks, checkpoint: {}) }
        let measured = try carried(candidate.reportingRefusal(sentinel))
        let error = try failure { _ = try direct(entries, links: links) }
        _ = try assertP1(error, budget: XCTUnwrap(measured.budget), used: XCTUnwrap(measured.used),
                         narrowing: ["page"], prefix: true)
        try await assertPublicParity(entries, expected: error)
    }

    func testPublicR8LinkedIdentityWorkPrefixAndParity() async throws {
        let entries = linkedEntries(identityBytes: 1_000_100)
        let links = try checkedLinks(entries)
        let link = try XCTUnwrap(links.byIndex[0])
        let measured = try measuredWork(before: { try $0.visit() }) { work in
            try work.row(entries[0], link: link, checkpoint: {})
        }
        let error = try failure { _ = try direct(entries, links: links) }
        try compareWork(error, measured, page: false, prefix: true)
        try await assertPublicParity(entries, expected: error)
    }

    // Measured visit padding also yields public R7/R9 fixtures below the source node cap.
    private func publicVisitFixture() throws -> (entries: [TypeAtlasEntry], padding: Int, refusal: MCPToolRefusal) {
        let entries = linkedEntries(identityBytes: 999_000)
        let links = try checkedLinks(entries)
        var work = TypeAtlasDefaultReplyWork()
        try work.visit(); try work.row(entries[0], link: links.byIndex[0], checkpoint: {})
        var padding = 0
        for _ in 0...1_000_000 {
            do { try work.visit(); padding += 1 }
            catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                guard (1...4_000).contains(padding) else {
                    XCTFail("Measured padding cannot witness the intended public source-preflight boundary")
                    throw ScriptingError.invalidArgument("public visit fixture precondition")
                }
                return (entries, padding, try carried(work.reportingRefusal(error)))
            }
        }
        XCTFail("Finite work ledger did not refuse")
        throw ScriptingError.invalidArgument("test expected finite work limit")
    }

    func testPublicR7PassOneVisitAndParity() async throws {
        let measured = try publicVisitFixture()
        var filler = small(); filler.id.key = .address(0x2000); filler.name = "F"
        // Swift is already one of the padding visits; p fillers add p+1 after the first row.
        let entries = measured.entries + Array(repeating: filler, count: measured.padding)
        let links = try checkedLinks(entries)
        let error = try failure { _ = try direct(entries, limit: 1, links: links) }
        try compareWork(error, measured.refusal, page: false)
        try await assertPublicParity(entries, arguments: .object(["limit": .int(1)]), expected: error)
    }

    func testPublicR9PassTwoVisitAndParity() async throws {
        let measured = try publicVisitFixture()
        var filler = small(); filler.id.key = .address(0x2000); filler.name = "F"
        let entries = measured.entries + Array(repeating: filler, count: measured.padding - 1)
        let links = try checkedLinks(entries)
        let error = try failure { _ = try direct(entries, limit: 1, links: links) }
        try compareWork(error, measured.refusal, page: false)
        try await assertPublicParity(entries, arguments: .object(["limit": .int(1)]), expected: error)
    }

    // R4 numeric fixture executes the production sum extracted by W02, not a fake row ledger.
    func testR4OverflowReportsObservedOperandBound() throws {
        let error = try failure { _ = try WorkspaceScriptingAPI.typeAtlasPreparationSum(UInt(Int.max), 1) }
        let value = try assertP1(error, budget: .init(unit: .workSteps, limit: 4_194_304),
                                 used: Int64(Int.max), narrowing: [])
        XCTAssertTrue(value.detail.hasSuffix(WorkspaceScriptingAPI.typeAtlasPreparationOverflowNote))
        XCTAssertTrue(WorkspaceScriptingAPI.isTypeAtlasPreparationRefusal(error))
        XCTAssertEqual(try WorkspaceScriptingAPI.typeAtlasPreparationSum(2, 3), 5)
        XCTAssertEqual(try WorkspaceScriptingAPI.typeAtlasPreparationSum(UInt(Int.max), 0), Int.max)
    }

    private func fanout() -> ImageAnalysis {
        var analysis = ImageAnalysis()
        // Supplement TypeAtlasPageTests.swift:810–816 supplies this exact initializer shape.
        analysis.objcClasses = [ObjCClass(name: "A", superclassName: nil, adoptedProtocols: [],
            classMethods: [], instanceMethods: [], ivars: [], properties: [], address: 0x1000)]
        analysis.objcClasses[0].instanceMethods = (0..<2_049).map { _ in
            ObjCMethod(selector: "m", typeEncoding: nil, isClassMethod: false)
        }
        analysis.objcSelectors = [0x9000: "m"]
        analysis.xrefs = (0..<2_049).map {
            XRef(id: UUID(), from: UInt64(0x100000 + $0 * 4), to: 0x9000, kind: XRefKind.selref)
        }
        return analysis
    }

    // PREPARATION-REFUSAL-P1-FANOUT, R5. Final full fanout is not the first refused charge.
    func testR5FanoutAndSyncAsyncParity() async throws {
        let snap = snapshot(uncached: fanout())
        let args: ScriptValue = .object(["page": .bool(true), "fields": .string("names")])
        let api = WorkspaceScriptingAPI(store: store(snap))
        let sync = try failure { _ = try api.execute("list-image-types", arguments: args) }
        _ = try assertP1(sync, budget: .init(unit: .workSteps, limit: 4_194_304), used: 4_196_352, narrowing: [])
        XCTAssertFalse(try WorkspaceScriptingAPI.typeAtlasPageWouldPrepare(snap.analysisBySlot[.primary], checkpoint: {}))
        do {
            _ = try await api.executeAsync("list-image-types", arguments: args)
            XCTFail("Expected async preparation refusal")
        } catch let error as ScriptingError { XCTAssertEqual(try carried(error), try carried(sync)) }
    }

    // PREPARATION-REFUSAL-P1-PAGE-DEFINITIONS, R6; E5 shared validator remains plain.
    func testR6PageDefinitionsAndSyncAsyncParity() async throws {
        let definitions = [TypeDefinition(kind: .struct, name: "U",
            fields: (0..<4_096).map { _ in FieldDef(name: "x", type: "int") })]
        let raw = try failure { try WorkspaceScriptingAPI.validateSnapshotTypeDefinitions(definitions) }
        XCTAssertEqual(raw, AttachedTypeReadBudget.refused)
        let api = WorkspaceScriptingAPI(store: store(snapshot(definitions: definitions)))
        let args: ScriptValue = .object(["page": .bool(true)])
        let sync = try failure { _ = try api.execute("list-image-types", arguments: args) }
        _ = try assertP1(sync, budget: .init(unit: .nodes, limit: 4_096), used: 4_097, narrowing: [])
        XCTAssertEqual(try carried(sync).detail, sentinelDetail)
        do {
            _ = try await api.executeAsync("list-image-types", arguments: args)
            XCTFail("Expected async page definitions refusal")
        } catch let error as ScriptingError { XCTAssertEqual(try carried(error), try carried(sync)) }
    }

    func testR6PageDefinitionsTextPrefixIsLabelled() throws {
        let definitions = [TypeDefinition(kind: .struct, name: String(repeating: "a", count: 4_000), fields: [])]
        let error = try failure {
            _ = try WorkspaceScriptingAPI.typeAtlasPage(.object(["page": .bool(true)]),
                snapshot: snapshot(definitions: definitions), checkpoint: {})
        }
        _ = try assertP1(error, budget: .init(unit: .bytes, limit: 2_048), used: 2_049, narrowing: [], prefix: true)
    }

    // SENTINEL-EQUALITY-PRESERVED and E3: checkpoint origin wins before preparation recognition.
    func testStableSentinelAndPreparationCheckpointProvenance() throws {
        var budget = AttachedTypeReadBudget()
        let raw = try failure { try budget.take(4_097) }
        XCTAssertEqual(raw, AttachedTypeReadBudget.refused)
        XCTAssertNil(try carried(raw).budget)
        XCTAssertNil(try carried(raw).used)
        let template = WorkspaceScriptingAPI.typeAtlasPreparationRefusal
        let injected = try failure {
            _ = try WorkspaceScriptingAPI.typeAtlasPageWouldPrepare(fanout(), checkpoint: { throw template })
        }
        XCTAssertEqual(injected, template)
        let exact = WorkspaceScriptingAPI.typeAtlasPreparationRefusalReporting(used: 4_196_352)
        XCTAssertTrue(WorkspaceScriptingAPI.isTypeAtlasPreparationRefusal(exact))
        var unrelated = try carried(exact); unrelated.narrowing = ["page"]
        XCTAssertFalse(WorkspaceScriptingAPI.isTypeAtlasPreparationRefusal(.structuredRefusal(unrelated)))
    }

    // DETAIL-CUT-KEEPS-BUDGET-USED. Only detail is cut, including when a note precedes a long hint.
    func testDetailCutKeepsBudgetUsedAndNarrowing() throws {
        let raw = MCPToolRefusal(code: .budgetExceeded, detail: String(repeating: "x", count: 1_025),
            budget: .init(unit: .bytes, limit: 166_000), used: 200_000, narrowing: ["page"])
        _ = try assertP1(.structuredRefusal(raw), budget: .init(unit: .bytes, limit: 166_000),
                         used: 200_000, narrowing: ["page"])
        XCTAssertEqual(MCPToolRefusal.executionRefusal(ScriptingError.structuredRefusal(raw))?.detail.count, 1_024)
        let labelled = TypeAtlasDefaultReplyPolicy.labelPrefix(.structuredRefusal(raw))
        let mapped = try XCTUnwrap(MCPToolRefusal.executionRefusal(labelled))
        XCTAssertTrue(mapped.detail.hasPrefix(TypeAtlasDefaultReplyPolicy.observedPrefixNote))
        XCTAssertEqual(mapped.detail.count, 1_024)
        XCTAssertEqual(mapped.budget, raw.budget); XCTAssertEqual(mapped.used, raw.used)
    }

    // One fixture for both identity cases. Literal expected values, never predicted byte strings.
    func testWithinBudgetBothCommandsAllThreeRoutesMatchLiteralsAndBytes() async throws {
        let definition = TypeDefinition(kind: .struct, name: "U", fields: [FieldDef(name: "x", type: "int")])
        let snap = snapshot([small()], definitions: [definition])
        let owner = store(snap)
        let api = WorkspaceScriptingAPI(store: owner)
        var now: UInt64 = 0
        let executor = MCPAttachExecutor(store: owner, api: { WorkspaceScriptingAPI(store: $0) }, now: {
            now += 1_000_000_000; return now
        })
        executor.setConsent(.allowed)
        let types: ScriptValue = .array([.object(["name": .string("U"), "kind": .string("struct"),
            "fields": .array([.object(["name": .string("x"), "type": .string("int")])])])])
        let image: ScriptValue = .object([
            "imageSlot": .int(0), "imageOwner": .string("11111111-2222-3333-4444-555555555555"),
            "total": .int(1), "types": .array([.object([
                "id": .object(["slot": .int(0), "kind": .string("objcClass"), "address": .hex(0x1000)]),
                "imageSlot": .int(0), "kind": .string("objcClass"), "name": .string("C0"),
                "superclass": .null, "members": .array([]), "conformances": .array([]),
                "methods": .array([]), "users": .array([]), "evidence": .string("descriptor")])])])
        for (command, expected) in [("list-types", types), ("list-image-types", image)] {
            // The catalog also appends U; filter it out explicitly on the image command.
            let arguments: ScriptValue = command == "list-image-types"
                ? .object(["kind": .string("objcClass")]) : .object([:])
            let sync = try api.execute(command, arguments: arguments)
            let asynchronous = try await api.executeAsync(command, arguments: arguments)
            let attached = try await executor.execute(command, arguments)
            let expectedBytes = try expected.jsonData()
            for value in [sync, asynchronous, attached] {
                XCTAssertEqual(value, expected)
                XCTAssertEqual(try value.jsonData(), expectedBytes)
            }
            XCTAssertEqual(sync, asynchronous); XCTAssertEqual(sync, attached)
            XCTAssertEqual(try sync.jsonData(), try asynchronous.jsonData())
            XCTAssertEqual(try sync.jsonData(), try attached.jsonData())
        }
    }
}
