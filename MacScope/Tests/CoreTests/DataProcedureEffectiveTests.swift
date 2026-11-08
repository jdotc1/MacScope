import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// VI1C-2: the effective leg of `set-data` / `set-procedures`. Real TinyMachO fixtures and a real
/// `AnalysisEngine`, so every structural write re-runs analysis. TinyMachO places no `bl` target in
/// this blob (one `b`, two `ret`), so no call-xref case is built; nothing here fakes engine output.
/// AUTHORED, run once by the lane.
@MainActor
final class DataProcedureEffectiveTests: XCTestCase {
    private static let code = Data([
        0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
        0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6
    ])
    private let other = ImageSlot(rawValue: 1)
    private struct Fixture {
        let store: WorkspaceStore
        let binary: URL
        let base: UInt64
        func address(_ index: Int) -> UInt64 { base + UInt64(index * 4) }
    }
    private let commands: [(name: String, field: String, procedures: Bool)] = [
        ("set-data", "isData", false), ("set-procedures", "isProcedure", true)]

    private func fixture(twoSlots: Bool = false) throws -> Fixture {
        let macho = TinyMachO.make(code: Self.code)
        let binary = try macho.write()
        addTeardownBlock { try? FileManager.default.removeItem(at: binary.deletingLastPathComponent()) }
        let engine = AnalysisEngine()
        let store = WorkspaceStore(workspaceName: "dp-effective", snapshot: try engine.analyze(url: binary),
                                   engine: engine, autosaveScheduler: nil)
        if twoSlots { store.snapshot.analysisBySlot[other] = store.snapshot.analysisBySlot[.primary] }
        return Fixture(store: store, binary: binary, base: macho.baseAddress)
    }

    private func entries(_ f: Fixture, _ index: Int, _ field: String, _ value: Bool?) -> ScriptValue {
        var row: [String: ScriptValue] = ["address": .hex(f.address(index))]
        if let value { row[field] = .bool(value) }
        return .object(["entries": .array([.object(row)])])
    }

    private func starts(_ store: WorkspaceStore, _ slot: ImageSlot = .primary) -> Set<UInt64> {
        Set((store.snapshot.analysis(in: slot)?.functions ?? []).map(\.startAddress))
    }

    private func history(_ manager: UndoManager) -> [String: ScriptValue] {
        ["canUndo": .bool(manager.canUndo), "canRedo": .bool(manager.canRedo),
         "undo": .string(manager.undoActionName), "redo": .string(manager.redoActionName),
         "groups": .int(Int64(manager.groupingLevel)), "event": .bool(manager.groupsByEvent),
         "enabled": .bool(manager.isUndoRegistrationEnabled)]
    }

    private struct Authored: Equatable {
        var overrides: [ImageAddress: AddressOverride]
        var bookmarks: [Bookmark]
        var types: [TypeDefinition]
        var xrefs: [ManualXRef]
        var segments: [SegmentOverride]
        init(_ s: WorkspaceSnapshot) {
            overrides = s.addressOverrides; bookmarks = s.bookmarks; types = s.typeDefinitions
            xrefs = s.manualXRefs; segments = s.segmentOverrides
        }
    }

    // 1 + S-9 + S-10. A procedure mark at a realizable address: the start exists after
    // reanalysis; collateral is disclosed with counts that match the real before/after
    // snapshots; and, in a two-slot store, the other slot's starts are untouched.
    func testProcedureMarkVerifiesDisclosesCollateralAndKeepsOtherSlotStarts() throws {
        let f = try fixture(twoSlots: true)
        let target = f.address(4)
        let beforeFunctions = f.store.snapshot.analysis(in: .primary)?.functions.count
        let beforeOther = starts(f.store, other)
        XCTAssertFalse(beforeOther.isEmpty)
        let result = try WorkspaceScriptingAPI(store: f.store).execute(
            "set-procedures", arguments: entries(f, 4, "isProcedure", true))
        let effective = try XCTUnwrap(result["effective"])
        XCTAssertEqual(effective["status"], .string("verified"))
        XCTAssertEqual(effective["checked"], .int(1))
        XCTAssertEqual(effective["mismatches"], .int(0))
        XCTAssertEqual(result["verification"], .string("full-state-equal"))
        XCTAssertEqual(result["observed"], result["requested"])
        XCTAssertTrue(starts(f.store).contains(target))
        XCTAssertEqual(starts(f.store, other), beforeOther)
        let collateral = try XCTUnwrap(effective["collateral"])
        XCTAssertEqual(collateral["functionCountBefore"], .int(Int64(beforeFunctions ?? -1)))
        XCTAssertEqual(collateral["functionCountAfter"],
                       .int(Int64(f.store.snapshot.analysis(in: .primary)?.functions.count ?? -2)))
        for key in ["functionStartsAdded", "functionStartsRemoved", "functionEndsMoved"] {
            XCTAssertNotNil(collateral[key], key)
        }
        // The target itself is never reported as collateral.
        XCTAssertFalse((collateral["functionStartsAdded"]?["sample"]?.arrayValue ?? []).contains(.hex(target)))
        XCTAssertNil(collateral["xrefClause"], "procedure marks have no xref clause")
    }

    // 2 + S-7 (disclosure only). A data mark at a function start: no start remains, the address is
    // code-excluded, and edges or xrefs from it (if the engine kept any) are listed as unconfirmed
    // collateral, never as a failure.
    func testDataMarkAtFunctionStartVerifiesAndDisclosesXrefClause() throws {
        let f = try fixture()
        let start = try XCTUnwrap(f.store.snapshot.analysis(in: .primary)?.functions.first?.startAddress)
        let result = try WorkspaceScriptingAPI(store: f.store).execute(
            "set-data", arguments: .object(["entries": .array([.object(["address": .hex(start)])])]))
        let effective = try XCTUnwrap(result["effective"])
        XCTAssertEqual(effective["status"], .string("verified"))
        XCTAssertEqual(effective["mismatches"], .int(0))
        XCTAssertEqual(result["verification"], .string("full-state-equal"))
        XCTAssertFalse(starts(f.store).contains(start))
        XCTAssertTrue(f.store.snapshot.codeExcludedAddresses(in: .primary).contains(start))
        XCTAssertTrue(effective["disclosure"]?.stringValue?.contains("never gate") ?? false)
        let collateral = try XCTUnwrap(effective["collateral"])
        XCTAssertEqual(collateral["xrefClause"], .string("unconfirmed"))
        let post = try XCTUnwrap(f.store.snapshot.analysis(in: .primary))
        let leftover = post.controlFlowEdges.filter { $0.from == start }.count + post.xrefs.filter { $0.from == start }.count
        XCTAssertEqual(collateral["fromTargets"]?["count"], .int(leftover > 0 ? 1 : 0))
        if leftover > 0 {
            XCTAssertEqual(collateral["fromTargets"]?["sample"]?.arrayValue?.first?["xrefClause"], .string("unconfirmed"))
        }
        // The lost start is the target, so it is not listed as collateral.
        XCTAssertFalse((collateral["functionStartsRemoved"]?["sample"]?.arrayValue ?? []).contains(.hex(start)))
    }

    // 3. Q1 (a): a procedure mark on an address that is already data is unrealizable. The write is
    // kept, nothing rolls back, and the reply does not claim full-state equality.
    func testProcedureMarkOnDataAddressIsUnrealizableAndKept() throws {
        let f = try fixture()
        let api = WorkspaceScriptingAPI(store: f.store)
        _ = try api.execute("set-data", arguments: entries(f, 4, "isData", true))
        let result = try api.execute("set-procedures", arguments: entries(f, 4, "isProcedure", true))
        let effective = try XCTUnwrap(result["effective"])
        XCTAssertEqual(effective["status"], .string("unrealizable"))
        let rows = try XCTUnwrap(effective["unrealizable"]?["sample"]?.arrayValue)
        XCTAssertEqual(rows.first?["address"], .hex(f.address(4)))
        XCTAssertEqual(rows.first?["reason"], .string("data-or-undefined"))
        XCTAssertEqual(result["verification"], .string("override-equal"))
        XCTAssertEqual(result["observed"], result["requested"])
        XCTAssertEqual(f.store.snapshot.addressOverrides[.primary(f.address(4))]?.markAsProcedure, true)
        XCTAssertFalse(starts(f.store).contains(f.address(4)))
    }

    // 4. Clears never assert the absence of a start; the start state is information only.
    func testClearsAreCleared() throws {
        let f = try fixture()
        let api = WorkspaceScriptingAPI(store: f.store)
        let entry = try XCTUnwrap(f.store.snapshot.analysis(in: .primary)?.functions.first?.startAddress)
        let entryArguments: ScriptValue = .object(["entries": .array([.object(["address": .hex(entry), "isProcedure": .bool(false)])])])
        _ = try api.execute("set-procedures", arguments: .object(["entries": .array([.object(["address": .hex(entry)])])]))
        let cleared = try api.execute("set-procedures", arguments: entryArguments)
        let effective = try XCTUnwrap(cleared["effective"])
        XCTAssertEqual(effective["status"], .string("cleared"))
        XCTAssertEqual(cleared["verification"], .string("full-state-equal"))
        let row = try XCTUnwrap(effective["clears"]?["sample"]?.arrayValue?.first)
        XCTAssertEqual(row["startsHere"], .bool(starts(f.store).contains(entry)))
        XCTAssertNil(effective["unrealizable"])
        // Data cleared: the raw leg gates and the exclusion check holds.
        _ = try api.execute("set-data", arguments: entries(f, 4, "isData", true))
        let code = try api.execute("set-data", arguments: entries(f, 4, "isData", false))
        XCTAssertEqual(code["effective"]?["status"], .string("cleared"))
        XCTAssertEqual(code["verification"], .string("full-state-equal"))
        XCTAssertFalse(f.store.snapshot.codeExcludedAddresses(in: .primary).contains(f.address(4)))
    }

    // 5. REQUIRED. An injected effective mismatch leaves the workspace unchanged by content and
    // names the effective stage and leg.
    func testInjectedEffectiveMismatchLeavesWorkspaceUnchanged() throws {
        for (name, field, _) in commands {
            let f = try fixture()
            let store = f.store
            let api = WorkspaceScriptingAPI(store: store)
            _ = try api.execute("rename", arguments: .object(["address": .hex(f.address(0)), "name": .string("early")]))
            let manager = store.undoManager
            let beforeAuthored = Authored(store.snapshot)
            let beforeWitness = ScriptingWriteReadback.AnalysisWitness.capture(store.snapshot)
            XCTAssertTrue(beforeWitness.complete, name)
            let beforeHistory = history(manager)
            let capture = ScriptingBatchReceiptCapture()
            let injected: @Sendable (String, ScriptValue) throws -> ScriptValue = { @Sendable _, _ in .null }
            XCTAssertThrowsError(try ScriptingBatchReceiptCapture.$current.withValue(capture) {
                try ScriptingWriteReadbackInjection.$observeEffective.withValue(injected) {
                    try api.execute(name, arguments: entries(f, 4, field, true))
                }
            }, name) { error in
                guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                let reply = failure.reply
                XCTAssertEqual(reply["error"], .string("writeReadbackFailed"), name)
                XCTAssertEqual(reply["stage"], .string("effective"), name)
                XCTAssertEqual(reply["leg"], .string("effective"), name)
                XCTAssertEqual(reply["rollbackStatus"], .string("restored-verified"), name)
                XCTAssertEqual(reply["rollbackIdentity"], .string("generation-advanced"), name)
                XCTAssertEqual(reply["rolledBack"], .bool(true), name)
                XCTAssertEqual(reply["effective"]?["status"], .string("mismatch"), name)
                XCTAssertNotNil(reply["requested"], name)
                XCTAssertNotNil(reply["observed"], name)
            }
            XCTAssertEqual(Authored(store.snapshot), beforeAuthored, name)
            XCTAssertEqual(ScriptingWriteReadback.AnalysisWitness.capture(store.snapshot), beforeWitness, name)
            XCTAssertEqual(history(manager), beforeHistory, name)
            XCTAssertNil(store.hostUndoManager, name)
            XCTAssertNil(capture.receipt, name)
        }
    }

    // 6. Q2 (a): reanalysis cannot run (bytes and binary gone). The override stays applied, the
    // effective leg is unobserved with the reason, and nothing throws or rolls back.
    func testReanalysisNotCompletedIsUnobservedWithoutRollback() throws {
        for (name, field, procedures) in commands {
            let f = try fixture()
            f.store.snapshot.analysisBySlot[.primary]?.imageBytes = Data()
            try FileManager.default.removeItem(at: f.binary)
            let result = try WorkspaceScriptingAPI(store: f.store).execute(name, arguments: entries(f, 4, field, true))
            XCTAssertEqual(result["reanalysisStatus"], .string("not-completed"), name)
            let effective = try XCTUnwrap(result["effective"], name)
            XCTAssertEqual(effective["status"], .string("unobserved"), name)
            XCTAssertFalse((effective["reason"]?.stringValue ?? "").isEmpty, name)
            XCTAssertEqual(result["verification"], .string("override-equal"), name)
            XCTAssertEqual(result["observed"], result["requested"], name)
            let stored = f.store.snapshot.addressOverrides[.primary(f.address(4))]
            XCTAssertEqual(procedures ? stored?.markAsProcedure : stored?.isData, true, name)
        }
    }

    // 7. The effective reader reads the post-write analysis, not the handler result: a handler that
    // reports "completed" while the analysis lacks the start is caught.
    func testStaleAnalysisBehindACompletedReplyIsCaught() throws {
        for (name, _, procedures) in commands {
            let f = try fixture()
            let store = f.store
            let target = f.address(4)
            let before = Authored(store.snapshot)
            let tamper = {
                if procedures {
                    // Stale: the forced start never made it into the analysis.
                    store.snapshot.analysisBySlot[.primary]?.functions.removeAll { $0.startAddress == target }
                } else {
                    // Stale: a function still starts at the data-marked address.
                    store.snapshot.analysisBySlot[.primary]?.functions.append(FunctionSummary(
                        id: UUID(), name: "stale", startAddress: target, endAddress: target + 4, confidence: 1))
                }
            }
            XCTAssertThrowsError(try ScriptingWriteReadback.overrideBatch(
                command: name, store: store, slot: .primary,
                expected: [(target, ScriptValue.bool(true))],
                project: { .bool(procedures ? $0.markAsProcedure : $0.isData) },
                flagIsolation: procedures) {
                    _ = store.setDataProcedureBatch([(address: target, value: true)], in: .primary, procedures: procedures)
                    tamper()
                    return .object(["ok": .bool(true), "reanalysisStatus": .string("completed")])
                }, name) { error in
                guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                XCTAssertEqual(failure.reply["stage"], .string("effective"), name)
                XCTAssertEqual(failure.reply["leg"], .string("effective"), name)
                XCTAssertEqual(failure.reply["effective"]?["readback"]?["mismatchCount"], .int(1), name)
            }
            XCTAssertEqual(Authored(store.snapshot), before, name)
            XCTAssertNil(store.hostUndoManager, name)
        }
    }

    // 8. S-10 gate: a primary-slot write that moves another slot's function starts is a mismatch.
    func testOtherSlotFunctionStartChangeIsAMismatch() throws {
        let f = try fixture(twoSlots: true)
        let store = f.store
        let target = f.address(4)
        let before = Authored(store.snapshot)
        XCTAssertFalse(starts(store, other).isEmpty)
        XCTAssertThrowsError(try ScriptingWriteReadback.overrideBatch(
            command: "set-procedures", store: store, slot: .primary,
            expected: [(target, ScriptValue.bool(true))],
            project: { .bool($0.markAsProcedure) },
            flagIsolation: true) {
                _ = store.setDataProcedureBatch([(address: target, value: true)], in: .primary, procedures: true)
                store.snapshot.analysisBySlot[self.other]?.functions.removeAll()
                return .object(["ok": .bool(true), "reanalysisStatus": .string("completed")])
            }) { error in
            guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
            XCTAssertEqual(failure.reply["stage"], .string("effective"))
            XCTAssertEqual(failure.reply["leg"], .string("effective"))
            XCTAssertEqual(failure.reply["effective"]?["crossSlotMismatches"], .array([.int(1)]))
            XCTAssertNotNil(failure.reply["rollbackStatus"])
        }
        XCTAssertEqual(Authored(store.snapshot), before)
    }
}
