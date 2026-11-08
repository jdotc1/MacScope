import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// VI1C-1: the isolation clause, the analysis-content rollback witness and `rollbackStatus` for
/// `set-data` / `set-procedures`. Real TinyMachO fixtures and a real `AnalysisEngine`, so every
/// structural write re-runs analysis, and so does the rollback. AUTHORED, run once by the lane.
@MainActor
final class DataProcedureReadbackTests: XCTestCase {
    private static let code = Data([
        0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
        0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6
    ])
    private enum Injected: Error { case failure }
    private struct Fixture {
        let store: WorkspaceStore
        let binary: URL
        let scratch: URL
        let base: UInt64
        func address(_ index: Int) -> UInt64 { base + UInt64(index * 4) }
        var journal: URL { scratch.appendingPathComponent("edits.journal") }
    }
    private let commands: [(name: String, field: String, procedures: Bool)] = [
        ("set-data", "isData", false), ("set-procedures", "isProcedure", true)]

    private func fixture() throws -> Fixture {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("dp-readback-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        let macho = TinyMachO.make(code: Self.code)
        let binary = try macho.write()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: scratch)
            try? FileManager.default.removeItem(at: binary.deletingLastPathComponent())
        }
        let engine = AnalysisEngine()
        let store = WorkspaceStore(workspaceName: "dp", snapshot: try engine.analyze(url: binary),
                                   engine: engine, autosaveScheduler: nil)
        return Fixture(store: store, binary: binary, scratch: scratch, base: macho.baseAddress)
    }

    private func history(_ manager: UndoManager) -> [String: ScriptValue] {
        ["canUndo": .bool(manager.canUndo), "canRedo": .bool(manager.canRedo),
         "undo": .string(manager.undoActionName), "redo": .string(manager.redoActionName),
         "groups": .int(Int64(manager.groupingLevel)), "event": .bool(manager.groupsByEvent),
         "enabled": .bool(manager.isUndoRegistrationEnabled)]
    }

    private func entries(_ f: Fixture, _ items: [(Int, Bool?, String)], field: String) -> ScriptValue {
        .object(["entries": .array(items.map { index, value, _ in
            var row: [String: ScriptValue] = ["address": .hex(f.address(index))]
            if let value { row[field] = .bool(value) }
            return .object(row)
        })])
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

    // 1. Success payloads match the #291 contract; a target that already has a dataShape reads
    //    its RAW flag (false), not the shape-aware `isData(at:in:)`.
    func testSuccessPayloadsKeepTheBatchReadbackContract() throws {
        let legacy: Set<String> = ["ok", "committed", "count", "changed", "imageSlot", "reanalysisStatus"]
        let additive: Set<String> = ["requested", "observed", "verification", "readback", "effective"]
        for (name, field, procedures) in commands {
            for value in [true, false] {
                let f = try fixture()
                let api = WorkspaceScriptingAPI(store: f.store)
                _ = try api.execute("make-strings", arguments: .object(["entries": .array([
                    .object(["address": .hex(f.address(1))])])]))
                XCTAssertNotNil(f.store.snapshot.analysis(in: .primary)?.analysisInputFingerprint, name)
                // The shape makes the shape-aware reader report data at address 1.
                XCTAssertTrue(f.store.snapshot.isData(at: f.address(1), in: .primary), name)
                let result = try api.execute(name, arguments: entries(f, [(1, value, ""), (2, value, "")], field: field))
                guard case .object(let fields) = result else { return XCTFail(name) }
                XCTAssertEqual(Set(fields.keys), legacy.union(additive), name)
                XCTAssertEqual(fields["ok"], .bool(true), name)
                XCTAssertEqual(fields["count"], .int(2), name)
                XCTAssertEqual(fields["observed"], fields["requested"], name)
                // Address 1 carries a data shape, so a procedure mark there is genuinely
                // unrealizable (VI1C-2, Q1 (a)): the raw leg is equal, the claim is override-equal.
                let unrealizable = procedures && value
                XCTAssertEqual(fields["verification"], .string(unrealizable ? "override-equal" : "full-state-equal"), name)
                if unrealizable { XCTAssertEqual(fields["effective"]?["status"], .string("unrealizable"), name) }
                XCTAssertNil(fields["generation"], name)
                XCTAssertEqual(fields["readback"]?["mismatchCount"], .int(0), name)
                let rows = try XCTUnwrap(fields["observed"]?["sample"]?.arrayValue, name)
                XCTAssertEqual(rows.map { $0["value"] }, [.bool(value), .bool(value)], name)
                let stored = f.store.snapshot.addressOverrides[.primary(f.address(1))]
                XCTAssertEqual(procedures ? stored?.markAsProcedure : stored?.isData, value, name)
                XCTAssertNotNil(stored?.dataShape, name)
            }
        }
    }

    // 2. REQUIRED. An injected mismatch (compare) or read failure (readback) leaves the workspace
    //    unchanged by CONTENT, and says so honestly.
    func testInjectedFailureLeavesWorkspaceUnchangedByContent() throws {
        for (name, field, _) in commands {
            for stage in ["compare", "readback"] {
                let label = "\(name)/\(stage)"
                let f = try fixture()
                let store = f.store
                try store.attachEditJournal(at: f.journal)
                let api = WorkspaceScriptingAPI(store: store)
                _ = try api.execute("rename", arguments: .object(["address": .hex(f.address(0)), "name": .string("early")]))
                let manager = store.undoManager
                let beforeAuthored = Authored(store.snapshot)
                let beforeWitness = ScriptingWriteReadback.AnalysisWitness.capture(store.snapshot)
                XCTAssertTrue(beforeWitness.complete, "facets must exist for TinyMachO stores: \(label)")
                XCTAssertFalse(beforeWitness.slots.isEmpty, label)
                let beforeFacets = store.snapshot.analysis(in: .primary)?.analysisInputFingerprint?.facets
                let beforeHistory = history(manager)
                let beforeGeneration = store.snapshot.analysisGenerationID
                let beforeSequence = try XCTUnwrap(store.editJournal?.sequence)
                let capture = ScriptingBatchReceiptCapture()
                let injected: @Sendable (String, ScriptValue) throws -> ScriptValue
                if stage == "compare" {
                    injected = { @Sendable _, _ in .null }
                } else {
                    injected = { @Sendable _, _ in throw Injected.failure }
                }
                XCTAssertThrowsError(try ScriptingBatchReceiptCapture.$current.withValue(capture) {
                    try ScriptingWriteReadbackInjection.$observe.withValue(injected) {
                        try api.execute(name, arguments: entries(f, [(1, true, ""), (3, true, "")], field: field))
                    }
                }, label) { error in
                    guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                    let reply = failure.reply
                    XCTAssertEqual(reply["error"], .string("writeReadbackFailed"), label)
                    XCTAssertEqual(reply["stage"], .string(stage), label)
                    XCTAssertEqual(reply["leg"], .string("raw"), label)
                    XCTAssertEqual(reply["rollbackStatus"], .string("restored-verified"), label)
                    XCTAssertEqual(reply["rollbackIdentity"], .string("generation-advanced"), label)
                    XCTAssertEqual(reply["rolledBack"], .bool(true), label)
                    XCTAssertNotNil(reply["requested"], label)
                    XCTAssertNotNil(reply["observed"], label)
                    XCTAssertNotNil(reply["recovery"]?.stringValue, label)
                }
                // Equal by content.
                XCTAssertEqual(Authored(store.snapshot), beforeAuthored, label)
                XCTAssertEqual(ScriptingWriteReadback.AnalysisWitness.capture(store.snapshot), beforeWitness, label)
                XCTAssertEqual(store.snapshot.analysis(in: .primary)?.analysisInputFingerprint?.facets, beforeFacets, label)
                XCTAssertTrue(manager === store.undoManager, label)
                XCTAssertEqual(history(manager), beforeHistory, label)
                XCTAssertNil(store.hostUndoManager, label)
                XCTAssertNil(capture.receipt, label)
                // Expected non-equalities: identity moved, the append-only journal is not rewound.
                XCTAssertNotEqual(store.snapshot.analysisGenerationID, beforeGeneration, label)
                XCTAssertGreaterThan(try XCTUnwrap(store.editJournal?.sequence), beforeSequence, label)
                // The earlier unrelated step is still the one undo step, and redo still works.
                manager.undo()
                XCTAssertNil(store.snapshot.addressOverrides[.primary(f.address(0))]?.customName, label)
                XCTAssertTrue(manager.canRedo, label)
                manager.redo()
                XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.customName, "early", label)
            }
        }
    }

    // 3. The second analysis cannot run (captured bytes gone and the binary removed, done from the
    //    request-local seam after the forward pass): overrides come back, analysis does not.
    func testRollbackWhoseReanalysisCannotRunIsOverridesOnly() throws {
        for (name, field, _) in commands {
            let f = try fixture()
            let store = f.store
            let before = Authored(store.snapshot)
            let binary = f.binary
            let manager = store.undoManager
            let beforeHistory = history(manager)
            let tamper: @Sendable (String, ScriptValue) throws -> ScriptValue = { @Sendable _, _ in
                MainActor.assumeIsolated {
                    store.snapshot.analysisBySlot[.primary]?.imageBytes = Data()
                    // Post-write analysis that rollback cannot re-derive: a marker block.
                    store.snapshot.analysisBySlot[.primary]?.basicBlocks.append(BasicBlockSummary(
                        id: UUID(), functionID: UUID(), startAddress: 1, endAddress: 2, instructionCount: 1))
                    try? FileManager.default.removeItem(at: binary)
                }
                return .null
            }
            XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue(tamper) {
                try WorkspaceScriptingAPI(store: store).execute(name, arguments: entries(f, [(1, true, "")], field: field))
            }, name) { error in
                guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                let reply = failure.reply
                XCTAssertEqual(reply["stage"], .string("compare"), name)
                XCTAssertEqual(reply["rollbackStatus"], .string("restored-overrides-only"), name)
                XCTAssertEqual(reply["rolledBack"], .bool(false), name)
                XCTAssertFalse(failure.rolledBack, name)
                XCTAssertEqual(reply["leg"], .string("raw"), name)
                XCTAssertEqual(reply["rollbackIdentity"], .string("generation-advanced"), name)
                let hint = reply["recovery"]?.stringValue ?? ""
                XCTAssertTrue(hint.contains("open-workspace"), name)
                XCTAssertTrue(hint.contains("unsaved edits are lost"), name)
            }
            XCTAssertEqual(Authored(store.snapshot), before, name)
            XCTAssertEqual(history(manager), beforeHistory, name)
            XCTAssertNil(store.hostUndoManager, name)
        }
    }

    // 4. A repeat that changes nothing never undoes an earlier step.
    func testIdempotentRepeatNeverUndoesEarlierStep() throws {
        for (name, field, procedures) in commands {
            let f = try fixture()
            let api = WorkspaceScriptingAPI(store: f.store)
            let args = entries(f, [(1, true, "")], field: field)
            let first = try api.execute(name, arguments: args)
            XCTAssertEqual(first["changed"], .int(1), name)
            let manager = f.store.undoManager
            let beforeHistory = history(manager)
            let beforeOverrides = f.store.snapshot.addressOverrides
            let repeated = try api.execute(name, arguments: args)
            XCTAssertEqual(repeated["changed"], .int(0), name)
            XCTAssertEqual(repeated["verification"], .string("full-state-equal"), name)
            XCTAssertEqual(history(manager), beforeHistory, name)
            XCTAssertEqual(f.store.snapshot.addressOverrides, beforeOverrides, name)
            manager.undo()
            let stored = f.store.snapshot.addressOverrides[.primary(f.address(1))]
            XCTAssertEqual(procedures ? stored?.markAsProcedure ?? false : stored?.isData ?? false, false, name)
        }
    }

    // 5. Isolation clause: a write that also edits another key, or another field of a named key,
    //    fails at compare and is restored.
    func testIsolationClauseRejectsCollateralOverrideEdits() throws {
        for (name, _, procedures) in commands {
            for variant in ["other-key", "other-field"] {
                let label = "\(name)/\(variant)"
                let f = try fixture()
                let store = f.store
                let api = WorkspaceScriptingAPI(store: store)
                let before = Authored(store.snapshot)
                let manager = store.undoManager
                let beforeHistory = history(manager)
                let target = f.address(1)
                XCTAssertThrowsError(try ScriptingWriteReadback.overrideBatch(
                    command: name, store: store, slot: .primary,
                    expected: [(target, ScriptValue.bool(true))],
                    project: { .bool(procedures ? $0.markAsProcedure : $0.isData) },
                    flagIsolation: procedures) {
                        // `run` reverses ONE undo group. Real handlers make one store call; this
                        // stub makes two, so group them like a single handler step.
                        let pending = try XCTUnwrap(store.hostUndoManager)
                        pending.beginUndoGrouping()
                        defer { pending.endUndoGrouping() }
                        var edits = [(address: target, value: true)]
                        if variant == "other-key" { edits.append((address: f.address(2), value: true)) }
                        _ = store.setDataProcedureBatch(edits, in: .primary, procedures: procedures)
                        if variant == "other-field" {
                            _ = try api.execute("rename", arguments: .object(["address": .hex(target), "name": .string("x")]))
                        }
                        return .object(["ok": .bool(true)])
                    }, label) { error in
                    guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                    XCTAssertEqual(failure.reply["stage"], .string("compare"), label)
                    XCTAssertEqual(failure.reply["rollbackStatus"], .string("restored-verified"), label)
                    XCTAssertEqual(failure.reply["rolledBack"], .bool(true), label)
                    XCTAssertEqual(failure.reply["leg"], .string("raw"), label)
                }
                XCTAssertEqual(Authored(store.snapshot), before, label)
                XCTAssertEqual(history(manager), beforeHistory, label)
                XCTAssertNil(store.hostUndoManager, label)
            }
        }
    }

    // 6. A residual edit that `run` cannot reverse (the stub makes two store calls, so two undo
    //    groups, and `run` reverses one) must never be reported as restored.
    func testRollbackNeverClaimsRestoredWhenAResidualEditRemains() throws {
        for (name, _, procedures) in commands {
            let f = try fixture()
            let store = f.store
            let api = WorkspaceScriptingAPI(store: store)
            let before = Authored(store.snapshot)
            let target = f.address(1)
            XCTAssertThrowsError(try ScriptingWriteReadback.overrideBatch(
                command: name, store: store, slot: .primary,
                expected: [(target, ScriptValue.bool(true))],
                project: { .bool(procedures ? $0.markAsProcedure : $0.isData) },
                flagIsolation: procedures) {
                    _ = store.setDataProcedureBatch([(address: target, value: true)], in: .primary, procedures: procedures)
                    _ = try api.execute("rename", arguments: .object(["address": .hex(target), "name": .string("x")]))
                    return .object(["ok": .bool(true)])
                }, name) { error in
                guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                let reply = failure.reply
                XCTAssertNotEqual(reply["rollbackStatus"], .string("restored-verified"), name)
                XCTAssertNotEqual(reply["rolledBack"], .bool(true), name)
                XCTAssertFalse(failure.rolledBack, name)
                // What it reports must match what is actually there.
                let residual = Authored(store.snapshot) != before
                XCTAssertTrue(residual, name)
                XCTAssertEqual(reply["rollbackStatus"], .string(residual ? "unavailable" : "restored-verified"), name)
                XCTAssertEqual(reply["failedStage"], .string("compare"), name)
                XCTAssertEqual(reply["stage"], .string("rollback"), name)
            }
            let stored = store.snapshot.addressOverrides[.primary(target)]
            XCTAssertEqual(procedures ? stored?.markAsProcedure : stored?.isData, true, name)
        }
    }
    // 7. G6: witnessless structural writers (make-arrays, set-undefined) have no effective leg. When
    //    their synchronous reanalysis cannot run (captured bytes gone, binary removed), the authored
    //    collections still match, so readback used to verify. It must now fail at stage "reanalysis".
    //    This asserts the fixed behavior: before the fix `run` returned success here.
    func testWitnesslessStructuralWriteFailsWhenReanalysisCannotRun() throws {
        for command in ["make-arrays", "set-undefined"] {
            let f = try fixture()
            let store = f.store
            let before = Authored(store.snapshot)
            let manager = store.undoManager
            let beforeHistory = history(manager)
            let target = f.address(1)
            let binary = f.binary
            let expected: ScriptValue
            let project: (AddressOverride) -> ScriptValue
            if command == "make-arrays" {
                expected = try ScriptingWriteReadback.dataShape(
                    DataShapeOverride(kind: .array, elementType: nil, elementCount: 2, elementDisplayFormat: nil))
                project = { (try? ScriptingWriteReadback.dataShape($0.dataShape)) ?? .null }
            } else {
                expected = .bool(true)
                project = { .bool($0.isUndefined) }
            }
            XCTAssertThrowsError(try store.withSynchronousReanalysis {
                try ScriptingWriteReadback.overrideBatch(
                    command: command, store: store, slot: .primary,
                    expected: [(target, expected)], project: project) {
                    store.snapshot.analysisBySlot[.primary]?.imageBytes = Data()
                    try? FileManager.default.removeItem(at: binary)
                    let result = command == "make-arrays"
                        ? store.makeArraysBatch([(address: target, elementType: nil, count: 2, format: nil)], in: .primary)
                        : store.setUndefinedBatch([(address: target, value: true)], in: .primary)
                    return .object(["ok": .bool(true), "changed": .int(Int64(result.changed)),
                                    "reanalysisStatus": .string(result.reanalysisStatus)])
                }
            }, command) { error in
                guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                let reply = failure.reply
                XCTAssertEqual(reply["error"], .string("writeReadbackFailed"), command)
                XCTAssertEqual(reply["stage"], .string("reanalysis"), command)
                XCTAssertNotNil(reply["detail"]?.stringValue, command)
                XCTAssertNil(reply["verification"], command)
            }
            XCTAssertEqual(Authored(store.snapshot), before, command)
            XCTAssertEqual(history(manager), beforeHistory, command)
            XCTAssertNil(store.hostUndoManager, command)
        }
    }
}
