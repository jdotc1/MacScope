import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// VI1-B: per-item readback with all-or-nothing rollback for the R4 batch-edit tools that
/// #272 left without it. The mismatch seam is #272's `ScriptingWriteReadbackInjection`.
@MainActor
final class VI1BatchReadbackTests: XCTestCase {
    private static let code = Data([
        0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
        0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6
    ])

    private func fixtureStore() throws -> (store: WorkspaceStore, base: UInt64) {
        let fixture = TinyMachO.make(code: Self.code)
        let url = try fixture.write()
        addTeardownBlock { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let engine = AnalysisEngine()
        return (WorkspaceStore(workspaceName: "vi1b", snapshot: try engine.analyze(url: url),
                               engine: engine, autosaveScheduler: nil), fixture.baseAddress)
    }

    private func segmentStore() -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.sections = [SectionSummary(id: UUID(), name: "one", address: 0x1000, size: 4, fileOffset: 0, isExecutable: true),
                             SectionSummary(id: UUID(), name: "two", address: 0x2000, size: 4, fileOffset: 4, isExecutable: false)]
        return WorkspaceStore(workspaceName: "vi1b-segments",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private struct Case {
        var command: String
        var legacy: Set<String>
        var segments = false
        var seed: (command: String, entries: ScriptValue)?
        var entries: ScriptValue
    }

    private static let plain: Set<String> = ["ok", "count", "changed"]
    private static let structural: Set<String> = ["ok", "committed", "count", "changed", "imageSlot", "reanalysisStatus"]
    private static let edits: Set<String> = ["ok", "committed", "count", "changed", "imageSlot"]
    private static let additive: Set<String> = ["requested", "observed", "verification", "readback"]

    private func cases(_ b: UInt64) -> [Case] {
        func rows(_ fields: [[String: ScriptValue]]) -> ScriptValue {
            .array(fields.map { ScriptValue.object($0) })
        }
        func a(_ delta: UInt64) -> ScriptValue { .hex(b + delta) }
        return [
            Case(command: "set-names", legacy: Self.plain, entries: rows([
                ["address": a(4), "name": .string(" n0 ")], ["address": a(8), "name": .string("n1")]])),
            Case(command: "set-comments", legacy: Self.plain, entries: rows([
                ["address": a(4), "comment": .string("c0")], ["address": a(8), "comment": .string(" c1 ")]])),
            Case(command: "set-operand-formats", legacy: Self.plain, entries: rows([
                ["address": a(4), "format": .string("hex")], ["address": a(8), "format": .string("decimal")]])),
            Case(command: "set-tags", legacy: Self.structural, entries: rows([
                ["address": a(4), "tag": .string("parser")], ["address": a(8), "tag": .string(" todo ")]])),
            Case(command: "set-colors", legacy: Self.structural, entries: rows([
                ["address": a(4), "color": .string("red")], ["address": a(8), "color": .string("blue")]])),
            Case(command: "set-data", legacy: Self.structural, entries: rows([
                ["address": a(4)], ["address": a(8), "isData": .bool(true)]])),
            Case(command: "set-procedures", legacy: Self.structural, entries: rows([
                ["address": a(4)], ["address": a(8), "isProcedure": .bool(true)]])),
            Case(command: "set-undefined", legacy: Self.structural, entries: rows([
                ["address": a(4)], ["address": a(8), "isUndefined": .bool(true)]])),
            Case(command: "make-arrays", legacy: Self.structural, entries: rows([
                ["address": a(4), "elementType": .string("int32_t"), "count": .int(2)],
                ["address": a(8), "count": .int(3), "format": .string("hex")]])),
            Case(command: "make-strings", legacy: Self.structural, entries: rows([
                ["address": a(4)], ["address": a(8), "length": .int(4)]])),
            Case(command: "make-alignments", legacy: Self.structural, entries: rows([
                ["address": a(4), "boundary": .int(4)], ["address": a(8), "boundary": .int(8)]])),
            Case(command: "rename-registers", legacy: Self.structural, entries: rows([
                ["address": a(0), "register": .string("X19"), "name": .string("first")],
                ["address": a(0), "register": .string("x20"), "name": .string("second")]])),
            Case(command: "clear-register-names", legacy: Self.structural,
                 seed: ("rename-registers", rows([
                    ["address": a(0), "register": .string("x19"), "name": .string("first")],
                    ["address": a(0), "register": .string("x20"), "name": .string("second")]])),
                 entries: rows([["address": a(0), "register": .string("x19")],
                                ["address": a(0), "register": .string("x20")]])),
            Case(command: "set-stack-locals", legacy: Self.structural, entries: rows([
                ["address": a(0), "local": .string("-16:-8"), "name": .string("loc1"), "type": .string("int")],
                ["address": a(0), "local": .string("-8:0"), "name": .string("loc2")]])),
            Case(command: "add-xrefs", legacy: Self.edits, entries: rows([
                ["from": a(0), "to": a(8)], ["from": a(4), "to": a(12), "kind": .string("data")]])),
            Case(command: "suppress-xrefs", legacy: Self.edits, entries: rows([
                ["from": a(0), "to": a(8)], ["from": a(4), "to": a(12), "kind": .string("data")]])),
            Case(command: "rename-segments", legacy: Self.edits, segments: true, entries: rows([
                ["section": .string("one"), "name": .string(" first ")], ["section": .string("two"), "name": .string("second")]])),
            Case(command: "rebase-segments", legacy: Self.edits, segments: true, entries: rows([
                ["section": .string("one"), "delta": .int(16)], ["section": .string("two"), "delta": .int(32)]])),
            Case(command: "clear-segment-overrides", legacy: Self.edits, segments: true,
                 seed: ("rename-segments", rows([["section": .string("one"), "name": .string("first")],
                                                  ["section": .string("two"), "name": .string("second")]])),
                 entries: rows([["section": .string("one")], ["section": .string("two")]])),
        ]
    }

    private func prepared(_ item: Case, base: UInt64, store: WorkspaceStore) throws -> ScriptValue {
        if let seed = item.seed {
            _ = try WorkspaceScriptingAPI(store: store).execute(seed.command, arguments: .object(["entries": seed.entries]))
        }
        return .object(["entries": item.entries])
    }

    private func authored(_ store: WorkspaceStore) -> [String: ScriptValue] {
        let snapshot = store.snapshot
        return ["overrides": .int(Int64(snapshot.addressOverrides.count)),
                "xrefs": .int(Int64(snapshot.manualXRefs.count)),
                "segments": .int(Int64(snapshot.segmentOverrides.count))]
    }

    private func history(_ manager: UndoManager) -> [String: ScriptValue] {
        ["canUndo": .bool(manager.canUndo), "canRedo": .bool(manager.canRedo),
         "undo": .string(manager.undoActionName), "redo": .string(manager.redoActionName),
         "groups": .int(Int64(manager.groupingLevel))]
    }

    private func makeStore(for item: Case) throws -> (WorkspaceStore, UInt64) {
        if item.segments { return (segmentStore(), 0x1000) }
        return try fixtureStore()
    }

    // (a) A clean batch returns observed equal to requested for every item, and (d) the
    // legacy reply keys are all still present with only the readback keys added.
    func testCleanBatchReturnsObservedEqualToRequestedAndKeepsLegacyKeys() throws {
        let (_, probe) = try fixtureStore()
        for item in cases(probe) {
            let (store, base) = try makeStore(for: item)
            let built = cases(base).first { $0.command == item.command }!
            let arguments = try prepared(built, base: base, store: store)
            let result = try WorkspaceScriptingAPI(store: store).execute(item.command, arguments: arguments)
            guard case .object(let fields) = result else { return XCTFail(item.command) }
            let effectiveKey: Set<String> = ["set-data", "set-procedures"].contains(item.command) ? ["effective"] : []
            XCTAssertEqual(Set(fields.keys), item.legacy.union(Self.additive).union(effectiveKey), item.command)
            XCTAssertEqual(fields["ok"], .bool(true), item.command)
            XCTAssertEqual(fields["count"], .int(Int64(built.entries.arrayValue?.count ?? -1)), item.command)
            XCTAssertEqual(fields["observed"], fields["requested"], item.command)
            XCTAssertEqual(fields["verification"], .string("full-state-equal"), item.command)
            let readback = fields["readback"]
            XCTAssertEqual(readback?["items"], .int(Int64(built.entries.arrayValue?.count ?? -1)), item.command)
            XCTAssertEqual(readback?["mismatchCount"], .int(0), item.command)
            XCTAssertEqual(readback?["firstMismatches"], .array([]), item.command)
            XCTAssertEqual(readback?["truncated"], .bool(false), item.command)
            // Each requested row carries its own value; none is a placeholder.
            let rows = try XCTUnwrap(fields["requested"]?["sample"]?.arrayValue, item.command)
            XCTAssertEqual(rows.count, built.entries.arrayValue?.count, item.command)
            for row in rows { XCTAssertNotNil(row["value"], item.command) }
            XCTAssertTrue(store.undoManager.canUndo, item.command)
        }
    }

    // (b) One item forced to mismatch rolls back every item, leaves the undo stack as it
    // was, publishes no receipt, and names the item, the stage and a recovery.
    func testOneMismatchRollsBackWholeBatchAndNamesTheItem() throws {
        let (_, probe) = try fixtureStore()
        for item in cases(probe) {
            let (store, base) = try makeStore(for: item)
            let built = cases(base).first { $0.command == item.command }!
            let arguments = try prepared(built, base: base, store: store)
            let last = (built.entries.arrayValue?.count ?? 1) - 1
            let beforeSnapshot = store.snapshot
            let manager = store.undoManager
            let priorHistory = history(manager), priorAuthored = authored(store)
            let capture = ScriptingBatchReceiptCapture()
            XCTAssertThrowsError(try ScriptingBatchReceiptCapture.$current.withValue(capture) {
                try ScriptingWriteReadbackInjection.$observe.withValue({ _, value in
                    guard case .array(var rows) = value, rows.indices.contains(last),
                          case .object(var row) = rows[last] else { return value }
                    row["value"] = .string("forced-mismatch")
                    rows[last] = .object(row)
                    return .array(rows)
                }) {
                    try WorkspaceScriptingAPI(store: store).execute(item.command, arguments: arguments)
                }
            }, item.command) { error in
                guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                let reply = failure.reply
                XCTAssertEqual(reply["error"], .string("writeReadbackFailed"), item.command)
                XCTAssertEqual(reply["stage"], .string("compare"), item.command)
                XCTAssertEqual(reply["rolledBack"], .bool(true), item.command)
                XCTAssertNotNil(reply["recovery"]?.stringValue, item.command)
                XCTAssertEqual(reply["item"]?["index"], .int(Int64(last)), item.command)
                XCTAssertEqual(reply["readback"]?["mismatchCount"], .int(1), item.command)
                XCTAssertEqual(reply["readback"]?["truncated"], .bool(false), item.command)
                XCTAssertEqual(reply["readback"]?["firstMismatches"]?.arrayValue?.count, 1, item.command)
                XCTAssertEqual(reply["readback"]?["firstMismatches"]?.arrayValue?.first?["observed"]?["value"], .string("forced-mismatch"), item.command)
            }
            XCTAssertEqual(store.snapshot.addressOverrides, beforeSnapshot.addressOverrides, item.command)
            XCTAssertEqual(store.snapshot.manualXRefs, beforeSnapshot.manualXRefs, item.command)
            XCTAssertEqual(store.snapshot.segmentOverrides, beforeSnapshot.segmentOverrides, item.command)
            XCTAssertEqual(authored(store), priorAuthored, item.command)
            XCTAssertTrue(manager === store.undoManager, item.command)
            XCTAssertEqual(history(manager), priorHistory, item.command)
            XCTAssertNil(capture.receipt, item.command)
            XCTAssertNil(store.hostUndoManager, item.command)
        }
    }

    // (c) The reply stays bounded for the largest batch: counts are complete, mismatch
    // detail is capped and marked truncated, and no mismatch is dropped from the count.
    func testReceiptBudgetIsRespectedAndTruncationReportsFullMismatchCount() throws {
        let (store, base) = try fixtureStore()
        let api = WorkspaceScriptingAPI(store: store)
        let arguments: ScriptValue = .object(["entries": .array((0..<1024).map {
            .object(["address": .hex(base + UInt64($0 * 4)), "name": .string("name" + String($0))])
        })])
        let before = store.snapshot.addressOverrides
        let mismatched = Set([3, 7, 11, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1023])
        XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, value in
            guard case .array(var rows) = value else { return value }
            for index in mismatched {
                guard case .object(var row) = rows[index] else { continue }
                row["value"] = .string("forced")
                rows[index] = .object(row)
            }
            return .array(rows)
        }) { try api.execute("set-names", arguments: arguments) }) { error in
            guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
            let readback = failure.reply["readback"]
            XCTAssertEqual(readback?["items"], .int(1024))
            XCTAssertEqual(readback?["mismatchCount"], .int(Int64(mismatched.count)))
            XCTAssertEqual(readback?["firstMismatches"]?.arrayValue?.count, ScriptingWriteReadback.maximumReportedMismatches)
            XCTAssertEqual(readback?["truncated"], .bool(true))
            // The first reported mismatches are the lowest indexes, in order.
            XCTAssertEqual(readback?["firstMismatches"]?.arrayValue?.first?["index"], .int(3))
            XCTAssertEqual(failure.reply["item"]?["index"], .int(3))
            XCTAssertEqual(failure.reply["rolledBack"], .bool(true))
            XCTAssertLessThan((try? failure.reply.jsonData().count) ?? Int.max, 32_768)
        }
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        // The same batch, clean: the success reply is bounded and reports the truncated sample.
        let result = try api.execute("set-names", arguments: arguments)
        XCTAssertEqual(result["readback"]?["items"], .int(1024))
        XCTAssertEqual(result["readback"]?["mismatchCount"], .int(0))
        XCTAssertEqual(result["readback"]?["truncated"], .bool(true))
        XCTAssertEqual(result["requested"]?["count"], .int(1024))
        XCTAssertEqual(result["requested"]?["sample"]?.arrayValue?.count, 16)
        XCTAssertEqual(result["observed"], result["requested"])
        XCTAssertLessThan(try result.jsonData().count, 32_768)
    }

    // A read that cannot be compared (not one row per request) counts every item as
    // unconfirmed only when the stage is compare; a thrown read failure reports its stage.
    func testUnreadableObservationRollsBackAndCountsEveryItem() throws {
        let (store, base) = try fixtureStore()
        let arguments: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(base + 4), "comment": .string("a")]),
            .object(["address": .hex(base + 8), "comment": .string("b")])])])
        let before = store.snapshot.addressOverrides
        XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
            try WorkspaceScriptingAPI(store: store).execute("set-comments", arguments: arguments)
        }) { error in
            let reply = (error as? ScriptingWriteReadbackFailure)?.reply
            XCTAssertEqual(reply?["readback"]?["mismatchCount"], .int(2))
            XCTAssertEqual(reply?["rolledBack"], .bool(true))
        }
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        XCTAssertFalse(store.undoManager.canUndo)
    }
}
