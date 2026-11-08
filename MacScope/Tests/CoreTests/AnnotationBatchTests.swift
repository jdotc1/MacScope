import Foundation
import XCTest
@testable import MacScope

@MainActor
final class AnnotationBatchTests: XCTestCase {
    private static let code = Data([
        0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
        0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6
    ])
    private func fixture() throws -> (store: WorkspaceStore, base: UInt64) {
        let fixture = TinyMachO.make(code: Self.code)
        let url = try fixture.write()
        addTeardownBlock { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let engine = AnalysisEngine()
        return (WorkspaceStore(workspaceName: "batch", snapshot: try engine.analyze(url: url),
                               engine: engine, autosaveScheduler: nil), fixture.baseAddress)
    }
    private func entries(_ base: UInt64, count: Int, field: String, prefix: String) -> ScriptValue {
        .array((0..<count).map {
            .object(["address": .hex(base + UInt64($0 * 4)), field: .string(prefix + String($0))])
        })
    }
    private func names(_ store: WorkspaceStore, base: UInt64, count: Int) throws -> [ScriptValue] {
        try (0..<count).map {
            try WorkspaceScriptingAPI(store: store).execute("name-at",
                arguments: .object(["address": .hex(base + UInt64($0 * 4))]))
        }
    }
    private func instructions(_ store: WorkspaceStore, base: UInt64) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute("instructions",
            arguments: .object(["address": .hex(base), "count": .int(5)]))
    }
    private func call(_ store: WorkspaceStore, command: String, entries: ScriptValue) throws -> ScriptValue {
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        return try XCTUnwrap(server.handle(.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(command), "arguments": .object(["entries": entries])])
        ])))
    }

    func testSetNamesIsOneUndoStepAndOneMapWrite() throws {
        let (store, base) = try fixture()
        let pre = try names(store, base: base, count: 3)
        let result = try WorkspaceScriptingAPI(store: store).execute("set-names",
            arguments: .object(["entries": entries(base, count: 3, field: "name", prefix: "name")]))
        // VI1-B: the legacy keys are unchanged; readback keys are additive.
        XCTAssertEqual(result["ok"], .bool(true))
        XCTAssertEqual(result["count"], .int(3))
        XCTAssertEqual(result["changed"], .int(3))
        XCTAssertEqual(result["observed"], result["requested"])
        XCTAssertEqual(result["readback"]?["mismatchCount"], .int(0))
        XCTAssertEqual(try names(store, base: base, count: 3), [.string("name0"), .string("name1"), .string("name2")])
        XCTAssertEqual(store.undoManager.undoActionName, "Rename Names")
        store.undoManager.undo()
        XCTAssertEqual(try names(store, base: base, count: 3), pre)
        XCTAssertFalse(store.undoManager.canUndo)
        store.undoManager.redo()
        XCTAssertEqual(try names(store, base: base, count: 3), [.string("name0"), .string("name1"), .string("name2")])
    }

    func testSetCommentsIsOneUndoStep() throws {
        let (store, base) = try fixture()
        let pre = try instructions(store, base: base)
        let result = try WorkspaceScriptingAPI(store: store).execute("set-comments",
            arguments: .object(["entries": entries(base, count: 3, field: "comment", prefix: "comment")]))
        XCTAssertEqual(result["changed"], .int(3))
        let rows = try XCTUnwrap(instructions(store, base: base).arrayValue)
        for index in 0..<3 {
            let address = ScriptValue.hex(base + UInt64(index * 4))
            let row = try XCTUnwrap(rows.first { $0["address"] == address })
            XCTAssertEqual(row["comment"], .string("comment\(index)"))
        }
        XCTAssertEqual(store.undoManager.undoActionName, "Edit Comments")
        store.undoManager.undo()
        XCTAssertEqual(try instructions(store, base: base), pre)
        XCTAssertFalse(store.undoManager.canUndo)
    }

    func testLocalLabelBatchValidationUndoAndNoOp() throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let rows = entries(base, count: 2, field: "label", prefix: "local")
        let result = try api.execute("set-local-labels", arguments: .object(["entries": rows]))
        XCTAssertEqual(result["changed"], .int(2))
        let committed = store.snapshot.addressOverrides
        let invalid: ScriptValue = .array([
            .object(["address": .hex(base), "label": .string("changed")]),
            .object(["address": .hex(base), "label": .string("duplicate")])
        ])
        XCTAssertThrowsError(try api.execute("set-local-labels", arguments: .object(["entries": invalid])))
        XCTAssertEqual(store.snapshot.addressOverrides, committed)
        XCTAssertEqual(try api.execute("set-local-labels", arguments: .object(["entries": rows]))["changed"], .int(0))
        store.undoManager.undo()
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
        store.undoManager.redo()
        XCTAssertEqual(store.snapshot.addressOverrides, committed)
    }

    func testDirectLocalLabelBatchPreservesSingleSetterTextAdmission() throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let label = String(repeating: "a", count: HeadlessAutomationAuthority.maximumArgumentStringBytes + 1)
        let arguments: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(base), "label": .string(label)])
        ])])
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(command: "set-local-labels", arguments: arguments))
        XCTAssertEqual(try api.execute("set-local-labels", arguments: arguments)["changed"], .int(1))
        XCTAssertEqual(store.snapshot.localLabels(in: store.snapshot.primarySlot)[base], label)
    }

    func testLocalLabelScriptReportsEarlierCompletedBatchOnLaterFailure() throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let script: ScriptValue = .array([
            .object(["command": .string("set-local-labels"), "arguments": .object([
                "entries": entries(base, count: 2, field: "label", prefix: "label")
            ])]),
            .object(["command": .string("set-local-labels"), "arguments": .object([
                "entries": entries(base, count: 2, field: "label", prefix: "label")
            ])]),
            .object(["command": .string("missing-command")])
        ])
        XCTAssertThrowsError(try api.runScript(script)) { error in
            let failure = error as? ScriptingBatchHistoryFailure
            XCTAssertEqual(failure?.receipts.count, 1)
            XCTAssertEqual(failure?.receipts.first?.count, 2)
            XCTAssertEqual(failure?.receipts.first?.changed, 2)
        }
        XCTAssertEqual(store.snapshot.addressOverrides.count, 2)
    }

    func testLocalLabelBatchRejectsUnrepresentableIDBeforeMutation() throws {
        let (store, base) = try fixture()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8))
        let request: ScriptValue = .object([
            "jsonrpc": .string("2.0"), "id": .string(String(repeating: "\\", count: 256)),
            "method": .string("tools/call"), "params": .object([
                "name": .string("set-local-labels"),
                "arguments": .object(["entries": entries(base, count: 1, field: "label", prefix: "label")])
            ])
        ])
        XCTAssertNil(server.handleMessage(try request.jsonData()))
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testBatchHistoryBoundsAndDescribesPastResultsWithoutClaimingCurrentState() throws {
        var history = ScriptingBatchHistory()
        history.record(command: "set-local-labels", count: 2, changed: 2)
        history.record(command: "set-local-labels", count: 2, changed: 0)
        for _ in 0..<128 { history.record(command: "set-local-labels", count: 1, changed: 1) }
        let error = history.failure(ScriptingError.unknownCommand("missing"))
        let failure = try XCTUnwrap(error as? ScriptingBatchHistoryFailure)
        XCTAssertEqual(failure.receipts.count, 128)
        XCTAssertEqual(failure.omitted, 1)
        XCTAssertTrue(failure.localizedDescription.contains("Current state may have changed later"))
    }

    func testBatchHistoryDoesNotClaimAnUndoneEditRemainsApplied() throws {
        let (store, base) = try fixture()
        let script: ScriptValue = .array([
            .object(["command": .string("set-local-labels"), "arguments": .object([
                "entries": entries(base, count: 1, field: "label", prefix: "label")
            ])]),
            .object(["command": .string("undo-last")]),
            .object(["command": .string("missing-command")])
        ])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).runScript(script)) { error in
            let history = error as? ScriptingBatchHistoryFailure
            XCTAssertEqual(history?.receipts.count, 1)
            XCTAssertTrue(error.localizedDescription.contains("Current state may have changed later"))
        }
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testAttachedOperandBatchRequiresGrantAndIsOneUndo() async throws {
        let (store, base) = try fixture()
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        let arguments: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(base), "format": .string("hex")])
        ])])
        do {
            _ = try await executor.execute("set-operand-formats", arguments)
            XCTFail("expected consent refusal")
        } catch { XCTAssertTrue(store.snapshot.addressOverrides.isEmpty) }
        executor.setConsent(.allowed)
        let result = try await executor.execute("set-operand-formats", arguments)
        XCTAssertEqual(result["changed"], .int(1))
        store.undoManager.undo()
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testAttachedLocalLabelBatchRequiresGrantAndIsOneUndo() async throws {
        let (store, base) = try fixture()
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        let arguments: ScriptValue = .object(["entries": entries(base, count: 2, field: "label", prefix: "label")])
        do {
            _ = try await executor.execute("set-local-labels", arguments)
            XCTFail("expected consent refusal")
        } catch { XCTAssertTrue(store.snapshot.addressOverrides.isEmpty) }
        executor.setConsent(.allowed)
        let result = try await executor.execute("set-local-labels", arguments)
        XCTAssertEqual(result["changed"], .int(2))
        store.undoManager.undo()
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testAsyncLocalLabelBatchRejectsOversizedIDBeforeMutation() async throws {
        let (store, base) = try fixture()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store), configuration: .init(
            maximumInputBytes: 4096, maximumOutputBytes: 512,
            maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8))
        let request: ScriptValue = .object([
            "jsonrpc": .string("2.0"), "id": .string(String(repeating: "\\", count: 256)),
            "method": .string("tools/call"), "params": .object([
                "name": .string("set-local-labels"),
                "arguments": .object(["entries": entries(base, count: 1, field: "label", prefix: "label")])
            ])
        ])
        let response = await server.handleMessageAsync(try request.jsonData())
        XCTAssertNil(response)
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testLocalLabelReceiptAdmissionUsesOriginalNumericID() async throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let id = "1e" + String(repeating: "0", count: 200)
        let body = "{\"jsonrpc\":\"2.0\",\"id\":\(id),\"method\":\"tools/call\",\"params\":{\"name\":\"set-local-labels\",\"arguments\":{\"entries\":[{\"address\":\"0x\(String(base, radix: 16))\",\"label\":\"x\"}]}}}"
        func server() -> MCPServer {
            MCPServer(api: api, configuration: .init(maximumInputBytes: 4096, maximumOutputBytes: 512,
                maximumToolDurationNanoseconds: 5_000_000_000, maximumRememberedCancellations: 8))
        }
        let sync = try XCTUnwrap(server().handleMessage(Data(body.utf8)))
        let asyncResponse = await server().handleMessageAsync(Data(body.utf8))
        let asyncData = try XCTUnwrap(asyncResponse)
        for data in [sync, asyncData] {
            let parsed = try Phase2StrictJSONParser().parse(data, limits: .providerEnvelope)
            XCTAssertEqual(parsed.objectValue?["id"], .number(id))
            XCTAssertEqual(parsed.objectValue?["error"]?.objectValue?["code"], .integer(-32602))
        }
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
    }

    func testOperandFormatBatchValidatesBeforeMutationAndUndoesOnce() throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let row: (UInt64, String) -> ScriptValue = { .object(["address": .hex($0), "format": .string($1)]) }
        let invalid: ScriptValue = .object(["entries": .array([row(base, "hex"), row(base + 4, "bad-format")])])
        XCTAssertThrowsError(try api.execute("set-operand-formats", arguments: invalid))
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: "set-operand-formats", arguments: invalid))
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
        let entries: ScriptValue = .array([row(base, "hex"), row(base + 4, "decimal")])
        let result = try api.execute("set-operand-formats", arguments: .object(["entries": entries]))
        XCTAssertEqual(result["changed"], .int(2))
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: store.snapshot.primarySlot, address: base)]?.operandFormat, .hex)
        store.undoManager.undo()
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
        store.undoManager.redo()
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: store.snapshot.primarySlot, address: base)]?.operandFormat, .hex)
        let clear = try api.execute("set-operand-formats", arguments: .object(["entries": .array([row(base, "")])]))
        XCTAssertEqual(clear["changed"], .int(1))
    }

    func testTypeBatchValidatesBeforeMutationAndPreservesUnknownNames() throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let row: (UInt64, String) -> ScriptValue = { .object(["address": .hex($0), "type": .string($1)]) }
        let valid = row(base, "  MissingType  ")
        let invalid: ScriptValue = .object(["address": .hex(base + 4), "type": .int(1)])
        let bad: ScriptValue = .object(["entries": .array([valid, invalid])])
        XCTAssertThrowsError(try api.execute("set-types", arguments: bad))
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: "set-types", arguments: bad))
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
        let result = try api.execute("set-types", arguments: .object(["entries": .array([valid, row(base + 4, "OtherType")])]))
        XCTAssertEqual(result["changed"], .int(2))
        let key = ImageAddress(slot: store.snapshot.primarySlot, address: base)
        XCTAssertEqual(store.snapshot.addressOverrides[key]?.appliedTypeName, "MissingType")
        store.undoManager.undo()
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
        store.undoManager.redo()
        XCTAssertEqual(store.snapshot.addressOverrides[key]?.appliedTypeName, "MissingType")
        _ = try api.execute("set-types", arguments: .object(["entries": .array([row(base, "")])]))
        XCTAssertNil(store.snapshot.addressOverrides[key])
    }

    func testBatchIsAllOrNothing() throws {
        let (store, base) = try fixture()
        let before = store.snapshot.addressOverrides
        let canUndo = store.undoManager.canUndo
        let valid: ScriptValue = .object(["address": .hex(base), "name": .string("valid")])
        let cases: [(ScriptValue, String)] = [
            (.array([valid, .object(["address": .string("zz"), "name": .string("bad")])]), "entries[1]"),
            (.array([valid, valid]), "entries[1]"),
            (entries(base, count: 1025, field: "name", prefix: "large"), "entries[1024]"),
            (.array([]), "entries[0]"),
            (.array([valid, .object(["address": .hex(base + 4), "name": .null])]), "entries[1]")
        ]
        for (value, label) in cases {
            XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("set-names",
                arguments: .object(["entries": value]))) { error in
                guard let scripting = error as? ScriptingError, case .invalidArgument(let detail) = scripting else {
                    return XCTFail("\(error)")
                }
                XCTAssertTrue(detail.contains(label), detail)
            }
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            XCTAssertEqual(store.undoManager.canUndo, canUndo)
            let reply = try call(store, command: "set-names", entries: value)
            XCTAssertEqual(reply["result"]?["isError"], .bool(true))
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            XCTAssertEqual(store.undoManager.canUndo, canUndo)
        }
    }

    func testGenericBatchRefusalNamesTheEntry() throws {
        let (store, base) = try fixture()
        let value: ScriptValue = .array([
            .object(["address": .hex(base), "name": .string("valid")]),
            .object(["address": .hex(base + 4), "name": .string(String(repeating: "x", count: 256 * 1024 + 1))])
        ])
        let before = store.snapshot.addressOverrides
        let reply = try call(store, command: "set-names", entries: value)
        XCTAssertEqual(reply["result"]?["isError"], .bool(true))
        let text = try XCTUnwrap(reply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        XCTAssertTrue(text.contains("entries[1]"), text)
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        XCTAssertFalse(store.undoManager.canUndo)
    }

    func testOverrideOnlyWriteSkipsBreakpointReprojection() throws {
        let (store, base) = try fixture()
        let counter = store.breakpointReprojectionCountForTesting
        XCTAssertEqual(counter, 0, "init seeds the witness; no warm-up publication")
        let api = WorkspaceScriptingAPI(store: store)
        _ = try api.execute("rename", arguments: .object(["address": .hex(base), "name": .string("single")]))
        _ = try api.execute("set-comment", arguments: .object(["address": .hex(base + 4), "comment": .string("comment")]))
        _ = try api.execute("set-names", arguments: .object([
            "entries": entries(base, count: 50, field: "name", prefix: "batch")
        ]))
        _ = try api.execute("undo-last")
        XCTAssertEqual(store.breakpointReprojectionCountForTesting, 0)
    }

    func testStructuralAndCatalogChangesStillReproject() async throws {
        let (store, base) = try fixture()
        XCTAssertEqual(store.breakpointReprojectionCountForTesting, 0)
        let slot = store.snapshot.primarySlot
        var replacement = store.snapshot
        var analysis = try XCTUnwrap(replacement.analysis(in: slot))
        XCTAssertFalse(analysis.instructions.isEmpty)
        analysis.instructions[0].hasBreakpoint = true
        replacement.replaceAnalysis(analysis, in: slot)
        store.snapshot = replacement
        XCTAssertEqual(store.breakpointReprojectionCountForTesting, 1)
        XCTAssertFalse(try XCTUnwrap(store.snapshot.analysis(in: slot)).instructions[0].hasBreakpoint)
        let beforeBinaries = store.snapshot.binaries
        let beforeInstructions = try XCTUnwrap(store.snapshot.analysis(in: slot)).instructions
        _ = try WorkspaceScriptingAPI(store: store).execute("make-data",
            arguments: .object(["address": .hex(base + 4), "isData": .bool(true)]))
        // make-data schedules its structural reanalysis in the background; observe it settled.
        await store.awaitPendingReanalysis()
        XCTAssertNil(store.lastReanalysisRefusal)
        let afterInstructions = try XCTUnwrap(store.snapshot.analysis(in: slot)).instructions
        // The projection witness compares binaries and per-slot instructions (with the catalog,
        // availability and primary slot, which make-data leaves alone). Binary publication and
        // analysis publication are separate reanalysis writes, and each reprojects exactly when
        // the input it publishes changed; an unchanged input yields the same snapshot, so it skips.
        let expected = 1
            + (beforeBinaries == store.snapshot.binaries ? 0 : 1)
            + (beforeInstructions == afterInstructions ? 0 : 1)
        XCTAssertEqual(store.breakpointReprojectionCountForTesting, expected)
        XCTAssertFalse(afterInstructions.contains(where: \.hasBreakpoint))
    }

    func testUndoLastUndoesOneBatch() throws {
        let (store, base) = try fixture()
        let pre = try names(store, base: base, count: 50)
        let api = WorkspaceScriptingAPI(store: store)
        for index in 0..<50 {
            _ = try api.execute("rename", arguments: .object([
                "address": .hex(base + UInt64(index * 4)), "name": .string("old_\(index)")
            ]))
        }
        _ = try api.execute("set-names", arguments: .object([
            "entries": entries(base, count: 50, field: "name", prefix: "new_")
        ]))
        XCTAssertEqual(try api.execute("undo-last"),
            .object(["ok": .bool(true), "undone": .string("Rename Names"), "canUndo": .bool(true)]))
        XCTAssertEqual(try names(store, base: base, count: 50), (0..<50).map { .string("old_\($0)") })
        let second = try api.execute("undo-last")
        XCTAssertEqual(second["undone"], .string("Rename"))
        let after = try names(store, base: base, count: 50)
        XCTAssertEqual(Array(after.prefix(49)), (0..<49).map { .string("old_\($0)") })
        XCTAssertEqual(after[49], pre[49])
    }

    func testUndoLastRefusesWhenNothingToUndo() throws {
        let (store, _) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertThrowsError(try api.execute("undo-last")) { error in
            guard let scripting = error as? ScriptingError, case .invalidArgument(let detail) = scripting else {
                return XCTFail("\(error)")
            }
            XCTAssertEqual(detail, "nothing to undo")
        }
        store.undoManager.beginUndoGrouping()
        defer { store.undoManager.endUndoGrouping() }
        let level = store.undoManager.groupingLevel
        XCTAssertThrowsError(try api.execute("undo-last")) { error in
            guard let scripting = error as? ScriptingError, case .invalidArgument(let detail) = scripting else {
                return XCTFail("\(error)")
            }
            XCTAssertEqual(detail, "an undo group is open; retry")
        }
        XCTAssertEqual(store.undoManager.groupingLevel, level)
    }

    func testUndoLastUnavailableWhenAttached() async throws {
        let (store, base) = try fixture()
        let pre = try names(store, base: base, count: 3)
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("set-names"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains("set-comments"))
        XCTAssertFalse(MCPAttachExecutor.attachCommands.contains("undo-last"))
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        do {
            _ = try await executor.execute("undo-last", .object([:]))
            XCTFail("attached undo-last must be unavailable")
        } catch {
            XCTAssertEqual(error as? MCPAttachExecutor.Failure, .unavailableWhenAttached)
        }
        let result = try await executor.execute("set-names", .object([
            "entries": entries(base, count: 3, field: "name", prefix: "attached")
        ]))
        XCTAssertEqual(result["changed"], .int(3))
        XCTAssertEqual(store.undoManager.undoActionName, "Agent: set-names")
        store.undoManager.undo()
        XCTAssertEqual(try names(store, base: base, count: 3), pre)
        XCTAssertFalse(store.undoManager.canUndo)
    }

    func testBatchMirrorsAnalystNames() throws {
        let (store, base) = try fixture()
        let slot = store.snapshot.primarySlot
        _ = try WorkspaceScriptingAPI(store: store).execute("set-names", arguments: .object([
            "entries": entries(base, count: 3, field: "name", prefix: "mirrored")
        ]))
        let live = try XCTUnwrap(store.navigatorStates[slot]).liveAnnotations().filter {
            $0.author == "analyst" && $0.predicate == "hasName"
        }
        XCTAssertEqual(live.count, 3)
        for index in 0..<3 {
            let subject = NavigatorSubjectRef.subject(
                kind: "address", ref: NavigatorSubjectRef.address(base + UInt64(index * 4)),
                identity: store.snapshot.binary(in: slot)?.artifactIdentity)
            let annotation = try XCTUnwrap(live.first { $0.subject == subject })
            XCTAssertEqual(annotation.value, .string("mirrored\(index)"))
        }
        store.undoManager.undo()
        let remaining = store.navigatorStates[slot]?.liveAnnotations().filter {
            $0.author == "analyst" && $0.predicate == "hasName"
        } ?? []
        XCTAssertTrue(remaining.isEmpty)
    }

    func testCostStatementsInDescriptions() throws {
        let commands = WorkspaceScriptingAPI.availableCommands
        for name in ["rename", "set-comment", "set-tag", "set-color", "set-local-label",
                     "clear-local-label", "set-names", "set-comments", "set-type", "set-types",
                     "set-operand-format", "set-operand-formats", "undo-last"] {
            let summary = try XCTUnwrap(commands.first { $0.name == name }).summary
            XCTAssertTrue(summary.contains("Cost:"), name)
            XCTAssertNil(summary.range(of: #"[0-9]+\s*(?:ms|s)\b"#, options: .regularExpression), name)
        }
    }

    func testTypeAndOperandCostsDisclosePossibleReanalysis() throws {
        for name in ["set-type", "set-types", "set-operand-format", "set-operand-formats"] {
            let summary = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == name }).summary
            XCTAssertTrue(summary.contains("undo step"), name)
            XCTAssertTrue(summary.contains("can trigger reanalysis"), name)
        }
    }

    func testNoOpBatchDoesNotCreateAnotherUndoStep() throws {
        let (store, base) = try fixture()
        let api = WorkspaceScriptingAPI(store: store)
        let blank: ScriptValue = .array([.object(["address": .hex(base), "name": .string(" \n ")])])
        XCTAssertEqual(try api.execute("set-names", arguments: .object(["entries": blank]))["changed"], .int(0))
        XCTAssertFalse(store.undoManager.canUndo)
        let named: ScriptValue = .array([.object(["address": .hex(base), "name": .string(" kept ")])])
        XCTAssertEqual(try api.execute("set-names", arguments: .object(["entries": named]))["changed"], .int(1))
        XCTAssertEqual(try api.execute("set-names", arguments: .object(["entries": named]))["changed"], .int(0))
        XCTAssertEqual(try names(store, base: base, count: 1), [.string("kept")])
        store.undoManager.undo()
        XCTAssertFalse(store.undoManager.canUndo)
    }

    func testBatchPreservesUneditedKeysInTheSlotMap() throws {
        let (store, base) = try fixture()
        let slot = store.snapshot.primarySlot
        store.setColorTag(at: [base + 16], color: .red)
        let before = store.snapshot.addressOverrides
        store.undoManager.removeAllActions()
        _ = try WorkspaceScriptingAPI(store: store).execute("set-names", arguments: .object([
            "entries": entries(base, count: 3, field: "name", prefix: "changed")
        ]))
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: slot, address: base + 16)]?.colorTag, .red)
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        XCTAssertFalse(store.undoManager.canUndo)
    }

    func testControlSingleRenameReplyUnchanged() throws {
        let (store, base) = try fixture()
        let result = try WorkspaceScriptingAPI(store: store).execute("rename",
            arguments: .object(["address": .hex(base), "name": .string("control")]))
        // VA1 adds readback fields; the pre-existing reply fields retain their values.
        XCTAssertEqual(result["ok"], .bool(true))
        XCTAssertEqual(result["address"], .hex(base))
        XCTAssertEqual(result["name"], .string("control"))
        XCTAssertEqual(store.undoManager.undoActionName, "Rename")
    }

    func testControlColorBulkUnchanged() throws {
        let (store, base) = try fixture()
        let before = store.snapshot.addressOverrides
        store.setColorTag(at: [base, base + 4], color: .red)
        XCTAssertEqual(store.undoManager.undoActionName, "Set Color")
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        XCTAssertFalse(store.undoManager.canUndo)
    }
}
