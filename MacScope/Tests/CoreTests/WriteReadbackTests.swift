import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

/// All controls in this file are AUTHORED, NOT RUN for sealed item 1243.
@MainActor
final class WriteReadbackTests: XCTestCase {
    private let primary = ImageSlot(rawValue: 7)
    private let focused = ImageSlot(rawValue: 9)
    private enum Injected: Error { case read }

    private func makeStore() -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        let snapshot = WorkspaceSnapshot(binaries: [image(primary), image(focused)],
            analysisBySlot: [primary: ImageAnalysis(), focused: ImageAnalysis()])
        return WorkspaceStore(workspaceName: "readback", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private struct Call {
        let command: String
        let arguments: ScriptValue
        let legacy: [String: ScriptValue]
    }

    private func calls() -> [Call] {
        let address = ScriptValue.hex(0x1000)
        func batch(_ field: String, _ value: ScriptValue) -> ScriptValue {
            .object(["entries": .array([.object(["address": address, field: value])])])
        }
        let basic: [String: ScriptValue] = ["ok": .bool(true), "address": address]
        let batchBasic: [String: ScriptValue] = ["ok": .bool(true), "count": .int(1), "changed": .int(1)]
        let bookmarkBasic = batchBasic.merging(["committed": .bool(true), "imageSlot": .int(7)]) { _, new in new }
        return [
            Call(command: "set-type", arguments: .object(["address": address, "type": .string(" Unknown ")]), legacy: basic),
            Call(command: "set-types", arguments: batch("type", .string(" Unknown ")), legacy: batchBasic),
            Call(command: "define-type", arguments: .object(["name": .string("T"), "kind": .string("struct"),
                "fields": .array([.object(["name": .string("x"), "type": .string("int")])])]),
                legacy: ["ok": .bool(true), "name": .string("T")]),
            Call(command: "set-signature", arguments: .object(["address": address, "returnType": .string("int")]), legacy: basic),
            Call(command: "set-signatures", arguments: batch("returnType", .string("int")),
                legacy: bookmarkBasic.merging(["imageSlot": .int(9), "reanalysisStatus": .string("not-needed")]) { _, new in new }),
            Call(command: "set-local-label", arguments: .object(["address": address, "label": .string(" local ")]),
                legacy: basic.merging(["label": .string(" local ")]) { _, new in new }),
            Call(command: "clear-local-label", arguments: .object(["address": address]), legacy: basic),
            Call(command: "set-local-labels", arguments: batch("label", .string(" local ")), legacy: batchBasic),
            Call(command: "add-bookmark", arguments: .object(["address": address, "name": .string(" mark ")]),
                legacy: basic.merging(["name": .string(" mark ")]) { _, new in new }),
            Call(command: "remove-bookmark", arguments: .object(["address": address]), legacy: basic),
            Call(command: "add-bookmarks", arguments: batch("name", .string(" mark ")), legacy: bookmarkBasic),
            Call(command: "remove-bookmarks", arguments: .object(["entries": .array([.object(["address": address])])]), legacy: bookmarkBasic),
        ]
    }

    private func seed(_ store: WorkspaceStore, for call: Call) {
        store.focusImage(focused)
        if call.command == "clear-local-label" { store.setLocalLabel(0x1000, in: primary, label: "old") }
        if call.command.hasPrefix("remove-bookmark") { store.addBookmark(at: 0x1000, in: primary, name: "old") }
    }

    private func history(_ manager: UndoManager) -> [String: ScriptValue] {
        ["canUndo": .bool(manager.canUndo), "canRedo": .bool(manager.canRedo),
         "undo": .string(manager.undoActionName), "redo": .string(manager.redoActionName),
         "groups": .int(Int64(manager.groupingLevel)), "event": .bool(manager.groupsByEvent),
         "enabled": .bool(manager.isUndoRegistrationEnabled)]
    }

    private func assertState(_ store: WorkspaceStore, equals before: WorkspaceSnapshot,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(store.snapshot.addressOverrides, before.addressOverrides, file: file, line: line)
        XCTAssertEqual(store.snapshot.bookmarks, before.bookmarks, file: file, line: line)
        XCTAssertEqual(store.snapshot.typeDefinitions, before.typeDefinitions, file: file, line: line)
    }

    // NOT RUN: all twelve handlers, all four kinds, unchanged legacy key values/types.
    func testAllCoveredSuccessPayloadsAndNativeUndoRedo() throws {
        for call in calls() {
            let store = makeStore(); seed(store, for: call)
            let before = store.snapshot
            let result = try WorkspaceScriptingAPI(store: store).execute(call.command, arguments: call.arguments)
            for (key, value) in call.legacy { XCTAssertEqual(result[key], value, "\(call.command).\(key)") }
            XCTAssertNotNil(result["requested"], call.command)
            XCTAssertEqual(result["observed"], result["requested"], call.command)
            XCTAssertEqual(result["verification"], .string("full-state-equal"))
            XCTAssertNil(result["generation"])
            XCTAssertNil(store.hostUndoManager)
            let committed = store.snapshot
            let manager = store.undoManager
            XCTAssertTrue(manager.canUndo)
            manager.undo()
            assertState(store, equals: before)
            manager.redo()
            assertState(store, equals: committed)
            if call.command == "set-signature" || call.command == "set-signatures" {
                XCTAssertNotNil(store.snapshot.addressOverrides[ImageAddress(slot: focused, address: 0x1000)]?.signature)
                XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x1000)]?.signature)
            }
        }
    }

    // NOT RUN: mismatch and thrown read failure restore all authored collections,
    // preserve both undo and redo history, and do not publish a batch receipt.
    func testInjectedMismatchAndReadFailureRestoreAllKindsAndHistory() throws {
        for call in calls() {
            for throwing in [false, true] {
                let store = makeStore(); seed(store, for: call)
                store.setCustomName(0x8000, in: primary, name: "earlier")
                store.setCustomComment(0x8004, in: primary, comment: "redo")
                let manager = store.undoManager
                manager.undo()
                let before = store.snapshot, priorHistory = history(manager)
                let capture = ScriptingBatchReceiptCapture()
                XCTAssertThrowsError(try ScriptingBatchReceiptCapture.$current.withValue(capture) {
                    try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in
                        if throwing { throw Injected.read }; return .null
                    }) {
                        try WorkspaceScriptingAPI(store: store).execute(call.command, arguments: call.arguments)
                    }
                }) { error in
                    guard let failure = error as? ScriptingWriteReadbackFailure else { return XCTFail("\(error)") }
                    XCTAssertEqual(failure.reply["error"], .string("writeReadbackFailed"))
                    XCTAssertEqual(failure.reply["stage"], .string(throwing ? "readback" : "compare"))
                    XCTAssertEqual(failure.reply["rolledBack"], .bool(true))
                    XCTAssertNotNil(failure.reply["requested"])
                    XCTAssertNotNil(failure.reply["observed"])
                    XCTAssertNotNil(failure.reply["recovery"]?.stringValue)
                }
                assertState(store, equals: before)
                XCTAssertTrue(manager === store.undoManager)
                XCTAssertEqual(history(manager), priorHistory)
                XCTAssertNil(capture.receipt)
                XCTAssertNil(store.hostUndoManager)
                manager.redo()
                XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x8004)]?.customComment, "redo")
                manager.undo(); assertState(store, equals: before)
                manager.undo()
                XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x8000)]?.customName)
            }
        }
    }

    // NOT RUN: a no-op has no private undo action; neither a successful no-op nor
    // an injected failed no-op may undo an unrelated earlier edit.
    func testIdempotentRepeatsNeverUndoEarlierStep() throws {
        for call in calls() {
            let store = makeStore(); seed(store, for: call)
            let api = WorkspaceScriptingAPI(store: store)
            _ = try api.execute(call.command, arguments: call.arguments)
            store.setCustomName(0x9000, in: primary, name: "keep")
            let before = store.snapshot, priorHistory = history(store.undoManager)
            let repeatResult = try api.execute(call.command, arguments: call.arguments)
            XCTAssertEqual(repeatResult["requested"], repeatResult["observed"])
            assertState(store, equals: before)
            XCTAssertEqual(history(store.undoManager), priorHistory)
            XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
                try api.execute(call.command, arguments: call.arguments)
            }) { error in
                let failure = error as? ScriptingWriteReadbackFailure
                XCTAssertEqual(failure?.reply["stage"], .string("compare"))
                XCTAssertEqual(failure?.reply["rolledBack"], .bool(true))
            }
            assertState(store, equals: before)
            XCTAssertEqual(history(store.undoManager), priorHistory)
            store.undoManager.undo()
            XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x9000)]?.customName)
        }
    }

    // VI1-B: names/comments/operand-format replies keep their legacy keys and values; the
    // readback keys are additive.
    func testExcludedSharedBranchesAreByteShapeCompatible() throws {
        for (command, field, text) in [("set-names", "name", "n"), ("set-comments", "comment", "c"),
                                       ("set-operand-formats", "format", "hex")] {
            let store = makeStore()
            let result = try WorkspaceScriptingAPI(store: store).execute(command,
                arguments: .object(["entries": .array([.object(["address": .hex(0x1000), field: .string(text)])])]))
            XCTAssertEqual(result["ok"], .bool(true))
            XCTAssertEqual(result["count"], .int(1))
            XCTAssertEqual(result["changed"], .int(1))
            XCTAssertEqual(result["observed"], result["requested"], command)
            guard case .object(let fields) = result else { return XCTFail(command) }
            XCTAssertEqual(Set(fields.keys),
                           ["ok", "count", "changed", "requested", "observed", "verification", "readback"], command)
        }
    }

    // NOT RUN: bound disclosure without reducing the full 1024-entry comparison.
    func testBatchDisclosureIsBoundedAndLateMismatchIsDetected() throws {
        let store = makeStore(), api = WorkspaceScriptingAPI(store: store)
        let arguments: ScriptValue = .object(["entries": .array((0..<1024).map {
            .object(["address": .hex(UInt64(0x1000 + $0 * 4)), "type": .string(String(repeating: "T", count: 4096))])
        })])
        let before = store.snapshot
        XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, value in
            guard case .array(var rows) = value else { return value }
            rows[1023] = .null; return .array(rows)
        }) { try api.execute("set-types", arguments: arguments) }) { error in
            XCTAssertEqual((error as? ScriptingWriteReadbackFailure)?.reply["stage"], .string("compare"))
        }
        assertState(store, equals: before)
        let result = try api.execute("set-types", arguments: arguments)
        XCTAssertEqual(result["requested"]?["count"], .int(1024))
        XCTAssertEqual(result["requested"]?["sample"]?.arrayValue?.count, 16)
        XCTAssertEqual(result["requested"]?["omitted"], .int(1008))
        XCTAssertEqual(result["requested"], result["observed"])
        XCTAssertLessThan(try result.jsonData().count, 32_768)
    }

    // NOT RUN: generation remains opt-in at execute(), and stale evidence is refused
    // before any readback hook or mutation. The UUID is analysisGenerationID.
    func testGenerationAndStalePreconditionStayUnchanged() throws {
        let store = makeStore(), api = WorkspaceScriptingAPI(store: store)
        let generation = store.snapshot.analysisGenerationID
        let result = try api.execute("set-type", arguments: .object(["address": .hex(0x1000), "type": .string("T"),
            "basedOnGeneration": .string(generation.uuidString)]))
        XCTAssertEqual(result["generation"], .string(store.snapshot.analysisGenerationID.uuidString))
        let before = store.snapshot
        XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in XCTFail("stale write read back"); return .null }) {
            try api.execute("set-type", arguments: .object(["address": .hex(0x1000), "type": .string("U"),
                "basedOnGeneration": .string(UUID().uuidString)]))
        }) { error in
            guard case ScriptingError.staleEvidence = error else { return XCTFail("\(error)") }
        }
        assertState(store, equals: before)
    }

    // NOT RUN: sync and async MCP preserve the same structured typed error;
    // no success/committed-batch envelope or receipt is emitted after reversal.
    func testMCPErrorEnvelopeSyncAndAsync() async throws {
        for asynchronous in [false, true] {
            let store = makeStore(), outcome = MCPMutationOutcome()
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
            let request: ScriptValue = .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                "params": .object(["name": .string("set-types"), "arguments": .object(["entries": .array([
                    .object(["address": .hex(0x1000), "type": .string("T")])])])])])
            let input = try request.jsonData()
            let response = try await MCPExecutionFence.$outcome.withValue(outcome) {
                try await ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
                    let data: Data? = asynchronous ? await server.handleMessageAsync(input) : server.handleMessage(input)
                    return try ScriptValue.decode(XCTUnwrap(data))
                }
            }
            XCTAssertEqual(response["result"]?["isError"], .bool(true))
            let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let payload = try ScriptValue.decode(Data(text.utf8))
            XCTAssertEqual(payload["stage"], .string("compare"))
            XCTAssertEqual(payload["rolledBack"], .bool(true))
            XCTAssertNil(payload["returnedResult"])
            XCTAssertNil(outcome.batchReceipt)
            XCTAssertEqual(outcome.snapshot, .rolledBack)
        }
    }

    // NOT RUN: duplicate bookmark input is compared as final state, while the
    // legacy count remains the original input count. Rollback retains UUID/order.
    func testBookmarkDuplicatesAndInterleavedSlotRollback() throws {
        let store = makeStore(), api = WorkspaceScriptingAPI(store: store)
        store.addBookmark(at: 0x1000, in: primary, name: "old")
        store.addBookmark(at: 0x2000, in: focused, name: "sibling")
        store.addBookmark(at: 0x3000, in: primary, name: "later")
        let before = store.snapshot, priorHistory = history(store.undoManager)
        let arguments: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(0x1000), "name": .string("first")]),
            .object(["address": .hex(0x1000), "name": .string("last")])])])
        XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
            try api.execute("add-bookmarks", arguments: arguments)
        }) { error in
            XCTAssertEqual((error as? ScriptingWriteReadbackFailure)?.reply["rolledBack"], .bool(true))
        }
        assertState(store, equals: before)
        XCTAssertEqual(history(store.undoManager), priorHistory)
        let result = try api.execute("add-bookmarks", arguments: arguments)
        XCTAssertEqual(result["count"], .int(2))
        XCTAssertEqual(result["changed"], .int(1))
        XCTAssertEqual(result["requested"], result["observed"])
        XCTAssertEqual(store.snapshot.bookmarks.first { $0.imageSlot == primary && $0.address == 0x1000 }?.name, "last")
    }

    // NOT RUN: attached writes keep the native Agent action name, undo/redo and
    // host-manager identity. A failed verification leaves prior undo/redo intact.
    func testAttachedManagerReplayAndFailedVerification() async throws {
        let store = makeStore(), host = UndoManager()
        host.groupsByEvent = false
        store.hostUndoManager = host
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let arguments: ScriptValue = .object(["address": .hex(0x1000), "type": .string("T")])
        let result = try await executor.execute("set-type", arguments)
        XCTAssertEqual(result["requested"], result["observed"])
        XCTAssertEqual(host.undoActionName, "Agent: set-type")
        host.undo()
        XCTAssertTrue(store.snapshot.addressOverrides.isEmpty)
        XCTAssertEqual(host.redoActionName, "Agent: set-type")
        let before = store.snapshot, priorHistory = history(host)
        do {
            _ = try await ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
                try await executor.execute("set-type", arguments)
            }
            XCTFail("injected attached readback must fail")
        } catch let failure as ScriptingWriteReadbackFailure {
            XCTAssertEqual(failure.reply["rolledBack"], .bool(true))
        }
        assertState(store, equals: before)
        XCTAssertEqual(history(host), priorHistory)
        XCTAssertTrue(store.hostUndoManager === host)
        host.redo()
        XCTAssertEqual(host.undoActionName, "Agent: set-type")
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x1000)]?.appliedTypeName, "T")
    }

    // MARK: - Installation and slot ownership

    private let ownershipCommands = ["rename", "set-comment", "set-names", "set-comments"]

    @MainActor
    private final class PrivateManagerCapture {
        var value: UndoManager?
    }

    private func ownershipArguments(_ command: String, value: String) -> ScriptValue {
        let field = command == "rename" || command == "set-names" ? "name" : "comment"
        let entry: ScriptValue = .object(["address": .hex(0x1000), field: .string(value)])
        return command == "set-names" || command == "set-comments"
            ? .object(["entries": .array([entry])]) : entry
    }

    private func assertOwnershipSnapshot(_ store: WorkspaceStore, equals before: WorkspaceSnapshot) {
        assertState(store, equals: before)
        XCTAssertEqual(store.snapshot.manualXRefs, before.manualXRefs)
        XCTAssertEqual(store.snapshot.segmentOverrides, before.segmentOverrides)
        XCTAssertEqual(store.snapshot.binaries.map(\.id), before.binaries.map(\.id))
        XCTAssertEqual(store.snapshot.binaries.map(\.slot), before.binaries.map(\.slot))
    }

    private func consumeRetiredWriteHistory(_ host: UndoManager, redo: Bool, unchanged: () -> Void) {
        XCTAssertEqual(host.groupingLevel, 0)
        if redo { host.redo() } else { host.undo() }
        unchanged()
        // Availability flags do not count application inverses. Probe bounded available history;
        // later outer replay must not reach the private manager or revive the retired mutation.
        for _ in 0..<2 {
            if host.canUndo { host.undo(); unchanged() }
            if host.canRedo { host.redo(); unchanged() }
        }
        // Do not assert exhaustion: remaining framework groups need not contain model inverses.
        // The assertions above concern state, not an unsupplied Foundation stack contract.
        XCTAssertEqual(host.groupingLevel, 0)
    }

    // Preserve-control for the common slot-owner guard.
    // Singular commands drive their real route; plural commands cover VerifiedUndo.
    func testAttachedRenameAndCommentOwnershipRoundTrips() async throws {
        for command in ownershipCommands {
            for eventGrouping in [false, true] {
                let store = makeStore(), host = UndoManager()
                host.groupsByEvent = eventGrouping
                store.hostUndoManager = host
                let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
                executor.setConsent(.allowed)
                let before = store.snapshot, wasDirty = store.isDirty
                let capture = PrivateManagerCapture()
                _ = try await ScriptingWriteReadbackInjection.$observe.withValue({ _, observed in
                    // run() calls this synchronously from its @MainActor readback at :481.
                    MainActor.assumeIsolated { capture.value = store.hostUndoManager }
                    return observed
                }) {
                    try await executor.execute(command, ownershipArguments(command, value: "owned"))
                }
                let privateManager = capture.value.flatMap { $0 === host ? nil : $0 }
                let committed = store.snapshot
                let key = ImageAddress(slot: primary, address: 0x1000)
                if command == "rename" || command == "set-names" {
                    XCTAssertEqual(store.snapshot.addressOverrides[key]?.customName, "owned")
                } else {
                    XCTAssertEqual(store.snapshot.addressOverrides[key]?.customComment, "owned")
                }
                XCTAssertEqual(host.groupingLevel, 0)
                XCTAssertEqual(host.groupsByEvent, eventGrouping)
                XCTAssertEqual(host.undoActionName, "Agent: \(command)")
                XCTAssertTrue(host.canUndo)
                XCTAssertFalse(host.canRedo)
                XCTAssertTrue(store.isDirty)
                if ScriptingWriteReadback.commands.contains(command) {
                    XCTAssertNotNil(privateManager)
                    XCTAssertFalse(privateManager === host)
                    XCTAssertTrue(privateManager?.canUndo == true)
                }
                host.undo()
                assertOwnershipSnapshot(store, equals: before)
                XCTAssertEqual(store.isDirty, wasDirty)
                XCTAssertFalse(host.canUndo)
                XCTAssertTrue(host.canRedo)
                XCTAssertEqual(host.redoActionName, "Agent: \(command)")
                if let privateManager { XCTAssertTrue(privateManager.canRedo) }
                host.redo()
                assertOwnershipSnapshot(store, equals: committed)
                XCTAssertTrue(store.isDirty)
                XCTAssertTrue(host.canUndo)
                XCTAssertFalse(host.canRedo)
                XCTAssertEqual(host.undoActionName, "Agent: \(command)")
                XCTAssertTrue(store.hostUndoManager === host)
                if let privateManager { XCTAssertTrue(privateManager.canUndo) }
            }
        }
    }

    // Fails without installation rejection and the direct
    // override registrar delegating to the common guard.
    func testAttachedRenameAndCommentRetainedUndoAndRedoRejectFork() async throws {
        for command in ownershipCommands {
            for redo in [false, true] {
                let store = makeStore(), host = UndoManager()
                host.groupsByEvent = false
                store.hostUndoManager = host
                let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
                executor.setConsent(.allowed)
                let capture = PrivateManagerCapture()
                _ = try await ScriptingWriteReadbackInjection.$observe.withValue({ _, observed in
                    MainActor.assumeIsolated { capture.value = store.hostUndoManager }
                    return observed
                }) {
                    try await executor.execute(command, ownershipArguments(command, value: "old"))
                }
                let privateManager = capture.value.flatMap { $0 === host ? nil : $0 }
                if redo { host.undo() }
                let installation = store.documentInstallationID
                if ScriptingWriteReadback.commands.contains(command) { XCTAssertNotNil(privateManager) }
                store.forkWorkspaceIdentity()
                XCTAssertNotEqual(store.documentInstallationID, installation)
                XCTAssertTrue(redo ? host.canRedo : host.canUndo)
                let before = store.snapshot, generation = store.mutationGeneration, dirty = store.isDirty
                let annotations = store.navigatorState(for: primary)?.annotations()
                let findings = store.analystFindings
                let privateHistory = privateManager.map(history)
                consumeRetiredWriteHistory(host, redo: redo) {
                    self.assertOwnershipSnapshot(store, equals: before)
                    XCTAssertEqual(store.navigatorState(for: self.primary)?.annotations(), annotations)
                    XCTAssertEqual(store.analystFindings, findings)
                    XCTAssertEqual(store.mutationGeneration, generation)
                    XCTAssertEqual(store.isDirty, dirty)
                    XCTAssertEqual(privateManager.map(self.history), privateHistory)
                    XCTAssertTrue(store.hostUndoManager === host)
                }
            }
        }
    }

    // Fails without target-identity rejection AND proxy retention.
    // The installation is unchanged and the detached manager keeps the old callback reachable.
    func testAttachedRenameAndCommentRetainedUndoAndRedoRejectOwnerABA() async throws {
        for command in ownershipCommands {
            for redo in [false, true] {
                let store = makeStore(), host = UndoManager()
                host.groupsByEvent = false
                store.hostUndoManager = host
                let original = store.snapshot, installation = store.documentInstallationID
                let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
                executor.setConsent(.allowed)
                let capture = PrivateManagerCapture()
                _ = try await ScriptingWriteReadbackInjection.$observe.withValue({ _, observed in
                    MainActor.assumeIsolated { capture.value = store.hostUndoManager }
                    return observed
                }) {
                    try await executor.execute(command, ownershipArguments(command, value: "old"))
                }
                let privateManager = capture.value.flatMap { $0 === host ? nil : $0 }
                if redo { host.undo() }
                if ScriptingWriteReadback.commands.contains(command) { XCTAssertNotNil(privateManager) }
                store.hostUndoManager = nil
                store.snapshot = .init(binaries: [], analysisBySlot: [:])
                store.snapshot = original
                XCTAssertEqual(store.documentInstallationID, installation)
                store.addBookmark(at: 0x2000, in: primary, name: "current owner")
                let beforeCurrent = store.snapshot
                if command == "rename" || command == "set-names" {
                    store.setCustomName(0x1000, in: primary, name: "current")
                } else { store.setCustomComment(0x1000, in: primary, comment: "current") }
                XCTAssertTrue(store.undoManager.canUndo)
                let before = store.snapshot, generation = store.mutationGeneration, dirty = store.isDirty
                let annotations = store.navigatorState(for: primary)?.annotations()
                let findings = store.analystFindings, privateHistory = privateManager.map(history)
                store.hostUndoManager = host
                XCTAssertTrue(redo ? host.canRedo : host.canUndo, "Detached history was not pruned")
                consumeRetiredWriteHistory(host, redo: redo) {
                    self.assertOwnershipSnapshot(store, equals: before)
                    XCTAssertEqual(store.navigatorState(for: self.primary)?.annotations(), annotations)
                    XCTAssertEqual(store.analystFindings, findings)
                    XCTAssertEqual(store.mutationGeneration, generation)
                    XCTAssertEqual(store.isDirty, dirty)
                    XCTAssertEqual(privateManager.map(self.history), privateHistory)
                }
                store.hostUndoManager = nil
                XCTAssertTrue(store.undoManager.canUndo, "The current owner's separate history survives")
                store.undoManager.undo()
                assertOwnershipSnapshot(store, equals: beforeCurrent)
            }
        }
    }

    // Preserve-control for the intentionally global slot=nil branch.
    // A slot guard incorrectly extended to this branch would reject this catalog replay.
    func testAttachedCatalogReplayRemainsGlobalAcrossFork() async throws {
        for redoBeforeFork in [false, true] {
            try await assertCatalogReplayAcrossFork(redoBeforeFork: redoBeforeFork)
        }
    }

    private func assertCatalogReplayAcrossFork(redoBeforeFork: Bool) async throws {
        let store = makeStore(), host = UndoManager()
        host.groupsByEvent = false
        store.hostUndoManager = host
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let before = store.snapshot.typeDefinitions, wasDirty = store.isDirty
        let capture = PrivateManagerCapture()
        _ = try await ScriptingWriteReadbackInjection.$observe.withValue({ _, observed in
            MainActor.assumeIsolated { capture.value = store.hostUndoManager }
            return observed
        }) {
            try await executor.execute("define-type", .object(["name": .string("OwnedType"),
                "kind": .string("struct"), "fields": .array([])]))
        }
        let privateManager = try XCTUnwrap(capture.value)
        let committed = store.snapshot.typeDefinitions
        XCTAssertNotEqual(committed, before)
        if redoBeforeFork { host.undo() }
        store.forkWorkspaceIdentity()
        let generation = store.mutationGeneration
        if redoBeforeFork {
            XCTAssertEqual(host.redoActionName, "Agent: define-type")
            host.redo()
            XCTAssertEqual(store.snapshot.typeDefinitions, committed)
            XCTAssertTrue(store.isDirty)
        }
        XCTAssertEqual(host.undoActionName, "Agent: define-type")
        host.undo()
        XCTAssertEqual(store.snapshot.typeDefinitions, before)
        XCTAssertEqual(store.isDirty, wasDirty)
        XCTAssertNotEqual(store.mutationGeneration, generation)
        XCTAssertTrue(privateManager.canRedo)
        XCTAssertTrue(host.canRedo)
        XCTAssertEqual(host.redoActionName, "Agent: define-type")
        host.redo()
        XCTAssertEqual(store.snapshot.typeDefinitions, committed)
        XCTAssertTrue(store.isDirty)
        XCTAssertTrue(privateManager.canUndo)
        XCTAssertTrue(host.canUndo)
        XCTAssertFalse(host.canRedo)
    }

    private func journalFixture() throws -> (WorkspaceStore, URL, UInt64) {
        let macho = TinyMachO.make(code: Data([0xc0, 0x03, 0x5f, 0xd6]))
        let binary = try macho.write()
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("readback-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: scratch)
            try? FileManager.default.removeItem(at: binary.deletingLastPathComponent())
        }
        let engine = AnalysisEngine()
        let store = WorkspaceStore(workspaceName: "readback", snapshot: try engine.analyze(url: binary), engine: engine, autosaveScheduler: nil)
        let journal = scratch.appendingPathComponent("edits.journal")
        try store.attachEditJournal(at: journal)
        return (store, journal, macho.baseAddress)
    }

    // NOT RUN: a reversed override appends forward+inverse records to the SAME
    // journal. There is no second evidence store and no duplicate receipt.
    func testJournalReceiptAndInverseAppendArePreserved() throws {
        let (store, journal, address) = try journalFixture()
        defer { store.detachEditJournal()?.close() }
        let before = store.snapshot
        let arguments: ScriptValue = .object(["address": .hex(address), "type": .string("Unknown")])
        XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
            try WorkspaceScriptingAPI(store: store).execute("set-type", arguments: arguments)
        }) { error in
            let failure = error as? ScriptingWriteReadbackFailure
            XCTAssertEqual(failure?.reply["rolledBack"], .bool(true))
            XCTAssertEqual(failure?.reply["editJournal"]?["synchronizedRecords"], .int(2))
            XCTAssertEqual(failure?.reply["editJournal"]?["durability"], .string("synchronized"))
        }
        assertState(store, equals: before)
        XCTAssertEqual(try EditJournalReader.read(Data(contentsOf: journal)).records.count, 2)
        let success = try WorkspaceScriptingAPI(store: store).execute("set-type", arguments: arguments)
        XCTAssertEqual(success["editJournal"]?["synchronizedRecords"], .int(1))
        XCTAssertEqual(success["requested"], success["observed"])
    }

    // NOT RUN: journal-only failure retains existing committed-live semantics;
    // combined readback+journal failure retains typed stage AND journal uncertainty.
    func testJournalFailureIsNotMisreportedAsSuccessfulRollbackDurability() throws {
        for mismatch in [false, true] {
            let (store, _, address) = try journalFixture()
            defer { store.detachEditJournal()?.close() }
            let before = store.snapshot
            let writer = try XCTUnwrap(store.editJournal)
            writer.appendHook = { _ in throw Injected.read }
            let arguments: ScriptValue = .object(["address": .hex(address), "type": .string("T")])
            if mismatch {
                XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
                    try WorkspaceScriptingAPI(store: store).execute("set-type", arguments: arguments)
                }) { error in
                    let failure = error as? ScriptingWriteReadbackFailure
                    XCTAssertEqual(failure?.reply["stage"], .string("compare"))
                    XCTAssertEqual(failure?.reply["rolledBack"], .bool(true))
                    XCTAssertEqual(failure?.reply["editJournal"]?["durability"], .string("unconfirmed"))
                }
                assertState(store, equals: before)
            } else {
                XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("set-type", arguments: arguments)) { error in
                    XCTAssertTrue(error is ScriptingJournalFailure)
                }
                XCTAssertNotEqual(store.snapshot.addressOverrides, before.addressOverrides)
            }
        }
    }

    // NOT RUN: caller-disabled undo remains disabled and receives no successful
    // bridge, while private native inverses still make failed writes reversible.
    func testDisabledUndoRegistrationIsPreserved() throws {
        for call in calls() {
            for mismatch in [false, true] {
                let store = makeStore(); seed(store, for: call)
                store.setCustomName(0xa000, in: primary, name: "earlier")
                let manager = store.undoManager
                manager.disableUndoRegistration()
                let before = store.snapshot, priorHistory = history(manager)
                let api = WorkspaceScriptingAPI(store: store)
                if mismatch {
                    XCTAssertThrowsError(try ScriptingWriteReadbackInjection.$observe.withValue({ _, _ in .null }) {
                        try api.execute(call.command, arguments: call.arguments)
                    }) { error in
                        XCTAssertEqual((error as? ScriptingWriteReadbackFailure)?.reply["rolledBack"], .bool(true))
                    }
                    assertState(store, equals: before)
                } else {
                    let result = try api.execute(call.command, arguments: call.arguments)
                    XCTAssertEqual(result["requested"], result["observed"])
                }
                XCTAssertEqual(history(manager), priorHistory)
                manager.enableUndoRegistration()
                manager.undo()
                XCTAssertNil(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0xa000)]?.customName)
            }
        }
    }

    // NOT RUN: equality of the public catalog projection cannot bypass the
    // separate full-model verifier. No unseen TypeDefinition Codable contract.
    func testEqualCatalogProjectionStillRequiresFullModelVerification() throws {
        let store = makeStore(), api = WorkspaceScriptingAPI(store: store)
        _ = try api.execute("define-type", arguments: .object(["name": .string("T")]))
        let definition = try XCTUnwrap(store.snapshot.typeDefinitions.first { $0.name == "T" })
        let before = store.snapshot, priorHistory = history(store.undoManager)
        let projection = ScriptingWriteReadback.catalog(definition)
        XCTAssertThrowsError(try ScriptingWriteReadback.run(command: "define-type", store: store, slot: nil,
            requested: projection, read: { snapshot in
                ScriptingWriteReadback.catalog(snapshot.typeDefinitions.first { $0.id == definition.id }!)
            }, matchesFullModel: { _ in false }) {
                store.upsertTypeDefinition(definition)
                return .object(["ok": .bool(true), "name": .string("T")])
            }) { error in
                let failure = error as? ScriptingWriteReadbackFailure
                XCTAssertEqual(failure?.reply["stage"], .string("compare"))
                XCTAssertEqual(failure?.reply["requested"], failure?.reply["observed"])
                XCTAssertEqual(failure?.reply["rolledBack"], .bool(true))
            }
        assertState(store, equals: before)
        XCTAssertEqual(history(store.undoManager), priorHistory)
    }

    // NOT RUN: all twelve covered writes remain unreachable through AppleScript;
    // additive write replies do not require expanding its existing authority.
    func testAppleScriptCoveredWritesRemainExcluded() throws {
        for call in calls() {
            XCTAssertThrowsError(try AppleScriptCommandTranslator.translate(command: "run command", parameters: [
                "command": .string(call.command), "arguments": call.arguments]))
        }
    }
}
