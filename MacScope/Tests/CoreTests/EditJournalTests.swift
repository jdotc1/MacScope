import Foundation
import Darwin
import XCTest
@testable import MacScope

@MainActor
final class EditJournalTests: XCTestCase {
    private static let code = Data([
        0x00, 0x00, 0x80, 0x52, 0x02, 0x00, 0x00, 0x14,
        0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xc0, 0x03, 0x5f, 0xd6
    ])
    private struct Fixture {
        let scratch: URL
        let binary: URL
        let base: UInt64
        var journal: URL { scratch.appendingPathComponent("edits.journal") }
        func address(_ index: Int) -> UInt64 { base + UInt64(index * 4) }
        func package(_ name: String = "P") -> URL { scratch.appendingPathComponent(name + ".mscope") }
    }
    private enum Injected: Error { case failure }

    private func fixture() throws -> Fixture {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("edit-journal-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        let macho = TinyMachO.make(code: Self.code)
        let binary = try macho.write()
        addTeardownBlock {
            try? FileManager.default.removeItem(at: scratch)
            try? FileManager.default.removeItem(at: binary.deletingLastPathComponent())
        }
        return Fixture(scratch: scratch, binary: binary, base: macho.baseAddress)
    }

    private func analyzed(_ url: URL, scheduler: AutosaveScheduling? = nil) throws -> WorkspaceStore {
        let engine = AnalysisEngine()
        return WorkspaceStore(workspaceName: "journal", snapshot: try engine.analyze(url: url),
                              engine: engine, autosaveScheduler: scheduler)
    }
    private func names(_ store: WorkspaceStore, _ f: Fixture) throws -> [ScriptValue] {
        try (0..<5).map {
            try WorkspaceScriptingAPI(store: store).execute("name-at",
                arguments: .object(["address": .hex(f.address($0))]))
        }
    }
    @discardableResult
    private func rename(_ store: WorkspaceStore, _ f: Fixture, _ index: Int, _ name: String) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute("rename",
            arguments: .object(["address": .hex(f.address(index)), "name": .string(name)]))
    }
    private func three(_ store: WorkspaceStore, _ f: Fixture) throws {
        for index in 0..<3 { try rename(store, f, index, "name\(index)") }
    }
    private func contents(_ f: Fixture) throws -> EditJournalContents {
        try EditJournalReader.read(Data(contentsOf: f.journal))
    }
    private func save(_ store: WorkspaceStore, to path: URL? = nil) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute("save-workspace",
            arguments: .object(path.map { ["path": .string($0.path)] } ?? [:]))
    }
    private func tree(_ root: URL) throws -> [String: Data] {
        let paths = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey])!
        var files: [String: Data] = [:]
        for case let url as URL in paths {
            if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
                files[String(url.path.dropFirst(root.path.count))] = try Data(contentsOf: url)
            }
        }
        return files
    }

    func testThreeRenamesReplayOntoAFreshStore() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        let created = try a.attachEditJournal(at: f.journal)
        XCTAssertTrue(created.created)
        XCTAssertEqual(created.replayed, 0)
        try three(a, f)
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3])
        a.detachEditJournal()?.close()
        let b = try analyzed(f.binary)
        let report = try b.attachEditJournal(at: f.journal)
        XCTAssertEqual(report.replayed, 3)
        XCTAssertFalse(report.alreadyApplied)
        XCTAssertEqual(try names(b, f), [.string("name0"), .string("name1"), .string("name2"), pre[3], pre[4]])
    }

    func testInfoReportsObservedJournalHealthAcrossLiveRoutes() async throws {
        let f = try fixture(), store = try analyzed(f.binary)
        let api = WorkspaceScriptingAPI(store: store)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        func check(_ state: String) async throws {
            let expected: ScriptValue = .object(["state": .string(state), "durability": .string("unverified")])
            let direct = try api.execute("info")
            XCTAssertEqual(direct["editJournal"], expected)
            let asynchronous = try await api.executeAsync("info")
            XCTAssertEqual(asynchronous["editJournal"], expected)
            let attachedInfo = try await attached.execute("info", .object([:]))
            XCTAssertEqual(attachedInfo["editJournal"], expected)
            let snapshotOnly = try WorkspaceScriptingAPI.snapshotListRead("info", arguments: .object([:]), snapshot: store.snapshot, scope: .attached)
            XCTAssertNil(snapshotOnly["editJournal"])
        }
        try await check("disabled")
        try store.attachEditJournal(at: f.journal)
        let writer = try XCTUnwrap(store.editJournal)
        try await check("healthy")
        writer.appendHook = { _ in throw Injected.failure }
        XCTAssertThrowsError(try rename(store, f, 0, "changed"))
        let failure = try XCTUnwrap(writer.failure)
        try await check("sticky-failed")
        let encoded = try api.execute("info").jsonData()
        let text = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        XCTAssertFalse(text.contains(f.journal.path))
        XCTAssertFalse(text.contains(failure))
        writer.close()
        try await check("sticky-failed")
        XCTAssertTrue(store.detachEditJournal() === writer)
        try await check("disabled")
    }

    func testInfoReportsClosedWriterAsUnavailable() async throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        let writer = try XCTUnwrap(store.editJournal)
        writer.close()
        let info = try await WorkspaceScriptingAPI(store: store).executeAsync("info")
        XCTAssertEqual(info["editJournal"]?["state"], .string("unavailable"))
        XCTAssertNil(writer.failure)
    }

    func testTornFinalRecordIsSkippedReportedAndTruncated() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        a.detachEditJournal()?.close()
        var bytes = try Data(contentsOf: f.journal)
        let offset = bytes.count
        let fourth = EditJournalRecord.override(seq: 4, slot: a.snapshot.primarySlot.rawValue,
            address: f.address(3), value: AddressOverride(customName: "name3"))
        bytes.append(try EditJournalCodec.line(fourth).prefix(40))
        try bytes.write(to: f.journal)
        let b = try analyzed(f.binary)
        let report = try b.attachEditJournal(at: f.journal)
        XCTAssertEqual(report.replayed, 3)
        XCTAssertEqual(report.tornTail?.offset, offset)
        XCTAssertEqual(report.tornTail?.length, 40)
        XCTAssertEqual(try Data(contentsOf: f.journal).count, offset)
        try rename(b, f, 3, "name3")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3, 4])
        b.detachEditJournal()?.close()
        let c = try analyzed(f.binary)
        XCTAssertEqual(try c.attachEditJournal(at: f.journal).replayed, 4)
        XCTAssertEqual(try names(c, f), [.string("name0"), .string("name1"), .string("name2"), .string("name3"), pre[4]])
    }

    func testCorruptMiddleRecordRefusesReplay() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        _ = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        a.detachEditJournal()?.close()
        var bytes = try Data(contentsOf: f.journal)
        let newlines = bytes.indices.filter { bytes[$0] == 10 }
        let start = newlines[1] + 1
        bytes[start] = bytes[start] == 48 ? 49 : 48
        try bytes.write(to: f.journal)
        let b = try analyzed(f.binary)
        let pre = try names(b, f), overrides = b.snapshot.addressOverrides
        XCTAssertThrowsError(try b.attachEditJournal(at: f.journal)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 3))
        }
        XCTAssertEqual(b.snapshot.addressOverrides, overrides)
        XCTAssertEqual(try names(b, f), pre)
        XCTAssertEqual(try Data(contentsOf: f.journal), bytes)
    }

    func testJournalOfAnotherBinaryIsRefused() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        _ = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        a.detachEditJournal()?.close()
        var code = Self.code
        code[0] = 1
        let other = try TinyMachO.make(code: code).write()
        defer { try? FileManager.default.removeItem(at: other.deletingLastPathComponent()) }
        let b = try analyzed(other)
        let before = try Data(contentsOf: f.journal)
        let overrides = b.snapshot.addressOverrides, pre = try names(b, f)
        let ia = EditJournalImageIdentity.capture(a.snapshot), ib = EditJournalImageIdentity.capture(b.snapshot)
        XCTAssertEqual(ia.first?.imageByteCount, ib.first?.imageByteCount)
        XCTAssertNotEqual(ia.first?.imageSHA256, ib.first?.imageSHA256)
        XCTAssertThrowsError(try b.attachEditJournal(at: f.journal)) {
            XCTAssertEqual($0 as? EditJournalError, .identityMismatch)
        }
        XCTAssertEqual(b.snapshot.addressOverrides, overrides)
        XCTAssertEqual(try names(b, f), pre)
        XCTAssertEqual(try Data(contentsOf: f.journal), before)
    }

    func testNoPackageWithoutSaveWorkspace() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        _ = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        let entries = FileManager.default.enumerator(at: f.scratch, includingPropertiesForKeys: nil)!
        for case let url as URL in entries { XCTAssertNotEqual(url.pathExtension.lowercased(), "mscope") }
        a.detachEditJournal()?.close()

        let trigger = ManualAutosaveTrigger()
        let b = try analyzed(f.binary, scheduler: trigger)
        _ = try names(b, f)
        let package = f.package()
        _ = try b.writeDocumentPackageThrowing(to: package)
        let before = try tree(package)
        try b.attachEditJournal(at: f.scratch.appendingPathComponent("package.journal"))
        try rename(b, f, 0, "later")
        XCTAssertNil(b.autosaveScheduler)
        XCTAssertFalse(trigger.isPending)
        XCTAssertFalse(trigger.firePending())
        XCTAssertEqual(try tree(package), before)

        let c = try analyzed(f.binary)
        _ = try names(c, f)
        let x = f.package("X")
        try FileManager.default.createDirectory(at: x, withIntermediateDirectories: true)
        for path in [x.appendingPathComponent("edits.journal"),
                     f.scratch.appendingPathComponent("edits.MSCOPE"), f.scratch, f.binary] {
            XCTAssertThrowsError(try c.attachEditJournal(at: path, launchPath: f.binary)) {
                guard let error = $0 as? EditJournalError, case .pathRefused = error else { return XCTFail("\($0)") }
            }
        }
    }

    func testReattachOfAppliedJournalIsIdempotent() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        try three(store, f)
        let before = store.snapshot.addressOverrides
        let journalBefore = try Data(contentsOf: f.journal)
        for _ in 0..<2 {
            store.detachEditJournal()?.close()
            let report = try store.attachEditJournal(at: f.journal)
            XCTAssertTrue(report.alreadyApplied)
            XCTAssertEqual(report.replayed, 0)
            XCTAssertFalse(report.created)
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            XCTAssertEqual(try Data(contentsOf: f.journal), journalBefore)
        }
    }

    func testUnsavedReattachIsIdempotentAndPreservesFreshRestartReplay() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        let before = a.snapshot.addressOverrides
        let journalBefore = try Data(contentsOf: f.journal)
        a.detachEditJournal()?.close()
        let report = try a.attachEditJournal(at: f.journal)
        XCTAssertTrue(report.alreadyApplied)
        XCTAssertEqual(report.replayed, 0)
        XCTAssertFalse(report.created)
        XCTAssertFalse(report.priorAcknowledgmentsVerified)
        XCTAssertEqual(a.snapshot.addressOverrides, before)
        XCTAssertEqual(try Data(contentsOf: f.journal), journalBefore)
        XCTAssertEqual(try contents(f).header?.base, [])
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3])
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".retired.1"))
        a.detachEditJournal()?.close()
        let b = try analyzed(f.binary)
        XCTAssertEqual(try b.attachEditJournal(at: f.journal).replayed, 3)
        XCTAssertEqual(try names(b, f), [.string("name0"), .string("name1"), .string("name2"), pre[3], pre[4]])
        b.detachEditJournal()?.close()
        try a.attachEditJournal(at: f.journal)
        try rename(a, f, 3, "next")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3, 4])
        XCTAssertEqual(try names(a, f)[4], pre[4])
        a.detachEditJournal()?.close()
        let c = try analyzed(f.binary)
        XCTAssertEqual(try c.attachEditJournal(at: f.journal).replayed, 4)
        XCTAssertEqual(try names(c, f), [.string("name0"), .string("name1"), .string("name2"), .string("next"), pre[4]])
        let entries = FileManager.default.enumerator(at: f.scratch, includingPropertiesForKeys: nil)!
        for case let url as URL in entries { XCTAssertNotEqual(url.pathExtension.lowercased(), "mscope") }
    }

    func testDirtyPackageReattachPreservesSavedRestartBase() throws {
        let f = try fixture(), original = try analyzed(f.binary)
        _ = try names(original, f)
        _ = try original.writeDocumentPackageThrowing(to: f.package())
        let packageBefore = try tree(f.package())
        let a = try WorkspaceStore.restoredPackage(from: f.package())
        let pre = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        XCTAssertTrue(a.isDirty)
        let journalBefore = try Data(contentsOf: f.journal)
        a.detachEditJournal()?.close()
        let report = try a.attachEditJournal(at: f.journal)
        XCTAssertTrue(report.alreadyApplied)
        XCTAssertFalse(report.priorAcknowledgmentsVerified)
        XCTAssertEqual(report.replayed, 0)
        XCTAssertEqual(try Data(contentsOf: f.journal), journalBefore)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".retired.1"))
        try rename(a, f, 3, "next")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3, 4])
        a.detachEditJournal()?.close()
        let b = try WorkspaceStore.restoredPackage(from: f.package())
        XCTAssertEqual(try b.attachEditJournal(at: f.journal).replayed, 4)
        XCTAssertEqual(try names(b, f), [.string("name0"), .string("name1"), .string("name2"), .string("next"), pre[4]])
        XCTAssertEqual(try tree(f.package()), packageBefore)
    }

    func testCleanFlagAfterSavingAnotherPackageDoesNotRebaseRestartJournal() throws {
        let f = try fixture(), original = try analyzed(f.binary)
        _ = try names(original, f)
        _ = try original.writeDocumentPackageThrowing(to: f.package("A"))
        let packageBefore = try tree(f.package("A"))
        let a = try WorkspaceStore.restoredPackage(from: f.package("A"))
        let pre = try names(a, f)
        let restartURL = try XCTUnwrap(a.documentURL)
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        a.detachEditJournal()?.close()
        let journalBefore = try Data(contentsOf: f.journal)
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        _ = try a.saveWorkspacePackage(to: f.package("B"), using: database)
        XCTAssertFalse(a.isDirty)
        XCTAssertEqual(a.documentURL, restartURL)
        XCTAssertTrue(try a.attachEditJournal(at: f.journal).alreadyApplied)
        XCTAssertEqual(try Data(contentsOf: f.journal), journalBefore)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".retired.1"))
        a.detachEditJournal()?.close()
        let b = try WorkspaceStore.restoredPackage(from: restartURL)
        XCTAssertEqual(try b.attachEditJournal(at: f.journal).replayed, 3)
        XCTAssertEqual(try names(b, f), [.string("name0"), .string("name1"), .string("name2"), pre[3], pre[4]])
        XCTAssertEqual(try tree(f.package("A")), packageBefore)
    }

    func testJournalLaunchReportDoesNotInferRotationOrPriorAcknowledgments() {
        let applied = EditJournalReport(replayed: 0, tornTail: nil, alreadyApplied: true, created: false)
        XCTAssertEqual(MCPLauncher.journalLaunchDetail(applied, rotationFailure: nil),
            "already applied; journal attached; prior acknowledgments cannot be verified")
        XCTAssertEqual(MCPLauncher.journalLaunchDetail(applied, rotationFailure: "injected"),
            "already applied; journal rotation failed: injected; prior acknowledgments cannot be verified")
        let replayed = EditJournalReport(replayed: 3, tornTail: (100, 7), alreadyApplied: false, created: false)
        XCTAssertEqual(MCPLauncher.journalLaunchDetail(replayed, rotationFailure: nil),
            "replayed 3 records; torn tail of 7 bytes at offset 100 skipped; prior acknowledgments cannot be verified")
        let created = EditJournalReport(replayed: 0, tornTail: nil, alreadyApplied: false, created: true)
        XCTAssertEqual(MCPLauncher.journalLaunchDetail(created, rotationFailure: nil), "replayed 0 records")
    }

    func testJournalReceiptReportsOnlySynchronizedRecordsForCurrentMutation() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        let first = try rename(store, f, 0, "first")
        XCTAssertEqual(first["editJournal"]?["scope"], .string("v1-address-overrides"))
        XCTAssertEqual(first["editJournal"]?["durability"], .string("synchronized"))
        XCTAssertEqual(first["editJournal"]?["synchronizedRecords"], .int(1))
        XCTAssertEqual(first["editJournal"]?["firstSynchronizedSequence"], .string("1"))
        let second = try rename(store, f, 1, "second")
        XCTAssertEqual(second["editJournal"]?["firstSynchronizedSequence"], .string("2"))
        XCTAssertEqual(second["editJournal"]?["lastSynchronizedSequence"], .string("2"))
    }

    func testJournalSyncFailurePreservesLiveResultAndRefusesRetry() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.beforeAppendSyncForTesting = { _ in throw Injected.failure }
        XCTAssertThrowsError(try rename(store, f, 0, "applied")) { error in
            let failure = error as? ScriptingJournalFailure
            XCTAssertEqual(failure?.liveApplied, true)
            XCTAssertEqual(failure?.result["editJournal"]?["durability"], .string("unconfirmed"))
            XCTAssertEqual(failure?.result["editJournal"]?["retrySafe"], .bool(false))
            XCTAssertEqual(failure?.result["editJournal"]?["synchronizedRecords"], .int(0))
        }
        XCTAssertEqual(try names(store, f)[0], .string("applied"))
        XCTAssertThrowsError(try rename(store, f, 1, "must-not-apply"))
    }

    func testRecoveryOfUnconfirmedRecordDoesNotRetroactivelyAcknowledgeIt() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        try a.attachEditJournal(at: f.journal)
        a.editJournal?.beforeAppendSyncForTesting = { _ in throw Injected.failure }
        XCTAssertThrowsError(try rename(a, f, 0, "uncertain")) { error in
            let failure = error as? ScriptingJournalFailure
            XCTAssertEqual(failure?.result["editJournal"]?["durability"], .string("unconfirmed"))
            XCTAssertEqual(failure?.result["editJournal"]?["synchronizedRecords"], .int(0))
            XCTAssertEqual(failure?.result["editJournal"]?["retrySafe"], .bool(false))
        }
        XCTAssertEqual(a.editJournal?.sequence, 0)
        // The hook runs after the complete write and before sync. Readable bytes
        // are deliberately distinct from an acknowledged synchronized append.
        XCTAssertEqual(try contents(f).records.map(\.seq), [1])
        a.detachEditJournal()?.close()
        let b = try analyzed(f.binary)
        let report = try b.attachEditJournal(at: f.journal)
        XCTAssertEqual(report.replayed, 1)
        XCTAssertFalse(report.priorAcknowledgmentsVerified)
        XCTAssertEqual(try names(b, f)[0], .string("uncertain"))
        let reply = try rename(b, f, 1, "later")
        XCTAssertEqual(reply["editJournal"]?["durability"], .string("synchronized"))
        XCTAssertEqual(reply["editJournal"]?["synchronizedRecords"], .int(1))
        XCTAssertEqual(reply["editJournal"]?["firstSynchronizedSequence"], .string("2"))
        XCTAssertEqual(reply["editJournal"]?["lastSynchronizedSequence"], .string("2"))
    }

    func testMCPReportsUnconfirmedJournalAndPreservesLiveMutation() async throws {
        for useAsync in [false, true] {
            let f = try fixture(), store = try analyzed(f.binary)
            try store.attachEditJournal(at: f.journal)
            store.editJournal?.beforeAppendSyncForTesting = { _ in throw Injected.failure }
            let request = ScriptValue.object([
                "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                "params": .object(["name": .string("rename"),
                    "arguments": .object(["address": .hex(f.address(0)), "name": .string("applied")])])
            ])
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
            let data = try request.jsonData()
            let raw: Data?
            if useAsync { raw = await server.handleMessageAsync(data) }
            else { raw = server.handleMessage(data) }
            let response = try ScriptValue.decode(try XCTUnwrap(raw))
            XCTAssertEqual(response["result"]?["isError"], .bool(true))
            let content = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            let detail = try ScriptValue.decode(Data(content.utf8))
            XCTAssertEqual(detail["retrySafe"], .bool(false))
            XCTAssertEqual(detail["returnedResult"]?["editJournal"]?["durability"], .string("unconfirmed"))
            XCTAssertEqual(try names(store, f)[0], .string("applied"))
        }
    }

    func testClosedJournalRejectsBeforeAnyMutation() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        let before = try names(store, f)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.close()
        XCTAssertThrowsError(try rename(store, f, 0, "must-not-apply"))
        XCTAssertEqual(try names(store, f), before)
    }

    func testAppendFailureRefusesNextMutationButAllowsSave() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        a.editJournal?.appendHook = { _ in throw Injected.failure }
        XCTAssertThrowsError(try rename(a, f, 0, "applied")) {
            XCTAssertTrue($0.localizedDescription.contains("edit-journal-failed:"))
        }
        XCTAssertEqual(try names(a, f)[0], .string("applied"))
        XCTAssertThrowsError(try rename(a, f, 1, "blocked"))
        XCTAssertEqual(try names(a, f)[1], pre[1])
        // The pre-check also protects callers that explicitly disable synchronous reanalysis.
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: a).execute("rename",
            arguments: .object(["address": .hex(f.address(2)), "name": .string("blocked")]),
            forcesSynchronousReanalysis: false))
        XCTAssertEqual(try names(a, f)[2], pre[2])
        XCTAssertEqual(try save(a, to: f.package("S"))["ok"], .bool(true))
        XCTAssertNotNil(a.editJournal?.failure)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".retired.1"))
    }

    func testMCPAnnotationCommitFailureRetainsEditAndNamesStage() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let envelope = try XCTUnwrap(server.handle(.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("rename"), "arguments": .object([
                "address": .hex(f.address(0)), "name": .string("retained")])]),
        ])))
        XCTAssertEqual(envelope["result"]?["isError"], .bool(true))
        let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        let output = try ScriptValue.decode(Data(text.utf8))
        let result = try XCTUnwrap(output["returnedResult"])
        XCTAssertEqual(result["requested"], .string("retained"))
        XCTAssertEqual(result["observed"], .string("retained"))
        XCTAssertEqual(result["verification"]?["code"], .string("commitFailed"))
        XCTAssertEqual(result["verification"]?["stage"], .string("commit"))
        XCTAssertEqual(try names(store, f)[0], .string("retained"))
        XCTAssertNotNil(store.editJournal?.failure)
        XCTAssertEqual(output["retrySafe"], .bool(false))
    }

    func testDataProcedureBatchJournalFailureReportsCapturedSlot() throws {
        for command in ["set-data", "set-procedures"] {
            let f = try fixture(), store = try analyzed(f.binary)
            try store.attachEditJournal(at: f.journal)
            store.editJournal?.appendHook = { _ in throw Injected.failure }
            let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0))])])])
            XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute(command, arguments: args)) { error in
                let failure = error as? ScriptingCommittedBatchFailure
                XCTAssertEqual(failure?.count, 1)
                XCTAssertEqual(failure?.changed, 1)
                XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
            }
        }
    }

    func testUndefinedBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0))])])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("set-undefined", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.isUndefined, true)
    }

    func testArrayShapeBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0)), "count": .int(2)])])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("make-arrays", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.dataShape?.elementCount, 2)
    }

    func testStringShapeBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0)), "length": .int(8)])])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("make-strings", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.dataShape?.stringLength, 8)
    }

    func testAlignmentBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0)), "boundary": .int(8)])])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("make-alignments", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.dataShape?.alignment, 8)
    }

    func testSignatureBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0)), "returnType": .string("int")])])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("set-signatures", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.focusedImageSlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.signature?.returnType, "int")
    }

    func testTagBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([.object(["address": .hex(f.address(0)), "tag": .string("saved")])])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("set-tags", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(f.address(0))]?.tag, "saved")
    }

    func testStackLocalBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        let function = try XCTUnwrap(store.snapshot.functions.first)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(function.startAddress), "local": .string("-24:-16"), "name": .string("saved")])
        ])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("set-stack-locals", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.stackLocalOverrides(forProcedureAt: function.startAddress, in: store.snapshot.primarySlot)["-24:-16"]?.name, "saved")
        XCTAssertNotNil(store.editJournal?.failure)
    }

    func testRegisterBatchJournalFailureReportsCapturedSlot() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        let function = try XCTUnwrap(store.snapshot.functions.first)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let args: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(function.startAddress), "register": .string("x19"), "name": .string("saved")])
        ])])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("rename-registers", arguments: args)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 1)
            XCTAssertEqual(failure?.changed, 1)
            XCTAssertEqual(failure?.imageSlot, Int64(store.snapshot.primarySlot.rawValue))
        }
        XCTAssertEqual(store.snapshot.registerNameOverrides(forProcedureAt: function.startAddress)["x19"], "saved")
        XCTAssertNotNil(store.editJournal?.failure)
    }

    func testLocalLabelBatchJournalFailureReportsReturnedChangesAndBlocksNextEdit() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        store.editJournal?.appendHook = { _ in throw Injected.failure }
        let api = WorkspaceScriptingAPI(store: store)
        let batch: ScriptValue = .object(["entries": .array([
            .object(["address": .hex(f.address(0)), "label": .string("first")]),
            .object(["address": .hex(f.address(1)), "label": .string("second")])
        ])])
        XCTAssertThrowsError(try api.execute("set-local-labels", arguments: batch)) { error in
            let failure = error as? ScriptingCommittedBatchFailure
            XCTAssertEqual(failure?.count, 2)
            XCTAssertEqual(failure?.changed, 2)
            XCTAssertTrue(error.localizedDescription.contains("edit-journal-failed:"))
        }
        XCTAssertEqual(store.snapshot.addressOverrides.count, 2)
        XCTAssertThrowsError(try api.execute("set-local-labels", arguments: batch))
        XCTAssertEqual(store.snapshot.addressOverrides.count, 2)
    }

    func testRequestedJournalLaunchParsing() throws {
        let accepted = [
            ["app", "--mcp", "/bin/ls", "--journal", "/tmp/e.journal"],
            ["app", "--mcp=/bin/ls", "--journal=/tmp/e.journal"]
        ]
        for args in accepted {
            let launch = try XCTUnwrap(MCPLauncher.requestedJournalLaunch(from: args))
            XCTAssertEqual(launch.binary, MCPLauncher.canonicalURL(forPath: "/bin/ls"))
            XCTAssertEqual(launch.journal, MCPLauncher.canonicalURL(forPath: "/tmp/e.journal"))
            XCTAssertNil(MCPLauncher.requestedBinary(from: args))
        }
        for args in [
            ["app", "--mcp", "/bin/ls"], ["app", "--mcp", "/bin/ls", "--journal"],
            ["app", "--mcp", "/bin/ls", "--other", "/tmp/e.journal"],
            ["app", "--mcp=/bin/ls", "--journal="],
            ["app", "--other", "--mcp", "/bin/ls", "--journal", "/tmp/e.journal"]
        ] { XCTAssertNil(MCPLauncher.requestedJournalLaunch(from: args)) }
    }

    func testUndoAndRedoAreJournaled() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        a.undoManager.groupsByEvent = false
        try a.attachEditJournal(at: f.journal)
        try three(a, f)
        a.undoManager.undo()
        a.undoManager.redo()
        a.undoManager.undo()
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3, 4, 5, 6])
        a.detachEditJournal()?.close()
        let b = try analyzed(f.binary)
        XCTAssertEqual(try b.attachEditJournal(at: f.journal).replayed, 6)
        XCTAssertEqual(try names(b, f), [.string("name0"), .string("name1"), pre[2], pre[3], pre[4]])
    }

    func testBulkColorWriteIsJournaled() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        a.setColorTag(at: [f.address(0), f.address(1)], color: .red)
        let records = try contents(f).records
        XCTAssertEqual(records.count, 1)
        guard case .slotOverrides(_, let slot, let entries) = try XCTUnwrap(records.first) else {
            return XCTFail("expected one bulk record")
        }
        XCTAssertEqual(slot, a.snapshot.primarySlot.rawValue)
        XCTAssertEqual(entries.count, 2)
        a.detachEditJournal()?.close()
        let b = try analyzed(f.binary)
        XCTAssertEqual(try b.attachEditJournal(at: f.journal).replayed, 1)
        for index in 0..<2 {
            let key = ImageAddress(slot: b.snapshot.primarySlot, address: f.address(index))
            XCTAssertEqual(b.snapshot.addressOverrides[key]?.colorTag, .red)
        }
        XCTAssertEqual(try names(b, f), pre)
    }

    func testOpenWorkspaceDetachesJournal() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        _ = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        try rename(a, f, 0, "saved")
        _ = try save(a, to: f.package("O"))
        let before = try Data(contentsOf: f.journal)
        _ = try WorkspaceScriptingAPI(store: a).execute("open-workspace",
            arguments: .object(["path": .string(f.package("O").path)]))
        XCTAssertNil(a.editJournal)
        XCTAssertNil(a.autosaveScheduler)
        try rename(a, f, 1, "afterOpen")
        XCTAssertEqual(try Data(contentsOf: f.journal), before)
    }

    func testSaveInPackageSessionRotatesJournal() throws {
        let f = try fixture(), original = try analyzed(f.binary)
        _ = try names(original, f)
        _ = try original.writeDocumentPackageThrowing(to: f.package())
        let p1 = try WorkspaceStore.restoredPackage(from: f.package())
        let pre = try names(p1, f)
        let first = try p1.attachEditJournal(at: f.journal)
        XCTAssertTrue(first.created)
        XCTAssertEqual(first.replayed, 0)
        try rename(p1, f, 0, "A")
        _ = try save(p1)
        try rename(p1, f, 1, "B")
        let active = try contents(f)
        XCTAssertEqual(active.header?.base.first?.override.customName, "A")
        XCTAssertEqual(active.records.map(\.seq), [1])
        let retired = try EditJournalReader.read(Data(contentsOf: URL(fileURLWithPath: f.journal.path + ".retired.1")))
        XCTAssertEqual(retired.records.count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".rotating"))
        p1.detachEditJournal()?.close()
        let p2 = try WorkspaceStore.restoredPackage(from: f.package())
        let report = try p2.attachEditJournal(at: f.journal)
        XCTAssertFalse(report.alreadyApplied)
        XCTAssertEqual(report.replayed, 1)
        XCTAssertEqual(try names(p2, f), [.string("A"), .string("B"), pre[2], pre[3], pre[4]])
    }

    func testAttachAfterInterruptedRotationCompletesIt() throws {
        let f = try fixture(), original = try analyzed(f.binary)
        _ = try names(original, f)
        _ = try original.writeDocumentPackageThrowing(to: f.package())
        let p1 = try WorkspaceStore.restoredPackage(from: f.package())
        let pre = try names(p1, f)
        try p1.attachEditJournal(at: f.journal)
        try rename(p1, f, 0, "A")
        p1.detachEditJournal()?.close()
        _ = try p1.writeDocumentPackageThrowing(to: f.package())
        let p2 = try WorkspaceStore.restoredPackage(from: f.package())
        XCTAssertNotNil(p2.documentURL)
        XCTAssertFalse(p2.isDirty)
        let report = try p2.attachEditJournal(at: f.journal)
        XCTAssertTrue(report.alreadyApplied)
        XCTAssertFalse(report.priorAcknowledgmentsVerified)
        XCTAssertEqual(report.replayed, 0)
        XCTAssertEqual(try contents(f).records.count, 0)
        XCTAssertEqual(try contents(f).header?.base.first?.override.customName, "A")
        let retired = try EditJournalReader.read(Data(contentsOf: URL(fileURLWithPath: f.journal.path + ".retired.1")))
        XCTAssertEqual(retired.records.count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".rotating"))
        try rename(p2, f, 1, "B")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1])
        p2.detachEditJournal()?.close()
        let p3 = try WorkspaceStore.restoredPackage(from: f.package())
        let third = try p3.attachEditJournal(at: f.journal)
        XCTAssertFalse(third.alreadyApplied)
        XCTAssertEqual(third.replayed, 1)
        XCTAssertEqual(try names(p3, f), [.string("A"), .string("B"), pre[2], pre[3], pre[4]])
    }

    // MARK: R2-LOCK: exclusive ownership, stale validation, rotation ownership

    private func refusal(_ body: () throws -> Void) -> EditJournalError? {
        do { try body(); return nil } catch { return error as? EditJournalError }
    }

    /// T1: scope item 1 (exclusive advisory lock).
    func testSecondWriterAndHardLinkAliasAreRefusedAndFirstIsUnaffected() throws {
        let f = try fixture(), a = try analyzed(f.binary), b = try analyzed(f.binary)
        let pre = try names(b, f)
        try a.attachEditJournal(at: f.journal)
        try rename(a, f, 0, "first")
        let before = try Data(contentsOf: f.journal)
        XCTAssertEqual(refusal { try b.attachEditJournal(at: f.journal) }, .ownedByAnotherWriter)
        XCTAssertNil(b.editJournal)
        XCTAssertEqual(try names(b, f), pre)
        let alias = f.scratch.appendingPathComponent("alias.journal")
        try FileManager.default.linkItem(at: f.journal, to: alias)
        XCTAssertEqual(refusal { try b.attachEditJournal(at: alias) }, .ownedByAnotherWriter)
        XCTAssertNil(b.editJournal)
        XCTAssertEqual(try names(b, f), pre)
        XCTAssertEqual(try Data(contentsOf: f.journal), before)
        try rename(a, f, 1, "second")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2])
        XCTAssertNil(a.editJournal?.failure)
        a.detachEditJournal()?.close()
        let c = try analyzed(f.binary)
        let report = try c.attachEditJournal(at: f.journal)
        XCTAssertEqual(report.replayed, 2)
        try rename(c, f, 2, "third")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3])
    }

    /// T2: scope item 2 (stale validation).
    func testBytesAppendedAfterValidationAreRefusedAndJournalIsUnchanged() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        try a.attachEditJournal(at: f.journal)
        try rename(a, f, 0, "one")
        a.detachEditJournal()?.close()
        let handle = try FileHandle(forWritingTo: f.journal)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("deadbeef".utf8))
        let validated = try Data(contentsOf: f.journal)
        let parsed = try EditJournalReader.read(validated)
        let tail = try XCTUnwrap(parsed.tornTail)
        XCTAssertEqual(tail.length, 8)
        try handle.write(contentsOf: Data("0123".utf8))
        try handle.close()
        let after = try Data(contentsOf: f.journal)
        let header = EditJournalHeader(base: [], images: [])
        XCTAssertEqual(refusal {
            _ = try EditJournalWriter(url: f.journal, header: header, sequence: 1, createHeader: false,
                truncateTo: parsed.completeByteCount, expectedContents: validated)
        }, .staleValidation)
        XCTAssertEqual(try Data(contentsOf: f.journal), after)
        XCTAssertEqual(refusal {
            _ = try EditJournalWriter(url: f.journal, header: header, sequence: 0, createHeader: true,
                expectedContents: Data())
        }, .staleValidation)
        XCTAssertEqual(try Data(contentsOf: f.journal), after)
        // A fresh attach sees the new bytes and recovers normally.
        let fresh = try analyzed(f.binary)
        let report = try fresh.attachEditJournal(at: f.journal)
        XCTAssertEqual(report.replayed, 1)
        XCTAssertNotNil(report.tornTail)
    }

    /// T3: scope item 3 (rotation keeps ownership).
    func testRotationOwnsNewGenerationExclusivelyAndPreservesRotatingEvidence() throws {
        let f = try fixture(), original = try analyzed(f.binary)
        _ = try names(original, f)
        _ = try original.writeDocumentPackageThrowing(to: f.package())
        let p1 = try WorkspaceStore.restoredPackage(from: f.package())
        let pre = try names(p1, f)
        try p1.attachEditJournal(at: f.journal)
        try rename(p1, f, 0, "A")
        let evidence = Data("pre-existing rotating evidence".utf8)
        let rotating = URL(fileURLWithPath: f.journal.path + ".rotating")
        try evidence.write(to: rotating)
        _ = try save(p1)
        XCTAssertNil(p1.editJournal?.failure)
        XCTAssertEqual(try Data(contentsOf: rotating), evidence)
        XCTAssertEqual(try contents(f).header?.base.first?.override.customName, "A")
        let p2 = try WorkspaceStore.restoredPackage(from: f.package())
        XCTAssertEqual(refusal { try p2.attachEditJournal(at: f.journal) }, .ownedByAnotherWriter)
        XCTAssertNil(p2.editJournal)
        try rename(p1, f, 1, "B")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1])
        p1.detachEditJournal()?.close()
        let p3 = try WorkspaceStore.restoredPackage(from: f.package())
        let report = try p3.attachEditJournal(at: f.journal)
        XCTAssertEqual(report.replayed, 1)
        XCTAssertEqual(try names(p3, f), [.string("A"), .string("B"), pre[2], pre[3], pre[4]])
        XCTAssertEqual(try Data(contentsOf: rotating), evidence)
    }

    // Item 1258 (roadmap R2): exclusive edit-journal writer ownership regression cases.
    private enum JournalPathChange: CaseIterable {
        case unlink, symlink, directory, regularFile
    }

    /// The attack preserves an alias of the opened inode so its exact bytes remain inspectable.
    /// These fixture mutations are the adversary, not cleanup performed by the writer.
    private func changeJournalPath(_ url: URL, to change: JournalPathChange) throws {
        let fm = FileManager.default
        try fm.linkItem(at: url, to: URL(fileURLWithPath: url.path + ".detached"))
        let marker = Data("replacement evidence\n".utf8)
        switch change {
        case .unlink:
            try fm.removeItem(at: url)
        case .symlink:
            try fm.removeItem(at: url)
            let target = URL(fileURLWithPath: url.path + ".target")
            try marker.write(to: target)
            try fm.createSymbolicLink(at: url, withDestinationURL: target)
        case .directory:
            try fm.removeItem(at: url)
            try fm.createDirectory(at: url, withIntermediateDirectories: false)
            try marker.write(to: url.appendingPathComponent("sentinel"))
        case .regularFile:
            let replacement = URL(fileURLWithPath: url.path + ".replacement")
            try marker.write(to: replacement)
            guard Darwin.rename(replacement.path, url.path) == 0 else {
                throw EditJournalWriter.systemError("replace fixture path")
            }
        }
    }

    private func assertJournalReplacementPreserved(_ url: URL, change: JournalPathChange,
                                                    file: StaticString = #filePath, line: UInt = #line) throws {
        let fm = FileManager.default
        let marker = Data("replacement evidence\n".utf8)
        switch change {
        case .unlink:
            XCTAssertFalse(fm.fileExists(atPath: url.path), file: file, line: line)
        case .symlink:
            XCTAssertEqual(try fm.destinationOfSymbolicLink(atPath: url.path), url.path + ".target",
                           file: file, line: line)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: url.path + ".target")), marker,
                           file: file, line: line)
        case .directory:
            XCTAssertEqual(try fm.contentsOfDirectory(atPath: url.path), ["sentinel"], file: file, line: line)
            XCTAssertEqual(try Data(contentsOf: url.appendingPathComponent("sentinel")), marker,
                           file: file, line: line)
        case .regularFile:
            XCTAssertEqual(try Data(contentsOf: url), marker, file: file, line: line)
        }
    }

    func testDetachedOpenRefusesBeforeValidationTruncationOrHeaderWrite() throws {
        for change in JournalPathChange.allCases {
            for staleBytes in [false, true] {
                let f = try fixture()
                let original = Data("validated bytes and torn tail\n".utf8)
                try original.write(to: f.journal)
                var hookCalled = false
                XCTAssertEqual(refusal {
                    _ = try EditJournalWriter(url: f.journal, header: .init(base: [], images: []),
                        sequence: 7, createHeader: true, truncateTo: 0,
                        expectedContents: staleBytes ? Data() : original,
                        openHookForTesting: { path in
                            hookCalled = true
                            XCTAssertEqual(path, f.journal.path)
                            try self.changeJournalPath(f.journal, to: change)
                        })
                }, .io("journal path no longer names this writer"))
                XCTAssertTrue(hookCalled)
                let detached = URL(fileURLWithPath: f.journal.path + ".detached")
                XCTAssertEqual(try Data(contentsOf: detached), original)
                try assertJournalReplacementPreserved(f.journal, change: change)
                // The refused initializer closed its descriptor and released its lock.
                let recovered = try EditJournalWriter(url: detached, header: .init(base: [], images: []),
                    sequence: 7, createHeader: false, expectedContents: original)
                recovered.close()
                XCTAssertEqual(try Data(contentsOf: detached), original)
            }
        }
    }

    func testOpenRefusesFinalSymlinkIncludingDanglingTargetWithoutChangingExistingBytes() throws {
        for targetExists in [false, true] {
            let f = try fixture()
            let target = f.scratch.appendingPathComponent("target")
            let sibling = f.scratch.appendingPathComponent("sibling")
            let evidence = Data("pre-existing evidence\n".utf8)
            try evidence.write(to: sibling)
            if targetExists { try evidence.write(to: target) }
            try FileManager.default.createSymbolicLink(at: f.journal, withDestinationURL: target)
            XCTAssertEqual(refusal {
                _ = try EditJournalWriter(url: f.journal, header: .init(base: [], images: []),
                    sequence: 0, createHeader: true, truncateTo: 0,
                    expectedContents: targetExists ? evidence : Data())
            }, .io("journal path no longer names this writer"))
            XCTAssertEqual(try Data(contentsOf: sibling), evidence)
            if targetExists { XCTAssertEqual(try Data(contentsOf: target), evidence) }
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: f.journal.path),
                           target.path)
            // Deliberately no assertion that a dangling target remains absent:
            // the existing O_CREAT open can create an empty target before lstat refuses.
        }
    }

    func testNewGenerationOpenRefusesOldValidationAfterRotatorCloses() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        try rename(store, f, 0, "before-rotation")
        let old = try Data(contentsOf: f.journal)
        let header = try XCTUnwrap(try contents(f).header)
        let writer = try XCTUnwrap(store.editJournal)
        writer.rotate(images: header.images, base: store.snapshot.addressOverrides)
        XCTAssertNil(writer.failure)
        let current = try Data(contentsOf: f.journal)
        XCTAssertNotEqual(current, old)
        XCTAssertEqual(refusal {
            _ = try EditJournalWriter(url: f.journal, header: header, sequence: 1,
                createHeader: false, expectedContents: old)
        }, .ownedByAnotherWriter)
        store.detachEditJournal()?.close()
        XCTAssertEqual(refusal {
            _ = try EditJournalWriter(url: f.journal, header: header, sequence: 1,
                createHeader: true, truncateTo: 0, expectedContents: old)
        }, .staleValidation)
        XCTAssertEqual(try Data(contentsOf: f.journal), current)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.journal.path + ".retired.1")), old)
    }

    func testDetachedAppendKeepsLiveEditAndNeverAcknowledgesItsSequence() throws {
        for change in JournalPathChange.allCases {
            for afterWrite in [false, true] {
                let f = try fixture(), store = try analyzed(f.binary)
                try store.attachEditJournal(at: f.journal)
                defer { store.detachEditJournal()?.close() }
                try rename(store, f, 0, "already-acknowledged")
                let namesBefore = try names(store, f)
                let writer = try XCTUnwrap(store.editJournal)
                let original = try Data(contentsOf: f.journal)
                let sequence = writer.sequence
                let lastRecord = try EditJournalCodec.encode(try XCTUnwrap(writer.lastAppendedRecord))
                var attemptedLine: Data?
                writer.appendHook = { line in
                    attemptedLine = line
                    if !afterWrite { try self.changeJournalPath(f.journal, to: change) }
                }
                if afterWrite {
                    writer.beforeAppendSyncForTesting = { _ in
                        try self.changeJournalPath(f.journal, to: change)
                    }
                }
                XCTAssertThrowsError(try rename(store, f, 1, "live-only")) { error in
                    let failure = error as? ScriptingJournalFailure
                    XCTAssertEqual(failure?.liveApplied, true)
                    XCTAssertEqual(failure?.result["editJournal"]?["durability"], .string("unconfirmed"))
                    XCTAssertEqual(failure?.result["editJournal"]?["synchronizedRecords"], .int(0))
                    XCTAssertEqual(failure?.result["editJournal"]?["retrySafe"], .bool(false))
                    XCTAssertNil(failure?.result["editJournal"]?["firstSynchronizedSequence"])
                    XCTAssertNil(failure?.result["editJournal"]?["lastSynchronizedSequence"])
                }
                XCTAssertEqual(writer.failure, "journal-io: journal path no longer names this writer")
                XCTAssertEqual(writer.observedHealth, .stickyFailed)
                XCTAssertEqual(writer.sequence, sequence)
                XCTAssertEqual(try EditJournalCodec.encode(try XCTUnwrap(writer.lastAppendedRecord)), lastRecord)
                XCTAssertEqual(try names(store, f)[1], .string("live-only"))
                let line = try XCTUnwrap(attemptedLine)
                XCTAssertEqual(line.last, UInt8(10))
                var expected = original
                if afterWrite { expected.append(line) }
                let detached = URL(fileURLWithPath: f.journal.path + ".detached")
                XCTAssertEqual(try Data(contentsOf: detached), expected)
                try assertJournalReplacementPreserved(f.journal, change: change)
                XCTAssertThrowsError(try rename(store, f, 2, "must-not-apply"))
                XCTAssertEqual(try names(store, f)[2], namesBefore[2])
                XCTAssertEqual(try names(store, f)[1], .string("live-only"))
                XCTAssertEqual(writer.sequence, sequence)
                XCTAssertEqual(try EditJournalCodec.encode(try XCTUnwrap(writer.lastAppendedRecord)), lastRecord)
                XCTAssertEqual(writer.failure, "journal-io: journal path no longer names this writer")
                XCTAssertEqual(try Data(contentsOf: detached), expected)
                try assertJournalReplacementPreserved(f.journal, change: change)
                XCTAssertFalse(FileManager.default.fileExists(atPath: f.package().path))
            }
        }
    }

    func testDetachedRotationRetainsExactEvidenceAndTheOldWriterLock() throws {
        for change in JournalPathChange.allCases {
            for stage in ["header", "retire", "rename"] {
                let f = try fixture(), store = try analyzed(f.binary)
                try store.attachEditJournal(at: f.journal)
                defer { store.detachEditJournal()?.close() }
                try rename(store, f, 0, "keep-live")
                let live = try names(store, f)
                let writer = try XCTUnwrap(store.editJournal)
                let original = try Data(contentsOf: f.journal)
                let oldHeader = try XCTUnwrap(try contents(f).header)
                let sequence = writer.sequence
                let lastRecord = try EditJournalCodec.encode(try XCTUnwrap(writer.lastAppendedRecord))
                let nextHeader = EditJournalHeader(base: EditJournalCodec.entries(store.snapshot.addressOverrides),
                                                   images: oldHeader.images)
                let expectedTemporary = try EditJournalCodec.line(nextHeader)
                var hookCalled = false
                writer.rotateHook = { step in
                    if step == stage {
                        hookCalled = true
                        try self.changeJournalPath(f.journal, to: change)
                    }
                }
                writer.rotate(images: oldHeader.images, base: store.snapshot.addressOverrides)
                XCTAssertTrue(hookCalled)
                XCTAssertEqual(writer.failure, "rotation: journal-io: journal path no longer names this writer")
                XCTAssertEqual(writer.sequence, sequence)
                XCTAssertEqual(try EditJournalCodec.encode(try XCTUnwrap(writer.lastAppendedRecord)), lastRecord)
                XCTAssertEqual(try names(store, f), live)
                let detached = URL(fileURLWithPath: f.journal.path + ".detached")
                XCTAssertEqual(try Data(contentsOf: detached), original)
                try assertJournalReplacementPreserved(f.journal, change: change)
                let stem = f.journal.lastPathComponent
                let artifacts = Set(try FileManager.default.contentsOfDirectory(atPath: f.scratch.path).filter {
                    $0.hasPrefix(stem + ".rotating") || $0.hasPrefix(stem + ".retired")
                })
                let expectedArtifacts: Set<String> = stage == "rename"
                    ? [stem + ".rotating", stem + ".retired.1"] : [stem + ".rotating"]
                XCTAssertEqual(artifacts, expectedArtifacts)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.journal.path + ".rotating")),
                               expectedTemporary)
                if stage == "rename" {
                    XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.journal.path + ".retired.1")), original)
                }
                XCTAssertEqual(refusal {
                    _ = try EditJournalWriter(url: detached, header: oldHeader, sequence: sequence,
                        createHeader: false, expectedContents: original)
                }, .ownedByAnotherWriter)
                XCTAssertThrowsError(try rename(store, f, 1, "blocked"))
                XCTAssertEqual(try names(store, f), live)
                XCTAssertEqual(try Data(contentsOf: detached), original)
                try assertJournalReplacementPreserved(f.journal, change: change)
            }
        }
    }

    func testDefaultWriterBytesMatchLiteralPinLineSequenceAcrossRotation() throws {
        let f = try fixture()
        let image = EditJournalImageIdentity(slot: 0, name: "fixture", kind: "test", architecture: "test",
            selectedSliceIndex: nil, uuid: nil, elfGNUBuildID: nil, imageByteCount: 0,
            imageSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        let header = EditJournalHeader(base: [], images: [image])
        // Literal payloads and newlines are independent of the writer. Reuse only the
        // unchanged pin codec's 17-byte checksum framing; no golden digest was computed
        // during the static review. This is not an independent checksum-algorithm test.
        func expectedLine(_ literal: String, framedByPinCodec frame: Data) -> Data {
            var result = Data(frame.prefix(17))
            result.append(Data((literal + "\n").utf8))
            return result
        }
        let headerLine = expectedLine(
            #"{"base":[],"format":"macscope-edit-journal","images":[{"architecture":"test","elfGNUBuildID":null,"imageByteCount":0,"imageSHA256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","kind":"test","name":"fixture","selectedSliceIndex":null,"slot":0,"uuid":null}],"seq":0,"version":1}"#,
            framedByPinCodec: try EditJournalCodec.line(header))
        let first = expectedLine(#"{"address":16,"kind":"override","seq":1,"slot":0}"#,
            framedByPinCodec: try EditJournalCodec.line(EditJournalRecord.override(seq: 1, slot: 0, address: 16, value: nil)))
        let second = expectedLine(#"{"address":32,"kind":"override","seq":2,"slot":0}"#,
            framedByPinCodec: try EditJournalCodec.line(EditJournalRecord.override(seq: 2, slot: 0, address: 32, value: nil)))
        let afterRotation = expectedLine(#"{"address":48,"kind":"override","seq":1,"slot":0}"#,
            framedByPinCodec: try EditJournalCodec.line(EditJournalRecord.override(seq: 1, slot: 0, address: 48, value: nil)))
        let writer = try EditJournalWriter(url: f.journal, header: header, sequence: 0, createHeader: true)
        defer { writer.close() }
        XCTAssertEqual(try Data(contentsOf: f.journal), headerLine)
        writer.appendOverride(ImageAddress(slot: ImageSlot(rawValue: 0), address: 16), nil)
        writer.appendOverride(ImageAddress(slot: ImageSlot(rawValue: 0), address: 32), nil)
        XCTAssertNil(writer.failure)
        let generationOne = headerLine + first + second
        XCTAssertEqual(try Data(contentsOf: f.journal), generationOne)
        XCTAssertEqual(writer.sequence, 2)
        writer.rotate(images: [image], base: [:])
        XCTAssertNil(writer.failure)
        XCTAssertEqual(writer.sequence, 0)
        XCTAssertNil(writer.lastAppendedRecord)
        XCTAssertEqual(try Data(contentsOf: f.journal), headerLine)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.journal.path + ".retired.1")), generationOne)
        writer.appendOverride(ImageAddress(slot: ImageSlot(rawValue: 0), address: 48), nil)
        XCTAssertNil(writer.failure)
        XCTAssertEqual(writer.sequence, 1)
        XCTAssertEqual(try Data(contentsOf: f.journal), headerLine + afterRotation)
        XCTAssertEqual(try EditJournalReader.read(Data(contentsOf: f.journal)).records.map(\.seq), [1])
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".rotating"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.package().path))
    }

    func testCanonicalStoreAttachResolvesExistingSymlinkBeforeWriterOpen() throws {
        let f = try fixture(), first = try analyzed(f.binary)
        try first.attachEditJournal(at: f.journal)
        try rename(first, f, 0, "before-alias")
        first.detachEditJournal()?.close()
        let alias = f.scratch.appendingPathComponent("alias.journal")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: f.journal)
        let second = try analyzed(f.binary)
        XCTAssertEqual(try second.attachEditJournal(at: alias).replayed, 1)
        defer { second.detachEditJournal()?.close() }
        XCTAssertEqual(second.editJournal?.url, MCPLauncher.canonicalURL(forPath: f.journal.path))
        let reply = try rename(second, f, 1, "after-alias")
        XCTAssertEqual(reply["editJournal"]?["lastSynchronizedSequence"], .string("2"))
        XCTAssertNil(second.editJournal?.failure)
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2])
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: alias.path), f.journal.path)
    }

    func testEarlierUnrelatedRecordAndNoopDoNotBroadenReceipt() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        try store.attachEditJournal(at: f.journal)
        defer { store.detachEditJournal()?.close() }
        store.setCustomName(f.address(1), in: store.snapshot.primarySlot, name: "outside-invocation")
        let result = try rename(store, f, 0, "requested")
        XCTAssertEqual(result["editJournal"]?["synchronizedRecords"], .int(1))
        XCTAssertEqual(result["editJournal"]?["firstSynchronizedSequence"], .string("2"))
        XCTAssertEqual(result["editJournal"]?["lastSynchronizedSequence"], .string("2"))
        let noChange = try rename(store, f, 0, "requested")
        XCTAssertNil(noChange["editJournal"])
        XCTAssertEqual(store.editJournal?.sequence, 2)
    }

    func testUndoSyncFailurePreservesLiveUndoAndUnconfirmedReceipt() throws {
        let f = try fixture(), store = try analyzed(f.binary)
        let before = try names(store, f)
        store.undoManager.groupsByEvent = false
        try store.attachEditJournal(at: f.journal)
        try rename(store, f, 0, "temporary")
        store.editJournal?.beforeAppendSyncForTesting = { _ in throw Injected.failure }
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("undo-last")) { error in
            let failure = error as? ScriptingJournalFailure
            XCTAssertEqual(failure?.handlerReturned, true)
            XCTAssertEqual(failure?.liveApplied, true)
            XCTAssertEqual(failure?.result["editJournal"]?["durability"], .string("unconfirmed"))
            XCTAssertEqual(failure?.result["editJournal"]?["synchronizedRecords"], .int(0))
        }
        XCTAssertEqual(try names(store, f), before)
        XCTAssertEqual(store.editJournal?.sequence, 1)
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2])
        XCTAssertThrowsError(try WorkspaceScriptingAPI(store: store).execute("undo-last"))
        store.detachEditJournal()?.close()
        let recovered = try analyzed(f.binary)
        defer { recovered.detachEditJournal()?.close() }
        XCTAssertEqual(try recovered.attachEditJournal(at: f.journal).replayed, 2)
        XCTAssertEqual(try names(recovered, f), before)
    }

    func testMCPClosedWriterRefusesBeforeMutationOnBothRoutes() async throws {
        for useAsync in [false, true] {
            let f = try fixture(), store = try analyzed(f.binary)
            let before = try names(store, f)
            try store.attachEditJournal(at: f.journal)
            store.editJournal?.close()
            let request = ScriptValue.object([
                "jsonrpc": .string("2.0"), "id": .int(7), "method": .string("tools/call"),
                "params": .object(["name": .string("rename"),
                    "arguments": .object(["address": .hex(f.address(0)), "name": .string("blocked")])])
            ])
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
            let raw: Data?
            if useAsync { raw = await server.handleMessageAsync(try request.jsonData()) }
            else { raw = server.handleMessage(try request.jsonData()) }
            let response = try ScriptValue.decode(try XCTUnwrap(raw))
            XCTAssertEqual(response["result"]?["isError"], .bool(true))
            let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertTrue(text.contains("no mutation was started"))
            XCTAssertEqual(try names(store, f), before)
            XCTAssertEqual(try contents(f).records.count, 0)
        }
    }

    func testMCPSynchronizedReceiptsRemainSequenceScopedAcrossBothRoutes() async throws {
        for useAsync in [false, true] {
            let f = try fixture(), store = try analyzed(f.binary)
            try store.attachEditJournal(at: f.journal)
            let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
            for index in 0..<3 {
                let request = ScriptValue.object([
                    "jsonrpc": .string("2.0"), "id": .int(Int64(index + 1)), "method": .string("tools/call"),
                    "params": .object(["name": .string("rename"),
                        "arguments": .object(["address": .hex(f.address(index)), "name": .string("name\(index)")])])
                ])
                let raw: Data?
                if useAsync { raw = await server.handleMessageAsync(try request.jsonData()) }
                else { raw = server.handleMessage(try request.jsonData()) }
                let response = try ScriptValue.decode(try XCTUnwrap(raw))
                XCTAssertEqual(response["result"]?["isError"], .bool(false))
                let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                let detail = try ScriptValue.decode(Data(text.utf8))
                XCTAssertEqual(detail["editJournal"]?["durability"], .string("synchronized"))
                XCTAssertEqual(detail["editJournal"]?["synchronizedRecords"], .int(1))
                XCTAssertEqual(detail["editJournal"]?["firstSynchronizedSequence"], .string(String(index + 1)))
                XCTAssertEqual(detail["editJournal"]?["lastSynchronizedSequence"], .string(String(index + 1)))
            }
            store.detachEditJournal()?.close()
            let recovered = try analyzed(f.binary)
            defer { recovered.detachEditJournal()?.close() }
            XCTAssertEqual(try recovered.attachEditJournal(at: f.journal).replayed, 3)
            XCTAssertEqual(Array(try names(recovered, f).prefix(3)), [.string("name0"), .string("name1"), .string("name2")])
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.package().path))
        }
    }

    func testNetZeroSessionReplaysAllRecordsAndDoesNotRotate() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        a.undoManager.groupsByEvent = false
        try a.attachEditJournal(at: f.journal)
        try rename(a, f, 0, "temporary")
        a.undoManager.undo()
        a.detachEditJournal()?.close()
        let before = try Data(contentsOf: f.journal)
        let b = try analyzed(f.binary)
        let report = try b.attachEditJournal(at: f.journal)
        XCTAssertFalse(report.alreadyApplied)
        XCTAssertFalse(report.created)
        XCTAssertEqual(report.replayed, 2)
        XCTAssertEqual(try names(b, f), pre)
        XCTAssertEqual(try Data(contentsOf: f.journal), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".retired.1"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".rotating"))
        try rename(b, f, 0, "later")
        XCTAssertEqual(try contents(f).records.map(\.seq), [1, 2, 3])
    }

    func testRotationFailureOnSaveKeepsReplyAndRefusesNextMutation() throws {
        let f = try fixture(), original = try analyzed(f.binary)
        _ = try names(original, f)
        _ = try original.writeDocumentPackageThrowing(to: f.package())
        let p1 = try WorkspaceStore.restoredPackage(from: f.package())
        let pre = try names(p1, f)
        try p1.attachEditJournal(at: f.journal)
        try rename(p1, f, 0, "A")
        let before = try Data(contentsOf: f.journal)
        p1.editJournal?.rotateHook = { step in
            if step == "header" { throw Injected.failure }
        }
        let reply = try save(p1)
        XCTAssertEqual(reply["ok"], .bool(true))
        XCTAssertEqual(reply["path"], .string(try XCTUnwrap(p1.documentURL).path))
        XCTAssertEqual(reply["analyzerVersion"], .int(Int64(WorkspaceAnalyzerStamp.currentVersion)))
        XCTAssertEqual(reply["functionCount"], .int(Int64(p1.snapshot.functions.count)))
        XCTAssertEqual(try MacScopeDocumentPackage.readManifest(from: f.package()).analyzer, .current)
        XCTAssertEqual(try Data(contentsOf: f.journal), before)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".retired.1"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.journal.path + ".rotating"))
        XCTAssertNotNil(p1.editJournal?.failure)
        XCTAssertThrowsError(try rename(p1, f, 1, "blocked")) { error in
            guard let scripting = error as? ScriptingError, case .invalidArgument(let detail) = scripting else {
                return XCTFail("\(error)")
            }
            XCTAssertTrue(detail.hasPrefix("edit-journal-failed: rotation:"), detail)
        }
        XCTAssertEqual(try names(p1, f)[1], pre[1])
    }

    func testCandidateHeaderWithFlippedDigestIsCorrupt() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        try a.attachEditJournal(at: f.journal)
        a.detachEditJournal()?.close()
        var bytes = try Data(contentsOf: f.journal)
        bytes[0] = bytes[0] == 48 ? 49 : 48
        try bytes.write(to: f.journal)
        XCTAssertThrowsError(try a.attachEditJournal(at: f.journal)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 1))
        }
        XCTAssertEqual(try names(a, f), pre)
        XCTAssertTrue(a.snapshot.addressOverrides.isEmpty)
        XCTAssertEqual(try Data(contentsOf: f.journal), bytes)
    }

    func testPlainTextFirstLineIsNotAJournal() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        let pre = try names(a, f)
        let bytes = Data("ordinary text\n".utf8)
        try bytes.write(to: f.journal)
        XCTAssertThrowsError(try a.attachEditJournal(at: f.journal)) {
            XCTAssertEqual($0 as? EditJournalError, .notAJournal)
        }
        XCTAssertEqual(try names(a, f), pre)
        XCTAssertTrue(a.snapshot.addressOverrides.isEmpty)
        XCTAssertEqual(try Data(contentsOf: f.journal), bytes)
    }

    func testControlNoJournalNoFileAndUnchangedReply() throws {
        let f = try fixture(), a = try analyzed(f.binary)
        _ = try names(a, f)
        let reply = try rename(a, f, 0, "control")
        XCTAssertEqual(reply["ok"], .bool(true))
        XCTAssertEqual(reply["address"], .hex(f.address(0)))
        XCTAssertEqual(reply["name"], .string("control"))
        XCTAssertEqual(reply["requested"], .string("control"))
        XCTAssertEqual(reply["observed"], .string("control"))
        XCTAssertEqual(reply["verification"], .string("candidateReadbackVerified"))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: f.scratch.path).isEmpty)
    }

    func testControlRequestedBinaryUnchanged() {
        let canonical = URL(fileURLWithPath: "/bin/ls").resolvingSymlinksInPath().standardizedFileURL.path
        XCTAssertEqual(MCPLauncher.requestedBinary(from: ["app", "--mcp", "/bin/ls"])?.path, canonical)
        XCTAssertEqual(MCPLauncher.requestedBinary(from: ["app", "--mcp=/bin/ls"])?.path, canonical)
        for args in [
            ["app"], ["app", "--mcp"], ["app", "--mcp", "/bin/ls", "extra"],
            ["app", "--mcp=/bin/ls", "extra"], ["app", "--mcp="], ["app", "--other", "x"],
            ["app", "--other", "--mcp", "/bin/ls"],
            ["app", "--run-script", "--mcp=/etc/passwd", "/bin/ls"]
        ] { XCTAssertNil(MCPLauncher.requestedBinary(from: args)) }
    }
}
