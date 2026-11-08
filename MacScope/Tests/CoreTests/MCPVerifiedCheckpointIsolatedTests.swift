import Darwin
import Foundation
import XCTest
@testable import MacScope

// VA8: the MCP `verified-checkpoint-isolated` command. Cases follow DESIGN.md section 6 and the
// orchestrator rulings (RULINGS.md). The fake runner stands in for the spawned child: it runs the real
// pure judge on the saved package and writes `result.json` in the shape the headless action writes.
// One test (testRealSelfSpawn...) spawns the real CoreTests host in headless mode (ruled Q10).
#if DEBUG
@MainActor
final class MCPVerifiedCheckpointIsolatedTests: XCTestCase {
    private let tool = "verified-checkpoint-isolated"

    override func tearDown() {
        WorkspaceScriptingAPI.verifiedCheckpointChildRunnerForTesting = nil
        super.tearDown()
    }

    // MARK: Fixtures

    private struct Headless {
        let fixture: VCFixture.Store
        let package: URL
        let store: WorkspaceStore
        let api: WorkspaceScriptingAPI
    }

    private func headless() throws -> Headless {
        let fixture = try VCFixture.makeStore(self)
        let package = fixture.root.appendingPathComponent("Base.mscope")
        _ = try fixture.store.writeDocumentPackageThrowing(to: package)
        let store = try WorkspaceStore.restoredPackage(from: package)
        try store.attachEditJournal(at: fixture.root.appendingPathComponent("edits.journal"))
        return Headless(fixture: fixture, package: package, store: store, api: WorkspaceScriptingAPI(store: store))
    }

    private func commit(_ h: Headless, address: UInt64? = nil, field: String = "name", value: String) throws -> ScriptValue {
        let reply = try h.api.execute("verified-commit", arguments: .object([
            "address": .hex(address ?? h.fixture.base), "field": .string(field), "value": .string(value)]))
        XCTAssertEqual(reply["outcome"], .string("committed"), "\(reply)")
        return try XCTUnwrap(reply["expectationOperation"])
    }

    /// Two committed operations (name, then comment) on the entry function, saved.
    private func savedHeadless() throws -> (Headless, [ScriptValue]) {
        let h = try headless()
        let operations = [try commit(h, value: "iso-name"), try commit(h, field: "comment", value: "iso comment")]
        _ = try h.api.execute("save-workspace", arguments: .object([:]))
        return (h, operations)
    }

    private func call(_ h: Headless, _ operations: [ScriptValue]) async throws -> ScriptValue {
        try await h.api.executeAsync(tool, arguments: .object(["operations": .array(operations)]))
    }

    /// Stands in for the spawned child.
    private final class FakeRunner: VerifiedCheckpointChildRunning, @unchecked Sendable {
        enum Mode {
            case honest, sameProcess, pidMismatch, otherExecutable, timeout, noResult, malformed, notFreshInstallation
        }
        let mode: Mode
        let fakePID: Int32 = ProcessInfo.processInfo.processIdentifier + 1
        /// Runs on the main actor between the parent's first observation and the judge.
        var duringRead: (@MainActor @Sendable () -> Void)?
        private let lock = NSLock()
        private var _received: [(workspace: URL, expectation: Data, executable: URL)] = []
        var received: [(workspace: URL, expectation: Data, executable: URL)] { lock.lock(); defer { lock.unlock() }; return _received }

        init(_ mode: Mode = .honest) { self.mode = mode }
        private func record(_ workspace: URL, _ expectation: Data, _ executable: URL) {
            lock.lock(); _received.append((workspace, expectation, executable)); lock.unlock()
        }

        func run(executable: URL, workspace: URL, expectation: Data, timeout: TimeInterval) async throws -> VerifiedCheckpointChildResult {
            record(workspace, expectation, executable)
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("fake-vcp-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            func result(_ data: Data?, exit: Int32 = 0, timedOut: Bool = false) -> VerifiedCheckpointChildResult {
                VerifiedCheckpointChildResult(pid: fakePID, exitStatus: exit, resultJSON: data, stderrFirstLine: "",
                                              timedOut: timedOut, directory: directory)
            }
            switch mode {
            case .timeout: return result(nil, exit: 15, timedOut: true)
            case .noResult: return result(nil, exit: 70)
            case .malformed: return result(Data("not json".utf8), exit: 70)
            default: break
            }
            if let duringRead { await MainActor.run { duringRead() } }
            let readerPID: Int32
            switch mode {
            case .sameProcess: readerPID = ProcessInfo.processInfo.processIdentifier
            case .pidMismatch: readerPID = fakePID + 1
            default: readerPID = fakePID
            }
            let installation = UUID()
            let decoded = try VerifiedCheckpointExpectation.decode(expectation)
            let judged: VerifiedCheckpointExpectation
            if mode == .notFreshInstallation {
                judged = VerifiedCheckpointExpectation(
                    schemaVersion: decoded.schemaVersion, workspaceID: decoded.workspaceID, documentID: decoded.documentID,
                    writerInstallationIDs: [installation], writerProcessID: decoded.writerProcessID, operations: decoded.operations)
            } else {
                judged = decoded
            }
            let path = mode == .otherExecutable ? "/usr/bin/other-executable" : (executable.path)
            let report = VerifiedCheckpoint.run(
                packageURL: workspace, expectation: judged,
                reader: VerifiedCheckpointReaderIdentity(installationID: installation, processID: readerPID, executable: path))
            guard case var .object(fields) = report.jsonValue() else { throw VerifiedCheckpointChildRunnerError(description: "shape") }
            fields["executable"] = .string(path)
            return result(try ScriptValue.object(fields).jsonData(), exit: report.passed ? 0 : 70)
        }
    }

    private func install(_ runner: FakeRunner) { WorkspaceScriptingAPI.verifiedCheckpointChildRunnerForTesting = runner }

    private func assertNeverIsolated(_ reply: ScriptValue, error: String, line: UInt = #line) {
        XCTAssertEqual(reply["ok"], .bool(false), "\(reply)", line: line)
        XCTAssertEqual(reply["error"], .string(error), "\(reply)", line: line)
        XCTAssertNil(reply["process"], "a refusal never names a process", line: line)
        XCTAssertNotEqual(reply["process"], .string("isolated"), line: line)
        XCTAssertNil(reply["isolation"], line: line)
    }

    // MARK: 1. Admission

    func testUnsavedChangesIsRefusedBeforeAnyChildAndSavePinsClean() async throws {
        let h = try headless()
        let operation = try commit(h, value: "dirty")
        XCTAssertTrue(h.store.hasUnsavedChanges)
        let runner = FakeRunner(); install(runner)
        assertNeverIsolated(try await call(h, [operation]), error: "unsavedChanges")
        XCTAssertTrue(runner.received.isEmpty, "nothing is spawned for a dirty store")
        _ = try h.api.execute("save-workspace", arguments: .object([:]))
        XCTAssertFalse(h.store.hasUnsavedChanges, "R-A: save clears hasUnsavedChanges")
        let reply = try await call(h, [operation])
        XCTAssertEqual(reply["process"], .string("isolated"), "\(reply)")
    }

    func testNeverSavedStoreIsNoSavedPackage() async throws {
        let fixture = try VCFixture.makeStore(self)
        let runner = FakeRunner(); install(runner)
        let reply = try await WorkspaceScriptingAPI(store: fixture.store).executeAsync(
            tool, arguments: .object(["operations": .array([try operationJSON()])]))
        assertNeverIsolated(reply, error: "noSavedPackage")
        XCTAssertTrue(runner.received.isEmpty)
    }

    func testBoundSessionIsAttachedSessionUnsupported() async throws {
        let session = try await VCSession(test: self)
        defer { session.session.close() }
        let runner = FakeRunner(); install(runner)
        let reply = try await WorkspaceScriptingAPI(store: session.store).executeAsync(
            tool, arguments: .object(["operations": .array([try operationJSON()])]))
        assertNeverIsolated(reply, error: "attachedSessionUnsupported")
        XCTAssertTrue(runner.received.isEmpty)
    }

    func testLatchedStoreIsRecoveryRequiredWithLatchFields() async throws {
        let h = try headless()
        struct Injected: Error {}
        h.store.verifiedHeadlessBeforeInstallHookForTesting = { throw Injected() }
        let latched = try h.api.execute("verified-commit", arguments: .object([
            "address": .hex(h.fixture.base), "field": .string("name"), "value": .string("latch")]))
        XCTAssertEqual(latched["outcome"], .string("indeterminate"), "\(latched)")
        h.store.verifiedHeadlessBeforeInstallHookForTesting = nil
        let runner = FakeRunner(); install(runner)
        let reply = try await call(h, [try operationJSON()])
        assertNeverIsolated(reply, error: "recoveryRequired")
        XCTAssertEqual(reply["latched"], .bool(true))
        XCTAssertNotNil(reply["latch"]?["operationID"])
        XCTAssertTrue(runner.received.isEmpty)
    }

    func testArgumentsAreExactAndBounded() async throws {
        let (h, operations) = try savedHeadless()
        let runner = FakeRunner(); install(runner)
        func refused(_ fields: [String: ScriptValue], _ field: String, line: UInt = #line) async {
            do {
                _ = try await h.api.executeAsync(tool, arguments: .object(fields))
                XCTFail("expected a refusal", line: line)
            } catch ScriptingError.structuredRefusal(let refusal) {
                XCTAssertEqual(refusal.field, field, line: line)
            } catch { XCTFail("\(error)", line: line) }
        }
        await refused([:], "operations")
        await refused(["operations": .array([])], "operations")
        await refused(["operations": .string("x")], "operations")
        await refused(["operations": .array(Array(repeating: operations[0], count: 257))], "operations")
        await refused(["operations": .array([.string("x")])], "operations[0]")
        await refused(["operations": .array([.object(["operationID": .string("nope")])])], "operations[0]")
        await refused(["operations": .array(operations), "workspaceID": .string(UUID().uuidString)], "workspaceID")
        await refused(["operations": .array(operations), "writerProcessID": .int(1)], "writerProcessID")
        await refused(["operations": .array(operations), "imageSlot": .int(-1)], "imageSlot")
        await refused(["operations": .array(operations), "imageSlot": .int(Int64(Int32.max))], "imageSlot")
        XCTAssertTrue(runner.received.isEmpty)
    }

    // MARK: 2. Envelope

    func testEnvelopeIsFilledByTheServer() async throws {
        let (h, operations) = try savedHeadless()
        let runner = FakeRunner(); install(runner)
        let reply = try await call(h, operations)
        XCTAssertEqual(reply["process"], .string("isolated"), "\(reply)")
        let received = try XCTUnwrap(runner.received.first)
        let sent = try VerifiedCheckpointExpectation.decode(received.expectation)
        XCTAssertEqual(sent.workspaceID, h.store.workspaceID)
        XCTAssertEqual(sent.documentID, h.store.documentID)
        XCTAssertEqual(sent.writerProcessID, ProcessInfo.processInfo.processIdentifier)
        XCTAssertEqual(sent.writerInstallationIDs, [h.store.documentInstallationID])
        XCTAssertEqual(sent.schemaVersion, 1, "name and comment stay schema 1")
        XCTAssertEqual(sent.operations.count, 2)
        XCTAssertEqual(received.workspace, h.store.documentURL)
        XCTAssertEqual(reply["isolation"]?["writerProcessIDSource"], .string("serving-process"))
        XCTAssertEqual(reply["isolation"]?["writerProcessID"], .int(Int64(ProcessInfo.processInfo.processIdentifier)))
    }

    // MARK: 3. Happy path

    func testHappyPathIsIsolatedAndEchoesTheJudgedExpectation() async throws {
        let (h, operations) = try savedHeadless()
        let runner = FakeRunner(); install(runner)
        let reply = try await call(h, operations)
        XCTAssertEqual(reply["ok"], .bool(true), "\(reply)")
        XCTAssertEqual(reply["command"], .string(tool))
        XCTAssertEqual(reply["process"], .string("isolated"))
        XCTAssertEqual(reply["readOnly"], .bool(true))
        XCTAssertEqual(reply["passed"], .bool(true))
        XCTAssertEqual(reply["summary"]?["expected"], .int(2))
        XCTAssertEqual(reply["summary"]?["confirmed"], .int(2))
        XCTAssertEqual(reply["summary"]?["unexpected"], .int(0))
        XCTAssertEqual(reply["isolation"]?["packageStableAcrossRead"], .bool(true))
        XCTAssertEqual(reply["isolation"]?["readerProcessID"], .int(Int64(runner.fakePID)))
        XCTAssertEqual(reply["isolation"]?["sameExecutable"], .bool(true))
        XCTAssertEqual(reply["isolation"]?["source"], .string("saved-package-on-disk"))
        XCTAssertNotNil(reply["generation"]?.stringValue.flatMap(UUID.init(uuidString:)))
        let echoed = try XCTUnwrap(reply["expectation"])
        let sent = try ScriptValue.decode(try XCTUnwrap(runner.received.first).expectation)
        XCTAssertEqual(echoed, sent, "the reply echoes exactly the expectation the child judged")
        XCTAssertNil(reply["artifactPath"], "a passed run deletes its temp directory")
    }

    // MARK: 4. Honesty negatives (never `isolated`)

    func testReaderInTheServingProcessIsNotIsolated() async throws {
        let (h, operations) = try savedHeadless()
        install(FakeRunner(.sameProcess))
        assertNeverIsolated(try await call(h, operations), error: "isolationNotEstablished")
    }

    func testReaderPIDDifferentFromSpawnedPIDIsNotIsolated() async throws {
        let (h, operations) = try savedHeadless()
        install(FakeRunner(.pidMismatch))
        let reply = try await call(h, operations)
        assertNeverIsolated(reply, error: "isolationNotEstablished")
        XCTAssertEqual(reply["reason"], .string("reader-process-is-not-the-spawned-process"))
    }

    func testDifferentExecutableIsNotIsolated() async throws {
        let (h, operations) = try savedHeadless()
        install(FakeRunner(.otherExecutable))
        let reply = try await call(h, operations)
        assertNeverIsolated(reply, error: "isolationNotEstablished")
        XCTAssertEqual(reply["reason"], .string("reader-executable-differs"))
    }

    func testNotFreshInstallationIsNotIsolated() async throws {
        let (h, operations) = try savedHeadless()
        install(FakeRunner(.notFreshInstallation))
        let reply = try await call(h, operations)
        assertNeverIsolated(reply, error: "isolationNotEstablished")
        XCTAssertEqual(reply["reason"], .string("installation-not-fresh"))
    }

    func testPackageRewrittenDuringReadIsRefused() async throws {
        let (h, operations) = try savedHeadless()
        let runner = FakeRunner()
        runner.duringRead = { [package = h.package] in
            try? Data("tamper".utf8).write(to: package.appendingPathComponent("tamper.bin"))
        }
        install(runner)
        let reply = try await call(h, operations)
        // A foreign file makes the package invalid or changes its content hash; either way not stable.
        XCTAssertEqual(reply["ok"], .bool(false), "\(reply)")
        XCTAssertNil(reply["process"])
        XCTAssertNil(reply["isolation"])
        XCTAssertEqual(reply["error"], .string("packageChangedDuringCheckpoint"))
        XCTAssertNotNil(reply["artifactPath"], "a refusal keeps the artifacts")
    }

    func testTimeoutIsRefusedAndKeepsArtifacts() async throws {
        let (h, operations) = try savedHeadless()
        install(FakeRunner(.timeout))
        let reply = try await call(h, operations)
        assertNeverIsolated(reply, error: "isolatedReaderTimedOut")
        XCTAssertNotNil(reply["artifactPath"])
    }

    func testMissingOrMalformedResultIsNoReport() async throws {
        let (h, operations) = try savedHeadless()
        for mode in [FakeRunner.Mode.noResult, .malformed] {
            install(FakeRunner(mode))
            assertNeverIsolated(try await call(h, operations), error: "isolatedReaderNoReport")
        }
    }

    func testOversizeResultFileIsRejectedByTheBoundedRead() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("bounded-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let big = directory.appendingPathComponent("big.json")
        try Data(repeating: 0x20, count: 2_049).write(to: big)
        XCTAssertNil(ProcessVerifiedCheckpointChildRunner.boundedRead(big, maximumBytes: 2_048))
        XCTAssertEqual(ProcessVerifiedCheckpointChildRunner.boundedRead(big, maximumBytes: 2_049)?.count, 2_049)
        XCTAssertNil(ProcessVerifiedCheckpointChildRunner.boundedRead(directory.appendingPathComponent("absent"), maximumBytes: 8))
    }

    // MARK: 5. Isolated but failing

    func testIsolatedButFailingReportsMismatchAndUnexpected() async throws {
        let (h, operations) = try savedHeadless()
        // Wrong requested value on the first operation.
        var wrong = operations
        guard case .object(var first) = wrong[0] else { return XCTFail() }
        first["requested"] = .string("a different name")
        wrong[0] = .object(first)
        let runner = FakeRunner(); install(runner)
        let mismatch = try await call(h, wrong)
        XCTAssertEqual(mismatch["process"], .string("isolated"), "\(mismatch)")
        XCTAssertEqual(mismatch["passed"], .bool(false))
        XCTAssertEqual(mismatch["operations"]?.arrayValue?.first?["outcome"], .string("mismatch"), "\(mismatch)")
        XCTAssertNotNil(mismatch["artifactPath"], "a failing run keeps its artifacts")

        // Commit 3, name only 2 of them: one unexpected record.
        let h3 = try headless()
        let ops = [try commit(h3, value: "n1"), try commit(h3, field: "comment", value: "c1"), try commit(h3, value: "n2")]
        _ = try h3.api.execute("save-workspace", arguments: .object([:]))
        let partial = try await call(h3, [ops[1], ops[2]])
        XCTAssertEqual(partial["process"], .string("isolated"), "\(partial)")
        XCTAssertEqual(partial["passed"], .bool(false))
        XCTAssertEqual(partial["summary"]?["unexpected"], .int(1), "\(partial)")
        XCTAssertEqual(partial["summary"]?["expected"], .int(2))
    }

    // MARK: 6. Production runner, without spawning

    func testProductionRunnerRequestAndEnvironment() throws {
        XCTAssertEqual(ProcessVerifiedCheckpointChildRunner.headlessSelector, HeadlessWorkspaceAcceptance.selector)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("req-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let package = directory.appendingPathComponent("P.mscope")
        let output = directory.appendingPathComponent("out")
        let expectation = directory.appendingPathComponent("expectation.json")
        let data = try ProcessVerifiedCheckpointChildRunner.requestJSON(workspace: package, output: output, expectation: expectation)
        let request = try HeadlessWorkspaceAcceptance.Request.decode(data)
        XCTAssertEqual(request.action, "verified-checkpoint")
        XCTAssertEqual(request.expectation?.lastPathComponent, "expectation.json")
        XCTAssertEqual(request.workspace.lastPathComponent, "P.mscope")
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path), "output must not exist before the spawn")
        guard case .object(let keys) = try ScriptValue.decode(data) else { return XCTFail() }
        XCTAssertEqual(Set(keys.keys), ["action", "workspace", "output", "expectation"])

        let env = ProcessVerifiedCheckpointChildRunner.scrubbedEnvironment(from: [
            "PATH": "/usr/bin", "HOME": "/Users\u{2F}x", "TMPDIR": "/tmp/", "XCTestConfigurationFilePath": "/x",
            "DYLD_INSERT_LIBRARIES": "/y", "DYLD_FRAMEWORK_PATH": "/z", "MACSCOPE_MCP_HARNESS_TOOLS": "1"])
        XCTAssertEqual(env, ["PATH": "/usr/bin", "HOME": "/Users\u{2F}x", "TMPDIR": "/tmp/"])
        XCTAssertEqual(ProcessVerifiedCheckpointChildRunner.defaultTimeout, 25)
    }

    // MARK: 7. One real self-spawn (ruled Q10)

    func testRealSelfSpawnOfTheHostReadsTheSavedPackageInAnotherProcess() async throws {
        let (h, operations) = try savedHeadless()
        WorkspaceScriptingAPI.verifiedCheckpointChildRunnerForTesting = nil
        let reply = try await call(h, operations)
        XCTAssertEqual(reply["process"], .string("isolated"), "\(reply)")
        XCTAssertEqual(reply["passed"], .bool(true), "\(reply)")
        XCTAssertEqual(reply["summary"]?["confirmed"], .int(2))
        let readerPID = try XCTUnwrap(reply["isolation"]?["readerProcessID"]?.intValue)
        XCTAssertNotEqual(readerPID, Int64(ProcessInfo.processInfo.processIdentifier), "a genuinely different process")
        XCTAssertGreaterThan(readerPID, 1)
    }

    // MARK: 8. Catalog

    func testCatalogHasReadOnlyToolWithRequiredOperationsAndIsNotAttachable() throws {
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == tool })
        XCTAssertFalse(info.mutates)
        XCTAssertEqual(info.arguments, ["operations", "imageSlot"])
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        XCTAssertEqual(schema["required"], .array([.string("operations")]))
        XCTAssertEqual(schema["additionalProperties"], .bool(false))
        XCTAssertFalse(MCPAttachExecutor.attachCommands.contains(tool))
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: tool, arguments: .object([
            "operations": .array([]) ]))) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.field, "operations")
        }
    }

    func testSyncTransportRefusesWithAsyncTransportRequired() throws {
        let h = try headless()
        XCTAssertThrowsError(try h.api.execute(tool, arguments: .object(["operations": .array([try operationJSON()])]))) { error in
            guard case ScriptingError.structuredRefusal(let refusal) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(refusal.detail.contains("asyncTransportRequired"))
        }
    }

    // MARK: Helpers

    /// A syntactically valid operation that no package holds (used where admission refuses first).
    private func operationJSON() throws -> ScriptValue {
        .object([
            "operationID": .string(UUID().uuidString), "requestDigest": .string(String(repeating: "a", count: 64)),
            "decision": .string("accepted"), "slot": .int(0), "address": .int(0x1000), "field": .string("name"),
            "requested": .string("x"), "beforeRevision": .int(0), "afterRevision": .int(1)])
    }
}
#endif
