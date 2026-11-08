import Foundation
import XCTest
@testable import MacScope

/// T9; authored, unrun; guards. F1/F5 only. Await the launch task, never sleep.
/// Failed launch checks assert the actual gate has no installed API.
@MainActor
final class ReadyLaunchIdentityGuardsTests: XCTestCase {
    func testInitialAndFinalFingerprintFailuresNeverInstallAPI() async throws {
        let url = try TinyMachO.make(code: Self.code).write()
        defer { try? FileManager.default.removeItem(at: url) }
        for failAt in [1, 2] {
            let probe = ReadyLaunchFingerprintProbe(failAt: failAt)
            let launch = MCPLauncher.startHeadlessSession(binaryURL: url, log: { _ in },
                fingerprint: { try probe.fingerprint($0) }, onLaunchState: { _ in })
            await launch.analysis.value
            XCTAssertNil(launch.gate.api)
            XCTAssertEqual(launch.gate.status.snapshot().state, "failed")
            XCTAssertEqual(probe.calls, failAt)
        }
    }

    func testChangedFinalFingerprintNeverInstallsAPI() async throws {
        let url = try TinyMachO.make(code: Self.code).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let probe = ReadyLaunchFingerprintProbe(changeFinal: true)
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, log: { _ in },
            fingerprint: { try probe.fingerprint($0) }, onLaunchState: { _ in })
        await launch.analysis.value
        XCTAssertNil(launch.gate.api)
        XCTAssertEqual(launch.gate.status.snapshot().state, "failed")
        XCTAssertEqual(probe.calls, 2)
    }

    func testChangedInitialFingerprintNeverInstallsAPI() async throws {
        let url = try TinyMachO.make(code: Self.code).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let probe = ReadyLaunchFingerprintProbe(changeInitial: true)
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, log: { _ in },
            fingerprint: { try probe.fingerprint($0) }, onLaunchState: { _ in })
        await launch.analysis.value
        XCTAssertNil(launch.gate.api)
        XCTAssertEqual(launch.gate.status.snapshot().state, "failed")
        XCTAssertEqual(probe.calls, 2)
    }

    func testSuccessfulLaunchFingerprintsExactlyTwiceAndStartsNotReady() async throws {
        let url = try TinyMachO.make(code: Self.code).write()
        defer { try? FileManager.default.removeItem(at: url) }
        let probe = ReadyLaunchFingerprintProbe()
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, log: { _ in },
            fingerprint: { try probe.fingerprint($0) }, onLaunchState: { _ in })
        // No actor suspension yet: analysis cannot have installed the API.
        XCTAssertNil(launch.gate.api)
        let reply = launch.server.handleLine(
            #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"functions","arguments":{}}}"#)
        try assertCatalogStartupReply(reply)
        await launch.analysis.value
        XCTAssertNotNil(launch.gate.api)
        XCTAssertEqual(launch.gate.status.snapshot().state, "ready")
        XCTAssertEqual(probe.calls, 2)
    }

    func testRetargetedCanonicalFileNeverInstallsAPI() async throws {
        let url = try TinyMachO.make(code: Self.code).write()
        let target = try TinyMachO.make(code: Self.code).write()
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: target)
        }
        let engine = ReadyLaunchProvider(afterAnalysis: { requested in
            try FileManager.default.removeItem(at: requested)
            try FileManager.default.createSymbolicLink(at: requested, withDestinationURL: target)
        })
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, engine: engine,
            log: { _ in }, onLaunchState: { _ in })
        await launch.analysis.value
        XCTAssertNil(launch.gate.api)
        XCTAssertEqual(launch.gate.status.snapshot().state, "failed")
    }

    func testWrongRequestedSliceNeverInstallsAPI() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try MachOFixture.makeUniversalDualExecutable().bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let engine = ReadyLaunchProvider(forceSlice: 0)
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, engine: engine,
            log: { _ in }, onLaunchState: { _ in }, sliceArchitecture: "arm64")
        await launch.analysis.value
        XCTAssertNil(launch.gate.api)
        XCTAssertEqual(launch.gate.status.snapshot().state, "failed")
    }

    func testJournalOpenFailureNeverInstallsAPI() async throws {
        let url = try TinyMachO.make(code: Self.code).write()
        defer { try? FileManager.default.removeItem(at: url) }
        // The parent is a regular fixture file, so no child journal can be opened.
        let journal = url.appendingPathComponent("journal")
        let launch = MCPLauncher.startHeadlessSession(binaryURL: url, journalURL: journal,
            log: { _ in }, onLaunchState: { _ in })
        await launch.analysis.value
        XCTAssertNil(launch.gate.api)
        XCTAssertEqual(launch.gate.status.snapshot().state, "failed")
    }

    private static let code = Data([0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6])
}

private final class ReadyLaunchFingerprintProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let failAt: Int?
    private let changeFinal: Bool
    private let changeInitial: Bool
    init(failAt: Int? = nil, changeFinal: Bool = false, changeInitial: Bool = false) {
        self.failAt = failAt; self.changeFinal = changeFinal; self.changeInitial = changeInitial
    }
    struct Failure: Error {}
    var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
    func fingerprint(_ url: URL) throws -> WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint {
        lock.lock(); defer { lock.unlock() }
        count += 1
        if count == failAt { throw Failure() }
        return .init(canonicalPath: url.resolvingSymlinksInPath().standardizedFileURL.path,
            device: 1, inode: 1, size: (changeInitial && count == 1) || (changeFinal && count == 2) ? 2 : 1,
            modificationSeconds: 0, modificationNanoseconds: 0,
            changeSeconds: 0, changeNanoseconds: 0, sha256: "synthetic-not-a-digest")
    }
}

private struct ReadyLaunchProvider: AnalysisProviding {
    var forceSlice: Int? = nil
    var afterAnalysis: (@Sendable (URL) throws -> Void)? = nil
    func analyze(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                 cancellation: AnalysisCancellationToken) throws -> WorkspaceSnapshot {
        let snapshot = try AnalysisEngine().analyze(url: url,
            requestedSliceIndex: forceSlice ?? requestedSliceIndex,
            overrides: overrides, cancellation: cancellation)
        try afterAnalysis?(url)
        return snapshot
    }
    func openBinary(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                    cancellation: AnalysisCancellationToken) async throws -> WorkspaceSnapshot {
        try analyze(url: url, requestedSliceIndex: requestedSliceIndex,
                    overrides: overrides, cancellation: cancellation)
    }
}

private func assertCatalogStartupReply(_ reply: String?) throws {
    let decoded = try ScriptValue.decode(Data(try XCTUnwrap(reply).utf8))
    let envelope = try catalogReplyObject(decoded, keys: ["jsonrpc", "id", "result"])
    XCTAssertEqual(envelope["jsonrpc"], .string("2.0"))
    XCTAssertEqual(envelope["id"], .int(1))
    let result = try catalogReplyObject(try XCTUnwrap(envelope["result"]), keys: ["content", "isError"])
    XCTAssertEqual(result["isError"], .bool(true))
    let content = try XCTUnwrap(result["content"]?.arrayValue)
    XCTAssertEqual(content.count, 1)
    let item = try catalogReplyObject(try XCTUnwrap(content.first), keys: ["type", "text"])
    XCTAssertEqual(item["type"], .string("text"))
    let text = try XCTUnwrap(item["text"]?.stringValue)
    let status = try catalogReplyObject(try ScriptValue.decode(Data(text.utf8)),
        keys: ["state", "phase", "progress", "elapsedMs", "error"])
    XCTAssertEqual(status["error"], .string("notReady"))
    XCTAssertEqual(status["state"], .string("analyzing"))
    XCTAssertEqual(status["phase"], .null)
    XCTAssertEqual(status["progress"]?.doubleValue, 0)
    XCTAssertGreaterThanOrEqual(try XCTUnwrap(status["elapsedMs"]?.intValue), 0)
}

private func catalogReplyObject(_ value: ScriptValue, keys: Set<String>) throws -> [String: ScriptValue] {
    let fields: [String: ScriptValue]?
    if case .object(let object) = value { fields = object } else { fields = nil }
    let object = try XCTUnwrap(fields)
    XCTAssertEqual(Set(object.keys), keys)
    return object
}
