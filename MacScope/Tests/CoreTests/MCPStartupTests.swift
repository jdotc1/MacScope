import Foundation
import XCTest
@testable import MacScope

private final class StartupLogRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
    func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return lines }
}

private final class StartupStatusReference: @unchecked Sendable {
    weak var status: MCPStartupStatus?
}

private enum StartupTestError: LocalizedError {
    case deliberate
    var errorDescription: String? { "deliberate startup failure" }
}

private final class BlockingStartupProvider: AnalysisProviding, @unchecked Sendable {
    let release = DispatchSemaphore(value: 0)
    let phasesBeforeHold: [AnalysisPhase]
    let phasesAfterHold: [AnalysisPhase]
    let phaseHolds: [DispatchSemaphore]
    let throwsAfterHold: Bool
    let rewrite: Bool
    private let lock = NSLock()
    private var entered = false
    var hasEntered: Bool { lock.lock(); defer { lock.unlock() }; return entered }

    init(phasesBeforeHold: [AnalysisPhase] = [.load, .decode, .functionDiscovery],
         phasesAfterHold: [AnalysisPhase] = [], phaseHolds: [DispatchSemaphore] = [],
         throwsAfterHold: Bool = false, rewrite: Bool = false) {
        self.phasesBeforeHold = phasesBeforeHold
        self.phasesAfterHold = phasesAfterHold
        self.phaseHolds = phaseHolds
        self.throwsAfterHold = throwsAfterHold
        self.rewrite = rewrite
    }

    func analyze(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                 cancellation: AnalysisCancellationToken) throws -> WorkspaceSnapshot {
        for (index, phase) in phasesBeforeHold.enumerated() {
            try cancellation.check(phase)
            if index < phaseHolds.count { phaseHolds[index].wait() }
        }
        lock.lock(); entered = true; lock.unlock()
        release.wait()
        for phase in phasesAfterHold { try cancellation.check(phase) }
        if throwsAfterHold { throw StartupTestError.deliberate }
        if rewrite { try Data("changed input".utf8).write(to: url) }
        return Self.snapshot(url)
    }

    func openBinary(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                    cancellation: AnalysisCancellationToken) async throws -> WorkspaceSnapshot {
        fatalError("Only synchronous analyze is used by these startup fixtures")
    }

    static func snapshot(_ url: URL) -> WorkspaceSnapshot {
        WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "test.bin", path: url.path,
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000,
                                        endAddress: 0x1008, confidence: 0.9)],
            symbols: [SymbolSummary(id: UUID(), name: "_main", address: 0x1000,
                                    kind: "export", libraryName: nil)],
            instructions: [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov",
                               operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret",
                               operands: "", hasBreakpoint: false, comment: nil)
            ], xrefs: [], hexBytes: Data())
    }
}

private actor StartupOutput {
    private(set) var values: [Data] = []
    func append(_ data: Data) { values.append(data) }
}

private actor StartupReleaseGate {
    private var released = false
    private var started = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func suspend() async {
        started = true
        if !released { await withCheckedContinuation { waiters.append($0) } }
    }
    var hasStarted: Bool { started }
    func release() {
        released = true
        let pending = waiters
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }
}

@MainActor
final class MCPStartupTests: XCTestCase {
    private func input() throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("startup-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let file = folder.appendingPathComponent("test.bin")
        try Data("startup fixture".utf8).write(to: file)
        addTeardownBlock { try? FileManager.default.removeItem(at: folder) }
        return file
    }
    private func api(_ url: URL) -> WorkspaceScriptingAPI {
        WorkspaceScriptingAPI(store: WorkspaceStore(workspaceName: "startup",
            snapshot: BlockingStartupProvider.snapshot(url), engine: AnalysisEngine(), autosaveScheduler: nil))
    }
    private func request(_ method: String, id: ScriptValue? = .int(1),
                         params: ScriptValue? = nil) throws -> Data {
        var value: [String: ScriptValue] = ["jsonrpc": .string("2.0"), "method": .string(method)]
        if let id { value["id"] = id }
        if let params { value["params"] = params }
        return try ScriptValue.object(value).jsonData()
    }
    private func tool(_ server: MCPServer, _ name: String = "info",
                      arguments: [String: ScriptValue] = [:]) async throws -> ScriptValue {
        let data = try request("tools/call", params: .object(["name": .string(name), "arguments": .object(arguments)]))
        let response = await server.handleMessageAsync(data)
        return try ScriptValue.decode(XCTUnwrap(response))
    }
    private func payload(_ response: ScriptValue) throws -> ScriptValue {
        let text = try XCTUnwrap(response["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }
    private func until(_ condition: () async -> Bool) async throws {
        let end = ContinuousClock.now + .seconds(5)
        while !(await condition()) {
            guard ContinuousClock.now < end else { throw StartupTestError.deliberate }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
    }
    private func frames(_ output: StartupOutput) async throws -> [ScriptValue] {
        let data = await output.values
        return try data.map { try ScriptValue.decode($0) }
    }

    func testInitializeAnswersWhileAnalysisIsBlocked() async throws {
        let provider = BlockingStartupProvider()
        defer { provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        try await until { provider.hasEntered }
        let output = StartupOutput()
        let session = launched.server.makeRequestSession(output: { await output.append($0) })
        for (index, method) in ["initialize", "ping", "tools/list"].enumerated() {
            await session.receive(try request(method, id: .int(Int64(index + 1))))
        }
        try await until { await output.values.count == 3 }
        let replies = try await frames(output)
        let initialize = try XCTUnwrap(replies.first { $0["id"] == .int(1) })
        XCTAssertEqual(initialize["result"]?["capabilities"]?["experimental"]?["macscope/analysis"]?["state"], .string("analyzing"))
        XCTAssertEqual(launched.gate.status.snapshot().state, "analyzing")
        provider.release.signal()
        await launched.analysis.value
        await session.finishInput()
    }

    // TC02 / TC10 / TC11 / TC13: held provider keeps work fields absent and the server
    // responsive; the summary is emitted once, only after settle; no block without an analysis.
    func testWorkSummaryIsAbsentWhileHeldAndEmittedOnceAfterReady() async throws {
        let provider = BlockingStartupProvider()
        defer { provider.release.signal() }
        let log = StartupLogRecorder()
        let work = StartupWorkCounters()
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider,
            log: { log.append($0) }, attribution: AnalysisAttribution(work: work))
        try await until { provider.hasEntered }
        let output = StartupOutput()
        let session = launched.server.makeRequestSession(output: { await output.append($0) })
        await session.receive(try request("initialize"))
        try await until { await output.values.count == 1 }
        XCTAssertEqual(work.snapshot().analysis, .notEntered)
        XCTAssertTrue(work.snapshot().values.isEmpty)
        XCTAssertFalse(log.snapshot().contains { $0.hasPrefix("attribution v1 ") })
        provider.release.signal()
        await launched.analysis.value
        await session.finishInput()
        let lines = log.snapshot().filter { $0.hasPrefix("attribution v1 ") }
        XCTAssertEqual(lines.count, 1)
        XCTAssertFalse(lines[0].contains(" work v1 "), "a fake provider never enters the engine scope")
    }

    /// ITEM 1283 launcher wiring, startHeadlessSession site: the launch server lists the core profile by default.
    func testHeadlessSessionLaunchServerUsesCoreListingProfile() async throws {
        let provider = BlockingStartupProvider()
        defer { provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        try await until { provider.hasEntered }
        let output = StartupOutput()
        let session = launched.server.makeRequestSession(output: { await output.append($0) })
        for (index, method) in ["initialize", "tools/list"].enumerated() {
            await session.receive(try request(method, id: .int(Int64(index + 1))))
        }
        try await until { await output.values.count == 2 }
        let replies = try await frames(output)
        let initialize = try XCTUnwrap(replies.first { $0["id"] == .int(1) })
        let instructions = try XCTUnwrap(initialize["result"]?["instructions"]?.stringValue)
        XCTAssertTrue(instructions.contains("tools/list is using core"))
        let list = try XCTUnwrap(replies.first { $0["id"] == .int(2) })
        let tools = try XCTUnwrap(list["result"]?["tools"]?.arrayValue)
        XCTAssertEqual(tools.count, 28)
        provider.release.signal()
        await launched.analysis.value
        await session.finishInput()
    }

    /// ITEM 1282 launcher wiring, startHeadlessSession site: only MACSCOPE_MCP_REQUEST_TIMING == "1" enables timing.
    func testHeadlessSessionRequestTimingFollowsEnvironmentKey() async throws {
        // MCPRequestTiming keeps its selection private; read it by reflection, with no production seam.
        func isEnabled(_ timing: MCPRequestTiming) -> Bool {
            guard let state = Mirror(reflecting: timing).children.first(where: { $0.label == "state" })?.value else {
                return false
            }
            let optional = Mirror(reflecting: state)
            return optional.displayStyle == .optional ? !optional.children.isEmpty : true
        }
        for (environment, expected) in [
            ([MCPRequestTiming.environmentKey: "1"], true),
            ([:], false),
            ([MCPRequestTiming.environmentKey: "true"], false),
        ] as [([String: String], Bool)] {
            let provider = BlockingStartupProvider()
            defer { provider.release.signal() }
            let launched = MCPLauncher.startHeadlessSession(
                binaryURL: try input(), engine: provider, log: { _ in }, environment: environment)
            try await until { provider.hasEntered }
            XCTAssertEqual(isEnabled(launched.server.timing), expected, "\(environment)")
            let session = launched.server.makeRequestSession(output: { _ in })
            provider.release.signal()
            await launched.analysis.value
            await session.finishInput()
        }
    }

    func testInfoProgressIsMonotonicAndReachesReady() async throws {
        let holds = (0..<3).map { _ in DispatchSemaphore(value: 0) }
        let provider = BlockingStartupProvider(phaseHolds: holds)
        defer { holds.forEach { $0.signal() }; provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        var progress: [Double] = []
        for (index, phase) in provider.phasesBeforeHold.enumerated() {
            try await until { launched.gate.status.snapshot().phase == phase }
            let response = try await tool(launched.server)
            let value = try payload(response)
            progress.append(try XCTUnwrap(value["analysis"]?["progress"]?.doubleValue))
            holds[index].signal()
        }
        provider.release.signal()
        await launched.analysis.value
        let ready = try payload(await tool(launched.server))
        progress.append(try XCTUnwrap(ready["analysis"]?["progress"]?.doubleValue))
        XCTAssertEqual(progress, [0, 1.0 / 9, 2.0 / 9, 1])
        XCTAssertTrue(zip(progress, progress.dropFirst()).allSatisfy { pair in pair.0 <= pair.1 })
        XCTAssertEqual(ready["analysis"]?["state"], .string("ready"))
        XCTAssertEqual(ready["functionCount"], .int(1))
    }

    func testOpaqueLargeProgressMetadataReachesRealInfoHandler() async throws {
        let gate = MCPStartupGate()
        let server = MCPServer(startup: gate)
        let output = StartupOutput()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
            execute: { await server.handleMessageAsync($0) }, output: { await output.append($0) },
            progressSource: gate.status, progressIntervalNanoseconds: 1_000_000)
        let huge = String(repeating: "9", count: 400)
        let token = Phase2ProductionJSONValue.number(huge)
        let request = Phase2ProductionJSONValue.object([
            "jsonrpc": .string("2.0"), "id": .integer(1), "method": .string("tools/call"),
            "params": .object(["name": .string("info"),
                "arguments": .object(["waitForReadyMs": .integer(5000)]),
                "_meta": .object(["progressToken": token])])
        ]).canonicalJSONBytes()
        await session.receive(request)
        try await until { await output.values.count >= 1 }
        gate.install(api: api(try input()), validateIdentity: {})
        try await until {
            let bytes = await output.values
            return bytes.contains { data in
                (try? Phase2StrictJSONParser().parse(data, limits: .providerEnvelope))?.objectValue?["id"] == .integer(1)
            }
        }
        await session.finishInput()
        let frames = try await output.values.map { try Phase2StrictJSONParser().parse($0, limits: .providerEnvelope) }
        let note = try XCTUnwrap(frames.first { $0.objectValue?["method"] == .string("notifications/progress") })
        XCTAssertEqual(note.objectValue?["params"]?.objectValue?["progressToken"], token)
        let reply = try XCTUnwrap(frames.first { $0.objectValue?["id"] == .integer(1) })
        XCTAssertNil(reply.objectValue?["error"])
        XCTAssertNotNil(reply.objectValue?["result"])
    }

    func testMalformedToolMetadataRemainsInvalidAtSessionBoundary() async throws {
        let server = MCPServer(api: api(try input()))
        let output = StartupOutput()
        let session = server.makeRequestSession(output: { await output.append($0) })
        await session.receive(try request("tools/call", params: .object([
            "name": .string("info"), "arguments": .object([:]), "_meta": .string("invalid")
        ])))
        try await until { await output.values.count == 1 }
        await session.finishInput()
        let outputFrames = try await frames(output)
        let reply = try XCTUnwrap(outputFrames.first)
        XCTAssertEqual(reply["error"]?["code"], .int(-32602))
    }

    func testOtherToolsAreRefusedNotReadyAtOnce() async throws {
        let provider = BlockingStartupProvider()
        defer { provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        try await until { provider.hasEntered }
        let start = ContinuousClock.now
        let response = try await tool(launched.server, "functions")
        XCTAssertLessThan(ContinuousClock.now - start, .seconds(1))
        XCTAssertEqual(response["result"]?["isError"], .bool(true))
        let value = try payload(response)
        XCTAssertEqual(value["error"], .string("notReady"))
        XCTAssertEqual(value["state"], .string("analyzing"))
        provider.release.signal()
        await launched.analysis.value
    }

    func testProgressNotificationsOnlyForTokenAndOnlyInFlight() async throws {
        for token in [ScriptValue.string("t1"), .int(7)] {
            let gate = MCPStartupGate()
            let server = MCPServer(startup: gate)
            let output = StartupOutput()
            let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
                execute: { await server.handleMessageAsync($0) }, output: { await output.append($0) },
                progressSource: gate.status, progressIntervalNanoseconds: 10_000_000)
            await session.receive(try request("tools/call", params: .object([
                "name": .string("info"), "arguments": .object(["waitForReadyMs": .int(5000)]),
                "_meta": .object(["progressToken": token])
            ])))
            try await until { await output.values.count >= 1 }
            gate.status.report(.init(phase: .decode, elapsed: .zero))
            try await until { await output.values.count >= 2 }
            gate.install(api: api(try input()), validateIdentity: {})
            try await until {
                let values = try? await self.frames(output)
                return values?.contains { $0["id"] == .int(1) } == true
            }
            await session.finishInput()
            let all = try await frames(output)
            let terminal = try XCTUnwrap(all.firstIndex { $0["id"] == .int(1) })
            let notifications = all.enumerated().filter { $0.element["method"] == .string("notifications/progress") }
            XCTAssertGreaterThanOrEqual(notifications.count, 2)
            let counts = notifications.compactMap { $0.element["params"]?["progress"]?.doubleValue }
            XCTAssertEqual(counts.count, notifications.count)
            XCTAssertTrue(zip(counts, counts.dropFirst()).allSatisfy { pair in pair.0 < pair.1 })
            for note in notifications {
                XCTAssertLessThan(note.offset, terminal)
                XCTAssertEqual(note.element["params"]?["progressToken"], token)
                XCTAssertEqual(note.element["params"]?["total"], .int(9))
            }
        }

        let gate = MCPStartupGate()
        let server = MCPServer(startup: gate)
        let output = StartupOutput()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
            execute: { await server.handleMessageAsync($0) }, output: { await output.append($0) },
            progressSource: gate.status, progressIntervalNanoseconds: 1_000_000)
        await session.receive(try request("tools/call", id: .int(2), params: .object([
            "name": .string("info"), "arguments": .object(["waitForReadyMs": .int(50)])
        ])))
        await session.receive(try request("tools/call", id: nil, params: .object([
            "name": .string("info"), "arguments": .object(["waitForReadyMs": .int(50)]),
            "_meta": .object(["progressToken": .string("notification")])
        ])))
        await session.receive(try request("tools/call", id: .int(3), params: .object([
            "name": .string("info"), "arguments": .object(["waitForReadyMs": .int(50)]),
            "_meta": .object(["progressToken": .double(1.5)])
        ])))
        try await until { await output.values.count == 2 }
        await session.finishInput()
        let all = try await frames(output)
        XCTAssertFalse(all.contains { $0["method"] == .string("notifications/progress") })
    }

    func testWaitForReadyReturnsReadyInfo() async throws {
        let provider = BlockingStartupProvider()
        defer { provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        try await until { provider.hasEntered }
        let response = Task { try await tool(launched.server, arguments: ["waitForReadyMs": .int(5000)]) }
        provider.release.signal()
        let value = try payload(await response.value)
        XCTAssertEqual(value["analysis"]?["state"], .string("ready"))
        XCTAssertEqual(value["functionCount"], .int(1))
        XCTAssertEqual(value["instructionCount"], .int(2))
        await launched.analysis.value
    }

    func testAnalysisFailureIsTypedLoggedAndExitStatusOne() async throws {
        let provider = BlockingStartupProvider(throwsAfterHold: true)
        defer { provider.release.signal() }
        let log = StartupLogRecorder()
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider,
                                                        log: { log.append($0) })
        try await until { provider.hasEntered }
        provider.release.signal()
        await launched.analysis.value
        let response = try await tool(launched.server, "functions")
        let value = try payload(response)
        XCTAssertEqual(response["result"]?["isError"], .bool(true))
        XCTAssertEqual(value["error"], .string("analysisFailed"))
        XCTAssertEqual(value["reason"], .string("deliberate startup failure"))
        XCTAssertEqual(launched.gate.exitStatus, 1)
        XCTAssertNil(launched.gate.api)
        XCTAssertTrue(log.snapshot().contains { $0.hasPrefix("analysis failed") })
        XCTAssertEqual(launched.gate.status.snapshot().completedPhases, 2)
    }

    func testBinaryChangedDuringBackgroundAnalysisFails() async throws {
        let provider = BlockingStartupProvider(rewrite: true)
        defer { provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        try await until { provider.hasEntered }
        provider.release.signal()
        await launched.analysis.value
        XCTAssertEqual(launched.gate.status.snapshot().state, "failed")
        XCTAssertEqual(launched.gate.status.snapshot().reason, MCPLauncherError.binaryIdentityChanged.errorDescription)
        XCTAssertNil(launched.gate.api)
    }

    func testInfoSchemaBoundsWaitForReadyMs() async throws {
        let server = MCPServer(startup: MCPStartupGate())
        let response = try XCTUnwrap(server.handleMessage(try request("tools/list")))
        let tools = try ScriptValue.decode(response)["result"]?["tools"]?.arrayValue ?? []
        let info = try XCTUnwrap(tools.first { $0["name"] == .string("info") })
        let schema = info["inputSchema"]?["properties"]?["waitForReadyMs"]
        XCTAssertEqual(schema?["type"], .string("integer"))
        XCTAssertEqual(schema?["minimum"], .int(0))
        XCTAssertEqual(schema?["maximum"], .int(25000))
        for value in [ScriptValue.int(25001), .int(-1), .double(1.5), .string("1")] {
            let refused = try await tool(server, arguments: ["waitForReadyMs": value])
            XCTAssertEqual(refused["result"]?["isError"], .bool(true))
            XCTAssertNil(refused["error"])
        }
        let wrongTool = try await tool(server, "functions", arguments: ["waitForReadyMs": .int(0)])
        XCTAssertEqual(wrongTool["result"]?["isError"], .bool(true))
        let plainAPI = api(try input())
        let plain = MCPServer(api: plainAPI)
        let accepted = try await tool(plain, arguments: ["waitForReadyMs": .int(25000)])
        XCTAssertEqual(try payload(accepted), try plainAPI.execute("info"))
    }

    func testCancelRequestStopsAnalysisAtNextPhase() async throws {
        let provider = BlockingStartupProvider(phasesBeforeHold: [.load], phasesAfterHold: [.listing])
        defer { provider.release.signal() }
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider, log: { _ in })
        try await until { provider.hasEntered }
        launched.gate.status.requestCancel()
        provider.release.signal()
        await launched.analysis.value
        XCTAssertEqual(launched.gate.status.snapshot().state, "failed")
        XCTAssertEqual(launched.gate.status.snapshot().phase, .load)
        XCTAssertNil(launched.gate.api)
    }

    func testPhaseBreadcrumbLoggedOncePerNewPhase() async throws {
        let provider = BlockingStartupProvider(phasesBeforeHold: [.load, .decode, .decode, .functionDiscovery])
        defer { provider.release.signal() }
        let log = StartupLogRecorder()
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider,
                                                        log: { log.append($0) })
        try await until { provider.hasEntered }
        XCTAssertEqual(log.snapshot().filter { $0.hasPrefix("phase ") },
                       ["phase load", "phase decode", "phase functionDiscovery"])
        provider.release.signal()
        await launched.analysis.value

        let direct = StartupLogRecorder()
        let status = MCPStartupStatus(onNewPhase: { direct.append($0.rawValue) })
        for phase in [AnalysisPhase.load, .decode, .decode, .functionDiscovery] {
            status.report(.init(phase: phase, elapsed: .zero))
        }
        status.markReady()
        let settled = status.snapshot()
        status.report(.init(phase: .listing, elapsed: .zero))
        status.markFailed("too late")
        XCTAssertEqual(direct.snapshot(), ["load", "decode", "functionDiscovery"])
        XCTAssertEqual(status.snapshot().state, "ready")
        XCTAssertEqual(status.snapshot().completedPhases, 9)
        XCTAssertEqual(status.snapshot().elapsedMs, settled.elapsedMs)
    }

    func testPhaseDeliveryRemainsOrderedAcrossConcurrentReportsAndSettlement() {
        let log = StartupLogRecorder()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let done = DispatchGroup()
        let status = MCPStartupStatus(onNewPhase: { phase in
            log.append("begin \(phase.rawValue)")
            if phase == .load {
                entered.signal()
                _ = release.wait(timeout: .now() + 10)
            }
            log.append("end \(phase.rawValue)")
        })
        done.enter()
        DispatchQueue.global().async {
            status.report(.init(phase: .load, elapsed: .zero))
            done.leave()
        }
        defer { release.signal() }
        guard entered.wait(timeout: .now() + 5) == .success else {
            XCTFail("First phase callback did not start")
            return
        }
        status.report(.init(phase: .decode, elapsed: .zero))
        status.report(.init(phase: .load, elapsed: .zero))
        status.markReady()
        status.report(.init(phase: .listing, elapsed: .zero))
        XCTAssertEqual(log.snapshot(), ["begin load"])
        release.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(log.snapshot(), ["begin load", "end load", "begin decode", "end decode"])
        XCTAssertEqual(status.snapshot().phase, .decode)
        XCTAssertEqual(status.snapshot().state, "ready")
    }

    func testPhaseCallbackCanReportReentrantlyWithoutNestedDelivery() {
        let log = StartupLogRecorder()
        let reference = StartupStatusReference()
        let status = MCPStartupStatus(onNewPhase: { phase in
            log.append("begin \(phase.rawValue)")
            if phase == .load {
                reference.status?.report(.init(phase: .decode, elapsed: .zero))
                log.append("reentry returned")
            }
            log.append("end \(phase.rawValue)")
        })
        reference.status = status
        let done = DispatchGroup()
        done.enter()
        DispatchQueue.global().async {
            status.report(.init(phase: .load, elapsed: .zero))
            done.leave()
        }
        guard done.wait(timeout: .now() + 10) == .success else {
            XCTFail("Reentrant report did not complete")
            return
        }
        XCTAssertEqual(log.snapshot(), ["begin load", "reentry returned", "end load",
                                       "begin decode", "end decode"])
        XCTAssertEqual(status.snapshot().phase, .decode)
    }

    func testControlInitializeWithoutStartupUnchanged() throws {
        let server = MCPServer(api: api(try input()))
        let raw = try XCTUnwrap(server.handleMessage(try request("initialize")))
        let response = try ScriptValue.decode(raw)
        XCTAssertEqual(response["jsonrpc"], .string("2.0"))
        XCTAssertEqual(response["id"], .int(1))
        XCTAssertEqual(response["result"], .object([
            "protocolVersion": .string(MCPServer.protocolVersion),
            "capabilities": .object(["tools": .object([:])]),
            "serverInfo": .object(["name": .string("macscope"), "version": .string(MCPServer.serverVersion)]),
            "instructions": .string(MCPServer.sessionInstructions)
        ]))
        XCTAssertNil(response["result"]?["capabilities"]?["experimental"])
    }

    func testControlInfoWithoutStartupUnchanged() async throws {
        let plainAPI = api(try input())
        let server = MCPServer(api: plainAPI)
        let expected = try plainAPI.execute("info")
        let response = try await tool(server)
        let value = try payload(response)
        XCTAssertEqual(value, expected)
        XCTAssertNil(value["analysis"])
    }

    func testStartedProgressWriteDrainsBeforeCompletionOrCancellation() async throws {
        for cancel in [false, true] {
            let status = MCPStartupStatus()
            let work = StartupReleaseGate()
            let heldOutput = StartupReleaseGate()
            let output = StartupOutput()
            defer { Task { await work.release(); await heldOutput.release() } }
            let result = try ScriptValue.object([
                "jsonrpc": .string("2.0"), "id": .int(0), "result": .object(["ok": .bool(true)])
            ]).jsonData()
            let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
                execute: { data in
                    if (try? ScriptValue.decode(data)["method"]) == .string("ping") { return result }
                    await work.suspend()
                    return result
                },
                output: { data in
                    if try ScriptValue.decode(data)["method"] == .string("notifications/progress") {
                        await heldOutput.suspend()
                    }
                    await output.append(data)
                }, progressSource: status, progressIntervalNanoseconds: 1_000_000)
            await session.receive(try request("tools/call", params: .object([
                "name": .string("info"), "_meta": .object(["progressToken": .string("held")])
            ])))
            try await until { await heldOutput.hasStarted }
            let cancellation: Task<Void, Never>?
            if cancel {
                let cancelFrame = try request("notifications/cancelled", id: nil,
                                          params: .object(["requestId": .int(1)]))
                cancellation = Task { await session.receive(cancelFrame) }
            } else {
                cancellation = nil
                await work.release()
            }
            // Give the terminal path time to enter while the progress output is
            // deliberately held. This is an ordering fixture, not a speed gate.
            try await Task.sleep(nanoseconds: 100_000_000)
            let before = await output.values
            let retained = await session.inFlightCount
            XCTAssertTrue(before.isEmpty, "terminal output must not overtake held progress")
            XCTAssertEqual(retained, 1, "the request ID stays owned during the drain")
            await session.receive(try request("ping", id: .int(2)))
            try await until { await output.values.count == 1 }
            let unrelated = try await frames(output)
            XCTAssertEqual(unrelated[0]["id"], .int(2), "other responses must not wait on this drain")
            if cancel { status.report(.init(phase: .listing, elapsed: .zero)) }
            await heldOutput.release()
            await cancellation?.value
            try await until { await output.values.count == 3 }
            await work.release()
            await session.finishInput()
            let all = try await frames(output)
            XCTAssertEqual(all[1]["method"], .string("notifications/progress"))
            XCTAssertEqual(all[2]["id"], .int(1))
            if cancel { XCTAssertEqual(all[2]["error"]?["code"], .int(-32800)) }
            else { XCTAssertEqual(all[2]["result"]?["ok"], .bool(true)) }
            XCTAssertEqual(all.filter { $0["method"] == .string("notifications/progress") }.count, 1)
        }
    }

    func testFailedStartupSendsNoCompletionProgress() async throws {
        let gate = MCPStartupGate()
        gate.status.report(.init(phase: .decode, elapsed: .zero))
        let server = MCPServer(startup: gate)
        let output = StartupOutput()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
            execute: { await server.handleMessageAsync($0) }, output: { await output.append($0) },
            progressSource: gate.status, progressIntervalNanoseconds: 1_000_000)
        await session.receive(try request("tools/call", params: .object([
            "name": .string("info"), "arguments": .object(["waitForReadyMs": .int(5000)]),
            "_meta": .object(["progressToken": .string("failure")])
        ])))
        try await until { await output.values.count >= 1 }
        gate.fail("failed")
        try await until {
            let values = try? await self.frames(output)
            return values?.contains { $0["id"] == .int(1) } == true
        }
        await session.finishInput()
        let all = try await frames(output)
        let progress = all.filter { $0["method"] == .string("notifications/progress") }
        XCTAssertEqual(progress.count, 1)
        XCTAssertEqual(progress[0]["params"]?["progress"], .int(1))
        let reply = try XCTUnwrap(all.last)
        XCTAssertEqual(try payload(reply)["analysis"]?["state"], .string("failed"))
    }

    func testLateProgressAfterCancelIsDropped() async throws {
        let status = MCPStartupStatus()
        let work = StartupReleaseGate()
        defer { Task { await work.release() } }
        let output = StartupOutput()
        let result = try ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(0), "result": .object([:])
        ]).jsonData()
        let session = MCPRequestSession(configuration: .production, mutatingCommands: [],
            execute: { _ in await work.suspend(); return result },
            output: { await output.append($0) }, progressSource: status,
            progressIntervalNanoseconds: 1_000_000)
        await session.receive(try request("tools/call", params: .object([
            "name": .string("info"), "_meta": .object(["progressToken": .string("late")])
        ])))
        try await until { await output.values.count == 1 }
        await session.receive(try request("notifications/cancelled", id: nil,
                                         params: .object(["requestId": .int(1)])))
        status.report(.init(phase: .diagnostics, elapsed: .zero))
        try await Task.sleep(nanoseconds: 20_000_000)
        await work.release()
        await session.finishInput()
        let all = try await frames(output)
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(all[0]["method"], .string("notifications/progress"))
        XCTAssertEqual(all[0]["params"]?["progress"], .int(0))
        XCTAssertEqual(all[1]["error"]?["code"], .int(-32800))
    }
}

private final class BlockingFingerprinter: @unchecked Sendable {
    private let lock = NSLock()
    private let release = DispatchSemaphore(value: 0)
    private let heldCall: Int?
    private var calls: [Bool] = []
    private var holding = false
    private var timeout = false

    init(heldCall: Int? = nil) { self.heldCall = heldCall }
    func unblock() { release.signal() }
    var hasEnteredHold: Bool { lock.lock(); defer { lock.unlock() }; return holding }
    var timedOut: Bool { lock.lock(); defer { lock.unlock() }; return timeout }
    var mainThreadCalls: [Bool] { lock.lock(); defer { lock.unlock() }; return calls }

    func fingerprint(_ url: URL) throws -> WorkspaceScriptingAPI.CallArgumentAuditFileFingerprint {
        lock.lock()
        calls.append(Thread.isMainThread)
        let shouldHold = heldCall == calls.count
        if shouldHold { holding = true }
        lock.unlock()
        if shouldHold && release.wait(timeout: .now() + 10) == .timedOut {
            lock.lock(); timeout = true; lock.unlock()
            throw StartupTestError.deliberate
        }
        return try WorkspaceScriptingAPI.callArgumentAuditFileFingerprint(at: url)
    }
}

private final class StartupStateRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [MCPLaunchState] = []
    func append(_ value: MCPLaunchState) { lock.lock(); values.append(value); lock.unlock() }
    func snapshot() -> [MCPLaunchState] { lock.lock(); defer { lock.unlock() }; return values }
}

private struct WrongPathStartupProvider: AnalysisProviding {
    let rewrite: Bool
    func analyze(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                 cancellation: AnalysisCancellationToken) throws -> WorkspaceSnapshot {
        if rewrite { try Data("changed input with different size".utf8).write(to: url) }
        return BlockingStartupProvider.snapshot(url.appendingPathExtension("wrong"))
    }
    func openBinary(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                    cancellation: AnalysisCancellationToken) async throws -> WorkspaceSnapshot {
        try analyze(url: url, requestedSliceIndex: requestedSliceIndex, overrides: overrides,
                    cancellation: cancellation)
    }
}

extension MCPStartupTests {
    private func assertResponsiveFingerprintWindow(_ heldCall: Int) async throws {
        let fingerprinter = BlockingFingerprinter(heldCall: heldCall)
        defer { fingerprinter.unblock() }
        let provider = BlockingStartupProvider()
        // No provider wait is needed for this case: only the selected fingerprint is held.
        provider.release.signal()
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider,
            log: { _ in }, fingerprint: { try fingerprinter.fingerprint($0) })
        try await until { fingerprinter.hasEnteredHold }
        XCTAssertFalse(fingerprinter.timedOut)
        XCTAssertEqual(fingerprinter.mainThreadCalls, Array(repeating: false, count: heldCall))
        XCTAssertEqual(provider.hasEntered, heldCall == 2)
        XCTAssertNil(launched.gate.api)

        let output = StartupOutput()
        let session = launched.server.makeRequestSession(output: { await output.append($0) })
        for (index, method) in ["initialize", "ping", "tools/list"].enumerated() {
            await session.receive(try request(method, id: .int(Int64(index + 1))))
        }
        await session.receive(try request("tools/call", id: .int(4),
            params: .object(["name": .string("info"), "arguments": .object([:])])))
        try await until { await output.values.count == 4 }
        let replies = try await frames(output)
        for id in 1...4 {
            let reply = try XCTUnwrap(replies.first { $0["id"] == .int(Int64(id)) })
            XCTAssertNil(reply["error"])
            XCTAssertNotNil(reply["result"])
        }
        let initialize = try XCTUnwrap(replies.first { $0["id"] == .int(1) })
        let initialStatus = initialize["result"]?["capabilities"]?["experimental"]?["macscope/analysis"]
        XCTAssertEqual(initialStatus?["state"], .string("analyzing"))
        let infoReply = try XCTUnwrap(replies.first { $0["id"] == .int(4) })
        let info = try payload(infoReply)
        XCTAssertEqual(info["analysis"]?["state"], .string("analyzing"))
        XCTAssertEqual(info["analysis"]?["phase"], heldCall == 1 ? .null : .string("functionDiscovery"))
        XCTAssertEqual(info["analysis"]?["progress"]?.doubleValue, heldCall == 1 ? 0 : 2.0 / 9)
        XCTAssertFalse(fingerprinter.timedOut)
        XCTAssertNil(launched.gate.api)
        fingerprinter.unblock()
        try await until { launched.gate.status.isSettled }
        XCTAssertEqual(launched.gate.status.snapshot().state, "ready")
        XCTAssertEqual(fingerprinter.mainThreadCalls, [false, false])
        XCTAssertFalse(fingerprinter.timedOut)
        await session.finishInput()
    }

    func testFirstFingerprintDoesNotBlockReadinessRequests() async throws {
        // The XCTest host does not call dispatchMain; MainActor is the main thread here.
        try await assertResponsiveFingerprintWindow(1)
    }

    func testSecondFingerprintDoesNotBlockReadinessRequests() async throws {
        try await assertResponsiveFingerprintWindow(2)
    }

    func testExactlyTwoBackgroundFingerprintsReachReady() async throws {
        let fingerprinter = BlockingFingerprinter()
        let provider = BlockingStartupProvider()
        provider.release.signal()
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: provider,
            log: { _ in }, fingerprint: { try fingerprinter.fingerprint($0) })
        try await until { launched.gate.status.isSettled }
        XCTAssertEqual(fingerprinter.mainThreadCalls, [false, false])
        XCTAssertFalse(fingerprinter.timedOut)
        XCTAssertEqual(launched.gate.status.snapshot().state, "ready")
        let ready = try payload(await tool(launched.server))
        XCTAssertEqual(ready["functionCount"], .int(1))
    }

    func testChangedFingerprintWinsOverWrongAnalysisPath() async throws {
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(),
            engine: WrongPathStartupProvider(rewrite: true), log: { _ in })
        try await until { launched.gate.status.isSettled }
        XCTAssertEqual(launched.gate.status.snapshot().state, "failed")
        XCTAssertEqual(launched.gate.status.snapshot().reason,
                       MCPLauncherError.binaryIdentityChanged.errorDescription)
        XCTAssertNil(launched.gate.api)
    }

    func testWrongAnalysisPathAloneKeepsIdentityMismatchReason() async throws {
        let launched = MCPLauncher.startHeadlessSession(binaryURL: try input(),
            engine: WrongPathStartupProvider(rewrite: false), log: { _ in })
        try await until { launched.gate.status.isSettled }
        XCTAssertEqual(launched.gate.status.snapshot().state, "failed")
        XCTAssertEqual(launched.gate.status.snapshot().reason,
                       MCPLauncherError.analysisIdentityMismatch.errorDescription)
        XCTAssertNil(launched.gate.api)
    }

    func testLaunchStateSequenceForReadyAndAnalysisFailure() async throws {
        let readyStates = StartupStateRecorder()
        let readyProvider = BlockingStartupProvider()
        readyProvider.release.signal()
        let ready = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: readyProvider,
            log: { _ in }, onLaunchState: { readyStates.append($0) })
        try await until { ready.gate.status.isSettled }
        XCTAssertEqual(readyStates.snapshot(), [.fingerprinting, .analyzing(.load), .analyzing(.decode),
            .analyzing(.functionDiscovery), .verifying, .binding, .ready])

        let failedStates = StartupStateRecorder()
        let failedProvider = BlockingStartupProvider(throwsAfterHold: true)
        failedProvider.release.signal()
        let failed = MCPLauncher.startHeadlessSession(binaryURL: try input(), engine: failedProvider,
            log: { _ in }, onLaunchState: { failedStates.append($0) })
        try await until { failed.gate.status.isSettled }
        XCTAssertEqual(failedStates.snapshot(), [.fingerprinting, .analyzing(.load), .analyzing(.decode),
            .analyzing(.functionDiscovery), .failed])
    }
}
