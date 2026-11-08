import Foundation
import Synchronization
import Testing
import ExternalMCP
@testable import ProxymanInstallation
@testable import ProxymanIntegration

let applicationHash = String(repeating: "a", count: 40)
let bridgeHash = String(repeating: "b", count: 40)
let updatedBridgeHash = String(repeating: "c", count: 40)
let bridgeDigest = "8d0800fb7ed991889f709898c9d69159abd725031bcc17b728aa7622e60d4767"
let origin = Date(timeIntervalSince1970: 1_767_225_600)

actor Gate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
}

private enum ReadinessFailure: Error { case exhausted }

func waitFor(_ condition: @Sendable () async -> Bool) async throws {
    for check in 0..<5_000 {
        if await condition() { return }
        if check < 4_999 { await Task.yield() }
    }
    Issue.record("Readiness condition was not reached within 5,000 checks")
    throw ReadinessFailure.exhausted
}

final class FakeInstallation: ProxymanInstallationManaging {
    private struct State: Sendable {
        var calls: [String] = []
        var confirmedCDHashes: Set<String>
        var configuredReviewIDs: [UUID] = []
        var nextReview = 0
        var reviews: [UUID: ProxymanInstallationReview] = [:]
        var configuration = MCPConnectionConfiguration(
            executableURL: URL(fileURLWithPath: "/fake/mcp-server"),
            expectedExecutableSHA256: String(repeating: "0", count: 64))
        var configurationError: (any Error)?
        var approveError: (any Error)?
        var approveGate: Gate?
        var inspectGate: Gate?
    }

    private let authorityID = UUID()
    private let state: Mutex<State>

    init(trustedCDHashes: Set<String> = []) {
        state = Mutex(State(confirmedCDHashes: trustedCDHashes))
    }

    var calls: [String] { state.withLock { $0.calls } }
    var confirmedCDHashes: Set<String> { state.withLock { $0.confirmedCDHashes } }
    var configuredReviewIDs: [UUID] { state.withLock { $0.configuredReviewIDs } }

    func setConfiguration(_ configuration: MCPConnectionConfiguration) {
        state.withLock { $0.configuration = configuration }
    }
    func setConnectionConfigurationError(_ error: (any Error)?) {
        state.withLock { $0.configurationError = error }
    }
    func setApproveError(_ error: (any Error)?) { state.withLock { $0.approveError = error } }
    func setApproveGate(_ gate: Gate?) { state.withLock { $0.approveGate = gate } }
    func setInspectGate(_ gate: Gate?) { state.withLock { $0.inspectGate = gate } }

    func inspect(applicationURL: URL) async throws -> ProxymanInstallationReview {
        let (review, gate) = state.withLock { state in
            state.calls.append("inspect")
            state.nextReview += 1
            let id = UUID(uuidString: String(format: "00000000-0000-0000-0000-%012llx", Int64(state.nextReview)))!
            let review = ProxymanInstallationReview(
                id: id, applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"),
                bridgeURL: URL(fileURLWithPath: "/fake/Proxyman.app/Contents/MacOS/mcp-server"),
                bundleIdentifier: "com.proxyman.NSProxy", applicationVersion: "26.4.0",
                applicationBuild: "260400", signingTeamIdentifier: "3X57WP8E8V",
                applicationCDHash: applicationHash, bridgeCDHash: bridgeHash,
                bridgeSHA256: bridgeDigest, inspectedAt: origin,
                trust: state.confirmedCDHashes.contains(bridgeHash) ? .trusted : .confirmationRequired)
            state.reviews[id] = review
            return (review, state.inspectGate)
        }
        if let gate { await gate.wait() }
        return review
    }

    func approve(reviewID: UUID) async throws -> ApprovedProxymanInstallation {
        try await approve(reviewID: reviewID, confirming: false)
    }

    func confirmAndApprove(reviewID: UUID) async throws -> ApprovedProxymanInstallation {
        try await approve(reviewID: reviewID, confirming: true)
    }

    private func approve(reviewID: UUID, confirming: Bool) async throws -> ApprovedProxymanInstallation {
        let gate = state.withLock { state in
            state.calls.append(confirming ? "confirmAndApprove" : "approve")
            return state.approveGate
        }
        if let gate { await gate.wait() }
        return try state.withLock { state in
            if let error = state.approveError { throw error }
            guard let review = state.reviews[reviewID] else {
                throw ProxymanInstallationError.reviewExpired
            }
            if confirming { state.confirmedCDHashes.insert(review.bridgeCDHash) }
            guard state.confirmedCDHashes.contains(review.bridgeCDHash) else {
                throw ProxymanInstallationError.confirmationRequired
            }
            return ApprovedProxymanInstallation(review: review, authorityID: authorityID)
        }
    }

    func connectionConfiguration(for approval: ApprovedProxymanInstallation) async throws -> MCPConnectionConfiguration {
        try state.withLock { state in
            state.calls.append("connectionConfiguration")
            state.configuredReviewIDs.append(approval.review.id)
            if let error = state.configurationError { throw error }
            return state.configuration
        }
    }

    func validatedApplicationURL(for approval: ApprovedProxymanInstallation) async throws -> URL {
        approval.review.applicationURL
    }
}

final class FakeClient: ExternalMCPClient {
    private struct State: Sendable {
        var connectCalls = 0
        var disconnectCalls = 0
        var successfulConnections = 0
        var events: [String] = []
        var connectGate: Gate?
        var disconnectGate: Gate?
        var errors: [any Error] = []
        var live = MCPConnectionSnapshot(connectionID: nil, state: .disconnected)
    }
    private let state = Mutex(State())

    var connectCalls: Int { state.withLock { $0.connectCalls } }
    var disconnectCalls: Int { state.withLock { $0.disconnectCalls } }
    var events: [String] { state.withLock { $0.events } }
    func setConnectGate(_ gate: Gate?) { state.withLock { $0.connectGate = gate } }
    func setDisconnectGate(_ gate: Gate?) { state.withLock { $0.disconnectGate = gate } }
    func scriptConnectErrors(_ errors: [any Error]) { state.withLock { $0.errors = errors } }

    private static func connected(id: UUID) -> MCPConnectionSnapshot {
        MCPConnectionSnapshot(connectionID: id, state: .connected,
            serverName: "fixture", serverVersion: "1.0", protocolVersion: "2025-11-25",
            toolCatalogRevision: 0, diagnosticCode: nil)
    }

    func connect(configuration: MCPConnectionConfiguration) async throws -> MCPConnectionSnapshot {
        let (gate, error) = state.withLock { state in
            state.events.append("connect:start")
            state.connectCalls += 1
            let error: (any Error)? = state.errors.isEmpty ? nil : state.errors.removeFirst()
            return (state.connectGate, error)
        }
        if let gate { await gate.wait() }
        return try state.withLock { state in
            state.events.append("connect:end")
            if let error {
                state.live = MCPConnectionSnapshot(connectionID: nil, state: .disconnected)
                throw error
            }
            state.successfulConnections += 1
            let id = UUID(uuidString: String(format: "00000000-0000-0001-0000-%012llx", Int64(state.successfulConnections)))!
            let snapshot = Self.connected(id: id)
            state.live = snapshot
            return snapshot
        }
    }

    func disconnect() async {
        let gate = state.withLock { state in
            state.events.append("disconnect:start")
            state.disconnectCalls += 1
            return state.disconnectGate
        }
        if let gate { await gate.wait() }
        state.withLock { state in
            state.live = MCPConnectionSnapshot(connectionID: nil, state: .disconnected)
            state.events.append("disconnect:end")
        }
    }

    func snapshot() async -> MCPConnectionSnapshot { state.withLock { $0.live } }
    func markChildExited() {
        state.withLock { $0.live = MCPConnectionSnapshot(connectionID: nil, state: .disconnected) }
    }
    func replaceLiveConnection(id: UUID) { state.withLock { $0.live = Self.connected(id: id) } }
    func discoverTools() async throws -> [MCPToolDescriptor] { throw MCPClientError.notConnected }
    func invoke(tool: String, arguments: MCPJSONValue) async throws -> MCPToolOutcome {
        throw MCPClientError.notConnected
    }
}

struct TemporaryDirectory: Sendable {
    let url: URL
    init() throws {
        url = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    func remove() { try? FileManager.default.removeItem(at: url) }
}

final class TestClock: Sendable {
    private let instant = Mutex(origin)
    func now() -> Date { instant.withLock { $0 } }
    func set(_ offset: TimeInterval) { instant.withLock { $0 = origin.addingTimeInterval(offset) } }
}

final class RecordingEvaluator: CodeRequirementEvaluating {
    struct State: Sendable {
        var application = CodeSigningFacts(signingIdentifier: "com.proxyman.NSProxy",
            teamIdentifier: "3X57WP8E8V", cdhash: applicationHash,
            hardenedRuntime: true, isAdHoc: false, requirementSatisfied: true)
        var bridge = CodeSigningFacts(signingIdentifier: "mcp-server",
            teamIdentifier: "3X57WP8E8V", cdhash: bridgeHash,
            hardenedRuntime: true, isAdHoc: false, requirementSatisfied: true)
        var throwsForApplication = false
        var calls: [(URL, String)] = []
    }
    private let state = Mutex(State())
    func change(_ update: (inout State) -> Void) { state.withLock { update(&$0) } }
    func calls() -> [(URL, String)] { state.withLock { $0.calls } }
    func evaluate(codeAt url: URL, requirement: String) throws -> CodeSigningFacts {
        try state.withLock { state in
            state.calls.append((url, requirement))
            if url.pathExtension == "app" {
                if state.throwsForApplication { throw ProxymanInstallationError.invalidSignature }
                return state.application
            }
            return state.bridge
        }
    }
}

struct FakeApplication: Sendable {
    let base: URL
    let application: URL
    var bridge: URL { application.appendingPathComponent("Contents/MacOS/mcp-server") }

    init(identifier: String = "com.proxyman.NSProxy") throws {
        base = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        application = base.appendingPathComponent("Proxyman.app", isDirectory: true)
        let contents = application.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        do {
            for directory in [base, application, contents, macOS] {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                       attributes: [.posixPermissions: 0o755])
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
            }
            let info = ["CFBundleIdentifier": identifier, "CFBundleShortVersionString": "26.4.0",
                        "CFBundleVersion": "260400", "CFBundlePackageType": "APPL"]
            let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            try data.write(to: contents.appendingPathComponent("Info.plist"))
            try Data("fixture-bridge-v1".utf8).write(to: bridge)
            try setMode(0o755, at: bridge)
        } catch {
            try? FileManager.default.removeItem(at: base)
            throw error
        }
    }
    func setMode(_ mode: Int, at url: URL) throws {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }
    func remove() { try? FileManager.default.removeItem(at: base) }
}

func makeService(_ evaluator: RecordingEvaluator = RecordingEvaluator(),
                 store: any ProxymanBuildConfirmationStoring = InMemoryProxymanBuildConfirmationStore(),
                 clock: TestClock = .init()) -> ProxymanInstallationService {
    ProxymanInstallationService(evaluator: evaluator, store: store, now: { clock.now() })
}

func fixtureURL() throws -> URL {
    var directory = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
    for _ in 0..<6 {
        let candidate = directory.appendingPathComponent("MCPFixtureServer").resolvingSymlinksInPath()
        if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        directory.deleteLastPathComponent()
    }
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    let candidate = root.appendingPathComponent(".build/arm64-apple-macosx/debug/MCPFixtureServer").resolvingSymlinksInPath()
    if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
    let products = root.appendingPathComponent(".build/out/Products/Debug/MCPFixtureServer").resolvingSymlinksInPath()
    if FileManager.default.isExecutableFile(atPath: products.path) { return products }
    throw MCPClientError.invalidConfiguration
}

func fixtureConfiguration() async throws -> MCPConnectionConfiguration {
    let url = try fixtureURL()
    return MCPConnectionConfiguration(executableURL: url,
        expectedExecutableSHA256: try await MCPExecutableValidation.sha256(at: url), arguments: [])
}
