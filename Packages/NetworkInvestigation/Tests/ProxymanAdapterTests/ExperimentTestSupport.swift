import Foundation
import ExternalMCP
import NetworkEvidenceCore
import Synchronization
@testable import ProxymanAdapter

final class ExperimentClock: Sendable {
    private let value = Mutex(SyntheticProxymanFixture.now)
    func now() -> Date { value.withLock { $0 } }
    func advance(_ seconds: TimeInterval) { value.withLock { $0 = $0.addingTimeInterval(seconds) } }
}

actor ExperimentClient: ExternalMCPClient {
    enum CreationMode: Sendable { case normal, unlisted, arrayEnvelope, disabled, otherHost, wrongKind }
    let inner: SyntheticProxymanClient
    private var mode: CreationMode = .normal
    private var issuedRuleID = "new-rule"
    private var rules: [MCPJSONValue] = []

    init(inner: SyntheticProxymanClient) { self.inner = inner }
    func connect(configuration: MCPConnectionConfiguration) async throws -> MCPConnectionSnapshot {
        try await inner.connect(configuration: configuration)
    }
    func discoverTools() async throws -> [MCPToolDescriptor] { try await inner.discoverTools() }
    func snapshot() async -> MCPConnectionSnapshot { await inner.snapshot() }
    func disconnect() async { await inner.disconnect() }
    func invoke(tool: String, arguments: MCPJSONValue) async throws -> MCPToolOutcome {
        let outcome = try await inner.invoke(tool: tool, arguments: arguments)
        guard tool == "create_blacklist", !outcome.isError, outcome.textContent.isEmpty else { return outcome }
        let rule: MCPJSONValue = .object([
            "id": .string(issuedRuleID), "kind": .string(mode == .wrongKind ? "breakpoint" : "blacklist"),
            "enabled": .bool(mode != .disabled),
            "url": mode == .otherHost ? .string("https://other.example.test/v1/features") : (arguments.pObject?["url"] ?? .null)
        ])
        if mode != .unlisted && mode != .arrayEnvelope {
            rules.append(rule)
            await pushRules()
        }
        return .init(connectionID: outcome.connectionID, toolName: tool,
            structuredContent: mode == .arrayEnvelope ? .array([rule]) : .object(["rule": rule]))
    }
    func preloadRule(id: String, kind: String, enabled: Bool, host: String) async {
        rules.append(.object(["id": .string(id), "kind": .string(kind), "enabled": .bool(enabled),
            "url": .string("https://\(host)/v1/features")]))
        await pushRules()
    }
    func setRuleEnabled(id: String, _ enabled: Bool?) async {
        rules = rules.map { rule in
            guard var row = rule.pObject, row["id"]?.pString == id else { return rule }
            row["enabled"] = enabled.map { .bool($0) }
            return .object(row)
        }
        await pushRules()
    }
    func removeRule(id: String) async {
        rules.removeAll { $0.pObject?["id"]?.pString == id }
        await pushRules()
    }
    func setIssuedRuleID(_ id: String) { issuedRuleID = id }
    func setMode(_ mode: CreationMode) { self.mode = mode }
    private func pushRules() async { await inner.setPayload("list_rules", .object(["rules": .array(rules)])) }
}

enum ExperimentAuditEvent: Equatable, Sendable {
    case intent(ProxymanExperimentProposal, clientCalls: Int)
    case outcome(ProxymanExperimentRecord, clientCalls: Int)
}

actor RecordingAuditSink: ProxymanExperimentAuditing {
    private enum AuditError: Error { case unavailable }
    private let inner: SyntheticProxymanClient
    private var recorded: [ExperimentAuditEvent] = []
    private var intentFails = false
    init(inner: SyntheticProxymanClient) { self.inner = inner }
    func recordIntent(_ proposal: ProxymanExperimentProposal) async throws {
        if intentFails { throw AuditError.unavailable }
        let count = await inner.calls().count
        recorded.append(.intent(proposal, clientCalls: count))
    }
    func recordOutcome(_ record: ProxymanExperimentRecord) async {
        let count = await inner.calls().count
        recorded.append(.outcome(record, clientCalls: count))
    }
    func events() async -> [ExperimentAuditEvent] { recorded }
    func failIntent(_ fail: Bool) { intentFails = fail }
}

struct ExperimentHarness: Sendable {
    static let action = ProxymanExperimentAction.blockEndpoint(endpoint: "https://api.example.test/v1/features", method: "GET")
    let client: ExperimentClient
    let clock: ExperimentClock
    let audit: RecordingAuditSink
    let adapter: ProxymanAdapter
    let controller: ProxymanExperimentController
    init(enabled: Bool = false) {
        let inner = SyntheticProxymanClient()
        let client = ExperimentClient(inner: inner)
        let clock = ExperimentClock()
        let audit = RecordingAuditSink(inner: inner)
        let adapter = ProxymanAdapter(client: client, now: { clock.now() })
        self.client = client; self.clock = clock; self.audit = audit; self.adapter = adapter
        controller = ProxymanExperimentController(adapter: adapter, enabled: enabled, audit: audit, now: { clock.now() })
    }
    func proposal(scope: ProxymanReadScope) async throws -> ProxymanExperimentProposal {
        try await controller.propose(action: Self.action, scope: scope)
    }
    func approved(scope: ProxymanReadScope) async throws -> (ProxymanExperimentProposal, ApprovedProxymanExperiment) {
        let proposal = try await proposal(scope: scope)
        let approval = try await controller.approve(proposalID: proposal.id, reviewedArgumentsSHA256: proposal.argumentsSHA256)
        return (proposal, approval)
    }
    func executed(scope: ProxymanReadScope) async throws -> ProxymanExperimentRecord {
        let (_, approval) = try await approved(scope: scope)
        return try await controller.execute(approval)
    }
    func replaceBlacklistSchema(_ schema: MCPJSONValue) async {
        let tools = await client.inner.catalog().filter { $0.name != "create_blacklist" }
        await client.inner.setTools(tools + [SyntheticProxymanFixture.descriptor("create_blacklist", schema: schema)])
    }
}

actor ReviewAuthorizationGate {
    private var continuation: CheckedContinuation<Bool, Never>?
    private var arrival: CheckedContinuation<Void, Never>?
    private var arrived = false

    func validate() async -> Bool {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            arrived = true
            arrival?.resume(); arrival = nil
        }
    }
    func waitUntilArrived() async {
        if arrived { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release(_ allowed: Bool) {
        continuation?.resume(returning: allowed); continuation = nil
    }
}
