import Foundation
import Darwin

final class MCPStartupStatus: @unchecked Sendable {
    struct Snapshot: Sendable {
        let state: String
        let phase: AnalysisPhase?
        let completedPhases: Int
        let elapsedMs: Int64
        let reason: String?
    }
    private let lock = NSLock()
    private let started = ContinuousClock.now
    private let onNewPhase: (@Sendable (AnalysisPhase) -> Void)?
    private var state = "analyzing"
    private var phase: AnalysisPhase?
    private var pendingPhases: [AnalysisPhase] = []
    private var isDeliveringPhase = false
    private var completedPhases = 0
    private var frozenElapsed: Int64?
    private var reason: String?
    private var cancelled = false

    init(onNewPhase: (@Sendable (AnalysisPhase) -> Void)? = nil) {
        self.onNewPhase = onNewPhase
    }

    private func elapsed() -> Int64 {
        let parts = (ContinuousClock.now - started).components
        let milliseconds = Double(parts.seconds) * 1_000 + Double(parts.attoseconds) / 1e15
        return Int64(min(max(milliseconds, 0), Double(Int64.max - 1_024)))
    }

    func report(_ progress: AnalysisProgress) {
        lock.lock()
        guard state == "analyzing", phase == nil || progress.phase.ordinal > phase!.ordinal else {
            lock.unlock()
            return
        }
        phase = progress.phase
        completedPhases = max(completedPhases, min(max(progress.phase.ordinal - 1, 0), 8))
        pendingPhases.append(progress.phase)
        guard !isDeliveringPhase else { lock.unlock(); return }
        isDeliveringPhase = true
        lock.unlock()
        // One reporter drains outside the state lock; reentrant and concurrent reporters
        // enqueue without waiting. Already-admitted callbacks can outlive settlement.
        while true {
            lock.lock()
            guard !pendingPhases.isEmpty else {
                isDeliveringPhase = false
                lock.unlock()
                return
            }
            let next = pendingPhases.removeFirst()
            lock.unlock()
            onNewPhase?(next)
        }
    }

    func markReady() {
        lock.lock()
        defer { lock.unlock() }
        guard state == "analyzing" else { return }
        state = "ready"
        completedPhases = 9
        frozenElapsed = elapsed()
    }

    func markFailed(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        guard state == "analyzing" else { return }
        state = "failed"
        reason = message
        frozenElapsed = elapsed()
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(state: state, phase: phase, completedPhases: completedPhases,
                        elapsedMs: frozenElapsed ?? elapsed(), reason: reason)
    }

    var isSettled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state != "analyzing"
    }

    func requestCancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelRequested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

@MainActor
final class MCPStartupGate {
    let status: MCPStartupStatus
    private(set) var api: WorkspaceScriptingAPI?
    private var identity: (@MainActor () throws -> Void)?

    init(status: MCPStartupStatus = MCPStartupStatus()) { self.status = status }

    func install(api: WorkspaceScriptingAPI, validateIdentity: @escaping @MainActor () throws -> Void) {
        guard !status.isSettled else { return }
        self.api = api
        identity = validateIdentity
        status.markReady()
    }

    func fail(_ reason: String) { status.markFailed(reason) }
    func validateIdentity() throws { try identity?() }
    var exitStatus: Int32 { status.snapshot().state == "failed" ? 1 : 0 }

    func analysisValue() -> ScriptValue {
        let value = status.snapshot()
        var fields: [String: ScriptValue] = [
            "state": .string(value.state),
            "phase": value.phase.map { .string($0.rawValue) } ?? .null,
            "progress": .double(Double(value.completedPhases) / 9),
            "elapsedMs": .int(value.elapsedMs)
        ]
        if value.state == "failed", let reason = value.reason { fields["reason"] = .string(reason) }
        return .object(fields)
    }

    static func ready(api: WorkspaceScriptingAPI,
                      validateIdentity: @escaping @MainActor () throws -> Void = {}) -> MCPStartupGate {
        let gate = MCPStartupGate()
        gate.install(api: api, validateIdentity: validateIdentity)
        return gate
    }

    func waitUntilSettled(maximumMilliseconds: Int64) async {
        let end = ContinuousClock.now + .milliseconds(min(max(maximumMilliseconds, 0), 25_000))
        while !status.isSettled && !Task.isCancelled {
            let remaining = end - ContinuousClock.now
            guard remaining > .zero else { return }
            do { try await Task.sleep(for: min(remaining, .milliseconds(50))) }
            catch { return }
        }
    }
}

enum MCPStartupLog {
    static func line(_ text: String) {
        let bytes = Data(("MacScope MCP: " + text + "\n").utf8)
        bytes.withUnsafeBytes { buffer in
            _ = Darwin.write(STDERR_FILENO, buffer.baseAddress!, buffer.count)
        }
    }
}
