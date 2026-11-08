import Foundation
import ExternalMCP
import ProxymanInstallation

/// Launches lazily, coalesces concurrent callers into one launch, and serializes
/// connect with disconnect. Cleanup uses only this owner's client and its owned
/// child; it never launches or terminates the Proxyman application.
public actor ProxymanIntegrationOwner {
    public nonisolated let client: any ExternalMCPClient

    private let installation: any ProxymanInstallationManaging
    private let now: @Sendable () -> Date
    private var phase: ProxymanIntegrationPhase = .notApproved
    private var heldReview: ProxymanInstallationReview?
    private var approval: ApprovedProxymanInstallation?
    private var approvedReview: ProxymanInstallationReview?
    private var connection: MCPConnectionSnapshot?
    private var audit: ProxymanConnectionAudit?
    private var failure: ProxymanIntegrationError?
    private var epoch: UInt64 = 0
    private var ownsConnection = false
    private var launchTask: Task<ProxymanIntegrationSnapshot, any Error>?
    private var teardownTask: Task<Void, Never>?
    private var teardownID: UUID?
    private(set) var launchWaiterCount = 0

    public init(installation: any ProxymanInstallationManaging,
                client: any ExternalMCPClient,
                now: @escaping @Sendable () -> Date) {
        self.installation = installation
        self.client = client
        self.now = now
    }

    public func snapshot() -> ProxymanIntegrationSnapshot {
        ProxymanIntegrationSnapshot(phase: phase, review: heldReview,
                                    connection: connection, audit: audit, failure: failure)
    }

    public func inspect(applicationURL: URL) async throws -> ProxymanInstallationReview {
        guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
        do {
            let review = try await installation.inspect(applicationURL: applicationURL)
            guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
            heldReview = review
            return review
        } catch {
            guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
            throw integrationError(error)
        }
    }

    public func approve(reviewID: UUID, confirmingBuild: Bool) async throws {
        guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
        guard phase != .connecting, phase != .connected else {
            throw ProxymanIntegrationError.connectionActive
        }
        guard let review = heldReview, review.id == reviewID else {
            throw ProxymanIntegrationError.installation(.reviewExpired)
        }
        let approvalEpoch = epoch
        heldReview = nil
        let result: ApprovedProxymanInstallation
        do {
            if confirmingBuild {
                result = try await installation.confirmAndApprove(reviewID: reviewID)
            } else {
                result = try await installation.approve(reviewID: reviewID)
            }
        } catch {
            guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
            throw integrationError(error)
        }
        try requireApprovalCanComplete(epoch: approvalEpoch)
        approval = result
        approvedReview = review
        phase = .approved
        connection = nil
        audit = nil
        failure = nil
    }

    private func requireApprovalCanComplete(epoch expectedEpoch: UInt64) throws {
        guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
        guard epoch == expectedEpoch, phase != .connecting, phase != .connected else {
            throw ProxymanIntegrationError.connectionActive
        }
    }

    public func ensureConnected() async throws -> ProxymanIntegrationSnapshot {
        guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
        if let launchTask { return try await waitForLaunch(launchTask) }
        if phase == .connected {
            let live = await client.snapshot()
            guard phase != .shutDown else { throw ProxymanIntegrationError.shutDown }
            if let launchTask { return try await waitForLaunch(launchTask) }
            if phase == .connected {
                if live.state == .connected, live.connectionID == connection?.connectionID {
                    return snapshot()
                }
                phase = .approved
                connection = nil
                audit = nil
            }
        }
        guard let approval, let review = approvedReview else {
            throw ProxymanIntegrationError.notApproved
        }
        let launchEpoch = epoch
        // Capture only preceding teardown work. Reading the mutable task later
        // could pick up a teardown that is itself waiting for this launch.
        let precedingTeardown = teardownTask
        let task = Task {
            try await self.launch(approval: approval, review: review,
                                  epoch: launchEpoch, precedingTeardown: precedingTeardown)
        }
        launchTask = task
        phase = .connecting
        return try await waitForLaunch(task)
    }

    private func waitForLaunch(_ task: Task<ProxymanIntegrationSnapshot, any Error>) async throws
        -> ProxymanIntegrationSnapshot {
        launchWaiterCount += 1
        defer { launchWaiterCount -= 1 }
        // Awaiting a task's value does not cancel the shared task when this caller cancels.
        return try await task.value
    }

    private func launch(approval: ApprovedProxymanInstallation,
                        review: ProxymanInstallationReview, epoch launchEpoch: UInt64,
                        precedingTeardown: Task<Void, Never>?) async throws
        -> ProxymanIntegrationSnapshot {
        if let precedingTeardown { await precedingTeardown.value }
        do {
            try requireCurrentLaunch(launchEpoch)
            if ownsConnection {
                ownsConnection = false
                await client.disconnect()
                try requireCurrentLaunch(launchEpoch)
            }
            let configuration = try await installation.connectionConfiguration(for: approval)
            try requireCurrentLaunch(launchEpoch)
            let connected = try await client.connect(configuration: configuration)
            try requireCurrentLaunch(launchEpoch)
            ownsConnection = true
            phase = .connected
            connection = connected
            audit = ProxymanConnectionAudit(
                connectionID: connected.connectionID,
                applicationVersion: review.applicationVersion,
                applicationBuild: review.applicationBuild,
                applicationCDHash: review.applicationCDHash,
                bridgeCDHash: review.bridgeCDHash,
                bridgeSHA256: review.bridgeSHA256,
                connectedAt: now())
            failure = nil
            launchTask = nil
            return snapshot()
        } catch {
            guard epoch == launchEpoch else { throw ProxymanIntegrationError.cancelled }
            let mapped = integrationError(error)
            phase = .failed
            failure = mapped
            launchTask = nil
            throw mapped
        }
    }

    private func requireCurrentLaunch(_ expectedEpoch: UInt64) throws {
        guard epoch == expectedEpoch else { throw ProxymanIntegrationError.cancelled }
    }

    public func disconnect() async {
        guard phase != .shutDown else {
            if let teardownTask { await teardownTask.value }
            return
        }
        let task = beginTeardown(shuttingDown: false)
        if let task { await task.value }
    }

    /// The application's termination handler must await this before exiting.
    public func shutdown() async {
        guard phase != .shutDown else {
            if let teardownTask { await teardownTask.value }
            return
        }
        let task = beginTeardown(shuttingDown: true)
        if let task { await task.value }
    }

    private func beginTeardown(shuttingDown: Bool) -> Task<Void, Never>? {
        epoch &+= 1
        let detachedLaunch = launchTask
        detachedLaunch?.cancel()
        launchTask = nil
        let needsDisconnect = detachedLaunch != nil || ownsConnection
        // Transfer ownership before suspending so concurrent stops share the work.
        ownsConnection = false
        if shuttingDown {
            approval = nil
            approvedReview = nil
            heldReview = nil
            phase = .shutDown
        } else {
            phase = approval == nil ? .notApproved : .approved
        }
        connection = nil
        audit = nil
        failure = nil
        let precedingTeardown = teardownTask
        guard needsDisconnect else { return precedingTeardown }
        let id = UUID()
        let task = Task {
            if let precedingTeardown { await precedingTeardown.value }
            if let detachedLaunch { _ = await detachedLaunch.result }
            await self.client.disconnect()
            self.finishTeardown(id: id)
        }
        teardownID = id
        teardownTask = task
        return task
    }

    private func finishTeardown(id: UUID) {
        guard teardownID == id else { return }
        teardownTask = nil
        teardownID = nil
    }
}
