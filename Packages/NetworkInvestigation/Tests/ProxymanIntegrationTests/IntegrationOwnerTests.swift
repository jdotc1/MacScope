import Foundation
import Synchronization
import Testing
import Darwin
import ExternalMCP
@testable import ProxymanInstallation
@testable import ProxymanIntegration

private final class CompletionFlag: Sendable {
    private let value = Mutex(false)
    var isSet: Bool { value.withLock { $0 } }
    func set() { value.withLock { $0 = true } }
}

private struct Boom: Error {}

@Suite(.serialized)
struct IntegrationOwnerTests {
    private func makeOwner(trusted: Bool = true) -> (ProxymanIntegrationOwner, FakeInstallation, FakeClient) {
        let installation = FakeInstallation(trustedCDHashes: trusted ? ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] : [])
        let client = FakeClient()
        let owner = ProxymanIntegrationOwner(installation: installation, client: client,
                                            now: { Date(timeIntervalSince1970: 1_767_225_600) })
        return (owner, installation, client)
    }

    @discardableResult
    private func approve(_ owner: ProxymanIntegrationOwner, confirming: Bool = false) async throws -> ProxymanInstallationReview {
        let review = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        try await owner.approve(reviewID: review.id, confirmingBuild: confirming)
        return review
    }

    @Test func constructionDoesNotInspectOrLaunch() async {
        let (owner, installation, client) = makeOwner(trusted: false)
        let snapshot = await owner.snapshot()
        #expect(snapshot == ProxymanIntegrationSnapshot(phase: .notApproved, review: nil, connection: nil, audit: nil, failure: nil))
        #expect(client.connectCalls == 0)
        #expect(client.disconnectCalls == 0)
        #expect(installation.calls == [])
    }

    @Test func inspectionReplacesOnlyHeldReview() async throws {
        let (owner, installation, client) = makeOwner()
        let first = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        #expect(first.id == UUID(uuidString: "00000000-0000-0000-0000-000000000001"))
        #expect(await owner.snapshot().review == first)
        #expect(await owner.snapshot().phase == .notApproved)
        let second = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        #expect(second.id == UUID(uuidString: "00000000-0000-0000-0000-000000000002"))
        #expect(await owner.snapshot().review == second)
        #expect(await owner.snapshot().phase == .notApproved)
        #expect(installation.calls == ["inspect", "inspect"])
        #expect(client.connectCalls == 0)
    }

    @Test func unknownReviewDoesNotConsumeHeldReview() async throws {
        let (owner, installation, _) = makeOwner()
        let review = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        await #expect(throws: ProxymanIntegrationError.installation(.reviewExpired)) {
            try await owner.approve(reviewID: UUID(uuidString: "00000000-0000-0000-0000-0000000000FF")!, confirmingBuild: true)
        }
        #expect(await owner.snapshot().review == review)
        #expect(installation.calls == ["inspect"])
    }

    @Test func confirmationConsumesReviewAndRemembersBuild() async throws {
        let (owner, installation, _) = makeOwner(trusted: false)
        let first = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        await #expect(throws: ProxymanIntegrationError.installation(.confirmationRequired)) {
            try await owner.approve(reviewID: first.id, confirmingBuild: false)
        }
        #expect(await owner.snapshot().phase == .notApproved)
        #expect(await owner.snapshot().review == nil)
        #expect(installation.confirmedCDHashes.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == false)
        try await approve(owner, confirming: true)
        #expect(await owner.snapshot().phase == .approved)
        #expect(await owner.snapshot().review == nil)
        #expect(installation.confirmedCDHashes.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == true)
        #expect(installation.calls == ["inspect", "approve", "inspect", "confirmAndApprove"])
    }

    @Test func trustedBuildApprovesWithoutConfirmation() async throws {
        let (owner, installation, _) = makeOwner()
        let review = try await approve(owner)
        #expect(review.trust == .trusted)
        #expect(await owner.snapshot().phase == .approved)
        #expect(installation.calls == ["inspect", "approve"])
    }

    @Test func connectionRequiresApproval() async throws {
        let (owner, _, client) = makeOwner()
        await #expect(throws: ProxymanIntegrationError.notApproved) { try await owner.ensureConnected() }
        #expect(client.connectCalls == 0)
        #expect(await owner.snapshot().phase == .notApproved)
        _ = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        await #expect(throws: ProxymanIntegrationError.notApproved) { try await owner.ensureConnected() }
        #expect(client.connectCalls == 0)
        #expect(await owner.snapshot().phase == .notApproved)
    }

    @Test func firstUseLaunchesLazilyAndRecordsExactAudit() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        #expect(client.connectCalls == 0)
        #expect(await owner.snapshot().phase == .approved)
        let snapshot = try await owner.ensureConnected()
        #expect(snapshot.phase == .connected)
        #expect(snapshot.connection == MCPConnectionSnapshot(
            connectionID: UUID(uuidString: "00000000-0000-0001-0000-000000000001"), state: .connected,
            serverName: "fixture", serverVersion: "1.0", protocolVersion: "2025-11-25", toolCatalogRevision: 0, diagnosticCode: nil))
        #expect(snapshot.audit == ProxymanConnectionAudit(
            connectionID: UUID(uuidString: "00000000-0000-0001-0000-000000000001"),
            applicationVersion: "26.4.0", applicationBuild: "260400",
            applicationCDHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            bridgeCDHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            bridgeSHA256: "8d0800fb7ed991889f709898c9d69159abd725031bcc17b728aa7622e60d4767",
            connectedAt: Date(timeIntervalSince1970: 1_767_225_600)))
        #expect(installation.calls == ["inspect", "approve", "connectionConfiguration"])
        #expect(client.connectCalls == 1)
        #expect(client.events == ["connect:start", "connect:end"])
    }

    @Test func healthyConnectionReturnsStoredSnapshot() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        let first = try await owner.ensureConnected()
        let second = try await owner.ensureConnected()
        #expect(second == first)
        #expect(client.connectCalls == 1)
        #expect(installation.calls == ["inspect", "approve", "connectionConfiguration"])
        #expect(installation.calls.count == 3)
    }

    @Test func simultaneousCallersShareOneLaunch() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        let gate = Gate()
        client.setConnectGate(gate)
        let tasks = (0..<5).map { _ in Task { try await owner.ensureConnected() } }
        do {
            try await waitFor { client.events.contains("connect:start") }
            try await waitFor { await owner.launchWaiterCount == 5 }
        } catch { await gate.open(); throw error }
        await gate.open()
        var results: [ProxymanIntegrationSnapshot] = []
        for task in tasks { results.append(try await task.value) }
        #expect(results.count == 5)
        for result in results {
            #expect(result == results[0])
            #expect(result.phase == .connected)
            #expect(result.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000001"))
        }
        #expect(client.connectCalls == 1)
        #expect(installation.calls.filter { $0 == "connectionConfiguration" }.count == 1)
        #expect(client.events == ["connect:start", "connect:end"])
    }

    @Test func failedSharedLaunchCanBeRetried() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        let gate = Gate()
        client.setConnectGate(gate)
        client.scriptConnectErrors([MCPClientError.deadlineExceeded])
        let tasks = (0..<3).map { _ in Task { try await owner.ensureConnected() } }
        do {
            try await waitFor { client.events.contains("connect:start") }
            try await waitFor { await owner.launchWaiterCount == 3 }
        } catch { await gate.open(); throw error }
        await gate.open()
        for task in tasks {
            await #expect(throws: ProxymanIntegrationError.client(.deadlineExceeded)) { try await task.value }
        }
        #expect(client.connectCalls == 1)
        let failed = await owner.snapshot()
        #expect(failed.phase == .failed)
        #expect(failed.failure == .client(.deadlineExceeded))
        #expect(failed.connection == nil)
        #expect(failed.audit == nil)
        #expect(client.disconnectCalls == 0)
        let retried = try await owner.ensureConnected()
        #expect(retried.phase == .connected)
        #expect(retried.failure == nil)
        #expect(client.connectCalls == 2)
        #expect(client.disconnectCalls == 0)
    }

    @Test func launchErrorsAreMappedAtBoundary() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        installation.setConnectionConfigurationError(ProxymanInstallationError.installationChanged)
        await #expect(throws: ProxymanIntegrationError.installation(.installationChanged)) { try await owner.ensureConnected() }
        #expect(client.connectCalls == 0)
        #expect(await owner.snapshot().phase == .failed)
        let (cancelledOwner, _, cancelledClient) = makeOwner()
        try await approve(cancelledOwner)
        cancelledClient.scriptConnectErrors([CancellationError()])
        await #expect(throws: ProxymanIntegrationError.cancelled) { try await cancelledOwner.ensureConnected() }
        let (unexpectedOwner, _, unexpectedClient) = makeOwner()
        try await approve(unexpectedOwner)
        unexpectedClient.scriptConnectErrors([Boom()])
        await #expect(throws: ProxymanIntegrationError.unexpected) { try await unexpectedOwner.ensureConnected() }
    }

    @Test func disconnectKeepsApprovalAndNextUseRelaunches() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        _ = try await owner.ensureConnected()
        await owner.disconnect()
        #expect(client.disconnectCalls == 1)
        let disconnected = await owner.snapshot()
        #expect(disconnected.phase == .approved)
        #expect(disconnected.connection == nil)
        #expect(disconnected.audit == nil)
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end"])
        let reconnected = try await owner.ensureConnected()
        #expect(reconnected.phase == .connected)
        #expect(reconnected.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000002"))
        #expect(reconnected.audit?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000002"))
        #expect(client.connectCalls == 2)
        #expect(client.disconnectCalls == 1)
        #expect(installation.calls.filter { $0 == "connectionConfiguration" }.count == 2)
    }

    @Test func disconnectWaitsForStaleLaunchAndPublishesNothing() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        let gate = Gate()
        client.setConnectGate(gate)
        let launch = Task { try await owner.ensureConnected() }
        do { try await waitFor { client.events.contains("connect:start") } }
        catch { await gate.open(); throw error }
        let finished = CompletionFlag()
        let teardown = Task { await owner.disconnect(); finished.set() }
        do { try await waitFor { await owner.snapshot().phase == .approved } }
        catch { await gate.open(); await teardown.value; throw error }
        #expect(client.events == ["connect:start"])
        #expect(finished.isSet == false)
        await gate.open()
        await #expect(throws: ProxymanIntegrationError.cancelled) { try await launch.value }
        await teardown.value
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end"])
        #expect(client.disconnectCalls == 1)
        let snapshot = await owner.snapshot()
        #expect(snapshot.phase == .approved)
        #expect(snapshot.connection == nil)
        #expect(snapshot.audit == nil)
        #expect(snapshot.failure == nil)
    }

    @Test func nextLaunchWaitsForPendingDisconnect() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        _ = try await owner.ensureConnected()
        let gate = Gate()
        client.setDisconnectGate(gate)
        let teardown = Task { await owner.disconnect() }
        do { try await waitFor { client.events.contains("disconnect:start") } }
        catch { await gate.open(); await teardown.value; throw error }
        let launch = Task { try await owner.ensureConnected() }
        do { try await waitFor { await owner.snapshot().phase == .connecting } }
        catch { await gate.open(); await teardown.value; throw error }
        #expect(client.connectCalls == 1)
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start"])
        await gate.open()
        await teardown.value
        let result = try await launch.value
        #expect(result.phase == .connected)
        #expect(result.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000002"))
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end", "connect:start", "connect:end"])
        #expect(client.connectCalls == 2)
    }

    @Test func exitedChildIsCleanedBeforeRelaunch() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        _ = try await owner.ensureConnected()
        client.markChildExited()
        let result = try await owner.ensureConnected()
        #expect(result.phase == .connected)
        #expect(result.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000002"))
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end", "connect:start", "connect:end"])
        #expect(client.disconnectCalls == 1)
        #expect(client.connectCalls == 2)
    }

    @Test func shutdownIsTerminalAndIdempotent() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        _ = try await owner.ensureConnected()
        await owner.shutdown()
        #expect(client.disconnectCalls == 1)
        #expect(await owner.snapshot() == ProxymanIntegrationSnapshot(phase: .shutDown, review: nil, connection: nil, audit: nil, failure: nil))
        await #expect(throws: ProxymanIntegrationError.shutDown) { try await owner.ensureConnected() }
        await #expect(throws: ProxymanIntegrationError.shutDown) {
            try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        }
        await #expect(throws: ProxymanIntegrationError.shutDown) {
            try await owner.approve(reviewID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, confirmingBuild: false)
        }
        #expect(client.connectCalls == 1)
        #expect(installation.calls == ["inspect", "approve", "connectionConfiguration"])
        await owner.shutdown()
        await owner.disconnect()
        #expect(client.disconnectCalls == 1)
    }

    @Test func shutdownWaitsForStaleLaunch() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        let gate = Gate()
        client.setConnectGate(gate)
        let launch = Task { try await owner.ensureConnected() }
        do { try await waitFor { client.events.contains("connect:start") } }
        catch { await gate.open(); throw error }
        let finished = CompletionFlag()
        let teardown = Task { await owner.shutdown(); finished.set() }
        do { try await waitFor { await owner.snapshot().phase == .shutDown } }
        catch { await gate.open(); await teardown.value; throw error }
        #expect(client.events == ["connect:start"])
        #expect(finished.isSet == false)
        await gate.open()
        await #expect(throws: ProxymanIntegrationError.cancelled) { try await launch.value }
        await teardown.value
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end"])
        #expect(client.disconnectCalls == 1)
        #expect(await owner.snapshot().phase == .shutDown)
        await #expect(throws: ProxymanIntegrationError.shutDown) { try await owner.ensureConnected() }
    }

    @Test func shutdownWithoutOwnedConnectionMakesNoClientCall() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        await owner.shutdown()
        #expect(client.disconnectCalls == 0)
        #expect(await owner.snapshot().phase == .shutDown)
        let (failedOwner, _, failedClient) = makeOwner()
        try await approve(failedOwner)
        failedClient.scriptConnectErrors([MCPClientError.untrustedExecutable])
        await #expect(throws: ProxymanIntegrationError.client(.untrustedExecutable)) { try await failedOwner.ensureConnected() }
        await failedOwner.shutdown()
        #expect(failedClient.disconnectCalls == 0)
        #expect(await failedOwner.snapshot().phase == .shutDown)
    }

    @Test func cancellingOneWaiterDoesNotCancelSharedLaunch() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        let gate = Gate()
        client.setConnectGate(gate)
        let first = Task { try await owner.ensureConnected() }
        let second = Task { try await owner.ensureConnected() }
        do {
            try await waitFor { client.events.contains("connect:start") }
            try await waitFor { await owner.launchWaiterCount == 2 }
        } catch { await gate.open(); throw error }
        first.cancel()
        await gate.open()
        let firstResult = try await first.value
        let secondResult = try await second.value
        #expect(firstResult.phase == .connected)
        #expect(secondResult.phase == .connected)
        #expect(client.connectCalls == 1)
        #expect(client.disconnectCalls == 0)
    }

    @Test func connectedApprovalIsRejectedWithoutConsumingReview() async throws {
        let (owner, installation, _) = makeOwner()
        try await approve(owner)
        _ = try await owner.ensureConnected()
        let review = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        await #expect(throws: ProxymanIntegrationError.connectionActive) {
            try await owner.approve(reviewID: review.id, confirmingBuild: true)
        }
        #expect(await owner.snapshot().review == review)
        #expect(await owner.snapshot().phase == .connected)
        #expect(installation.calls == ["inspect", "approve", "connectionConfiguration", "inspect"])
        await owner.disconnect()
        try await owner.approve(reviewID: review.id, confirmingBuild: true)
        #expect(await owner.snapshot().phase == .approved)
        #expect(await owner.snapshot().review == nil)
    }

    @Test func realShutdownEndsOnlyOwnedBridgeChild() async throws {
        let installation = FakeInstallation()
        installation.setConfiguration(try await fixtureConfiguration())
        let client = SDKExternalMCPClient()
        let owner = ProxymanIntegrationOwner(installation: installation, client: client,
                                            now: { Date(timeIntervalSince1970: 1_767_225_600) })
        let decoy = Process()
        decoy.executableURL = URL(fileURLWithPath: "/bin/sleep")
        decoy.arguments = ["30"]
        try decoy.run()
        defer { if decoy.isRunning { decoy.terminate() }; decoy.waitUntilExit() }
        do {
            try await approve(owner, confirming: true)
            let result = try await owner.ensureConnected()
            #expect(result.phase == .connected)
            _ = try await client.discoverTools()
            let pidResult = try await client.invoke(tool: "pid", arguments: .object([:]))
            let pid = try #require(pidResult.structuredContent?.objectValue?["pid"]?.intValue)
            #expect(kill(Int32(pid), 0) == 0)
            await owner.shutdown()
            for _ in 0..<20 where kill(Int32(pid), 0) == 0 {
                try await Task.sleep(for: .milliseconds(25))
            }
            #expect(kill(Int32(pid), 0) == -1)
            #expect(decoy.isRunning == true)
            #expect(await client.snapshot().state == .disconnected)
        } catch {
            await owner.shutdown()
            throw error
        }
    }

    @Test func connectingApprovalIsRejectedAndReviewSurvivesLaunch() async throws {
        let (owner, installation, client) = makeOwner()
        try await approve(owner)
        let gate = Gate()
        client.setConnectGate(gate)
        let launch = Task { try await owner.ensureConnected() }
        do {
            try await waitFor { client.events.contains("connect:start") }
            try await waitFor { await owner.launchWaiterCount == 1 }
            let review = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
            #expect(review.id == UUID(uuidString: "00000000-0000-0000-0000-000000000002"))
            await #expect(throws: ProxymanIntegrationError.connectionActive) {
                try await owner.approve(reviewID: review.id, confirmingBuild: false)
            }
            #expect(await owner.snapshot().phase == .connecting)
            #expect(await owner.snapshot().review == review)
            await gate.open()
            let result = try await launch.value
            #expect(result.phase == .connected)
            #expect(await owner.snapshot().review == review)
            #expect(installation.calls == ["inspect", "approve", "connectionConfiguration", "inspect"])
        } catch { await gate.open(); throw error }
    }

    @Test func failedReplacementApprovalKeepsEarlierApproval() async throws {
        let (owner, installation, _) = makeOwner(trusted: false)
        let first = try await approve(owner, confirming: true)
        let second = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        installation.setApproveError(ProxymanInstallationError.installationChanged)
        await #expect(throws: ProxymanIntegrationError.installation(.installationChanged)) {
            try await owner.approve(reviewID: second.id, confirmingBuild: true)
        }
        #expect(await owner.snapshot().phase == .approved)
        #expect(await owner.snapshot().review == nil)
        installation.setApproveError(nil)
        #expect(try await owner.ensureConnected().phase == .connected)
        #expect(installation.configuredReviewIDs == [first.id])
        #expect(installation.calls == ["inspect", "confirmAndApprove", "inspect", "confirmAndApprove", "connectionConfiguration"])
    }

    @Test func newApprovalClearsLaunchFailureAndReplacesConfiguration() async throws {
        let (owner, installation, client) = makeOwner()
        client.scriptConnectErrors([MCPClientError.deadlineExceeded])
        let first = try await approve(owner)
        await #expect(throws: ProxymanIntegrationError.client(.deadlineExceeded)) { try await owner.ensureConnected() }
        #expect(await owner.snapshot().phase == .failed)
        let second = try await approve(owner)
        #expect(await owner.snapshot() == ProxymanIntegrationSnapshot(phase: .approved, review: nil, connection: nil, audit: nil, failure: nil))
        #expect(try await owner.ensureConnected().phase == .connected)
        #expect(installation.configuredReviewIDs == [first.id, second.id])
        #expect(client.connectCalls == 2)
        #expect(client.disconnectCalls == 0)
    }

    @Test func disconnectClearsFailureButPreservesUnapprovedReview() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        client.scriptConnectErrors([MCPClientError.deadlineExceeded])
        await #expect(throws: ProxymanIntegrationError.client(.deadlineExceeded)) { try await owner.ensureConnected() }
        #expect(await owner.snapshot().phase == .failed)
        #expect(await owner.snapshot().failure == .client(.deadlineExceeded))
        await owner.disconnect()
        #expect(await owner.snapshot().phase == .approved)
        #expect(await owner.snapshot().failure == nil)
        #expect(client.disconnectCalls == 0)
        let (unapprovedOwner, _, unapprovedClient) = makeOwner()
        let review = try await unapprovedOwner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        await unapprovedOwner.disconnect()
        #expect(await unapprovedOwner.snapshot().phase == .notApproved)
        #expect(await unapprovedOwner.snapshot().review == review)
        #expect(unapprovedClient.disconnectCalls == 0)
    }

    @Test func mismatchedConnectionIdentityForcesOwnedCleanupAndRelaunch() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        let initial = try await owner.ensureConnected()
        #expect(initial.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000001"))
        client.replaceLiveConnection(id: UUID(uuidString: "00000000-0000-0001-0000-0000000000AA")!)
        let result = try await owner.ensureConnected()
        #expect(result.phase == .connected)
        #expect(result.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000002"))
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end", "connect:start", "connect:end"])
        #expect(client.connectCalls == 2)
        #expect(client.disconnectCalls == 1)
    }

    @Test func concurrentShutdownsAwaitOneTeardown() async throws {
        let (owner, _, client) = makeOwner()
        try await approve(owner)
        _ = try await owner.ensureConnected()
        let gate = Gate()
        client.setDisconnectGate(gate)
        let first = Task { await owner.shutdown() }
        do { try await waitFor { client.events.contains("disconnect:start") } }
        catch { await gate.open(); await first.value; throw error }
        let secondFinished = CompletionFlag()
        let thirdFinished = CompletionFlag()
        let second = Task { await owner.shutdown(); secondFinished.set() }
        let third = Task { await owner.shutdown(); thirdFinished.set() }
        do { try await waitFor { await owner.snapshot().phase == .shutDown } }
        catch { await gate.open(); await first.value; await second.value; await third.value; throw error }
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start"])
        #expect(secondFinished.isSet == false)
        #expect(thirdFinished.isSet == false)
        await gate.open()
        await first.value
        await second.value
        await third.value
        #expect(client.events == ["connect:start", "connect:end", "disconnect:start", "disconnect:end"])
        #expect(client.disconnectCalls == 1)
        #expect(await owner.snapshot().phase == .shutDown)
    }

    @Test func shutdownDiscardsPendingApproval() async throws {
        let (owner, installation, client) = makeOwner()
        let gate = Gate()
        installation.setApproveGate(gate)
        let review = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        let approval = Task { try await owner.approve(reviewID: review.id, confirmingBuild: false) }
        do { try await waitFor { installation.calls == ["inspect", "approve"] } }
        catch { await gate.open(); throw error }
        await owner.shutdown()
        #expect(client.disconnectCalls == 0)
        #expect(await owner.snapshot().phase == .shutDown)
        await gate.open()
        await #expect(throws: ProxymanIntegrationError.shutDown) { try await approval.value }
        #expect(await owner.snapshot().phase == .shutDown)
        #expect(await owner.snapshot().review == nil)
        #expect(installation.calls == ["inspect", "approve"])
    }

    @Test func launchDuringApprovalPreservesEarlierApprovalAndAudit() async throws {
        let (owner, installation, _) = makeOwner()
        let first = try await approve(owner)
        let second = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        let gate = Gate()
        installation.setApproveGate(gate)
        let approval = Task { try await owner.approve(reviewID: second.id, confirmingBuild: false) }
        let connected: ProxymanIntegrationSnapshot
        do {
            try await waitFor { installation.calls == ["inspect", "approve", "inspect", "approve"] }
            connected = try await owner.ensureConnected()
        } catch { await gate.open(); throw error }
        #expect(connected.phase == .connected)
        #expect(connected.connection?.connectionID == UUID(uuidString: "00000000-0000-0001-0000-000000000001"))
        await gate.open()
        await #expect(throws: ProxymanIntegrationError.connectionActive) { try await approval.value }
        let after = await owner.snapshot()
        #expect(after.phase == .connected)
        #expect(after.connection == connected.connection)
        #expect(after.audit == connected.audit)
        #expect(after.review == nil)
        #expect(installation.configuredReviewIDs == [first.id])
        #expect(installation.calls == ["inspect", "approve", "inspect", "approve", "connectionConfiguration"])
    }

    @Test func disconnectEpochDiscardsPendingReplacementApproval() async throws {
        let (owner, installation, client) = makeOwner()
        let first = try await approve(owner)
        let second = try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app"))
        let gate = Gate()
        installation.setApproveGate(gate)
        let approval = Task { try await owner.approve(reviewID: second.id, confirmingBuild: false) }
        do { try await waitFor { installation.calls == ["inspect", "approve", "inspect", "approve"] } }
        catch { await gate.open(); throw error }
        await owner.disconnect()
        #expect(client.disconnectCalls == 0)
        await gate.open()
        await #expect(throws: ProxymanIntegrationError.connectionActive) { try await approval.value }
        #expect(await owner.snapshot().phase == .approved)
        #expect(await owner.snapshot().review == nil)
        #expect(try await owner.ensureConnected().phase == .connected)
        #expect(installation.configuredReviewIDs == [first.id])
        #expect(client.connectCalls == 1)
    }

    @Test func shutdownDiscardsPendingInspection() async throws {
        let (owner, installation, client) = makeOwner(trusted: false)
        let gate = Gate()
        installation.setInspectGate(gate)
        let inspection = Task { try await owner.inspect(applicationURL: URL(fileURLWithPath: "/fake/Proxyman.app")) }
        do { try await waitFor { installation.calls == ["inspect"] } }
        catch { await gate.open(); throw error }
        await owner.shutdown()
        await gate.open()
        await #expect(throws: ProxymanIntegrationError.shutDown) { try await inspection.value }
        #expect(await owner.snapshot().phase == .shutDown)
        #expect(await owner.snapshot().review == nil)
        #expect(client.disconnectCalls == 0)
    }
}
