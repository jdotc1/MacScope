import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

struct ProxymanExperimentAuditTests {
    @Test func auditIntentPrecedesDispatchAndOutcomeFollowsVerification() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        let record = try await h.controller.execute(approval)
        #expect(await h.audit.events() == [.intent(proposal, clientCalls: 1), .outcome(record, clientCalls: 3)])
    }

    @Test func failedIntentPreventsDispatchAndConsumesApproval() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.audit.failIntent(true)
        let (_, approval) = try await h.approved(scope: scope)
        await #expect(throws: ProxymanExperimentError.auditUnavailable) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
        #expect(await h.audit.events().isEmpty)
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
    }

    @Test func thrownDispatchStillRecordsUnknownOutcome() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.inner.setThrow("create_blacklist")
        let (proposal, approval) = try await h.approved(scope: scope)
        let record = try await h.controller.execute(approval)
        #expect(record.verification == .outcomeUnknown)
        #expect(await h.audit.events() == [.intent(proposal, clientCalls: 1), .outcome(record, clientCalls: 2)])
    }

    @Test func proposalAndPreDispatchFailuresWriteNoAuditEvents() async throws {
        let proposalOnly = ExperimentHarness(enabled: true)
        _ = try await proposalOnly.proposal(scope: SyntheticProxymanFixture.scope())
        #expect(await proposalOnly.audit.events().isEmpty)
        let expired = ExperimentHarness(enabled: true)
        let (_, expiredApproval) = try await expired.approved(scope: SyntheticProxymanFixture.scope())
        expired.clock.advance(60)
        await #expect(throws: ProxymanExperimentError.expired) { try await expired.controller.execute(expiredApproval) }
        #expect(await expired.audit.events().isEmpty)
        let stale = ExperimentHarness(enabled: true)
        let (_, staleApproval) = try await stale.approved(scope: SyntheticProxymanFixture.scope())
        await stale.client.inner.setTools(await stale.client.inner.catalog())
        await #expect(throws: ProxymanAdapterError.staleReference) { try await stale.controller.execute(staleApproval) }
        #expect(await stale.audit.events().isEmpty)
    }

}
