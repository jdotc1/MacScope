import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

struct ProxymanExperimentLifecycleTests {
    @Test func proposingDoesNotMutateAndDefaultTierCannotApprove() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        let proposal = try await h.proposal(scope: scope)
        await #expect(throws: ProxymanExperimentError.disabled) { try await h.controller.approve(proposalID: proposal.id, reviewedArgumentsSHA256: proposal.argumentsSHA256) }
        #expect(await h.client.inner.calls().map(\.tool) == ["list_rules"])
        #expect(await h.client.inner.calls().allSatisfy { !ProxymanToolPolicy.reviewedMutations.contains($0.tool) })
    }

    @Test func alteredReviewDigestCannotAuthorizeExactArguments() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let proposal = try await h.proposal(scope: scope)
        await #expect(throws: ProxymanExperimentError.invalidReview) { try await h.controller.approve(proposalID: proposal.id, reviewedArgumentsSHA256: String(repeating: "0", count: 64)) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func approvedActionExecutesOnceAndVerifiesOnlyRuleInventory() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        let record = try await h.controller.execute(approval)
        #expect(record.verification == .ruleListed)
        #expect(record.createdRuleID == "new-rule")
        #expect(record.diagnosticCode == nil)
        #expect(record.argumentsSHA256 == proposal.argumentsSHA256)
        #expect(record.argumentsJSON == proposal.argumentsJSON)
        #expect(record.schemaDigest == proposal.schemaDigest)
        #expect(record.connectionID == proposal.connectionID && record.scopeID == proposal.scopeID)
        #expect(record.executedAt == Date(timeIntervalSince1970: 1_795_000_000))
        let saved = try JSONEncoder().encode(record)
        let reopened = try JSONDecoder().decode(ProxymanExperimentRecord.self, from: saved)
        let arguments = try JSONDecoder().decode(MCPJSONValue.self, from: Data(reopened.argumentsJSON.utf8))
        #expect(try ProxymanDigest.json(arguments) == reopened.argumentsSHA256)
        #expect(reopened == record)
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().map(\.tool) == ["list_rules", "create_blacklist", "list_rules"])
    }

    @Test func cannotApproveOneProposalTwice() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, _) = try await h.approved(scope: scope)
        await #expect(throws: ProxymanExperimentError.invalidReview) { try await h.controller.approve(proposalID: proposal.id, reviewedArgumentsSHA256: proposal.argumentsSHA256) }
    }

    @Test func unknownProposalCannotBeApproved() async throws {
        let h = ExperimentHarness(enabled: true)
        await #expect(throws: ProxymanExperimentError.unknownProposal) { try await h.controller.approve(proposalID: UUID(), reviewedArgumentsSHA256: String(repeating: "0", count: 64)) }
    }

    @Test func disablingTierRevokesOutstandingApproval() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        await h.controller.setEnabled(false)
        await #expect(throws: ProxymanExperimentError.disabled) { try await h.controller.execute(approval) }
        await h.controller.setEnabled(true)
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func approvalExpiresBeforeVendorMutation() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        h.clock.advance(60)
        await #expect(throws: ProxymanExperimentError.expired) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func approvalRemainsValidBeforeExpiryBoundary() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        h.clock.advance(59)
        let record = try await h.controller.execute(approval)
        #expect(record.verification == .ruleListed)
        #expect(record.executedAt == Date(timeIntervalSince1970: 1_795_000_059))
    }

    @Test func expiredReviewIsDiscardedBeforeAnotherApproval() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let proposal = try await h.proposal(scope: scope)
        h.clock.advance(60)
        await #expect(throws: ProxymanExperimentError.expired) { try await h.controller.approve(proposalID: proposal.id, reviewedArgumentsSHA256: proposal.argumentsSHA256) }
        await #expect(throws: ProxymanExperimentError.unknownProposal) { try await h.controller.approve(proposalID: proposal.id, reviewedArgumentsSHA256: proposal.argumentsSHA256) }
    }

    @Test func revokingInvestigationInvalidatesApprovedMutation() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        await h.adapter.invalidate(scopeID: scope.authorityID)
        await #expect(throws: ProxymanAdapterError.scopeRevoked) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func catalogChangeAfterApprovalPreventsMutation() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        await h.client.inner.setTools(await h.client.inner.catalog())
        await #expect(throws: ProxymanAdapterError.staleReference) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func failedMutationIsNotRetriedOrReportedAsRolledBack() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        await h.client.inner.setThrow("create_blacklist")
        let record = try await h.controller.execute(approval)
        #expect(record.verification == .outcomeUnknown)
        #expect(record.diagnosticCode == "mutationResultUnavailable")
        #expect(record.createdRuleID == nil)
        #expect(record.argumentsJSON == proposal.argumentsJSON && record.schemaDigest == proposal.schemaDigest)
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 1)
    }

    @Test func vendorErrorResultIsUnknownWithoutPersistingVendorText() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        await h.client.inner.setError("create_blacklist")
        let record = try await h.controller.execute(approval)
        #expect(record.verification == .outcomeUnknown)
        #expect(record.diagnosticCode == "postMutationVerificationUnavailable")
        #expect(record.createdRuleID == nil)
        let encoded = try JSONEncoder().encode(record)
        #expect(!String(decoding: encoded, as: UTF8.self).contains(SyntheticProxymanFixture.secret))
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 1)
    }

    @Test func revocationDuringProposalPreparationCannotRecreateAuthority() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.inner.holdNext("list_rules")
        let task = Task { try await h.proposal(scope: scope) }
        await h.client.inner.waitForInvocation("list_rules")
        await h.controller.revokeAll()
        await h.client.inner.resume("list_rules")
        await #expect(throws: ProxymanExperimentError.invalidReview) { try await task.value }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func disableDuringDispatchValidationPreventsMutation() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        let gate = ReviewAuthorizationGate()
        let task = Task {
            try await h.controller.execute(approval, expectedScopeID: scope.authorityID, expectedConnectionID: proposal.connectionID,
                authorizationStillValid: { await gate.validate() })
        }
        await gate.waitUntilArrived()
        await h.controller.setEnabled(false)
        await gate.release(true)
        await #expect(throws: ProxymanExperimentError.invalidReview) { try await task.value }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func applicationScopeAndConnectionBindingsAreRequired() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        await #expect(throws: ProxymanExperimentError.invalidReview) {
            try await h.controller.execute(approval, expectedScopeID: UUID(), expectedConnectionID: proposal.connectionID,
                authorizationStillValid: { true })
        }
        await #expect(throws: ProxymanExperimentError.invalidReview) {
            try await h.controller.execute(approval, expectedScopeID: scope.authorityID, expectedConnectionID: UUID(),
                authorizationStillValid: { true })
        }
        await #expect(throws: ProxymanExperimentError.invalidReview) {
            try await h.controller.execute(approval, expectedScopeID: scope.authorityID, expectedConnectionID: proposal.connectionID,
                authorizationStillValid: { false })
        }
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
    }

    @Test func failedPostMutationVerificationRetainsKnownCleanupIdentifier() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (_, approval) = try await h.approved(scope: scope)
        await h.client.inner.setThrow("list_rules")
        let record = try await h.controller.execute(approval)
        #expect(record.verification == .outcomeUnknown)
        #expect(record.createdRuleID == "new-rule")
        #expect(record.diagnosticCode == "postMutationVerificationUnavailable")
    }

    @Test func discardedProposalFreesCapacityAndRevokesItsApproval() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        await h.controller.discard(proposalID: proposal.id)
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
        for _ in 0..<70 {
            let item = try await h.proposal(scope: scope)
            await h.controller.discard(proposalID: item.id)
        }
    }

    @Test func expiredProposalsDoNotPermanentlyExhaustBoundedCapacity() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        for _ in 0..<64 { _ = try await h.proposal(scope: scope) }
        await #expect(throws: ProxymanExperimentError.capacityExceeded) { try await h.proposal(scope: scope) }
        h.clock.advance(60)
        let next = try await h.proposal(scope: scope)
        #expect(next.expiresAt == Date(timeIntervalSince1970: 1_795_000_120))
    }

    @Test func cancellationBeforeIntentConsumesApprovalWithoutDispatch() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let (proposal, approval) = try await h.approved(scope: scope)
        let gate = ReviewAuthorizationGate()
        let task = Task {
            try await h.controller.execute(approval, expectedScopeID: scope.authorityID, expectedConnectionID: proposal.connectionID,
                authorizationStillValid: { await gate.validate() })
        }
        await gate.waitUntilArrived()
        task.cancel()
        await gate.release(true)
        await #expect(throws: ProxymanAdapterError.cancelled) { try await task.value }
        #expect(await h.client.inner.calls().filter { $0.tool == "create_blacklist" }.count == 0)
        #expect(await h.audit.events().isEmpty)
        await #expect(throws: ProxymanExperimentError.approvalConsumed) { try await h.controller.execute(approval) }
    }

    @Test func previouslyListedRuleIdentityCannotVerifyCreation() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.preloadRule(id: "new-rule", kind: "blacklist", enabled: true, host: "api.example.test")
        let record = try await h.executed(scope: scope)
        #expect(record.verification == .unverified)
        #expect(record.diagnosticCode == "createdRuleIdentityUnverified")
        #expect(record.createdRuleID == "new-rule")
        #expect(await h.client.inner.calls().map(\.tool) == ["list_rules", "create_blacklist"])
    }

    @Test func unlistedCreatedRuleRemainsUnverified() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.setMode(.unlisted)
        let record = try await h.executed(scope: scope)
        #expect(record.verification == .unverified)
        #expect(record.diagnosticCode == "ruleVerificationIncomplete")
        #expect(record.createdRuleID == "new-rule")
        #expect(await h.client.inner.calls().map(\.tool) == ["list_rules", "create_blacklist", "list_rules"])
    }

    @Test(arguments: [ExperimentClient.CreationMode.disabled, .otherHost, .wrongKind]) func listedRuleMustMatchKindHostAndEnabledState(mode: ExperimentClient.CreationMode) async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.setMode(mode)
        let record = try await h.executed(scope: scope)
        #expect(record.verification == .unverified)
        #expect(record.diagnosticCode == "ruleVerificationIncomplete")
        #expect(record.createdRuleID == "new-rule")
    }

    @Test func arrayMutationEnvelopeRemainsUnknown() async throws {
        let h = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.setMode(.arrayEnvelope)
        let record = try await h.executed(scope: scope)
        #expect(record.verification == .outcomeUnknown)
        #expect(record.diagnosticCode == "mutationEnvelopeUnsupported")
        #expect(record.createdRuleID == nil)
        #expect(await h.client.inner.calls().map(\.tool) == ["list_rules", "create_blacklist"])
    }

}
