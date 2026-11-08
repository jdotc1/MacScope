import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
import Synchronization
@testable import ProxymanAdapter

@Suite("Proxyman experiment mutation boundary")
struct ProxymanExperimentPolicyTests {
    @Test func onlyExactBlacklistToolIsPermitted() {
        for tool in Proxyman26ToolCatalog.names {
            #expect(ProxymanExperimentPolicy.permits(tool: tool) == (tool == "create_blacklist"))
        }
        #expect(Proxyman26ToolCatalog.names.filter { ProxymanExperimentPolicy.permits(tool: $0) }.count == 1)
        for tool in ["", "CREATE_BLACKLIST", "create_blacklist "] {
            #expect(!ProxymanExperimentPolicy.permits(tool: tool))
        }
    }

    @Test func experimentPolicyNarrowsReviewedMutationsWithoutChangingReads() {
        #expect(ProxymanToolPolicy.classification(of: "create_blacklist") == .trafficMutation)
        #expect(ProxymanToolPolicy.reviewedMutations.contains("create_blacklist"))
        #expect(!ProxymanToolPolicy.implementedReads.contains("create_blacklist"))
        #expect(ProxymanToolPolicy.reviewedMutations.contains("create_breakpoint"))
        #expect(!ProxymanExperimentPolicy.permits(tool: "create_breakpoint"))
    }

    @Test func forgedPreparedMutationIsRejectedBeforeIntentOrDispatch() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let prepared = try await harness.adapter.prepareExperiment(action: ExperimentHarness.action,
            scope: scope, now: SyntheticProxymanFixture.now)
        let original = prepared.proposal
        let proposal = ProxymanExperimentProposal(id: original.id, scopeID: original.scopeID,
            connectionID: original.connectionID, action: original.action, toolName: "create_breakpoint",
            argumentsJSON: original.argumentsJSON, argumentsSHA256: original.argumentsSHA256,
            schemaDigest: original.schemaDigest, createdAt: original.createdAt, expiresAt: original.expiresAt,
            expectedEffect: original.expectedEffect, verificationPlan: original.verificationPlan,
            cleanupPlan: original.cleanupPlan)
        let catalog = await harness.client.inner.catalog()
        let descriptor = try #require(catalog.first { $0.name == "create_breakpoint" })
        let forged = PreparedProxymanExperiment(proposal: proposal, lease: prepared.lease,
            arguments: prepared.arguments, schemaDigest: descriptor.schemaDigest,
            previousRuleIDs: prepared.previousRuleIDs)
        let counter = ExperimentIntentCounter()
        await #expect(throws: ProxymanExperimentError.invalidReview) {
            try await harness.adapter.executeExperiment(forged, now: SyntheticProxymanFixture.now,
                authorizeDispatch: { true }, recordIntent: { counter.increment() })
        }
        #expect(counter.value == 0)
        let calls = await harness.client.inner.calls()
        #expect(!calls.contains { $0.tool == "create_breakpoint" })
        #expect(!calls.contains { $0.tool == "create_blacklist" })
    }

    @Test func actionCodingAcceptsOnlyLiteralEndpointBlocking() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(ExperimentHarness.action)
        #expect(String(decoding: encoded, as: UTF8.self) == "{\"blockEndpoint\":{\"endpoint\":\"https://api.example.test/v1/features\",\"method\":\"GET\"}}")
        #expect(try JSONDecoder().decode(ProxymanExperimentAction.self, from: encoded) == ExperimentHarness.action)
        let breakpoint = "{\"breakpoint\":{\"endpoint\":\"https://api.example.test/v1/features\",\"method\":\"GET\",\"request\":false,\"response\":true}}"
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(ProxymanExperimentAction.self, from: Data(breakpoint.utf8))
        }
    }

    @Test func controllerIsNotAReadInvestigationTool() {
        let harness = ExperimentHarness()
        let any: Any = harness.controller
        #expect(!(any is any ProxymanInvestigating))
    }

    @Test func verificationAndCleanupStatesHaveStableCoding() throws {
        let encoder = JSONEncoder()
        let verification = try encoder.encode(ProxymanExperimentVerification.ruleListed)
        let cleanup = try encoder.encode(ProxymanExperimentCleanupState.ruleStillActive)
        #expect(String(decoding: verification, as: UTF8.self) == "\"ruleListed\"")
        #expect(String(decoding: cleanup, as: UTF8.self) == "\"ruleStillActive\"")
        let verificationStates: [ProxymanExperimentVerification] = [.ruleListed, .unverified, .outcomeUnknown]
        let cleanupStates: [ProxymanExperimentCleanupState] = [.ruleRemoved, .ruleDisabled, .ruleStillActive, .unverifiable]
        #expect(verificationStates.map(\.rawValue) == ["ruleListed", "unverified", "outcomeUnknown"])
        #expect(cleanupStates.map(\.rawValue) == ["ruleRemoved", "ruleDisabled", "ruleStillActive", "unverifiable"])
    }

    @Test func reviewCapacityAndLifetimeAreBounded() {
        #expect(ProxymanExperimentPolicy.capacity == 64)
        #expect(ProxymanExperimentPolicy.lifetime == TimeInterval(60))
    }
}

private final class ExperimentIntentCounter: Sendable {
    private let storage = Mutex<Int>(0)
    var value: Int { storage.withLock { $0 } }
    func increment() { storage.withLock { $0 += 1 } }
}
