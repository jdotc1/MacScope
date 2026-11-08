import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

@Suite("Proxyman manual experiment cleanup evidence")
struct ProxymanExperimentCleanupTests {
    @Test func activeRuleCheckReadsInventoryOnce() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        let count = await harness.client.inner.calls().count
        let state = try await harness.controller.checkCleanup(record: record, scope: scope)
        let calls = await harness.client.inner.calls()
        #expect(state == .ruleStillActive)
        #expect(calls.count == count + 1)
        #expect(calls.last?.tool == "list_rules")
    }

    @Test func removedRuleIsReportedAsRemoved() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        await harness.client.removeRule(id: "new-rule")
        #expect(try await harness.controller.checkCleanup(record: record, scope: scope) == .ruleRemoved)
    }

    @Test func disabledRuleIsReportedAsDisabled() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        await harness.client.setRuleEnabled(id: "new-rule", false)
        #expect(try await harness.controller.checkCleanup(record: record, scope: scope) == .ruleDisabled)
    }

    @Test func missingEnabledStateIsUnverifiable() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        await harness.client.setRuleEnabled(id: "new-rule", nil)
        #expect(try await harness.controller.checkCleanup(record: record, scope: scope) == .unverifiable)
    }

    @Test(arguments: [false, true])
    func replacedRuleWithDifferentKindOrHostIsUnverifiable(otherHost: Bool) async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        await harness.client.removeRule(id: "new-rule")
        await harness.client.preloadRule(id: "new-rule", kind: otherHost ? "blacklist" : "breakpoint",
            enabled: true, host: otherHost ? "other.example.test" : "api.example.test")
        #expect(try await harness.controller.checkCleanup(record: record, scope: scope) == .unverifiable)
    }

    @Test func missingCreatedIdentifierNeedsNoInventoryRead() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        await harness.client.inner.setThrow("create_blacklist")
        let record = try await harness.executed(scope: scope)
        #expect(record.createdRuleID == nil)
        let count = await harness.client.inner.calls().count
        #expect(try await harness.controller.checkCleanup(record: record, scope: scope) == .unverifiable)
        #expect(await harness.client.inner.calls().count == count)
    }

    @Test func cleanupRejectsDifferentScopeWithoutReadingInventory() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        let otherScope = try SyntheticProxymanFixture.scope()
        let count = await harness.client.inner.calls().count
        await #expect(throws: ProxymanExperimentError.invalidReview) {
            try await harness.controller.checkCleanup(record: record, scope: otherScope)
        }
        #expect(await harness.client.inner.calls().count == count)
    }

    @Test func cleanupRemainsAvailableWhenTierIsDisabled() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        await harness.controller.setEnabled(false)
        #expect(try await harness.controller.checkCleanup(record: record, scope: scope) == .ruleStillActive)
    }

    @Test func cleanupPropagatesInventoryFailure() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let record = try await harness.executed(scope: scope)
        await harness.client.inner.setThrow("list_rules")
        await #expect(throws: ProxymanAdapterError.vendorFailure("list_rules")) {
            try await harness.controller.checkCleanup(record: record, scope: scope)
        }
    }

    @Test func cleanupRejectsOtherMutationWithoutReadingInventory() async throws {
        let harness = ExperimentHarness(enabled: true)
        let scope = try SyntheticProxymanFixture.scope()
        let original = try await harness.executed(scope: scope)
        let record = ProxymanExperimentRecord(proposalID: original.proposalID, action: original.action,
            toolName: "create_breakpoint", connectionID: original.connectionID, scopeID: original.scopeID,
            argumentsJSON: original.argumentsJSON, argumentsSHA256: original.argumentsSHA256,
            schemaDigest: original.schemaDigest, executedAt: original.executedAt,
            createdRuleID: original.createdRuleID, verification: original.verification,
            cleanupInstructions: original.cleanupInstructions, diagnosticCode: original.diagnosticCode)
        let count = await harness.client.inner.calls().count
        await #expect(throws: ProxymanExperimentError.invalidReview) {
            try await harness.controller.checkCleanup(record: record, scope: scope)
        }
        #expect(await harness.client.inner.calls().count == count)
    }
}
