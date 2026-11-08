import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

struct ProxymanExperimentTargetTests {
    @Test func proposalPinsLiteralArgumentsAndLifetime() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        let proposal = try await h.proposal(scope: scope)
        #expect(proposal.argumentsJSON == #"{"action":"block","include_paths":false,"method":"GET","url":"https://api.example.test/v1/features"}"#)
        #expect(proposal.argumentsSHA256 == "66c8fe97fa16ad45fc5d6ce88210dd1e53ee50c6797b569a393d8657b1eed53f")
        #expect(proposal.toolName == "create_blacklist")
        #expect(proposal.action == ExperimentHarness.action)
        #expect(proposal.scopeID == scope.authorityID)
        #expect(proposal.createdAt == Date(timeIntervalSince1970: 1_795_000_000))
        #expect(proposal.expiresAt == Date(timeIntervalSince1970: 1_795_000_060))
        let descriptor = try #require(await h.client.inner.catalog().first { $0.name == "create_blacklist" })
        #expect(proposal.schemaDigest == descriptor.schemaDigest)
        #expect(await h.client.inner.calls().map(\.tool) == ["list_rules"])
    }

    @Test func dispatchUsesOnlyReviewedLiteralKeys() async throws {
        let h = ExperimentHarness(enabled: true)
        _ = try await h.executed(scope: SyntheticProxymanFixture.scope())
        let calls = await h.client.inner.calls().filter { $0.tool == "create_blacklist" }
        #expect(calls.count == 1)
        let call = try #require(calls.first)
        #expect(call.arguments == .object(["action": .string("block"), "include_paths": .bool(false), "method": .string("GET"), "url": .string("https://api.example.test/v1/features")]))
        let arguments = try #require(call.arguments.pObject)
        #expect(arguments.keys.sorted() == ["action", "include_paths", "method", "url"])
        #expect(arguments["use_regex"] == nil)
        #expect(arguments["is_regex"] == nil)
    }

    @Test func optionalLiteralRegexFlagIsReviewed() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        var properties = try #require(SyntheticProxymanFixture.blacklistSchema.pObject?["properties"]?.pObject)
        properties["use_regex"] = SyntheticProxymanFixture.boolean
        await h.replaceBlacklistSchema(SyntheticProxymanFixture.schema(properties, required: ["url", "method", "include_paths"]))
        let proposal = try await h.proposal(scope: scope)
        #expect(proposal.argumentsJSON == #"{"action":"block","include_paths":false,"method":"GET","url":"https://api.example.test/v1/features","use_regex":false}"#)
        #expect(proposal.argumentsSHA256 == "74f3d1203da594cc338f819c8994a2b8cc1abef690e826d393c09e0794d57d60")
    }

    @Test func incompatibleRegexFlagIsRefused() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        var properties = try #require(SyntheticProxymanFixture.blacklistSchema.pObject?["properties"]?.pObject)
        properties["use_regex"] = SyntheticProxymanFixture.string
        await h.replaceBlacklistSchema(SyntheticProxymanFixture.schema(properties, required: ["url", "method", "include_paths"]))
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("literalMutationProfile")) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func missingVisibleBlockActionIsRefused() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        var properties = try #require(SyntheticProxymanFixture.blacklistSchema.pObject?["properties"]?.pObject)
        properties.removeValue(forKey: "action")
        await h.replaceBlacklistSchema(SyntheticProxymanFixture.schema(properties, required: ["url", "method", "include_paths"]))
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("literalMutationProfile")) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func hiddenOnlyBlockActionIsRefused() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        var properties = try #require(SyntheticProxymanFixture.blacklistSchema.pObject?["properties"]?.pObject)
        properties["action"] = .object(["type": .string("string"), "enum": .array([.string("block_and_hide")])])
        await h.replaceBlacklistSchema(SyntheticProxymanFixture.schema(properties, required: ["url", "method", "include_paths"]))
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("literalMutationProfile")) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func unreviewedRequiredArgumentIsRefused() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        var properties = try #require(SyntheticProxymanFixture.blacklistSchema.pObject?["properties"]?.pObject)
        properties["note"] = SyntheticProxymanFixture.string
        await h.replaceBlacklistSchema(SyntheticProxymanFixture.schema(properties, required: ["url", "method", "include_paths", "note"]))
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("create_blacklist")) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func missingBlacklistDescriptorIsRefused() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.inner.setTools(await h.client.inner.catalog().filter { $0.name != "create_blacklist" })
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("literalMutationProfile")) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func missingRuleInventoryIsRefused() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.inner.setTools(await h.client.inner.catalog().filter { $0.name != "list_rules" })
        await #expect(throws: ProxymanAdapterError.unsupportedCapability("rules")) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test(arguments: [
        "https://other.example.test/v1/features", "https://api.example.test/v1/*",
        "https://api.example.test/v1?token=x", "https://user:x@api.example.test/v1/features",
        "https://api.example.test/people/123", "https://api.example.test/v1#fragment",
        "https://api.example.test/people/:redacted", "https://api.example.test/:unavailable",
        "ftp://api.example.test/v1/features", "https://api.example.test:70000/v1/features",
        "https://api.example.test:0/v1/features", "https://api.example.test:/v1/features", "",
        "https://api.example.test/" + String(repeating: "a", count: 1000),
        "https://api.example.test/v1/{id}", "api.example.test/v1/features"
    ]) func broadOrSensitiveMutationTargetsAreRejected(endpoint: String) async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        await #expect(throws: ProxymanExperimentError.invalidTarget) {
            try await h.controller.propose(action: .blockEndpoint(endpoint: endpoint, method: "GET"), scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func httpAndExplicitPortRetainExactReviewedText() async throws {
        let examples = [
            ("http://api.example.test/v1/features", "POST", #"{"action":"block","include_paths":false,"method":"POST","url":"http://api.example.test/v1/features"}"#, "fffe55515e71d8ce6d1ec9cacee9936603ed2834543c7787207578228cb62598"),
            ("https://api.example.test:8443/v1/features", "GET", #"{"action":"block","include_paths":false,"method":"GET","url":"https://api.example.test:8443/v1/features"}"#, "d4e455262c0796640e0e281078669bd3cb417827e52005c819aacaae3214ffa0")
        ]
        for (endpoint, method, json, digest) in examples {
            let h = ExperimentHarness()
            let proposal = try await h.controller.propose(action: .blockEndpoint(endpoint: endpoint, method: method), scope: SyntheticProxymanFixture.scope())
            #expect(proposal.argumentsJSON == json)
            #expect(proposal.argumentsSHA256 == digest)
        }
    }

    @Test func methodsMustBeSpecificValidUppercaseTokens() async throws {
        for method in ["GET", "POST", "PROPFIND"] {
            let h = ExperimentHarness()
            let proposal = try await h.controller.propose(action: .blockEndpoint(endpoint: "https://api.example.test/v1/features", method: method), scope: SyntheticProxymanFixture.scope())
            #expect(proposal.argumentsJSON.contains("\"method\":\"\(method)\""))
        }
        for method in ["ANY", "get", "", "POST\nclear_session", "ABCDEFGHIJKLMNOPQ"] {
            let h = ExperimentHarness()
            await #expect(throws: ProxymanExperimentError.invalidTarget) {
                try await h.controller.propose(action: .blockEndpoint(endpoint: "https://api.example.test/v1/features", method: method), scope: SyntheticProxymanFixture.scope())
            }
            #expect(await h.client.inner.calls().isEmpty)
        }
    }

    @Test func scopeClockBoundsAreInclusiveOnlyAtStart() async throws {
        for offset in [TimeInterval(120), TimeInterval(-3601)] {
            let h = ExperimentHarness()
            h.clock.advance(offset)
            await #expect(throws: ProxymanExperimentError.invalidTarget) {
                try await h.proposal(scope: SyntheticProxymanFixture.scope())
            }
            #expect(await h.client.inner.calls().isEmpty)
        }
        let h = ExperimentHarness()
        h.clock.advance(-3600)
        let proposal = try await h.proposal(scope: SyntheticProxymanFixture.scope())
        #expect(proposal.createdAt == Date(timeIntervalSince1970: 1_794_996_400))
        #expect(proposal.expiresAt == Date(timeIntervalSince1970: 1_794_996_460))
    }

    @Test func proposalLifetimeIsClippedToScopeEnd() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        let shorter = try ProxymanReadScope(authorityID: scope.authorityID, workspaceID: scope.workspaceID,
            investigationID: scope.investigationID, binarySHA256: scope.binarySHA256, allowedHosts: scope.allowedHosts,
            start: scope.start, end: Date(timeIntervalSince1970: 1_795_000_030), maximumFlows: scope.maximumFlows,
            approvedPaths: scope.approvedPaths, approvedFieldNames: scope.approvedFieldNames)
        let proposal = try await h.proposal(scope: shorter)
        #expect(proposal.expiresAt == Date(timeIntervalSince1970: 1_795_000_030))
    }

    @Test func revokedScopeCannotPrepareProposal() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        await h.adapter.invalidate(scopeID: scope.authorityID)
        await #expect(throws: ProxymanAdapterError.scopeRevoked) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func disconnectedClientCannotPrepareProposal() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        await h.client.inner.disconnect()
        await #expect(throws: ProxymanAdapterError.notConnected) {
            try await h.proposal(scope: scope)
        }
        #expect(await h.client.inner.calls().isEmpty)
    }

    @Test func plansSeparateInventoryFromTrafficEvidence() async throws {
        let h = ExperimentHarness()
        let scope = try SyntheticProxymanFixture.scope()
        let proposal = try await h.proposal(scope: scope)
        #expect(proposal.cleanupPlan.contains("No automatic cleanup"))
        #expect(proposal.expectedEffect.contains("Block the explicitly selected test endpoint"))
        #expect(proposal.verificationPlan.contains("Rule inventory alone does not prove traffic effects"))
    }

}
