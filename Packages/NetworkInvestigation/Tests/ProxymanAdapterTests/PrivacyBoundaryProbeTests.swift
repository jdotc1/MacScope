import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

/// Adversarial reproductions. These contain synthetic secrets only.
@Suite struct PrivacyBoundaryProbeTests {
    @Test(arguments: ["application/private-secret-67qz", "application/vnd.private-secret-67qz+json"])
    func customMediaSubtypeDoesNotBecomeModelOrPersistentContent(_ mediaType: String) async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope(approvedPaths: [], approvedFieldNames: [])
        let value = changedFlow(["response": .object([
            "headers": .object(["Content-Type": .string(mediaType)]),
            "body": .object(["enabled": .bool(true)])
        ])])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let batch = try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope)
        #expect(batch.flows.count == 1)
        let bytes = try JSONEncoder().encode(batch.flows)
        #expect(!String(decoding: bytes, as: UTF8.self).contains("private-secret-67qz"))
    }

    @Test func destinationPortChangeInvalidatesPriorFlowIdentity() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let first = changedFlow(["url": .string("https://api.example.test:8443/v1/features")])
        await client.setPayload("get_flows", .object(["flows": .array([first])]))
        let batch = try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope)
        let selected = try #require(batch.flows.first)
        // The same vendor ID and timestamp now describe a different network destination.
        await client.setPayload("get_flow_detail", changedFlow(["url": .string("https://api.example.test:9443/v1/features")]))
        await #expect(throws: ProxymanAdapterError.staleReference) {
            try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        }
    }

    @Test func changedQueryValueInvalidatesPriorFlowIdentityWithoutRetainingTheValue() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let first = changedFlow(["url": .string("https://api.example.test/v1/features?token=private-query-one")])
        await client.setPayload("get_flows", .object(["flows": .array([first])]))
        let batch = try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope)
        let selected = try #require(batch.flows.first)
        #expect(!String(decoding: try JSONEncoder().encode(selected), as: UTF8.self).contains("private-query-one"))
        await client.setPayload("get_flow_detail", changedFlow(["url": .string("https://api.example.test/v1/features?token=private-query-two")]))
        await #expect(throws: ProxymanAdapterError.staleReference) {
            try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        }
    }

    @Test func explicitPortIsPreservedAndOmittedPortDecodesCompatibly() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let value = changedFlow(["url": .string("https://api.example.test:8443/v1/features?token=private-port-test")])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        await client.setPayload("get_flow_detail", value)
        let selected = try #require(try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope).flows.first)
        #expect(selected.port == 8443)
        let detail = try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        #expect(detail.summary.port == 8443)
        let bytes = try JSONEncoder().encode(detail.summary)
        #expect(!String(decoding: bytes, as: UTF8.self).contains("private-port-test"))
        var object = try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        object.removeValue(forKey: "port")
        let older = try JSONDecoder().decode(NetworkFlowSummary.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(older.port == nil)
        #expect(older.reference == selected.reference)
    }

    @Test(arguments: ["0", "65536", "-1", "999999999999999999999999"])
    func invalidExplicitPortsAreRejected(_ port: String) async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let value = changedFlow(["url": .string("https://api.example.test:\(port)/v1/features")])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let scope = try SyntheticProxymanFixture.scope()
        await #expect(throws: (any Error).self) {
            try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope)
        }
    }

    @Test func conflictingURLAndStandalonePortAreRejected() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let value = changedFlow(["url": .string("https://api.example.test:8443/v1/features"), "port": .int(9443)])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let scope = try SyntheticProxymanFixture.scope()
        await #expect(throws: ProxymanAdapterError.malformedResponse("conflictingPort")) {
            try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope)
        }
    }

    @Test func standaloneQueryIdentityChangesAreDetected() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let value = changedFlow(["url": .null, "scheme": .string("https"), "host": .string(SyntheticProxymanFixture.host),
            "path": .string("/v1/features"), "port": .int(8443),
            "query_params": .object(["token": .string("private-first")])])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let selected = try #require(try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope).flows.first)
        #expect(selected.port == 8443)
        var changed = try #require(value.pObject)
        changed["query_params"] = .object(["token": .string("private-second")])
        await client.setPayload("get_flow_detail", .object(changed))
        await #expect(throws: ProxymanAdapterError.staleReference) {
            try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        }
    }

    @Test func userInfoIdentityChangesAreDetectedWithoutPersistingCredentials() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let value = changedFlow(["url": .string("https://user:private-first@api.example.test/v1/features")])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let selected = try #require(try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope).flows.first)
        #expect(!String(decoding: try JSONEncoder().encode(selected), as: UTF8.self).contains("private-first"))
        await client.setPayload("get_flow_detail", changedFlow(["url": .string("https://user:private-second@api.example.test/v1/features")]))
        await #expect(throws: ProxymanAdapterError.staleReference) {
            try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        }
    }

    @Test func mediaTypesUseFixedVocabularyAndRemoveParameters() {
        #expect(ProxymanPrivacy.minimizedMediaType("application/json; token=private-secret-67qz") == "application/json")
        #expect(ProxymanPrivacy.minimizedMediaType("TEXT/PLAIN; charset=utf-8") == "text/plain")
        #expect(ProxymanPrivacy.minimizedMediaType("application/problem+json") == "application/problem+json")
        #expect(ProxymanPrivacy.minimizedMediaType("application/private-secret-67qz") == nil)
        #expect(ProxymanPrivacy.minimizedMediaType("application/vnd.private-secret-67qz+json") == nil)
        #expect(ProxymanPrivacy.minimizedMediaType(nil) == nil)
    }

    @Test(arguments: ["http", "https", "ws", "wss"])
    func fullURLsEstablishStandardDestinationPorts(_ scheme: String) async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let value = changedFlow(["url": .string("\(scheme)://api.example.test/v1/features")])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let selected = try #require(try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope).flows.first)
        let expected = ["https", "wss"].contains(scheme) ? 443 : 80
        #expect(selected.port == expected)
        // Spelling an already established default explicitly does not change request identity.
        await client.setPayload("get_flow_detail", changedFlow(["url": .string("\(scheme)://api.example.test:\(expected)/v1/features")]))
        let detail = try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        #expect(detail.summary.reference == selected.reference)
    }

    @Test func standaloneMetadataWithoutPortRemainsUnknownAndCannotAliasKnownDestination() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let scope = try SyntheticProxymanFixture.scope()
        let value = changedFlow(["url": .null, "scheme": .string("https"), "host": .string(SyntheticProxymanFixture.host),
            "path": .string("/v1/features")])
        await client.setPayload("get_flows", .object(["flows": .array([value])]))
        let selected = try #require(try await adapter.findFlows(query: .init(host: SyntheticProxymanFixture.host), scope: scope).flows.first)
        #expect(selected.port == nil)
        var changed = try #require(value.pObject)
        changed["port"] = .int(443)
        await client.setPayload("get_flow_detail", .object(changed))
        await #expect(throws: ProxymanAdapterError.staleReference) {
            try await adapter.inspectFlow(reference: selected.reference, scope: scope)
        }
    }
}
