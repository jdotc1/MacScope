import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

@Suite struct ProcessFilterTests {
    func make(schema: MCPJSONValue = SyntheticProxymanFixture.flowSchemaWithProcessFilter) async -> (SyntheticProxymanClient, ProxymanAdapter) {
        let client = SyntheticProxymanClient()
        let catalog = await client.catalog().filter { $0.name != "get_flows" }
        await client.setTools(catalog + [SyntheticProxymanFixture.descriptor("get_flows", schema: schema)])
        return (client, ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now }))
    }

    @Test func processFilterSendsIntegerAndKeepsOnlyMatchingVendorSource() async throws {
        let (client, adapter) = await make()
        await client.setPayload("get_flows", .object(["flows": .array([
            SyntheticProxymanFixture.flow(id: "1", pid: 2468),
            SyntheticProxymanFixture.flow(id: "2", pid: 777),
            changedFlow(["id": .string("3"), "client": .object(["name": .string("SyntheticApp.app")])])
        ])]))
        let batch = try await adapter.findFlows(query: .init(processID: 2468), scope: SyntheticProxymanFixture.scope())
        #expect(batch.flows.map(\.reference.vendorFlowID) == ["1"])
        let calls = await client.calls()
        #expect(calls.count == 1)
        let call = try #require(calls.first)
        #expect(call.tool == "get_flows")
        #expect(call.arguments == .object(["limit": .int(20), "host_filter": .string("api.example.test"), "pid_filter": .int(2468)]))
        #expect(try #require(batch.flows.first).source == .vendorReported(name: "Source name omitted", processID: 2468))
        #expect(batch.limitations.contains(.filtersAppliedLocally))
    }

    @Test func missingProcessPropertyRejectsBeforeVendorInvocation() async throws {
        let (client, adapter) = await make(schema: SyntheticProxymanFixture.flowSchema)
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("get_flows")) {
            try await adapter.findFlows(query: .init(processID: 2468), scope: SyntheticProxymanFixture.scope())
        }
        #expect(await client.calls().isEmpty)
    }

    @Test func textProcessPropertyDoesNotEnableTextFallback() async throws {
        let (client, adapter) = await make(schema: SyntheticProxymanFixture.flowSchemaWithTextProcessFilter)
        await #expect(throws: ProxymanAdapterError.schemaIncompatible("get_flows")) {
            try await adapter.findFlows(query: .init(processID: 2468), scope: SyntheticProxymanFixture.scope())
        }
        #expect(await client.calls().isEmpty)
    }

    @Test func processIdentifierBoundsRejectInvalidAndAcceptEndpoints() async throws {
        let (client, adapter) = await make()
        let scope = try SyntheticProxymanFixture.scope()
        for pid in [0, -1, 2147483648] {
            await #expect(throws: ProxymanAdapterError.invalidQuery) {
                try await adapter.findFlows(query: .init(processID: pid), scope: scope)
            }
            #expect(await client.calls().isEmpty)
        }
        for pid in [1, 2147483647] {
            let batch = try await adapter.findFlows(query: .init(processID: pid), scope: scope)
            #expect(batch.flows.isEmpty)
            let call = try #require(await client.calls().last)
            #expect(call.tool == "get_flows")
            #expect(call.arguments.pObject?["pid_filter"] == .int(pid))
        }
        #expect(await client.calls().count == 2)
    }

    @Test func absentProcessFilterNeverAddsWireArgument() async throws {
        let (client, adapter) = await make()
        let batch = try await adapter.findFlows(query: .init(), scope: SyntheticProxymanFixture.scope())
        let calls = await client.calls()
        #expect(calls.count == 1)
        let call = try #require(calls.first)
        #expect(call.arguments.pObject?["pid_filter"] == nil)
        #expect(batch.flows.count == 1)
    }

    @Test func queryCodingPreservesProcessAndDecodesOlderPayload() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(ProxymanFlowQuery(limit: 5, processID: 99))
        #expect(String(decoding: encoded, as: UTF8.self) == "{\"limit\":5,\"onlyErrors\":false,\"processID\":99}")
        let decoded = try JSONDecoder().decode(ProxymanFlowQuery.self, from: Data("{\"limit\":5,\"onlyErrors\":false}".utf8))
        #expect(decoded == ProxymanFlowQuery(limit: 5))
        #expect(decoded.processID == nil)
    }

    @Test func processFilterPersistsAcrossHostsAndRemainingLimits() async throws {
        let (client, adapter) = await make()
        let scope = try SyntheticProxymanFixture.scope(hosts: ["api.example.test", "other.example.test"])
        let batch = try await adapter.findFlows(query: .init(processID: 2468), scope: scope)
        let calls = await client.calls()
        #expect(calls.count == 2)
        #expect(calls.allSatisfy { $0.tool == "get_flows" })
        #expect(calls.compactMap { $0.arguments.pObject?["host_filter"]?.pString } == ["api.example.test", "other.example.test"])
        #expect(calls.compactMap { $0.arguments.pObject?["limit"]?.pInt } == [20, 19])
        #expect(calls.allSatisfy { $0.arguments.pObject?["pid_filter"] == .int(2468) })
        #expect(batch.flows.map(\.reference.vendorFlowID) == ["42"])
    }

    @Test func localProcessFilteringDoesNotLoosenVendorResultBound() async throws {
        let (client, adapter) = await make()
        await client.setPayload("get_flows", .object(["flows": .array([
            SyntheticProxymanFixture.flow(id: "1", pid: 2468), SyntheticProxymanFixture.flow(id: "2", pid: 777)
        ])]))
        await #expect(throws: ProxymanAdapterError.responseLimitExceeded) {
            try await adapter.findFlows(query: .init(limit: 1, processID: 2468), scope: SyntheticProxymanFixture.scope())
        }
    }
}
