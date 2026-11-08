import Foundation
import Testing
import ExternalMCP
import NetworkEvidenceCore
@testable import ProxymanAdapter

@Suite struct ToolCatalogTests {
    @Test func candidateCatalogHasExpectedUniqueSortedNames() {
        let names = Proxyman26ToolCatalog.names
        #expect(names.count == 111)
        #expect(Set(names).count == 111)
        #expect(names == names.sorted())
        #expect(names.first == "annotate_flows")
        #expect(names.last == "update_settings")
        for name in ["get_flows", "get_flow_detail", "create_blacklist", "create_breakpoint", "list_rules", "get_version"] {
            #expect(names.contains(name))
        }
        #expect(!names.contains("run_shell"))
    }

    @Test func everyCandidateMatchesItsExpectedClassificationAndTotals() {
        #expect(Proxyman26ToolCatalog.expectedClassification.count == 111)
        for name in Proxyman26ToolCatalog.names {
            #expect(ProxymanToolPolicy.classification(of: name) == Proxyman26ToolCatalog.expectedClassification[name])
        }
        let totals: [(ProxymanToolClassification, Int)] = [
            (.metadataRead, 17), (.sensitiveRead, 21), (.export, 4), (.appOnlyAction, 4),
            (.captureChange, 8), (.trafficMutation, 36), (.securityConfiguration, 14),
            (.processLaunch, 7), (.deniedUnknown, 0)
        ]
        for (classification, count) in totals {
            #expect(Proxyman26ToolCatalog.names.filter { ProxymanToolPolicy.classification(of: $0) == classification }.count == count)
        }
    }

    @Test func expandedToolsKeepExplicitRiskClasses() {
        let groups: [(ProxymanToolClassification, [String])] = [
            (.appOnlyAction, ["save_session", "open_session_file", "save_flows", "save_flow_body"]),
            (.captureChange, ["delete_flows", "pin_flows", "annotate_flows"]),
            (.trafficMutation, ["import_rules", "repeat_flows", "resolve_breakpoint"]),
            (.securityConfiguration, ["update_settings", "install_network_extension", "set_network_extension_enabled"]),
            (.sensitiveRead, ["get_traffic_overview", "get_flow_timing", "list_pending_breakpoints"]),
            (.metadataRead, ["get_network_extension_status", "get_license_status"]),
            (.export, ["export_rules"]), (.processLaunch, ["get_terminal_manual_command"])
        ]
        for (classification, names) in groups {
            for name in names { #expect(ProxymanToolPolicy.classification(of: name) == classification) }
        }
    }

    @Test func unknownAndAlteredNamesAreDenied() {
        for name in ["run_shell", "unknown_read_only_tool", "GET_FLOWS", "get_flows ", "get_flows_v2", ""] {
            #expect(ProxymanToolPolicy.classification(of: name) == .deniedUnknown)
        }
    }

    @Test func discoveredUnknownCountChangesWithoutInvokingTools() async throws {
        let client = SyntheticProxymanClient()
        let adapter = ProxymanAdapter(client: client, now: { SyntheticProxymanFixture.now })
        let catalog = Proxyman26ToolCatalog.names.map { SyntheticProxymanFixture.descriptor($0) }
        await client.setTools(catalog)
        #expect(try await adapter.capabilities().unknownToolCount == 0)
        #expect(await client.calls().isEmpty)
        await client.setTools(catalog + [SyntheticProxymanFixture.descriptor("brand_new_tool")])
        #expect(try await adapter.capabilities().unknownToolCount == 1)
        #expect(await client.calls().isEmpty)
    }

    @Test func implementedReadsAndReviewedMutationsStayBounded() {
        let reads = ProxymanToolPolicy.implementedReads
        let mutations = ProxymanToolPolicy.reviewedMutations
        #expect(reads.count == 11)
        #expect(reads.filter { ProxymanToolPolicy.classification(of: $0) == .metadataRead }.count == 4)
        #expect(reads.filter { ProxymanToolPolicy.classification(of: $0) == .sensitiveRead }.count == 7)
        #expect(mutations.count == 2)
        for name in mutations { #expect(ProxymanToolPolicy.classification(of: name) == .trafficMutation) }
        for name in reads {
            let classification = ProxymanToolPolicy.classification(of: name)
            #expect(classification == .metadataRead || classification == .sensitiveRead)
        }
    }

    @Test func classificationCodingUsesStableRawValues() throws {
        let encoded = try JSONEncoder().encode(ProxymanToolClassification.appOnlyAction)
        #expect(String(decoding: encoded, as: UTF8.self) == "\"appOnlyAction\"")
        let decoded = try JSONDecoder().decode(ProxymanToolClassification.self, from: Data("\"deniedUnknown\"".utf8))
        #expect(decoded == .deniedUnknown)
    }

    @Test func fixtureMutationSchemasUseVendorArgumentNames() throws {
        let breakpoint = try #require(SyntheticProxymanFixture.catalog.first { $0.name == "create_breakpoint" }).inputSchema
        let blacklist = try #require(SyntheticProxymanFixture.catalog.first { $0.name == "create_blacklist" }).inputSchema
        let breakpointProperties = try #require(breakpoint.pObject?["properties"]?.pObject)
        let blacklistProperties = try #require(blacklist.pObject?["properties"]?.pObject)
        #expect(breakpointProperties.keys.sorted() == ["enable_request", "enable_response", "include_paths", "method", "url", "use_regex"])
        #expect(breakpoint.pObject?["required"] == .array([.string("url"), .string("method"), .string("include_paths"), .string("use_regex")]))
        #expect(blacklistProperties.keys.sorted() == ["action", "include_paths", "method", "url"])
        #expect(blacklist.pObject?["required"] == .array([.string("url"), .string("method"), .string("include_paths")]))
        #expect(blacklistProperties["action"] == .object(["type": .string("string"), "enum": .array([.string("block"), .string("block_and_hide")])]))
        #expect(breakpointProperties["is_regex"] == nil)
        #expect(blacklistProperties["is_regex"] == nil)
    }
}
