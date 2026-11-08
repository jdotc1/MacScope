import Foundation
import Testing
@testable import NetworkEvidenceCore

@Suite struct EndpointMatcherTests {
    private func kind(_ query: EndpointQuery, _ string: String) -> EndpointMatchKind? {
        NetworkEndpointMatcher.match(query, string: string)?.kind
    }

    @Test func hostOnlyMatchesUrlAndBareHostCaseInsensitivelyAndExactly() throws {
        let query = try EndpointQuery(host: "API.Example.com")
        #expect(query.host == "api.example.com" && query.segments == nil)
        #expect(kind(query, "https://api.example.com/v1/users") == .hostOnly)
        #expect(kind(query, "api.example.com") == .hostOnly)
        #expect(kind(query, "HTTPS://Api.Example.COM:8443") == .hostOnly)
        #expect(kind(query, "https://evil-api.example.com/") == nil)
        #expect(kind(query, "https://sub.api.example.com/") == nil)
        #expect(kind(query, "https://example.com/") == nil)
        #expect(kind(query, "/v1/users") == nil)
    }

    @Test func exactUrlNeedsHostAndLiteralPathToAgree() throws {
        let query = try EndpointQuery(host: "api.example.com", path: "/v1/users")
        #expect(kind(query, "https://api.example.com/v1/users") == .exactURL)
        #expect(kind(query, "https://api.example.com/v1/users/") == .exactURL)
        #expect(kind(query, "https://api.example.com/v1/other") == nil)
        #expect(kind(query, "https://api.example.com") == nil)
        #expect(kind(query, "https://other.example.com/v1/users") == nil)
    }

    @Test func pathTemplatesAcceptBracesAndFormatSpecifiers() throws {
        let query = try EndpointQuery(host: "api.example.com", path: "/v1/users/42/orders")
        #expect(kind(query, "https://api.example.com/v1/users/{id}/orders") == .pathTemplate)
        #expect(kind(query, "https://api.example.com/v1/users/%@/orders") == .pathTemplate)
        #expect(kind(query, "https://api.example.com/v1/users/%d/orders") == .pathTemplate)
        #expect(kind(query, "/v1/users/%ld/orders") == .pathTemplate)
        #expect(kind(query, "/users/%@") == .pathTemplate)
        #expect(kind(query, "https://api.example.com/v1/accounts/{id}/orders") == nil)
        #expect(kind(query, "https://other.example.com/v1/users/{id}/orders") == nil)
        let partial = try EndpointQuery(host: "api.example.com", path: "/v1/user_42")
        #expect(kind(partial, "https://api.example.com/v1/user_%@") == .pathTemplate)
        #expect(kind(partial, "https://api.example.com/v1/team_%@") == nil)
    }

    @Test func pathComponentIsHostlessAndSegmentAligned() throws {
        let query = try EndpointQuery(host: "api.example.com", path: "/v1/users/list")
        #expect(kind(query, "/v1/users/list") == .pathComponent)
        #expect(kind(query, "/users/list") == .pathComponent)
        #expect(kind(query, "/users") == .pathComponent)
        #expect(kind(query, "/use") == nil)
        #expect(kind(query, "/v1/list") == nil)
        #expect(kind(query, "/") == nil)
        #expect(kind(try EndpointQuery(host: "api.example.com"), "/v1/users") == nil)
    }

    @Test func methodFiltersOnlyWhenTheStringCarriesOne() throws {
        let get = try EndpointQuery(host: "api.example.com", path: "/v1/users", method: "get")
        #expect(get.method == "GET")
        #expect(kind(get, "GET https://api.example.com/v1/users") == .exactURL)
        #expect(kind(get, "POST https://api.example.com/v1/users") == nil)
        #expect(kind(get, "https://api.example.com/v1/users") == .exactURL)
        #expect(NetworkEndpointMatcher.match(get, string: "GET /v1/users")?.method == "GET")
    }

    @Test func queryValuesFragmentsAndUserInfoNeverSurvive() throws {
        let query = try EndpointQuery(host: "https://bob:hunter2@api.example.com:8443/v1/users?token=SECRET123#frag-SECRET123")
        #expect(query.host == "api.example.com")
        #expect(query.segments == ["v1", "users"])
        let explicit = try EndpointQuery(host: "api.example.com", path: "/v1/users?token=SECRET123#SECRET123")
        #expect(explicit.segments == ["v1", "users"])
        let rendered = String(describing: query) + String(describing: explicit)
            + (query.redactedPath ?? "") + (explicit.redactedPath ?? "")
        #expect(!rendered.contains("SECRET123") && !rendered.contains("hunter2") && !rendered.contains("frag"))
        let hit = try #require(NetworkEndpointMatcher.match(query,
            string: "https://u:pw-SECRET123@api.example.com/v1/users?key=SECRET123#SECRET123"))
        #expect(!String(describing: hit).contains("SECRET123") && !String(describing: hit).contains("pw-"))
        #expect(hit.kind == .exactURL && hit.host == "api.example.com" && hit.path == "/v1/users")
    }

    @Test func sensitiveSegmentsAreMinimizedInMatches() throws {
        let query = try EndpointQuery(host: "api.example.com", path: "/v1/token/abc")
        let hit = try #require(NetworkEndpointMatcher.match(query, string: "https://api.example.com/v1/token/abc"))
        #expect(hit.path == "/v1/token/:redacted")
        let template = try #require(NetworkEndpointMatcher.match(
            try EndpointQuery(host: "api.example.com", path: "/v1/users/42"), string: "/v1/users/{id}"))
        #expect(template.path == "/v1/users/:param")
    }

    @Test func malformedInputIsRefusedWithoutEchoingIt() {
        #expect(throws: EndpointQuery.Failure.host) { try EndpointQuery(host: "not a host SECRET123") }
        #expect(throws: EndpointQuery.Failure.host) { try EndpointQuery(host: "ftp://api.example.com") }
        #expect(throws: EndpointQuery.Failure.host) { try EndpointQuery(host: "") }
        #expect(throws: EndpointQuery.Failure.path) { try EndpointQuery(host: "a.example.com", path: "v1/users") }
        #expect(throws: EndpointQuery.Failure.path) { try EndpointQuery(host: "a.example.com", path: "//x") }
        #expect(throws: EndpointQuery.Failure.method) { try EndpointQuery(host: "a.example.com", method: "GET\nX") }
        #expect(NetworkEndpointMatcher.match((try? EndpointQuery(host: "a.example.com"))!, string: String(repeating: "a", count: 5000)) == nil)
    }
}
