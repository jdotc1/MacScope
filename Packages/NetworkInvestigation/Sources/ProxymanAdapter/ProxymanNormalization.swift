import Foundation
import ExternalMCP
import NetworkEvidenceCore

struct ProxymanParsedFlow {
    let summary: NetworkFlowSummary
    let rawPath: String
    let rawSourceName: String?
    let queryKeys: [String]
    let responseKeys: [String]
    let requestHeaders: [String]
    let responseHeaders: [String]
}

/// Normalization profiles are tested synthetic compatibility profiles. Live schemas and
/// payloads must still pass these checks; unknown envelopes do not become empty results.
enum ProxymanNormalization {
    static func payload(_ outcome: MCPToolOutcome) throws -> MCPJSONValue {
        guard !outcome.isError else { throw ProxymanAdapterError.vendorFailure(outcome.toolName) }
        let value: MCPJSONValue
        if let structured = outcome.structuredContent { value = structured }
        else {
            guard outcome.textContent.count == 1, let text = outcome.textContent.first,
                  text.utf8.count <= 524_288, let data = text.data(using: .utf8) else {
                throw ProxymanAdapterError.malformedResponse("contentEnvelope")
            }
            do { value = try JSONDecoder().decode(MCPJSONValue.self, from: data) }
            catch { throw ProxymanAdapterError.malformedResponse("jsonContent") }
        }
        do {
            var budget = 16_384
            try ProxymanSchemaValidator.boundValue(value, budget: &budget)
            let encoder = JSONEncoder()
            guard try encoder.encode(value).count <= 524_288 else { throw ProxymanAdapterError.responseLimitExceeded }
        } catch { throw ProxymanAdapterError.responseLimitExceeded }
        return value
    }

    static func flows(_ payload: MCPJSONValue, maximum: Int) throws -> [MCPJSONValue] {
        let result: [MCPJSONValue]?
        if let direct = payload.pArray { result = direct }
        else if let object = payload.pObject {
            result = object["flows"]?.pArray ?? object["data"]?.pObject?["flows"]?.pArray
        } else { result = nil }
        guard let result else { throw ProxymanAdapterError.malformedResponse("flowsEnvelope") }
        guard result.count <= maximum else { throw ProxymanAdapterError.responseLimitExceeded }
        return result
    }

    static func detailObject(_ payload: MCPJSONValue) throws -> MCPJSONValue {
        guard let object = payload.pObject else { throw ProxymanAdapterError.malformedResponse("flowEnvelope") }
        if let flow = object["flow"]?.pObject { return .object(flow) }
        if let flow = object["data"]?.pObject?["flow"]?.pObject { return .object(flow) }
        return payload
    }

    static func flow(_ value: MCPJSONValue, connectionID: UUID, batchID: UUID, scope: ProxymanReadScope,
                     observedAt: Date) throws -> ProxymanParsedFlow {
        guard let object = value.pObject else { throw ProxymanAdapterError.malformedResponse("flowObject") }
        let request = object["request"]?.pObject ?? [:]
        let response = object["response"]?.pObject ?? [:]
        guard let id = ProxymanMinimizer.identifier(object.first(["id", "flow_id", "flowId"])) else {
            throw ProxymanAdapterError.malformedResponse("flowIdentifier")
        }
        guard let timestamp = object.first(["timestamp", "request_time", "requestTime", "started_at", "startedAt", "startTime"])
                ?? request.first(["timestamp", "startedAt", "startTime"]),
              let time = date(timestamp) else { throw ProxymanAdapterError.unverifiableFlowIdentity }
        guard let method = (object["method"] ?? request["method"])?.pString,
              isHTTPMethod(method) else { throw ProxymanAdapterError.malformedResponse("httpMethod") }

        let scheme: String
        let host: String
        let rawPath: String
        let port: Int?
        let requestTargetDigest: String
        let query = object.first(["query_params", "queryParams"]) ?? request.first(["query_params", "queryParams", "query"])
        let declaredPort = object.first(["port", "destination_port", "destinationPort"]) ?? request["port"]
        var urlQueryKeys: [String] = []
        if let rawURL = (object["url"] ?? request["url"])?.pString {
            guard rawURL.utf8.count <= 16_384, let components = URLComponents(string: rawURL),
                  let urlScheme = components.scheme?.lowercased(), ProxymanPrivacy.isSupportedScheme(urlScheme),
                  let rawHost = components.host, let urlHost = ProxymanMinimizer.canonicalHost(rawHost) else {
                throw ProxymanAdapterError.malformedResponse("flowURL")
            }
            if let declaredHost = object["host"]?.pString,
               ProxymanMinimizer.canonicalHost(declaredHost) != urlHost {
                throw ProxymanAdapterError.malformedResponse("conflictingHost")
            }
            scheme = urlScheme; host = urlHost
            rawPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
            port = try validatedPort(components.port, wasReported: components.rangeOfPort != nil) ?? defaultPort(scheme)
            if let declaredPort {
                guard let number = declaredPort.pInt,
                      try validatedPort(number, wasReported: true) == (port ?? defaultPort(scheme)) else {
                    throw ProxymanAdapterError.malformedResponse("conflictingPort")
                }
            }
            urlQueryKeys = (components.queryItems ?? []).prefix(256).map(\.name)
            requestTargetDigest = try ProxymanDigest.json(.object([
                "scheme": .string(scheme), "host": .string(host), "port": .int(port ?? defaultPort(scheme)),
                "path": .string(rawPath),
                "query": components.percentEncodedQuery.map(MCPJSONValue.string) ?? query ?? .null,
                "user": components.percentEncodedUser.map(MCPJSONValue.string) ?? .null,
                "password": components.percentEncodedPassword.map(MCPJSONValue.string) ?? .null
            ]))
        } else {
            guard let rawHost = object["host"]?.pString,
                  let canonicalHost = ProxymanMinimizer.canonicalHost(rawHost),
                  let rawScheme = object["scheme"]?.pString, ProxymanPrivacy.isSupportedScheme(rawScheme.lowercased()),
                  let path = (object["path"] ?? request["path"])?.pString,
                  path.hasPrefix("/"), path.utf8.count <= 16_384, !path.contains("?"), !path.contains("#") else {
                throw ProxymanAdapterError.malformedResponse("flowDestination")
            }
            scheme = rawScheme.lowercased(); host = canonicalHost; rawPath = path
            if let declaredPort {
                guard let number = declaredPort.pInt else { throw ProxymanAdapterError.malformedResponse("flowPort") }
                port = try validatedPort(number, wasReported: true)
            } else { port = nil }
            requestTargetDigest = try ProxymanDigest.json(.object([
                "scheme": .string(scheme), "host": .string(host), "port": port.map(MCPJSONValue.int) ?? .null,
                "path": .string(rawPath), "query": query ?? .null, "user": .null, "password": .null
            ]))
        }

        let source = source(object)
        let identity = try ProxymanDigest.json(.object([
            "flow": .string(id), "timestamp": .double(time.timeIntervalSince1970),
            "method": .string(method), "scheme": .string(scheme), "host": .string(host),
            "path": .string(rawPath), "source": source.identity, "requestTargetDigest": .string(requestTargetDigest)
        ]))
        let reference = NetworkFlowReference(connectionID: connectionID, batchID: batchID,
            scopeID: scope.authorityID, vendorFlowID: id, identityDigest: identity)
        let status = (object.first(["status", "status_code", "statusCode"]) ?? response.first(["status", "statusCode", "status_code"]))?.pInt
        if let status, !(100...599).contains(status) { throw ProxymanAdapterError.malformedResponse("statusCode") }
        let duration = object.first(["duration_ms", "durationMilliseconds"])?.pNumber
        if let duration, duration < 0 || duration > 86_400_000 { throw ProxymanAdapterError.malformedResponse("duration") }
        let requestHeaders = request["headers"] ?? object["request_headers"] ?? object["requestHeaders"]
        let responseHeaders = response["headers"] ?? object["response_headers"] ?? object["responseHeaders"]
        let media = ProxymanMinimizer.mediaType(
            (object.first(["content_type", "contentType", "responseContentType"]) ?? response.first(["content_type", "contentType"]))?.pString
                ?? headerValue("content-type", headers: responseHeaders))
        let body = ["body", "body_preview", "bodyPreview"].compactMap { response[$0] }.first
            ?? ["response_body", "responseBody", "response_body_preview"].compactMap { object[$0] }.first
        let truncated = (response.first(["body_truncated", "bodyTruncated", "truncated"]) ?? object.first(["body_truncated", "bodyTruncated"]))?.pBool == true
        let availability: NetworkBodyAvailability
        if truncated { availability = .previewTruncated }
        else if let body { availability = body == .null || body == .string("") ? .absent : .available }
        else if let available = (object.first(["has_body", "hasBody"]) ?? response["hasBody"])?.pBool {
            availability = available ? .available : .absent
        } else { availability = .notReported }
        let summary = NetworkFlowSummary(reference: reference, requestTime: time, observedAt: observedAt,
            method: method, scheme: scheme, host: host, path: ProxymanPrivacy.approvedPath(rawPath, allowed: scope.approvedPaths), port: port,
            statusCode: status, durationMilliseconds: duration, responseContentType: media,
            source: source.attribution, tlsVisibility: tls(object, scheme: scheme, method: method),
            ruleInfluence: ruleInfluence(object), bodyAvailability: availability)
        return .init(summary: summary, rawPath: rawPath, rawSourceName: source.filterName,
            queryKeys: ProxymanPrivacy.approvedFieldNames(urlQueryKeys + keys(query), allowed: scope.approvedFieldNames),
            responseKeys: ProxymanPrivacy.approvedFieldNames(bodyKeys(body), allowed: scope.approvedFieldNames),
            requestHeaders: ProxymanPrivacy.standardHeaderNames(headerNames(requestHeaders)),
            responseHeaders: ProxymanPrivacy.standardHeaderNames(headerNames(responseHeaders)))
    }

    static func isHTTPMethod(_ string: String) -> Bool {
        ProxymanPrivacy.isHTTPMethod(string)
    }

    private static func defaultPort(_ scheme: String) -> Int { ["https", "wss"].contains(scheme) ? 443 : 80 }

    private static func validatedPort(_ port: Int?, wasReported: Bool) throws -> Int? {
        guard let port else {
            if wasReported { throw ProxymanAdapterError.malformedResponse("flowPort") }
            return nil
        }
        guard (1...65535).contains(port) else { throw ProxymanAdapterError.malformedResponse("flowPort") }
        return port
    }

    private static func date(_ value: MCPJSONValue) -> Date? {
        if let number = value.pNumber {
            let seconds = number > 100_000_000_000 ? number / 1000 : number
            guard (0...4_102_444_800).contains(seconds) else { return nil }
            return Date(timeIntervalSince1970: seconds)
        }
        guard let string = value.pString, string.utf8.count <= 64 else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: string) ?? ISO8601DateFormatter().date(from: string)
    }

    private static func source(_ object: [String: MCPJSONValue]) -> (attribution: NetworkSourceAttribution, identity: MCPJSONValue, filterName: String?) {
        let source = object["client"] ?? object["source"] ?? object["application"]
        let metadata = source?.pObject ?? [:]
        let rawName = source?.pString ?? metadata.first(["name", "appName", "applicationName"])?.pString
            ?? object.first(["client_name", "clientName", "app_name"])?.pString
        let rawPID = (metadata.first(["pid", "processID", "process_id"]) ?? object.first(["pid", "process_id"]))?.pInt
        let pid = rawPID.flatMap { (1...Int(Int32.max)).contains($0) ? $0 : nil }
        // Hash the complete bounded source value, including unknown vendor attributes. A
        // truncated display name must not make two distinct source identities equivalent.
        let identity: MCPJSONValue = .object([
            "source": source ?? .null, "name": rawName.map { .string($0) } ?? .null,
            "pid": (metadata.first(["pid", "processID", "process_id"]) ?? object.first(["pid", "process_id"])) ?? .null
        ])
        let name = rawName.flatMap(ProxymanMinimizer.sourceName)
        guard let pid else { return (.unknown, identity, name) }
        return (.vendorReported(name: "Source name omitted", processID: pid), identity, name)
    }

    private static func tls(_ object: [String: MCPJSONValue], scheme: String, method: String) -> NetworkTLSVisibility {
        if method == "CONNECT" { return .connectionMetadataOnly }
        if scheme == "http" || scheme == "ws" { return .plaintextHTTP }
        let decrypted = object.first(["tls_decrypted", "tlsDecrypted", "is_decrypted", "isHTTPSDecrypted"])?.pBool
            ?? object["tls"]?.pObject?["decrypted"]?.pBool
        if decrypted == true { return .decryptedHTTP }
        if decrypted == false { return .connectionMetadataOnly }
        return .unknown
    }

    static func normalizedRuleKind(_ string: String) -> String? {
        let cleaned = string.lowercased().filter { $0 != " " && $0 != "_" && $0 != "-" }
        let map = ["breakpoint": "breakpoint", "maplocal": "maplocal", "mapremote": "mapremote",
                   "blacklist": "blacklist", "blocklist": "blacklist", "scripting": "scripting",
                   "whitelist": "whitelist", "allowlist": "whitelist", "dns": "dns_spoofing",
                   "dnsspoofing": "dns_spoofing", "networkcondition": "network_condition",
                   "networkthrottling": "network_condition", "reverseproxy": "reverse_proxy", "nocaching": "no_caching"]
        return map[cleaned]
    }

    private static func ruleInfluence(_ object: [String: MCPJSONValue]) -> NetworkRuleInfluence {
        guard let value = object.first(["matched_tools", "matchedTools"])
                ?? object["summary"]?.pObject?["debuggingTools"], let array = value.pArray, array.count <= 64 else { return .unknown }
        if array.isEmpty { return .vendorReportedNone }
        let kinds = array.compactMap { item in
            (item.pString ?? item.pObject?.first(["type", "kind", "name"])?.pString).flatMap(normalizedRuleKind)
        }
        guard kinds.count == array.count else { return .unknown }
        return .vendorReportedApplied(Array(Set(kinds)).sorted())
    }

    private static func keys(_ value: MCPJSONValue?) -> [String] {
        if let object = value?.pObject { return Array(object.keys.sorted().prefix(256)) }
        return value?.pArray?.prefix(256).compactMap { $0.pObject?.first(["key", "name"])?.pString } ?? []
    }
    private static func headerNames(_ value: MCPJSONValue?) -> [String] { keys(value).map { $0.lowercased() } }
    private static func headerValue(_ name: String, headers: MCPJSONValue?) -> String? {
        if let object = headers?.pObject {
            return object.first(where: { $0.key.lowercased() == name })?.value.pString
        }
        return headers?.pArray?.prefix(128).first(where: {
            $0.pObject?.first(["key", "name"])?.pString?.lowercased() == name
        })?.pObject?["value"]?.pString
    }
    private static func bodyKeys(_ body: MCPJSONValue?) -> [String] {
        if let object = body?.pObject { return Array(object.keys.sorted().prefix(128)) }
        guard let string = body?.pString, string.utf8.count <= 32_768,
              let data = string.data(using: .utf8),
              let object = try? JSONDecoder().decode(MCPJSONValue.self, from: data).pObject else { return [] }
        return Array(object.keys.sorted().prefix(128))
    }

    static func rules(_ payload: MCPJSONValue, defaultKind: String? = nil) throws -> [ProxymanRuleSummary] {
        let rows: [(MCPJSONValue, String?)]
        if let array = payload.pArray { rows = array.map { ($0, defaultKind) } }
        else if let object = payload.pObject, let array = object["rules"]?.pArray { rows = array.map { ($0, defaultKind) } }
        else if let object = payload.pObject {
            var collected: [(MCPJSONValue, String?)] = []
            var found = false
            for (key, value) in object {
                guard let kind = normalizedRuleKind(key) else { continue }
                guard let array = value.pArray else { throw ProxymanAdapterError.malformedResponse("ruleFamily") }
                found = true; collected += array.map { ($0, kind) }
            }
            guard found else { throw ProxymanAdapterError.malformedResponse("rulesEnvelope") }
            rows = collected
        } else { throw ProxymanAdapterError.malformedResponse("rulesEnvelope") }
        guard rows.count <= 256 else { throw ProxymanAdapterError.responseLimitExceeded }
        return try rows.map { row, inheritedKind in
            guard let object = row.pObject, let id = ProxymanMinimizer.identifier(object.first(["id", "rule_id", "ruleId"])),
                  let kind = object.first(["type", "kind", "rule_type"])?.pString.flatMap(normalizedRuleKind) ?? inheritedKind else {
                throw ProxymanAdapterError.malformedResponse("ruleIdentity")
            }
            let enabled = object.first(["enabled", "is_enabled", "isEnabled"])?.pBool
            let rawHost = object["host"]?.pString ?? object["domain"]?.pString
                ?? object["url"]?.pString.flatMap { URLComponents(string: $0)?.host }
            return .init(id: id, kind: kind, enabled: enabled.map { $0 ? .yes : .no } ?? .unknown,
                host: rawHost.flatMap(ProxymanMinimizer.canonicalHost))
        }
    }
}
