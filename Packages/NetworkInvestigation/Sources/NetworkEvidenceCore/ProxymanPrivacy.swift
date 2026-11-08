import Foundation

/// Shared minimization for captured and static routes. Equality of a redacted route is
/// never proof that the original paths, payloads, or program dataflow were identical.
public enum ProxymanPrivacy {
    public static func minimizedPath(_ path: String) -> String { ProxymanMinimizer.path(path) }
    public static func safeFieldNames(_ names: [String]) -> [String] { ProxymanMinimizer.fieldNames(names) }
    /// Fixed app-owned vocabulary; unknown/vendor MIME subtypes may contain private values.
    public static func minimizedMediaType(_ value: String?) -> String? { ProxymanMinimizer.mediaType(value) }
    public static func isSafeFieldName(_ name: String) -> Bool { ProxymanMinimizer.isFieldName(name) }
    public static func isApprovablePath(_ path: String) -> Bool {
        path.hasPrefix("/") && path.utf8.count <= 512 && minimizedPath(path) == path
            && !path.contains(":redacted") && !path.contains(":unavailable")
    }
    public static func isSupportedScheme(_ scheme: String) -> Bool { ["http", "https", "ws", "wss"].contains(scheme) }
    public static func isHTTPMethod(_ method: String) -> Bool {
        (1...16).contains(method.utf8.count) && method.utf8.allSatisfy { (65...90).contains($0) }
    }

    /// External text is exposed only if a separate app-owned scope already approved it.
    public static func approvedPath(_ path: String, allowed: Set<String>) -> String {
        allowed.contains(path) && isApprovablePath(path) ? path : "/:redacted"
    }

    public static func approvedFieldNames(_ names: [String], allowed: Set<String>) -> [String] {
        safeFieldNames(names).filter(allowed.contains)
    }

    public static func standardHeaderNames(_ names: [String]) -> [String] {
        let standard: Set<String> = ["accept", "accept-charset", "accept-encoding", "accept-language",
            "access-control-allow-credentials", "access-control-allow-headers", "access-control-allow-methods",
            "access-control-allow-origin", "access-control-expose-headers", "access-control-max-age",
            "age", "allow", "authorization", "cache-control", "connection", "content-disposition",
            "content-encoding", "content-language", "content-length", "content-location", "content-range",
            "content-security-policy", "content-type", "cookie", "date", "dnt", "etag", "expect",
            "expires", "forwarded", "host", "if-match", "if-modified-since", "if-none-match",
            "if-range", "if-unmodified-since", "last-modified", "location", "origin", "pragma",
            "proxy-authenticate", "proxy-authorization", "range", "referer", "retry-after", "server",
            "set-cookie", "strict-transport-security", "te", "trailer", "transfer-encoding", "upgrade",
            "user-agent", "vary", "via", "warning", "www-authenticate", "x-content-type-options",
            "x-frame-options", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user"]
        return safeFieldNames(names.map { $0.lowercased() }).filter(standard.contains)
    }
}

public enum ProxymanMinimizer {
    static let secretMarkers: Set<String> = [
        "token", "access_token", "refresh_token", "apikey", "api_key", "secret", "password",
        "passwd", "credential", "credentials", "session", "sessionid", "authorization", "auth"
    ]

    public static func canonicalHost(_ input: String) -> String? {
        guard !input.isEmpty, input.utf8.count <= 253,
              input == input.trimmingCharacters(in: .whitespacesAndNewlines),
              input.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0)
                  || (48...57).contains($0) || $0 == 45 || $0 == 46 }) else { return nil }
        let value = input.lowercased().hasSuffix(".") ? String(input.lowercased().dropLast()) : input.lowercased()
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-") }) else { return nil }
        return value
    }

    public static func path(_ input: String) -> String {
        guard input.utf8.count <= 16_384, !input.utf8.contains(0), input.hasPrefix("/") else { return "/:unavailable" }
        let route = input.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)[0]
            .split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
        let segments = route.split(separator: "/", omittingEmptySubsequences: false)
        var previousSensitive = false
        var output: [String] = []
        for raw in segments.prefix(64) {
            guard let segment = String(raw).removingPercentEncoding else { return "/:unavailable" }
            let lower = segment.lowercased()
            let asciiRoute = segment.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0)
                || (48...57).contains($0) || [45, 46, 95, 126, 58].contains($0) }
            let numeric = !segment.isEmpty && segment.utf8.allSatisfy { (48...57).contains($0) }
            let hexLike = segment.count >= 16 && segment.utf8.allSatisfy { (48...57).contains($0)
                || (65...70).contains($0) || (97...102).contains($0) || $0 == 45 }
            let credentialLike = lower.hasPrefix("sk-") || lower.hasPrefix("eyj") || lower.hasPrefix("bearer")
                || lower.contains("token=") || lower.contains("session=")
            let sensitive = previousSensitive || !asciiRoute || segment.utf8.count > 40 || numeric || hexLike || credentialLike
            output.append(sensitive && !segment.isEmpty ? ":redacted" : segment)
            previousSensitive = secretMarkers.contains(lower)
        }
        if segments.count > 64 { output.append(":redacted") }
        var result = output.joined(separator: "/")
        if result.isEmpty { result = "/" }
        if result.utf8.count > 512 {
            result = String(result.prefix(490)) + "/:redacted"
        }
        return result
    }

    public static func fieldNames(_ names: [String]) -> [String] {
        Array(Set(names.prefix(256).filter(isFieldName))).sorted().prefix(64).map { $0 }
    }

    public static func isFieldName(_ name: String) -> Bool {
        guard (1...64).contains(name.utf8.count), let first = name.utf8.first,
              (65...90).contains(first) || (97...122).contains(first) || first == 95 || first == 36 else { return false }
        return name.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0)
            || (48...57).contains($0) || [45, 46, 95, 36].contains($0) }
            && !name.lowercased().hasPrefix("eyj") && !name.lowercased().hasPrefix("sk-")
    }

        public static func mediaType(_ value: String?) -> String? {
        guard let value, value.utf8.count <= 512 else { return nil }
        let type = value.split(separator: ";", maxSplits: 1).first.map(String.init)?
            .trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        let parts = type.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty }), type.utf8.count <= 128,
              type.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || [47, 45, 46, 43].contains($0) }) else { return nil }
        let approved: Set<String> = [
            "application/json", "application/problem+json", "application/graphql-response+json",
            "application/vnd.api+json", "application/xml", "application/xhtml+xml",
            "application/octet-stream", "application/pdf", "application/zip", "application/gzip",
            "application/javascript", "application/x-www-form-urlencoded",
            "application/protobuf", "application/x-protobuf", "application/grpc",
            "text/plain", "text/html", "text/css", "text/javascript", "text/xml", "text/csv",
            "text/event-stream", "multipart/form-data", "multipart/mixed",
            "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml", "image/avif",
            "audio/mpeg", "audio/wav", "audio/ogg", "video/mp4", "video/webm"
        ]
        return approved.contains(type) ? type : nil
    }

    public static func sourceName(_ value: String) -> String? {
        guard value.utf8.count <= 1024 else { return nil }
        let name = (value as NSString).lastPathComponent
        guard (1...96).contains(name.utf8.count), name.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [32, 45, 46, 95, 40, 41].contains($0)
        }) else { return nil }
        return name
    }
}
