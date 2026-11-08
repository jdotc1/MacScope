import Foundation

/// How a binary string relates to an endpoint query. Every kind is a static candidate:
/// a match never proves that the code runs or that the request is ever sent.
public enum EndpointMatchKind: String, Codable, CaseIterable, Sendable {
    case exactURL, hostOnly, pathTemplate, pathComponent
}

/// A normalised endpoint question: one canonical host, an optional literal path and an optional method.
/// Query values, fragments and URL user-info of the input are discarded at parse time, so they can
/// never reach a reply, an error or a log.
public struct EndpointQuery: Equatable, Sendable {
    public enum Failure: Error, Equatable, Sendable { case host, path, method }

    public let host: String
    /// Decoded path segments; nil when the query names no path (or only "/").
    public let segments: [String]?
    public let method: String?

    public init(host: String, path: String? = nil, method: String? = nil) throws {
        guard let location = NetworkEndpointMatcher.splitLocation(host, requireScheme: false),
              let canonical = location.host else { throw Failure.host }
        var rawPath = location.rawPath
        if let path {
            guard path.utf8.count <= NetworkEndpointMatcher.maximumPathBytes else { throw Failure.path }
            let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
            rawPath = NetworkEndpointMatcher.stripQueryAndFragment(trimmed)
            guard rawPath.isEmpty || rawPath.hasPrefix("/"), !rawPath.hasPrefix("//") else { throw Failure.path }
        }
        guard rawPath.utf8.allSatisfy({ $0 >= 0x20 && $0 != 0x7f && $0 != 0x20 }) else { throw Failure.path }
        let parts = NetworkEndpointMatcher.segments(of: rawPath)
        guard parts.count <= NetworkEndpointMatcher.maximumSegments else { throw Failure.path }
        if let method {
            let upper = method.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            guard ProxymanPrivacy.isHTTPMethod(upper) else { throw Failure.method }
            self.method = upper
        } else {
            self.method = nil
        }
        self.host = canonical
        self.segments = parts.isEmpty ? nil : parts
    }

    /// Safe to echo: the host is restricted to host characters and the path goes through the shared minimizer.
    public var redactedPath: String? {
        segments.map { ProxymanPrivacy.minimizedPath("/" + $0.joined(separator: "/")) }
    }
}

/// One binary string that answers a query, with only privacy-minimized fields.
public struct EndpointStringMatch: Equatable, Sendable {
    public let kind: EndpointMatchKind
    public let scheme: String?
    public let host: String?
    /// Minimized path; template placeholders appear as `:param`.
    public let path: String?
    public let method: String?
}

public enum NetworkEndpointMatcher {
    static let maximumStringBytes = 4096
    static let maximumPathBytes = 2048
    static let maximumSegments = 64
    static let maximumSegmentBytes = 256
    static let maximumWildcardsPerSegment = 8

    /// Interprets `string` against `query`. Host comparison is case-insensitive and exact (no suffix match).
    /// `method` filters only when the string itself carries a method token ("GET /v1/items").
    public static func match(_ query: EndpointQuery, string: String) -> EndpointStringMatch? {
        guard let parsed = parse(string) else { return nil }
        if let wanted = query.method, let carried = parsed.method, wanted != carried { return nil }
        let hasPlaceholders = parsed.segments.contains(where: hasPlaceholder)
        func result(_ kind: EndpointMatchKind) -> EndpointStringMatch {
            EndpointStringMatch(kind: kind, scheme: parsed.scheme, host: parsed.host,
                                path: redactedPath(parsed.segments), method: parsed.method)
        }
        if let host = parsed.host {
            guard host == query.host else { return nil }
            guard let wanted = query.segments else { return result(.hostOnly) }
            guard !parsed.segments.isEmpty, parsed.segments.count == wanted.count else { return nil }
            if !hasPlaceholders { return parsed.segments == wanted ? result(.exactURL) : nil }
            return segmentsMatch(pattern: parsed.segments, wanted) ? result(.pathTemplate) : nil
        }
        guard let wanted = query.segments, !parsed.segments.isEmpty,
              parsed.segments.count <= wanted.count else { return nil }
        for start in 0...(wanted.count - parsed.segments.count) {
            let window = Array(wanted[start..<(start + parsed.segments.count)])
            if hasPlaceholders {
                if segmentsMatch(pattern: parsed.segments, window) { return result(.pathTemplate) }
            } else if window == parsed.segments {
                return result(.pathComponent)
            }
        }
        return nil
    }

    // MARK: Parsing

    struct ParsedString {
        let scheme: String?
        let host: String?
        let segments: [String]
        let method: String?
    }

    struct Location {
        let scheme: String?
        let host: String?
        let rawPath: String
    }

    static func parse(_ string: String) -> ParsedString? {
        guard string.utf8.count <= maximumStringBytes else { return nil }
        var text = string.trimmingCharacters(in: .whitespacesAndNewlines)
        var method: String?
        if let space = text.firstIndex(of: " ") {
            let token = String(text[..<space])
            guard ProxymanPrivacy.isHTTPMethod(token) else { return nil }
            method = token
            text = text[text.index(after: space)...].trimmingCharacters(in: .whitespaces)
        }
        guard !text.isEmpty, !text.contains(" "), !text.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f })
        else { return nil }
        if text.hasPrefix("/") {
            guard !text.hasPrefix("//") else { return nil }
            let parts = segments(of: stripQueryAndFragment(text))
            guard !parts.isEmpty, parts.count <= maximumSegments else { return nil }
            return ParsedString(scheme: nil, host: nil, segments: parts, method: method)
        }
        guard let location = splitLocation(text, requireScheme: false), let host = location.host else { return nil }
        if location.scheme == nil {
            // A bare host must look like one; this keeps ordinary words and file names out.
            guard host.contains("."), let last = host.split(separator: ".").last,
                  last.utf8.contains(where: { (97...122).contains($0) }) else { return nil }
        }
        let parts = segments(of: location.rawPath)
        guard parts.count <= maximumSegments else { return nil }
        return ParsedString(scheme: location.scheme, host: host, segments: parts, method: method)
    }

    /// Splits `scheme://user@host:port/path?query#fragment` (scheme optional) into scheme, canonical host and
    /// the raw path. User-info, port, query and fragment are dropped here.
    static func splitLocation(_ input: String, requireScheme: Bool) -> Location? {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.count <= maximumStringBytes else { return nil }
        var scheme: String?
        var rest = Substring(text)
        if let range = text.range(of: "://") {
            let candidate = String(text[..<range.lowerBound]).lowercased()
            guard ProxymanPrivacy.isSupportedScheme(candidate) else { return nil }
            scheme = candidate
            rest = text[range.upperBound...]
        } else if requireScheme {
            return nil
        }
        let authorityEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? rest.endIndex
        var authority = String(rest[..<authorityEnd])
        let tail = String(rest[authorityEnd...])
        if let at = authority.lastIndex(of: "@") { authority = String(authority[authority.index(after: at)...]) }
        if let colon = authority.lastIndex(of: ":") {
            let port = authority[authority.index(after: colon)...]
            guard !port.isEmpty, port.utf8.allSatisfy({ (48...57).contains($0) }), port.utf8.count <= 5 else { return nil }
            authority = String(authority[..<colon])
        }
        guard let host = ProxymanMinimizer.canonicalHost(authority) else { return nil }
        let path = tail.hasPrefix("/") ? stripQueryAndFragment(tail) : ""
        return Location(scheme: scheme, host: host, rawPath: path)
    }

    static func stripQueryAndFragment(_ value: String) -> String {
        guard let end = value.firstIndex(where: { $0 == "?" || $0 == "#" }) else { return value }
        return String(value[..<end])
    }

    static func segments(of rawPath: String) -> [String] {
        rawPath.split(separator: "/", omittingEmptySubsequences: true).map { raw in
            let text = String(raw)
            return text.removingPercentEncoding ?? text
        }
    }

    // MARK: Placeholders

    private static let formatTokens = ["%lld", "%llu", "%ld", "%lu", "%@", "%d", "%i", "%u", "%s", "%f"]

    static func hasPlaceholder(_ segment: String) -> Bool { !tokens(of: segment).wildcards.isEmpty }

    /// Literal pieces around placeholders: `user_%@_x` gives `["user_", "_x"]` with one wildcard between.
    static func tokens(of segment: String) -> (pieces: [String], wildcards: [Int]) {
        var pieces: [String] = [""]
        var wildcards: [Int] = []
        var index = segment.startIndex
        while index < segment.endIndex {
            let rest = segment[index...]
            if rest.hasPrefix("{"), let close = rest.firstIndex(of: "}") {
                wildcards.append(pieces.count - 1)
                pieces.append("")
                index = segment.index(after: close)
            } else if let token = formatTokens.first(where: { rest.hasPrefix($0) }) {
                wildcards.append(pieces.count - 1)
                pieces.append("")
                index = segment.index(index, offsetBy: token.count)
            } else {
                pieces[pieces.count - 1].append(segment[index])
                index = segment.index(after: index)
            }
        }
        return (pieces, wildcards)
    }

    static func segmentsMatch(pattern: [String], _ literal: [String]) -> Bool {
        guard pattern.count == literal.count else { return false }
        return zip(pattern, literal).allSatisfy { segmentMatches(pattern: $0, $1) }
    }

    static func segmentMatches(pattern: String, _ text: String) -> Bool {
        guard pattern.utf8.count <= maximumSegmentBytes, text.utf8.count <= maximumSegmentBytes else { return false }
        let parsed = tokens(of: pattern)
        guard !parsed.wildcards.isEmpty else { return pattern == text }
        guard parsed.wildcards.count <= maximumWildcardsPerSegment else { return false }
        let pieces = parsed.pieces
        guard text.hasPrefix(pieces[0]), text.hasSuffix(pieces[pieces.count - 1]),
              text.count >= pieces.reduce(0, { $0 + $1.count }) + parsed.wildcards.count else { return false }
        // Each wildcard consumes at least one character; middle pieces must appear in order.
        var cursor = text.index(text.startIndex, offsetBy: pieces[0].count)
        let limit = text.index(text.endIndex, offsetBy: -pieces[pieces.count - 1].count)
        guard cursor <= limit else { return false }
        for piece in pieces.dropFirst().dropLast() {
            guard cursor < limit else { return false }
            let from = text.index(after: cursor)
            guard from <= limit,
                  let found = text.range(of: piece, range: from..<limit) else { return false }
            cursor = found.upperBound
        }
        return cursor < limit
    }

    static func redactedPath(_ segments: [String]) -> String? {
        guard !segments.isEmpty else { return nil }
        let shown = segments.map { hasPlaceholder($0) ? ":param" : $0 }
        return ProxymanPrivacy.minimizedPath("/" + shown.joined(separator: "/"))
    }
}
