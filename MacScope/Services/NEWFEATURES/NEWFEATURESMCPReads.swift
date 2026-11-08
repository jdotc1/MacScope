import Foundation
import NEWFEATURESCore

/// Typed, bounded NEWFEATURES MCP read logic. Pure over an already admitted graph
/// snapshot: this file does NOT self-register (registration is a separate hot-file
/// commit) and never reaches recursive decompilation.
enum NEWFEATURESMCPReads {
    static let callPathCommand = "verified-call-path"
    /// Catalog description for registration; states the difference from main's `call-path`.
    static let callPathSummary = "Simple paths over verified projection edges, each hop carrying per-edge call-site proof, unlike call-path which searches raw explicit calls without proof."
    static let callPathInfo = ScriptingCommandInfo(
        name: callPathCommand, summary: callPathSummary, mutates: false,
        arguments: [WorkspaceScriptingAPI.imageSlotFilterArgument, "source", "target", "maxDepth", "limit", "cursor"])
    static let callPathRequired = [WorkspaceScriptingAPI.imageSlotFilterArgument, "source", "target"]

    static func validate(_ fields: [String: ScriptValue]) throws { _ = try parseCallPath(.object(fields)) }

    static func argumentSchema(_ argument: String) -> ScriptValue {
        if argument == "maxDepth" {
            return .object(["type": .string("integer"), "minimum": .int(0), "maximum": .int(Int64(maximumDepth)),
                            "description": .string("Longest path in hops (default \(defaultMaxDepth))." )])
        }
        return .object(["type": .array([.string("integer"), .string("string")]),
                        "description": .string("A function address in the image: integer or 0x-prefixed hex string. Required.")])
    }

    static let defaultLimit = 10
    /// Same page ceiling the shared navigator `limit` schema advertises; the response-byte cap and
    /// `maximumEnumeratedPaths` bound the work and the answer.
    static let maximumLimit = NavigatorMCPCommands.maximumPageLimit
    static let defaultMaxDepth = 5
    static let maximumDepth = 16
    /// Exactly the existing MCP inner-payload admission: half the production output cap.
    static var maximumResponseBytes: Int { MCPServer.Configuration.production.maximumOutputBytes / 2 }
    static let maximumEnumeratedPaths = 1_000

    struct CallPathRequest: Equatable {
        let source: UInt64
        let target: UInt64
        let maxDepth: Int
        let limit: Int
        let offset: Int
        let cursor: String?
    }

    // MARK: - Argument validation (named errors)

    static func parseCallPath(_ arguments: ScriptValue) throws -> CallPathRequest {
        guard case .object(let fields) = arguments else {
            throw ToolArgumentError(field: "arguments", detail: "Arguments must be an object.", expected: "object")
        }
        func address(_ name: String) throws -> UInt64 {
            guard let value = fields[name], value != .null else {
                throw ToolArgumentError(field: name, detail: "Field '\(name)' is required.",
                                        expected: "address as integer or 0x-prefixed hex string")
            }
            guard let parsed = value.addressValue else {
                throw ToolArgumentError(field: name, detail: "Field '\(name)' is not a valid address.",
                                        expected: "address as integer or 0x-prefixed hex string")
            }
            return parsed
        }
        func integer(_ name: String, default fallback: Int, _ range: ClosedRange<Int>) throws -> Int {
            guard let value = fields[name], value != .null else { return fallback }
            guard let parsed = value.intValue, range.contains(Int(clamping: parsed)) else {
                throw ToolArgumentError(field: name,
                                        detail: "Field '\(name)' must be an integer in \(range.lowerBound)...\(range.upperBound).",
                                        expected: "integer", minimum: Int64(range.lowerBound),
                                        maximum: Int64(range.upperBound))
            }
            return Int(parsed)
        }
        let source = try address("source")
        let target = try address("target")
        let maxDepth = try integer("maxDepth", default: defaultMaxDepth, 0...maximumDepth)
        let limit = try integer("limit", default: defaultLimit, 1...maximumLimit)
        var cursor: String?
        var offset = 0
        if let value = fields["cursor"], value != .null {
            guard let text = value.stringValue, text.utf8.count <= 256 else {
                throw ToolArgumentError(field: "cursor", detail: "Field 'cursor' must be a string from nextCursor.",
                                        expected: "string")
            }
            cursor = text
            guard let decoded = decodeCursor(text, source: source, target: target, maxDepth: maxDepth) else {
                throw ToolArgumentError(field: "cursor", code: .preconditionFailed,
                                        detail: "Cursor is malformed or was issued for different source, target or maxDepth.",
                                        expected: "nextCursor from the same selectors")
            }
            offset = decoded.offset
        }
        return CallPathRequest(source: source, target: target, maxDepth: maxDepth, limit: limit,
                               offset: offset, cursor: cursor)
    }

    // MARK: - Cursor (bound to the source revision)

    private static func cursorPrefix(_ image: NEWFEATURESImageKey?) -> String {
        guard let image else { return "" }
        return "\(image.analysisRevision)-\(image.analysisInputFingerprintSHA256.prefix(16))"
    }

    static func encodeCursor(offset: Int, image: NEWFEATURESImageKey, source: UInt64, target: UInt64,
                             maxDepth: Int) -> String {
        "nfp1.\(offset).\(cursorPrefix(image)).\(String(source, radix: 16)).\(String(target, radix: 16)).\(maxDepth)"
    }

    /// Syntax and selector binding only; revision binding is checked against the live image.
    static func decodeCursor(_ text: String, source: UInt64, target: UInt64, maxDepth: Int)
        -> (offset: Int, revision: String)? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 6, parts[0] == "nfp1", let offset = Int(parts[1]), offset >= 0,
              parts[4] == String(target, radix: 16), parts[3] == String(source, radix: 16),
              parts[5] == String(maxDepth) else { return nil }
        return (offset, parts[2])
    }

    // MARK: - Response

    static func callPath(
        request: CallPathRequest,
        graph: NEWFEATURESGraphSnapshot,
        source: NEWFEATURESFunctionKey,
        destination: NEWFEATURESFunctionKey,
        budget: NEWFEATURESReadBudget,
        operation: NEWFEATURESGraphOperation,
        maximumResponseBytes: Int = NEWFEATURESMCPReads.maximumResponseBytes
    ) throws -> ScriptValue {
        let image = graph.image
        if let cursor = request.cursor {
            guard let decoded = decodeCursor(cursor, source: request.source, target: request.target,
                                             maxDepth: request.maxDepth),
                  decoded.revision == cursorPrefix(image) else {
                throw ToolArgumentError(field: "cursor", code: .preconditionFailed,
                                        detail: "Cursor was issued for a different analysis revision; restart without a cursor.",
                                        expected: "nextCursor from the current analysis revision")
            }
        }
        let enumeration = try NEWFEATURESPathEnumerator.enumerate(
            from: source, to: destination, graph: graph, maxDepth: request.maxDepth,
            maxPaths: maximumEnumeratedPaths, budget: budget, operation: operation
        )
        let total = enumeration.paths.count
        let deterministicCut = enumeration.cut == nil || enumeration.cut == .pathLimit
            || enumeration.cut == .edgeVisitLimit
        let start = min(request.offset, total)
        var count = min(request.limit, total - start)
        while true {
            let value = response(request: request, enumeration: enumeration, image: image, source: source,
                                 destination: destination, start: start, count: count,
                                 deterministicCut: deterministicCut)
            let size = (try? value.jsonData().count) ?? Int.max
            if size <= maximumResponseBytes { return value }
            guard count > 1 else {
                throw ToolArgumentError(field: "limit", code: .budgetExceeded,
                                        detail: "A single path exceeds the response cap.", expected: "smaller maxDepth")
            }
            count = count / 2
        }
    }

    private static func function(_ key: NEWFEATURESFunctionKey) -> ScriptValue {
        .object(["address": .string("0x" + String(key.address, radix: 16))])
    }

    private static func proof(_ confidence: NEWFEATURESCallConfidence) -> String {
        switch confidence {
        case .confirmedDirect: return "retained BL instruction word decodes to the callee entry and matches the call xref"
        case .provenIndirect: return "indirect call target proven"
        case .unverified: return "unverified"
        }
    }

    private static func response(
        request: CallPathRequest, enumeration: NEWFEATURESPathEnumeration, image: NEWFEATURESImageKey,
        source: NEWFEATURESFunctionKey, destination: NEWFEATURESFunctionKey,
        start: Int, count: Int, deterministicCut: Bool
    ) -> ScriptValue {
        let total = enumeration.paths.count
        let end = start + count
        let page = enumeration.paths[start..<end].enumerated().map { entry -> ScriptValue in
            let hops = entry.element
            return .object([
                "index": .int(Int64(start + entry.offset)),
                "hopCount": .int(Int64(hops.count)),
                "functions": .array(([hops.first?.caller ?? source] + hops.map(\.callee)).map(function)),
                "edges": .array(hops.map { hop in
                    .object([
                        "caller": function(hop.caller),
                        "callee": function(hop.callee),
                        "callSiteCount": .int(Int64(hop.siteCount)),
                        "evidence": .array(hop.sites.map { site in
                            .object([
                                "callSite": .string("0x" + String(site.callSite, radix: 16)),
                                "confidence": .string(site.confidence.rawValue),
                                "proof": .string(proof(site.confidence)),
                            ])
                        }),
                    ])
                }),
            ])
        }
        let more = end < total
        let status: String
        if total > 0 { status = "found" }
        else if enumeration.isComplete { status = "notFoundInObservedGraph" }
        else { status = "searchCut" }
        var fields: [String: ScriptValue] = [
            "command": .string(callPathCommand),
            "status": .string(status),
            "source": function(source),
            "target": function(destination),
            "boundTo": .object([
                "imageSlot": .int(Int64(image.slot)),
                "imageID": .string(image.binaryID.uuidString),
                "sha256": .string(image.sha256),
                "analysisRevision": .string(String(image.analysisRevision)),
                "analysisInputFingerprintSHA256": .string(image.analysisInputFingerprintSHA256),
                "ledger": .string("verified direct-call projection of this analysis revision"),
            ]),
            "searchBound": .object([
                "maxDepth": .int(Int64(enumeration.maxDepth)),
                "maxEdgeVisits": .int(Int64(enumeration.maxEdgeVisits)),
                "edgeVisits": .int(Int64(enumeration.edgeVisits)),
                "maxEnumeratedPaths": .int(Int64(enumeration.maxPaths)),
                "cut": enumeration.cut.map { .string($0.rawValue) } ?? .null,
                "unverifiedEdgesObservedNotTraversed": .int(Int64(enumeration.observedUnverifiedEdges)),
            ]),
            "totalPaths": .int(Int64(total)),
            "totalIsLowerBound": .bool(!enumeration.isComplete),
            "isTruncated": .bool(more || !enumeration.isComplete),
            "returnedPaths": .int(Int64(count)),
            "paths": .array(page),
            "claim": .string("simple paths over verified observed call references within searchBound only; absence is not proof of no runtime path"),
        ]
        fields["nextCursor"] = more && deterministicCut
            ? .string(encodeCursor(offset: end, image: image, source: request.source, target: request.target,
                                   maxDepth: request.maxDepth))
            : .null
        return .object(fields)
    }
}
