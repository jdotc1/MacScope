import Foundation
import NetworkEvidenceCore

/// `endpoint-references`: where an observed network endpoint (a host, optionally with a path and
/// method) appears in the binary. Read-only and static: every row is a string-literal candidate
/// with the xref sites that reach it, and says so (`evidence: staticCandidate`). A row never proves
/// that the function runs or that the request is sent.
///
/// Privacy: the query is normalised by `EndpointQuery` before anything else, which drops URL query
/// values, fragments and user-info. Rows carry only the minimized host, path and scheme of the
/// matched string, never the string itself, so a credential embedded in a binary URL cannot leak.
extension WorkspaceScriptingAPI {
    nonisolated static let endpointEvidenceLabel = "staticCandidate"

    private struct EndpointSite {
        let match: Int
        let xref: XRef?
        let cfString: UInt64?
    }

    nonisolated static func endpointReferences(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        let query = try endpointQuery(arguments)
        let limit = try endpointPageLimit(arguments)
        let slot = try resolveImageSlot(arguments, snapshot: snapshot)
        let digest = endpointQueryDigest(query, slot: slot)
        let offset = try endpointCursorOffset(arguments["cursor"], snapshot: snapshot, slot: slot, digest: digest)
        try checkpoint()

        let analysis = snapshot.analysis(in: slot)
        let literals = analysis?.stringLiterals ?? (slot == snapshot.primarySlot ? snapshot.stringLiterals : [])
        var matches: [(literal: StringLiteralSummary, match: EndpointStringMatch)] = []
        for (index, literal) in literals.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            if let match = NetworkEndpointMatcher.match(query, string: literal.value) {
                matches.append((literal, match))
            }
        }
        matches.sort { $0.literal.address < $1.literal.address }

        let rowCap = maximumSnapshotRows
        let workCap = maximumSnapshotSelectionWork
        var used = 0
        let charge: () throws -> Void = {
            used += 1
            if used > workCap { throw WorkspaceSnapshot.XRefQueryFailure.workBudget }
        }
        var sites: [EndpointSite] = []
        do {
            var objectsByBacking: [UInt64: [UInt64]] = [:]
            var suppressed: [UInt64: Set<XRefEndpointKey>] = [:]
            if !matches.isEmpty {
                if let table = snapshot.cfStringBackings(in: slot) {
                    for (index, entry) in table.backings.enumerated() {
                        if index % checkpointInterval == 0 { try checkpoint() }
                        objectsByBacking[entry.value, default: []].append(entry.key)
                    }
                }
                for (index, edit) in snapshot.manualXRefs.enumerated() where edit.imageSlot == slot && edit.isSuppression {
                    if index % checkpointInterval == 0 { try checkpoint() }
                    suppressed[edit.to, default: []].insert(edit.endpointKey)
                }
            }
            for (index, entry) in matches.enumerated() {
                try checkpoint()
                let target = entry.literal.address
                let direct = try snapshot.boundedEffectiveXRefs(.to(target), in: slot, limit: nil,
                    maximumRows: rowCap - sites.count, maximumWork: workCap, chargeWork: charge, checkpoint: checkpoint)
                    .sorted { ($0.from, $0.kind) < ($1.from, $1.kind) }
                var found = direct.map { EndpointSite(match: index, xref: $0, cfString: nil) }
                for object in (objectsByBacking[target] ?? []).sorted() {
                    let hidden = suppressed[target] ?? []
                    let chained = try snapshot.boundedEffectiveXRefs(.to(object), in: slot, limit: nil,
                        maximumRows: rowCap - sites.count - found.count, maximumWork: workCap,
                        including: { !hidden.contains(XRefEndpointKey(from: $0.from, to: target, kind: $0.kind)) },
                        chargeWork: charge, checkpoint: checkpoint)
                        .sorted { ($0.from, $0.kind) < ($1.from, $1.kind) }
                    found += chained.map {
                        EndpointSite(match: index, xref: XRef(id: $0.id, from: $0.from, to: target, kind: $0.kind), cfString: object)
                    }
                }
                // A matching string nobody references is still a candidate; say so with null site fields.
                if found.isEmpty { found = [EndpointSite(match: index, xref: nil, cfString: nil)] }
                guard sites.count + found.count <= rowCap else { throw WorkspaceSnapshot.XRefQueryFailure.resultBudget }
                sites += found
            }
        } catch WorkspaceSnapshot.XRefQueryFailure.workBudget {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "endpoint-references exceeds the snapshot work budget",
                budget: .init(unit: .workSteps, limit: Int64(workCap)), used: Int64(workCap + 1),
                narrowing: ["path", "image"]))
        } catch WorkspaceSnapshot.XRefQueryFailure.resultBudget {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "endpoint-references exceeds the snapshot result budget; narrow the query with path or method",
                budget: .init(unit: .rows, limit: Int64(rowCap)), used: Int64(rowCap + 1),
                narrowing: ["path", "method", "image"]))
        }

        let siteRefs = sites.compactMap(\.xref)
        let named = try namedGraphRows(siteRefs, includeKind: true, snapshot: snapshot, slot: slot, checkpoint: checkpoint)
        var namedIterator = named.makeIterator()
        var rows: [ScriptValue] = []
        rows.reserveCapacity(sites.count)
        for (index, site) in sites.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            let entry = matches[site.match]
            var fields: [String: ScriptValue] = [
                "evidence": .string(endpointEvidenceLabel),
                "matchKind": .string(entry.match.kind.rawValue),
                "stringAddress": .hex(entry.literal.address),
                "cfStringAddress": site.cfString.map { ScriptValue.hex($0) } ?? .null,
                "scheme": entry.match.scheme.map { ScriptValue.string($0) } ?? .null,
                "host": entry.match.host.map { ScriptValue.string($0) } ?? .null,
                "path": entry.match.path.map { ScriptValue.string($0) } ?? .null,
                "method": entry.match.method.map { ScriptValue.string($0) } ?? .null,
                "imageSlot": .int(Int64(slot.rawValue)),
                "from": .null, "xrefKind": .null, "fromFunction": .null, "fromFunctionName": .null,
            ]
            if let xref = site.xref, case .object(let source)? = namedIterator.next() {
                fields["from"] = .hex(xref.from)
                fields["xrefKind"] = .string(xref.kind)
                fields["fromFunction"] = source["fromFunction"] ?? .null
                fields["fromFunctionName"] = source["fromFunctionName"] ?? .null
                if let demangled = source["fromFunctionDemangled"] { fields["fromFunctionDemangled"] = demangled }
            }
            rows.append(.object(fields))
        }

        guard offset <= rows.count else { throw staleEndpointCursor() }
        var page: [ScriptValue] = []
        var usedBytes = 0
        var position = offset
        while position < rows.count && page.count < limit {
            try checkpoint()
            let bytes = try listPageWireBytes(rows[position]) + 1
            if !page.isEmpty && bytes > maximumListPageBytes - usedBytes { break }
            page.append(rows[position])
            usedBytes += bytes
            position += 1
        }
        let next: ScriptValue = position < rows.count
            ? .string(encodeEndpointCursor(offset: position, snapshot: snapshot, slot: slot, digest: digest)) : .null
        let complete: ScriptValue
        switch analysis?.stringLiteralCoverage ?? (slot == snapshot.primarySlot ? snapshot.stringLiteralCoverage : nil) {
        case .some(.complete): complete = .bool(true)
        case .some(.incomplete), .some(.notAttempted): complete = .bool(false)
        case .none: complete = .null
        }
        return .object([
            "rows": .array(page), "total": .int(Int64(rows.count)),
            "isTruncated": .bool(next != .null), "nextCursor": next,
            "sourceComplete": complete, "totalIsExact": .bool(complete == .bool(true)),
            "imageSlot": .int(Int64(slot.rawValue)),
            "evidence": .string(endpointEvidenceLabel),
            "query": .object([
                "host": .string(query.host),
                "path": query.redactedPath.map { ScriptValue.string($0) } ?? .null,
                "method": query.method.map { ScriptValue.string($0) } ?? .null,
            ]),
        ])
    }

    // MARK: Arguments

    private nonisolated static func endpointQuery(_ arguments: ScriptValue) throws -> EndpointQuery {
        func optionalString(_ key: String) throws -> String? {
            switch arguments[key] {
            case .none, .some(.null): return nil
            case .some(.string(let text)): return text
            case .some: throw ScriptingError.invalidArgument("\(key) must be a string")
            }
        }
        guard let host = try optionalString("host") else { throw ScriptingError.missingArgument("host") }
        let path = try optionalString("path")
        let method = try optionalString("method")
        do { return try EndpointQuery(host: host, path: path, method: method) }
        catch let failure as EndpointQuery.Failure {
            // Fixed text only: the rejected input is never echoed.
            switch failure {
            case .host:
                throw ScriptingError.invalidArgument("host must be a hostname or an http, https, ws or wss URL")
            case .path:
                throw ScriptingError.invalidArgument("path must start with / and be at most 2048 bytes without control characters")
            case .method:
                throw ScriptingError.invalidArgument("method must be an HTTP method token")
            }
        }
    }

    private nonisolated static func endpointPageLimit(_ arguments: ScriptValue) throws -> Int {
        switch arguments["limit"] {
        case .none, .some(.null):
            return defaultListPageLimit
        case .some(.int(let value)) where (1...Int64(maximumListPageLimit)).contains(value):
            return Int(value)
        default:
            throw ScriptingError.invalidArgument("limit must be an integer from 1 to 1000")
        }
    }

    // MARK: Cursor

    /// FNV-1a over the normalised query and image; binds a cursor to its query without carrying it.
    private nonisolated static func endpointQueryDigest(_ query: EndpointQuery, slot: ImageSlot) -> String {
        var hash: UInt64 = 0xcbf29ce484222325
        let text = [query.host, query.segments?.joined(separator: "/") ?? "-", query.method ?? "-", String(slot.rawValue)]
            .joined(separator: "|")
        for byte in text.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
        let digits = String(hash, radix: 16)
        return String(repeating: "0", count: 16 - digits.count) + digits
    }

    private nonisolated static func encodeEndpointCursor(
        offset: Int, snapshot: WorkspaceSnapshot, slot: ImageSlot, digest: String
    ) -> String {
        Data("e1|\(slot.rawValue)|\(offset)|\(snapshot.analysisGenerationID.uuidString)|\(digest)".utf8).base64EncodedString()
    }

    private nonisolated static func staleEndpointCursor() -> ScriptingError {
        .invalidArgument("staleCursor: the list changed or the cursor belongs to another list; restart without a cursor")
    }

    private nonisolated static func endpointCursorOffset(
        _ value: ScriptValue?, snapshot: WorkspaceSnapshot, slot: ImageSlot, digest: String
    ) throws -> Int {
        guard let value, value != .null else { return 0 }
        func malformed() -> ScriptingError { .invalidArgument("malformed cursor") }
        guard case .string(let text) = value,
              text.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes,
              let data = Data(base64Encoded: text), data.base64EncodedString() == text,
              let decoded = String(data: data, encoding: .utf8) else { throw malformed() }
        let fields = decoded.split(separator: "|", omittingEmptySubsequences: false)
        guard fields.count == 5, fields[0] == "e1",
              let cursorSlot = Int(fields[1]), String(cursorSlot) == String(fields[1]),
              !fields[2].isEmpty, fields[2].utf8.allSatisfy({ (48...57).contains($0) }),
              let offset = Int(fields[2]), offset > 0,
              let generation = UUID(uuidString: String(fields[3])),
              fields[4].utf8.count == 16,
              fields[4].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw malformed() }
        guard cursorSlot == slot.rawValue, generation == snapshot.analysisGenerationID,
              String(fields[4]) == digest else { throw staleEndpointCursor() }
        return offset
    }
}
