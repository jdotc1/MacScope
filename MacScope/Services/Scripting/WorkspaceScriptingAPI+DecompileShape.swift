import Foundation

/// Opt-in decompile projection. Null shape keys are absent; omitted format means text.
/// lineRange is inclusive, positional `a-b` with positive, at-most-nine-digit endpoints.
/// Invalid syntax uses the fixed format/lineRange/malformed-cursor refusal texts below.
/// Whole-line code values are bounded by maximumListPageBytes, except that one first
/// line is always retained. The finished reply is bounded separately, after all fields.
/// Continuations bind slot, start, generation and backend/full-text FNV-1a; not format.
struct DecompileShape: Equatable, Sendable {
    enum Format: String, Equatable, Sendable { case text, lines }
    let format: Format
    let lineRange: ClosedRange<Int>?
    let cursor: String?
}

extension WorkspaceScriptingAPI {
    nonisolated static func decompileShape(_ arguments: ScriptValue) throws -> DecompileShape? {
        func present(_ key: String) -> ScriptValue? {
            guard let value = arguments[key], value != .null else { return nil }
            return value
        }
        let formatValue = present("format"), rangeValue = present("lineRange"), cursorValue = present("cursor")
        guard formatValue != nil || rangeValue != nil || cursorValue != nil else { return nil }
        let format: DecompileShape.Format
        if let formatValue {
            guard let text = formatValue.stringValue, let parsed = DecompileShape.Format(rawValue: text) else {
                throw ScriptingError.invalidArgument("format must be \"text\" or \"lines\"")
            }
            format = parsed
        } else { format = .text }
        var range: ClosedRange<Int>?
        if let rangeValue {
            func invalid() -> ScriptingError { .invalidArgument("lineRange must be \"a-b\" with 1 <= a <= b") }
            guard let text = rangeValue.stringValue, text.utf8.prefix(33).count <= 32 else { throw invalid() }
            let parts = text.split(separator: "-", omittingEmptySubsequences: false)
            func endpoint(_ part: Substring) -> Int? {
                guard (1...9).contains(part.utf8.count), let first = part.utf8.first, (49...57).contains(first),
                      part.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
                return Int(part)
            }
            guard parts.count == 2, let first = endpoint(parts[0]), let last = endpoint(parts[1]), first <= last else { throw invalid() }
            range = first...last
        }
        if range != nil, cursorValue != nil {
            throw ScriptingError.invalidArgument("lineRange cannot be combined with cursor")
        }
        var cursor: String?
        if let cursorValue {
            guard let text = cursorValue.stringValue,
                  text.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes else {
                throw ScriptingError.invalidArgument("malformed cursor")
            }
            cursor = text
        }
        return DecompileShape(format: format, lineRange: range, cursor: cursor)
    }

    private nonisolated static func decompileDocumentDigest(backend: String, text: String) -> String {
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in backend.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
        hash = hash &* 0x100000001b3 // The separating NUL byte.
        for byte in text.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
        let hex = String(hash, radix: 16)
        return String(repeating: "0", count: 16 - hex.count) + hex
    }

    private nonisolated static func decodeDecompileCursor(
        _ cursor: String
    ) throws -> (slot: Int, start: UInt64, next: Int, generation: UUID, digest: String, fold: String) {
        func malformed() -> ScriptingError { .invalidArgument("malformed cursor") }
        guard cursor.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes,
              let data = Data(base64Encoded: cursor), data.base64EncodedString() == cursor,
              let body = String(data: data, encoding: .utf8) else { throw malformed() }
        let fields = body.split(separator: "|", omittingEmptySubsequences: false)
        // d1: no fold. d2: the fold kinds are bound explicitly after the text digest (E4 Q5).
        let isFold = fields.count == 7 && fields[0] == "d2"
        guard fields.count == 6 && fields[0] == "d1" || isFold,
              !isFold || (fields[6].utf8.count <= 64 && !fields[6].isEmpty
                  && fields[6].utf8.allSatisfy({ (97...122).contains($0) || $0 == 44 })),
              let slot = Int(fields[1]), slot >= 0, String(slot) == String(fields[1]),
              let start = UInt64(fields[2]), String(start) == String(fields[2]),
              let next = Int(fields[3]), next >= 2, String(next) == String(fields[3]),
              let generation = UUID(uuidString: String(fields[4])),
              fields[5].utf8.count == 16,
              fields[5].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw malformed() }
        return (slot, start, next, generation, String(fields[5]), isFold ? String(fields[6]) : "")
    }

    nonisolated static func shapedDecompileFields(
        _ fields: [String: ScriptValue], shape: DecompileShape,
        slot: ImageSlot, functionStart: UInt64, snapshot: WorkspaceSnapshot,
        backend: String, fullText: String, lineCount: Int,
        textAt: (Int) -> String, lineAt: (Int) -> ScriptValue,
        nativeDocumentTruncated: Bool? = nil, foldMode: String? = nil, checkpoint: () throws -> Void
    ) throws -> [String: ScriptValue] {
        let digest = decompileDocumentDigest(backend: backend, text: fullText)
        var first = shape.lineRange?.lowerBound ?? 1
        let end = min(shape.lineRange?.upperBound ?? lineCount, lineCount)
        if shape.lineRange != nil, lineCount == 0 || first > lineCount {
            throw ScriptingError.invalidArgument("lineRange starts past the end: the function has \(lineCount) lines")
        }
        if let cursor = shape.cursor {
            let decoded = try decodeDecompileCursor(cursor)
            guard decoded.fold == (foldMode ?? "") else {
                throw ScriptingError.invalidArgument("staleCursor: the cursor was issued for another fold mode; restart without a cursor or repeat the same fold")
            }
            guard decoded.slot == slot.rawValue, decoded.start == functionStart,
                  decoded.generation == snapshot.analysisGenerationID, decoded.digest == digest,
                  decoded.next <= lineCount else {
                throw ScriptingError.invalidArgument("staleCursor: the decompile changed or the cursor belongs to another function; restart without a cursor")
            }
            first = decoded.next
        }
        let emptyTextBytes = try listPageWireBytes(.string(""))
        let joinerBytes = try listPageWireBytes(.string("\n")) - emptyTextBytes
        var bytes: Int
        if shape.format == .text { bytes = emptyTextBytes }
        else { bytes = try listPageWireBytes(.array([])) }
        var texts: [String] = []
        var rows: [ScriptValue] = []
        var count = 0
        var stopped = false
        for index in 0..<lineCount {
            // Preserve the legacy MacIR line-walk checkpoints, including skipped positions.
            if index > 0, index.isMultiple(of: 1_024) { try checkpoint() }
            guard !stopped, index + 1 >= first, index + 1 <= end else { continue }
            let text = textAt(index)
            let row: ScriptValue? = shape.format == .lines ? lineAt(index) : nil
            let increment: Int
            if let row { increment = try listPageWireBytes(row) + (count == 0 ? 0 : 1) }
            else { increment = try listPageWireBytes(.string(text)) - emptyTextBytes + (count == 0 ? 0 : joinerBytes) }
            let (nextBytes, overflow) = bytes.addingReportingOverflow(increment)
            if count > 0, overflow || nextBytes > maximumListPageBytes { stopped = true; continue }
            bytes = overflow ? Int.max : nextBytes
            if let row { rows.append(row) } else { texts.append(text) }
            count += 1
        }
        func codeValue() -> ScriptValue {
            shape.format == .text ? .string(texts.joined(separator: "\n")) : .array(rows)
        }
        // Check the complete value too: serialization policy cannot silently defeat the cap.
        while count > 1, try listPageWireBytes(codeValue()) > maximumListPageBytes {
            if shape.format == .text { texts.removeLast() } else { rows.removeLast() }
            count -= 1
        }
        let last = count == 0 ? nil : first + count - 1
        var cursor: ScriptValue = .null
        if let last, last < lineCount {
            var body = "\(foldMode == nil ? "d1" : "d2")|\(slot.rawValue)|\(functionStart)|\(last + 1)|\(snapshot.analysisGenerationID.uuidString)|\(digest)"
            if let foldMode { body += "|" + foldMode }
            cursor = .string(Data(body.utf8).base64EncodedString())
        }
        var result = fields
        result.removeValue(forKey: "pseudocode"); result.removeValue(forKey: "lines")
        result[shape.format == .text ? "pseudocode" : "lines"] = codeValue()
        result["lineCount"] = .int(Int64(lineCount))
        result["firstLine"] = count == 0 ? .null : .int(Int64(first))
        result["lastLine"] = last.map { .int(Int64($0)) } ?? .null
        result["nextCursor"] = cursor
        result["truncated"] = .bool(cursor != .null || nativeDocumentTruncated == true)
        if let nativeDocumentTruncated { result["documentTruncated"] = .bool(nativeDocumentTruncated) }
        // Keep `complete` as the native document's original claim. A page can
        // omit lines even when that document is complete; report the reply separately.
        if case .bool(let documentComplete)? = fields["complete"] {
            result["responseComplete"] = .bool(documentComplete && nativeDocumentTruncated != true
                && first == 1 && count == lineCount)
        }
        if shape.cursor != nil { result.removeValue(forKey: "regions") }
        return result
    }
}

/// Original logical lines, not lines inferred by splitting an encoded page.
struct DecompileReplySource: Sendable {
    let text: String
    let lines: [String]
}

extension WorkspaceScriptingAPI {
    nonisolated static let maximumDecompileReplyBytes = 200_000

    /// Object frame + LF with id 1 and the synthetic single-generation envelope.
    /// The constants are frozen by MCPToolReplySizeOracle tests (legacy / structured).
    nonisolated static func decompileReplyFrameBytes(_ reply: ScriptValue) throws -> Int {
        max(try listPageWireBytes(reply) + 235, try reply.jsonData().count + 305)
    }

    /// Call only after provenance, selector, fold and paired fields have been assembled.
    /// Fitting replies are returned verbatim. Unknown fields are required, not discardable.
    nonisolated static func boundedDecompileReply(
        _ reply: ScriptValue, shape: DecompileShape?, slot: ImageSlot,
        functionStart: UInt64, snapshot: WorkspaceSnapshot,
        sources: [String: DecompileReplySource], foldMode: String? = nil,
        refreshPage: (inout [String: ScriptValue]) -> Void = { _ in }
    ) throws -> ScriptValue {
        guard shape != nil, case .object(var fields) = reply else { return reply }
        let limit = maximumDecompileReplyBytes
        if try decompileReplyFrameBytes(reply) <= limit { return reply }
        let paired = fields["backend"] == .string("both")
        let paths = paired ? ["native", "macir"] : [""]
        func page(_ path: String, _ object: [String: ScriptValue]) -> [String: ScriptValue]? {
            if path.isEmpty { return object }
            if case .object(let value)? = object[path] { return value }
            return nil
        }
        func replacing(_ path: String, _ value: [String: ScriptValue],
                       in object: [String: ScriptValue]) -> [String: ScriptValue] {
            if path.isEmpty { return value }
            var result = object; result[path] = .object(value); return result
        }
        // A paired reply spends one budget: shorten native first, then MacIR.
        for path in paths {
            guard let original = page(path, fields),
                  let first = original["firstLine"]?.intValue,
                  let last = original["lastLine"]?.intValue, last > first else { continue }
            let count = Int(last - first + 1)
            guard let backend = original["backend"]?.stringValue, let source = sources[backend],
                  first > 0, last <= Int64(source.lines.count) else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
                    detail: "decompile reply has no matching logical-line source"))
            }
            let digest = decompileDocumentDigest(backend: backend, text: source.text)
            let base = fields
            func candidate(_ kept: Int) -> [String: ScriptValue] {
                var value = original
                if let rows = original["lines"]?.arrayValue {
                    value["lines"] = .array(Array(rows.prefix(kept)))
                } else {
                    value["pseudocode"] = .string(source.lines.dropFirst(Int(first) - 1)
                        .prefix(kept).joined(separator: "\n"))
                }
                let end = first + Int64(kept) - 1
                var body = "\(foldMode == nil ? "d1" : "d2")|\(slot.rawValue)|\(functionStart)|\(end + 1)|\(snapshot.analysisGenerationID.uuidString)|\(digest)"
                if let foldMode { body += "|" + foldMode }
                value["lastLine"] = .int(end)
                value["nextCursor"] = .string(Data(body.utf8).base64EncodedString())
                value["truncated"] = .bool(true)
                value["responseComplete"] = .bool(false)
                if !paired { refreshPage(&value) }
                return replacing(path, value, in: base)
            }
            fields = candidate(1)
            if try decompileReplyFrameBytes(.object(fields)) <= limit {
                // Keep only candidates actually measured to fit. Cursor escaping need not
                // be monotonic; binary search may underfill, but cannot admit an oversize page.
                var low = 2, high = count - 1
                while low <= high {
                    let middle = low + (high - low) / 2
                    let trial = candidate(middle)
                    if try decompileReplyFrameBytes(.object(trial)) <= limit {
                        fields = trial; low = middle + 1
                    } else { high = middle - 1 }
                }
                return .object(fields)
            }
        }
        // Only after every code value is at its minimum may whole optional fields go.
        let optional: Set<String> = [
            "regions", "unplacedComments", "callTargetNames", "commentsTotal", "commentsPlaced",
            "folded", "foldedEvents", "foldedEventsTruncated", "foldRefused",
            "unfoldedLineCount", "foldedLineCount", "structureFallback", "demangled",
            "cache", "generation", "structured", "language", "backendRequested",
        ]
        var omissions: [(path: String, key: String, name: String, bytes: Int)] = []
        for path in paired ? [""] + paths : paths {
            guard let value = page(path, fields) else { continue }
            for (key, item) in value where optional.contains(key) {
                omissions.append((path, key, path.isEmpty ? key : path + "." + key,
                    try listPageWireBytes(.object([key: item]))))
            }
        }
        omissions.sort { $0.bytes == $1.bytes ? $0.name < $1.name : $0.bytes > $1.bytes }
        var names: [ScriptValue] = []
        for omission in omissions {
            guard var value = page(omission.path, fields) else { continue }
            value.removeValue(forKey: omission.key)
            value["responseComplete"] = .bool(false)
            fields = replacing(omission.path, value, in: fields)
            names.append(.string(omission.name))
            fields["omittedFields"] = .array(names)
            fields["responseComplete"] = .bool(false)
            if try decompileReplyFrameBytes(.object(fields)) <= limit { return .object(fields) }
        }
        // D2 is a single code value / single logical line, never two oversized backends.
        let code = fields["pseudocode"] ?? fields["lines"]
        if !paired, fields["firstLine"] != .null, fields["firstLine"] != nil,
           fields["firstLine"] == fields["lastLine"], let code {
            // Payload contribution, not a standalone scalar/array MCP envelope.
            let legacyCodeBytes = try listPageWireBytes(code)
            let structuredCodeBytes = try code.jsonData().count
            if legacyCodeBytes > limit - 235 || structuredCodeBytes > limit - 305 {
                return .object(fields)
            }
        }
        let used = try decompileReplyFrameBytes(.object(fields))
        throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "decompile reply cannot fit its required fields and first line; no partial output is returned",
            budget: .init(unit: .bytes, limit: Int64(limit)), used: Int64(clamping: used),
            narrowing: ["lineRange", "format", "backend"]))
    }
}

// MARK: - E4 fold reply fields

extension WorkspaceScriptingAPI {
    /// At most this many folded events are returned per reply page.
    nonisolated static let maximumFoldedEvents = 500
    /// At most this many individual refusals are listed; reason counts are always complete.
    nonisolated static let maximumFoldRefusalEntries = 50

    nonisolated static func foldModeText(_ kinds: Set<PseudocodeFoldKind>) -> String {
        kinds.map(\.rawValue).sorted().joined(separator: ",")
    }

    /// `folded` is always present for a non-empty fold request. Events follow the returned line
    /// page: an event is listed on the page holding its anchor line, and events with no rendered
    /// anchor go on the final page. The list is capped and `foldedEventsTruncated` says so.
    nonisolated static func applyFoldFields(
        _ fields: inout [String: ScriptValue], kinds: Set<PseudocodeFoldKind>, report: PseudocodeFoldReport?
    ) {
        let report = report ?? PseudocodeFoldReport()
        var folded: [String: ScriptValue] = [:]
        for kind in kinds { folded[kind.rawValue] = .int(Int64(report.counts[kind] ?? 0)) }
        fields["folded"] = .object(folded)
        let shaped = fields["firstLine"] != nil
        let first = fields["firstLine"]?.intValue
        let last = fields["lastLine"]?.intValue
        let finalPage = fields["nextCursor"].map { $0 == .null } ?? true
        let page = report.events.filter { event in
            guard shaped else { return true }
            guard let line = event.beforeLine else { return finalPage }
            guard let first, let last else { return false }
            return Int64(line) >= first && Int64(line) <= last
        }
        var events: [ScriptValue] = []
        for event in page.prefix(maximumFoldedEvents) {
            var row: [String: ScriptValue] = [
                "address": .hex(event.address), "kind": .string(event.kind.rawValue),
                "callee": .string(event.callee), "role": .string(event.role.rawValue),
            ]
            if let value = event.replacedWith { row["replacedWith"] = .string(value) }
            if let value = event.comment { row["comment"] = .string(value) }
            if let value = event.commentPlacedAt { row["commentPlacedAt"] = .hex(value) }
            if let value = event.beforeLine { row["beforeLine"] = .int(Int64(value)) }
            events.append(.object(row))
        }
        fields["foldedEvents"] = .array(events)
        fields["foldedEventsTruncated"] = .bool(page.count > maximumFoldedEvents)
        if !report.refused.isEmpty {
            var reasons: [String: Int64] = [:]
            for refusal in report.refused { reasons[refusal.reason, default: 0] += 1 }
            let entries = report.refused.prefix(maximumFoldRefusalEntries).map { refusal -> ScriptValue in
                var row: [String: ScriptValue] = ["reason": .string(refusal.reason)]
                if let address = refusal.address { row["address"] = .hex(address) }
                if let callee = refusal.callee { row["callee"] = .string(callee) }
                return .object(row)
            }
            fields["foldRefused"] = .object([
                "count": .int(Int64(report.refused.count)),
                "reasons": .object(reasons.mapValues { .int($0) }),
                "entries": .array(entries),
                "entriesTruncated": .bool(report.refused.count > maximumFoldRefusalEntries),
            ])
        }
    }
}
