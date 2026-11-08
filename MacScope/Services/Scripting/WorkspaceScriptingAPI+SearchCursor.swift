import Foundation

extension WorkspaceScriptingAPI {
    nonisolated static let maximumSearchCursorBytes = 1_024

    private nonisolated static func searchKindsMask(_ kinds: Set<BinarySearchResult.Kind>) -> Int {
        BinarySearchResult.Kind.allCases.enumerated().reduce(0) {
            kinds.contains($1.element) ? $0 | (1 << $1.offset) : $0
        }
    }

    nonisolated static func encodeSearchCursor(
        _ point: BinarySearchService.SearchResumePoint, cumulative: Int,
        query: String, mode: BinarySearchMode, kinds: Set<BinarySearchResult.Kind>,
        slotFilter: ImageSlot?, snapshot: WorkspaceSnapshot
    ) -> String {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let fields = [
            "s1", snapshot.analysisGenerationID.uuidString, mode.rawValue,
            String(searchKindsMask(kinds)), slotFilter.map { String($0.rawValue) } ?? "-",
            point.phase.rawValue, String(point.slot.rawValue), String(point.kindIndex),
            String(point.row), String(point.hexSection), String(point.hexOffset),
            String(cumulative), String(searchKindsMask(point.prefixLimited)),
            Data(needle.utf8).base64EncodedString(),
        ]
        return Data(fields.joined(separator: "|").utf8).base64EncodedString()
    }

    nonisolated static func decodeSearchCursor(
        _ value: ScriptValue, query: String, mode: BinarySearchMode,
        kinds: Set<BinarySearchResult.Kind>, slotFilter: ImageSlot?, snapshot: WorkspaceSnapshot
    ) throws -> (point: BinarySearchService.SearchResumePoint, cumulative: Int) {
        func malformed() -> ScriptingError { .invalidArgument("malformed cursor") }
        guard case .string(let text) = value,
              text.utf8.prefix(maximumSearchCursorBytes + 1).count <= maximumSearchCursorBytes,
              let data = Data(base64Encoded: text), data.base64EncodedString() == text,
              let decoded = String(data: data, encoding: .utf8) else { throw malformed() }
        let fields = decoded.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 14, fields[0] == "s1",
              let generation = UUID(uuidString: fields[1]),
              let encodedMode = BinarySearchMode(rawValue: fields[2]),
              let phase = BinarySearchService.SearchResumePoint.Phase(rawValue: fields[5]) else {
            throw malformed()
        }
        func number(_ index: Int) throws -> Int {
            guard let n = Int(fields[index]), n >= 0, String(n) == fields[index] else { throw malformed() }
            return n
        }
        let mask = try number(3)
        let filter: Int?
        if fields[4] == "-" { filter = nil } else { filter = try number(4) }
        let slot = try number(6), kindIndex = try number(7), row = try number(8)
        let section = try number(9), offset = try number(10)
        let cumulative = try number(11), prefixMask = try number(12)
        let allMask = (1 << BinarySearchResult.Kind.allCases.count) - 1
        guard mask <= allMask, prefixMask <= allMask, cumulative <= Int.max - 501,
              let queryData = Data(base64Encoded: fields[13]),
              queryData.base64EncodedString() == fields[13],
              let encodedQuery = String(data: queryData, encoding: .utf8),
              encodedQuery.utf8.count <= 256 else { throw malformed() }
        switch phase {
        case .metadataQuantum, .metadataRest:
            guard kindIndex < 3, section == 0, offset == 0 else { throw malformed() }
        case .instructions:
            guard kindIndex == 0, section == 0, offset == 0 else { throw malformed() }
        case .hex:
            guard kindIndex == 0, row == 0 else { throw malformed() }
        }
        let prefix = Set(BinarySearchResult.Kind.allCases.enumerated().compactMap {
            prefixMask & (1 << $0.offset) == 0 ? nil : $0.element
        })
        guard generation == snapshot.analysisGenerationID, encodedMode == mode,
              mask == searchKindsMask(kinds), filter == slotFilter?.rawValue,
              encodedQuery == query.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw ScriptingError.invalidArgument(
                "staleCursor: the analysis changed or the cursor belongs to another search; restart without a cursor")
        }
        let startForHex = phase == .metadataQuantum && slot == 0 && kindIndex == 0 &&
            row == 0 && section == 0 && offset == 0
        guard mode == .hex ? (phase == .hex || startForHex) : phase != .hex,
              prefix.isSubset(of: mode == .hex ? kinds.intersection([.bytes]) :
                  kinds.intersection([.instruction, .string, .symbol, .function])) else { throw malformed() }
        return (.init(phase: phase, slot: ImageSlot(rawValue: slot), kindIndex: kindIndex,
                      row: row, hexSection: section, hexOffset: offset, prefixLimited: prefix), cumulative)
    }

    nonisolated static func searchIncompleteReply(
        _ outcome: BinarySearchService.BoundedOutcome, nextCursor: ScriptValue, cumulative: Int,
        limit: Int = BinarySearchService.defaultLimit
    ) -> ScriptValue {
        let resumable = outcome.resumePoint != nil
        var refusal = MCPToolRefusal(
            code: resumable ? .budgetExceeded : .preconditionFailed,
            detail: "Search is incomplete, not a zero-match result. " +
                (resumable ? "Resume with cursor, or narrow kind and imageSlot." :
                    "A source or retained prefix is incomplete; narrow kind, or use strings section where available."),
            retryable: resumable)
        refusal.narrowing = resumable ? ["cursor", "kind", "imageSlot"] :
            (outcome.sourceIncomplete[.string] == nil ? ["kind"] : ["kind", "section"])
        if resumable {
            switch outcome.stoppedBy {
            case .workSteps:
                refusal.budget = .init(unit: .workSteps, limit: 200_000)
                refusal.used = Int64(outcome.visits)
            case .deadline:
                refusal.budget = .init(unit: .wallMillis, limit: 2_000)
                refusal.used = outcome.elapsedMillis.map { Int64($0) }
            case .matchLimit:
                refusal.budget = .init(unit: .rows, limit: Int64(min(500, max(1, limit))))
                refusal.used = Int64(min(500, max(1, limit)) + 1)
            case .preparation, nil: break
            }
        }
        var fields: [String: ScriptValue] = [:]
        if case .object(let outer) = refusal.value, case .object(let base)? = outer["refusal"] {
            fields = base
        }
        fields["kindsCovered"] = .array(outcome.kindsCovered.map(\.rawValue).sorted().map(ScriptValue.string))
        fields["kindsPending"] = .array(outcome.kindsPending.map(\.rawValue).sorted().map(ScriptValue.string))
        fields["sourceIncomplete"] = .object(Dictionary(uniqueKeysWithValues:
            outcome.sourceIncomplete.map { ($0.key.rawValue, ScriptValue.string($0.value)) }))
        fields["stoppedBy"] = outcome.stoppedBy.map { .string($0.rawValue) } ?? .null
        fields["nextCursor"] = nextCursor
        fields["lowerBound"] = .int(Int64(cumulative))
        return .object(["error": .string("refused"), "refusal": .object(fields)])
    }

    nonisolated static func searchPageReply(
        _ outcome: BinarySearchService.BoundedOutcome, cumulative: Int,
        query: String, mode: BinarySearchMode, kinds: Set<BinarySearchResult.Kind>,
        slotFilter: ImageSlot?, snapshot: WorkspaceSnapshot
    ) -> ScriptValue {
        let nextCursor: ScriptValue = outcome.resumePoint.map {
            .string(encodeSearchCursor($0, cumulative: cumulative + outcome.results.count,
                query: query, mode: mode, kinds: kinds, slotFilter: slotFilter, snapshot: snapshot))
        } ?? .null
        let incomplete = !outcome.kindsPending.isEmpty
        if outcome.results.isEmpty && (incomplete || outcome.isTruncated || outcome.resumePoint != nil) {
            return searchIncompleteReply(outcome, nextCursor: nextCursor, cumulative: cumulative)
        }
        var reply: [String: ScriptValue] = [
            "total": outcome.isTruncated ? .null : .int(Int64(cumulative + outcome.lowerBound)),
            "lowerBound": .int(Int64(cumulative + outcome.lowerBound)),
            "isTruncated": .bool(outcome.isTruncated),
            "results": .array(outcome.results.map(searchRow)),
            "kindsCovered": .array(outcome.kindsCovered.map(\.rawValue).sorted().map(ScriptValue.string)),
            "nextCursor": nextCursor,
        ]
        if incomplete {
            let wrapped = searchIncompleteReply(outcome, nextCursor: nextCursor, cumulative: cumulative)
            if case .object(var fields)? = wrapped["refusal"] {
                fields.removeValue(forKey: "kindsCovered")
                fields.removeValue(forKey: "nextCursor")
                fields.removeValue(forKey: "lowerBound")
                reply["incomplete"] = .object(fields)
            }
        }
        return .object(reply)
    }
}
