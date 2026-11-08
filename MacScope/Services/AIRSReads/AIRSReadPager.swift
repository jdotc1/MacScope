import Foundation

/// A server-side-validated continuation. Possession is not authorization: every field is compared
/// with retained state before any row is read. The token is base64 of compact versioned JSON.
struct AIRSReadCursor: Equatable, Sendable {
    enum DecodeFailure: Error, Equatable { case malformed, invalidOffset }

    static let version = 1
    var command: String
    var entryID: UUID
    var reportID: UUID
    var imageSlot: Int
    var imageOwnerID: UUID
    var installationID: UUID
    var generation: UUID
    var focusEpoch: UUID
    var reportStateEpoch: UUID
    var modelID: String
    var filterToken: String
    var offset: Int

    /// nil when the encoded token would exceed `AIRSMCPReads.maximumCursorBytes`; no cursor is minted then.
    func encoded() -> String? {
        let object: [String: Any] = [
            "v": Self.version, "c": command, "e": entryID.uuidString, "r": reportID.uuidString,
            "s": imageSlot, "o": imageOwnerID.uuidString, "i": installationID.uuidString,
            "g": generation.uuidString, "f": focusEpoch.uuidString, "t": reportStateEpoch.uuidString,
            "m": modelID, "k": filterToken, "n": offset,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return nil }
        let token = data.base64EncodedString()
        return token.utf8.count <= AIRSMCPReads.maximumCursorBytes ? token : nil
    }

    static func decode(_ token: String) -> Result<AIRSReadCursor, DecodeFailure> {
        guard !token.isEmpty, let data = Data(base64Encoded: token),
              let any = try? JSONSerialization.jsonObject(with: data),
              let object = any as? [String: Any],
              object["v"] as? Int == version else { return .failure(.malformed) }
        func text(_ key: String) -> String? { object[key] as? String }
        func uuid(_ key: String) -> UUID? { text(key).flatMap(UUID.init(uuidString:)) }
        guard let command = text("c"), let entry = uuid("e"), let report = uuid("r"),
              let owner = uuid("o"), let installation = uuid("i"), let generation = uuid("g"),
              let focus = uuid("f"), let state = uuid("t"), let model = text("m"), let filter = text("k"),
              let slot = object["s"] as? Int, slot >= 0,
              let rawOffset = object["n"] as? NSNumber,
              CFGetTypeID(rawOffset) != CFBooleanGetTypeID() else { return .failure(.malformed) }
        let double = rawOffset.doubleValue
        guard double.rounded() == double, double >= 0, double < 9e15 else { return .failure(.invalidOffset) }
        return .success(AIRSReadCursor(
            command: command, entryID: entry, reportID: report, imageSlot: slot, imageOwnerID: owner,
            installationID: installation, generation: generation, focusEpoch: focus, reportStateEpoch: state,
            modelID: model, filterToken: filter, offset: Int(double)))
    }
}

/// Pure paging over one immutable retained row array. Never recomputes, never trims inside a row.
enum AIRSReadPager {
    static let pageByteCap = 196_608

    enum Outcome: Equatable {
        case page(ScriptValue)
        case refusal(MCPToolRefusal)
        /// A decoded, correctly bound offset beyond the retained total.
        case offsetOutOfBounds(total: Int)
    }

    static func byteLimitRefusal(used: Int) -> MCPToolRefusal {
        MCPToolRefusal(code: .budgetExceeded, detail: "pageByteLimit", retryable: false,
                       budget: MCPRefusalBudget(unit: .bytes, limit: Int64(pageByteCap)), used: Int64(used))
    }

    /// `makeCursor` receives the next offset and returns the encoded token, or nil when it cannot be minted.
    static func page(report: AIRSReadReport, offset: Int, limit: Int,
                     makeCursor: (Int) -> String?) -> Outcome {
        let total = report.rows.count
        guard offset >= 0, offset <= total else { return .offsetOutOfBounds(total: total) }
        let maxCount = min(limit, total - offset)
        let sizes: [Int]
        do { sizes = try report.rows[offset..<(offset + maxCount)].map { try $0.jsonData().count } }
        catch { return .refusal(byteLimitRefusal(used: 0)) }

        func envelope(count: Int, rows: [ScriptValue]) -> (ScriptValue, Int)? {
            let next = offset + count
            let cursor: String? = next < total ? makeCursor(next) : nil
            if next < total && cursor == nil { return nil }
            var fields = report.header
            fields["rows"] = .array(rows)
            fields["total"] = .int(Int64(total))
            fields["totalLowerBound"] = .int(Int64(total))
            fields["totalIsExact"] = .bool(true)
            fields["isTruncated"] = .bool(cursor != nil)
            fields["nextCursor"] = cursor.map(ScriptValue.string) ?? .null
            fields["sourceComplete"] = report.sourceComplete.map(ScriptValue.bool) ?? .null
            fields["denominators"] = report.denominators.value
            fields["returnedBefore"] = .int(Int64(offset))
            fields["returnedThisPage"] = .int(Int64(count))
            fields["remainingAfter"] = .int(Int64(total - next))
            let value = ScriptValue.object(fields)
            guard let size = try? value.jsonData().count else { return nil }
            return (value, size)
        }

        var count = maxCount
        var lastUsed = 0
        while true {
            guard let (empty, emptySize) = envelope(count: count, rows: []) else {
                return .refusal(byteLimitRefusal(used: lastUsed))
            }
            _ = empty
            let predicted = emptySize + sizes.prefix(count).reduce(0, +) + max(count - 1, 0)
            lastUsed = predicted
            if predicted <= pageByteCap {
                let rows = Array(report.rows[offset..<(offset + count)])
                if let (value, exact) = envelope(count: count, rows: rows), exact <= pageByteCap {
                    return .page(value)
                }
            }
            if count <= 1 && (maxCount > 0 || predicted > pageByteCap) {
                if count == 0 { return .refusal(byteLimitRefusal(used: lastUsed)) }
                return .refusal(byteLimitRefusal(used: lastUsed))
            }
            if count == 0 { return .refusal(byteLimitRefusal(used: lastUsed)) }
            count -= 1
        }
    }
}
