import Foundation

extension WorkspaceScriptingAPI {
    /// E2: refuses, before any output exists, when the authored comments of one function exceed the
    /// per-decompile caps. Counts the comments and their UTF-8 bytes; both limits are named in
    /// `+DecompileBudget.swift`.
    nonisolated static func enforceUserCommentBudget(_ comments: [UInt64: String]) throws {
        if comments.count > maximumUserCommentsPerDecompile {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "decompile refused: \(comments.count) authored comments in the function exceed the limit of \(maximumUserCommentsPerDecompile); no partial output is returned",
                budget: .init(unit: .rows, limit: Int64(maximumUserCommentsPerDecompile)),
                used: Int64(comments.count), narrowing: []))
        }
        var bytes = 0
        for text in comments.values {
            bytes += text.utf8.count
            if bytes > maximumUserCommentBytesPerDecompile {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "decompile refused: the function's authored comments exceed \(maximumUserCommentBytesPerDecompile) bytes; no partial output is returned",
                    budget: .init(unit: .bytes, limit: Int64(maximumUserCommentBytesPerDecompile)),
                    used: Int64(bytes), narrowing: []))
            }
        }
    }

    /// True when `function` has at least one authored comment. Stops at the first.
    nonisolated static func functionHasUserComments(
        _ function: FunctionSummary, in slot: ImageSlot, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws -> Bool {
        let trace = NativeDecompilerPhaseRecord.current()
        var visited = 0
        defer { trace?.add(.overridesVisited, UInt64(visited)) }
        for (key, override) in snapshot.addressOverrides {
            if visited > 0, visited.isMultiple(of: 4_096) { try checkpoint() }
            visited += 1
            if key.slot == slot, let comment = override.customComment,
               !comment.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
               WorkspaceSnapshot.function(function, contains: key.address) { return true }
        }
        return false
    }

    /// The reply fields E2 adds. Present only when the function has authored comments or a call
    /// target was disclosed, so a function with neither keeps a byte-identical reply.
    nonisolated static func decompileAnnotationFields(
        comments: [UInt64: String], document: PseudocodeDocument,
        callTargetNames: [CallTargetNameDisclosure]
    ) -> [String: ScriptValue] {
        var fields: [String: ScriptValue] = [:]
        if !comments.isEmpty {
            fields["commentsTotal"] = .int(Int64(document.placedCommentCount + document.unplacedComments.count))
            fields["commentsPlaced"] = .int(Int64(document.placedCommentCount))
            fields["unplacedComments"] = .array(document.unplacedComments.map { entry in
                .object(["address": .hex(entry.address), "text": .string(entry.text),
                         "reason": .string(entry.reason.rawValue)])
            })
        }
        if !callTargetNames.isEmpty {
            fields["callTargetNames"] = .array(callTargetNames.map { entry in
                .object(["address": .hex(entry.address), "stored": .string(entry.stored),
                         "rendered": .string(entry.rendered),
                         "reasons": .array(entry.reasons.map { .string($0) })])
            })
        }
        return fields
    }
}
