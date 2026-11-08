import Foundation

extension WorkspaceScriptingAPI {
    /// Catalog indices and links are those of the WHOLE image, before kind/limit filtering.
    /// The caller owns preparation preflight and computes links once, with its checkpoints.
    nonisolated static func typeAtlasUnpagedReply(
        _ entries: [TypeAtlasEntry], links: TypeAtlasSwiftObjCLinks,
        slot: ImageSlot, snapshot: WorkspaceSnapshot, kind: TypeAtlasKind?, limit: Int,
        mode: TypeAtlasUnpagedMode = .publicPrefix, checkpoint: () throws -> Void = {}
    ) throws -> ScriptValue {
        var work = TypeAtlasDefaultReplyWork()
        var total = 0
        var selected = 0
        var ordinaryBytes = 0
        var useSummary = false
        let ceiling = max(0, limit)
        // Pass 1 never retains projected rows or charges ordinary output source credits.
        // After overflow, finish only the whole-filter count, not the ordinary projection.
        for (index, entry) in entries.enumerated() {
            try checkpoint()
            do { try work.visit() }
            catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                throw work.reportingRefusal(error)
            }
            guard kind == nil || entry.kind == kind else { continue }
            total += 1
            guard selected < ceiling else { continue }
            selected += 1
            guard mode == .publicPrefix, !useSummary else { continue }
            do { try work.row(entry, link: links.byIndex[index], checkpoint: checkpoint) }
            catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                throw work.reportingRefusal(error)
            }
            let row = try applyingTypeAtlasLink(typeAtlasEntryValue(entry),
                link: links.byIndex[index], checkpoint: checkpoint)
            let bytes = try listPageWireBytes(row)
            // Compare before adding the separator, so arithmetic cannot overflow.
            if bytes >= defaultTypeAtlasEscapedRowCap - ordinaryBytes {
                useSummary = true
            } else {
                ordinaryBytes += bytes + 1
            }
        }
        var output = AttachedTypeReadBudget()
        if links.counts != nil {
            try output.take(2); try output.framing(256)
        }
        var rows: [ScriptValue] = []
        var bytes = 0
        var nextOffset: Int?
        var emittedSummary = false
        // Pass 2 admits only the final emitted model and the additions of this row's link.
        for (index, original) in entries.enumerated() {
            try checkpoint()
            do { try work.visit() }
            catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                throw work.reportingRefusal(error)
            }
            guard kind == nil || original.kind == kind else { continue }
            guard rows.count < selected else { break }
            let link = links.byIndex[index]
            do {
                try work.row(original, link: link, checkpoint: checkpoint)
            } catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                // The shared work ledger ran out: continue from this original index, as for output.
                if mode == .internalComplete { throw work.reportingRefusal(error) }
                if rows.isEmpty {
                    throw work.reportingRefusal(typeAtlasDefaultRowRefusal(
                        original, index: index, slot: slot, kind: kind))
                }
                nextOffset = index
                break
            }
            let transformed = useSummary
                ? try TypeAtlasDefaultReplyPolicy.summarized(original, checkpoint: checkpoint)
                : (entry: original, slots: 0)
            var admittedEntry = transformed.entry
            if link?.membersListedOn == true { admittedEntry.members = [] }
            var candidate = output
            var failedAdmission = false
            do {
                try candidate.entries([admittedEntry], checkpoint: checkpoint)
                if let link {
                    var selectedLinks = TypeAtlasSwiftObjCLinks()
                    selectedLinks.byIndex[index] = link
                    try candidate.links(selectedLinks, checkpoint: checkpoint)
                }
                if transformed.slots > 0 {
                    try candidate.take(1); try candidate.framing(64)
                }
            } catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                if mode == .internalComplete {
                    throw TypeAtlasDefaultReplyPolicy.labelBudgetPrefix(candidate.reportingRefusal(error))
                }
                failedAdmission = true
            }
            if failedAdmission {
                if rows.isEmpty {
                    throw TypeAtlasDefaultReplyPolicy.labelBudgetPrefix(candidate.reportingRefusal(
                        typeAtlasDefaultRowRefusal(original, index: index, slot: slot, kind: kind)))
                }
                nextOffset = index
                break
            }
            var row = try applyingTypeAtlasLink(typeAtlasEntryValue(admittedEntry),
                link: link, checkpoint: checkpoint)
            if transformed.slots > 0, case .object(var fields) = row {
                fields["unnamedVtableSlots"] = .object([
                    "count": .int(Int64(transformed.slots)), "first": .int(0),
                    "last": .int(Int64(transformed.slots - 1)),
                ])
                row = .object(fields)
            }
            if mode == .publicPrefix {
                let charge = try listPageWireBytes(row)
                if charge >= defaultTypeAtlasEscapedRowCap - bytes {
                    if rows.isEmpty {
                        throw typeAtlasDefaultRowRefusal(original, index: index, slot: slot, kind: kind,
                            budget: .init(unit: .bytes, limit: Int64(defaultTypeAtlasEscapedRowCap)),
                            used: Int64(charge))
                    }
                    nextOffset = index
                    break
                }
                bytes += charge + 1
            }
            output = candidate
            rows.append(row)
            emittedSummary = emittedSummary || transformed.slots > 0
        }
        var result = imageProvenanceFields(slot: slot, snapshot: snapshot)
        result["total"] = .count(UInt64(total))
        result["types"] = .array(rows)
        if let counts = links.counts { result["swiftObjCLinks"] = typeAtlasLinkCountsValue(counts) }
        if emittedSummary { result["vtableSummaryVersion"] = .int(1) }
        if let nextOffset {
            result["isTruncated"] = .bool(true)
            result["nextCursor"] = .string(typeAtlasDefaultContinuation(
                slot: slot, offset: nextOffset, generation: snapshot.analysisGenerationID, kind: kind))
        }
        try checkpoint()
        return .object(result)
    }

    private nonisolated static func typeAtlasDefaultRowRefusal(
        _ entry: TypeAtlasEntry, index: Int, slot: ImageSlot, kind: TypeAtlasKind?,
        budget: MCPRefusalBudget? = nil, used: Int64? = nil
    ) -> ScriptingError {
        let identity = TypeAtlasDefaultReplyPolicy.boundedIdentity(entry.name)
        var route: [String: ScriptValue] = [
            "page": .bool(true), "fields": .string("full"), "limit": .int(1),
            "image": .int(Int64(slot.rawValue)),
        ]
        if let kind { route["kind"] = .string(kind.rawValue) }
        let canName = !entry.name.isEmpty && entry.name.utf8.prefix(1_025).count <= 1_024
        if canName { route["name"] = .string(entry.name) }
        // All values here are finite JSON primitives; keep an explicit fallback route.
        let encoded = (try? ScriptValue.object(route).jsonData())
            .map { String(decoding: $0, as: UTF8.self) }
            ?? "{page:true, fields:\"full\", limit:1}"
        let selection = canName
            ? " Compare the returned id if names repeat."
            : " Stream full pages and compare the original row id; the name exceeds the exact-name filter or is empty."
        return .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "Type Atlas row at original index \(index), name \(identity), exceeds the default reply allowance after summary. Use list-image-types \(encoded)." + selection + " " + typeAtlasPageHint,
            budget: budget, used: used, narrowing: ["page"]))
    }
}
