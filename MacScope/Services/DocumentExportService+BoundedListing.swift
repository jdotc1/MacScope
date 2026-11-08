import Foundation

/// Pure rendering of already resolved listing rows. No source admission or save authority.
/// Preparation of `rows`/`resolved` belongs to the existing listing builder and host budget.
extension DocumentExportService {
    enum ListingFormat: Equatable, Sendable { case plainText, html }

    struct ListingLimits: Equatable, Sendable {
        let maximumRows: Int
        let maximumUTF8Bytes: Int
        let maximumInputFieldUTF8Bytes: Int

        init(maximumRows: Int = 20_000, maximumUTF8Bytes: Int = 2 * 1_024 * 1_024,
             maximumInputFieldUTF8Bytes: Int = 64 * 1_024) throws {
            guard (1...100_000).contains(maximumRows),
                  (1...8 * 1_024 * 1_024).contains(maximumUTF8Bytes),
                  (1...64 * 1_024).contains(maximumInputFieldUTF8Bytes) else {
                throw ListingRenderError.invalidLimits
            }
            self.maximumRows = maximumRows
            self.maximumUTF8Bytes = maximumUTF8Bytes
            self.maximumInputFieldUTF8Bytes = maximumInputFieldUTF8Bytes
        }
    }

    enum ListingRenderError: Error { case invalidLimits, envelopeExceedsOutputLimit }
    enum ListingStopReason: String, Equatable, Sendable {
        case rowLimit, inputFieldLimit, outputByteLimit, unsupportedHTMLControl
    }

    struct BoundedListing: Equatable, Sendable {
        let text: String
        let format: ListingFormat
        let consumedRows: Int
        let inputRowCount: Int
        let stopReason: ListingStopReason?
        var isComplete: Bool { stopReason == nil }
    }

    /// Exact canonical row formatting shared with legacy `renderListing`.
    /// A partial result ends BEFORE an entire row (including all prefix-comment lines).
    /// The host must surface stopReason/consumedRows; text alone is not a completion receipt.
    /// Cancellation throws rather than returning a partial result for an abandoned request.
    func renderBoundedListing(
        rows: [ListingRow],
        resolved: [UInt64: DisassemblyListingBuilder.ResolvedInstruction],
        format: ListingFormat,
        limits: ListingLimits,
        checkCancellation: () throws -> Void = { try Task.checkCancellation() }
    ) throws -> BoundedListing {
        try checkCancellation()
        let prefix = format == .html
            ? "<!doctype html><html><head><meta charset=\"utf-8\"><title>MacScope listing</title>"
                + "<style>body{font:10pt Arial,sans-serif}pre,code{font:inherit;white-space:pre}</style>"
                + "</head><body><pre><code>"
            : ""
        let suffix = format == .html ? "</code></pre></body></html>" : ""
        guard prefix.utf8.count + suffix.utf8.count <= limits.maximumUTF8Bytes else {
            throw ListingRenderError.envelopeExceedsOutputLimit
        }
        var body = prefix
        var used = prefix.utf8.count
        var consumed = 0
        var hasLine = false
        var reason: ListingStopReason?
        for row in rows {
            try checkCancellation()
            guard consumed < limits.maximumRows else { reason = .rowLimit; break }
            // Prefix() bounds the size scan before any split/padding/escaping allocation.
            let fields = boundedListingFields(for: row, resolved: resolved)
            guard fields.allSatisfy({ $0.utf8.prefix(limits.maximumInputFieldUTF8Bytes + 1).count
                <= limits.maximumInputFieldUTF8Bytes }) else { reason = .inputFieldLimit; break }
            let lines = canonicalListingLines(for: row, resolved: resolved)
            let canonical = (hasLine ? "\n" : "") + lines.joined(separator: "\n")
            let remaining = limits.maximumUTF8Bytes - used - suffix.utf8.count
            var piece: String? = nil
            switch format {
            case .plainText:
                guard canonical.utf8.count <= remaining else { reason = .outputByteLimit; break }
                piece = canonical
            case .html:
                // Count exact escaped bytes first. Never create an oversized escaped string.
                guard let count = boundedListingHTMLEscapedSize(canonical, maximum: remaining) else {
                    reason = canonical.unicodeScalars.contains(where: { $0.value < 32 && ![9, 10, 13].contains($0.value) })
                        ? .unsupportedHTMLControl : .outputByteLimit
                    break
                }
                piece = boundedListingEscapeHTML(canonical, capacity: count)
            }
            guard let piece else { break }
            body += piece
            used += piece.utf8.count
            consumed += 1
            hasLine = true
        }
        try checkCancellation()
        body += suffix
        return BoundedListing(text: body, format: format, consumedRows: consumed,
                              inputRowCount: rows.count, stopReason: reason)
    }

    private func boundedListingFields(
        for row: ListingRow,
        resolved: [UInt64: DisassemblyListingBuilder.ResolvedInstruction]
    ) -> [String] {
        switch row {
        case let .sectionHeader(header): return [header.name]
        case let .label(label): return [label.name]
        case let .prefixComment(comment): return [comment.text]
        case let .instruction(instruction):
            if let selected = resolved[instruction.address] {
                return [selected.row.bytes, selected.row.mnemonic, selected.row.operands,
                        selected.inlineComment ?? "", selected.undefinedDirective?.mnemonic ?? "",
                        selected.undefinedDirective?.operands ?? "", selected.shapeDirective?.mnemonic ?? "",
                        selected.shapeDirective?.operands ?? ""]
            }
            return [instruction.bytes, instruction.mnemonic, instruction.operands, instruction.comment ?? ""]
        }
    }

    private func boundedListingHTMLEscapedSize(_ text: String, maximum: Int) -> Int? {
        var size = 0
        for scalar in text.unicodeScalars {
            let addition: Int
            switch scalar.value {
            case 38: addition = 5 // &amp;
            case 60, 62: addition = 4 // &lt; / &gt;
            case 34: addition = 6 // &quot;
            case 39, 13: addition = 5 // &#39; / &#13;
            case 0..<32 where scalar.value != 9 && scalar.value != 10: return nil
            default: addition = String(scalar).utf8.count
            }
            guard addition <= maximum - size else { return nil }
            size += addition
        }
        return size
    }

    private func boundedListingEscapeHTML(_ text: String, capacity: Int) -> String {
        var result = ""
        result.reserveCapacity(capacity)
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 38: result += "&amp;"
            case 60: result += "&lt;"
            case 62: result += "&gt;"
            case 34: result += "&quot;"
            case 39: result += "&#39;"
            case 13: result += "&#13;"
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
}
