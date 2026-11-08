import Foundation

/// Request-local logical admission. This is not a heap-byte or elapsed-time quota.
/// No counter is reset between selection, scans, enrichment and encoding.
final class FunctionFactsAdmission {
    static let maximumInnerBytes = 3_000
    static let maximumRows = 32
    static let maximumSectionRows = 8
    static let maximumTextBytes = 1_048_576
    static let maximumNameBytes = 256
    private(set) var work = 0
    private var rows = 0
    private var textBytes = 0
    private var outputBytes = 0
    /// False while the shed-able row sections are built: their size is enforced by the real
    /// serialized check (with row shedding), not by this pre-count.
    var countsOutput = true
    let checkpoint: () throws -> Void

    init(checkpoint: @escaping () throws -> Void) { self.checkpoint = checkpoint }

    func refusal(_ unit: MCPRefusalBudget.Unit, limit: Int, used: Int) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "function-facts exceeds its shared admission budget",
            budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used),
            narrowing: ["function", "address", "imageSlot"]))
    }

    func visit(_ amount: Int = 1) throws {
        try checkpoint()
        let limit = WorkspaceScriptingAPI.maximumSnapshotSelectionWork
        guard amount >= 0, amount <= limit - work else {
            throw refusal(.workSteps, limit: limit, used: limit + 1)
        }
        work += amount
    }

    func row() throws {
        try visit()
        guard rows < Self.maximumRows else {
            throw refusal(.rows, limit: Self.maximumRows, used: Self.maximumRows + 1)
        }
        rows += 1
    }

    /// Visit bytes without constructing a UTF-8 array or hashing an unadmitted string.
    @discardableResult
    func observeText<Text: StringProtocol>(_ value: Text, maximum: Int = maximumTextBytes) throws -> Int {
        var count = 0
        for _ in value.utf8 {
            guard count < maximum else { throw refusal(.bytes, limit: maximum, used: maximum + 1) }
            guard textBytes < Self.maximumTextBytes else {
                throw refusal(.bytes, limit: Self.maximumTextBytes, used: Self.maximumTextBytes + 1)
            }
            count += 1
            textBytes += 1
            if count.isMultiple(of: WorkspaceScriptingAPI.checkpointInterval) { try checkpoint() }
        }
        try checkpoint()
        return count
    }

    func output(_ count: Int) throws {
        try checkpoint()
        guard countsOutput else { return }
        guard count >= 0, count <= Self.maximumInnerBytes - outputBytes else {
            throw refusal(.bytes, limit: Self.maximumInnerBytes,
                used: max(Self.maximumInnerBytes + 1, outputBytes + max(count, 0)))
        }
        outputBytes += count
    }

    func resetOutput() { outputBytes = 0 }

    /// GraphNameIndex is the sole admitted image-sized materialization exception.
    /// Preflight its immutable inputs before the existing memo can allocate. Its own
    /// 262,144-row / 8,192-byte-name / 1-or-16-MiB checks remain in force.
    func graphInputs(_ analysis: ImageAnalysis) throws {
        for function in analysis.functions {
            try visit()
            try observeText(function.name, maximum: 4_096)
        }
        for symbol in analysis.symbols {
            try visit()
            try observeText(symbol.name, maximum: 4_096)
        }
    }
}

/// Counts conservative JSON bytes BEFORE inserting each value into the final tree.
/// The existing sorted-key serializer still owns all emitted bytes and escaping.
private struct FunctionFactsTree {
    let admission: FunctionFactsAdmission

    func text(_ value: String) throws -> ScriptValue {
        try admission.output(2)
        for byte in value.utf8 {
            // Six is conservative for controls and non-ASCII; slash escaping is
            // implementation-dependent, so reserve two for slash as well.
            let cost = byte < 0x20 || byte >= 0x80 ? 6 : ([0x22, 0x5c, 0x2f].contains(byte) ? 2 : 1)
            try admission.output(cost)
        }
        return .string(value)
    }

    func scalar(_ value: ScriptValue) throws -> ScriptValue {
        switch value {
        case .string(let text): return try self.text(text)
        case .null: try admission.output(4)
        case .bool(let flag): try admission.output(flag ? 4 : 5)
        case .int(let number): try admission.output(String(number).utf8.count) // real digits plus sign
        default: throw ScriptingError.invalidArgument("unsupported function-facts scalar")
        }
        return value
    }

    func object(_ fields: [(String, ScriptValue)]) throws -> ScriptValue {
        try admission.output(2 + max(0, fields.count - 1))
        var result: [String: ScriptValue] = [:]
        for (key, value) in fields {
            _ = try text(key)
            try admission.output(1)
            result[key] = value
        }
        return .object(result)
    }

    func array(_ rows: [ScriptValue]) throws -> ScriptValue {
        try admission.output(2 + max(0, rows.count - 1))
        return .array(rows)
    }
}

extension WorkspaceScriptingAPI {
    /// Stored facts only. Resolve exactly once, scan recovered xrefs once, and
    /// reuse the callees row namer and F2 target describer on that same capture.
    nonisolated static func functionFacts(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        try withoutActuallyEscaping(checkpoint) { checkpoint in
            try buildFunctionFacts(arguments, snapshot: snapshot, checkpoint: checkpoint)
        }
    }

    nonisolated private static func buildFunctionFacts(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        checkpoint: @escaping () throws -> Void
    ) throws -> ScriptValue {
        let admission = FunctionFactsAdmission(checkpoint: checkpoint)
        let tree = FunctionFactsTree(admission: admission)
        try admission.visit()
        if let name = arguments["function"]?.stringValue {
            try admission.observeText(name, maximum: FunctionFactsAdmission.maximumNameBytes)
        }
        // The existing selectors trim/normalize string arguments. Admit those
        // bytes before parsing can allocate, including on direct API routes.
        for key in ["address", "imageSlot"] {
            if let text = arguments[key]?.stringValue {
                try admission.observeText(text, maximum: FunctionFactsAdmission.maximumNameBytes)
            }
        }
        for binary in snapshot.binaries {
            try admission.row() // imageProjection may copy this bounded array
            try admission.observeText(binary.name, maximum: 4_096)
        }
        let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
        let view = filter.map { imageProjection(of: snapshot, in: $0) } ?? snapshot
        let slot = filter ?? view.primarySlot
        for section in view.analysis(in: slot)?.sections ?? [] {
            try admission.visit()
            try admission.observeText(section.name, maximum: FunctionFactsAdmission.maximumNameBytes)
        }
        var function = try boundedSnapshotFunction(arguments, snapshot: view,
            checkpoint: checkpoint,
            candidateAdmission: { candidate in
                try admission.visit()
                try admission.observeText(candidate.name, maximum: 4_096)
                try admission.observeText(view.displayName(at: candidate.startAddress, in: slot,
                    default: candidate.name), maximum: 4_096)
            }, matchAdmission: { try admission.row() })
        // A hex `function` that matched no name was resolved as an address; report it as one.
        let requestedAddress: UInt64? = {
            guard let name = arguments["function"]?.stringValue else { return arguments["address"]?.addressValue }
            guard arguments["address"] == nil, let hex = strictHexAddress(name),
                  function.name != name,
                  view.displayName(at: function.startAddress, in: slot, default: function.name) != name
            else { return nil }
            return hex
        }()
        if let address = requestedAddress {
            for candidate in view.functions {
                try admission.visit()
                let exact = candidate.startAddress == address
                guard exact || (candidate.endAddress > candidate.startAddress
                    && candidate.startAddress <= address && address < candidate.endAddress) else { continue }
                let currentExact = function.startAddress == address
                if (exact && !currentExact) || (exact == currentExact && (
                    candidate.startAddress < function.startAddress
                    || (candidate.startAddress == function.startAddress && (
                        candidate.endAddress < function.endAddress
                        || (candidate.endAddress == function.endAddress
                            && candidate.name.utf8.lexicographicallyPrecedes(function.name.utf8)))))) {
                    function = candidate
                }
            }
        }
        let name = view.displayName(at: function.startAddress, in: slot, default: function.name)
        try admission.observeText(name, maximum: FunctionFactsAdmission.maximumNameBytes)
        let sizeKnown = function.endAddress > function.startAddress
        let finalAddressOnly = !sizeKnown && function.startAddress == UInt64.max
        let range = finalAddressOnly ? nil : view.functionRange(function)
        func contains(_ address: UInt64) -> Bool { range?.contains(address) ?? (address == UInt64.max) }

        func ordered(_ a: XRef, _ b: XRef) -> Bool {
            if a.from != b.from { return a.from < b.from }
            if a.to != b.to { return a.to < b.to }
            return a.kind < b.kind
        }
        // Keep the first eight rows in deterministic reply order without ever
        // materializing a full section. Replacement reuses an admitted slot.
        func retainPrefix<Element>(_ value: Element, in rows: inout [Element],
                                   before: (Element, Element) -> Bool) throws {
            let limit = FunctionFactsAdmission.maximumSectionRows
            if rows.count == limit {
                try admission.visit()
                guard before(value, rows[limit - 1]) else { return }
            } else { try admission.row() }
            var position = 0
            while position < rows.count {
                try admission.visit()
                if before(value, rows[position]) { break }
                position += 1
            }
            // Account for the at-most-eight array moves before insertion.
            try admission.visit(rows.count)
            if rows.count == limit { rows.removeLast() }
            rows.insert(value, at: position)
        }

        var calls: [XRef] = [], references: [XRef] = []
        var callTotal = 0, referenceTotal = 0
        var seen = Set<XRefEndpointKey>()
        // The indexed path can allocate a cold endpoint index before its visitor.
        // Borrow the same raw recovered population instead; one charged scan feeds
        // both categories and does not build an endpoint index or effective-xref set.
        for ref in view.xrefs {
            try admission.visit()
            guard contains(ref.from) else { continue }
            try admission.observeText(ref.kind, maximum: FunctionFactsAdmission.maximumNameBytes)
            let key = XRefEndpointKey(from: ref.from, to: ref.to, kind: ref.kind)
            guard !seen.contains(key) else { continue }
            // Exact totals require remembering unique endpoint identities, not
            // full rows. Every insertion follows the shared work/text admission;
            // there can be at most 100,000 keys, even for omitted observations.
            seen.insert(key)
            if ref.kind == XRefKind.call {
                callTotal += 1
                try retainPrefix(ref, in: &calls, before: ordered)
            } else {
                referenceTotal += 1
                try retainPrefix(ref, in: &references, before: ordered)
            }
        }
        let selected = calls + references // at most sixteen admitted rows
        let named = try namedGraphRows(selected, includeKind: true, snapshot: view, slot: slot,
            checkpoint: checkpoint, admission: admission)
        let targets = Set(references.map(\.to)) // at most eight already-admitted targets
        let describer = try DataTargetDescriber(snapshot: view, slot: slot, targets: targets,
            checkpoint: checkpoint, admission: admission)
        var callRows: [ScriptValue] = [], referenceRows: [ScriptValue] = []
        admission.countsOutput = false
        for (index, ref) in selected.enumerated() {
            try admission.visit()
            guard case .object(let source) = named[index] else {
                throw ScriptingError.invalidArgument("missing function-facts graph row")
            }
            var fields: [(String, ScriptValue)] = [
                ("from", try tree.scalar(.hex(ref.from))), ("to", try tree.scalar(.hex(ref.to))),
                ("imageSlot", try tree.scalar(.int(Int64(slot.rawValue)))),
                ("toName", try tree.scalar(source["toName"] ?? .null)),
            ]
            for key in ["selector", "toDemangled"] {
                if let value = source[key] { fields.append((key, try tree.scalar(value))) }
            }
            if index < calls.count {
                callRows.append(try tree.object(fields))
            } else {
                fields.append(("kind", try tree.scalar(.string(ref.kind))))
                let description = describer.describe(ref, named: source["toName"]?.stringValue != nil)
                fields.append(("targetKind", try tree.scalar(description["targetKind"] ?? .string("data"))))
                if let cString = description["cString"] { fields.append(("cString", try tree.scalar(cString))) }
                if let value = description["value"] {
                    if let text = value.stringValue {
                        let length = try admission.observeText(text)
                        var preview = "", bytes = 0
                        for scalar in text.unicodeScalars {
                            let width = String(scalar).utf8.count
                            guard width <= maximumInstructionPreviewBytes - bytes else { break }
                            try admission.visit()
                            preview.unicodeScalars.append(scalar)
                            bytes += width
                        }
                        fields.append(("value", try tree.text(preview)))
                        fields.append(("valueTruncated", try tree.scalar(.bool(length > bytes))))
                        fields.append(("valueByteLength", try tree.scalar(.int(Int64(length)))))
                    } else {
                        fields.append(("value", try tree.scalar(.null)))
                        fields.append(("valueStatus", try tree.text("unavailable")))
                        fields.append(("valueReason", try tree.text("noStoredTargetValue")))
                    }
                }
                referenceRows.append(try tree.object(fields))
            }
        }

        var blocks: [BasicBlockSummary] = []
        var blockTotal = 0
        var instructionCount: Int64 = 0, straddles = 0
        for block in view.basicBlocks {
            try admission.visit()
            guard contains(block.startAddress) else { continue }
            guard block.instructionCount >= 0,
                  let count = Int64(exactly: block.instructionCount), count <= Int64.max - instructionCount else {
                throw ScriptingError.invalidArgument("invalid stored block instructionCount")
            }
            blockTotal += 1
            instructionCount += count
            if let range, block.endAddress > range.upperBound { straddles += 1 }
            // Totals and whole-block sums include every in-range block, including
            // those omitted from the retained prefix. functionID is not selection.
            try retainPrefix(block, in: &blocks) {
                if $0.startAddress != $1.startAddress { return $0.startAddress < $1.startAddress }
                if $0.endAddress != $1.endAddress { return $0.endAddress < $1.endAddress }
                return $0.instructionCount < $1.instructionCount
            }
        }
        var blockRows: [ScriptValue] = []
        admission.countsOutput = false
        for block in blocks {
            blockRows.append(try tree.object([
                ("start", try tree.scalar(.hex(block.startAddress))),
                ("end", try tree.scalar(.hex(block.endAddress))),
                ("instructionCount", try tree.scalar(.int(Int64(block.instructionCount)))),
            ]))
        }
        admission.countsOutput = true
        var branch = 0, switches = 0
        for edge in view.controlFlowEdges {
            try admission.visit()
            guard contains(edge.from) else { continue }
            try admission.observeText(edge.kind, maximum: FunctionFactsAdmission.maximumNameBytes)
            if edge.kind == "branch" { branch += 1 }
            if edge.kind == "switch" { switches += 1 }
        }
        func category(_ source: String, _ rows: [ScriptValue], total: Int) throws -> ScriptValue {
            try tree.object([
                ("address", try tree.scalar(.hex(function.startAddress))),
                ("status", try tree.text("partial")),
                ("source", try tree.text(source)),
                ("enumerationComplete", try tree.scalar(.bool(true))),
                ("total", try tree.scalar(.int(Int64(total)))),
                ("omitted", try tree.scalar(.int(Int64(total - rows.count)))),
                ("truncated", try tree.scalar(.bool(total > rows.count))),
                ("reason", try tree.text(view.xrefs.isEmpty ? "noStoredXRefs" : "storedRowsOnly")),
                ("rows", try tree.array(rows)),
            ])
        }
        // Pre-count only the fixed sections (rows are prebuilt); the real serialized size decides.
        func assemble(_ calls: [ScriptValue], _ references: [ScriptValue],
                      _ shownBlocks: [ScriptValue]) throws -> ScriptValue {
            admission.resetOutput()
            let callsValue = try category("storedDirectCallXRefs", calls, total: callTotal)
            let referencesValue = try category("storedNonCallXRefs", references, total: referenceTotal)
            let constants = try tree.object([
                ("address", try tree.scalar(.hex(function.startAddress))),
                ("status", try tree.text("partial")),
                ("reason", try tree.text("dataAndStringTargetsInReferences;numericImmediatesNotIncluded")),
            ])
            let branches = try tree.object([
                ("address", try tree.scalar(.hex(function.startAddress))),
                ("status", try tree.text(view.controlFlowEdges.isEmpty ? "unavailable" : "partial")),
                ("reason", try tree.text("storedEdgesOnly;conditionalityNotStored")),
                ("branchCount", try tree.scalar(.int(Int64(branch + switches)))),
                ("branch", try tree.scalar(.int(Int64(branch)))), ("switch", try tree.scalar(.int(Int64(switches)))),
            ])
            let size = try tree.object([
                ("address", try tree.scalar(.hex(function.startAddress))),
                ("sizeKnown", try tree.scalar(.bool(sizeKnown))),
                ("bytes", try tree.scalar(sizeKnown ? .hex(function.endAddress - function.startAddress) : .null)),
                ("blockStatus", try tree.text(view.basicBlocks.isEmpty ? "unavailable" : "partial")),
                ("reason", try tree.text("wholeStoredBlocksByStart")),
                ("blockCount", try tree.scalar(.int(Int64(blockTotal)))),
                ("total", try tree.scalar(.int(Int64(blockTotal)))),
                ("omitted", try tree.scalar(.int(Int64(blockTotal - shownBlocks.count)))),
                ("truncated", try tree.scalar(.bool(blockTotal > shownBlocks.count))),
                ("instructionCount", try tree.scalar(.int(instructionCount))),
                ("straddlingBlockCount", try tree.scalar(.int(Int64(straddles)))),
                ("blocks", try tree.array(shownBlocks)),
            ])
            let backend = try tree.object([
                ("address", try tree.scalar(.hex(function.startAddress))),
                ("status", try tree.text("unavailable")), ("reason", try tree.text("noStoredFunctionBackend")),
            ])
            let coverage = view.stringLiteralCoverage
            let coverageValue = try tree.object([
                ("address", try tree.scalar(.hex(function.startAddress))),
                ("status", try tree.text(coverage?.status ?? "unavailable")),
                ("reason", try tree.text(coverage == nil ? "noStoredStringCoverage" : "storedCoverage")),
                ("stopReason", try tree.scalar(coverage?.stopReason.map { .string($0.rawValue) } ?? .null)),
            ])
            var fields: [(String, ScriptValue)] = [
                ("name", try tree.text(name)), ("start", try tree.scalar(.hex(function.startAddress))),
                ("end", try tree.scalar(.hex(function.endAddress))),
                ("extent", try tree.text(sizeKnown ? "storedRange" : "exactStartOnly")),
                ("imageSlot", try tree.scalar(.int(Int64(slot.rawValue)))),
                ("imageOwner", try tree.scalar(snapshot.binary(in: slot).map { .string($0.id.uuidString) } ?? .null)),
                ("resolvedFunction", try tree.scalar(.hex(function.startAddress))),
                ("resolution", try tree.text(requestedAddress != nil
                    && requestedAddress != function.startAddress ? "containing" : "exact")),
                ("calls", callsValue), ("references", referencesValue), ("constants", constants),
                ("branches", branches), ("size", size), ("backend", backend),
                ("stringLiteralCoverage", coverageValue),
            ]
            if let address = requestedAddress {
                fields.append(("requestedAddress", try tree.scalar(.hex(address))))
            }
            return try tree.object(fields)
        }
        // Reserve one bounded encoder visit per admitted byte; then use the wire's
        // existing serializer. Rows are shed (blocks, then references, then calls),
        // one at a time from the end, until the real reply fits the inner cap.
        try admission.visit(FunctionFactsAdmission.maximumInnerBytes)
        var shownCalls = callRows, shownReferences = referenceRows, shownBlocks = blockRows
        var result = ScriptValue.null
        while true {
            result = try assemble(shownCalls, shownReferences, shownBlocks)
            let data = try result.jsonData()
            try checkpoint()
            if data.count <= FunctionFactsAdmission.maximumInnerBytes { break }
            if !shownBlocks.isEmpty { shownBlocks.removeLast() }
            else if !shownReferences.isEmpty { shownReferences.removeLast() }
            else if !shownCalls.isEmpty { shownCalls.removeLast() }
            else {
                throw admission.refusal(.bytes, limit: FunctionFactsAdmission.maximumInnerBytes,
                    used: data.count)
            }
        }
        return result
    }
}
