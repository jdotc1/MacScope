import Foundation

/// An uncommitted verification failure, not ScriptingCommittedBatchFailure.
/// `rolledBack` describes the authored collections and original undo manager,
/// not the append-only journal or an analysis-generation rewind.
struct ScriptingWriteReadbackFailure: LocalizedError {
    var reply: ScriptValue
    var rolledBack: Bool { reply["rolledBack"]?.boolValue == true }
    var errorDescription: String? {
        "writeReadbackFailed: " + (reply["stage"]?.stringValue ?? "rollback")
            + "; " + (reply["recovery"]?.stringValue ?? "Inspect the workspace before retrying.")
    }
}

/// Request-local test seam. Production is nil. It acts only AFTER the snapshot
/// reader returned, so tests can inject a mismatch or throw a read failure.
enum ScriptingWriteReadbackInjection {
    @TaskLocal static var observe: (@Sendable (String, ScriptValue) throws -> ScriptValue)?
    /// VI1C-2. Acts after the effective reader (`set-data` / `set-procedures` only): it receives the
    /// per-target effective rows and may replace them, so a test can force an effective mismatch
    /// without corrupting the engine. Production is nil.
    @TaskLocal static var observeEffective: (@Sendable (String, ScriptValue) throws -> ScriptValue)?
}

@MainActor
enum ScriptingWriteReadback {
    /// Commands whose write goes through `run`. Their native undo step reaches the caller's
    /// manager only after verification succeeds, so an attached caller must not open its own
    /// group around them: a group closed after a rolled-back write is not empty history.
    static let commands: Set<String> = [
        "set-type", "set-types", "define-type", "set-signature", "set-signatures",
        "set-local-label", "clear-local-label", "set-local-labels",
        "add-bookmark", "remove-bookmark", "add-bookmarks", "remove-bookmarks",
        // VI1-B: the remaining R4 batch-edit tools.
        "set-names", "set-comments", "set-operand-formats", "set-tags", "set-colors",
        "set-data", "set-procedures", "set-undefined", "make-arrays", "make-strings", "make-alignments",
        "rename-registers", "clear-register-names", "set-stack-locals",
        "add-xrefs", "suppress-xrefs", "rename-segments", "rebase-segments", "clear-segment-overrides",
    ]

    /// Names the single top-level undo step an attached caller wants, and records whether the
    /// verified bridge consumed it.
    final class AgentUndoName: @unchecked Sendable {
        let name: String
        var used = false
        init(name: String) { self.name = name }
    }
    @TaskLocal static var agentUndoName: AgentUndoName?

    static func encoded<T: Encodable>(_ value: T) throws -> ScriptValue {
        try ScriptValue.decode(JSONEncoder().encode(value))
    }

    static func text(_ value: String?) -> ScriptValue {
        WorkspaceStore.normalizedOverrideText(value).map(ScriptValue.string) ?? .null
    }

    static func signature(_ value: FunctionSignatureOverride?) throws -> ScriptValue {
        guard let value, !value.isEmpty else { return .null }
        return try encoded(value)
    }

    /// The existing list-types public view, with stable identity added. Do not
    /// assume an unsupplied TypeDefinition serialization contract. The separate
    /// full-model verifier below also compares metadata outside this projection.
    static func catalog(_ type: TypeDefinition) -> ScriptValue {
        .object(["id": .string(type.id.uuidString), "name": .string(type.name),
                 "kind": .string(type.kind.rawValue),
                 "fields": .array(type.fields.map {
                     .object(["name": .string($0.name), "type": .string($0.type)])
                 })])
    }

    static func dataShape(_ value: DataShapeOverride?) throws -> ScriptValue {
        guard let value else { return .null }
        return try encoded(value)
    }

    static func row(_ address: UInt64, _ value: ScriptValue) -> ScriptValue {
        .object(["address": .hex(address), "value": value])
    }

    enum Field: Equatable { case type, signature, label }

    static func overrides(
        command: String, store: WorkspaceStore, slot: ImageSlot, field: Field,
        expected: [(UInt64, ScriptValue)], apply: () throws -> ScriptValue
    ) throws -> ScriptValue {
        try run(command: command, store: store, slot: slot,
            requested: .array(expected.map { row($0.0, $0.1) }), read: { snapshot in
                let labels = field == .label ? snapshot.localLabels(in: slot) : [:]
                return .array(try expected.map { address, _ in
                    let value = snapshot.addressOverrides[ImageAddress(slot: slot, address: address)]
                    switch field {
                    case .type: return row(address, value?.appliedTypeName.map(ScriptValue.string) ?? .null)
                    case .signature: return try row(address, signature(value?.signature))
                    case .label: return row(address, labels[address].map(ScriptValue.string) ?? .null)
                    }
                })
            }, apply: apply)
    }

    static func bookmarks(
        command: String, store: WorkspaceStore, slot: ImageSlot,
        expected: [(UInt64, String?)], apply: () throws -> ScriptValue
    ) throws -> ScriptValue {
        // A repeated address has last-write-wins state. Preserve the existing
        // handler's input count and changed count, but compare unique final targets.
        var targets: [UInt64] = []
        var values: [UInt64: ScriptValue] = [:]
        for (address, name) in expected {
            if values[address] == nil { targets.append(address) }
            values[address] = name.map { .string($0.trimmingCharacters(in: .whitespacesAndNewlines)) } ?? .null
        }
        return try run(command: command, store: store, slot: slot,
            requested: .array(targets.map { row($0, values[$0]!) }), read: { snapshot in
                let bookmarks = snapshot.sortedBookmarks().filter { $0.imageSlot == slot }
                return .array(targets.map { address in
                    row(address, bookmarks.first { $0.address == address }.map { .string($0.name) } ?? .null)
                })
            }, apply: apply)
    }

    /// VI1-B. Per-item readback for the batch-edit tools. Each row is `header` plus the
    /// requested value; the observed rows come from the post-write snapshot through `observe`,
    /// which must return one value per row. Atomicity is `run`'s: any mismatch reverses the batch.
    static func batch(
        command: String, store: WorkspaceStore, slot: ImageSlot?,
        rows: [(header: [String: ScriptValue], requested: ScriptValue)],
        observe: @escaping (WorkspaceSnapshot) throws -> [ScriptValue],
        matchesFullModel: @escaping (WorkspaceSnapshot) -> Bool = { _ in true },
        witness: AnalysisWitness? = nil,
        effective: EffectiveLeg? = nil,
        apply: () throws -> ScriptValue
    ) throws -> ScriptValue {
        func compose(_ values: [ScriptValue]) -> ScriptValue {
            .array(zip(rows, values).map { row, value in
                var fields = row.header
                fields["value"] = value
                return .object(fields)
            })
        }
        return try run(command: command, store: store, slot: slot,
            requested: compose(rows.map { $0.requested }),
            read: { compose(try observe($0)) }, matchesFullModel: matchesFullModel,
            summarize: true, witness: witness, effective: effective, apply: apply)
    }

    /// Address-keyed override batch: `project` reads one state from the override at each address.
    static func overrideBatch(
        command: String, store: WorkspaceStore, slot: ImageSlot,
        expected: [(address: UInt64, requested: ScriptValue)],
        project: @escaping (AddressOverride) -> ScriptValue,
        flagIsolation procedures: Bool? = nil,
        apply: () throws -> ScriptValue
    ) throws -> ScriptValue {
        // VI1C-1: only `set-data` / `set-procedures` pass `flagIsolation`. They add the
        // isolation clause and the analysis-content witness; every other caller is unchanged.
        let isolation: (WorkspaceSnapshot) -> Bool
        let witness: AnalysisWitness?
        let effective: EffectiveLeg?
        if let procedures {
            isolation = flagIsolation(before: store.snapshot, slot: slot,
                                      targets: Set(expected.map(\.address)), procedures: procedures)
            witness = AnalysisWitness.capture(store.snapshot)
            effective = EffectiveLeg(before: store.snapshot, slot: slot, procedures: procedures,
                                     edits: expected.map { ($0.address, $0.requested.boolValue ?? true) })
        } else {
            isolation = { _ in true }
            witness = nil
            effective = nil
        }
        return try batch(command: command, store: store, slot: slot,
            rows: expected.map { (["address": .hex($0.address)], $0.requested) },
            observe: { snapshot in
                expected.map { project(snapshot.addressOverrides[ImageAddress(slot: slot, address: $0.address)] ?? AddressOverride()) }
            }, matchesFullModel: isolation, witness: witness, effective: effective, apply: apply)
    }

    /// Isolation clause (design 2.1). Every override outside the named targets is equal to its
    /// pre-write value, in every slot; a named target differs from its pre-write value in the
    /// one requested flag only. An absent override reads as an empty one.
    static func flagIsolation(
        before: WorkspaceSnapshot, slot: ImageSlot, targets: Set<UInt64>, procedures: Bool
    ) -> (WorkspaceSnapshot) -> Bool {
        let prior = before.addressOverrides
        return { after in
            let current = after.addressOverrides
            for key in Set(prior.keys).union(current.keys) {
                let old = prior[key] ?? AddressOverride()
                var new = current[key] ?? AddressOverride()
                if key.slot == slot, targets.contains(key.address) {
                    if procedures { new.markAsProcedure = old.markAsProcedure } else { new.isData = old.isData }
                }
                if new != old { return false }
            }
            return true
        }
    }

    /// Content witness for derived analysis (design 3.2): per slot, the `analysisInputFingerprint`
    /// facets (UUID-free, sorted canonical records) plus basic blocks with the block's function
    /// id resolved to the function start address (block ids and function UUIDs are not stable).
    /// A slot without a fingerprint makes the witness incomplete, so a rollback cannot be verified.
    struct AnalysisWitness: Equatable {
        struct Facet: Equatable { var kind: String; var items: Int; var sha256: String }
        struct Block: Equatable { var function: UInt64?; var start: UInt64; var end: UInt64; var count: Int }
        struct Slot: Equatable { var overall: String; var facets: [Facet]; var blocks: [Block] }
        var slots: [ImageSlot: Slot] = [:]
        var complete = true

        static func capture(_ snapshot: WorkspaceSnapshot) -> AnalysisWitness {
            var witness = AnalysisWitness()
            for (slot, analysis) in snapshot.analysisBySlot {
                guard let fingerprint = analysis.analysisInputFingerprint else {
                    witness.complete = false
                    continue
                }
                let starts = Dictionary(analysis.functions.map { ($0.id, $0.startAddress) },
                                        uniquingKeysWith: { first, _ in first })
                let blocks = analysis.basicBlocks.map {
                    Block(function: starts[$0.functionID], start: $0.startAddress, end: $0.endAddress,
                          count: $0.instructionCount)
                }.sorted { ($0.start, $0.end, $0.count, $0.function ?? 0) < ($1.start, $1.end, $1.count, $1.function ?? 0) }
                witness.slots[slot] = Slot(
                    overall: fingerprint.overallSHA256,
                    facets: fingerprint.facets.map { Facet(kind: $0.kind.rawValue, items: $0.itemCount, sha256: $0.sha256) }
                        .sorted { $0.kind < $1.kind },
                    blocks: blocks)
            }
            return witness
        }

        func matches(_ snapshot: WorkspaceSnapshot) -> Bool {
            let now = Self.capture(snapshot)
            return complete && now.complete && now == self
        }
    }

    /// VI1C-2. The effective leg for `set-data` / `set-procedures`: what reanalysis actually did,
    /// read from the post-write snapshot (never from the handler result, which supplies only the
    /// `reanalysisStatus` string). Only the named targets and other slots' function starts gate;
    /// every other change is collateral, disclosed and never gating (design 2.2, 2.3).
    @MainActor
    struct EffectiveLeg {
        static let xrefClauseNote = "Control-flow edges and xrefs originating at a data-marked address are listed under collateral as xrefClause: unconfirmed. This readback does not verify their absence and they never gate."

        let before: WorkspaceSnapshot
        let slot: ImageSlot
        let procedures: Bool
        let edits: [(address: UInt64, value: Bool)]

        struct Outcome {
            var status: String
            var expectedRows: ScriptValue = .array([])
            var observedRows: ScriptValue = .array([])
            var crossSlotMismatches: [Int64] = []
            var fields: [String: ScriptValue] = [:]
        }

        /// Why a procedure mark at `address` cannot produce a function start (design 2.2), or nil.
        private func unrealizableReason(
            _ address: UInt64, rows: [UInt64: InstructionRow], analysis: ImageAnalysis
        ) -> String? {
            guard let row = rows[address] else { return "no-instruction" }
            if before.isData(at: address, in: slot) || before.isUndefined(at: address, in: slot) {
                return "data-or-undefined"
            }
            if before.isInLoaderDataRange(address, in: slot) { return "loader-data-range" }
            if !analysis.sections.isEmpty {
                let executable = analysis.sections.contains { section in
                    guard section.isExecutable, !section.isZeroFill, section.size > 0 else { return false }
                    let (end, overflow) = section.address.addingReportingOverflow(section.size)
                    return !overflow && address >= section.address && address < end
                }
                if !executable { return "non-executable" }
            }
            return row.mnemonic == "unavailable" ? "undecoded" : nil
        }

        func evaluate(store: WorkspaceStore, after: WorkspaceSnapshot, reanalysisStatus: String?) -> Outcome {
            var fields: [String: ScriptValue] = ["checked": .int(Int64(edits.count))]
            func finish(_ status: String, reason: String? = nil) -> Outcome {
                fields["status"] = .string(status)
                if let reason { fields["reason"] = .string(String(reason.prefix(256))) }
                return Outcome(status: status, fields: fields)
            }
            switch reanalysisStatus {
            case "not-needed": return finish("unchanged")
            case "completed": break
            case "pending": return finish("pending", reason: "Reanalysis had not landed when the write was read back.")
            case "not-completed":
                return finish("unobserved", reason: store.lastReanalysisRefusal?.message
                    ?? store.lastIssue ?? "Reanalysis did not complete; the override stays applied.")
            default:
                return finish("unobserved", reason: "The write reply carried no recognised reanalysisStatus.")
            }
            guard let pre = before.analysis(in: slot), let post = after.analysis(in: slot) else {
                return finish("unobserved", reason: "No analysis is available for the image slot.")
            }
            let startsBefore = Set(pre.functions.map(\.startAddress))
            let startsAfter = Set(post.functions.map(\.startAddress))
            let targets = Set(edits.map(\.address))
            let rows = Dictionary(pre.instructions.map { ($0.address, $0) }, uniquingKeysWith: { first, _ in first })
            let excluded = after.codeExcludedAddresses(in: slot)
            var edgeCounts: [UInt64: Int] = [:]
            var xrefCounts: [UInt64: Int] = [:]
            if !procedures {
                for edge in post.controlFlowEdges where targets.contains(edge.from) { edgeCounts[edge.from, default: 0] += 1 }
                for xref in post.xrefs where targets.contains(xref.from) { xrefCounts[xref.from, default: 0] += 1 }
            }
            var expected: [ScriptValue] = []
            var observed: [ScriptValue] = []
            var unrealizable: [ScriptValue] = []
            var clears: [ScriptValue] = []
            var verified = 0
            for (address, value) in edits {
                if procedures {
                    if value {
                        if let reason = unrealizableReason(address, rows: rows, analysis: pre) {
                            unrealizable.append(.object(["address": .hex(address), "reason": .string(reason)]))
                        } else {
                            verified += 1
                            expected.append(.object(["address": .hex(address), "functionStart": .bool(true)]))
                            observed.append(.object(["address": .hex(address), "functionStart": .bool(startsAfter.contains(address))]))
                        }
                    } else {
                        clears.append(.object(["address": .hex(address), "startsHere": .bool(startsAfter.contains(address))]))
                    }
                } else if value {
                    verified += 1
                    expected.append(.object(["address": .hex(address), "functionStart": .bool(false), "codeExcluded": .bool(true)]))
                    observed.append(.object(["address": .hex(address), "functionStart": .bool(startsAfter.contains(address)),
                                             "codeExcluded": .bool(excluded.contains(address))]))
                } else {
                    clears.append(.object(["address": .hex(address), "startsHere": .bool(startsAfter.contains(address))]))
                    // Code again only if no other exclusion remains. A loader data range makes
                    // the exclusion set instruction-dependent, so that case makes no claim.
                    let override = after.addressOverrides[ImageAddress(slot: slot, address: address)]
                    let remains = (override?.isUndefined ?? false) || !(override?.dataShape?.isEmpty ?? true)
                    if remains || !after.isInLoaderDataRange(address, in: slot) {
                        expected.append(.object(["address": .hex(address), "codeExcluded": .bool(remains)]))
                        observed.append(.object(["address": .hex(address), "codeExcluded": .bool(excluded.contains(address))]))
                    }
                }
            }
            // Cross-slot: a primary-slot write must not move any other slot's function starts.
            func startSet(_ snapshot: WorkspaceSnapshot, _ other: ImageSlot) -> Set<UInt64>? {
                snapshot.analysis(in: other).map { Set($0.functions.map(\.startAddress)) }
            }
            var crossSlot: [Int64] = []
            for other in Set(before.analysisBySlot.keys).union(after.analysisBySlot.keys).sorted() where other != slot {
                if startSet(before, other) != startSet(after, other) { crossSlot.append(Int64(other.rawValue)) }
            }
            // Collateral: disclosed, never gating.
            let beforeEnds = Dictionary(pre.functions.map { ($0.startAddress, $0.endAddress) }, uniquingKeysWith: { first, _ in first })
            let moved: [ScriptValue] = post.functions.compactMap { function in
                guard !targets.contains(function.startAddress), let old = beforeEnds[function.startAddress],
                      old != function.endAddress else { return nil }
                return .object(["address": .hex(function.startAddress), "endBefore": .hex(old), "endAfter": .hex(function.endAddress)])
            }
            var collateral: [String: ScriptValue] = [
                "functionStartsAdded": ScriptingWriteReadback.disclosure(.array(startsAfter.subtracting(startsBefore).subtracting(targets).sorted().map { .hex($0) })),
                "functionStartsRemoved": ScriptingWriteReadback.disclosure(.array(startsBefore.subtracting(startsAfter).subtracting(targets).sorted().map { .hex($0) })),
                "functionEndsMoved": ScriptingWriteReadback.disclosure(.array(moved)),
                "functionCountBefore": .int(Int64(pre.functions.count)), "functionCountAfter": .int(Int64(post.functions.count)),
                "xrefCountBefore": .int(Int64(pre.xrefs.count)), "xrefCountAfter": .int(Int64(post.xrefs.count)),
                "edgeCountBefore": .int(Int64(pre.controlFlowEdges.count)), "edgeCountAfter": .int(Int64(post.controlFlowEdges.count)),
            ]
            if !procedures {
                collateral["xrefClause"] = .string("unconfirmed")
                collateral["fromTargets"] = ScriptingWriteReadback.disclosure(.array(targets.sorted().compactMap { address in
                    guard edgeCounts[address, default: 0] + xrefCounts[address, default: 0] > 0 else { return nil }
                    return .object(["address": .hex(address), "controlFlowEdges": .int(Int64(edgeCounts[address, default: 0])),
                                    "xrefs": .int(Int64(xrefCounts[address, default: 0])), "xrefClause": .string("unconfirmed")])
                }))
                fields["disclosure"] = .string(Self.xrefClauseNote)
            }
            fields["collateral"] = .object(collateral)
            if !unrealizable.isEmpty { fields["unrealizable"] = ScriptingWriteReadback.disclosure(.array(unrealizable)) }
            if !clears.isEmpty { fields["clears"] = ScriptingWriteReadback.disclosure(.array(clears)) }
            let status = !unrealizable.isEmpty ? "unrealizable" : verified > 0 ? "verified" : "cleared"
            fields["status"] = .string(status)
            return Outcome(status: status, expectedRows: .array(expected), observedRows: .array(observed),
                           crossSlotMismatches: crossSlot, fields: fields)
        }
    }

    static let maximumReportedMismatches = 8

    /// Counts and names mismatched rows without dropping any from the count. At most
    /// `maximumReportedMismatches` are described; `truncated` says the list is partial.
    static func mismatchSummary(requested: ScriptValue, observed: ScriptValue) -> (summary: ScriptValue, first: ScriptValue?)? {
        guard case .array(let wanted) = requested else { return nil }
        var observedRows: [ScriptValue]?
        if case .array(let rows) = observed, rows.count == wanted.count { observedRows = rows }
        var count = 0
        var described: [ScriptValue] = []
        for index in wanted.indices {
            let seen = observedRows?[index]
            if let seen, seen == wanted[index] { continue }
            count += 1
            guard described.count < maximumReportedMismatches else { continue }
            var fields: [String: ScriptValue] = ["index": .int(Int64(index)),
                "requested": disclosure(wanted[index]), "observed": disclosure(seen ?? .null)]
            if let address = wanted[index]["address"] { fields["address"] = address }
            described.append(.object(fields))
        }
        let summary: ScriptValue = .object([
            "items": .int(Int64(wanted.count)), "mismatchCount": .int(Int64(count)),
            "firstMismatches": .array(described), "truncated": .bool(count > described.count),
        ])
        return (summary, described.first)
    }

    /// The comparison always uses the complete values. Disclosure is a bounded
    /// sample: at most 16 rows, 16 children per value and 128 UTF-8 bytes per leaf,
    /// with a 512-node budget per state. No input is rejected or truncated at apply.
    static func disclosure(_ value: ScriptValue) -> ScriptValue {
        var budget = 512
        func clipped(_ value: ScriptValue, depth: Int) -> ScriptValue {
            guard budget > 0, depth < 8 else { return .string("<omitted>") }
            budget -= 1
            switch value {
            case .string(let text):
                guard text.utf8.count > 128 else { return value }
                return .object(["prefix": .string(String(decoding: text.utf8.prefix(128), as: UTF8.self)),
                                "utf8Bytes": .int(Int64(text.utf8.count)), "truncated": .bool(true)])
            case .array(let rows):
                return .object(["count": .int(Int64(rows.count)),
                    "sample": .array(rows.prefix(16).map { clipped($0, depth: depth + 1) }),
                    "omitted": .int(Int64(max(0, rows.count - 16)))])
            case .object(let fields):
                let keys = fields.keys.sorted()
                var result: [String: ScriptValue] = [:]
                for key in keys.prefix(16) { result[key] = clipped(fields[key]!, depth: depth + 1) }
                if keys.count > 16 { result["omittedKeys"] = .int(Int64(keys.count - 16)) }
                return .object(result)
            default: return value
            }
        }
        return clipped(value, depth: 0)
    }

    /// Isolate native undo registrations until verification. The original
    /// manager, including its redo history and any open event group, is untouched
    /// on failure. No global undo(), action-name inference, or cache reset.
    static func run(
        command: String, store: WorkspaceStore, slot: ImageSlot?,
        requested: ScriptValue,
        read: (WorkspaceSnapshot) throws -> ScriptValue,
        matchesFullModel: (WorkspaceSnapshot) -> Bool = { _ in true },
        summarize: Bool = false,
        witness: AnalysisWitness? = nil,
        effective: EffectiveLeg? = nil,
        apply: () throws -> ScriptValue
    ) throws -> ScriptValue {
        let before = store.snapshot
        let original = store.undoManager
        let originalHost = store.hostUndoManager // strong for the whole span
        let pending = UndoManager()
        pending.groupsByEvent = false
        store.hostUndoManager = pending
        defer { store.hostUndoManager = originalHost }
        var stage = "apply"
        var observed: ScriptValue = .null
        var reportedRequested = requested
        var leg = "raw"
        var effectiveFailure: ScriptValue?
        var verification = "full-state-equal"
        var effectiveFields: [String: ScriptValue]?
        do {
            // Each covered store call already opens/closes exactly one group
            // when groupsByEvent is false. Do not nest it and lose its action name.
            let result = try apply()
            stage = "readback"
            // This read uses the POST-write snapshot, not the mutator's result.
            let after = store.snapshot
            observed = try read(after)
            if let inject = ScriptingWriteReadbackInjection.observe {
                observed = try inject(command, observed)
            }
            stage = "compare"
            guard observed == requested, matchesFullModel(after) else { throw Mismatch() }
            guard case .object(var fields) = result else { throw UnexpectedResult() }
            // G6: a witnessless structural writer (make-arrays, set-undefined, ...) has no effective
            // leg, so nothing else reads whether its inverse/override reanalysis ran. The store
            // reports a refused or failed synchronous reanalysis as "not-completed"; the authored
            // collections can still match, so fail here instead of verifying stale derived analysis.
            if effective == nil, fields["reanalysisStatus"]?.stringValue == "not-completed" {
                stage = "reanalysis"
                throw ReanalysisNotCompleted()
            }
            if let effective {
                // Effective leg: what reanalysis did, read from `after`, not from `result`.
                stage = "effective"
                leg = "effective"
                let outcome = effective.evaluate(store: store, after: store.snapshot,
                                                 reanalysisStatus: fields["reanalysisStatus"]?.stringValue)
                var seen = outcome.observedRows
                if let inject = ScriptingWriteReadbackInjection.observeEffective {
                    seen = try inject(command, seen)
                }
                if seen != outcome.expectedRows || !outcome.crossSlotMismatches.isEmpty {
                    reportedRequested = outcome.expectedRows
                    observed = seen
                    var failure: [String: ScriptValue] = [
                        "status": .string("mismatch"),
                        "crossSlotMismatches": .array(outcome.crossSlotMismatches.map { .int($0) })]
                    if let found = mismatchSummary(requested: outcome.expectedRows, observed: seen) {
                        failure["readback"] = found.summary
                    }
                    effectiveFailure = .object(failure)
                    throw Mismatch()
                }
                var summary = outcome.fields
                summary["mismatches"] = .int(0)
                effectiveFields = summary
                if !["verified", "unchanged", "cleared"].contains(outcome.status) { verification = "override-equal" }
            }
            // The private manager stays enabled for failure recovery even when
            // the caller disabled history. Such a successful write must not
            // publish any action or alter the caller's disabled/history state.
            if pending.canUndo && original.isUndoRegistrationEnabled {
                let claim = agentUndoName
                claim?.used = true
                let bridge = VerifiedUndo(manager: pending, actionName: claim?.name ?? pending.undoActionName, slot: slot)
                store.hostUndoManager = originalHost
                bridge.register(store: store, on: original, undo: true)
            }
            fields["requested"] = disclosure(requested)
            fields["observed"] = disclosure(observed)
            fields["verification"] = .string(verification)
            if let effectiveFields { fields["effective"] = .object(effectiveFields) }
            if summarize, case .array(let rows) = requested {
                fields["readback"] = .object(["items": .int(Int64(rows.count)), "mismatchCount": .int(0),
                    "firstMismatches": .array([]), "truncated": .bool(rows.count > 16)])
            }
            return .object(fields)
        } catch {
            // pending started empty. canUndo proves THIS invocation registered
            // history, including the idempotent/no-op case with an empty group.
            if pending.canUndo { pending.undo() }
            // Native bookmark undo restores a slot partition by remove+append.
            // Restore only its previous inter-slot order after proving that both
            // partitions are already identical in content and internal order.
            if let slot,
               store.snapshot.bookmarks.filter({ $0.imageSlot == slot }) == before.bookmarks.filter({ $0.imageSlot == slot }),
               store.snapshot.bookmarks.filter({ $0.imageSlot != slot }) == before.bookmarks.filter({ $0.imageSlot != slot }),
               store.snapshot.bookmarks != before.bookmarks {
                store.snapshot.bookmarks = before.bookmarks
            }
            let restored = store.snapshot.addressOverrides == before.addressOverrides
                && store.snapshot.bookmarks == before.bookmarks
                && store.snapshot.typeDefinitions == before.typeDefinitions
                && store.snapshot.manualXRefs == before.manualXRefs
                && store.snapshot.segmentOverrides == before.segmentOverrides
            // With a witness, a rollback is verified only when derived analysis matches the
            // pre-write content too. Undo re-runs the engine; it does not restore by value.
            let analysisRestored = witness.map { $0.matches(store.snapshot) } ?? true
            let verified = restored && analysisRestored
            var fields: [String: ScriptValue] = [
                "error": .string("writeReadbackFailed"),
                "stage": .string(restored ? stage : "rollback"),
                "requested": disclosure(reportedRequested), "observed": disclosure(observed),
                "rolledBack": .bool(verified),
                "recovery": .string(verified
                    ? "Read fresh workspace state before retrying. The failed write was reversed; journal history is retained."
                    : restored
                    ? "Overrides were restored but derived analysis did not match the pre-write analysis. If a .mscope package exists, run open-workspace on it; unsaved edits are lost. Do not trust function lists or xrefs until then."
                    : "Stop writes and inspect overrides, bookmarks and the type catalog. Native rollback did not restore the pre-image; do not retry automatically.")
            ]
            if witness != nil {
                fields["rollbackStatus"] = .string(!restored ? "unavailable" : analysisRestored ? "restored-verified" : "restored-overrides-only")
                fields["rollbackIdentity"] = .string("generation-advanced")
                fields["leg"] = .string(leg)
            }
            if let effectiveFailure { fields["effective"] = effectiveFailure }
            if !restored { fields["failedStage"] = .string(stage) }
            if summarize, stage == "compare", let found = mismatchSummary(requested: requested, observed: observed) {
                fields["readback"] = found.summary
                if let first = found.first {
                    fields["item"] = .object(["index": first["index"] ?? .null, "address": first["address"] ?? .null])
                }
            }
            if !(error is Mismatch) { fields["detail"] = .string(String(error.localizedDescription.prefix(256))) }
            throw ScriptingWriteReadbackFailure(reply: .object(fields))
        }
    }

    private struct Mismatch: Error {}
    private struct UnexpectedResult: Error {}
    private struct ReanalysisNotCompleted: LocalizedError {
        var errorDescription: String? {
            "Structural reanalysis did not complete after the write (refused or failed); derived analysis was not refreshed."
        }
    }

    /// Keep native inverse closures, dirty-token restoration, journal appends and
    /// structural reanalysis. Publish only the bridge to the caller's manager.
    /// Slot bridges use the existing generation-owned target, so removing an
    /// image retires them just like ordinary authoring undo. Catalog undo is global.
    @MainActor
    private final class VerifiedUndo {
        let manager: UndoManager
        let actionName: String
        let slot: ImageSlot?

        init(manager: UndoManager, actionName: String, slot: ImageSlot?) {
            self.manager = manager; self.actionName = actionName; self.slot = slot
        }

        func register(store: WorkspaceStore, on outer: UndoManager, undo: Bool) {
            let explicit = !outer.groupsByEvent && !outer.isUndoing && !outer.isRedoing
            if explicit { outer.beginUndoGrouping() }
            if let slot {
                store.registerSlotScopedUndo(in: slot) { store in self.replay(store: store, undo: undo) }
            } else {
                outer.registerUndo(withTarget: store) { store in self.replay(store: store, undo: undo) }
            }
            // Inverse groups inherit their outer title. In particular, retain
            // the attached executor's "Agent: command" name across undo/redo.
            if !outer.isUndoing && !outer.isRedoing { outer.setActionName(actionName) }
            if explicit { outer.endUndoGrouping() }
        }

        func replay(store: WorkspaceStore, undo: Bool) {
            let outer = store.undoManager
            let host = store.hostUndoManager
            store.hostUndoManager = manager
            if undo { manager.undo() } else { manager.redo() }
            store.hostUndoManager = host
            register(store: store, on: outer, undo: !undo)
        }
    }
}
