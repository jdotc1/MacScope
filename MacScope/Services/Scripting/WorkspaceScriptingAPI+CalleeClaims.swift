import Foundation

/// VI3 slice C: the three claim commands (DESIGN sections 2.1 to 2.4 and 3).
///
/// - `open-claim`: reads slice B's typed direct-callee inventory, maps it onto slice A's ledger model
///   and opens (or returns) the claim of that function. `supersede:true` opens revision n+1 over a
///   stale claim with every callee open and returns the earlier outcomes as non-satisfying
///   `priorOutcomes`. `rebind:true` (slice D) re-binds a `generationAdvanced` claim to the current
///   generation, keeping its outcomes except for examined callees whose body digest changed.
/// - `record-callee-outcome`: appends one `examined`/`irrelevant`/`deferred` outcome to the claim.
/// - `claim-status`: read-only; lists what is still open.
///
/// "Mutating (ledger only)": the two writers honour `basedOnGeneration` (the shared
/// `requireCurrentGeneration` runs before any effect), run inside the execution fence, do NOT change
/// `analysisGenerationID` (the ledger is outside the snapshot), register NO undo step and are
/// journal-exempt (`editJournalExemptCommands`) as commands; the store's ledger observer persists the
/// claim events itself (VI3 slice F, item 1256). Every reply reports `durability` as the store's
/// `calleeClaimDurability`, read after the mutation returns: `session` until the whole ledger is in
/// the edit journal (`journal`) or a published package (`package`).
///
/// Staleness is digest-bound (slice A's `classify`, DESIGN 2.4): a moved generation with an equal root
/// inventory digest is `generationAdvanced` (rebindable); a different digest is `inventoryChanged`
/// (supersede only). The projection epoch is carried and reported, never a gate.
///
/// Refusals are returned as `{ok:false, error:<code>, detail, ...}` objects (the `staleEvidenceReply`
/// shape), because `MCPRefusalCode` is a closed set. `budgetExceeded` is slice B's own structured
/// refusal, rethrown unchanged: no claim and no empty list is ever produced from a refused scan.
extension WorkspaceScriptingAPI {
    nonisolated static let calleeClaimScope =
        "Stored direct call xrefs of this function only; not indirect calls, virtual dispatch, callbacks, tail calls or program-wide"
    nonisolated static let examinedNotWitnessedLimitation = "examinedNotWitnessed"
    nonisolated static let calleeClaimDefaultPageLimit = 100

    nonisolated static var calleeClaimCommands: [DocumentCommand] {
        [
            (ScriptingCommandInfo(
                name: "open-claim",
                summary: "Opt-in callee coverage (session only): open the claim of one function, listing its stored direct call targets (`function` display or raw name, or `address` inside it; optional `imageSlot`). The claim stays open until every listed callee has a recorded outcome; a second call returns the existing claim (alreadyOpen). Indirect and tail calls are typed in `limitations`, never guessed. A claim whose analysis generation moved is stale: if the callee inventory is unchanged (`generationAdvanced`, `rebindable:true`) `rebind:true` re-binds it, keeps every outcome whose callee body digest is unchanged and returns the others to open (`invalidatedCallees`; `bodyNotDigestible` lists examined callees with no body in this image); if the inventory changed (`inventoryChanged`, with `addedCallees`/`removedCallees`) only `supersede:true` opens the next revision with every callee open and earlier outcomes listed as non-satisfying `priorOutcomes`. `rebind` and `supersede` cannot be combined. Changes only the in-memory claim ledger, not the analysis generation; no undo step.",
                mutates: true, arguments: ["function", "address", "imageSlot", "rebind", "supersede"]
            ), { arguments, store in try openClaim(arguments, store: store) }),
            (ScriptingCommandInfo(
                name: "record-callee-outcome",
                summary: "Record the outcome of one callee of an open claim (session only): `outcome` is examined, irrelevant or deferred, with a `reason` of 1...2048 bytes; examined may carry `bearing` (supports, contradicts, neutral). `callee` is an address or a name from the claim's own list. The latest outcome per callee wins and history is kept. A stale claim is refused (claimStale). Changes only the in-memory claim ledger; no undo step. An examined outcome needs a read witness: the callee's code must have been read in this session, at the current analysis generation, by instructions (by function, not an address range), decompile, basic-blocks or function-facts. Otherwise it is refused with examinedWithoutWitness; re-read the callee and record again. callees, callers, call-graph and xrefs never witness. The stored outcome carries the witness {command, generation, sequence}.",
                mutates: true, arguments: ["claim", "callee", "outcome", "reason", "bearing"]
            ), { arguments, store in try recordCalleeOutcome(arguments, store: store) }),
            (ScriptingCommandInfo(
                name: "claim-status",
                summary: "Read-only: what is still open in a callee-coverage claim. Select with `claim` (identifier) or `function`/`address` (with optional `imageSlot`; several images holding a claim for the function need `imageSlot`: claimAmbiguous). With no selector it lists claims whose status matches `state` (open, closed, stale or all; default open). openCallees is limited by `limit` 1...100 (default 100); `detail:\"all\"` also lists every callee with its latest outcome. Session only.",
                mutates: false, arguments: ["claim", "function", "address", "imageSlot", "state", "limit", "detail"]
            ), { arguments, store in try claimStatus(arguments, store: store) }),
        ]
    }

    // MARK: - B to A mapping

    /// Maps slice B's snapshot onto slice A's inventory. Pure: kinds map 1:1, the required set is sorted
    /// strictly ascending by callee address (A requires that), out-of-function branches stay advisory
    /// and are not carried, and B's limitations become the inventory's limitations unchanged.
    nonisolated static func calleeClaimVAInventory(from snapshot: CalleeClaimInventorySnapshot) throws -> VACalleeInventory {
        func clipped(_ text: String, bytes: Int) -> String {
            var text = text
            while text.utf8.count > bytes { text.removeLast() }
            return text
        }
        func mapped(_ kind: CalleeClaimInventorySnapshot.CalleeKind) -> VACalleeKind {
            switch kind {
            case .function: return .function
            case .interior: return .interior
            case .stub: return .stub
            case .external: return .external
            case .unnamed: return .unnamed
            }
        }
        var seen = Set<UInt64>()
        var entries: [VACalleeInventoryEntry] = []
        for callee in snapshot.callees.sorted(by: { $0.address < $1.address }) {
            guard seen.insert(callee.address).inserted else { continue }
            let kind = mapped(callee.kind)
            let name = callee.name.flatMap { $0.isEmpty ? nil : clipped($0, bytes: VACalleeClaimLimits.maximumNameBytes) }
            entries.append(VACalleeInventoryEntry(
                callee: VAAddress64(callee.address), kind: kind, name: kind == .unnamed ? nil : name,
                callSiteCount: callee.callSiteCount, callSites: callee.callSites.map { VAAddress64($0) },
                callSitesTruncated: callee.callSitesTruncated,
                containingFunction: kind == .interior ? callee.containingFunction.map { VAAddress64($0) } : nil,
                offsetInFunction: kind == .interior ? callee.offsetInContainingFunction : nil))
        }
        var indirectSeen = Set<VACalleeIndirectEntry>()
        var indirect: [VACalleeIndirectEntry] = []
        for resolved in snapshot.resolvedIndirect {
            let entry = VACalleeIndirectEntry(
                callSite: VAAddress64(resolved.callSite), target: VAAddress64(resolved.target),
                targetName: resolved.targetName.flatMap {
                    $0.isEmpty ? nil : clipped($0, bytes: VACalleeClaimLimits.maximumNameBytes)
                },
                scope: clipped(resolved.scope.isEmpty ? "function" : resolved.scope,
                               bytes: VACalleeClaimLimits.maximumScopeBytes))
            if indirectSeen.insert(entry).inserted { indirect.append(entry) }
        }
        let inventory = VACalleeInventory(
            function: VAAddress64(snapshot.functionStart), completeness: .complete, callees: entries,
            indirect: indirect, unresolvedIndirectCallSites: snapshot.unresolvedIndirectCallSites ?? 0,
            limitations: snapshot.limitations, inventoryDigest: snapshot.inventoryDigest)
        try inventory.validate()
        return inventory
    }

    // MARK: - Ledger views

    private struct ClaimView {
        var binding: VACalleeClaimBinding
        var inventory: VACalleeInventory
        var revision: Int
    }

    /// The latest binding, inventory and revision of every claim, derived from the event log.
    private static func claimViews(_ ledger: CalleeClaimLedger) -> [UUID: ClaimView] {
        var views: [UUID: ClaimView] = [:]
        for event in ledger.events {
            switch event.kind {
            case .claimOpened, .claimSuperseded:
                if let binding = event.binding, let inventory = event.inventory {
                    views[event.claimID] = ClaimView(binding: binding, inventory: inventory, revision: event.revision)
                }
            case .claimRebound:
                if let binding = event.binding { views[event.claimID]?.binding = binding }
            case .outcomeRecorded:
                break
            }
        }
        return views
    }

    nonisolated private static func nowMilliseconds() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970 * 1_000))
    }

    nonisolated private static func nanos() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    /// What the caller observes now about the claim's target. A claim at its bound generation on the same
    /// image is current by definition and costs nothing; a moved generation rescans the function once.
    private static func claimObservation(for view: ClaimView, store: WorkspaceStore,
                                         millis: inout Int) throws -> VACalleeClaimObservation {
        let snapshot = store.snapshot
        let generation = snapshot.analysisGenerationID
        let slot = ImageSlot(rawValue: view.binding.slot)
        guard let owner = snapshot.binary(in: slot)?.id else {
            return VACalleeClaimObservation(
                imageOwner: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
                generation: generation, inventory: view.inventory)
        }
        if owner != view.binding.imageOwner || generation == view.binding.analysisGeneration {
            return VACalleeClaimObservation(imageOwner: owner, generation: generation, inventory: view.inventory)
        }
        let started = nanos()
        defer { millis += Int((nanos() - started) / 1_000_000) }
        let arguments: ScriptValue = .object([
            "address": .hex(view.binding.function.rawValue), "imageSlot": .int(Int64(slot.rawValue)),
        ])
        var observed: VACalleeInventory?
        do {
            let read = try calleeClaimInventory(arguments: arguments, snapshot: snapshot, checkpoint: {})
            if read.functionStart == view.binding.function.rawValue {
                observed = try calleeClaimVAInventory(from: read)
            }
        } catch CalleeClaimInventoryError.inventoryUnavailable {
            observed = nil
        } catch CalleeClaimInventoryError.digestUnavailable {
            observed = nil
        } catch ScriptingError.structuredRefusal(let refusal) where refusal.code != .budgetExceeded && refusal.code != .cancelled {
            observed = nil
        } catch ScriptingError.invalidArgument {
            observed = nil
        }
        return VACalleeClaimObservation(imageOwner: owner, generation: generation, inventory: observed)
    }

    // MARK: - Reply building

    private static func refusal(_ code: String, _ detail: String, store: WorkspaceStore,
                                _ extra: [String: ScriptValue] = [:]) -> ScriptValue {
        var fields: [String: ScriptValue] = [
            "ok": .bool(false), "error": .string(code), "detail": .string(detail),
            "durability": .string(store.calleeClaimDurability.rawValue), "generation": .string(store.snapshot.analysisGenerationID.uuidString),
        ]
        for (key, value) in extra { fields[key] = value }
        return .object(fields)
    }

    private static func staleRefusal(claimID: UUID, view: ClaimView, classification: VACalleeStaleClassification,
                                     store: WorkspaceStore, observed: VACalleeClaimObservation? = nil) -> ScriptValue {
        let recovery: String
        if classification.kind == .functionGone || classification.kind == .imageChanged {
            recovery = "the function no longer resolves in this image, so there is no inventory to rebind or supersede over"
        } else if classification.rebindable {
            recovery = "open-claim with rebind:true re-binds it (supersede:true opens the next revision)"
        } else {
            recovery = "open-claim with supersede:true opens the next revision"
        }
        var extra: [String: ScriptValue] = [
            "claim": .string(claimID.uuidString), "revision": .int(Int64(view.revision)),
            "staleKind": classification.kind.map { .string($0.rawValue) } ?? .null,
            "rebindable": .bool(classification.rebindable),
            "claimGeneration": .string(view.binding.analysisGeneration.uuidString),
            "currentGeneration": .string(store.snapshot.analysisGenerationID.uuidString),
            "addedCallees": .array(classification.addedCallees.map { .hex($0.rawValue) }),
            "removedCallees": .array(classification.removedCallees.map { .hex($0.rawValue) }),
        ]
        if classification.kind == .inventoryChanged {
            extra["addedCalleeNames"] = .array(diffRows(classification.addedCallees, inventory: observed?.inventory))
            extra["removedCalleeNames"] = .array(diffRows(classification.removedCallees, inventory: view.inventory))
        }
        return refusal("claimStale", "the claim is stale (\(classification.kind?.rawValue ?? "unknown")); \(recovery)",
                       store: store, extra)
    }

    /// Display rows for the added/removed callees of an `inventoryChanged` claim: ascending addresses with
    /// the name as display only (the address is the identity).
    private static func diffRows(_ addresses: [VAAddress64], inventory: VACalleeInventory?) -> [ScriptValue] {
        var rows: [ScriptValue] = []
        for address in addresses {
            let name: String? = inventory?.callees.first(where: { $0.callee == address })?.name
            let display: ScriptValue = name.map { ScriptValue.string($0) } ?? .null
            rows.append(.object(["callee": .hex(address.rawValue), "name": display]))
        }
        return rows
    }

    // MARK: - Body digests (slice D)

    /// The digest of the body behind one callee address, typed from `inventory` (the callee's entry) or, for
    /// an advisory indirect target, from the image's function table. nil: no body in this image.
    private static func bodyDigest(of address: VAAddress64, in inventory: VACalleeInventory,
                                   snapshot: WorkspaceSnapshot, slot: Int) throws -> String? {
        let view = imageProjection(of: snapshot, in: ImageSlot(rawValue: slot))
        let callee: CalleeClaimInventorySnapshot.Callee
        if let entry = inventory.callees.first(where: { $0.callee == address }) {
            let kind: CalleeClaimInventorySnapshot.CalleeKind
            switch entry.kind {
            case .function: kind = .function
            case .interior: kind = .interior
            case .stub: kind = .stub
            case .external: kind = .external
            case .unnamed: kind = .unnamed
            }
            callee = .init(address: address.rawValue, kind: kind, name: nil,
                           containingFunction: entry.containingFunction?.rawValue,
                           offsetInContainingFunction: entry.offsetInFunction,
                           callSiteCount: 0, callSites: [], callSitesTruncated: false)
        } else {
            let isFunction = view.analysis(in: view.primarySlot)?.functions
                .contains { $0.startAddress == address.rawValue } ?? false
            callee = .init(address: address.rawValue, kind: isFunction ? .function : .unnamed, name: nil,
                           containingFunction: nil, offsetInContainingFunction: nil,
                           callSiteCount: 0, callSites: [], callSitesTruncated: false)
        }
        return try calleeBodyDigest(callee: callee, snapshot: view)
    }

    /// The outcome now standing per callee in the claim's current revision: the latest `outcomeRecorded`
    /// event, minus callees a `claimRebound` returned to open afterwards.
    private static func currentOutcomes(_ claimID: UUID, revision: Int,
                                        ledger: CalleeClaimLedger) -> [VAAddress64: VACalleeOutcomeRecord] {
        var standing: [VAAddress64: VACalleeOutcomeRecord] = [:]
        for event in ledger.events where event.claimID == claimID && event.revision == revision {
            switch event.kind {
            case .outcomeRecorded:
                if let callee = event.callee, let outcome = event.outcome, let reason = event.reason {
                    standing[callee] = VACalleeOutcomeRecord(
                        callee: callee, outcome: outcome, reason: reason, bearing: event.bearing,
                        bodyDigest: event.bodyDigest, witness: event.witness, sequence: event.sequence,
                        revision: event.revision)
                }
            case .claimRebound:
                for callee in event.invalidatedCallees ?? [] { standing[callee] = nil }
            case .claimOpened, .claimSuperseded:
                break
            }
        }
        return standing
    }

    private static func claimLimitRefusal(_ detail: String, store: WorkspaceStore, ledger: CalleeClaimLedger) -> ScriptValue {
        var closeable: [(open: Int, id: UUID)] = []
        let views = claimViews(ledger)
        let generation = store.snapshot.analysisGenerationID
        for id in ledger.claimIDs {
            guard let view = views[id], view.binding.analysisGeneration == generation,
                  let report = try? ledger.report(
                    claimID: id, observed: .init(imageOwner: view.binding.imageOwner, generation: generation,
                                                 inventory: view.inventory)) else { continue }
            closeable.append((report.coverage.open, id))
        }
        closeable.sort { ($0.open, $0.id.uuidString) < ($1.open, $1.id.uuidString) }
        return refusal("claimLimit", detail, store: store, [
            "narrowing": .array(closeable.prefix(8).map { .string($0.id.uuidString) }),
            "maximumClaims": .int(Int64(VACalleeClaimLimits.maximumClaims)),
            "maximumEvents": .int(Int64(VACalleeClaimLimits.maximumEvents)),
        ])
    }

    private static func calleeRow(_ address: VAAddress64, view: ClaimView) -> ScriptValue {
        if let entry = view.inventory.callees.first(where: { $0.callee == address }) {
            return .object([
                "callee": .hex(address.rawValue), "name": entry.name.map { .string($0) } ?? .null,
                "kind": .string(entry.kind.rawValue), "callSiteCount": .int(Int64(entry.callSiteCount)),
                "advisory": .bool(false),
            ])
        }
        let advisory = view.inventory.indirect.first(where: { $0.target == address })
        return .object([
            "callee": .hex(address.rawValue), "name": advisory?.targetName.map { .string($0) } ?? .null,
            "kind": .string("indirect"), "callSiteCount": .int(Int64(advisory == nil ? 0 : 1)),
            "advisory": .bool(true),
        ])
    }

    private static func rows(_ addresses: [VAAddress64], view: ClaimView, limit: Int) -> (rows: [ScriptValue], truncated: Bool) {
        (addresses.prefix(limit).map { calleeRow($0, view: view) }, addresses.count > limit)
    }

    /// True when the latest outcome of any callee of the current revision is `examined`.
    private static func hasExaminedOutcome(_ claimID: UUID, revision: Int, ledger: CalleeClaimLedger) -> Bool {
        currentOutcomes(claimID, revision: revision, ledger: ledger).values.contains { $0.outcome == .examined && $0.witness == nil }
    }

    private static func coverageValue(_ report: VACalleeClaimReport, limitations: [String]) -> ScriptValue {
        let coverage = report.coverage
        return .object([
            "required": .int(Int64(coverage.required)), "examined": .int(Int64(coverage.examined)),
            "irrelevant": .int(Int64(coverage.irrelevant)), "deferred": .int(Int64(coverage.deferred)),
            "open": .int(Int64(coverage.open)), "advisoryRecorded": .int(Int64(coverage.advisoryRecorded)),
            "unresolvedIndirectCallSites": .int(Int64(coverage.unresolvedIndirectCallSites)),
            "limitations": .array(limitations.map { .string($0) }),
            "scope": .string(calleeClaimScope),
        ])
    }

    /// The common success reply: `durability`, `generation`, `claim`, `revision`, `binding`, `status`,
    /// `coverage` and `limitations` are always present.
    private static func claimReply(claimID: UUID, report: VACalleeClaimReport, view: ClaimView,
                                   ledger: CalleeClaimLedger, store: WorkspaceStore, limit: Int,
                                   includeAllCallees: Bool = false, inventoryMillis: Int,
                                   observed: VACalleeClaimObservation? = nil,
                                   extra: [String: ScriptValue] = [:]) -> ScriptValue {
        var limitations = Set(report.coverage.limitations)
        if hasExaminedOutcome(claimID, revision: view.revision, ledger: ledger) {
            limitations.insert(examinedNotWitnessedLimitation)
        }
        let sortedLimitations = limitations.sorted()
        let snapshot = store.snapshot
        let open = rows(report.openCallees, view: view, limit: limit)
        let deferred = rows(report.deferredCallees, view: view, limit: limit)
        var fields: [String: ScriptValue] = [
            "ok": .bool(true),
            "durability": .string(store.calleeClaimDurability.rawValue),
            "generation": .string(snapshot.analysisGenerationID.uuidString),
            "claim": .string(claimID.uuidString),
            "revision": .int(Int64(report.revision)),
            "binding": .object([
                "generation": .string(report.binding.analysisGeneration.uuidString),
                "inventoryDigest": .string(report.binding.inventoryDigest),
                "projectionEpoch": .null,
                "imageOwner": .string(report.binding.imageOwner.uuidString),
                "imageSlot": .int(Int64(report.binding.slot)),
                "function": .hex(report.binding.function.rawValue),
            ]),
            "function": .hex(view.binding.function.rawValue),
            "functionName": .string(snapshot.displayName(
                at: view.binding.function.rawValue, in: ImageSlot(rawValue: view.binding.slot),
                default: view.binding.function.description)),
            "imageSlot": .int(Int64(view.binding.slot)),
            "status": .string(report.status.rawValue),
            "staleKind": report.staleKind.map { .string($0.rawValue) } ?? .null,
            "rebindable": .bool(report.rebindable),
            "leaf": .bool(report.leaf),
            "closedWithDeferrals": .bool(report.closedWithDeferrals),
            "coverage": coverageValue(report, limitations: sortedLimitations),
            "limitations": .array(sortedLimitations.map { .string($0) }),
            "openCallees": .array(open.rows),
            "openCalleesTotal": .int(Int64(report.openCallees.count)),
            "openCalleesTruncated": .bool(open.truncated),
            "deferredCallees": .array(deferred.rows),
            "contradictingCallees": .array(report.contradictingCallees.map { .hex($0.rawValue) }),
            "scope": .string(calleeClaimScope),
        ]
        if report.status == .stale {
            fields["addedCallees"] = .array(report.addedCallees.map { .hex($0.rawValue) })
            fields["removedCallees"] = .array(report.removedCallees.map { .hex($0.rawValue) })
            if report.staleKind == .inventoryChanged {
                fields["addedCalleeNames"] = .array(diffRows(report.addedCallees, inventory: observed?.inventory))
                fields["removedCalleeNames"] = .array(diffRows(report.removedCallees, inventory: view.inventory))
            }
            if report.staleKind == .generationAdvanced { fields["projectionEpochMoved"] = .bool(report.projectionEpochMoved) }
        }
        if includeAllCallees {
            var all: [ScriptValue] = []
            let standing = currentOutcomes(claimID, revision: view.revision, ledger: ledger)
            for entry in view.inventory.callees.prefix(limit) {
                var row = calleeRow(entry.callee, view: view)
                let latest = standing[entry.callee]
                if case .object(var object) = row {
                    object["outcome"] = latest.map {
                        .object([
                            "outcome": .string($0.outcome.rawValue), "reason": .string($0.reason),
                            "bearing": $0.bearing.map { .string($0.rawValue) } ?? .null,
                            "witness": witnessValue($0.witness), "sequence": .int(Int64($0.sequence)),
                        ])
                    } ?? .null
                    row = .object(object)
                }
                all.append(row)
            }
            fields["callees"] = .array(all)
            fields["calleesTruncated"] = .bool(view.inventory.callees.count > limit)
        }
        for (key, value) in extra { fields[key] = value }
        let replyBytes = (try? ScriptValue.object(fields).jsonData().count) ?? 0
        fields["metrics"] = .object(["inventoryMillis": .int(Int64(inventoryMillis)), "replyBytes": .int(Int64(replyBytes))])
        return .object(fields)
    }

    // MARK: - Argument helpers

    private static func claimString(_ arguments: ScriptValue, _ key: String) throws -> String? {
        guard let value = arguments[key], value != .null else { return nil }
        guard let text = value.stringValue else { throw ScriptingError.invalidArgument("\(key) must be a string") }
        return text
    }

    private static func claimFlag(_ arguments: ScriptValue, _ key: String) throws -> Bool {
        guard let value = arguments[key], value != .null else { return false }
        guard let flag = value.boolValue else { throw ScriptingError.invalidArgument("\(key) must be a boolean") }
        return flag
    }

    private static func claimPageLimit(_ arguments: ScriptValue) throws -> Int {
        guard let value = arguments["limit"], value != .null else { return calleeClaimDefaultPageLimit }
        guard let number = value.intValue, (1...100).contains(number) else {
            throw ScriptingError.invalidArgument("limit must be an integer from 1 through 100")
        }
        return Int(number)
    }

    // MARK: - open-claim

    /// `open-claim` on a selector that no longer resolves, i.e. `invalidArgument` (name) or `unknownSubject` (address) (DESIGN 2.4): when exactly one existing claim
    /// matches it (address: bound function and slot; name: the claim's custom display name at its bound
    /// address), classify it with slice A and return the `claimStale` refusal. nil (the caller keeps the
    /// original `invalidArgument`) when no claim, more than one claim, an unparsable selector, or any
    /// classification other than `functionGone`/`imageChanged`. Records no event, with or without
    /// `rebind`/`supersede`.
    private static func goneClaimRefusal(_ arguments: ScriptValue, store: WorkspaceStore) -> ScriptValue? {
        let box = store.calleeClaimLedgerBox
        let views = claimViews(box.ledger)
        guard !views.isEmpty else { return nil }
        let snapshot = store.snapshot
        var slotFilter: Int?
        if let slotValue = arguments["imageSlot"], slotValue != .null {
            guard let slot = slotValue.intValue else { return nil }
            slotFilter = Int(slot)
        }
        let addressValue = arguments["address"].flatMap { $0 == .null ? nil : $0 }
        let functionValue = arguments["function"].flatMap { $0 == .null ? nil : $0 }
        let matches: [(id: UUID, view: ClaimView)]
        switch (addressValue, functionValue) {
        case (let value?, nil):
            guard let address = value.addressValue else { return nil }
            matches = views.filter { entry in
                entry.value.binding.function.rawValue == address
                    && (slotFilter == nil || slotFilter == entry.value.binding.slot)
            }.map { ($0.key, $0.value) }
        case (nil, let value?):
            guard let name = value.stringValue, !name.isEmpty else { return nil }
            matches = views.filter { entry in
                (slotFilter == nil || slotFilter == entry.value.binding.slot)
                    && snapshot.displayName(at: entry.value.binding.function.rawValue,
                                            in: ImageSlot(rawValue: entry.value.binding.slot), default: "") == name
            }.map { ($0.key, $0.value) }
        default:
            return nil
        }
        guard matches.count == 1, let match = matches.first else { return nil }
        var millis = 0
        guard let observed = try? claimObservation(for: match.view, store: store, millis: &millis),
              let classification = try? box.ledger.classify(claimID: match.id, observed: observed),
              classification.kind == .functionGone || classification.kind == .imageChanged else { return nil }
        return staleRefusal(claimID: match.id, view: match.view, classification: classification, store: store,
                            observed: observed)
    }

    private static func openClaim(_ arguments: ScriptValue, store: WorkspaceStore) throws -> ScriptValue {
        let rebind = try claimFlag(arguments, "rebind")
        let supersede = try claimFlag(arguments, "supersede")
        if rebind && supersede {
            return refusal("invalidArguments",
                           "rebind and supersede cannot be combined: rebind keeps the revision and its outcomes, supersede opens the next revision with every callee open",
                           store: store)
        }
        let snapshot = store.snapshot
        let started = nanos()
        let read: CalleeClaimInventorySnapshot
        do {
            read = try calleeClaimInventory(arguments: arguments, snapshot: snapshot, checkpoint: {})
        } catch CalleeClaimInventoryError.inventoryUnavailable(let detail) {
            return refusal("inventoryUnavailable", detail, store: store)
        } catch CalleeClaimInventoryError.digestUnavailable {
            return refusal("inventoryUnavailable", "the inventory digest could not be computed", store: store)
        } catch ScriptingError.invalidArgument(let detail) {
            // The selector no longer resolves. An existing claim for it is classified before this fails.
            if let gone = goneClaimRefusal(arguments, store: store) { return gone }
            throw ScriptingError.invalidArgument(detail)
        } catch ScriptingError.structuredRefusal(let refusal) where refusal.code == .unknownSubject {
            // An address outside every function refuses with unknownSubject (a name raises invalidArgument).
            if let gone = goneClaimRefusal(arguments, store: store) { return gone }
            throw ScriptingError.structuredRefusal(refusal)
        }
        let inventoryMillis = Int((nanos() - started) / 1_000_000)
        let inventory: VACalleeInventory
        do { inventory = try calleeClaimVAInventory(from: read) }
        catch {
            return refusal("inventoryUnavailable", "the inventory could not be validated: \(error)", store: store)
        }
        let slot = ImageSlot(rawValue: read.imageSlot)
        guard let owner = snapshot.binary(in: slot)?.id else {
            return refusal("inventoryUnavailable", "image slot \(read.imageSlot) has no image", store: store)
        }
        let generation = snapshot.analysisGenerationID
        let binding = VACalleeClaimBinding(
            imageOwner: owner, slot: read.imageSlot, function: VAAddress64(read.functionStart),
            analysisGeneration: generation, projectionEpoch: nil, inventoryDigest: inventory.inventoryDigest)
        let observed = VACalleeClaimObservation(imageOwner: owner, generation: generation, inventory: inventory)
        let box = store.calleeClaimLedgerBox
        let existing = claimViews(box.ledger).first {
            $0.value.binding.slot == binding.slot && $0.value.binding.function == binding.function
        }

        var claimID: UUID
        var alreadyOpen = false
        var superseded = false
        var extra: [String: ScriptValue] = [:]
        do {
            if let (id, view) = existing {
                claimID = id
                let classification = try box.ledger.classify(claimID: id, observed: observed)
                if rebind {
                    switch classification.kind {
                    case nil:
                        alreadyOpen = true
                        extra["alreadyCurrent"] = .bool(true)
                    case .generationAdvanced:
                        // An examined outcome survives only while the body behind it is provably the same.
                        // Equal digests keep it; both nil keep it but disclose the gap; any other pair
                        // (changed digest, or exactly one side nil) fails closed and returns it to open.
                        var invalidated: [VAAddress64] = []
                        var notDigestible: [VAAddress64] = []
                        let standing = currentOutcomes(id, revision: view.revision, ledger: box.ledger)
                        for callee in standing.keys.sorted() {
                            guard let record = standing[callee], record.outcome == .examined else { continue }
                            let now = try bodyDigest(of: callee, in: inventory, snapshot: snapshot, slot: binding.slot)
                            switch (record.bodyDigest, now) {
                            case (nil, nil): notDigestible.append(callee)
                            case let (before?, after?) where before == after: break
                            default: invalidated.append(callee)
                            }
                        }
                        let previous = view.binding.analysisGeneration
                        try box.ledger.rebind(claimID: id, observed: observed, invalidatedCallees: invalidated,
                                              atMilliseconds: nowMilliseconds())
                        alreadyOpen = true
                        extra["rebound"] = .bool(true)
                        extra["previousGeneration"] = .string(previous.uuidString)
                        extra["analysisGeneration"] = .string(generation.uuidString)
                        extra["invalidatedCallees"] = .array(invalidated.map { .hex($0.rawValue) })
                        extra["bodyNotDigestible"] = .array(notDigestible.map { .hex($0.rawValue) })
                    default:
                        return staleRefusal(claimID: id, view: view, classification: classification,
                                            store: store, observed: observed)
                    }
                } else if classification.kind != nil, supersede {
                    try box.ledger.supersede(claimID: id, inventory: inventory, binding: binding,
                                             atMilliseconds: nowMilliseconds())
                    superseded = true
                    extra["supersededRevision"] = .int(Int64(view.revision))
                    // Earlier outcomes of callees still present are history, never satisfaction.
                    let present = Set(inventory.callees.map(\.callee)).union(inventory.indirect.map(\.target))
                    var latest: [VAAddress64: VACalleeOutcomeRecord] = [:]
                    for record in try box.ledger.priorOutcomes(claimID: id) where present.contains(record.callee) {
                        if latest[record.callee].map({ $0.sequence < record.sequence }) ?? true {
                            latest[record.callee] = record
                        }
                    }
                    var priorRows: [ScriptValue] = []
                    for callee in latest.keys.sorted() {
                        guard let record = latest[callee] else { continue }
                        let bearingValue: ScriptValue = record.bearing.map { ScriptValue.string($0.rawValue) } ?? .null
                        priorRows.append(.object([
                            "callee": .hex(callee.rawValue), "outcome": .string(record.outcome.rawValue),
                            "reason": .string(record.reason), "bearing": bearingValue,
                            "sequence": .int(Int64(record.sequence)), "revision": .int(Int64(record.revision)),
                            "satisfies": .bool(false),
                        ]))
                    }
                    extra["priorOutcomes"] = .array(priorRows)
                } else {
                    alreadyOpen = true
                    if supersede { extra["supersede"] = .string("notNeeded: the claim is current") }
                }
            } else {
                if rebind {
                    return refusal("unknownClaim", "no claim exists for this function, so there is nothing to rebind; open-claim without rebind opens it",
                                   store: store)
                }
                claimID = UUID()
                try box.ledger.open(claimID: claimID, inventory: inventory, binding: binding,
                                    atMilliseconds: nowMilliseconds())
            }
        } catch VACalleeClaimError.claimLimit {
            return claimLimitRefusal("the ledger holds the maximum of \(VACalleeClaimLimits.maximumClaims) claims",
                                     store: store, ledger: box.ledger)
        } catch VACalleeClaimError.eventLimit {
            return claimLimitRefusal("the ledger holds the maximum of \(VACalleeClaimLimits.maximumEvents) events",
                                     store: store, ledger: box.ledger)
        } catch VACalleeClaimError.inventoryUnavailable {
            return refusal("inventoryUnavailable", "the inventory is not complete", store: store)
        }
        extra["alreadyOpen"] = .bool(alreadyOpen)
        extra["superseded"] = .bool(superseded)
        guard let view = claimViews(box.ledger)[claimID],
              let report = try? box.ledger.report(claimID: claimID, observed: observed) else {
            return refusal("unknownClaim", "the claim could not be read back", store: store)
        }
        return claimReply(claimID: claimID, report: report, view: view, ledger: box.ledger, store: store,
                          limit: calleeClaimDefaultPageLimit, inventoryMillis: inventoryMillis,
                          observed: observed, extra: extra)
    }

    // MARK: - record-callee-outcome

    private enum CalleeResolution {
        case found(VAAddress64)
        case ambiguous([VAAddress64])
        case notFound([String])
    }

    private static func resolveClaimCallee(_ value: ScriptValue, view: ClaimView) -> CalleeResolution {
        var known = Set(view.inventory.callees.map(\.callee)).union(view.inventory.indirect.map(\.target))
        if let address = value.addressValue, known.contains(VAAddress64(address)) {
            return .found(VAAddress64(address))
        }
        known.removeAll()
        guard let text = value.stringValue else { return .notFound([]) }
        var named: [(VAAddress64, String)] = view.inventory.callees.compactMap { entry in entry.name.map { (entry.callee, $0) } }
        named += view.inventory.indirect.compactMap { entry in entry.targetName.map { (entry.target, $0) } }
        let exact = Set(named.filter { $0.1 == text }.map(\.0)).sorted()
        if exact.count == 1 { return .found(exact[0]) }
        if exact.count > 1 { return .ambiguous(exact) }
        let needle = text.lowercased()
        let close = Set(named.map(\.1).filter { !needle.isEmpty && $0.lowercased().contains(needle) }).sorted()
        return .notFound(Array(close.prefix(5)))
    }

    private static func recordCalleeOutcome(_ arguments: ScriptValue, store: WorkspaceStore) throws -> ScriptValue {
        let box = store.calleeClaimLedgerBox
        guard let claimText = try claimString(arguments, "claim") else { throw ScriptingError.missingArgument("claim") }
        guard let calleeValue = arguments["callee"], calleeValue != .null else { throw ScriptingError.missingArgument("callee") }
        guard let outcomeText = try claimString(arguments, "outcome") else { throw ScriptingError.missingArgument("outcome") }
        guard let claimID = UUID(uuidString: claimText), let view = claimViews(box.ledger)[claimID] else {
            return refusal("unknownClaim", "no claim has the identifier '\(claimText.prefix(64))'", store: store)
        }

        // Staleness first, exactly as slice A orders it.
        var millis = 0
        let observed = try claimObservation(for: view, store: store, millis: &millis)
        let classification = try box.ledger.classify(claimID: claimID, observed: observed)
        if classification.kind != nil {
            return staleRefusal(claimID: claimID, view: view, classification: classification, store: store,
                                observed: observed)
        }

        guard let outcome = VACalleeOutcomeKind(rawValue: outcomeText) else {
            return refusal("outcomeInvalid", "outcome must be examined, irrelevant or deferred", store: store,
                           ["allowed": .array(VACalleeOutcomeKind.allCases.map { .string($0.rawValue) })])
        }
        guard let reason = try claimString(arguments, "reason") else {
            return refusal("outcomeInvalid", "reason is required (1...2048 bytes)", store: store)
        }
        var bearing: VACalleeBearing?
        if let bearingText = try claimString(arguments, "bearing") {
            guard let parsed = VACalleeBearing(rawValue: bearingText) else {
                return refusal("outcomeInvalid", "bearing must be supports, contradicts or neutral", store: store,
                               ["allowed": .array(VACalleeBearing.allCases.map { .string($0.rawValue) })])
            }
            bearing = parsed
        }
        let callee: VAAddress64
        switch resolveClaimCallee(calleeValue, view: view) {
        case .found(let address): callee = address
        case .ambiguous(let addresses):
            return refusal("calleeNotInClaim", "the name matches \(addresses.count) callees of the claim; pass the address",
                           store: store, ["claim": .string(claimID.uuidString),
                                          "candidates": .array(addresses.map { .hex($0.rawValue) })])
        case .notFound(let close):
            return refusal("calleeNotInClaim", "the callee is not in the claim's own list", store: store,
                           ["claim": .string(claimID.uuidString), "closest": .array(close.map { .string($0) })])
        }

        // Only examined outcomes carry a body digest, computed now from the current snapshot. The claim is
        // current here, so the stored inventory types the callee exactly as a rescan would.
        var calleeDigest: String?
        var witness: VACalleeWitnessSummary?
        if outcome == .examined {
            let generation = store.snapshot.analysisGenerationID
            guard let entry = box.readWitnesses.latest(imageSlot: view.binding.slot, functionStart: callee.rawValue,
                                                       generation: generation) else {
                return refusal("examinedWithoutWitness",
                               "examined needs a read of the callee's code in this session at the current generation",
                               store: store,
                               ["claim": .string(claimID.uuidString), "callee": .hex(callee.rawValue),
                                "hint": .string("Read the callee with instructions (by function), decompile, basic-blocks or function-facts, then record again. callees, callers, call-graph and xrefs do not count, and a witness is lost when the analysis generation changes, the log overflows or the app restarts."),
                                "witnessingCommands": .array(CalleeReadWitnessLog.witnessingCommands.map { .string($0) })])
            }
            witness = VACalleeWitnessSummary(command: entry.command, generation: entry.generation,
                                             sequence: entry.sequence)
            calleeDigest = try bodyDigest(of: callee, in: view.inventory, snapshot: store.snapshot,
                                          slot: view.binding.slot)
        }
        do {
            try box.ledger.recordOutcome(claimID: claimID, callee: callee, outcome: outcome, reason: reason,
                                         bearing: bearing, bodyDigest: calleeDigest, witness: witness, observed: observed,
                                         atMilliseconds: nowMilliseconds())
        } catch let error as VACalleeClaimError {
            switch error {
            case .outcomeInvalid(let detail): return refusal("outcomeInvalid", detail, store: store)
            case .calleeNotInClaim: return refusal("calleeNotInClaim", "the callee is not in the claim's own list", store: store)
            case .unknownClaim: return refusal("unknownClaim", "the claim does not exist", store: store)
            case .claimStale:
                return staleRefusal(claimID: claimID, view: view, classification: classification, store: store,
                                    observed: observed)
            case .eventLimit, .claimLimit:
                return claimLimitRefusal("the ledger holds the maximum of \(VACalleeClaimLimits.maximumEvents) events",
                                         store: store, ledger: box.ledger)
            default: throw error
            }
        }
        guard let report = try? box.ledger.report(claimID: claimID, observed: observed) else {
            return refusal("unknownClaim", "the claim could not be read back", store: store)
        }
        var recorded: [String: ScriptValue] = [
            "callee": .hex(callee.rawValue), "outcome": .string(outcome.rawValue), "reason": .string(reason),
            "bearing": bearing.map { .string($0.rawValue) } ?? .null, "witness": witnessValue(witness),
            "bodyDigest": calleeDigest.map { ScriptValue.string($0) } ?? .null,
        ]
        if let sequence = box.ledger.events.last?.sequence { recorded["sequence"] = .int(Int64(sequence)) }
        let extra: [String: ScriptValue] = ["recorded": .object(recorded)]
        return claimReply(claimID: claimID, report: report, view: view, ledger: box.ledger, store: store,
                          limit: calleeClaimDefaultPageLimit, inventoryMillis: millis, observed: observed, extra: extra)
    }

    private static func witnessValue(_ witness: VACalleeWitnessSummary?) -> ScriptValue {
        guard let witness else { return .null }
        return .object(["command": .string(witness.command), "generation": .string(witness.generation.uuidString),
                        "sequence": .int(Int64(witness.sequence))])
    }

    // MARK: - read witness

    /// Appends one witness for a SUCCESSFUL read of `instructions` (function-selected), `decompile`,
    /// `basic-blocks` or `function-facts`, for the function the read resolved, in the slot that answered.
    /// `snapshot` is the one the read was admitted on, so its generation is the generation read.
    /// Nothing else witnesses, and a refused read (thrown, or an error reply) never reaches this point
    /// with a usable function: resolution failure appends nothing.
    func recordReadWitness(command: String, arguments: ScriptValue, result: ScriptValue, snapshot: WorkspaceSnapshot) {
        guard CalleeReadWitnessLog.witnessingCommands.contains(command) else { return }
        if case .object(let fields) = result, fields["error"] != nil || fields["ok"] == .bool(false) { return }
        let slot: ImageSlot
        let function: FunctionSummary
        do {
            switch command {
            case "instructions":
                guard arguments["function"]?.stringValue != nil else { return }
                slot = snapshot.primarySlot
                function = try Self.resolveFunction(arguments, snapshot)
            case "basic-blocks":
                slot = snapshot.primarySlot
                function = try Self.resolveFunction(arguments, snapshot)
            case "function-facts":
                let filter = try Self.resolveImageSlotFilter(arguments, snapshot: snapshot)
                let view = filter.map { Self.imageProjection(of: snapshot, in: $0) } ?? snapshot
                slot = filter ?? view.primarySlot
                function = try Self.resolveFunction(arguments, view)
            default: // decompile
                slot = try Self.resolveImageSlot(arguments, snapshot: snapshot)
                function = try Self.resolveFunction(arguments, Self.imageProjection(of: snapshot, in: slot))
            }
        } catch {
            return
        }
        store.calleeClaimLedgerBox.readWitnesses.append(
            imageSlot: slot.rawValue, functionStart: function.startAddress, command: command,
            generation: snapshot.analysisGenerationID)
    }

    // MARK: - claim-status

    private static func claimStatus(_ arguments: ScriptValue, store: WorkspaceStore) throws -> ScriptValue {
        let limit = try claimPageLimit(arguments)
        let state = try claimString(arguments, "state") ?? "open"
        guard ["open", "closed", "stale", "all"].contains(state) else {
            throw ScriptingError.invalidArgument("state must be open, closed, stale or all")
        }
        let detail = try claimString(arguments, "detail") ?? "open"
        guard ["open", "all"].contains(detail) else {
            throw ScriptingError.invalidArgument("detail must be open or all")
        }
        let box = store.calleeClaimLedgerBox
        let ledger = box.ledger
        let views = claimViews(ledger)
        var selected: UUID?

        if let claimText = try claimString(arguments, "claim") {
            guard let id = UUID(uuidString: claimText), views[id] != nil else {
                return refusal("unknownClaim", "no claim has the identifier '\(claimText.prefix(64))'", store: store)
            }
            selected = id
        } else if arguments["function"].map({ $0 != .null }) ?? false || arguments["address"].map({ $0 != .null }) ?? false {
            let snapshot = store.snapshot
            let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
            let slots = filter.map { [$0.rawValue] } ?? Set(views.values.map(\.binding.slot)).sorted()
            var matches: [(slot: Int, id: UUID)] = []
            var firstError: Error?
            var resolvedAny = false
            for slot in slots {
                let projected = imageProjection(of: snapshot, in: ImageSlot(rawValue: slot))
                do {
                    let function = try boundedSnapshotFunction(arguments, snapshot: projected, checkpoint: {})
                    resolvedAny = true
                    for (id, view) in views where view.binding.slot == slot && view.binding.function.rawValue == function.startAddress {
                        matches.append((slot, id))
                    }
                } catch {
                    if filter != nil { throw error }
                    firstError = firstError ?? error
                }
            }
            if !resolvedAny, !slots.isEmpty, let firstError { throw firstError }
            if matches.count > 1 {
                return refusal("claimAmbiguous", "the function has a claim in \(matches.count) images; pass imageSlot",
                               store: store, ["imageSlots": .array(matches.map { .int(Int64($0.slot)) }.sorted {
                                   ($0.intValue ?? 0) < ($1.intValue ?? 0)
                               })])
            }
            selected = matches.first?.id
            if selected == nil {
                return .object(["ok": .bool(true), "durability": .string(store.calleeClaimDurability.rawValue),
                                "generation": .string(snapshot.analysisGenerationID.uuidString),
                                "claims": .array([]), "total": .int(0), "truncated": .bool(false),
                                "scope": .string(calleeClaimScope)])
            }
        }

        if let id = selected, let view = views[id] {
            var millis = 0
            let observed = try claimObservation(for: view, store: store, millis: &millis)
            let report = try ledger.report(claimID: id, observed: observed)
            return claimReply(claimID: id, report: report, view: view, ledger: ledger, store: store, limit: limit,
                              includeAllCallees: detail == "all", inventoryMillis: millis, observed: observed)
        }

        // No selector: claims whose status matches `state`.
        var millis = 0
        var summaries: [ScriptValue] = []
        var total = 0
        for id in ledger.claimIDs {
            guard let view = views[id] else { continue }
            let observed = try claimObservation(for: view, store: store, millis: &millis)
            let report = try ledger.report(claimID: id, observed: observed)
            guard state == "all" || report.status.rawValue == state else { continue }
            total += 1
            if summaries.count < limit {
                summaries.append(.object([
                    "claim": .string(id.uuidString), "revision": .int(Int64(report.revision)),
                    "function": .hex(view.binding.function.rawValue), "imageSlot": .int(Int64(view.binding.slot)),
                    "status": .string(report.status.rawValue),
                    "staleKind": report.staleKind.map { .string($0.rawValue) } ?? .null,
                    "rebindable": .bool(report.rebindable),
                    "open": .int(Int64(report.coverage.open)), "required": .int(Int64(report.coverage.required)),
                    "closedWithDeferrals": .bool(report.closedWithDeferrals),
                ]))
            }
        }
        var fields: [String: ScriptValue] = [
            "ok": .bool(true), "durability": .string(store.calleeClaimDurability.rawValue),
            "generation": .string(store.snapshot.analysisGenerationID.uuidString),
            "state": .string(state), "claims": .array(summaries), "total": .int(Int64(total)),
            "truncated": .bool(total > summaries.count), "scope": .string(calleeClaimScope),
            "limitations": .array([]),
        ]
        let bytes = (try? ScriptValue.object(fields).jsonData().count) ?? 0
        fields["metrics"] = .object(["inventoryMillis": .int(Int64(millis)), "replyBytes": .int(Int64(bytes))])
        return .object(fields)
    }
}
