import Foundation

/// An inert exact selector, not a command registration or transport authorization.
/// ownerGeneration is live-ledger authority only in the controller, never in a snapshot alone.
struct ExactClassReadSelector: Sendable {
    let owner: Phase2ReadImageOwner
    let entryID: TypeAtlasEntryID
}

enum ExactClassReadFailure: Error, Equatable, Sendable {
    case unsupportedKind, invalidSelector, unresolvedOwner, analysisUnavailable
    case ambiguousEntry, incompleteCatalog, limitExceeded, deadlineExceeded, staleSource
}

/// Limits can only tighten the app-owned maxima. Existing catalog/nested preflight is also
/// applied independently; these limits cannot enlarge AttachedTypeReadBudget.
struct ExactClassReadLimits: Sendable {
    var selectorUTF8Bytes = 1_024
    var imageRows = 256
    var searchRows = 4_096
    var projectionNodes = 16_384
    var projectionUTF8Bytes = 262_144
    var encodedBytes = 1_048_576
    var duration: Duration = .seconds(10)

    fileprivate func validate() throws {
        guard (1...1_024).contains(selectorUTF8Bytes), (1...256).contains(imageRows),
              (1...4_096).contains(searchRows), (1...16_384).contains(projectionNodes),
              (1...262_144).contains(projectionUTF8Bytes), (1...1_048_576).contains(encodedBytes),
              duration > .zero, duration <= .seconds(10) else {
            throw ExactClassReadFailure.limitExceeded
        }
    }
}

extension WorkspaceScriptingAPI {
    /// Pure bounded source projection. This does not mint accepted evidence or grant a callable
    /// operation. App owners must retain the original admission and publish through the controller.
    /// WorkspaceSnapshot does not contain the live owner generation or session lifecycle; matching
    /// its binary fields is membership validation only, never a freshness/authorization decision.
    nonisolated static func exactClassRead(
        selector: ExactClassReadSelector, snapshot: WorkspaceSnapshot,
        limits: ExactClassReadLimits = .init(),
        checkpoint: () throws -> Void = {},
        now: () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) throws -> ScriptValue {
        let started = now()
        try limits.validate()
        let deadline = started.advanced(by: limits.duration)
        func check() throws {
            try Task.checkCancellation()
            try checkpoint()
            guard now() < deadline else { throw ExactClassReadFailure.deadlineExceeded }
        }
        try check()
        guard selector.entryID.kind == .objcClass || selector.entryID.kind == .swiftClass else {
            throw ExactClassReadFailure.unsupportedKind
        }
        guard selector.entryID.slot == selector.owner.slot,
              selector.owner.architecture.utf8.prefix(limits.selectorUTF8Bytes + 1).count <= limits.selectorUTF8Bytes else {
            throw ExactClassReadFailure.invalidSelector
        }
        if case .name(let name) = selector.entryID.key {
            guard !name.isEmpty,
                  name.utf8.prefix(limits.selectorUTF8Bytes + 1).count <= limits.selectorUTF8Bytes else {
                throw ExactClassReadFailure.invalidSelector
            }
        }
        guard snapshot.binaries.count <= limits.imageRows else { throw ExactClassReadFailure.limitExceeded }
        var slotMatches = 0
        var ownerMatches = 0
        for binary in snapshot.binaries {
            try check()
            if binary.id == selector.owner.binaryID { ownerMatches += 1 }
            if binary.slot == selector.owner.slot {
                slotMatches += 1
                guard binary.id == selector.owner.binaryID,
                      binary.architecture == selector.owner.architecture,
                      binary.selectedSliceIndex == selector.owner.sliceIndex else {
                    throw ExactClassReadFailure.unresolvedOwner
                }
            }
        }
        guard slotMatches == 1, ownerMatches == 1 else { throw ExactClassReadFailure.unresolvedOwner }
        guard snapshot.analysis(in: selector.owner.slot) != nil else { throw ExactClassReadFailure.analysisUnavailable }

        // Reuse the existing bounded cached/uncached catalog construction and nested preflight,
        // including its one-million-work ceiling. It projects via typeAtlasEntryValue unchanged.
        // Its 4,096-node catalog ceiling is below this 5,000-row request. Nevertheless verify
        // completeness explicitly: a later change to list caps must never create false absence.
        let list = try snapshotTypeListRead("list-image-types", arguments: .object([
            "image": .int(Int64(selector.owner.slot.rawValue)), "limit": .int(5_000)
        ]), snapshot: snapshot, checkpoint: check, swiftObjCLinks: false, mode: .internalComplete)
        guard let rows = list["types"]?.arrayValue,
              let total = list["total"]?.intValue, total == Int64(rows.count) else {
            throw ExactClassReadFailure.incompleteCatalog
        }
        guard rows.count <= limits.searchRows else { throw ExactClassReadFailure.limitExceeded }
        var identity: [String: ScriptValue] = ["slot": .int(Int64(selector.entryID.slot.rawValue)),
                                               "kind": .string(selector.entryID.kind.rawValue)]
        switch selector.entryID.key {
        case .address(let address): identity["address"] = .hex(address)
        case .name(let name): identity["name"] = .string(name)
        }
        var selected: ScriptValue?
        for row in rows {
            try check()
            guard let rowKind = row["kind"]?.stringValue, TypeAtlasKind(rawValue: rowKind) != nil,
                  row["id"]?["kind"] == .string(rowKind),
                  row["id"]?["slot"] == .int(Int64(selector.owner.slot.rawValue)) else {
                throw ExactClassReadFailure.incompleteCatalog
            }
            if row["id"] == .object(identity) {
                guard selected == nil else { throw ExactClassReadFailure.ambiguousEntry }
                selected = row
            }
        }
        var fields = imageProvenanceFields(slot: selector.owner.slot, snapshot: snapshot)
        fields["status"] = .string(selected == nil ? "notFoundInCurrentCatalog" : "found")
        fields["class"] = selected ?? .null
        fields["selector"] = .object(identity)
        let result = ScriptValue.object(fields)
        var nodes = limits.projectionNodes
        var bytes = limits.projectionUTF8Bytes
        func text(_ value: String) throws {
            let count = value.utf8.prefix(bytes + 1).count
            guard count <= bytes else { throw ExactClassReadFailure.limitExceeded }
            bytes -= count
        }
        func visit(_ value: ScriptValue, depth: Int) throws {
            try check()
            guard nodes > 0, depth <= 32 else { throw ExactClassReadFailure.limitExceeded }
            nodes -= 1
            switch value {
            case .string(let string): try text(string)
            case .array(let values): for child in values { try visit(child, depth: depth + 1) }
            case .object(let values):
                for (key, child) in values { try text(key); try visit(child, depth: depth + 1) }
            default: break
            }
        }
        try visit(result, depth: 0)
        try check()
        // The independently prebounded value graph bounds encoding allocation. The exact cap
        // includes the complete status/selector/provenance wrapper, not only the selected row.
        guard try result.jsonData().count <= limits.encodedBytes else { throw ExactClassReadFailure.limitExceeded }
        try check()
        return result
    }
}

/// Internal app-owned seam only. No v1, scripting, headless or attached operation is registered.
/// The original source admission is retained for both found and not-found results. Full current
/// state equality additionally rejects workspace/user-authoring changes before delivery.
@MainActor
final class ExactClassReadController {
    struct Prepared: Sendable {
        fileprivate let controllerID: UUID
        fileprivate let state: Phase2ReadCurrentState
        fileprivate let envelope: NEWFEATURESResultEnvelope<ScriptValue>
        fileprivate let deadline: ContinuousClock.Instant
    }
    private let id = UUID()
    private weak var store: WorkspaceStore?
    private let bridge: NEWFEATURESAdmissionBridge

    init(store: WorkspaceStore, session: WorkspaceDocumentSession) {
        self.store = store
        self.bridge = NEWFEATURESAdmissionBridge(store: store, session: session)
    }

    func prepare(selector: ExactClassReadSelector, limits: ExactClassReadLimits = .init()) throws -> Prepared {
        let started = ContinuousClock.now
        try limits.validate()
        let deadline = started.advanced(by: limits.duration)
        try Task.checkCancellation()
        guard let store else { throw ExactClassReadFailure.staleSource }
        let state = store.phase2ReadCurrentState(for: selector.owner.slot)
        guard state.image?.owner == selector.owner else { throw ExactClassReadFailure.unresolvedOwner }
        let admission = try bridge.admit(slot: selector.owner.slot)
        let snapshot = store.snapshot
        let value = try WorkspaceScriptingAPI.exactClassRead(selector: selector, snapshot: snapshot, limits: limits,
            checkpoint: {
                guard ContinuousClock.now < deadline else { throw ExactClassReadFailure.deadlineExceeded }
            })
        return Prepared(controllerID: id, state: state, envelope: admission.retaining(value), deadline: deadline)
    }

    /// Synchronous final handoff only; a caller that queues/defer-delivers must invoke this at
    /// the actual delivery boundary, not cache a successful check. No transport grant is minted.
    func publish(_ prepared: Prepared, to sink: (ScriptValue) throws -> Void) throws {
        try Task.checkCancellation()
        guard ContinuousClock.now < prepared.deadline else { throw ExactClassReadFailure.deadlineExceeded }
        guard prepared.controllerID == id, let store,
              store.phase2ReadCurrentState(for: prepared.state.image?.slot) == prepared.state else {
            throw ExactClassReadFailure.staleSource
        }
        try bridge.publish(prepared.envelope) { value in
            // Include live revalidation work in the deadline, and check cancellation again at
            // the actual synchronous sink. No cached freshness Boolean escapes this boundary.
            try Task.checkCancellation()
            guard ContinuousClock.now < prepared.deadline else {
                throw ExactClassReadFailure.deadlineExceeded
            }
            try sink(value)
        }
    }
}
