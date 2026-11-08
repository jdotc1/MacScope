import Foundation

/// A persistence acknowledgement describes the entire live ledger, not merely its last event.
enum CalleeClaimDurability: String { case session, journal, package }
enum CalleeClaimAttachmentState: String { case attached, detached }

enum CalleeClaimPersistenceError: LocalizedError, Equatable {
    case conflictingHistory
    case nonAppendMutation
    case journalUnavailable
    case journalIdentityMismatch
    case appendNotSynchronized

    var errorDescription: String? {
        switch self {
        case .conflictingHistory: return "callee-claim-history-conflict"
        case .nonAppendMutation: return "callee-claim-non-append-mutation"
        case .journalUnavailable: return "callee-claim-journal-unavailable"
        case .journalIdentityMismatch: return "callee-claim-journal-identity-mismatch"
        case .appendNotSynchronized: return "callee-claim-append-not-synchronized"
        }
    }
}

/// The existing command layer mutates this value in place. Swift writeback invokes didSet,
/// covering open, outcome, rebind and supersede without changing that layer's API.
@MainActor
final class CalleeClaimLedgerBox {
    var ledger = CalleeClaimLedger() {
        didSet {
            guard !installing, ledger != oldValue else { return }
            changed?(oldValue)
        }
    }
    var readWitnesses = CalleeReadWitnessLog()
    var changed: ((CalleeClaimLedger) -> Void)?
    var packageEvents: [VACalleeClaimEvent]?
    var journalEvents: [VACalleeClaimEvent]?
    var journalIdentity: ObjectIdentifier?
    var persistenceIssue: String?
    private var installing = false

    func install(_ value: CalleeClaimLedger) {
        installing = true
        ledger = value
        installing = false
    }
}

@MainActor
private let calleeClaimLedgerBoxes = NSMapTable<WorkspaceStore, CalleeClaimLedgerBox>.weakToStrongObjects()

extension WorkspaceStore {
    var calleeClaimLedgerBox: CalleeClaimLedgerBox {
        if let box = calleeClaimLedgerBoxes.object(forKey: self) { return box }
        let box = CalleeClaimLedgerBox()
        box.changed = { [weak self] previous in self?.calleeClaimsDidChange(from: previous) }
        calleeClaimLedgerBoxes.setObject(box, forKey: self)
        return box
    }

    var calleeClaimLedger: CalleeClaimLedger { calleeClaimLedgerBox.ledger }

    var calleeClaimDurability: CalleeClaimDurability {
        let box = calleeClaimLedgerBox
        guard !box.ledger.events.isEmpty else { return .session }
        if box.packageEvents == box.ledger.events { return .package }
        if box.journalEvents == box.ledger.events { return .journal }
        return .session
    }

    var calleeClaimPersistenceIssue: String? { calleeClaimLedgerBox.persistenceIssue }

    /// A store-side load state, not a new Core status. Bindings and outcomes are not rewritten.
    /// Core already classifies another/missing owner as imageChanged, non-rebindable.
    func calleeClaimAttachmentState(claimID: UUID) -> CalleeClaimAttachmentState {
        guard let binding = calleeClaimLedger.events.reversed().first(where: {
            $0.claimID == claimID && $0.binding != nil
        })?.binding else { return .detached }
        return snapshot.binary(in: ImageSlot(rawValue: binding.slot))?.id == binding.imageOwner
            ? .attached : .detached
    }

    func resetCalleeClaims() {
        // A box is installation-owned. Old command references cannot journal into a new install.
        if let previous = calleeClaimLedgerBoxes.object(forKey: self) {
            previous.changed = nil
            // Reusing a v2 writer after installing an earlier package would append a second
            // claim sequence 1 to its old history. Retain its file, but require explicit attach.
            if !previous.ledger.events.isEmpty { detachEditJournal()?.close() }
        }
        calleeClaimLedgerBoxes.removeObject(forKey: self)
    }

    func persistableCalleeClaims() throws -> CalleeClaimEnvelope? {
        let ledger = calleeClaimLedger
        guard !ledger.events.isEmpty else { return nil }
        return try CalleeClaimEnvelope(ledger: ledger)
    }

    func installRestoredCalleeClaims(_ ledger: CalleeClaimLedger) {
        let box = calleeClaimLedgerBox
        box.install(ledger)
        box.packageEvents = ledger.events
        box.journalEvents = nil
        box.journalIdentity = nil
        box.persistenceIssue = nil
    }

    /// Called after publication acknowledgement, never at capture. Exact equality above keeps
    /// changes newer than an asynchronous save's capture session-only until synchronized.
    func acknowledgeSavedCalleeClaims(_ events: [VACalleeClaimEvent]) {
        calleeClaimLedgerBox.packageEvents = events
    }

    private func calleeClaimsDidChange(from previous: CalleeClaimLedger) {
        let box = calleeClaimLedgerBox
        markDocumentMutated()
        guard box.ledger.events.starts(with: previous.events) else {
            box.persistenceIssue = CalleeClaimPersistenceError.nonAppendMutation.localizedDescription
            box.journalEvents = nil
            return
        }
        synchronizeCalleeClaims()
    }

    /// Full-prefix synchronization also covers attaching after session-only edits. An uncertain
    /// append leaves the event in memory and does not advance the acknowledged prefix.
    func synchronizeCalleeClaims() {
        let box = calleeClaimLedgerBox
        guard !box.ledger.events.isEmpty, let writer = editJournal else { return }
        guard writer.observedHealth == .healthy else {
            box.persistenceIssue = CalleeClaimPersistenceError.journalUnavailable.localizedDescription
            return
        }
        guard writer.imageIdentities == EditJournalImageIdentity.capture(snapshot) else {
            box.persistenceIssue = CalleeClaimPersistenceError.journalIdentityMismatch.localizedDescription
            return
        }
        if box.journalIdentity != ObjectIdentifier(writer) {
            box.journalEvents = []
            box.journalIdentity = ObjectIdentifier(writer)
        }
        var acknowledged = box.journalEvents ?? []
        guard box.ledger.events.starts(with: acknowledged) else {
            box.persistenceIssue = CalleeClaimPersistenceError.conflictingHistory.localizedDescription
            return
        }
        for event in box.ledger.events.dropFirst(acknowledged.count) {
            writer.appendCalleeClaim(event, priorEvents: acknowledged)
            guard writer.observedHealth == .healthy,
                  case .calleeClaim(_, let written)? = writer.lastAppendedRecord,
                  written == event else {
                box.persistenceIssue = CalleeClaimPersistenceError.appendNotSynchronized.localizedDescription
                return
            }
            acknowledged.append(event)
            box.journalEvents = acknowledged
        }
        box.persistenceIssue = nil
    }

    /// Journal histories contain a whole claim prefix despite interleaved override/audit lines.
    /// Equal overlap is idempotent; divergent same-sequence events refuse before any mutation.
    func mergingJournalCalleeClaims(_ records: [EditJournalRecord]) throws -> CalleeClaimLedger {
        var events = calleeClaimLedger.events
        let journalEvents = records.compactMap { record -> VACalleeClaimEvent? in
            if case .calleeClaim(_, let event) = record { return event }
            return nil
        }
        _ = try CalleeClaimLedger(events: journalEvents)
        for event in journalEvents {
            if event.sequence <= UInt64(events.count) {
                guard events[Int(event.sequence) - 1] == event else {
                    throw CalleeClaimPersistenceError.conflictingHistory
                }
            } else {
                guard event.sequence == UInt64(events.count + 1) else {
                    throw CalleeClaimPersistenceError.conflictingHistory
                }
                events.append(event)
            }
        }
        return try CalleeClaimLedger(events: events)
    }

    func installJournalCalleeClaims(_ ledger: CalleeClaimLedger, records: [EditJournalRecord],
                                   writer: EditJournalWriter) {
        let box = calleeClaimLedgerBox
        let changed = box.ledger != ledger
        box.install(ledger)
        let recoveredEvents = records.compactMap { record -> VACalleeClaimEvent? in
            if case .calleeClaim(_, let event) = record { return event }
            return nil
        }
        box.journalEvents = nil
        box.journalIdentity = ObjectIdentifier(writer)
        box.persistenceIssue = nil
        if changed { markDocumentMutated() }
        if !recoveredEvents.isEmpty, !writer.synchronizeRecoveredCalleeClaims() {
            box.persistenceIssue = CalleeClaimPersistenceError.appendNotSynchronized.localizedDescription
            return
        }
        box.journalEvents = recoveredEvents
        synchronizeCalleeClaims()
    }

    func acknowledgeRotatedCalleeClaims(_ writer: EditJournalWriter) {
        guard writer.observedHealth == .healthy else { return }
        let box = calleeClaimLedgerBox
        box.journalEvents = box.ledger.events
        box.journalIdentity = ObjectIdentifier(writer)
        box.persistenceIssue = nil
    }
}
