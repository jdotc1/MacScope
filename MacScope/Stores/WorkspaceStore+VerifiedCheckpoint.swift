import Foundation

/// VA4 slice C: read-only views of a store for the fresh-reader checkpoint. Everything here reads
/// members that are already visible outside WorkspaceStore.swift; nothing mutates the store.
extension WorkspaceStore {
    /// This store as a reader: its (freshly minted) document installation and the calling process.
    func verifiedCheckpointReader(executable: String = Bundle.main.executableURL?.path ?? "unknown")
        -> VerifiedCheckpointReaderIdentity {
        VerifiedCheckpointReaderIdentity(installationID: documentInstallationID,
                                         processID: ProcessInfo.processInfo.processIdentifier,
                                         executable: executable)
    }

    /// The store's current annotation state as a checkpoint subject. Pass the journal report from
    /// `attachEditJournal` and the operation ids the saved package held before that attach to get
    /// the journal tier; omit both to judge the store as a plain restore.
    func verifiedCheckpointSubject(journal: EditJournalReport? = nil,
                                   savedOperationIDs: Set<UUID> = []) -> VerifiedCheckpointSubject {
        let facts = journal.map {
            VerifiedCheckpointJournalFacts(
                replayed: $0.replayed, alreadyApplied: $0.alreadyApplied,
                tornTailBytes: $0.tornTail.map { Int($0.length) },
                unattachedAuditRecords: $0.unattachedAuditRecords, savedOperationIDs: savedOperationIDs)
        }
        return VerifiedCheckpointSubject(
            workspaceID: workspaceID, documentID: documentID,
            audit: verifiedAnnotationAudit.isEmpty ? nil : verifiedAnnotationAudit,
            snapshot: snapshot, journal: facts)
    }

    /// Judge this store against an expectation.
    func verifiedCheckpoint(_ expectation: VerifiedCheckpointExpectation, journal: EditJournalReport? = nil,
                            savedOperationIDs: Set<UUID> = []) -> VerifiedCheckpointReport {
        VerifiedCheckpoint.check(subject: verifiedCheckpointSubject(journal: journal, savedOperationIDs: savedOperationIDs),
                                 expectation: expectation, reader: verifiedCheckpointReader())
    }
}
