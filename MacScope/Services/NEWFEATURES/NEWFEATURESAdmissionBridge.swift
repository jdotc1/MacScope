import Foundation
import NEWFEATURESCore

enum NEWFEATURESAdmissionFailure: Error, Equatable, Sendable {
    case analysisRequired
    case sourceIdentityUnavailable
    case staleSource
    case documentClosed
    case ambiguousFunction
    case functionNotFound
    case inputLimitExceeded
}

/// App-only authority; not Codable and not constructible from a worker's projection.
struct NEWFEATURESAppAdmission: Sendable {
    let projection: NEWFEATURESLedgerAdmission
    fileprivate let precondition: Phase2ReadPrecondition
    fileprivate let sessionID: WorkspaceDocumentSessionID

    fileprivate init(projection: NEWFEATURESLedgerAdmission,
                     precondition: Phase2ReadPrecondition,
                     sessionID: WorkspaceDocumentSessionID) {
        self.projection = projection
        self.precondition = precondition
        self.sessionID = sessionID
    }

    /// Positive, negative and partial results all retain the same original authority.
    func retaining<Result: Sendable>(_ result: Result) -> NEWFEATURESResultEnvelope<Result> {
        NEWFEATURESResultEnvelope(admission: self, result: result)
    }
}

struct NEWFEATURESResultEnvelope<Result: Sendable>: Sendable {
    fileprivate let admission: NEWFEATURESAppAdmission
    fileprivate let result: Result

    fileprivate init(admission: NEWFEATURESAppAdmission, result: Result) {
        self.admission = admission
        self.result = result
    }
}

/// Pure mapping of already retained analysis identity. No disk reads or digest work.
enum NEWFEATURESIdentityProjection {
    static func make(current: Phase2ReadCurrentState,
                     fingerprint: AnalysisInputFingerprint?) throws -> NEWFEATURESImageKey {
        guard let image = current.image else {
            throw NEWFEATURESAdmissionFailure.sourceIdentityUnavailable
        }
        guard let fingerprint else { throw NEWFEATURESAdmissionFailure.analysisRequired }
        guard fingerprint.imageSlot == image.slot,
              fingerprint.binaryID == image.binaryID,
              fingerprint.selectedSliceIndex == image.sliceIndex,
              fingerprint.overallSHA256 == image.analysisFingerprintSHA256 else {
            throw NEWFEATURESAdmissionFailure.sourceIdentityUnavailable
        }
        do {
            return try NEWFEATURESImageKey(
                documentInstance: current.workspace.document.instanceID,
                workspaceInstance: current.workspace.instanceID,
                slot: image.slot.rawValue, binaryID: image.binaryID,
                ownerGeneration: image.ownerGeneration, architecture: image.architecture,
                sliceIndex: image.sliceIndex, sha256: fingerprint.imageBytesSHA256,
                analysisRevision: image.analysisRevision,
                analysisInputFingerprintSHA256: fingerprint.overallSHA256
            )
        } catch {
            throw NEWFEATURESAdmissionFailure.sourceIdentityUnavailable
        }
    }

    static func requireCurrent(_ expected: NEWFEATURESImageKey,
                               precondition: Phase2ReadPrecondition,
                               current: Phase2ReadCurrentState,
                               fingerprint: AnalysisInputFingerprint?) throws {
        // Keep Phase2's own comparison authoritative. The additional full projection equality
        // conservatively retains analysis revision even when facet-qualified reads can survive it.
        guard precondition.compared(to: current).isCurrent,
              try make(current: current, fingerprint: fingerprint) == expected else {
            throw NEWFEATURESAdmissionFailure.staleSource
        }
    }
}

/// App coordinator owns the real store/session pair. No independent revision ledger.
/// Construct only at the document owner with that session's actual WorkspaceStore.
/// This source admission does not grant scripting/MCP/Phase2 operation permission;
/// each caller must still traverse its existing authorization and evidence acceptor.
@MainActor
final class NEWFEATURESAdmissionBridge {
    private weak var store: WorkspaceStore?
    private weak var session: WorkspaceDocumentSession?

    init(store: WorkspaceStore, session: WorkspaceDocumentSession) {
        self.store = store
        self.session = session
    }

    func admit(slot: ImageSlot) throws -> NEWFEATURESAppAdmission {
        let (store, session) = try liveOwner()
        let current = store.phase2ReadCurrentState(for: slot)
        let key = try NEWFEATURESIdentityProjection.make(
            current: current,
            fingerprint: store.snapshot.analysis(in: slot)?.analysisInputFingerprint
        )
        // An empty facet list deliberately requests Phase2's conservative whole-image
        // comparison. Lane-specific facet optimization must not weaken the full-key check.
        let precondition = Phase2ReadPrecondition(
            workspace: current.workspace, workspaceRevision: current.workspaceRevision,
            strictWholeWorkspace: false, image: current.image, dependencies: []
        )
        return NEWFEATURESAppAdmission(
            projection: NEWFEATURESLedgerAdmission(image: key),
            precondition: precondition, sessionID: session.snapshot.sessionID
        )
    }

    func revalidate(_ admission: NEWFEATURESAppAdmission) throws {
        let (store, session) = try liveOwner()
        guard session.snapshot.sessionID == admission.sessionID else {
            throw NEWFEATURESAdmissionFailure.staleSource
        }
        let slot = ImageSlot(rawValue: admission.projection.image.slot)
        try NEWFEATURESIdentityProjection.requireCurrent(
            admission.projection.image, precondition: admission.precondition,
            current: store.phase2ReadCurrentState(for: slot),
            fingerprint: store.snapshot.analysis(in: slot)?.analysisInputFingerprint
        )
    }

    /// Resolve image-qualified addresses against the admitted snapshot, refusing overlaps
    /// and duplicate UUIDs. No fallback to another image, focus, or a bare-address dictionary.
    func functionID(address: UInt64, admission: NEWFEATURESAppAdmission) throws -> UUID {
        try revalidate(admission)
        guard let store,
              let analysis = store.snapshot.analysis(in: ImageSlot(rawValue: admission.projection.image.slot))
        else { throw NEWFEATURESAdmissionFailure.analysisRequired }
        return try NEWFEATURESFunctionOwnership.resolve(address: address, functions: analysis.functions)
    }

    /// No suspension between the live authority check and the synchronous sink.
    /// For a transport, call this at its final enqueue boundary. A sink that defers work
    /// must retain the envelope and invoke publish again at its actual delivery boundary.
    func publish<Result: Sendable>(
        _ envelope: NEWFEATURESResultEnvelope<Result>,
        to sink: (Result) throws -> Void
    ) throws {
        try revalidate(envelope.admission)
        try sink(envelope.result)
    }

    private func liveOwner() throws -> (WorkspaceStore, WorkspaceDocumentSession) {
        guard let store, let session, !session.isClosedForWindowClose,
              !session.isTerminationPreparationActive else {
            throw NEWFEATURESAdmissionFailure.documentClosed
        }
        guard session.snapshot.documentID == store.documentID,
              session.snapshot.workspaceID == store.workspaceID else {
            throw NEWFEATURESAdmissionFailure.staleSource
        }
        return (store, session)
    }
}

/// Uses the same unique range resolver as the existing call graph.
enum NEWFEATURESFunctionOwnership {
    static func resolve(address: UInt64, functions: [FunctionSummary]) throws -> UUID {
        guard functions.count <= 100_000 else {
            throw NEWFEATURESAdmissionFailure.inputLimitExceeded
        }
        guard functions.allSatisfy({ $0.endAddress > $0.startAddress }) else {
            throw NEWFEATURESAdmissionFailure.ambiguousFunction
        }
        let ranges = FunctionRangeIndex(functions)
        guard let match = ranges.owner(of: address) else {
            if functions.contains(where: { address >= $0.startAddress && address < $0.endAddress }) {
                throw NEWFEATURESAdmissionFailure.ambiguousFunction
            }
            throw NEWFEATURESAdmissionFailure.functionNotFound
        }
        guard functions.lazy.filter({ $0.id == match.id }).prefix(2).count == 1 else {
            throw NEWFEATURESAdmissionFailure.ambiguousFunction
        }
        return match.id
    }
}
