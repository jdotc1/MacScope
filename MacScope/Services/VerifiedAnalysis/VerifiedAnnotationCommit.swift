import Foundation
import Synchronization

/// Why a verified-commit fence stopped being armed.
enum VerifiedCommitRevocation: Equatable, Sendable {
    /// The live document's mutation generation advanced (manual edit, Undo, analysis, ...).
    case mutation
    /// The document installation changed (open, reload, restore, new).
    case installation
    /// The owning session closed.
    case closed
}

/// Thread-safe final live compare-and-swap. The store revokes it synchronously from the single
/// generation choke point; the publisher seals it inside the namespace-coordinated closure,
/// immediately before the rename. `seal()` is the only call made off the main actor.
final class VerifiedCommitFence: Sendable {
    enum Phase: Equatable, Sendable {
        case armed
        case sealed
        /// The install's own mutations are expected and must not revoke the fence.
        case installing
        case revoked(VerifiedCommitRevocation)
        case revokedAfterSeal(VerifiedCommitRevocation)
        case finished
    }

    private let state = Mutex<Phase>(.armed)

    var phase: Phase { state.withLock { $0 } }

    func revoke(_ reason: VerifiedCommitRevocation) {
        state.withLock { phase in
            switch phase {
            case .armed: phase = .revoked(reason)
            case .sealed: phase = .revokedAfterSeal(reason)
            case .installing, .revoked, .revokedAfterSeal, .finished: break
            }
        }
    }

    /// Atomically fails when anything has revoked the fence since admission.
    func seal() -> Bool {
        state.withLock { phase in
            guard phase == .armed else { return false }
            phase = .sealed
            return true
        }
    }

    /// Returns the phase observed at install time. Only a sealed (possibly later revoked) fence
    /// may install; an unsealed or revoked-before-seal fence never reached the rename.
    func beginInstall() -> Phase {
        state.withLock { phase in
            let observed = phase
            switch observed {
            case .sealed, .revokedAfterSeal: phase = .installing
            default: break
            }
            return observed
        }
    }

    func finish() { state.withLock { $0 = .finished } }
}

/// Maps native workspace state to the portable projection stamp. The production implementation
/// belongs to VA4; the commit service only verifies that the stamps a receipt claims are the
/// stamps the native candidate and the committed state actually produce.
@MainActor
protocol VerifiedAnnotationProjecting {
    func stamp(
        workspaceID: UUID, documentID: UUID, installationID: UUID,
        snapshot: WorkspaceSnapshot, revision: UInt64
    ) throws -> VAProjectionStamp
}

struct VerifiedAnnotationCommitRequest {
    let state: VAVerificationState
    let receipt: VAVerificationReceipt
    let nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink]
    /// Required for an accepted receipt; nil for a rejected (audit-only) receipt.
    let target: ImageAddress?
    /// The class of the one field this commit edits (VA-SCOPE S4). `nil` for a rejected receipt.
    let fieldClass: VerifiedFieldClass?
    let requested: String?
    let expectingVersion: String
    let projector: any VerifiedAnnotationProjecting

    /// The legacy name/comment view of `fieldClass`; nil for the classes it cannot express.
    var field: VerifiedAnnotationField? { fieldClass?.annotationField }
    var operationID: UUID { receipt.request.id }
    var isAccepted: Bool { receipt.decision == .accepted }

    /// Name/comment form, argument-for-argument what the memberwise initializer used to be.
    init(state: VAVerificationState, receipt: VAVerificationReceipt,
         nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink], target: ImageAddress?,
         field: VerifiedAnnotationField?, requested: String?, expectingVersion: String,
         projector: any VerifiedAnnotationProjecting) {
        self.init(state: state, receipt: receipt, nativeEvidenceLinks: nativeEvidenceLinks, target: target,
                  fieldClass: field.map { VerifiedFieldClass($0) }, requested: requested,
                  expectingVersion: expectingVersion, projector: projector)
    }

    init(state: VAVerificationState, receipt: VAVerificationReceipt,
         nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink], target: ImageAddress?,
         fieldClass: VerifiedFieldClass?, requested: String?, expectingVersion: String,
         projector: any VerifiedAnnotationProjecting) {
        self.state = state; self.receipt = receipt; self.nativeEvidenceLinks = nativeEvidenceLinks
        self.target = target; self.fieldClass = fieldClass; self.requested = requested
        self.expectingVersion = expectingVersion; self.projector = projector
    }
}

extension VerifiedFieldClass {
    /// Class-aware read of the one override member this class owns (VA-SCOPE S4, S6b). For
    /// `functionSignature` the value is the canonical signature text (rowToken and provenance dropped), so
    /// the key-level CAS and the readback compare content, never identity. If a stored signature cannot be
    /// canonicalised the value is `"unencodable:" + hash`, which can never equal a valid canonical string
    /// (it is not JSON), mirroring `NativeAnnotationProjector`.
    func value(in override: AddressOverride) -> String? {
        switch self {
        case .name: return override.customName
        case .comment: return override.customComment
        case .addressType: return override.appliedTypeName
        case .functionSignature:
            guard let signature = override.signature else { return nil }
            if let text = try? VerifiedFieldCodec.canonicalSignature(signature) { return text }
            let raw = (try? JSONEncoder().encode(signature)) ?? Data()
            return "unencodable:" + VerifiedAnnotationAuditCodec.sha256Hex(raw)
        }
    }

    /// For `functionSignature`, `value` is canonical signature text and was validated at prepare
    /// (`invalidReceipt "signature-value"`), so a decode failure here is a programming error. Release builds
    /// leave the override unchanged rather than write a guess.
    func set(_ value: String?, in override: inout AddressOverride) {
        switch self {
        case .name: override.customName = value
        case .comment: override.customComment = value
        case .addressType: override.appliedTypeName = value
        case .functionSignature:
            guard let value else { override.signature = nil; return }
            guard let signature = try? VerifiedFieldCodec.decodeSignature(value) else {
                assertionFailure("signature value was validated at prepare")
                return
            }
            override.signature = signature
        }
    }
}

struct VerifiedAnnotationCommitRefusal: Error, Equatable, Sendable {
    enum Code: String, Sendable {
        case sessionClosed, sourceUnavailable, writeBusy, conflictUnresolved, locationUnavailable
        case journalFailed, staleVersion, idempotencyConflict, invalidReceipt, candidateRejected
        case projectionMismatch, stageFailed, publishFailed, liveFenceRevoked, destinationChanged
        case recoveryRequired, headlessJournalRequired, cancelled, notHeadless
    }
    let code: Code
    let detail: String?
    init(_ code: Code, _ detail: String? = nil) { self.code = code; self.detail = detail }
}

struct VerifiedAnnotationCommitIndeterminate: Error, Equatable, Sendable {
    enum Code: String, Sendable {
        case publicationUnknown, publishedReadbackFailed, committedLiveNotInstalled
        case committedLiveAdvanced, sessionReplaced, sessionClosedAfterPossibleCommit
        case journalAppendUncertain
    }
    let code: Code
    let detail: String?
    init(_ code: Code, _ detail: String? = nil) { self.code = code; self.detail = detail }
}

struct VerifiedAnnotationCommitInfo: Equatable, Sendable {
    let operationID: UUID
    /// False when a later manual edit of the same field won (the receipt stays as history).
    let annotationInstalled: Bool
    /// True when manual edits raced in after the commit point; the document stays dirty.
    let liveAdvanced: Bool
    /// The session-mode journal degraded after the package was published.
    let journalDegraded: Bool
}

enum VerifiedAnnotationCommitOutcome: Sendable {
    case committed(VABackendSnapshot, VerifiedAnnotationCommitInfo)
    /// Exact retry of an already committed operation; nothing was written.
    case existing(VABackendSnapshot)
    /// Proven unchanged: no disk, live or journal mutation survived.
    case refused(VerifiedAnnotationCommitRefusal)
    /// Possibly committed. The store is latched against further verified writes and ordinary
    /// saves until `reconcileVerifiedCommit()` (or a fresh attach, headless) re-reads canonical truth.
    case indeterminate(VerifiedAnnotationCommitIndeterminate)
}

enum VerifiedCommitReconciliationOutcome: Equatable, Sendable {
    case nothingToReconcile
    case committedAndInstalled(operationID: UUID)
    case notCommitted(operationID: UUID)
    case unresolved(String)
}

/// In-memory recovery record. A process crash needs none: the disk package (or journal) is
/// self-describing, so the operation is simply present or absent after reopen.
struct VerifiedCommitLatch: Equatable, Sendable {
    let operationID: UUID
    let requestDigest: String
    let reason: String
    let isHeadless: Bool
    /// Session mode: the exact disk version the commit expected to replace.
    let expectedVersion: WorkspacePackageExternalVersion?
}

enum VerifiedAnnotationCommitService {
    /// Service-level advertisement. The app-level `NativeIntegrationGate.unconfigured` stays
    /// all-false until VA4 wires a production projector and the GUI.
    static let capabilities = VABackendCapabilities(
        isolatedCandidates: true, independentCandidateReadback: true,
        atomicStateAndReceiptPublication: true, compareAndSwapPublication: true)
}
