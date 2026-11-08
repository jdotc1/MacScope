import Foundation

/// Maps the portable VA Core receipt types onto the Foundation-only audit envelope records.
/// Unused in production until VA3b; the envelope itself lives in MacScopeAnalysisCore and
/// cannot import VA Core.
extension VerifiedAnnotationProjectionIdentity {
    init(_ stamp: VAProjectionStamp) {
        self.init(workspaceID: stamp.workspaceID, documentID: stamp.documentID,
                  installationID: stamp.installationID, revision: stamp.revision, digest: stamp.digest)
    }
}

/// Typed refusal for edit kinds the audit mapping does not carry. Every `VAEditKind` is mapped since S6b;
/// the case is kept so a future kind can be refused rather than silently classified.
enum VerifiedAnnotationAuditMappingError: Error, Equatable {
    case unsupportedEditKind(VAEditKind)
}

extension VerifiedAnnotationAuditRecord {
    /// Value bound per edit kind. Exhaustive on purpose: a new `VAEditKind` must be classified here
    /// and cannot silently inherit the comment limit.
    static func auditValueLimit(for kind: VAEditKind) throws -> Int {
        switch kind {
        case .functionName: return 256
        case .functionComment: return 2048
        // R4: type names are at most 256 UTF-8 bytes here, for `addressType` only.
        case .addressType: return 256
        // S6b: the canonical signature text, bounded by the codec (`VerifiedFieldCodec.maximumSignatureBytes`,
        // 16,384 bytes) and by Core's own prototype bound.
        case .functionPrototype: return VerifiedFieldCodec.maximumSignatureBytes
        }
    }

    /// Ruling 4: name and comment keep v1 bytes with no `fieldClass` key, so they map to nil. An accepted
    /// `addressType` or `functionPrototype` edit records `fieldClass` (v2 Body domain). A rejected receipt changed nothing and
    /// stays v1 whatever it asked for, so a rejected typed request needs no typed-edits reader feature.
    static func recordedFieldClass(for receipt: VAVerificationReceipt) -> VerifiedAnnotationAuditFieldClass? {
        guard receipt.decision == .accepted, receipt.request.edits.count == 1 else { return nil }
        switch receipt.request.edits[0].kind {
        case .functionName, .functionComment: return nil
        case .addressType: return VerifiedAnnotationAuditFieldClass(rawValue: VerifiedFieldClass.addressType.rawValue)
        case .functionPrototype: return VerifiedAnnotationAuditFieldClass(rawValue: VerifiedFieldClass.functionSignature.rawValue)
        }
    }

    /// Revalidates the Core receipt (request digest, request shape, one edit, evidence ids) before mapping,
    /// so a record never carries data the Core ledger would have refused.
    init(receipt: VAVerificationReceipt, nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink],
         checkpointReferences: [VerifiedAnnotationCheckpointReference] = []) throws {
        let bad = VerifiedAnnotationAuditError.malformedRecord
        do {
            try receipt.request.validateRetentionBounds()
            try receipt.before.validate()
            guard receipt.requestDigest == (try receipt.request.digest()),
                  receipt.request.base.workspaceID == receipt.before.workspaceID,
                  receipt.request.base.documentID == receipt.before.documentID else {
                throw VerifiedAnnotationAuditError.digestMismatch
            }
            if receipt.decision == .accepted {
                try receipt.request.validateShape()
                guard receipt.request.edits.count == 1, receipt.before == receipt.request.base else { throw bad }
                let edit = receipt.request.edits[0]
                let limit = try Self.auditValueLimit(for: edit.kind)
                guard (edit.value?.utf8.count ?? 0) <= limit,
                      Set(edit.evidenceIDs) == Set(nativeEvidenceLinks.map(\.evidenceID)) else { throw bad }
            }
        } catch let error as VerifiedAnnotationAuditError { throw error }
        catch let error as VerifiedAnnotationAuditMappingError { throw error }
        catch { throw bad }
        try self.init(
            operationID: receipt.request.id,
            requestDigest: receipt.requestDigest,
            decision: receipt.decision == .accepted ? .accepted : .rejected,
            before: .init(receipt.before),
            after: receipt.after.map { .init($0) },
            mechanical: receipt.mechanical == .candidateReadbackVerified ? .candidateReadbackVerified : .notVerified,
            persistence: receipt.persistence == .pendingFreshProcessCheckpoint ? .pendingFreshProcessCheckpoint : .notApplicable,
            failure: receipt.failure, recovery: receipt.recovery,
            recordedAtMilliseconds: Int64((receipt.recordedAt.timeIntervalSince1970 * 1000).rounded()),
            nativeEvidenceLinks: nativeEvidenceLinks, checkpointReferences: checkpointReferences,
            fieldClass: Self.recordedFieldClass(for: receipt))
    }
}
