// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

/// The same check applies during live execution and when admitted history is reopened.
public enum VAEvidenceEligibility {
    /// Kind-agnostic form: today's behavior (disassembly or function facts). Production callers use the
    /// kind-aware overload so an `addressType` edit cannot be justified by function evidence.
    public static func requireMutationEvidence(_ record: VAEvidenceRecord, for target: VATargetReference,
                                               at stamp: VAProjectionStamp) throws {
        try requireMutationEvidence(record, for: target, accepting: [.disassembly, .functionFacts], at: stamp)
    }

    /// `addressType` accepts only `.addressFacts` evidence; every other kind accepts `.disassembly`
    /// or `.functionFacts`.
    public static func requireMutationEvidence(_ record: VAEvidenceRecord, for target: VATargetReference,
                                               kind: VAEditKind, at stamp: VAProjectionStamp) throws {
        let accepted: Set<VAQueryKind> = kind == .addressType ? [.addressFacts] : [.disassembly, .functionFacts]
        try requireMutationEvidence(record, for: target, accepting: accepted, at: stamp)
    }

    private static func requireMutationEvidence(_ record: VAEvidenceRecord, for target: VATargetReference,
                                                accepting queries: Set<VAQueryKind>,
                                                at stamp: VAProjectionStamp) throws {
        guard record.observation.stamp == stamp, record.observation.target == target else {
            throw VAVerificationError.mismatchedEvidence
        }
        guard record.observation.completeness == .complete,
              queries.contains(record.observation.query),
              !record.observation.content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VAVerificationError.incompleteEvidence
        }
    }
}
