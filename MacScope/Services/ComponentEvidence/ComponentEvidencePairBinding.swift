import Foundation

extension ComponentEvidence {
    /// Immutable identity facts, not a retained owner or a liveness guarantee.
    struct PairBinding: Sendable {
        let ownerID: ObjectIdentifier
        let installationID: UUID

        /// The caller supplies its current owner from its own weak-held reference.
        func validate(currentOwner: AnyObject?, currentInstallation: UUID?) throws {
            guard let currentOwner, let currentInstallation,
                  ObjectIdentifier(currentOwner) == ownerID,
                  currentInstallation == installationID else {
                throw try ComponentEvidenceSecurityDelta.Refusal(code: .sourceStale, underlyingKind: .stale)
            }
        }
    }
}
