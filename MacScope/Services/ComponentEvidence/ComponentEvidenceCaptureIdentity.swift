import Foundation

extension ComponentEvidence {
    /// A root observation valid for alias comparison within one admission call only.
    struct CaptureRootIdentity: Sendable, Hashable {
        let device: UInt64
        let inode: UInt64
    }

    /// Opaque authority supplied by the caller; never derived from a path or content.
    struct ProviderCaptureIdentity: Sendable, Hashable {
        let providerDomain: UUID
        let token: UUID
    }

    enum AliasDecision: Sendable, Hashable {
        case providerSame, rootsCoalesced, distinct
    }
}
