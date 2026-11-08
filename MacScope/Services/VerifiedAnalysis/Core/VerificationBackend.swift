// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

public struct VABackendCapabilities: Sendable, Equatable {
    public let isolatedCandidates: Bool
    public let independentCandidateReadback: Bool
    public let atomicStateAndReceiptPublication: Bool
    public let compareAndSwapPublication: Bool
    public init(isolatedCandidates: Bool, independentCandidateReadback: Bool,
                atomicStateAndReceiptPublication: Bool, compareAndSwapPublication: Bool) {
        self.isolatedCandidates = isolatedCandidates; self.independentCandidateReadback = independentCandidateReadback
        self.atomicStateAndReceiptPublication = atomicStateAndReceiptPublication
        self.compareAndSwapPublication = compareAndSwapPublication
    }
    public var supportsVerifiedMutation: Bool {
        isolatedCandidates && independentCandidateReadback && atomicStateAndReceiptPublication && compareAndSwapPublication
    }
}

public struct VABackendSnapshot: Sendable {
    public let state: VAVerificationState
    /// Opaque native publication token. It guards audit-only changes as well as annotation changes.
    public let version: String
    public init(state: VAVerificationState, version: String) { self.state = state; self.version = version }
}

/// Only trusted host adapters conform. Never expose adapter construction or publication as model tools.
/// Production implementations must reuse MacScope's existing evidence and document publication owners.
public protocol VAVerificationBackend: Sendable {
    var capabilities: VABackendCapabilities { get async }
    func load() async throws -> VABackendSnapshot
    func observe(_ target: VATargetReference, kind: VAQueryKind, at stamp: VAProjectionStamp) async throws -> VAEvidenceRecord
    /// Returns a value independently read back from an isolated candidate. Accepted state stays intact.
    func stage(_ edits: [VAEditIntent], against baseline: VAWorkspaceProjection) async throws -> VAWorkspaceProjection
    /// Publish accepted state AND receipt together, with an atomic expected-version guard.
    /// An exception after the commit boundary MUST be publicationIndeterminate, never an ordinary rejection.
    func publish(_ state: VAVerificationState, expecting version: String) async throws -> VABackendSnapshot
}

public enum NativeIntegrationGate {
    /// Current native proposal acceptance must not be labeled verified until these capabilities are wired.
    public static let unconfigured = VABackendCapabilities(isolatedCandidates: false,
        independentCandidateReadback: false, atomicStateAndReceiptPublication: false, compareAndSwapPublication: false)
}
