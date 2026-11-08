// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

/// The actor reservation is deliberate: actor methods can otherwise interleave across backend awaits.
public actor VAVerificationCoordinator {
    private let backend: any VAVerificationBackend
    private var reserved = false
    private var needsRecovery = false
    public init(backend: any VAVerificationBackend) { self.backend = backend }

    private func reserve(recovery: Bool = false) throws {
        guard !reserved else { throw VAVerificationError.busy }
        guard recovery || !needsRecovery else { throw VAVerificationError.recoveryRequired }
        reserved = true
    }

    public func snapshot() async throws -> VAVerificationState {
        try reserve()
        defer { reserved = false }
        let snapshot = try await backend.load()
        try snapshot.state.validate()
        return snapshot.state
    }

    /// The adapter resolves or issues evidence through the existing native read authority.
    public func inspect(_ target: VATargetReference, kind: VAQueryKind) async throws -> VAEvidenceRecord {
        try reserve()
        defer { reserved = false }
        try Task.checkCancellation()
        let baseline = try await backend.load()
        try baseline.state.validate()
        let stamp = try baseline.state.projection.stamp()
        try baseline.state.projection.requireTarget(target, query: kind)
        let record = try await backend.observe(target, kind: kind, at: stamp)
        guard record.observation.stamp == stamp, record.observation.target == target,
              record.observation.query == kind else { throw VAVerificationError.mismatchedEvidence }
        if let existing = baseline.state.evidence.first(where: { $0.id == record.id }) {
            guard existing == record else { throw VAVerificationError.mismatchedEvidence }
            return existing
        }
        guard baseline.state.evidence.count < 10_000 else { throw VAVerificationError.budgetExceeded("evidence ledger") }
        var next = baseline.state
        next.evidence.append(record)
        try next.validate()
        try Task.checkCancellation()
        _ = try await publish(next, expecting: baseline.version)
        return record
    }

    public func execute(_ request: VAMutationRequest) async throws -> VAVerificationReceipt {
        try reserve()
        defer { reserved = false }
        try Task.checkCancellation()
        let baseline = try await backend.load()
        try baseline.state.validate()
        let before = try baseline.state.projection.stamp()
        // Bounded requests cannot force unbounded hashing/retention even when they are rejected.
        try request.validateRetentionBounds()
        if let existing = baseline.state.receipts.first(where: { $0.request.id == request.id }) {
            guard existing.request == request, existing.requestDigest == (try request.digest()) else {
                throw VAVerificationError.idempotencyConflict
            }
            return existing
        }
        guard baseline.state.receipts.count < 10_000 else { throw VAVerificationError.budgetExceeded("receipt ledger") }
        var candidate: VAWorkspaceProjection
        do {
            try request.validateShape()
            guard request.base == before else { throw VAVerificationError.staleProjection }
            let capabilities = await backend.capabilities
            guard capabilities.supportsVerifiedMutation else { throw VAVerificationError.unsupportedPublication }
            for edit in request.edits {
                try baseline.state.projection.requireTarget(edit.target, edit: edit.kind)
                for id in edit.evidenceIDs {
                    guard let evidence = baseline.state.evidence.first(where: { $0.id == id }) else {
                        throw VAVerificationError.unknownEvidence
                    }
                    try VAEvidenceEligibility.requireMutationEvidence(evidence, for: edit.target, kind: edit.kind, at: before)
                }
            }
            try Task.checkCancellation()
            candidate = try await backend.stage(request.edits, against: baseline.state.projection)
            try VACandidateVerifier.verify(before: baseline.state.projection, candidate: candidate, edits: request.edits)
            try Task.checkCancellation()
            // The backend must repeat this guard at its atomic commit point.
            let rechecked = try await backend.load()
            guard rechecked.version == baseline.version,
                  (try rechecked.state.projection.stamp()) == before else { throw VAVerificationError.staleProjection }
        } catch {
            if error is CancellationError { throw VAVerificationError.cancelled }
            // A backend that violated the candidate isolation contract cannot be treated as harmless rejection.
            if case VAVerificationError.publicationIndeterminate = error { needsRecovery = true; throw error }
            let now = try await backend.load()
            try now.state.validate()
            guard now.version == baseline.version else { throw VAVerificationError.staleProjection }
            let receipt = try VAVerificationReceipt(request: request, decision: .rejected, before: before, after: nil,
                mechanical: .notVerified, persistence: .notApplicable, failure: String(describing: error),
                recovery: "Read current native evidence, correct the request, and retry with a new operation ID.")
            var rejected = baseline.state
            rejected.receipts.append(receipt)
            _ = try await publish(rejected, expecting: baseline.version)
            return receipt
        }
        guard before.revision < UInt64.max else { throw VAVerificationError.exhausted }
        candidate.revision = before.revision + 1
        let after = try candidate.stamp()
        let receipt = try VAVerificationReceipt(request: request, decision: .accepted, before: before, after: after,
            mechanical: .candidateReadbackVerified, persistence: .pendingFreshProcessCheckpoint)
        var next = baseline.state
        next.projection = candidate
        next.receipts.append(receipt)
        try next.validate()
        try Task.checkCancellation()
        _ = try await publish(next, expecting: baseline.version)
        return receipt
    }

    private func publish(_ state: VAVerificationState, expecting version: String) async throws -> VABackendSnapshot {
        do {
            let result = try await backend.publish(state, expecting: version)
            do { try result.state.validate() }
            catch {
                needsRecovery = true
                throw VAVerificationError.publicationIndeterminate("Committed state failed validation: \(error)")
            }
            guard try VACanonicalJSON.encode(result.state) == VACanonicalJSON.encode(state) else {
                needsRecovery = true
                throw VAVerificationError.publicationIndeterminate("Committed readback differs from proposed state")
            }
            return result
        } catch {
            if case VAVerificationError.publicationIndeterminate = error { needsRecovery = true }
            throw error
        }
    }

    /// Reconciliation only reads the canonical state. It never guesses which candidate should win.
    public func recover() async throws -> VAVerificationState {
        try reserve(recovery: true)
        defer { reserved = false }
        let snapshot = try await backend.load()
        try snapshot.state.validate()
        needsRecovery = false
        return snapshot.state
    }

}
