import Foundation
import ExternalMCP
import NetworkEvidenceCore

public enum ProxymanExperimentAction: Codable, Sendable, Equatable {
    case blockEndpoint(endpoint: String, method: String)

    var endpoint: String { switch self { case .blockEndpoint(let e, _): e } }
    var method: String { switch self { case .blockEndpoint(_, let m): m } }
    var tool: String { "create_blacklist" }
    var kind: String { "blacklist" }
}

public struct ProxymanExperimentProposal: Codable, Sendable, Equatable {
    public let id: UUID
    public let scopeID: UUID
    public let connectionID: UUID
    public let action: ProxymanExperimentAction
    public let toolName: String
    public let argumentsJSON: String
    public let argumentsSHA256: String
    public let schemaDigest: String
    public let createdAt: Date
    public let expiresAt: Date
    public let expectedEffect: String
    public let verificationPlan: String
    public let cleanupPlan: String
}

/// Only the review controller can mint these runtime tokens. They cannot be decoded from a
/// model response, restored from a workspace, or constructed from an approval Boolean.
public struct ApprovedProxymanExperiment: Sendable {
    fileprivate let id: UUID
    public let proposalID: UUID
}

public enum ProxymanExperimentVerification: String, Codable, Sendable {
    case ruleListed, unverified, outcomeUnknown
}
public struct ProxymanExperimentRecord: Codable, Sendable, Equatable {
    public let proposalID: UUID
    public let action: ProxymanExperimentAction
    public let toolName: String
    public let connectionID: UUID
    public let scopeID: UUID
    public let argumentsJSON: String
    public let argumentsSHA256: String
    public let schemaDigest: String
    public let executedAt: Date
    public let createdRuleID: String?
    public let verification: ProxymanExperimentVerification
    public let cleanupInstructions: String
    public let diagnosticCode: String?
}
public enum ProxymanExperimentError: Error, Equatable, Sendable {
    case disabled, unknownProposal, invalidReview, expired, approvalConsumed, invalidTarget, capacityExceeded, auditUnavailable
}

public protocol ProxymanExperimentAuditing: Sendable {
    func recordIntent(_ proposal: ProxymanExperimentProposal) async throws
    func recordOutcome(_ record: ProxymanExperimentRecord) async
}

public enum ProxymanExperimentCleanupState: String, Codable, Sendable {
    case ruleRemoved, ruleDisabled, ruleStillActive, unverifiable
}

enum ProxymanExperimentPolicy {
    static let permittedTool: String = "create_blacklist"
    static func permits(tool: String) -> Bool { tool == permittedTool }
    static let capacity: Int = 64
    static let lifetime: TimeInterval = 60
}

struct PreparedProxymanExperiment: Sendable {
    let proposal: ProxymanExperimentProposal
    let lease: ProxymanAdapter.ScopeLease
    let arguments: MCPJSONValue
    let schemaDigest: String
    let previousRuleIDs: Set<String>
}

/// Native-app review service, deliberately not a member of ProxymanInvestigating or any model
/// tool registry. Enabling the tier does not approve any proposed action.
public actor ProxymanExperimentController {
    private let adapter: ProxymanAdapter
    private let audit: any ProxymanExperimentAuditing
    private let clock: @Sendable () -> Date
    private var enabled: Bool
    private var reviewEpoch = UUID()
    private var proposals: [UUID: PreparedProxymanExperiment] = [:]
    private var approvals: [UUID: UUID] = [:]
    private var pendingExecutions: [UUID: UUID] = [:]

    public init(adapter: ProxymanAdapter, enabled: Bool = false, audit: any ProxymanExperimentAuditing, now: @escaping @Sendable () -> Date = { Date() }) {
        self.adapter = adapter; self.enabled = enabled; self.audit = audit; self.clock = now
    }

    /// Call only from an explicit native settings action, never from model-generated input.
    public func setEnabled(_ enabled: Bool) {
        if self.enabled != enabled || !enabled { revokeAll() }
        self.enabled = enabled
    }

    public func propose(action: ProxymanExperimentAction, scope: ProxymanReadScope) async throws -> ProxymanExperimentProposal {
        purgeExpiredProposals()
        guard proposals.count < ProxymanExperimentPolicy.capacity else { throw ProxymanExperimentError.capacityExceeded }
        let epoch = reviewEpoch
        let prepared = try await adapter.prepareExperiment(action: action, scope: scope, now: clock())
        guard epoch == reviewEpoch else { throw ProxymanExperimentError.invalidReview }
        purgeExpiredProposals()
        guard prepared.proposal.expiresAt > clock() else { throw ProxymanExperimentError.expired }
        guard proposals.count < ProxymanExperimentPolicy.capacity else { throw ProxymanExperimentError.capacityExceeded }
        proposals[prepared.proposal.id] = prepared
        return prepared.proposal
    }

    /// The app's explicit user-approval event must pass the digest of the exact displayed
    /// arguments. No read tool, proposal, or provider output calls this method automatically.
    public func approve(proposalID: UUID, reviewedArgumentsSHA256: String) throws -> ApprovedProxymanExperiment {
        guard enabled else { throw ProxymanExperimentError.disabled }
        guard let prepared = proposals[proposalID] else { throw ProxymanExperimentError.unknownProposal }
        guard prepared.proposal.expiresAt > clock() else {
            discard(proposalID: proposalID)
            throw ProxymanExperimentError.expired
        }
        purgeExpiredProposals()
        guard reviewedArgumentsSHA256 == prepared.proposal.argumentsSHA256,
              !approvals.values.contains(proposalID) else { throw ProxymanExperimentError.invalidReview }
        let id = UUID()
        approvals[id] = proposalID
        return ApprovedProxymanExperiment(id: id, proposalID: proposalID)
    }

    public func execute(_ approval: ApprovedProxymanExperiment) async throws -> ProxymanExperimentRecord {
        try await executePrepared(approval, expectedScopeID: nil, expectedConnectionID: nil, authorizationStillValid: { true })
    }

    /// The application coordinator supplies its current investigation and connection binding,
    /// and revalidates its own authority immediately before dispatch is reserved.
    public func execute(_ approval: ApprovedProxymanExperiment, expectedScopeID: UUID, expectedConnectionID: UUID,
                        authorizationStillValid: @escaping @Sendable () async -> Bool) async throws -> ProxymanExperimentRecord {
        try await executePrepared(approval, expectedScopeID: expectedScopeID, expectedConnectionID: expectedConnectionID,
            authorizationStillValid: authorizationStillValid)
    }

    private func executePrepared(_ approval: ApprovedProxymanExperiment, expectedScopeID: UUID?, expectedConnectionID: UUID?,
                                 authorizationStillValid: @escaping @Sendable () async -> Bool) async throws -> ProxymanExperimentRecord {
        guard enabled else { throw ProxymanExperimentError.disabled }
        guard let candidate = proposals[approval.proposalID], approvals[approval.id] == approval.proposalID else {
            throw ProxymanExperimentError.approvalConsumed
        }
        guard expectedScopeID.map({ $0 == candidate.proposal.scopeID }) ?? true,
              expectedConnectionID.map({ $0 == candidate.proposal.connectionID }) ?? true else {
            throw ProxymanExperimentError.invalidReview
        }
        // Consume before the first await. Concurrent calls cannot execute an approved mutation twice.
        guard approvals.removeValue(forKey: approval.id) == approval.proposalID,
              let prepared = proposals.removeValue(forKey: approval.proposalID) else {
            throw ProxymanExperimentError.approvalConsumed
        }
        guard prepared.proposal.expiresAt > clock() else { throw ProxymanExperimentError.expired }
        let epoch = reviewEpoch
        pendingExecutions[approval.proposalID] = epoch
        defer { pendingExecutions.removeValue(forKey: approval.proposalID) }
        let audit = self.audit
        let record = try await adapter.executeExperiment(prepared, now: clock(), authorizeDispatch: {
            guard await authorizationStillValid() else { return false }
            return await self.reserveDispatch(proposalID: approval.proposalID, epoch: epoch, expiresAt: prepared.proposal.expiresAt)
        }, recordIntent: {
            try await audit.recordIntent(prepared.proposal)
        })
        await audit.recordOutcome(record)
        return record
    }

    public func checkCleanup(record: ProxymanExperimentRecord, scope: ProxymanReadScope) async throws -> ProxymanExperimentCleanupState {
        try await adapter.cleanupState(record: record, scope: scope)
    }

    public func revokeAll() {
        reviewEpoch = UUID()
        proposals.removeAll(); approvals.removeAll(); pendingExecutions.removeAll()
    }

    /// Discarding an unexecuted review removes its authority and frees its bounded slot.
    public func discard(proposalID: UUID) {
        proposals.removeValue(forKey: proposalID)
        approvals = approvals.filter { $0.value != proposalID }
        pendingExecutions.removeValue(forKey: proposalID)
    }

    private func purgeExpiredProposals() {
        let now = clock()
        for id in proposals.filter({ $0.value.proposal.expiresAt <= now }).map(\.key) { discard(proposalID: id) }
    }

    /// Reservation is the commit boundary. Revocation prevents unreserved dispatches; it cannot
    /// recall an operation already reserved/sent to another process or promise rollback.
    private func reserveDispatch(proposalID: UUID, epoch: UUID, expiresAt: Date) -> Bool {
        guard enabled, reviewEpoch == epoch, pendingExecutions[proposalID] == epoch, expiresAt > clock() else { return false }
        pendingExecutions.removeValue(forKey: proposalID)
        return true
    }
}
