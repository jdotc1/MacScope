import Foundation
import NetworkEvidenceCore

public enum ProxymanAdapterError: Error, Equatable, Sendable {
    case notConnected, invalidScope, invalidQuery, scopeMismatch, scopeRevoked
    case unsupportedCapability(String), schemaIncompatible(String), malformedResponse(String)
    case responseLimitExceeded, staleReference, unverifiableFlowIdentity, vendorFailure(String), cancelled
}

/// Scope is app input, never authority derived from network content or model output.
public struct ProxymanReadScope: Codable, Sendable, Equatable {
    public let authorityID: UUID
    public let workspaceID: UUID
    public let investigationID: UUID
    public let binarySHA256: String
    public let allowedHosts: Set<String>
    public let start: Date
    public let end: Date
    public let maximumFlows: Int
    /// Exact app-reviewed routes and structural names. Empty means omit all such external text.
    public let approvedPaths: Set<String>
    public let approvedFieldNames: Set<String>

    public init(authorityID: UUID, workspaceID: UUID, investigationID: UUID, binarySHA256: String,
                allowedHosts: Set<String>, start: Date, end: Date, maximumFlows: Int = 40,
                approvedPaths: Set<String> = [], approvedFieldNames: Set<String> = []) throws {
        self.authorityID = authorityID; self.workspaceID = workspaceID; self.investigationID = investigationID
        self.binarySHA256 = binarySHA256; self.allowedHosts = allowedHosts
        self.start = start; self.end = end; self.maximumFlows = maximumFlows
        self.approvedPaths = approvedPaths; self.approvedFieldNames = approvedFieldNames
        try validate()
    }

    public func validate() throws {
        let zero = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        guard authorityID != zero, workspaceID != zero, investigationID != zero,
              binarySHA256.utf8.count == 64,
              binarySHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              (1...16).contains(allowedHosts.count), (1...100).contains(maximumFlows),
              start.timeIntervalSince1970.isFinite, end.timeIntervalSince1970.isFinite,
              start <= end, end.timeIntervalSince(start) <= 31 * 24 * 60 * 60,
              allowedHosts.allSatisfy({ ProxymanMinimizer.canonicalHost($0) == $0 }),
              approvedPaths.count <= 128, approvedPaths.allSatisfy(ProxymanPrivacy.isApprovablePath),
              approvedFieldNames.count <= 64, approvedFieldNames.allSatisfy(ProxymanPrivacy.isSafeFieldName) else {
            throw ProxymanAdapterError.invalidScope
        }
    }

    private enum CodingKeys: String, CodingKey {
        case authorityID, workspaceID, investigationID, binarySHA256, allowedHosts, start, end, maximumFlows
        case approvedPaths, approvedFieldNames
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(authorityID: c.decode(UUID.self, forKey: .authorityID),
                      workspaceID: c.decode(UUID.self, forKey: .workspaceID),
                      investigationID: c.decode(UUID.self, forKey: .investigationID),
                      binarySHA256: c.decode(String.self, forKey: .binarySHA256),
                      allowedHosts: c.decode(Set<String>.self, forKey: .allowedHosts),
                      start: c.decode(Date.self, forKey: .start), end: c.decode(Date.self, forKey: .end),
                      maximumFlows: c.decode(Int.self, forKey: .maximumFlows),
                      approvedPaths: c.decodeIfPresent(Set<String>.self, forKey: .approvedPaths) ?? [],
                      approvedFieldNames: c.decodeIfPresent(Set<String>.self, forKey: .approvedFieldNames) ?? [])
    }
}

public struct ProxymanFlowQuery: Codable, Sendable, Equatable {
    public let host: String?
    public let method: String?
    public let statusCode: Int?
    public let pathContains: String?
    public let onlyErrors: Bool
    public let clientName: String?
    public let limit: Int
    public let processID: Int?
    public init(host: String? = nil, method: String? = nil, statusCode: Int? = nil,
                pathContains: String? = nil, onlyErrors: Bool = false,
                clientName: String? = nil, limit: Int = 20, processID: Int? = nil) {
        self.host = host; self.method = method; self.statusCode = statusCode
        self.pathContains = pathContains; self.onlyErrors = onlyErrors
        self.clientName = clientName; self.limit = limit; self.processID = processID
    }
}

public struct ProxymanFlowBatch: Codable, Sendable, Equatable {
    public let id: UUID
    public let connectionID: UUID
    public let observedAt: Date
    public let flows: [NetworkFlowSummary]
    public let limitations: [NetworkObservationLimitation]
    public init(id: UUID, connectionID: UUID, observedAt: Date, flows: [NetworkFlowSummary],
                limitations: [NetworkObservationLimitation]) {
        self.id = id; self.connectionID = connectionID; self.observedAt = observedAt
        self.flows = flows; self.limitations = limitations
    }
}

public enum ProxymanCapability: String, Codable, Sendable, CaseIterable {
    case version, proxyStatus, flows, flowDetail, advancedFiltering, rules, toolStatus
    case sslStatus, certificateStatus, reverseProxies, dnsRules, externalProxy
}
public struct ProxymanCapabilities: Codable, Sendable, Equatable {
    public let connectionID: UUID
    public let supported: Set<ProxymanCapability>
    public let unavailable: [ProxymanCapability]
    public let unknownToolCount: Int
    public init(connectionID: UUID, supported: Set<ProxymanCapability>, unavailable: [ProxymanCapability], unknownToolCount: Int) {
        self.connectionID = connectionID; self.supported = supported
        self.unavailable = unavailable; self.unknownToolCount = unknownToolCount
    }
}
public struct ProxymanRuleSummary: Codable, Sendable, Equatable {
    public let id: String
    public let kind: String
    public let enabled: ProxymanKnowledgeState
    public let host: String?
    public init(id: String, kind: String, enabled: ProxymanKnowledgeState, host: String? = nil) {
        self.id = id; self.kind = kind; self.enabled = enabled; self.host = host
    }
}
public struct ProxymanRuleSnapshot: Codable, Sendable, Equatable {
    public let connectionID: UUID
    public let observedAt: Date
    public let rules: [ProxymanRuleSummary]
    public let isComplete: Bool
    public let limitations: [NetworkObservationLimitation]
    public init(connectionID: UUID, observedAt: Date, rules: [ProxymanRuleSummary], isComplete: Bool,
                limitations: [NetworkObservationLimitation] = []) {
        self.connectionID = connectionID; self.observedAt = observedAt; self.rules = rules
        self.isComplete = isComplete; self.limitations = limitations
    }
}

public protocol ProxymanInvestigating: Sendable {
    func capabilities() async throws -> ProxymanCapabilities
    func status(scope: ProxymanReadScope) async throws -> ProxymanEnvironmentStatus
    func findFlows(query: ProxymanFlowQuery, scope: ProxymanReadScope) async throws -> ProxymanFlowBatch
    func inspectFlow(reference: NetworkFlowReference, scope: ProxymanReadScope) async throws -> NetworkFlowDetail
    func rules(scope: ProxymanReadScope) async throws -> ProxymanRuleSnapshot
    func invalidate(scopeID: UUID) async
}
