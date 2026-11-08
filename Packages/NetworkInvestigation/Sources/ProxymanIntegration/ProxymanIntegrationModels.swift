import Foundation
import ExternalMCP
import ProxymanInstallation

public enum ProxymanIntegrationPhase: String, Sendable, Equatable {
    case notApproved, approved, connecting, connected, failed, shutDown
}

public enum ProxymanIntegrationError: Error, Sendable, Equatable {
    case notApproved, connectionActive, shutDown, cancelled, unexpected
    case installation(ProxymanInstallationError)
    case client(MCPClientError)
}

public struct ProxymanConnectionAudit: Sendable, Equatable {
    public let connectionID: UUID?
    public let applicationVersion: String
    public let applicationBuild: String
    public let applicationCDHash: String
    public let bridgeCDHash: String
    public let bridgeSHA256: String
    public let connectedAt: Date

    public init(connectionID: UUID?, applicationVersion: String, applicationBuild: String,
                applicationCDHash: String, bridgeCDHash: String, bridgeSHA256: String,
                connectedAt: Date) {
        self.connectionID = connectionID
        self.applicationVersion = applicationVersion
        self.applicationBuild = applicationBuild
        self.applicationCDHash = applicationCDHash
        self.bridgeCDHash = bridgeCDHash
        self.bridgeSHA256 = bridgeSHA256
        self.connectedAt = connectedAt
    }
}

public struct ProxymanIntegrationSnapshot: Sendable, Equatable {
    public let phase: ProxymanIntegrationPhase
    public let review: ProxymanInstallationReview?
    public let connection: MCPConnectionSnapshot?
    public let audit: ProxymanConnectionAudit?
    public let failure: ProxymanIntegrationError?

    public init(phase: ProxymanIntegrationPhase, review: ProxymanInstallationReview?,
                connection: MCPConnectionSnapshot?, audit: ProxymanConnectionAudit?,
                failure: ProxymanIntegrationError?) {
        self.phase = phase
        self.review = review
        self.connection = connection
        self.audit = audit
        self.failure = failure
    }
}

func integrationError(_ error: any Error) -> ProxymanIntegrationError {
    switch error {
    case let error as ProxymanIntegrationError: error
    case let error as ProxymanInstallationError: .installation(error)
    case let error as MCPClientError: .client(error)
    case is CancellationError: .cancelled
    default: .unexpected
    }
}
