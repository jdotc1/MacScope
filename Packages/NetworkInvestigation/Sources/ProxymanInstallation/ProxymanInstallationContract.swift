import Foundation
import ExternalMCP

public enum ProxymanInstallationContract {
    public static let applicationBundleIdentifier = "com.proxyman.NSProxy"
    public static let bridgeSigningIdentifier = "mcp-server"
    public static let signingTeamIdentifier = "3X57WP8E8V"
    public static let applicationRequirement = "anchor apple generic and identifier \"com.proxyman.NSProxy\" and certificate leaf[subject.OU] = \"3X57WP8E8V\""
    public static let bridgeRequirement = "anchor apple generic and identifier \"mcp-server\" and certificate leaf[subject.OU] = \"3X57WP8E8V\""
    public static let standardApplicationURL = URL(fileURLWithPath: "/Applications/Proxyman.app", isDirectory: true)
    public static let bridgeRelativePath = "Contents/MacOS/mcp-server"
}

public enum ProxymanInstallationTrust: Sendable, Equatable {
    case trusted
    case confirmationRequired
}

/// Values presented for a person's explicit build confirmation.
public struct ProxymanInstallationReview: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let applicationURL: URL
    public let bridgeURL: URL
    public let bundleIdentifier: String
    public let applicationVersion: String
    public let applicationBuild: String
    public let signingTeamIdentifier: String
    public let applicationCDHash: String
    public let bridgeCDHash: String
    public let bridgeSHA256: String
    public let inspectedAt: Date
    public let trust: ProxymanInstallationTrust
}

/// In-memory consent bound to the service that issued it; it cannot be decoded from vendor input.
public struct ApprovedProxymanInstallation: Sendable {
    let review: ProxymanInstallationReview
    let authorityID: UUID
}

public enum ProxymanInstallationError: Error, Sendable, Equatable, LocalizedError {
    case notInstalled
    case invalidApplication
    case missingBridge
    case invalidSignature
    case adHocSignature
    case untrustedSigner
    case hardenedRuntimeMissing
    case untrustedPermissions
    case reviewExpired
    case installationChanged
    case confirmationRequired

    public var errorDescription: String? {
        switch self {
        case .notInstalled: "Proxyman was not found. Select your installed Proxyman application."
        case .invalidApplication: "Select the Proxyman application bundle, not an arbitrary executable."
        case .missingBridge: "The selected application has no regular executable MCP bridge. Update Proxyman and enable MCP in its settings."
        case .invalidSignature: "The application or bridge has an invalid or unsupported code signature."
        case .adHocSignature: "Ad hoc signatures cannot establish the developer's identity."
        case .untrustedSigner: "The application or bridge does not satisfy the required developer identity."
        case .hardenedRuntimeMissing: "The application or bridge does not use the hardened runtime."
        case .untrustedPermissions: "The application or bridge has unsafe file permissions."
        case .reviewExpired: "The installation review expired. Inspect the installation again."
        case .installationChanged: "Proxyman changed after review. Inspect the updated installation before connecting."
        case .confirmationRequired: "Confirm this Proxyman build before connecting."
        }
    }
}

public protocol ProxymanInstallationManaging: Sendable {
    func inspect(applicationURL: URL) async throws -> ProxymanInstallationReview
    func approve(reviewID: UUID) async throws -> ApprovedProxymanInstallation
    func confirmAndApprove(reviewID: UUID) async throws -> ApprovedProxymanInstallation
    func connectionConfiguration(for approval: ApprovedProxymanInstallation) async throws -> MCPConnectionConfiguration
    func validatedApplicationURL(for approval: ApprovedProxymanInstallation) async throws -> URL
}
