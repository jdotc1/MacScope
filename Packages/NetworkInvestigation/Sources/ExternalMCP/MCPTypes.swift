import Foundation
import MCP

/// Protocol values are ephemeral, untrusted input. They are never authorization.
public typealias MCPJSONValue = MCP.Value

public enum MCPConnectionState: String, Codable, Sendable {
    case notConfigured, connecting, connected, degraded, disconnected, recovering
    case permissionDenied, unsupportedVersion, protocolError
}

public struct MCPConnectionSnapshot: Sendable, Equatable {
    public let connectionID: UUID?
    public let state: MCPConnectionState
    public let serverName: String?
    public let serverVersion: String?
    public let protocolVersion: String?
    public let toolCatalogRevision: UInt64
    public let diagnosticCode: String?

    public init(connectionID: UUID? = nil, state: MCPConnectionState = .notConfigured,
                serverName: String? = nil, serverVersion: String? = nil,
                protocolVersion: String? = nil, toolCatalogRevision: UInt64 = 0,
                diagnosticCode: String? = nil) {
        self.connectionID = connectionID; self.state = state
        self.serverName = serverName; self.serverVersion = serverVersion
        self.protocolVersion = protocolVersion; self.toolCatalogRevision = toolCatalogRevision
        self.diagnosticCode = diagnosticCode
    }
}

public struct MCPToolDescriptor: Sendable, Hashable {
    public let name: String
    public let inputSchema: MCPJSONValue
    public let outputSchema: MCPJSONValue?
    public let schemaDigest: String

    public init(name: String, inputSchema: MCPJSONValue, outputSchema: MCPJSONValue? = nil,
                schemaDigest: String) {
        self.name = name; self.inputSchema = inputSchema
        self.outputSchema = outputSchema; self.schemaDigest = schemaDigest
    }
}

/// Raw vendor output. Kept out of Codable persistence and minimized by the adapter.
public struct MCPToolOutcome: Sendable {
    public let connectionID: UUID
    public let toolName: String
    public let structuredContent: MCPJSONValue?
    public let textContent: [String]
    public let isError: Bool

    public init(connectionID: UUID, toolName: String, structuredContent: MCPJSONValue? = nil,
                textContent: [String] = [], isError: Bool = false) {
        self.connectionID = connectionID; self.toolName = toolName
        self.structuredContent = structuredContent; self.textContent = textContent
        self.isError = isError
    }
}

/// Error codes deliberately carry no vendor text, executable paths, or traffic.
public enum MCPClientError: String, Error, Sendable, Equatable {
    case invalidConfiguration, untrustedExecutable, permissionDenied
    case notConnected, connectionBusy, staleConnection, unsupportedProtocol, capabilityMissing
    case deadlineExceeded, cancelled, transportClosed, childExited, malformedMessage
    case responseTooLarge, backpressure, tooManyRequests, toolCatalogLimit, repeatedCursor
    case unknownTool, invalidArguments, unsupportedContent, serverError, protocolFailure
}

public struct MCPResourceLimits: Sendable {
    public let requestTimeout: TimeInterval
    public let maximumMessageBytes: Int
    public let maximumPendingRequests: Int
    public let maximumBufferedMessages: Int
    public let maximumTools: Int
    public let maximumToolPages: Int
    public let maximumJSONDepth: Int
    public let maximumJSONNodes: Int
    public let maximumFramesPerSecond: Int

    public init(requestTimeout: TimeInterval = 15, maximumMessageBytes: Int = 1_048_576,
                maximumPendingRequests: Int = 8, maximumBufferedMessages: Int = 16,
                maximumTools: Int = 256, maximumToolPages: Int = 8,
                maximumJSONDepth: Int = 48, maximumJSONNodes: Int = 16_384,
                maximumFramesPerSecond: Int = 256) {
        self.requestTimeout = requestTimeout; self.maximumMessageBytes = maximumMessageBytes
        self.maximumPendingRequests = maximumPendingRequests
        self.maximumBufferedMessages = maximumBufferedMessages
        self.maximumTools = maximumTools; self.maximumToolPages = maximumToolPages
        self.maximumJSONDepth = maximumJSONDepth; self.maximumJSONNodes = maximumJSONNodes
        self.maximumFramesPerSecond = maximumFramesPerSecond
    }

    func validate() throws {
        guard requestTimeout.isFinite, (0.02...120).contains(requestTimeout),
              (256...4_194_304).contains(maximumMessageBytes),
              (1...32).contains(maximumPendingRequests),
              (1...64).contains(maximumBufferedMessages),
              (1...1_024).contains(maximumTools), (1...32).contains(maximumToolPages),
              (2...64).contains(maximumJSONDepth), (32...65_536).contains(maximumJSONNodes),
              (16...4_096).contains(maximumFramesPerSecond)
        else { throw MCPClientError.invalidConfiguration }
    }
}

/// Created only after application-level installation and code-signature validation.
/// No shell is used. No inherited proxy variables or authentication tokens are passed.
public struct MCPConnectionConfiguration: Sendable {
    public let executableURL: URL
    public let expectedExecutableSHA256: String
    public let arguments: [String]
    public let environment: [String: String]
    public let limits: MCPResourceLimits

    public init(executableURL: URL, expectedExecutableSHA256: String,
                arguments: [String] = [], environment: [String: String]? = nil,
                limits: MCPResourceLimits = .init()) {
        self.executableURL = executableURL; self.expectedExecutableSHA256 = expectedExecutableSHA256
        self.arguments = arguments
        self.environment = environment ?? ["HOME": NSHomeDirectory(), "TMPDIR": NSTemporaryDirectory(),
                                           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"]
        self.limits = limits
    }

    func validate() throws {
        try limits.validate()
        let allowedEnvironment: Set<String> = ["HOME", "TMPDIR", "LANG", "LC_ALL"]
        guard executableURL.isFileURL, executableURL.path.hasPrefix("/"),
              expectedExecutableSHA256.count == 64,
              expectedExecutableSHA256.allSatisfy({ $0.isASCII && $0.isHexDigit }),
              arguments.count <= 16,
              arguments.allSatisfy({ $0.utf8.count <= 4_096 && !$0.contains("\0") }),
              Set(environment.keys).isSubset(of: allowedEnvironment),
              environment.values.allSatisfy({ $0.utf8.count <= 4_096 && !$0.contains("\0") })
        else { throw MCPClientError.invalidConfiguration }
    }
}

/// Owned by an app-mediated vendor adapter. Never expose it directly to a model worker.
public protocol ExternalMCPClient: Sendable {
    func connect(configuration: MCPConnectionConfiguration) async throws -> MCPConnectionSnapshot
    func discoverTools() async throws -> [MCPToolDescriptor]
    func invoke(tool: String, arguments: MCPJSONValue) async throws -> MCPToolOutcome
    func snapshot() async -> MCPConnectionSnapshot
    func disconnect() async
}
