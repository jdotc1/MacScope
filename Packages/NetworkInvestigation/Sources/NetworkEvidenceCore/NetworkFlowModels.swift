import Foundation

public struct NetworkFlowReference: Codable, Sendable, Equatable, Hashable {
    public let connectionID: UUID
    public let batchID: UUID
    public let scopeID: UUID
    public let vendorFlowID: String
    public let identityDigest: String
    public init(connectionID: UUID, batchID: UUID, scopeID: UUID, vendorFlowID: String, identityDigest: String) {
        self.connectionID = connectionID; self.batchID = batchID; self.scopeID = scopeID
        self.vendorFlowID = vendorFlowID; self.identityDigest = identityDigest
    }
}

public enum NetworkSourceAttribution: Codable, Sendable, Equatable {
    case unknown
    /// Vendor metadata, not proof that the current MacScope binary generated this traffic.
    case vendorReported(name: String, processID: Int?)
}
public enum NetworkTLSVisibility: String, Codable, Sendable {
    case unknown, connectionMetadataOnly, plaintextHTTP, decryptedHTTP
}
public enum NetworkRuleInfluence: Codable, Sendable, Equatable {
    case unknown, possible, vendorReportedNone
    case vendorReportedApplied([String])
}
public enum NetworkBodyAvailability: String, Codable, Sendable {
    case notReported, absent, available, previewTruncated
}
public enum NetworkObservationLimitation: String, Codable, Sendable {
    case boundedSnapshot, limitReached, filtersAppliedLocally, captureSessionIdentityUnavailable
    case sourceAttributionUnverified, tlsVisibilityUnknown, ruleInfluenceUnknown
    case sensitiveContentOmitted, archiveVisibilityUnverified
}

public struct NetworkFlowSummary: Codable, Sendable, Equatable {
    public let reference: NetworkFlowReference
    public let requestTime: Date
    public let observedAt: Date
    public let method: String
    public let scheme: String
    public let host: String
    public let path: String
    /// Known effective destination port. Full URLs resolve their standard defaults; nil
    /// means standalone metadata did not establish a port and cannot supply an exact endpoint.
    public let port: Int?
    public let statusCode: Int?
    public let durationMilliseconds: Double?
    public let responseContentType: String?
    public let source: NetworkSourceAttribution
    public let tlsVisibility: NetworkTLSVisibility
    public let ruleInfluence: NetworkRuleInfluence
    public let bodyAvailability: NetworkBodyAvailability
    public init(reference: NetworkFlowReference, requestTime: Date, observedAt: Date,
                method: String, scheme: String, host: String, path: String, port: Int? = nil,
                statusCode: Int? = nil, durationMilliseconds: Double? = nil,
                responseContentType: String? = nil, source: NetworkSourceAttribution = .unknown,
                tlsVisibility: NetworkTLSVisibility = .unknown, ruleInfluence: NetworkRuleInfluence = .unknown,
                bodyAvailability: NetworkBodyAvailability = .notReported) {
        self.reference = reference; self.requestTime = requestTime; self.observedAt = observedAt
        self.method = method; self.scheme = scheme; self.host = host; self.path = path; self.port = port
        self.statusCode = statusCode; self.durationMilliseconds = durationMilliseconds
        self.responseContentType = responseContentType; self.source = source
        self.tlsVisibility = tlsVisibility; self.ruleInfluence = ruleInfluence; self.bodyAvailability = bodyAvailability
    }
}

public struct NetworkFlowDetail: Codable, Sendable, Equatable {
    public let summary: NetworkFlowSummary
    public let queryKeyNames: [String]
    public let responseFieldNames: [String]
    public let requestHeaderNames: [String]
    public let responseHeaderNames: [String]
    public let limitations: [NetworkObservationLimitation]
    public init(summary: NetworkFlowSummary, queryKeyNames: [String] = [], responseFieldNames: [String] = [],
                requestHeaderNames: [String] = [], responseHeaderNames: [String] = [],
                limitations: [NetworkObservationLimitation] = []) {
        self.summary = summary; self.queryKeyNames = queryKeyNames; self.responseFieldNames = responseFieldNames
        self.requestHeaderNames = requestHeaderNames; self.responseHeaderNames = responseHeaderNames
        self.limitations = limitations
    }
}

public enum ProxymanRecordingState: String, Codable, Sendable { case recording, stopped, unknown }
public enum ProxymanKnowledgeState: String, Codable, Sendable { case yes, no, unknown }
public struct ProxymanEnvironmentStatus: Codable, Sendable, Equatable {
    public let connectionID: UUID
    public let observedAt: Date
    public let version: String?
    public let build: String?
    public let recording: ProxymanRecordingState
    public let sslProxying: ProxymanKnowledgeState
    public let certificateTrusted: ProxymanKnowledgeState
    public let limitations: [NetworkObservationLimitation]
    public init(connectionID: UUID, observedAt: Date, version: String? = nil, build: String? = nil,
                recording: ProxymanRecordingState = .unknown, sslProxying: ProxymanKnowledgeState = .unknown,
                certificateTrusted: ProxymanKnowledgeState = .unknown,
                limitations: [NetworkObservationLimitation] = []) {
        self.connectionID = connectionID; self.observedAt = observedAt; self.version = version; self.build = build
        self.recording = recording; self.sslProxying = sslProxying; self.certificateTrusted = certificateTrusted
        self.limitations = limitations
    }
}
