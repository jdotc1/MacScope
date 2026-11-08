import Foundation
import CryptoKit

/// Closed diagnostics: never include a vendor error, captured URL, body or credential.
public enum InvestigationError: String, Error, Codable, Sendable {
    case invalidIdentity, invalidInput, bounds, staleAuthority, notAuthorized, closed
    case unknownHandle, expiredHandle, wrongOperation, unsupportedProvider, missingEvidence
    case invalidReport, unknownSchema, fileExists, unsafeFile, fileChanged, ioFailure
    case cancellation, evidenceCoverageUnverified, unsupportedExperiment, evidenceSealed, auditPersistenceFailed
}

public enum InvestigationDigest {
    public static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    public static func isValid(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

public enum InvestigationText {
    /// Display-only text. This is not a promise that arbitrary text is free of secrets.
    public static func bounded(_ value: String, bytes: Int = 256) -> String {
        let filtered = String(value.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
                && !(0x202A...0x202E).contains($0.value)
                && !(0x2066...0x2069).contains($0.value)
        })
        var result = ""
        for character in filtered {
            guard result.utf8.count + String(character).utf8.count <= bytes else { break }
            result.append(character)
        }
        return result
    }
    public static func isBounded(_ value: String, bytes: Int) -> Bool {
        value.utf8.count <= bytes && bounded(value, bytes: bytes) == value
    }
}

/// Durable association plus current runtime authority. Codable does not confer execution authority.
public struct WorkspaceInvestigationIdentity: Codable, Hashable, Sendable {
    public let workspaceID: UUID
    public let documentID: UUID
    public let installationID: UUID
    public let binaryID: UUID
    public let imageSlot: Int
    public let architecture: String
    public let sliceIndex: Int?
    public let binarySHA256: String
    public let analysisGenerationID: UUID
    public let analysisSHA256: String
    public let nativeReadIdentitySHA256: String?

    public init(workspaceID: UUID, documentID: UUID, installationID: UUID, binaryID: UUID,
                imageSlot: Int, architecture: String, sliceIndex: Int? = nil,
                binarySHA256: String, analysisGenerationID: UUID, analysisSHA256: String,
                nativeReadIdentitySHA256: String? = nil) throws {
        self.workspaceID = workspaceID; self.documentID = documentID
        self.installationID = installationID; self.binaryID = binaryID
        self.imageSlot = imageSlot; self.architecture = architecture; self.sliceIndex = sliceIndex
        self.binarySHA256 = binarySHA256; self.analysisGenerationID = analysisGenerationID
        self.analysisSHA256 = analysisSHA256
        self.nativeReadIdentitySHA256 = nativeReadIdentitySHA256
        try validate()
    }
    public func validate() throws {
        guard imageSlot >= 0, sliceIndex.map({ $0 >= 0 }) ?? true,
              !architecture.isEmpty, InvestigationText.isBounded(architecture, bytes: 64),
              InvestigationDigest.isValid(binarySHA256), InvestigationDigest.isValid(analysisSHA256),
              nativeReadIdentitySHA256.map(InvestigationDigest.isValid) ?? true,
              [workspaceID, documentID, installationID, binaryID, analysisGenerationID]
                .allSatisfy({ $0 != UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) }) else {
            throw InvestigationError.invalidIdentity
        }
    }
    /// Reopened/forked reports can be associated, but this does not restore a grant.
    public func hasSameDurableTarget(as other: Self) -> Bool {
        workspaceID == other.workspaceID && documentID == other.documentID
            && binaryID == other.binaryID && imageSlot == other.imageSlot
            && architecture == other.architecture && sliceIndex == other.sliceIndex
            && binarySHA256 == other.binarySHA256
    }
}

public struct StaticCodeReference: Codable, Hashable, Sendable, Identifiable {
    public let id: UUID
    public let binarySHA256: String
    public let imageSlot: Int
    public let address: UInt64
    public let functionAddress: UInt64?
    public let functionName: String?
    public let source: StaticEvidenceKind
    public init(id: UUID = UUID(), binarySHA256: String, imageSlot: Int, address: UInt64,
                functionAddress: UInt64? = nil, functionName: String? = nil, source: StaticEvidenceKind) {
        self.id = id; self.binarySHA256 = binarySHA256; self.imageSlot = imageSlot
        self.address = address; self.functionAddress = functionAddress
        self.functionName = functionName.map { InvestigationText.bounded($0, bytes: 256) }
        self.source = source
    }
}

public enum StaticEvidenceKind: String, Codable, Sendable {
    case stringLiteral, symbol, objectiveCSelector, decompiledInterpretation, crossReference, responseKey
}

/// Endpoint structure only. No raw binary string, query value, credential or pseudocode is retained.
public struct StaticEndpointCandidate: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public let reference: StaticCodeReference
    public let host: String?
    public let path: String?
    public let method: String?
    public let responseFieldNames: [String]
    public let scheme: String?
    public let port: Int?
    public init(id: UUID = UUID(), reference: StaticCodeReference, host: String? = nil,
                path: String? = nil, method: String? = nil, responseFieldNames: [String] = [],
                scheme: String? = nil, port: Int? = nil) {
        self.id = id; self.reference = reference; self.host = host; self.path = path
        self.method = method; self.responseFieldNames = responseFieldNames
        self.scheme = scheme; self.port = port
    }
}

public struct StaticCallEdge: Codable, Hashable, Sendable {
    public let caller: UInt64
    public let callee: UInt64
    public init(caller: UInt64, callee: UInt64) { self.caller = caller; self.callee = callee }
}

public struct NetworkStaticSnapshot: Codable, Equatable, Sendable {
    public let identity: WorkspaceInvestigationIdentity
    public let candidates: [StaticEndpointCandidate]
    public let callEdges: [StaticCallEdge]
    public let isComplete: Bool
    public init(identity: WorkspaceInvestigationIdentity, candidates: [StaticEndpointCandidate],
                callEdges: [StaticCallEdge] = [], isComplete: Bool = false) throws {
        self.identity = identity; self.candidates = candidates; self.callEdges = callEdges
        self.isComplete = isComplete
        try validate()
    }
    public func validate() throws {
        try identity.validate()
        guard candidates.count <= 512, callEdges.count <= 4096,
              Set(candidates.map(\.id)).count == candidates.count else { throw InvestigationError.bounds }
        for candidate in candidates {
            guard candidate.reference.binarySHA256 == identity.binarySHA256,
                  candidate.reference.imageSlot == identity.imageSlot,
                  candidate.scheme.map(ProxymanPrivacy.isSupportedScheme) ?? true,
                  candidate.port.map({ (1...65535).contains($0) }) ?? true,
                  candidate.host.map({ Self.isHost($0) }) ?? true,
                  candidate.path.map({ $0.hasPrefix("/") && !$0.contains("?")
                      && !$0.contains("#") && InvestigationText.isBounded($0, bytes: 512) }) ?? true,
                  candidate.method.map({ ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","CONNECT","TRACE"].contains($0) }) ?? true,
                  candidate.responseFieldNames.count <= 32,
                  candidate.responseFieldNames.allSatisfy(Self.isFieldName),
                  candidate.reference.functionName.map({ InvestigationText.isBounded($0, bytes: 256) }) ?? true
            else { throw InvestigationError.invalidInput }
        }
    }
    public static func isHost(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, value == value.lowercased(),
              !value.hasPrefix("."), !value.hasSuffix("."), !value.contains("..") else { return false }
        return value.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 46 }
    }
    public static func isFieldName(_ value: String) -> Bool {
        ProxymanPrivacy.isSafeFieldName(value)
    }
}

public enum RuntimeObservationKind: String, Codable, Sendable {
    case stoppedFrame, functionCall, userAction, errorBranch
}

public struct NetworkRuntimeReference: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public let identity: WorkspaceInvestigationIdentity
    public let debuggerSessionID: UUID
    public let processID: Int
    public let capturedAt: Date
    public let functionAddress: UInt64?
    public let kind: RuntimeObservationKind
    /// App-correlated trace marker; never inferred solely from timestamp or process display name.
    public let flowIdentityDigest: String?
    public init(id: UUID = UUID(), identity: WorkspaceInvestigationIdentity, debuggerSessionID: UUID,
                processID: Int, capturedAt: Date, functionAddress: UInt64?, kind: RuntimeObservationKind,
                flowIdentityDigest: String? = nil) {
        self.id = id; self.identity = identity; self.debuggerSessionID = debuggerSessionID
        self.processID = processID; self.capturedAt = capturedAt; self.functionAddress = functionAddress
        self.kind = kind; self.flowIdentityDigest = flowIdentityDigest
    }
}

public enum NetworkEvidenceStrength: String, Codable, CaseIterable, Sendable {
    case directlyObserved, stronglySupported, plausibleHypothesis, weakAssociation
    case contradicted, insufficientEvidence
}

public enum NetworkCorrelationBasis: String, Codable, Sendable {
    case exactHostAndPath, hostOnly, pathOnly, methodAgreement, methodConflict
    case responseFieldOverlap, staticCrossReference, runtimeFunctionObservation
    case explicitRuntimeFlowLink, temporalAssociation, upstreamCaller
}

public struct NetworkCorrelationFinding: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public let flow: NetworkFlowReference
    public let staticReference: StaticCodeReference
    public let runtimeIDs: [UUID]
    public let strength: NetworkEvidenceStrength
    public let basis: [NetworkCorrelationBasis]
    public let explanation: String
    public let limitations: [String]
    public init(id: UUID = UUID(), flow: NetworkFlowReference, staticReference: StaticCodeReference,
                runtimeIDs: [UUID], strength: NetworkEvidenceStrength, basis: [NetworkCorrelationBasis],
                explanation: String, limitations: [String]) {
        self.id = id; self.flow = flow; self.staticReference = staticReference
        self.runtimeIDs = runtimeIDs; self.strength = strength; self.basis = basis
        self.explanation = explanation; self.limitations = limitations
    }
}

public struct NetworkHypothesis: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public let statement: String
    public let supportingFindingIDs: [UUID]
    public let requiredObservation: String
    public init(id: UUID = UUID(), statement: String, supportingFindingIDs: [UUID],
                requiredObservation: String) {
        self.id = id; self.statement = statement; self.supportingFindingIDs = supportingFindingIDs
        self.requiredObservation = requiredObservation
    }
}

public struct NetworkCorrelationResult: Codable, Equatable, Sendable {
    public let findings: [NetworkCorrelationFinding]
    public let hypotheses: [NetworkHypothesis]
    public let limitations: [String]
    public init(findings: [NetworkCorrelationFinding], hypotheses: [NetworkHypothesis], limitations: [String]) {
        self.findings = findings; self.hypotheses = hypotheses; self.limitations = limitations
    }
}

public enum NetworkInvestigationState: String, Codable, Sendable {
    case prepared, authorized, querying, observationsAvailable, noMatchingObservations, revoked, closed, historical
}

public enum NetworkSourceFreshness: String, Codable, Sendable {
    case liveReferenceUnverified, historicalRequiresReauthorization, missingArtifact, changedArtifact, artifactIntegrityVerified
}

public struct NetworkInvestigationSnapshot: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public let identity: WorkspaceInvestigationIdentity
    public let question: String
    public let state: NetworkInvestigationState
    public let endpoints: [StaticEndpointCandidate]
    public let observations: [NetworkFlowSummary]
    public let correlation: NetworkCorrelationResult?
    public let status: ProxymanEnvironmentStatus?
    public let freshness: NetworkSourceFreshness
    public init(id: UUID, identity: WorkspaceInvestigationIdentity, question: String,
                state: NetworkInvestigationState, endpoints: [StaticEndpointCandidate],
                observations: [NetworkFlowSummary], correlation: NetworkCorrelationResult?,
                status: ProxymanEnvironmentStatus?, freshness: NetworkSourceFreshness) {
        self.id = id; self.identity = identity; self.question = question; self.state = state
        self.endpoints = endpoints; self.observations = observations; self.correlation = correlation
        self.status = status; self.freshness = freshness
    }
}
