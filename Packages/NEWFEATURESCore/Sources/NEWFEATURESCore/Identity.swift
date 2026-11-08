import Foundation

public enum NEWFEATURESError: Error, Equatable, Sendable {
    case invalidImageIdentity
    case invalidPolicy
    case malformedGraph(String)
    case malformedFact(String)
    case sourceChanged
    case operationAlreadyActive
    case nativeWorkerNeedsRecovery
}

/// A value projection of Phase2 identity. Decoding this value confers no app authority.
/// No defaults remint missing identity dimensions. Nil slice preserves the ledger's
/// selection exactly and does not establish that an outer container was thin.
public struct NEWFEATURESImageKey: Hashable, Codable, Sendable, Comparable {
    public let documentInstance: UUID
    public let workspaceInstance: UUID
    public let slot: Int
    public let binaryID: UUID
    public let ownerGeneration: UInt64
    public let architecture: String
    public let sliceIndex: Int?
    public let sha256: String
    public var contentSHA256: String { sha256 }
    public let analysisRevision: UInt64
    public let analysisInputFingerprintSHA256: String

    public init(
        documentInstance: UUID, workspaceInstance: UUID, slot: Int, binaryID: UUID,
        ownerGeneration: UInt64, architecture: String, sliceIndex: Int?,
        sha256: String, analysisRevision: UInt64, analysisInputFingerprintSHA256: String
    ) throws {
        guard slot >= 0, ownerGeneration > 0, analysisRevision > 0,
              sliceIndex.map({ $0 >= 0 }) ?? true,
              !architecture.isEmpty, architecture.utf8.count <= 64,
              // Phase2 retains the loader's full architecture description, including
              // spaces in universal-slice qualifiers. Preserve it exactly as identity.
              architecture.utf8.contains(where: { $0 != 32 }),
              architecture.utf8.allSatisfy({ (32...126).contains($0) }),
              Self.isDigest(sha256), Self.isDigest(analysisInputFingerprintSHA256)
        else { throw NEWFEATURESError.invalidImageIdentity }
        self.documentInstance = documentInstance
        self.workspaceInstance = workspaceInstance
        self.slot = slot
        self.binaryID = binaryID
        self.ownerGeneration = ownerGeneration
        self.architecture = architecture
        self.sliceIndex = sliceIndex
        self.sha256 = sha256
        self.analysisRevision = analysisRevision
        self.analysisInputFingerprintSHA256 = analysisInputFingerprintSHA256
    }

    private static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case documentInstance, workspaceInstance, slot, binaryID, ownerGeneration,
             architecture, sliceIndex, sha256, analysisRevision, analysisInputFingerprintSHA256
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            documentInstance: c.decode(UUID.self, forKey: .documentInstance),
            workspaceInstance: c.decode(UUID.self, forKey: .workspaceInstance),
            slot: c.decode(Int.self, forKey: .slot),
            binaryID: c.decode(UUID.self, forKey: .binaryID),
            ownerGeneration: c.decode(UInt64.self, forKey: .ownerGeneration),
            architecture: c.decode(String.self, forKey: .architecture),
            sliceIndex: c.decodeIfPresent(Int.self, forKey: .sliceIndex),
            sha256: c.decode(String.self, forKey: .sha256),
            analysisRevision: c.decode(UInt64.self, forKey: .analysisRevision),
            analysisInputFingerprintSHA256: c.decode(String.self, forKey: .analysisInputFingerprintSHA256)
        )
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.documentInstance != rhs.documentInstance { return lhs.documentInstance.uuidString < rhs.documentInstance.uuidString }
        if lhs.workspaceInstance != rhs.workspaceInstance { return lhs.workspaceInstance.uuidString < rhs.workspaceInstance.uuidString }
        if lhs.slot != rhs.slot { return lhs.slot < rhs.slot }
        if lhs.binaryID != rhs.binaryID { return lhs.binaryID.uuidString < rhs.binaryID.uuidString }
        if lhs.ownerGeneration != rhs.ownerGeneration { return lhs.ownerGeneration < rhs.ownerGeneration }
        if lhs.architecture != rhs.architecture { return lhs.architecture < rhs.architecture }
        if lhs.sliceIndex != rhs.sliceIndex { return (lhs.sliceIndex ?? -1) < (rhs.sliceIndex ?? -1) }
        if lhs.sha256 != rhs.sha256 { return lhs.sha256 < rhs.sha256 }
        if lhs.analysisRevision != rhs.analysisRevision { return lhs.analysisRevision < rhs.analysisRevision }
        return lhs.analysisInputFingerprintSHA256 < rhs.analysisInputFingerprintSHA256
    }
}

public struct NEWFEATURESFunctionKey: Hashable, Codable, Sendable, Comparable {
    public let image: NEWFEATURESImageKey
    public let address: UInt64

    public init(image: NEWFEATURESImageKey, address: UInt64) {
        self.image = image
        self.address = address
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.image != rhs.image { return lhs.image < rhs.image }
        return lhs.address < rhs.address
    }
}

public enum NEWFEATURESFactSource: String, Codable, Sendable {
    case sourceBytes
    case symbolTable
    case sdkHeader
    case classMetadata
    case verifiedAnalysis
}

public struct NEWFEATURESProvenance: Codable, Hashable, Sendable {
    public let source: NEWFEATURESFactSource
    public let sourceID: String
    public let sourceSHA256: String
    public let observationAddress: UInt64?

    public init(
        source: NEWFEATURESFactSource,
        sourceID: String,
        sourceSHA256: String,
        observationAddress: UInt64? = nil
    ) throws {
        guard !sourceID.isEmpty, sourceID.utf8.count <= 256,
              sourceID.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 }),
              sourceSHA256.utf8.count == 64,
              sourceSHA256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw NEWFEATURESError.malformedFact("invalid provenance") }
        self.source = source
        self.sourceID = sourceID
        self.sourceSHA256 = sourceSHA256
        self.observationAddress = observationAddress
    }

    private enum CodingKeys: String, CodingKey {
        case source, sourceID, sourceSHA256, observationAddress
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            source: values.decode(NEWFEATURESFactSource.self, forKey: .source),
            sourceID: values.decode(String.self, forKey: .sourceID),
            sourceSHA256: values.decode(String.self, forKey: .sourceSHA256),
            observationAddress: values.decodeIfPresent(UInt64.self, forKey: .observationAddress)
        )
    }
}

/// Inert projection only. The app retains the Phase2 precondition in its own
/// admission envelope and rechecks it at publication. This is not a receipt.
public struct NEWFEATURESLedgerAdmission: Hashable, Sendable {
    public let image: NEWFEATURESImageKey
    public var workspaceInstance: UUID { image.workspaceInstance }
    public var ownerGeneration: UInt64 { image.ownerGeneration }
    public var analysisInputFingerprintSHA256: String { image.analysisInputFingerprintSHA256 }
    public var architecture: String { image.architecture }
    public var sliceIndex: Int? { image.sliceIndex }

    public init(image: NEWFEATURESImageKey) { self.image = image }
}

public struct NEWFEATURESReadBudget: Sendable, Equatable {
    public let maxFunctions: Int
    public let maxDepth: Int
    public let maxEdgeVisits: Int
    public let maxOutputBytesPerFunction: Int
    public let maxTotalUTF8Bytes: Int
    public let maxElapsedSeconds: Int

    public init(
        maxFunctions: Int = 96,
        maxDepth: Int = 5,
        maxEdgeVisits: Int = 20_000,
        maxOutputBytesPerFunction: Int = 128 * 1024,
        maxTotalUTF8Bytes: Int = 2 * 1024 * 1024,
        maxElapsedSeconds: Int = 20
    ) throws {
        guard (1...500).contains(maxFunctions), (0...16).contains(maxDepth),
              (1...200_000).contains(maxEdgeVisits),
              (1...1_048_576).contains(maxOutputBytesPerFunction),
              (1...2_621_440).contains(maxTotalUTF8Bytes),
              (1...300).contains(maxElapsedSeconds)
        else { throw NEWFEATURESError.invalidPolicy }
        self.maxFunctions = maxFunctions
        self.maxDepth = maxDepth
        self.maxEdgeVisits = maxEdgeVisits
        self.maxOutputBytesPerFunction = maxOutputBytesPerFunction
        self.maxTotalUTF8Bytes = maxTotalUTF8Bytes
        self.maxElapsedSeconds = maxElapsedSeconds
    }
}
