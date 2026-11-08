import Foundation

enum AIRSEvidenceError: Error, Equatable, LocalizedError {
    case unsupportedSchema(Int)
    case bounds
    case invalidRecord
    case wrongWorkspace

    var errorDescription: String? {
        switch self {
        case .unsupportedSchema(let version): "AIRS evidence schema \(version) requires a newer reader."
        case .bounds: "AIRS evidence could not be retained. The workspace limit is 256 records and 24 MiB, with at most 1 MiB per imported finding. Existing evidence is unchanged. Save this workspace and start a new workspace to retain more evidence."
        case .invalidRecord: "The saved AIRS evidence record is invalid."
        case .wrongWorkspace: "The AIRS evidence belongs to a different workspace."
        }
    }
}

/// Immutable source observations. Binding is a live projection, never persisted authority.
struct AIRSEvidenceRecord: Codable, Equatable, Identifiable, Sendable {
    enum Source: String, Codable, Sendable { case nativeUnwind, importedHandoff }
    let id: UUID
    let workspaceID: UUID
    let source: Source
    let sourceImageID: UUID?
    let nativeRequestID: UUID?
    let createdAt: Date
    let rawPayload: Data

    func validate(workspaceID: UUID) throws {
        guard self.workspaceID == workspaceID else { throw AIRSEvidenceError.wrongWorkspace }
        guard !rawPayload.isEmpty, rawPayload.count <= AIRSEvidenceEnvelope.maximumPayloadBytes,
              createdAt.timeIntervalSinceReferenceDate.isFinite else { throw AIRSEvidenceError.bounds }
        switch source {
        case .nativeUnwind:
            guard sourceImageID != nil, nativeRequestID != nil else { throw AIRSEvidenceError.invalidRecord }
        case .importedHandoff:
            guard nativeRequestID == nil else { throw AIRSEvidenceError.invalidRecord }
            guard rawPayload.count <= 1_048_576 else { throw AIRSEvidenceError.bounds }
        }
    }
}

struct AIRSEvidenceEnvelope: Codable, Equatable, Sendable {
    static let maximumRecords = 256
    static let maximumPayloadBytes = 24 * 1_024 * 1_024
    let schemaVersion: Int
    private(set) var records: [AIRSEvidenceRecord]

    init(schemaVersion: Int = 1, records: [AIRSEvidenceRecord] = []) {
        self.schemaVersion = schemaVersion
        self.records = records
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, records
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let version = try values.decode(Int.self, forKey: .schemaVersion)
        guard version == 1 else { throw AIRSEvidenceError.unsupportedSchema(version) }
        self.init(schemaVersion: version, records: try values.decode([AIRSEvidenceRecord].self, forKey: .records))
    }

    func validate(workspaceID: UUID) throws {
        guard schemaVersion == 1 else { throw AIRSEvidenceError.unsupportedSchema(schemaVersion) }
        guard records.count <= Self.maximumRecords else { throw AIRSEvidenceError.bounds }
        var ids = Set<UUID>()
        var requests = Set<UUID>()
        var total = 0
        for record in records {
            guard ids.insert(record.id).inserted else { throw AIRSEvidenceError.invalidRecord }
            if let request = record.nativeRequestID, !requests.insert(request).inserted {
                throw AIRSEvidenceError.invalidRecord
            }
            guard record.rawPayload.count <= Self.maximumPayloadBytes - total else { throw AIRSEvidenceError.bounds }
            total += record.rawPayload.count
            try record.validate(workspaceID: workspaceID)
        }
    }

    /// Same records and exact payload bytes, owned by a forked workspace identity.
    func rebound(to workspaceID: UUID) -> AIRSEvidenceEnvelope {
        AIRSEvidenceEnvelope(schemaVersion: schemaVersion, records: records.map {
            AIRSEvidenceRecord(id: $0.id, workspaceID: workspaceID, source: $0.source,
                sourceImageID: $0.sourceImageID, nativeRequestID: $0.nativeRequestID,
                createdAt: $0.createdAt, rawPayload: $0.rawPayload)
        })
    }

    mutating func append(_ record: AIRSEvidenceRecord, workspaceID: UUID) throws {
        var candidate = self
        candidate.records.append(record)
        try candidate.validate(workspaceID: workspaceID)
        self = candidate
    }
}

struct AIRSEvidenceBinding {
    let binary: BinaryImage?
    let unresolvedReason: String?
    var isResolved: Bool { binary != nil && unresolvedReason == nil }
}

extension AIRSEvidenceRecord {
    private enum CodingKeys: String, CodingKey {
        case id, workspaceID, source, sourceImageID, nativeRequestID, createdAt, rawPayload
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        self.init(id: try values.decode(UUID.self, forKey: .id),
            workspaceID: try values.decode(UUID.self, forKey: .workspaceID),
            source: try values.decode(Source.self, forKey: .source),
            sourceImageID: try values.decodeIfPresent(UUID.self, forKey: .sourceImageID),
            nativeRequestID: try values.decodeIfPresent(UUID.self, forKey: .nativeRequestID),
            createdAt: Date(timeIntervalSinceReferenceDate: try values.decode(Double.self, forKey: .createdAt)),
            rawPayload: try values.decode(Data.self, forKey: .rawPayload))
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(id, forKey: .id)
        try values.encode(workspaceID, forKey: .workspaceID)
        try values.encode(source, forKey: .source)
        try values.encodeIfPresent(sourceImageID, forKey: .sourceImageID)
        try values.encodeIfPresent(nativeRequestID, forKey: .nativeRequestID)
        // Preserve the captured timestamp exactly; the outer manifest date formatter
        // rounds ordinary Date fields to milliseconds.
        try values.encode(createdAt.timeIntervalSinceReferenceDate, forKey: .createdAt)
        try values.encode(rawPayload, forKey: .rawPayload)
    }
}
