import CryptoKit
import Foundation

/// Decode refusals are never repaired by dropping historical operations.
enum VerifiedAnnotationAuditError: Error, Equatable {
    case unsupportedSchema(Int)
    case malformedRecord
    case recordTooLarge
    case tooManyRecords
    case envelopeTooLarge
    case duplicateOperationID(UUID)
    case digestMismatch
    case wrongOwner
    case readerFeatureDisagreement
    /// A v2 (typed-edit) audit record exists but the manifest does not declare
    /// `verified-annotation.typed-edits.v1`.
    case typedEditsFeatureMissing
    /// The manifest declares `verified-annotation.typed-edits.v1` but no v2 audit record exists.
    case typedEditsFeatureWithoutRecords
}

extension VerifiedAnnotationAuditError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .typedEditsFeatureMissing:
            return "The workspace holds typed-edit verified annotation records but does not declare the reader feature that protects them."
        case .typedEditsFeatureWithoutRecords:
            return "The workspace declares the typed-edit verified annotation reader feature but holds no typed-edit records."
        default:
            return nil
        }
    }
}

/// The audit Body's field-class vocabulary. This file compiles into MacScopeAnalysisCore, which does not
/// contain `VerifiedFieldClass` (Services/VerifiedAnalysis, app target), so the closed set is declared here
/// with identical raw values; a test pins the two sets equal. `fieldClass` is written to the Body only for
/// the classes that postdate v1.
enum VerifiedAnnotationAuditFieldClass: String, Codable, CaseIterable, Equatable, Sendable {
    case name, comment, addressType, functionSignature

    /// True for the classes that use the v2 Body encoding (`addressType`, `functionSignature`).
    /// `name` and `comment` keep the v1 encoding exactly; one encoding exists per class.
    var usesTypedEditEncoding: Bool {
        switch self {
        case .name, .comment: return false
        case .addressType, .functionSignature: return true
        }
    }

    /// Ruling 9 (refined): true iff the only override fields that differ between `previous` and
    /// `new` are the ones this class owns. A missing override is the empty override.
    ///
    /// Owned fields (`AddressOverride`, Models/AnalysisModels+Overrides.swift):
    /// - `name`: `customName`
    /// - `comment`: `customComment`
    /// - `addressType`: `appliedTypeName`
    /// - `functionSignature`: `signature` and `ownReturnAuthorityFile` (the session-only authority
    ///   that `signature`'s `didSet` resets whenever the signature changes)
    /// Every other field (tag, colorTag, isData, switchHint, operandFormat, markAsProcedure,
    /// dataShape, isUndefined, patch, appendedExecutableCave, registerNames, stackLocals,
    /// localLabel) must be equal. Pure: S4 wires it into journal replay.
    func fieldClassMatches(previous: AddressOverride?, new: AddressOverride?) -> Bool {
        let old = previous ?? AddressOverride()
        var candidate = new ?? AddressOverride()
        switch self {
        case .name: candidate.customName = old.customName
        case .comment: candidate.customComment = old.customComment
        case .addressType: candidate.appliedTypeName = old.appliedTypeName
        case .functionSignature:
            // Assign the signature first: its didSet clears the authority, which is restored next.
            candidate.signature = old.signature
            candidate.ownReturnAuthorityFile = old.ownReturnAuthorityFile
        }
        return candidate == old
    }
}

/// Canonical encoding for this envelope. Foundation and CryptoKit only, so the type can live in
/// MacScopeAnalysisCore. A checksum provides integrity comparison, not authentication.
enum VerifiedAnnotationAuditCodec {
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try JSONDecoder().decode(type, from: data)
    }
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

/// Identity of an annotation projection (workspace, document, installation, revision, digest).
struct VerifiedAnnotationProjectionIdentity: Codable, Equatable, Hashable, Sendable {
    let workspaceID: UUID
    let documentID: UUID
    let installationID: UUID
    let revision: UInt64
    let digest: String
}

enum VerifiedAnnotationDecision: String, Codable, Sendable { case accepted, rejected }
/// The actual mechanical result of the operation. Never upgraded after the fact.
enum VerifiedAnnotationMechanicalResult: String, Codable, Sendable { case notVerified, candidateReadbackVerified }
enum VerifiedAnnotationPersistenceStatus: String, Codable, Sendable { case notApplicable, pendingFreshProcessCheckpoint }

/// Archived references only; these values do not grant live evidence admission.
struct VerifiedAnnotationEvidenceLink: Codable, Equatable, Sendable {
    let evidenceID: UUID
    let preconditionDigest: String
}

/// A reference to a separate checkpoint report for an exact saved projection/cut.
/// It does not upgrade the immutable record's pending-checkpoint status.
struct VerifiedAnnotationCheckpointReference: Codable, Equatable, Sendable {
    let reportID: UUID
    let projection: VerifiedAnnotationProjectionIdentity
    let packageDigest: String
}

struct VerifiedAnnotationAuditRecord: Codable, Equatable, Sendable {
    /// v1 Body domain. `name` and `comment` records use it with no `fieldClass` key, byte-identical to before v2.
    static let domain = "com.jeff.macscope.verified-annotation-audit.record.v1"
    /// v2 Body domain for `addressType` and `functionSignature`: v1 with `.v1` replaced by `.v2`. Carries `fieldClass`.
    static let domainV2 = "com.jeff.macscope.verified-annotation-audit.record.v2"

    struct Body: Codable, Equatable, Sendable {
        let domain: String
        let operationID: UUID
        /// Immutable request digest, lowercase hex SHA-256.
        let requestDigest: String
        let decision: VerifiedAnnotationDecision
        let before: VerifiedAnnotationProjectionIdentity
        let after: VerifiedAnnotationProjectionIdentity?
        let mechanical: VerifiedAnnotationMechanicalResult
        let persistence: VerifiedAnnotationPersistenceStatus
        let failure: String?
        let recovery: String?
        /// Milliseconds since 1970.
        let recordedAtMilliseconds: Int64
        let nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink]
        let checkpointReferences: [VerifiedAnnotationCheckpointReference]
        /// Present (v2 domain) only for the classes that postdate v1; omitted from the bytes when nil.
        let fieldClass: VerifiedAnnotationAuditFieldClass?
    }
    let body: Body
    /// True when this record uses the v2 Body encoding, which needs the typed-edits reader feature.
    var usesTypedEditEncoding: Bool { body.domain == Self.domainV2 }
    /// The recorded class, or nil for a v1 record (name or comment; v1 never recorded which).
    var recordedFieldClass: VerifiedAnnotationAuditFieldClass? { body.fieldClass }
    let canonicalBytes: Data
    let digest: String
    var operationID: UUID { body.operationID }

    init(operationID: UUID, requestDigest: String, decision: VerifiedAnnotationDecision,
         before: VerifiedAnnotationProjectionIdentity, after: VerifiedAnnotationProjectionIdentity?,
         mechanical: VerifiedAnnotationMechanicalResult, persistence: VerifiedAnnotationPersistenceStatus,
         failure: String? = nil, recovery: String? = nil, recordedAtMilliseconds: Int64,
         nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink],
         checkpointReferences: [VerifiedAnnotationCheckpointReference] = [],
         fieldClass: VerifiedAnnotationAuditFieldClass? = nil) throws {
        // Exactly one encoding per class: name, comment and nil stay v1 with no key.
        let typed = fieldClass?.usesTypedEditEncoding == true
        try self.init(body: Body(domain: typed ? Self.domainV2 : Self.domain, operationID: operationID, requestDigest: requestDigest,
            decision: decision, before: before, after: after, mechanical: mechanical, persistence: persistence,
            failure: failure, recovery: recovery, recordedAtMilliseconds: recordedAtMilliseconds,
            nativeEvidenceLinks: nativeEvidenceLinks, checkpointReferences: checkpointReferences,
            fieldClass: typed ? fieldClass : nil))
    }

    init(body: Body) throws {
        try Self.validate(body)
        let bytes: Data
        do { bytes = try VerifiedAnnotationAuditCodec.encode(body) } catch { throw VerifiedAnnotationAuditError.malformedRecord }
        guard bytes.count <= VerifiedAnnotationAuditEnvelope.maximumRecordBytes else {
            throw VerifiedAnnotationAuditError.recordTooLarge
        }
        self.body = body
        canonicalBytes = bytes
        digest = VerifiedAnnotationAuditCodec.sha256Hex(bytes)
    }

    private enum CodingKeys: String, CodingKey { case canonicalBytes, digest }
    init(from decoder: Decoder) throws {
        do {
            try VerifiedAnnotationAuditEnvelope.requireKeys(decoder, ["canonicalBytes", "digest"])
            let values = try decoder.container(keyedBy: CodingKeys.self)
            // Check base64 size before allocating decoded record bytes or computing a checksum.
            let encoded = try values.decode(String.self, forKey: .canonicalBytes)
            guard encoded.utf8.count <= ((VerifiedAnnotationAuditEnvelope.maximumRecordBytes + 2) / 3) * 4 else {
                throw VerifiedAnnotationAuditError.recordTooLarge
            }
            guard let bytes = Data(base64Encoded: encoded), !bytes.isEmpty else {
                throw VerifiedAnnotationAuditError.malformedRecord
            }
            guard bytes.count <= VerifiedAnnotationAuditEnvelope.maximumRecordBytes else {
                throw VerifiedAnnotationAuditError.recordTooLarge
            }
            let checksum = try values.decode(String.self, forKey: .digest)
            guard VerifiedAnnotationAuditCodec.isSHA256(checksum),
                  VerifiedAnnotationAuditCodec.sha256Hex(bytes) == checksum else {
                throw VerifiedAnnotationAuditError.digestMismatch
            }
            let decoded = try VerifiedAnnotationAuditCodec.decode(Body.self, from: bytes)
            // Canonical equality refuses duplicate keys, unknown fields and any other spelling
            // that decoding would otherwise silently discard.
            guard try VerifiedAnnotationAuditCodec.encode(decoded) == bytes else {
                throw VerifiedAnnotationAuditError.malformedRecord
            }
            try Self.validate(decoded)
            body = decoded
            canonicalBytes = bytes
            digest = checksum
        } catch let error as VerifiedAnnotationAuditError { throw error }
        catch { throw VerifiedAnnotationAuditError.malformedRecord }
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(canonicalBytes, forKey: .canonicalBytes)
        try values.encode(digest, forKey: .digest)
    }

    private static func validate(_ body: Body) throws {
        let bad = VerifiedAnnotationAuditError.malformedRecord
        switch body.domain {
        case domain: guard body.fieldClass == nil else { throw bad }
        case domainV2: guard body.fieldClass?.usesTypedEditEncoding == true else { throw bad }
        default: throw bad
        }
        guard VerifiedAnnotationAuditCodec.isSHA256(body.requestDigest),
              VerifiedAnnotationAuditCodec.isSHA256(body.before.digest),
              body.failure.map({ $0.utf8.count <= 4096 }) ?? true,
              body.recovery.map({ $0.utf8.count <= 4096 }) ?? true,
              body.nativeEvidenceLinks.count <= AnalystFindingRecord.maximumCitations,
              body.checkpointReferences.count <= AnalystFindingRecord.maximumCitations,
              Set(body.nativeEvidenceLinks.map(\.evidenceID)).count == body.nativeEvidenceLinks.count,
              body.nativeEvidenceLinks.allSatisfy({ VerifiedAnnotationAuditCodec.isSHA256($0.preconditionDigest) }),
              Set(body.checkpointReferences.map(\.reportID)).count == body.checkpointReferences.count else { throw bad }
        if body.decision == .accepted {
            guard let after = body.after,
                  after.workspaceID == body.before.workspaceID, after.documentID == body.before.documentID,
                  after.installationID == body.before.installationID,
                  body.before.revision < UInt64.max, after.revision == body.before.revision + 1,
                  VerifiedAnnotationAuditCodec.isSHA256(after.digest),
                  body.mechanical == .candidateReadbackVerified,
                  body.persistence == .pendingFreshProcessCheckpoint, body.failure == nil,
                  !body.nativeEvidenceLinks.isEmpty else { throw bad }
        } else {
            guard body.after == nil, body.mechanical == .notVerified, body.persistence == .notApplicable,
                  body.failure?.isEmpty == false, body.checkpointReferences.isEmpty else { throw bad }
        }
        for checkpoint in body.checkpointReferences {
            guard checkpoint.projection == body.after, VerifiedAnnotationAuditCodec.isSHA256(checkpoint.packageDigest) else {
                throw bad
            }
        }
    }
}

/// Historical annotation receipts, inside the native package transaction. A checksum provides
/// integrity comparison, not authentication. Reopening never turns these references into live evidence.
struct VerifiedAnnotationAuditEnvelope: Codable, Equatable, Sendable {
    // Existing native authored-history budgets: AnalystFindingEnvelope (256 / 8 MiB / 24 MiB).
    static let maximumRecords = AnalystFindingEnvelope.maximumRecords
    static let maximumRecordBytes = AnalystFindingEnvelope.maximumRecordBytes
    static let maximumEncodedBytes = AnalystFindingEnvelope.maximumEncodedBytes
    static let empty = Self(records: [])
    let records: [VerifiedAnnotationAuditRecord]
    var isEmpty: Bool { records.isEmpty }
    /// True when any record uses the v2 Body encoding; the manifest then declares the typed-edits feature.
    var usesTypedEditEncoding: Bool { records.contains { $0.usesTypedEditEncoding } }

    private struct Wire: Encodable {
        let schemaVersion: Int
        let records: [VerifiedAnnotationAuditRecord]
    }
    private init(records: [VerifiedAnnotationAuditRecord]) { self.records = records }

    /// VA3b seam: prepare the candidate value before entering the joined owner publication.
    /// This never mutates accepted memory or silently evicts a historical operation.
    func appending(_ record: VerifiedAnnotationAuditRecord, workspaceID: UUID, documentID: UUID) throws -> Self {
        guard records.count < Self.maximumRecords else { throw VerifiedAnnotationAuditError.tooManyRecords }
        let candidate = Self(records: records + [record])
        try candidate.validate(workspaceID: workspaceID, documentID: documentID)
        return candidate
    }

    func validate(workspaceID: UUID, documentID: UUID) throws {
        try validateBoundsAndIDs()
        guard records.allSatisfy({ $0.body.before.workspaceID == workspaceID && $0.body.before.documentID == documentID }) else {
            throw VerifiedAnnotationAuditError.wrongOwner
        }
    }

    private func validateBoundsAndIDs() throws {
        guard records.count <= Self.maximumRecords else { throw VerifiedAnnotationAuditError.tooManyRecords }
        var ids = Set<UUID>()
        for record in records {
            guard ids.insert(record.operationID).inserted else {
                throw VerifiedAnnotationAuditError.duplicateOperationID(record.operationID)
            }
        }
        guard try VerifiedAnnotationAuditCodec.encode(Wire(schemaVersion: 1, records: records)).count <= Self.maximumEncodedBytes else {
            throw VerifiedAnnotationAuditError.envelopeTooLarge
        }
    }

    private enum CodingKeys: String, CodingKey { case schemaVersion, records }
    init(from decoder: Decoder) throws {
        do {
            try Self.requireKeys(decoder, ["schemaVersion", "records"])
            let values = try decoder.container(keyedBy: CodingKeys.self)
            let version = try values.decode(Int.self, forKey: .schemaVersion)
            guard version == 1 else { throw VerifiedAnnotationAuditError.unsupportedSchema(version) }
            var items = try values.nestedUnkeyedContainer(forKey: .records)
            var decoded: [VerifiedAnnotationAuditRecord] = []
            var byteCount = 0
            while !items.isAtEnd {
                guard decoded.count < Self.maximumRecords else { throw VerifiedAnnotationAuditError.tooManyRecords }
                let record = try items.decode(VerifiedAnnotationAuditRecord.self)
                byteCount += ((record.canonicalBytes.count + 2) / 3) * 4
                guard byteCount <= Self.maximumEncodedBytes else { throw VerifiedAnnotationAuditError.envelopeTooLarge }
                decoded.append(record)
            }
            records = decoded
            try validateBoundsAndIDs()
        } catch let error as VerifiedAnnotationAuditError { throw error }
        catch { throw VerifiedAnnotationAuditError.malformedRecord }
    }

    func encode(to encoder: Encoder) throws {
        try validateBoundsAndIDs()
        try Wire(schemaVersion: 1, records: records).encode(to: encoder)
    }

    fileprivate static func requireKeys(_ decoder: Decoder, _ keys: Set<String>) throws {
        struct Key: CodingKey {
            let stringValue: String
            let intValue: Int? = nil
            init?(stringValue: String) { self.stringValue = stringValue }
            init?(intValue: Int) { return nil }
        }
        let values = try decoder.container(keyedBy: Key.self)
        guard Set(values.allKeys.map(\.stringValue)) == keys else { throw VerifiedAnnotationAuditError.malformedRecord }
    }
}
