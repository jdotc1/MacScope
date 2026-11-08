import CryptoKit
import Foundation

/// VA4 slice A: a pure, fresh-reader checkpoint. It judges a package the production reader has
/// already opened (`MacScopeDocumentPackage.openPackage`) against a caller-supplied expectation.
///
/// What this proves: the SAVED bytes carry the audit records and the annotation values the writer
/// claimed. What it does not prove: process isolation (the caller supplies the reader identity, and
/// `passed` stays false unless the reader process differs from the writer's), nor that the archived
/// projection stamp digest reproduces (a reopen mints a new installation ID, so that digest cannot
/// be reproduced; gating is field-level and stamp reproduction is informational only).
/// It writes nothing: the report is returned, never stored in the package.

// MARK: - Bounds

enum VerifiedCheckpointBounds {
    static let maximumOperations = 256
    static let maximumRequestFileBytes = 65_536
    static let maximumNameBytes = 256
    static let maximumTypeNameBytes = VerifiedFieldCodec.maximumTypeNameBytes
    static let maximumSignatureBytes = VerifiedFieldCodec.maximumSignatureBytes
    static let maximumCommentBytes = 2_048
    static let maximumDiagnosticBytes = 4_096
    static let maximumReportEntries = 256
    static let maximumNotes = 64
    static let maximumStringBytes = 4_096
}

// MARK: - Expectation

/// What the writer says it did. The audit record omits target, field and value, so a checkpoint
/// cannot confirm fields without this. Stored fields only: nothing here is inferred.
struct VerifiedCheckpointExpectation: Codable, Equatable, Sendable {
    /// Written for expectations whose operations are all name or comment (bytes unchanged since v1).
    static let currentSchemaVersion = 1
    /// Written only when at least one operation is typed (VA-SCOPE slice S5).
    static let typedSchemaVersion = 2
    static let supportedSchemaVersions: ClosedRange<Int> = 1...2

    struct Operation: Codable, Equatable, Sendable {
        let operationID: UUID
        /// Lowercase hex SHA-256 of the immutable request, as recorded by the writer.
        let requestDigest: String
        let decision: VerifiedAnnotationDecision
        /// `ImageSlot.rawValue` of the annotated image.
        let slot: Int
        let address: UInt64
        /// "name" or "comment".
        let field: String
        /// The value the request asked for.
        let requested: String
        /// The value that should be present if the operation did not take effect (nil = absent).
        let baseline: String?
        /// Optional lowercase hex SHA-256 of the target image bytes.
        let imageSHA256: String?
        /// Accepted-ordinal bookends from the writer's receipt.
        let beforeRevision: UInt64
        let afterRevision: UInt64?
        /// Schema 2, typed operations only: the `VerifiedFieldClass` raw value. Absent for name/comment.
        let fieldClass: String?
        /// Schema 2, typed operations only: lowercase hex SHA-256 of the UTF-8 bytes of `requested`.
        let requestedDigest: String?
        /// Schema 2, typed operations only: true when the edit erased the value. Written only when true
        /// (absent otherwise, so existing bytes are unchanged). With it, `requested` is the empty string
        /// and `baseline` is the value that was erased.
        let erase: Bool?

        init(operationID: UUID, requestDigest: String, decision: VerifiedAnnotationDecision, slot: Int,
             address: UInt64, field: String, requested: String, baseline: String?, imageSHA256: String?,
             beforeRevision: UInt64, afterRevision: UInt64?, fieldClass: String? = nil,
             requestedDigest: String? = nil, erase: Bool? = nil) {
            self.operationID = operationID; self.requestDigest = requestDigest; self.decision = decision
            self.slot = slot; self.address = address; self.field = field; self.requested = requested
            self.baseline = baseline; self.imageSHA256 = imageSHA256; self.beforeRevision = beforeRevision
            self.afterRevision = afterRevision; self.fieldClass = fieldClass
            self.requestedDigest = requestedDigest; self.erase = erase
        }

        /// A typed (address type) operation; `field` and `fieldClass` are both the class raw value and
        /// `requestedDigest` is computed from `requested`.
        static func addressType(operationID: UUID, requestDigest: String, decision: VerifiedAnnotationDecision,
                                slot: Int, address: UInt64, requested: String, baseline: String?,
                                imageSHA256: String? = nil, beforeRevision: UInt64,
                                afterRevision: UInt64?, erase: Bool = false) -> Self {
            typed(.addressType, operationID: operationID, requestDigest: requestDigest, decision: decision,
                  slot: slot, address: address, requested: requested, baseline: baseline,
                  imageSHA256: imageSHA256, beforeRevision: beforeRevision, afterRevision: afterRevision,
                  erase: erase)
        }

        /// A typed (function signature) operation. `requested` and `baseline` are S1 canonical signature
        /// text (`VerifiedFieldCodec.canonicalSignature`). For an erase pass `requested: ""` and `erase: true`.
        static func functionSignature(operationID: UUID, requestDigest: String, decision: VerifiedAnnotationDecision,
                                      slot: Int, address: UInt64, requested: String, baseline: String?,
                                      imageSHA256: String? = nil, beforeRevision: UInt64,
                                      afterRevision: UInt64?, erase: Bool = false) -> Self {
            typed(.functionSignature, operationID: operationID, requestDigest: requestDigest, decision: decision,
                  slot: slot, address: address, requested: requested, baseline: baseline,
                  imageSHA256: imageSHA256, beforeRevision: beforeRevision, afterRevision: afterRevision,
                  erase: erase)
        }

        private static func typed(_ fieldClass: VerifiedFieldClass, operationID: UUID, requestDigest: String,
                                  decision: VerifiedAnnotationDecision, slot: Int, address: UInt64,
                                  requested: String, baseline: String?, imageSHA256: String?,
                                  beforeRevision: UInt64, afterRevision: UInt64?, erase: Bool) -> Self {
            Self(operationID: operationID, requestDigest: requestDigest, decision: decision, slot: slot,
                 address: address, field: fieldClass.rawValue, requested: requested,
                 baseline: baseline, imageSHA256: imageSHA256, beforeRevision: beforeRevision,
                 afterRevision: afterRevision, fieldClass: fieldClass.rawValue,
                 requestedDigest: VerifiedAnnotationAuditCodec.sha256Hex(Data(requested.utf8)),
                 erase: erase ? true : nil)
        }

        var isTyped: Bool { fieldClass != nil }
    }

    let schemaVersion: Int
    let workspaceID: UUID
    let documentID: UUID
    /// Installation IDs the writer used (equality with the reader's is a finding).
    let writerInstallationIDs: [UUID]
    /// The writer's process id, when known; a checkpoint in the same process is not isolation.
    let writerProcessID: Int32?
    let operations: [Operation]

    /// Decode bounded, strict JSON from a request file's bytes.
    static func decode(_ data: Data, supportedSchemaVersions: ClosedRange<Int> = Self.supportedSchemaVersions) throws -> Self {
        guard data.count <= VerifiedCheckpointBounds.maximumRequestFileBytes else {
            throw VerifiedCheckpointInvalid(reason: "expectation-too-large")
        }
        let decoded: Self
        do { decoded = try JSONDecoder().decode(Self.self, from: data) }
        catch { throw VerifiedCheckpointInvalid(reason: "expectation-malformed") }
        try decoded.validate(supportedSchemaVersions: supportedSchemaVersions)
        return decoded
    }

    /// The schema a writer must use: 1 when every operation is name or comment, 2 otherwise.
    static func requiredSchemaVersion(for operations: [Operation]) -> Int {
        operations.contains(where: \.isTyped) ? typedSchemaVersion : currentSchemaVersion
    }

    /// Writer: sorted-key JSON. Refuses a schemaVersion that disagrees with the operations, so name/comment
    /// expectations keep their v1 bytes and a v2 document always has a typed operation.
    func encoded() throws -> Data {
        try validate()
        guard schemaVersion == Self.requiredSchemaVersion(for: operations) else {
            throw VerifiedCheckpointInvalid(reason: "expectation-schema-version")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    /// `supportedSchemaVersions` lets a test simulate an old reader (`1...1`).
    func validate(supportedSchemaVersions: ClosedRange<Int> = Self.supportedSchemaVersions) throws {
        func bad(_ reason: String) -> VerifiedCheckpointInvalid { .init(reason: reason) }
        guard supportedSchemaVersions.contains(schemaVersion) else { throw bad("expectation-schema-version") }
        guard !operations.isEmpty else { throw bad("expectation-no-operations") }
        // Schema 2 exists only for typed operations; a name/comment-only document stays schema 1.
        if schemaVersion == Self.typedSchemaVersion, !operations.contains(where: \.isTyped) {
            throw bad("expectation-schema-version")
        }
        guard operations.count <= VerifiedCheckpointBounds.maximumOperations else { throw bad("expectation-too-many-operations") }
        guard writerInstallationIDs.count <= VerifiedCheckpointBounds.maximumOperations else { throw bad("expectation-too-many-installations") }
        guard Set(operations.map(\.operationID)).count == operations.count else { throw bad("expectation-duplicate-operation") }
        for operation in operations {
            guard VerifiedAnnotationAuditCodec.isSHA256(operation.requestDigest) else { throw bad("expectation-request-digest") }
            if let rawClass = operation.fieldClass {
                // Typed: schema 2 only, class and field agree, and only the classes this reader judges.
                guard schemaVersion >= Self.typedSchemaVersion, rawClass == operation.field,
                      let fieldClass = VerifiedFieldClass(rawValue: rawClass),
                      fieldClass == .addressType || fieldClass == .functionSignature else { throw bad("expectation-field") }
                // `erase` is written only when true; an explicit false is not a canonical encoding.
                if let erase = operation.erase, !erase { throw bad("expectation-field") }
                let erasing = operation.erase == true
                let limit = fieldClass == .addressType ? VerifiedCheckpointBounds.maximumTypeNameBytes
                                                       : VerifiedCheckpointBounds.maximumSignatureBytes
                guard operation.requested.utf8.count <= limit,
                      (operation.baseline?.utf8.count ?? 0) <= limit else {
                    throw bad("expectation-value-too-large")
                }
                if erasing {
                    guard operation.requested.isEmpty else { throw bad("expectation-erase-requested-not-empty") }
                    guard operation.baseline != nil else { throw bad("expectation-erase-without-baseline") }
                } else {
                    guard !operation.requested.isEmpty else { throw bad("expectation-requested-empty") }
                }
                let failure = fieldClass == .addressType ? "expectation-type-name" : "expectation-signature"
                func requireCanonical(_ text: String) throws {
                    do {
                        switch fieldClass {
                        case .addressType:
                            guard try VerifiedFieldCodec.canonicalTypeName(text) == text else { throw bad(failure) }
                        default:
                            let decoded = try VerifiedFieldCodec.decodeSignature(text)
                            guard try VerifiedFieldCodec.canonicalSignature(decoded) == text else { throw bad(failure) }
                        }
                    } catch let invalid as VerifiedCheckpointInvalid { throw invalid }
                    catch VerifiedFieldCodecError.signatureTooLarge { throw bad("expectation-value-too-large") }
                    catch { throw bad(failure) }
                }
                if !erasing { try requireCanonical(operation.requested) }
                if let baseline = operation.baseline { try requireCanonical(baseline) }
                guard operation.requestedDigest == VerifiedAnnotationAuditCodec.sha256Hex(Data(operation.requested.utf8)) else {
                    throw bad("expectation-requested-digest")
                }
            } else {
                guard let field = VerifiedAnnotationField(rawValue: operation.field) else { throw bad("expectation-field") }
                guard operation.erase == nil else { throw bad("expectation-field") }
                guard operation.requestedDigest == nil else { throw bad("expectation-requested-digest") }
                let limit = field.maximumUTF8Bytes
                guard operation.requested.utf8.count <= limit,
                      (operation.baseline?.utf8.count ?? 0) <= limit else { throw bad("expectation-value-too-large") }
                guard !operation.requested.isEmpty else { throw bad("expectation-requested-empty") }
            }
            if let digest = operation.imageSHA256, !VerifiedAnnotationAuditCodec.isSHA256(digest) {
                throw bad("expectation-image-digest")
            }
            guard operation.slot >= 0 else { throw bad("expectation-slot") }
            switch operation.decision {
            case .accepted:
                guard let after = operation.afterRevision, after == operation.beforeRevision + 1,
                      operation.beforeRevision < UInt64.max else { throw bad("expectation-revisions") }
            case .rejected:
                guard operation.afterRevision == nil else { throw bad("expectation-revisions") }
            }
        }
    }
}

struct VerifiedCheckpointInvalid: Error, Equatable, CustomStringConvertible {
    let reason: String
    var description: String { reason }
}

// MARK: - Outcomes and report

/// The reader process, supplied by the caller so the function stays pure.
struct VerifiedCheckpointReaderIdentity: Equatable, Sendable {
    let installationID: UUID
    let processID: Int32
    let executable: String
}

enum VerifiedCheckpointOutcome: Equatable, Sendable {
    case confirmed
    case confirmedAfterTransformation(notes: [String])
    case rejectedRecorded
    /// Reserved for the journal path (needs VA3b); never produced by slice A.
    case confirmedFromJournal
    /// A rejection whose record reached the store only through the journal; keeps the rejected meaning.
    case rejectedRecordedFromJournal
    case operationAbsent
    case mismatch(field: String, expected: String, observed: String)
    case receiptWithoutEffect
    case annotationWithoutReceipt
    case auditUnattached
    case chainBroken(revision: UInt64)
    case installationNotFresh
    case targetIdentityMismatch(reason: String)
    case expectationInvalid(reason: String)
    case packageUnreadable(reason: String)
    case unsupportedPackage(missingFeatures: [String])
    case overBudget(which: String)

    var isPass: Bool {
        switch self {
        case .confirmed, .confirmedAfterTransformation, .rejectedRecorded, .confirmedFromJournal,
             .rejectedRecordedFromJournal: return true
        default: return false
        }
    }

    var code: String {
        switch self {
        case .confirmed: return "confirmed"
        case .confirmedAfterTransformation: return "confirmedAfterTransformation"
        case .rejectedRecorded: return "rejectedRecorded"
        case .confirmedFromJournal: return "confirmedFromJournal"
        case .rejectedRecordedFromJournal: return "rejectedRecordedFromJournal"
        case .operationAbsent: return "operationAbsent"
        case .mismatch: return "mismatch"
        case .receiptWithoutEffect: return "receiptWithoutEffect"
        case .annotationWithoutReceipt: return "annotationWithoutReceipt"
        case .auditUnattached: return "auditUnattached"
        case .chainBroken: return "chainBroken"
        case .installationNotFresh: return "installationNotFresh"
        case .targetIdentityMismatch: return "targetIdentityMismatch"
        case .expectationInvalid: return "expectationInvalid"
        case .packageUnreadable: return "packageUnreadable"
        case .unsupportedPackage: return "unsupportedPackage"
        case .overBudget: return "overBudget"
        }
    }

    /// Bounded human-readable detail; never longer than the diagnostic budget.
    var detail: String {
        let text: String
        switch self {
        case let .confirmedAfterTransformation(notes): text = notes.joined(separator: "; ")
        case let .mismatch(field, expected, observed): text = "\(field): expected \(expected), observed \(observed)"
        case let .chainBroken(revision): text = "revision \(revision)"
        case let .targetIdentityMismatch(reason), let .expectationInvalid(reason),
             let .packageUnreadable(reason), let .overBudget(reason): text = reason
        case let .unsupportedPackage(features): text = features.joined(separator: ", ")
        default: text = ""
        }
        return VerifiedCheckpoint.bounded(text, to: VerifiedCheckpointBounds.maximumDiagnosticBytes)
    }
}

struct VerifiedCheckpointOperationResult: Equatable, Sendable {
    let operationID: UUID
    let outcome: VerifiedCheckpointOutcome
}

struct VerifiedCheckpointReport: Equatable, Sendable {
    let workspaceID: UUID?
    let documentID: UUID?
    let readerInstallationID: UUID
    let readerProcessID: Int32
    /// Package-level finding that fails every operation (identity, freshness, attachment).
    let packageOutcome: VerifiedCheckpointOutcome?
    let operations: [VerifiedCheckpointOperationResult]
    /// Accepted or rejected records the expectation did not name.
    let unexpectedOperationIDs: [UUID]
    /// True only if the reader process differs from the writer process the expectation names.
    let processIsolated: Bool
    /// Informational: load repairs and stamp reproduction. Not gated.
    let notes: [String]
    /// Journal tier: bytes of a torn journal tail that replay dropped (nil when none or no journal).
    var journalTornTailBytes: Int? = nil
    /// Journal tier: audit records whose owner is not this document; replayed as edits, never attached.
    var unattachedAuditRecords: [UUID] = []

    var allOperationsPass: Bool {
        packageOutcome == nil && unexpectedOperationIDs.isEmpty && !operations.isEmpty
            && operations.allSatisfy { $0.outcome.isPass }
    }
    /// The literal acceptance claim: every field confirmed AND read from a different process.
    var passed: Bool { allOperationsPass && processIsolated }

    /// A report that failed before any record was read.
    static func failed(_ outcome: VerifiedCheckpointOutcome, reader: VerifiedCheckpointReaderIdentity) -> Self {
        Self(workspaceID: nil, documentID: nil, readerInstallationID: reader.installationID,
             readerProcessID: reader.processID, packageOutcome: outcome, operations: [],
             unexpectedOperationIDs: [], processIsolated: false, notes: [])
    }

    func jsonValue() -> ScriptValue {
        .object([
            "passed": .bool(passed), "allOperationsPass": .bool(allOperationsPass),
            "processIsolated": .bool(processIsolated),
            "workspaceID": workspaceID.map { .string($0.uuidString) } ?? .null,
            "documentID": documentID.map { .string($0.uuidString) } ?? .null,
            "readerInstallationID": .string(readerInstallationID.uuidString),
            "readerProcessID": .int(Int64(readerProcessID)),
            "packageOutcome": packageOutcome.map {
                .object(["code": .string($0.code), "detail": .string($0.detail)])
            } ?? .null,
            "unexpectedOperationIDs": .array(unexpectedOperationIDs.map { .string($0.uuidString) }),
            "operations": .array(operations.map {
                .object(["operationID": .string($0.operationID.uuidString),
                         "outcome": .string($0.outcome.code), "detail": .string($0.outcome.detail),
                         "pass": .bool($0.outcome.isPass)])
            }),
            "notes": .array(notes.map { .string($0) }),
            "journalTornTailBytes": journalTornTailBytes.map { .int(Int64($0)) } ?? .null,
            "unattachedAuditRecords": .array(unattachedAuditRecords.map { .string($0.uuidString) }),
            "evidenceScope": .string("saved-bytes checkpoint; stamp reproduction informational; no live evidence admission")
        ])
    }
}

// MARK: - Subject (what is judged)

/// Facts from an edit-journal attach (`EditJournalReport`), copied so the judgement stays pure.
struct VerifiedCheckpointJournalFacts: Equatable, Sendable {
    var replayed: Int
    var alreadyApplied: Bool
    var tornTailBytes: Int?
    /// Journal audit records owned by a different workspace or document.
    var unattachedAuditRecords: [UUID]
    /// Operation ids the SAVED package already held before the journal replayed; a record outside
    /// this set reached the subject through the journal.
    var savedOperationIDs: Set<UUID>
}

/// The state a checkpoint judges: either a package the production reader opened, or a store that
/// restored one (and optionally replayed a journal). Read-only values only.
struct VerifiedCheckpointSubject {
    let workspaceID: UUID
    let documentID: UUID
    let audit: VerifiedAnnotationAuditEnvelope?
    let snapshot: WorkspaceSnapshot
    let repairNotes: [String]
    let journal: VerifiedCheckpointJournalFacts?

    init(workspaceID: UUID, documentID: UUID, audit: VerifiedAnnotationAuditEnvelope?, snapshot: WorkspaceSnapshot,
         repairNotes: [String] = [], journal: VerifiedCheckpointJournalFacts? = nil) {
        self.workspaceID = workspaceID; self.documentID = documentID; self.audit = audit
        self.snapshot = snapshot; self.repairNotes = repairNotes; self.journal = journal
    }

    init(contents: WorkspacePackageContents) {
        let notes = contents.analysisRepairs.prefix(VerifiedCheckpointBounds.maximumNotes).map {
            "load-repair slot \($0.slot.rawValue) \($0.imageName): " + $0.items.joined(separator: ", ")
        }
        self.init(workspaceID: contents.manifest.workspaceUUID, documentID: contents.manifest.documentID,
                  audit: contents.manifest.verifiedAnnotationAudit, snapshot: contents.snapshot, repairNotes: notes)
    }
}

// MARK: - Reader

enum VerifiedCheckpoint {
    static func bounded(_ text: String, to limit: Int) -> String {
        guard text.utf8.count > limit else { return text }
        var result = ""
        for character in text {
            if result.utf8.count + String(character).utf8.count > limit { break }
            result.append(character)
        }
        return result
    }

    private static func shown(_ value: String?) -> String {
        guard let value else { return "<absent>" }
        return "\"" + bounded(value, to: 128) + "\""
    }

    /// Open `packageURL` with the production reader and judge it. Maps reader errors to typed outcomes.
    static func run(packageURL: URL, expectation: VerifiedCheckpointExpectation,
                    reader: VerifiedCheckpointReaderIdentity,
                    fileManager: FileManager = .default) -> VerifiedCheckpointReport {
        do {
            try Task.checkCancellation()
            let contents = try MacScopeDocumentPackage.openPackage(from: packageURL, fileManager: fileManager)
            return check(contents: contents, expectation: expectation, reader: reader)
        } catch let error as MacScopeDocumentPackage.UnsupportedReaderFeaturesError {
            return .failed(.unsupportedPackage(missingFeatures: Array(error.features.prefix(VerifiedCheckpointBounds.maximumNotes))), reader: reader)
        } catch is CancellationError {
            return .failed(.overBudget(which: "cancelled"), reader: reader)
        } catch {
            return .failed(.packageUnreadable(reason: bounded(String(describing: error),
                to: VerifiedCheckpointBounds.maximumDiagnosticBytes)), reader: reader)
        }
    }

    /// Pure judgement of an already-opened package. Reads nothing from disk and writes nothing.
    static func check(contents: WorkspacePackageContents, expectation: VerifiedCheckpointExpectation,
                      reader: VerifiedCheckpointReaderIdentity) -> VerifiedCheckpointReport {
        check(subject: VerifiedCheckpointSubject(contents: contents), expectation: expectation, reader: reader)
    }

    static func check(subject: VerifiedCheckpointSubject, expectation: VerifiedCheckpointExpectation,
                      reader: VerifiedCheckpointReaderIdentity) -> VerifiedCheckpointReport {
        do { try expectation.validate() } catch {
            let reason = (error as? VerifiedCheckpointInvalid)?.reason ?? "expectation-invalid"
            return .failed(.expectationInvalid(reason: reason), reader: reader)
        }
        let journal = subject.journal
        func report(package: VerifiedCheckpointOutcome?, ops: [VerifiedCheckpointOperationResult] = [],
                    unexpected: [UUID] = [], notes: [String] = []) -> VerifiedCheckpointReport {
            VerifiedCheckpointReport(workspaceID: subject.workspaceID, documentID: subject.documentID,
                readerInstallationID: reader.installationID, readerProcessID: reader.processID,
                packageOutcome: package, operations: ops, unexpectedOperationIDs: unexpected,
                processIsolated: expectation.writerProcessID.map { $0 != reader.processID } ?? false,
                notes: Array(notes.prefix(VerifiedCheckpointBounds.maximumNotes)),
                journalTornTailBytes: journal?.tornTailBytes,
                unattachedAuditRecords: Array((journal?.unattachedAuditRecords ?? []).prefix(VerifiedCheckpointBounds.maximumReportEntries)))
        }

        // Package identity: the reader's ids must be the expectation's.
        guard subject.workspaceID == expectation.workspaceID else {
            return report(package: .mismatch(field: "workspaceID", expected: expectation.workspaceID.uuidString,
                                             observed: subject.workspaceID.uuidString))
        }
        guard subject.documentID == expectation.documentID else {
            return report(package: .mismatch(field: "documentID", expected: expectation.documentID.uuidString,
                                             observed: subject.documentID.uuidString))
        }
        // With a journal attached, an empty envelope is judged per operation (absent, torn, or
        // unattached); without one it is a package-level finding.
        let envelope = subject.audit ?? .empty
        if envelope.isEmpty && journal == nil { return report(package: .auditUnattached) }
        if envelope.records.count > VerifiedCheckpointBounds.maximumReportEntries {
            return report(package: .overBudget(which: "records"))
        }
        do { try envelope.validate(workspaceID: expectation.workspaceID, documentID: expectation.documentID) }
        catch { return report(package: .packageUnreadable(reason: "audit-envelope-invalid")) }

        // Freshness: the reader's installation must not be any archived one.
        var archived = Set(expectation.writerInstallationIDs)
        for record in envelope.records {
            archived.insert(record.body.before.installationID)
            if let after = record.body.after { archived.insert(after.installationID) }
        }
        if archived.contains(reader.installationID) { return report(package: .installationNotFresh) }

        // Revision chain over accepted records, in stored order.
        var brokenAt: Set<UUID> = []
        var previous: UInt64 = 0
        for record in envelope.records where record.body.decision == .accepted {
            let before = record.body.before.revision
            let after = record.body.after?.revision
            if before != previous || after != previous + 1 {
                brokenAt.insert(record.operationID)
            }
            previous = after ?? previous
        }

        let notes = subject.repairNotes
        var info = notes
        if let tail = journal?.tornTailBytes { info.append("journal torn tail: \(tail) bytes dropped") }
        // Informational stamp reproduction (Q3): never gates.
        if let last = envelope.records.last(where: { $0.body.decision == .accepted }), let after = last.body.after {
            let digest = NativeAnnotationProjector.digest(subject.snapshot.addressOverrides)
            info.append(digest == after.digest ? "stamp digest reproduced at last accepted record"
                                               : "stamp digest not reproduced (informational)")
        }

        let byID = Dictionary(uniqueKeysWithValues: envelope.records.map { ($0.operationID, $0) })
        let expectedIDs = Set(expectation.operations.map(\.operationID))
        let unexpected = envelope.records.map(\.operationID).filter { !expectedIDs.contains($0) }

        var results: [VerifiedCheckpointOperationResult] = []
        for operation in expectation.operations {
            results.append(.init(operationID: operation.operationID,
                outcome: judge(operation, record: byID[operation.operationID], chainBroken: brokenAt,
                               subject: subject, notes: notes)))
        }
        return report(package: nil, ops: results, unexpected: unexpected, notes: info)
    }

    private static func judge(_ operation: VerifiedCheckpointExpectation.Operation,
                              record: VerifiedAnnotationAuditRecord?, chainBroken: Set<UUID>,
                              subject: VerifiedCheckpointSubject, notes: [String]) -> VerifiedCheckpointOutcome {
        let outcome = judgeStored(operation, record: record, chainBroken: chainBroken, subject: subject, notes: notes)
        // Journal tier: a pass whose record the saved package did not hold came from the journal.
        if let journal = subject.journal, !journal.savedOperationIDs.contains(operation.operationID) {
            switch outcome {
            case .confirmed: return .confirmedFromJournal
            case .rejectedRecorded: return .rejectedRecordedFromJournal
            default: break
            }
        }
        return outcome
    }

    private static func judgeStored(_ operation: VerifiedCheckpointExpectation.Operation,
                                    record: VerifiedAnnotationAuditRecord?, chainBroken: Set<UUID>,
                                    subject: VerifiedCheckpointSubject, notes: [String]) -> VerifiedCheckpointOutcome {
        guard let record else {
            if subject.journal?.unattachedAuditRecords.contains(operation.operationID) == true { return .auditUnattached }
            // No receipt: an annotation holding the requested value is a finding of its own.
            let key = ImageAddress(slot: ImageSlot(rawValue: operation.slot), address: operation.address)
            let present: String?
            if operation.isTyped {
                switch observedTyped(operation, key: key, subject: subject) {
                case .failure(let finding): return finding.outcome
                case .success(let value): present = value
                }
            } else {
                present = VerifiedAnnotationField(rawValue: operation.field).flatMap { field in
                    subject.snapshot.addressOverrides[key].flatMap { field.value(in: $0) } }
            }
            let wanted = operation.erase == true ? nil : operation.requested
            if operation.decision == .accepted, present == wanted, operation.baseline != wanted {
                return .annotationWithoutReceipt
            }
            return .operationAbsent
        }
        let body = record.body
        guard body.requestDigest == operation.requestDigest else {
            return .mismatch(field: "requestDigest", expected: operation.requestDigest, observed: body.requestDigest)
        }
        guard body.decision == operation.decision else {
            return .mismatch(field: "decision", expected: operation.decision.rawValue, observed: body.decision.rawValue)
        }
        if chainBroken.contains(operation.operationID) {
            return .chainBroken(revision: body.after?.revision ?? body.before.revision)
        }
        if operation.decision == .accepted {
            guard body.before.revision == operation.beforeRevision else {
                return .mismatch(field: "beforeRevision", expected: String(operation.beforeRevision),
                                 observed: String(body.before.revision))
            }
            guard body.after?.revision == operation.afterRevision else {
                return .mismatch(field: "afterRevision", expected: operation.afterRevision.map(String.init) ?? "nil",
                                 observed: body.after.map { String($0.revision) } ?? "nil")
            }
        }

        // Target identity.
        let slot = ImageSlot(rawValue: operation.slot)
        guard subject.snapshot.binaries.contains(where: { $0.slot == slot }) else {
            return .targetIdentityMismatch(reason: "slot \(operation.slot) not in package")
        }
        if let expected = operation.imageSHA256 {
            let bytes = subject.snapshot.analysis(in: slot)?.imageBytes ?? Data()
            let observed = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            guard observed == expected else { return .targetIdentityMismatch(reason: "image sha256 differs") }
        }

        if operation.isTyped {
            // S4 rule (VerifiedAnnotationAuditMapping.recordedFieldClass(for:)): only an accepted receipt carries
            // a field class; every rejected receipt is a v1 record with none. So an accepted typed operation
            // needs the class to match, while a rejected one accepts nil or the matching class. Any other
            // class is still a mismatch.
            let recorded = record.recordedFieldClass?.rawValue
            let classOK = operation.decision == .rejected ? (recorded == nil || recorded == operation.fieldClass)
                                                          : recorded == operation.fieldClass
            guard classOK else {
                return .mismatch(field: "fieldClass", expected: operation.fieldClass ?? "nil",
                                 observed: record.recordedFieldClass?.rawValue ?? "nil")
            }
            return judgeType(operation, slot: slot, subject: subject, notes: notes)
        }

        // Stored field value.
        guard let field = VerifiedAnnotationField(rawValue: operation.field) else {
            return .expectationInvalid(reason: "expectation-field")
        }
        let observed = subject.snapshot.addressOverrides[ImageAddress(slot: slot, address: operation.address)]
            .flatMap { field.value(in: $0) }
        switch operation.decision {
        case .accepted:
            if observed == operation.requested {
                return notes.isEmpty ? .confirmed : .confirmedAfterTransformation(notes: notes)
            }
            if observed == operation.baseline { return .receiptWithoutEffect }
            return .mismatch(field: "value", expected: shown(operation.requested), observed: shown(observed))
        case .rejected:
            if observed == operation.baseline { return .rejectedRecorded }
            if observed == operation.requested { return .annotationWithoutReceipt }
            return .mismatch(field: "value", expected: shown(operation.baseline), observed: shown(observed))
        }
    }

    private struct TypedFinding: Error { let outcome: VerifiedCheckpointOutcome }

    /// The saved value of a typed field at the operation's address, in the same text form the expectation
    /// uses. Address type: `appliedTypeName`. Signature: `canonicalSignature` of the saved override's
    /// signature (nil if absent); a signature that cannot be canonicalised is a finding, never a confirm.
    /// Never reads pseudocode or `ownReturnAuthorityFile`.
    private static func observedTyped(_ operation: VerifiedCheckpointExpectation.Operation, key: ImageAddress,
                                      subject: VerifiedCheckpointSubject) -> Result<String?, TypedFinding> {
        let override = subject.snapshot.addressOverrides[key]
        guard operation.fieldClass == VerifiedFieldClass.functionSignature.rawValue else {
            return .success(override?.appliedTypeName)
        }
        guard let signature = override?.signature else { return .success(nil) }
        do { return .success(try VerifiedFieldCodec.canonicalSignature(signature)) }
        catch {
            return .failure(TypedFinding(outcome: .mismatch(field: "signature",
                expected: shown(operation.erase == true ? nil : operation.requested), observed: "<not canonicalisable>")))
        }
    }

    /// Typed fields. Address type: observed is the saved override's `appliedTypeName`, and a non-erase
    /// confirm needs exactly one resolved `TypeDefinition` with that name (ruling 5). Signature: observed is
    /// the canonical signature text; no TypeDefinition is required. An erase expects the value to be absent.
    /// Never reads pseudocode.
    private static func judgeType(_ operation: VerifiedCheckpointExpectation.Operation, slot: ImageSlot,
                                  subject: VerifiedCheckpointSubject, notes: [String]) -> VerifiedCheckpointOutcome {
        let observed: String?
        switch observedTyped(operation, key: ImageAddress(slot: slot, address: operation.address), subject: subject) {
        case .failure(let finding): return finding.outcome
        case .success(let value): observed = value
        }
        let erasing = operation.erase == true
        let wanted: String? = erasing ? nil : operation.requested
        switch operation.decision {
        case .accepted:
            if observed == wanted {
                if !erasing, operation.fieldClass == VerifiedFieldClass.addressType.rawValue {
                    let definitions = subject.snapshot.typeDefinitions.filter { $0.name == operation.requested }.count
                    guard definitions == 1 else {
                        return .mismatch(field: "typeDefinition", expected: "exactly 1 definition named \(shown(operation.requested))",
                                         observed: String(definitions))
                    }
                }
                return notes.isEmpty ? .confirmed : .confirmedAfterTransformation(notes: notes)
            }
            if observed == operation.baseline { return .receiptWithoutEffect }
            return .mismatch(field: "value", expected: shown(wanted), observed: shown(observed))
        case .rejected:
            if observed == operation.baseline { return .rejectedRecorded }
            if observed == wanted { return .annotationWithoutReceipt }
            return .mismatch(field: "value", expected: shown(operation.baseline), observed: shown(observed))
        }
    }
}
