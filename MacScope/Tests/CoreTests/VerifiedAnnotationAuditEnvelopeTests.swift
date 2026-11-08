#if DEBUG
import Foundation
import XCTest
@testable import MacScope

final class VerifiedAnnotationAuditEnvelopeTests: XCTestCase {
    private let workspaceID = UUID()
    private let documentID = UUID()

    private func record(workspace: UUID? = nil, document: UUID? = nil, id: UUID = UUID(),
                        rejected: Bool = false) throws -> VerifiedAnnotationAuditRecord {
        let before = VAProjectionStamp(workspaceID: workspace ?? workspaceID, documentID: document ?? documentID,
            installationID: UUID(), revision: 7, digest: String(repeating: "a", count: 64))
        let after = VAProjectionStamp(workspaceID: before.workspaceID, documentID: before.documentID,
            installationID: before.installationID, revision: 8, digest: String(repeating: "b", count: 64))
        let evidenceID = UUID()
        let request = VAMutationRequest(id: id, base: before,
            edits: [.init(target: .init(componentID: UUID(), function: VAAddress64(0x1000)),
                          kind: .functionName, value: "investigator_Ω", evidenceIDs: [evidenceID])],
            rationale: "Native function evidence")
        let receipt = try VAVerificationReceipt(request: request, decision: rejected ? .rejected : .accepted,
            before: before, after: rejected ? nil : after,
            mechanical: rejected ? .notVerified : .candidateReadbackVerified,
            persistence: rejected ? .notApplicable : .pendingFreshProcessCheckpoint,
            failure: rejected ? "candidate mismatch" : nil, recordedAt: Date(timeIntervalSince1970: 1234.567))
        return try VerifiedAnnotationAuditRecord(receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: String(repeating: "c", count: 64))],
            checkpointReferences: rejected ? [] : [.init(reportID: UUID(), projection: .init(after),
                packageDigest: String(repeating: "d", count: 64))])
    }

    private func envelope(_ record: VerifiedAnnotationAuditRecord) throws -> VerifiedAnnotationAuditEnvelope {
        try .empty.appending(record, workspaceID: record.body.before.workspaceID,
                             documentID: record.body.before.documentID)
    }

    private func manifest(_ envelope: VerifiedAnnotationAuditEnvelope? = nil, version: Int = 1) -> WorkspacePackageManifest {
        WorkspacePackageManifest(formatVersion: version, documentID: documentID, workspaceUUID: workspaceID,
            workspaceName: "Audit storage", createdAt: Date(timeIntervalSince1970: 1),
            modifiedAt: Date(timeIntervalSince1970: 1), binaries: [], session: nil,
            verifiedAnnotationAudit: envelope)
    }

    private func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: VerifiedAnnotationAuditCodec.encode(value)) as? [String: Any])
    }

    private func json(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private func changedRecord(_ transform: (inout [String: Any]) throws -> Void) throws -> Data {
        let original = try record()
        var body = try XCTUnwrap(JSONSerialization.jsonObject(with: original.canonicalBytes) as? [String: Any])
        try transform(&body)
        let bytes = try json(body)
        return try json(["canonicalBytes": bytes.base64EncodedString(), "digest": VerifiedAnnotationAuditCodec.sha256Hex(bytes)])
    }

    func testFeatureIsRequiredAndOlderReaderRefusesBeforeRecordDecode() throws {
        let prepared = try MacScopeDocumentPackage.preparedManifest(manifest(envelope(record())), reconstructionState: .empty)
        let feature = WorkspacePackageManifest.verifiedAnnotationAuditReaderFeature
        XCTAssertTrue(prepared.requiredReaderFeatures.contains(feature))
        let bytes = try MacScopeDocumentPackage.encodedManifest(prepared)
        XCTAssertEqual(try MacScopeDocumentPackage.validatedManifest(manifestData: bytes).verifiedAnnotationAudit,
                       prepared.verifiedAnnotationAudit)
        var root = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        root["verifiedAnnotationAudit"] = "a reader without the feature must not decode this"
        let incompatible = try json(root)
        XCTAssertThrowsError(try MacScopeDocumentPackage.decodedManifestForReaderTesting(incompatible,
            supportedFeatures: MacScopeDocumentPackage.supportedReaderFeatures.subtracting([feature]))) {
            XCTAssertEqual($0 as? MacScopeDocumentPackage.UnsupportedReaderFeaturesError, .init(features: [feature]))
            XCTAssertTrue($0.localizedDescription.contains(feature))
            XCTAssertFalse($0.localizedDescription.contains("reconstruction job"))
        }
    }

    func testAbsentAndEmptyEnvelopesPreserveLegacyVersionsWithoutFeature() throws {
        for version in [1, 2] {
            for envelope: VerifiedAnnotationAuditEnvelope? in [nil, .empty] {
                let prepared = try MacScopeDocumentPackage.preparedManifest(manifest(envelope, version: version), reconstructionState: .empty)
                let bytes = try MacScopeDocumentPackage.encodedManifest(prepared)
                let opened = try MacScopeDocumentPackage.validatedContents(manifestData: bytes, attachmentsByBinaryID: [:])
                XCTAssertNil(opened.manifest.verifiedAnnotationAudit)
                XCTAssertFalse(opened.manifest.requiredReaderFeatures.contains(WorkspacePackageManifest.verifiedAnnotationAuditReaderFeature))
                XCTAssertEqual(try MacScopeDocumentPackage.encodedManifest(opened.manifest), bytes)
            }
        }
    }

    func testFeatureEnvelopeDisagreementRefusesBothDirections() throws {
        var missing = manifest(try envelope(record()))
        XCTAssertThrowsError(try MacScopeDocumentPackage.validatedManifest(manifestData: MacScopeDocumentPackage.encodedManifest(missing))) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .readerFeatureDisagreement)
        }
        missing.verifiedAnnotationAudit = nil
        missing.requiredReaderFeatures = [WorkspacePackageManifest.verifiedAnnotationAuditReaderFeature]
        XCTAssertThrowsError(try MacScopeDocumentPackage.validatedManifest(manifestData: MacScopeDocumentPackage.encodedManifest(missing))) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .readerFeatureDisagreement)
        }
    }

    func testVersion3RootPolicyPreservesEnvelope() throws {
        let fixture = try ReconstructionPackageFixture.make()
        defer { fixture.remove() }
        var manifest = fixture.manifest
        let expected = try envelope(record(workspace: manifest.workspaceUUID, document: manifest.documentID))
        manifest.verifiedAnnotationAudit = expected
        try MacScopeDocumentPackage.writePackage(manifest, attachmentsByBinaryID: [fixture.binaryID: fixture.binaryBytes],
            reconstructionState: fixture.state, reconstructionAttachmentSources: [fixture.source], to: fixture.packageURL)
        XCTAssertEqual(try MacScopeDocumentPackage.openPackage(from: fixture.packageURL).manifest.verifiedAnnotationAudit, expected)
    }

    @MainActor
    func testNormalSaveReopenAndDatabaseSavePreserveCanonicalBytes() throws {
        let root = TestWorkRoot.scratch.appendingPathComponent("annotation-audit-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = WorkspaceStore(workspaceName: "Audit", snapshot: .init(binaries: [], analysisBySlot: [:]),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let expected = try envelope(record(workspace: store.workspaceID, document: store.documentID))
        try store.setVerifiedAnnotationAuditForTesting(expected)
        let url = root.appendingPathComponent("normal.mscope")
        _ = try store.writeDocumentPackageThrowing(to: url)
        let reopened = try WorkspaceStore.restoredPackage(from: url, scheduleDurableRecovery: false)
        XCTAssertNotEqual(reopened.documentInstallationID, store.documentInstallationID)
        XCTAssertEqual(reopened.verifiedAnnotationAudit, expected)
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(reopened.verifiedAnnotationAudit), try VerifiedAnnotationAuditCodec.encode(expected))
        let payload = try reopened.makePackagePayload()
        let opened = try MacScopeDocumentPackage.validatedContents(manifestData: payload.manifestData,
            attachmentsByBinaryID: payload.attachmentsByBinaryID, reconstructionState: payload.reconstructionState,
            instructionSidecarData: payload.instructionSidecarData)
        XCTAssertEqual(opened.manifest.formatVersion, 4)
        XCTAssertEqual(opened.manifest.verifiedAnnotationAudit?.records.first?.canonicalBytes, expected.records.first?.canonicalBytes)
        let database = try WorkspaceDatabase.inMemory()
        try database.applySchema()
        let directURL = root.appendingPathComponent("database.mscope")
        _ = try reopened.saveWorkspacePackage(to: directURL, using: database)
        XCTAssertEqual(try MacScopeDocumentPackage.openPackage(from: directURL).manifest.verifiedAnnotationAudit, expected)
    }

    func testDuplicateOperationsRefuseWithoutChangingCandidate() throws {
        let record = try record()
        let initial = try envelope(record)
        XCTAssertThrowsError(try initial.appending(record, workspaceID: workspaceID, documentID: documentID)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .duplicateOperationID(record.operationID))
        }
        let wire = try object(record)
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditEnvelope.self,
            from: json(["schemaVersion": 1, "records": [wire, wire]]))) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .duplicateOperationID(record.operationID))
        }
        XCTAssertEqual(initial.records.count, 1)
    }

    func testMalformedUnknownAndDuplicateRecordMembersAreTypedRefusals() throws {
        let malformed = try changedRecord { body in body["before"] = "not an identity" }
        let unknown = try changedRecord { body in body["futureField"] = "must not disappear" }
        let original = try record().canonicalBytes
        let duplicate = Data(("{\"domain\":\"duplicate\"," + String(decoding: original.dropFirst(), as: UTF8.self)).utf8)
        let duplicateWire = try json(["canonicalBytes": duplicate.base64EncodedString(), "digest": VerifiedAnnotationAuditCodec.sha256Hex(duplicate)])
        for data in [malformed, unknown, duplicateWire] {
            XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: data)) {
                XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
            }
        }
    }

    func testOversizedRecordIsRefusedBeforeParsingOrHashing() throws {
        let bytes = Data(repeating: 32, count: VerifiedAnnotationAuditEnvelope.maximumRecordBytes + 1)
        let wire = try json(["canonicalBytes": bytes.base64EncodedString(), "digest": "not computed"])
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: wire)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .recordTooLarge)
        }
    }

    func testRecordCountLimitIsTypedAndNeverPrunes() throws {
        let wire = try object(record())
        let bytes = try json(["schemaVersion": 1,
            "records": Array(repeating: wire, count: VerifiedAnnotationAuditEnvelope.maximumRecords + 1)])
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditEnvelope.self, from: bytes)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .tooManyRecords)
        }
    }

    func testRecordChecksumRefusesTamperingAndMalformedRequestDigestIsMalformed() throws {
        var wire = try object(record())
        wire["digest"] = String(repeating: "0", count: 64)
        let outer = try json(wire)
        let inner = try changedRecord { body in
            body["requestDigest"] = "not a digest"
        }
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: outer)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .digestMismatch)
        }
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: inner)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
        }
    }

    func testCoreReceiptMappingIsDomainSpecificAndRefusesMismatchedEvidence() throws {
        let mapped = try record()
        XCTAssertEqual(mapped.body.domain, VerifiedAnnotationAuditRecord.domain)
        XCTAssertEqual(mapped.body.mechanical, .candidateReadbackVerified)
        XCTAssertEqual(mapped.body.persistence, .pendingFreshProcessCheckpoint)
        let before = VAProjectionStamp(workspaceID: workspaceID, documentID: documentID, installationID: UUID(),
                                       revision: 1, digest: String(repeating: "a", count: 64))
        let request = VAMutationRequest(base: before,
            edits: [.init(target: .init(componentID: UUID(), function: VAAddress64(0x1000)),
                          kind: .functionName, value: "x", evidenceIDs: [UUID()])], rationale: "r")
        let after = VAProjectionStamp(workspaceID: workspaceID, documentID: documentID,
            installationID: before.installationID, revision: 2, digest: String(repeating: "b", count: 64))
        let receipt = try VAVerificationReceipt(request: request, decision: .accepted, before: before, after: after,
            mechanical: .candidateReadbackVerified, persistence: .pendingFreshProcessCheckpoint)
        XCTAssertThrowsError(try VerifiedAnnotationAuditRecord(receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: UUID(), preconditionDigest: String(repeating: "c", count: 64))])) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
        }
    }

    func testDomainIsAnnotationSpecificAndReconstructionDomainIsRejected() throws {
        let record = try record()
        XCTAssertTrue(String(decoding: record.canonicalBytes, as: UTF8.self).contains(VerifiedAnnotationAuditRecord.domain))
        let bytes = try changedRecord { $0["domain"] = "reconstruction.tool.receipt.v1" }
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: bytes)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
        }
    }

    func testMalformedResultIdentityEvidenceAndCheckpointAreRefused() throws {
        let mutations: [(inout [String: Any]) throws -> Void] = [
            { body in
                body["mechanical"] = "notVerified"
            },
            { body in
                var after = try XCTUnwrap(body["after"] as? [String: Any])
                after["installationID"] = UUID().uuidString; body["after"] = after
            },
            { $0["nativeEvidenceLinks"] = [] },
            { body in
                var checkpoints = try XCTUnwrap(body["checkpointReferences"] as? [[String: Any]])
                checkpoints[0]["packageDigest"] = "invalid"; body["checkpointReferences"] = checkpoints
            },
        ]
        for mutate in mutations {
            let bytes = try changedRecord(mutate)
            XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: bytes)) {
                XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
            }
        }
    }

    func testWrongPackageOwnerAndUnsupportedSchemaAreTypedRefusals() throws {
        let envelope = try envelope(record())
        XCTAssertThrowsError(try envelope.validate(workspaceID: UUID(), documentID: documentID)) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .wrongOwner)
        }
        XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditEnvelope.self,
            from: json(["schemaVersion": 2, "records": []]))) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .unsupportedSchema(2))
        }
    }

    func testRejectedReceiptRoundTripsWithoutUpgradingItsResult() throws {
        let original = try envelope(record(rejected: true))
        let reopened = try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditEnvelope.self, from: VerifiedAnnotationAuditCodec.encode(original))
        XCTAssertEqual(original, reopened)
        XCTAssertNil(reopened.records[0].body.after)
        XCTAssertEqual(reopened.records[0].body.mechanical, .notVerified)
        XCTAssertEqual(reopened.records[0].body.persistence, .notApplicable)
    }

    @MainActor
    func testLiveAnnotationSettersDoNotPopulateAuditHistory() throws {
        let store = VerifiedAnnotationTestFixture.store()
        store.setCustomName(0x1000, in: .primary, name: "new name")
        store.setCustomComment(0x1000, in: .primary, comment: "new comment")
        XCTAssertTrue(store.verifiedAnnotationAudit.isEmpty)
        let empty = WorkspaceStore(workspaceName: "Empty", snapshot: .init(binaries: [], analysisBySlot: [:]),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let payload = try empty.makePackagePayload()
        let manifest = try MacScopeDocumentPackage.validatedManifest(manifestData: payload.manifestData)
        XCTAssertNil(manifest.verifiedAnnotationAudit)
        XCTAssertFalse(manifest.requiredReaderFeatures.contains(WorkspacePackageManifest.verifiedAnnotationAuditReaderFeature))
    }
    // MARK: VA-SCOPE slice S2: audit record v2, typed-edits reader feature, fieldClassMatches

    private typealias FieldClass = VerifiedAnnotationAuditFieldClass
    private let typedFeature = WorkspacePackageManifest.verifiedAnnotationTypedEditsReaderFeature
    private let auditFeature = WorkspacePackageManifest.verifiedAnnotationAuditReaderFeature

    private func uuid(_ n: Int) -> UUID { UUID(uuidString: String(format: "00000000-0000-0000-0000-%012X", n))! }
    private var fixedWorkspace: UUID { uuid(1) }
    private var fixedDocument: UUID { uuid(2) }

    /// Fixed-input record. Golden bytes below were computed by hand from the v1 encoder (sorted keys,
    /// optional keys omitted) BEFORE any S2 change, then checked against the encoder by these tests.
    private func fixedRecord(_ operation: Int, _ digestCharacter: Character,
                             fieldClass: FieldClass? = nil) throws -> VerifiedAnnotationAuditRecord {
        func identity(_ revision: UInt64, _ digest: Character) -> VerifiedAnnotationProjectionIdentity {
            .init(workspaceID: uuid(1), documentID: uuid(2), installationID: uuid(3), revision: revision,
                  digest: String(repeating: digest, count: 64))
        }
        return try VerifiedAnnotationAuditRecord(operationID: uuid(operation),
            requestDigest: String(repeating: digestCharacter, count: 64), decision: .accepted,
            before: identity(7, "a"), after: identity(8, "b"), mechanical: .candidateReadbackVerified,
            persistence: .pendingFreshProcessCheckpoint, recordedAtMilliseconds: 1_234_567,
            nativeEvidenceLinks: [.init(evidenceID: uuid(0xE1), preconditionDigest: String(repeating: "c", count: 64))],
            fieldClass: fieldClass)
    }

    private func fixedEnvelope(_ records: [VerifiedAnnotationAuditRecord]) throws -> VerifiedAnnotationAuditEnvelope {
        try records.reduce(VerifiedAnnotationAuditEnvelope.empty) {
            try $0.appending($1, workspaceID: fixedWorkspace, documentID: fixedDocument)
        }
    }

    private func fixedManifest(_ envelope: VerifiedAnnotationAuditEnvelope?) -> WorkspacePackageManifest {
        WorkspacePackageManifest(formatVersion: 1, documentID: fixedDocument, workspaceUUID: fixedWorkspace,
            workspaceName: "Audit v2", createdAt: Date(timeIntervalSince1970: 1),
            modifiedAt: Date(timeIntervalSince1970: 1), binaries: [], session: nil, verifiedAnnotationAudit: envelope)
    }

    private func wire(_ body: [String: Any]) throws -> Data {
        let bytes = try json(body)
        return try json(["canonicalBytes": bytes.base64EncodedString(), "digest": VerifiedAnnotationAuditCodec.sha256Hex(bytes)])
    }

    private func bodyObject(_ record: VerifiedAnnotationAuditRecord) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: record.canonicalBytes) as? [String: Any])
    }

    private let goldenV1Name = #"{"after":{"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","documentID":"00000000-0000-0000-0000-000000000002","installationID":"00000000-0000-0000-0000-000000000003","revision":8,"workspaceID":"00000000-0000-0000-0000-000000000001"},"before":{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documentID":"00000000-0000-0000-0000-000000000002","installationID":"00000000-0000-0000-0000-000000000003","revision":7,"workspaceID":"00000000-0000-0000-0000-000000000001"},"checkpointReferences":[],"decision":"accepted","domain":"com.jeff.macscope.verified-annotation-audit.record.v1","mechanical":"candidateReadbackVerified","nativeEvidenceLinks":[{"evidenceID":"00000000-0000-0000-0000-0000000000E1","preconditionDigest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"operationID":"00000000-0000-0000-0000-0000000000A1","persistence":"pendingFreshProcessCheckpoint","recordedAtMilliseconds":1234567,"requestDigest":"1111111111111111111111111111111111111111111111111111111111111111"}"#
    private let goldenV1NameDigest = "558c25947a7ecdbc47ff3eccbe67b46b5644e6e7c07cc2da9b9da862cdf9c5ec"
    private let goldenV1CommentDigest = "dc8a0e0c9c3a9ea0aac1ee3d4a0c7de2808ac5c942c6ca32e2d39576e78d307c"
    private let goldenV2AddressType = #"{"after":{"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","documentID":"00000000-0000-0000-0000-000000000002","installationID":"00000000-0000-0000-0000-000000000003","revision":8,"workspaceID":"00000000-0000-0000-0000-000000000001"},"before":{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","documentID":"00000000-0000-0000-0000-000000000002","installationID":"00000000-0000-0000-0000-000000000003","revision":7,"workspaceID":"00000000-0000-0000-0000-000000000001"},"checkpointReferences":[],"decision":"accepted","domain":"com.jeff.macscope.verified-annotation-audit.record.v2","fieldClass":"addressType","mechanical":"candidateReadbackVerified","nativeEvidenceLinks":[{"evidenceID":"00000000-0000-0000-0000-0000000000E1","preconditionDigest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"operationID":"00000000-0000-0000-0000-0000000000A3","persistence":"pendingFreshProcessCheckpoint","recordedAtMilliseconds":1234567,"requestDigest":"3333333333333333333333333333333333333333333333333333333333333333"}"#
    private let goldenV2AddressTypeDigest = "a478eb587883363d1c272b89b6ab2b20bc8490d81102fb8c432bb80613934a18"

    /// An old reader's record decode, reproduced from the pre-S2 `init(from:)`: the v1 Body shape, canonical
    /// re-encode equality, and the v1-only domain check.
    private struct LegacyV1Body: Codable {
        let domain: String
        let operationID: UUID
        let requestDigest: String
        let decision: VerifiedAnnotationDecision
        let before: VerifiedAnnotationProjectionIdentity
        let after: VerifiedAnnotationProjectionIdentity?
        let mechanical: VerifiedAnnotationMechanicalResult
        let persistence: VerifiedAnnotationPersistenceStatus
        let failure: String?
        let recovery: String?
        let recordedAtMilliseconds: Int64
        let nativeEvidenceLinks: [VerifiedAnnotationEvidenceLink]
        let checkpointReferences: [VerifiedAnnotationCheckpointReference]
    }

    private func legacyReaderAccepts(canonicalBytes bytes: Data) throws {
        let bad = VerifiedAnnotationAuditError.malformedRecord
        guard let decoded = try? VerifiedAnnotationAuditCodec.decode(LegacyV1Body.self, from: bytes),
              try VerifiedAnnotationAuditCodec.encode(decoded) == bytes,
              decoded.domain == VerifiedAnnotationAuditRecord.domain else { throw bad }
    }

    // (a) T6
    func testV1NameAndCommentRecordsKeepGoldenBytesAndRoundTripByteIdentically() throws {
        let name = try fixedRecord(0xA1, "1")
        let comment = try fixedRecord(0xA2, "2")
        XCTAssertEqual(String(decoding: name.canonicalBytes, as: UTF8.self), goldenV1Name)
        XCTAssertEqual(name.digest, goldenV1NameDigest)
        XCTAssertEqual(comment.digest, goldenV1CommentDigest)
        for item in [name, comment, try record()] {
            XCTAssertNil(item.body.fieldClass)
            XCTAssertEqual(item.body.domain, VerifiedAnnotationAuditRecord.domain)
            XCTAssertFalse(String(decoding: item.canonicalBytes, as: UTF8.self).contains("fieldClass"))
            XCTAssertFalse(item.usesTypedEditEncoding)
        }
        // Naming the legacy classes explicitly still produces the v1 encoding with no key.
        for legacy in [FieldClass.name, .comment] {
            XCTAssertEqual(try fixedRecord(0xA1, "1", fieldClass: legacy).canonicalBytes, name.canonicalBytes)
        }
        let envelope = try fixedEnvelope([name, comment])
        let encoded = try VerifiedAnnotationAuditCodec.encode(envelope)
        let decoded = try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditEnvelope.self, from: encoded)
        XCTAssertEqual(decoded, envelope)
        XCTAssertEqual(decoded.records.map(\.canonicalBytes), [name.canonicalBytes, comment.canonicalBytes])
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(decoded), encoded)
        XCTAssertFalse(envelope.usesTypedEditEncoding)
    }

    func testV1PackageKeepsFeatureListAndManifestBytesIdentical() throws {
        let envelope = try fixedEnvelope([fixedRecord(0xA1, "1"), fixedRecord(0xA2, "2")])
        let prepared = try MacScopeDocumentPackage.preparedManifest(fixedManifest(envelope), reconstructionState: .empty)
        XCTAssertEqual(prepared.requiredReaderFeatures, [auditFeature])
        let bytes = try MacScopeDocumentPackage.encodedManifest(prepared)
        let opened = try MacScopeDocumentPackage.validatedManifest(manifestData: bytes)
        XCTAssertEqual(opened.verifiedAnnotationAudit, envelope)
        XCTAssertEqual(try MacScopeDocumentPackage.encodedManifest(opened), bytes)
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains(typedFeature))
    }

    // (b)
    func testV2AddressTypeAndFunctionSignatureRecordsRoundTrip() throws {
        let type = try fixedRecord(0xA3, "3", fieldClass: .addressType)
        let signature = try fixedRecord(0xA4, "4", fieldClass: .functionSignature)
        XCTAssertEqual(String(decoding: type.canonicalBytes, as: UTF8.self), goldenV2AddressType)
        XCTAssertEqual(type.digest, goldenV2AddressTypeDigest)
        XCTAssertEqual(type.body.domain, VerifiedAnnotationAuditRecord.domainV2)
        XCTAssertEqual(type.body.domain, "com.jeff.macscope.verified-annotation-audit.record.v2")
        XCTAssertEqual(type.recordedFieldClass, .addressType)
        XCTAssertEqual(signature.recordedFieldClass, .functionSignature)
        XCTAssertTrue(String(decoding: signature.canonicalBytes, as: UTF8.self).contains("\"fieldClass\":\"functionSignature\""))
        XCTAssertTrue(type.usesTypedEditEncoding && signature.usesTypedEditEncoding)
        let envelope = try fixedEnvelope([fixedRecord(0xA1, "1"), type, signature])
        XCTAssertTrue(envelope.usesTypedEditEncoding)
        let encoded = try VerifiedAnnotationAuditCodec.encode(envelope)
        let decoded = try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditEnvelope.self, from: encoded)
        XCTAssertEqual(decoded, envelope)
        XCTAssertEqual(try VerifiedAnnotationAuditCodec.encode(decoded), encoded)
        XCTAssertEqual(decoded.records[1].canonicalBytes, type.canonicalBytes)
        // Bounds are unchanged and the envelope schema stays 1.
        XCTAssertEqual(VerifiedAnnotationAuditEnvelope.maximumRecords, 256)
        XCTAssertEqual(VerifiedAnnotationAuditEnvelope.maximumRecordBytes, 8 * 1024 * 1024)
        XCTAssertEqual(VerifiedAnnotationAuditEnvelope.maximumEncodedBytes, 24 * 1024 * 1024)
        XCTAssertEqual(try object(envelope)["schemaVersion"] as? Int, 1)
    }

    func testV2PackageDeclaresFeatureAndRoundTripsByteIdentically() throws {
        let envelope = try fixedEnvelope([fixedRecord(0xA1, "1"), fixedRecord(0xA3, "3", fieldClass: .addressType)])
        let prepared = try MacScopeDocumentPackage.preparedManifest(fixedManifest(envelope), reconstructionState: .empty)
        XCTAssertEqual(prepared.requiredReaderFeatures, [auditFeature, typedFeature])
        XCTAssertEqual(typedFeature, "verified-annotation.typed-edits.v1")
        let bytes = try MacScopeDocumentPackage.encodedManifest(prepared)
        let opened = try MacScopeDocumentPackage.validatedManifest(manifestData: bytes)
        XCTAssertEqual(opened.verifiedAnnotationAudit, envelope)
        XCTAssertEqual(try MacScopeDocumentPackage.encodedManifest(opened), bytes)
        XCTAssertTrue(MacScopeDocumentPackage.supportedReaderFeatures.contains(typedFeature))
    }

    // (c)
    func testV2WithNameOrCommentAndV1WithFieldClassAreMalformed() throws {
        let v2 = try bodyObject(fixedRecord(0xA3, "3", fieldClass: .addressType))
        let v1 = try bodyObject(fixedRecord(0xA1, "1"))
        var cases: [[String: Any]] = []
        for raw in ["name", "comment", "notAClass"] { var body = v2; body["fieldClass"] = raw; cases.append(body) }
        var noKey = v2; noKey.removeValue(forKey: "fieldClass"); cases.append(noKey)
        var nullKey = v2; nullKey["fieldClass"] = NSNull(); cases.append(nullKey)
        for raw in ["name", "comment", "addressType", "functionSignature"] { var body = v1; body["fieldClass"] = raw; cases.append(body) }
        for body in cases {
            XCTAssertThrowsError(try VerifiedAnnotationAuditCodec.decode(VerifiedAnnotationAuditRecord.self, from: wire(body)),
                                 "\(body["domain"] ?? "?") \(body["fieldClass"] ?? "nil")") {
                XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
            }
        }
        // The same refusals hold when a Body is built directly rather than decoded.
        let good = try fixedRecord(0xA3, "3", fieldClass: .addressType).body
        func body(domain: String, fieldClass: FieldClass?) -> VerifiedAnnotationAuditRecord.Body {
            .init(domain: domain, operationID: good.operationID, requestDigest: good.requestDigest, decision: good.decision,
                  before: good.before, after: good.after, mechanical: good.mechanical, persistence: good.persistence,
                  failure: nil, recovery: nil, recordedAtMilliseconds: good.recordedAtMilliseconds,
                  nativeEvidenceLinks: good.nativeEvidenceLinks, checkpointReferences: [], fieldClass: fieldClass)
        }
        let v1Domain = VerifiedAnnotationAuditRecord.domain, v2Domain = VerifiedAnnotationAuditRecord.domainV2
        for bad in [body(domain: v2Domain, fieldClass: .name), body(domain: v2Domain, fieldClass: .comment),
                    body(domain: v2Domain, fieldClass: nil), body(domain: v1Domain, fieldClass: .addressType),
                    body(domain: v1Domain, fieldClass: .name)] {
            XCTAssertThrowsError(try VerifiedAnnotationAuditRecord(body: bad)) {
                XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
            }
        }
        XCTAssertNoThrow(try VerifiedAnnotationAuditRecord(body: body(domain: v2Domain, fieldClass: .functionSignature)))
        XCTAssertNoThrow(try VerifiedAnnotationAuditRecord(body: body(domain: v1Domain, fieldClass: nil)))
    }

    // (d) T7
    func testTypedEditsFeatureEquivalenceRefusesBothDirectionsWithDistinctErrors() throws {
        let v2 = try fixedEnvelope([fixedRecord(0xA3, "3", fieldClass: .addressType)])
        let v1 = try fixedEnvelope([fixedRecord(0xA1, "1")])
        func refusal(_ envelope: VerifiedAnnotationAuditEnvelope?, features: [String]) throws -> Error? {
            var manifest = fixedManifest(envelope)
            manifest.requiredReaderFeatures = features
            let bytes = try MacScopeDocumentPackage.encodedManifest(manifest)
            do { _ = try MacScopeDocumentPackage.validatedManifest(manifestData: bytes); return nil } catch { return error }
        }
        // A v2 record without the feature.
        XCTAssertEqual(try refusal(v2, features: [auditFeature]) as? VerifiedAnnotationAuditError, .typedEditsFeatureMissing)
        // The feature without a v2 record: v1-only envelope, and no envelope at all.
        XCTAssertEqual(try refusal(v1, features: [auditFeature, typedFeature]) as? VerifiedAnnotationAuditError,
                       .typedEditsFeatureWithoutRecords)
        XCTAssertEqual(try refusal(nil, features: [typedFeature]) as? VerifiedAnnotationAuditError,
                       .typedEditsFeatureWithoutRecords)
        // Agreeing manifests open.
        XCTAssertNil(try refusal(v2, features: [auditFeature, typedFeature]))
        XCTAssertNil(try refusal(v1, features: [auditFeature]))
        XCTAssertNotEqual(VerifiedAnnotationAuditError.typedEditsFeatureMissing, .typedEditsFeatureWithoutRecords)
        XCTAssertNotEqual(VerifiedAnnotationAuditError.typedEditsFeatureMissing, .readerFeatureDisagreement)
        XCTAssertNotNil(VerifiedAnnotationAuditError.typedEditsFeatureMissing.errorDescription)
        XCTAssertNotNil(VerifiedAnnotationAuditError.typedEditsFeatureWithoutRecords.errorDescription)
        XCTAssertNotEqual(VerifiedAnnotationAuditError.typedEditsFeatureMissing.errorDescription,
                          VerifiedAnnotationAuditError.typedEditsFeatureWithoutRecords.errorDescription)
    }

    // (e) T7
    func testSimulatedOldReaderGetsUnsupportedFeatureThenMalformedRecordWhenCheckBypassed() throws {
        let envelope = try fixedEnvelope([fixedRecord(0xA1, "1"), fixedRecord(0xA3, "3", fieldClass: .addressType)])
        let prepared = try MacScopeDocumentPackage.preparedManifest(fixedManifest(envelope), reconstructionState: .empty)
        let bytes = try MacScopeDocumentPackage.encodedManifest(prepared)
        let oldReaderFeatures = MacScopeDocumentPackage.supportedReaderFeatures.subtracting([typedFeature])
        XCTAssertThrowsError(try MacScopeDocumentPackage.decodedManifestForReaderTesting(bytes, supportedFeatures: oldReaderFeatures)) {
            XCTAssertEqual($0 as? MacScopeDocumentPackage.UnsupportedReaderFeaturesError, .init(features: [typedFeature]))
            XCTAssertTrue($0.localizedDescription.contains(typedFeature))
            XCTAssertFalse($0.localizedDescription.contains("reconstruction job"))
        }
        // The current reader accepts the same bytes.
        XCTAssertNoThrow(try MacScopeDocumentPackage.decodedManifestForReaderTesting(
            bytes, supportedFeatures: MacScopeDocumentPackage.supportedReaderFeatures))
        // Feature check bypassed: the old reader's record decode refuses the v2 record, and accepts the v1 one.
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let records = try XCTUnwrap((root["verifiedAnnotationAudit"] as? [String: Any])?["records"] as? [[String: Any]])
        XCTAssertEqual(records.count, 2)
        func canonical(_ index: Int) throws -> Data {
            try XCTUnwrap(Data(base64Encoded: XCTUnwrap(records[index]["canonicalBytes"] as? String)))
        }
        XCTAssertNoThrow(try legacyReaderAccepts(canonicalBytes: canonical(0)))
        XCTAssertThrowsError(try legacyReaderAccepts(canonicalBytes: canonical(1))) {
            XCTAssertEqual($0 as? VerifiedAnnotationAuditError, .malformedRecord)
        }
    }

    // (f) ruling 9, refined
    func testFieldClassMatchesTruthTable() throws {
        func base() -> AddressOverride {
            var override = AddressOverride(customName: "n", customComment: "c", tag: "t", colorTag: .red, isData: false,
                signature: FunctionSignatureOverride(returnType: "int"), appliedTypeName: "T",
                switchHint: SwitchHintOverride(tableBase: 0x1000, entryCount: 2), operandFormat: .hex,
                markAsProcedure: false, dataShape: DataShapeOverride(kind: .array, elementType: "int32_t", elementCount: 2),
                isUndefined: false, patch: BytePatch(bytes: [0x1f, 0x20, 0x03, 0xd5]),
                appendedExecutableCave: AppendedExecutableCaveAuthoring(ownerBinaryID: uuid(0x10), functionID: uuid(0x11),
                    selectedSliceSHA256: String(repeating: "a", count: 64), branchSourceAddress: 0x1000,
                    codeBytes: Data([0, 0, 0, 0])),
                registerNames: ["x19": "count"], stackLocals: ["0-8": StackLocalOverride(name: "a")], localLabel: "loc")
            override.ownReturnAuthorityFile = "authority"
            return override
        }
        typealias Mutation = (inout AddressOverride) -> Void
        var owner: [(String, FieldClass?, Mutation)] = []
        owner.append(("customName", .name, { $0.customName = "other" } as Mutation))
        owner.append(("customComment", .comment, { $0.customComment = "other" } as Mutation))
        owner.append(("appliedTypeName", .addressType, { $0.appliedTypeName = "U" } as Mutation))
        owner.append(("signature", .functionSignature, { $0.signature = FunctionSignatureOverride(returnType: "void") } as Mutation))
        owner.append(("ownReturnAuthorityFile", .functionSignature, { $0.ownReturnAuthorityFile = "elsewhere" } as Mutation))
        owner.append(("tag", nil, { $0.tag = "other" } as Mutation))
        owner.append(("colorTag", nil, { $0.colorTag = .blue } as Mutation))
        owner.append(("isData", nil, { $0.isData = true } as Mutation))
        owner.append(("switchHint", nil, { $0.switchHint = SwitchHintOverride(tableBase: 0x2000, entryCount: 3) } as Mutation))
        owner.append(("operandFormat", nil, { $0.operandFormat = .decimal } as Mutation))
        owner.append(("markAsProcedure", nil, { $0.markAsProcedure = true } as Mutation))
        owner.append(("dataShape", nil, { $0.dataShape = DataShapeOverride(kind: .alignment, alignment: 8) } as Mutation))
        owner.append(("isUndefined", nil, { $0.isUndefined = true } as Mutation))
        owner.append(("patch", nil, { $0.patch = BytePatch(bytes: [0]) } as Mutation))
        owner.append(("appendedExecutableCave", nil, { $0.appendedExecutableCave = nil } as Mutation))
        owner.append(("registerNames", nil, { $0.registerNames = ["x20": "i"] } as Mutation))
        owner.append(("stackLocals", nil, { $0.stackLocals = ["0-8": StackLocalOverride(name: "b")] } as Mutation))
        owner.append(("localLabel", nil, { $0.localLabel = "other" } as Mutation))
        XCTAssertEqual(Set(owner.compactMap { $0.1 }), Set(FieldClass.allCases))
        for fieldClass in FieldClass.allCases {
            // No change at all matches (an unchanged override differs in no field).
            XCTAssertTrue(fieldClass.fieldClassMatches(previous: base(), new: base()), "\(fieldClass) unchanged")
            for (field, ownerClass, mutate) in owner {
                var changed = base()
                mutate(&changed)
                XCTAssertNotEqual(changed, base(), "\(field) mutation must change the override")
                XCTAssertEqual(fieldClass.fieldClassMatches(previous: base(), new: changed), ownerClass == fieldClass,
                               "\(fieldClass) vs changed \(field)")
            }
            // Changing the owned field together with another field is false.
            var both = base()
            let ownMutation = try XCTUnwrap(owner.first(where: { $0.1 == fieldClass })).2
            ownMutation(&both)
            XCTAssertTrue(fieldClass.fieldClassMatches(previous: base(), new: both), "\(fieldClass) owned only")
            both.tag = "extra"
            XCTAssertFalse(fieldClass.fieldClassMatches(previous: base(), new: both), "\(fieldClass) owned plus tag")
        }
        // A missing override is the empty override.
        for fieldClass in FieldClass.allCases {
            XCTAssertTrue(fieldClass.fieldClassMatches(previous: nil, new: nil))
            XCTAssertTrue(fieldClass.fieldClassMatches(previous: nil, new: AddressOverride()))
            XCTAssertFalse(fieldClass.fieldClassMatches(previous: base(), new: nil))
        }
        XCTAssertTrue(FieldClass.name.fieldClassMatches(previous: nil, new: AddressOverride(customName: "x")))
        XCTAssertFalse(FieldClass.comment.fieldClassMatches(previous: nil, new: AddressOverride(customName: "x")))
        XCTAssertTrue(FieldClass.addressType.fieldClassMatches(previous: AddressOverride(appliedTypeName: "T"), new: nil))
        XCTAssertTrue(FieldClass.functionSignature.fieldClassMatches(previous: nil,
            new: AddressOverride(signature: FunctionSignatureOverride(returnType: "int"))))
    }

    func testAuditFieldClassVocabularyMatchesVerifiedFieldClass() {
        XCTAssertEqual(Set(FieldClass.allCases.map(\.rawValue)), Set(VerifiedFieldClass.allCases.map(\.rawValue)))
        for fieldClass in VerifiedFieldClass.allCases {
            XCTAssertEqual(FieldClass(rawValue: fieldClass.rawValue)?.usesTypedEditEncoding,
                           fieldClass == .addressType || fieldClass == .functionSignature)
        }
    }
}
#endif
