import Foundation
import XCTest
@testable import MacScope

/// VA4 slice A, Option A: the fresh reader judges saved bytes in this process. The literal
/// acceptance (a separate child process opening the saved package) is NOT RUN here.
///
/// The cases that need the VA3b commit service or the edit journal (P1-P7, H1-H4, torn tail,
/// unattached audit) live in VerifiedCheckpointCommitTests.
final class VerifiedCheckpointTests: XCTestCase {
    private let workspaceID = UUID()
    private let documentID = UUID()
    private let writerInstallation = UUID()
    private let target = 0x4000 as UInt64

    private func stamp(_ revision: UInt64, installation: UUID? = nil) -> VerifiedAnnotationProjectionIdentity {
        .init(workspaceID: workspaceID, documentID: documentID, installationID: installation ?? writerInstallation,
              revision: revision, digest: String(repeating: revision % 2 == 0 ? "a" : "b", count: 64))
    }

    private func digest(_ seed: String) -> String { VerifiedAnnotationAuditCodec.sha256Hex(Data(seed.utf8)) }

    private func record(_ id: UUID, seed: String = "r", before: UInt64 = 0, rejected: Bool = false,
                        installation: UUID? = nil,
                        fieldClass: VerifiedAnnotationAuditFieldClass? = nil) throws -> VerifiedAnnotationAuditRecord {
        try VerifiedAnnotationAuditRecord(operationID: id, requestDigest: digest(seed),
            decision: rejected ? .rejected : .accepted, before: stamp(before, installation: installation),
            after: rejected ? nil : stamp(before + 1, installation: installation),
            mechanical: rejected ? .notVerified : .candidateReadbackVerified,
            persistence: rejected ? .notApplicable : .pendingFreshProcessCheckpoint,
            failure: rejected ? "candidate mismatch" : nil, recordedAtMilliseconds: 1_234,
            nativeEvidenceLinks: [.init(evidenceID: UUID(), preconditionDigest: digest("c"))],
            fieldClass: fieldClass)
    }

    private func expectOp(_ id: UUID, seed: String = "r", before: UInt64 = 0, rejected: Bool = false,
                          slot: Int = 0, field: String = "name", requested: String = "parse_header",
                          baseline: String? = nil) -> VerifiedCheckpointExpectation.Operation {
        .init(operationID: id, requestDigest: digest(seed), decision: rejected ? .rejected : .accepted,
              slot: slot, address: target, field: field, requested: requested, baseline: baseline,
              imageSHA256: nil, beforeRevision: before, afterRevision: rejected ? nil : before + 1)
    }

    private func expectation(_ ops: [VerifiedCheckpointExpectation.Operation],
                             writerPID: Int32? = 100) -> VerifiedCheckpointExpectation {
        .init(schemaVersion: VerifiedCheckpointExpectation.requiredSchemaVersion(for: ops),
              workspaceID: workspaceID, documentID: documentID,
              writerInstallationIDs: [writerInstallation], writerProcessID: writerPID, operations: ops)
    }

    private func contents(_ records: [VerifiedAnnotationAuditRecord]?, name: String? = nil, comment: String? = nil,
                          slotPresent: Bool = true, appliedType: String? = nil, definitions: [String] = [],
                          repairs: [WorkspaceAnalysisRepair] = [],
                          signature: FunctionSignatureOverride? = nil) throws -> WorkspacePackageContents {
        var envelope: VerifiedAnnotationAuditEnvelope?
        if let records {
            var built = VerifiedAnnotationAuditEnvelope.empty
            for record in records { built = try built.appending(record, workspaceID: workspaceID, documentID: documentID) }
            envelope = built
        }
        let manifest = WorkspacePackageManifest(formatVersion: 1, documentID: documentID, workspaceUUID: workspaceID,
            workspaceName: "Checkpoint", createdAt: Date(timeIntervalSince1970: 1),
            modifiedAt: Date(timeIntervalSince1970: 1), binaries: [], session: nil, verifiedAnnotationAudit: envelope)
        var overrides: [ImageAddress: AddressOverride] = [:]
        if name != nil || comment != nil || appliedType != nil || signature != nil {
            var value = AddressOverride(isData: false)
            value.customName = name
            value.customComment = comment
            value.appliedTypeName = appliedType
            value.signature = signature
            overrides[.primary(target)] = value
        }
        let images = slotPresent ? [BinaryImage(id: UUID(), name: "target", path: "/synthetic",
                                                kind: "Mach-O", architecture: "arm64")] : []
        var snapshot = WorkspaceSnapshot(binaries: images, analysisBySlot: [:], addressOverrides: overrides)
        snapshot.typeDefinitions = definitions.map { TypeDefinition(kind: .struct, name: $0) }
        var result = WorkspacePackageContents(manifest: manifest, snapshot: snapshot, attachmentsByBinaryID: [:])
        result.analysisRepairs = repairs
        return result
    }

    private func reader(pid: Int32 = 200, installation: UUID = UUID()) -> VerifiedCheckpointReaderIdentity {
        .init(installationID: installation, processID: pid, executable: "/synthetic/MacScope")
    }

    private func outcomes(_ report: VerifiedCheckpointReport) -> [VerifiedCheckpointOutcome] {
        report.operations.map(\.outcome)
    }

    // MARK: - Pass paths

    func testAcceptedAnnotationIsConfirmedAndPassesFromADifferentProcess() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(report), [.confirmed])
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertTrue(report.processIsolated)
        XCTAssertTrue(report.passed)
    }

    func testSameProcessConfirmsFieldsButNeverClaimsTheLiteralAcceptance() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id)], writerPID: 200), reader: reader(pid: 200))
        XCTAssertEqual(outcomes(report), [.confirmed])
        XCTAssertTrue(report.allOperationsPass)
        XCTAssertFalse(report.processIsolated)
        XCTAssertFalse(report.passed)
        // An unknown writer process is not isolation either.
        XCTAssertFalse(VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id)], writerPID: nil), reader: reader()).passed)
    }

    func testCommentFieldAndTwoOperationChainConfirm() throws {
        let first = UUID(), second = UUID()
        let report = VerifiedCheckpoint.check(
            contents: try contents([try record(first, seed: "a", before: 0), try record(second, seed: "b", before: 1)],
                                   name: "parse_header", comment: "reads the Mach-O header"),
            expectation: expectation([expectOp(first, seed: "a", before: 0),
                expectOp(second, seed: "b", before: 1, field: "comment", requested: "reads the Mach-O header")]),
            reader: reader())
        XCTAssertEqual(outcomes(report), [.confirmed, .confirmed])
        XCTAssertTrue(report.passed)
    }

    func testRejectedOperationIsRecordedWhenBaselineIsUnchanged() throws {
        let accepted = UUID(), rejected = UUID()
        let report = VerifiedCheckpoint.check(
            contents: try contents([try record(accepted, seed: "a", before: 0), try record(rejected, seed: "b", before: 1, rejected: true)],
                                   name: "parse_header", comment: nil),
            expectation: expectation([expectOp(accepted, seed: "a", before: 0),
                expectOp(rejected, seed: "b", before: 1, rejected: true, field: "comment", requested: "wrong", baseline: nil)]),
            reader: reader())
        XCTAssertEqual(outcomes(report), [.confirmed, .rejectedRecorded])
        XCTAssertTrue(report.passed)
    }

    func testLoadRepairsAreReportedAsTransformationNotesNotHidden() throws {
        let id = UUID()
        let repair = WorkspaceAnalysisRepair(slot: .primary, imageName: "target", duplicateFunctions: 2)
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header", repairs: [repair]),
            expectation: expectation([expectOp(id)]), reader: reader())
        guard case let .confirmedAfterTransformation(notes) = outcomes(report).first else {
            return XCTFail("expected a transformation outcome: \(outcomes(report))")
        }
        XCTAssertTrue(notes.joined().contains("target"))
        XCTAssertTrue(report.passed)
        XCTAssertFalse(report.notes.isEmpty)
    }

    // MARK: - Findings

    func testAbsentOperationAndUnexpectedRecordBothFail() throws {
        let expected = UUID(), other = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(other)]),
            expectation: expectation([expectOp(expected)]), reader: reader())
        XCTAssertEqual(outcomes(report), [.operationAbsent])
        XCTAssertEqual(report.unexpectedOperationIDs, [other])
        XCTAssertFalse(report.passed)

        // An extra record fails even when every expected operation is confirmed.
        let id = UUID()
        let extra = VerifiedCheckpoint.check(
            contents: try contents([try record(id, before: 0), try record(other, seed: "x", before: 1)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(extra), [.confirmed])
        XCTAssertEqual(extra.unexpectedOperationIDs, [other])
        XCTAssertFalse(extra.allOperationsPass)
        XCTAssertFalse(extra.passed)
    }

    func testAnnotationWithoutAnyReceiptIsItsOwnFinding() throws {
        let id = UUID(), other = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(other)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(report), [.annotationWithoutReceipt])
        XCTAssertFalse(report.passed)
    }

    func testRejectedReceiptWithTheRequestedValuePresentIsAnnotationWithoutReceipt() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id, rejected: true)], name: "parse_header"),
            expectation: expectation([expectOp(id, rejected: true)]), reader: reader())
        XCTAssertEqual(outcomes(report), [.annotationWithoutReceipt])
    }

    func testReceiptWithoutEffectWhenValueStillEqualsBaseline() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "old_name"),
            expectation: expectation([expectOp(id, baseline: "old_name")]), reader: reader())
        XCTAssertEqual(outcomes(report), [.receiptWithoutEffect])
        XCTAssertFalse(report.passed)
    }

    func testDifferentStoredValueIsAMismatchNamingBothSides() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "other_name"),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(report), [.mismatch(field: "value", expected: "\"parse_header\"", observed: "\"other_name\"")])
    }

    func testRequestDigestDecisionAndRevisionMismatchesAreNamed() throws {
        let id = UUID()
        let stored = try contents([try record(id)], name: "parse_header")
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(contents: stored,
            expectation: expectation([expectOp(id, seed: "different")]), reader: reader())).first?.code, "mismatch")
        let digestReport = VerifiedCheckpoint.check(contents: stored,
            expectation: expectation([expectOp(id, seed: "different")]), reader: reader())
        guard case let .mismatch(field, _, _) = digestReport.operations[0].outcome else { return XCTFail("digest") }
        XCTAssertEqual(field, "requestDigest")
        let decision = VerifiedCheckpoint.check(contents: stored,
            expectation: expectation([expectOp(id, rejected: true)]), reader: reader())
        guard case let .mismatch(decisionField, _, _) = decision.operations[0].outcome else { return XCTFail("decision") }
        XCTAssertEqual(decisionField, "decision")
        let revision = VerifiedCheckpoint.check(contents: stored,
            expectation: expectation([expectOp(id, before: 3)]), reader: reader())
        // before 3 is chain-consistent only against the stored record when it equals the stored one.
        guard case let .mismatch(revisionField, _, _) = revision.operations[0].outcome else { return XCTFail("revision") }
        XCTAssertEqual(revisionField, "beforeRevision")
    }

    func testBrokenAcceptedChainIsReportedAtTheBreak() throws {
        let first = UUID(), second = UUID()
        // The second accepted record skips revision 1: before 5 after 6.
        let report = VerifiedCheckpoint.check(
            contents: try contents([try record(first, seed: "a", before: 0), try record(second, seed: "b", before: 5)], name: "parse_header"),
            expectation: expectation([expectOp(first, seed: "a", before: 0), expectOp(second, seed: "b", before: 5)]),
            reader: reader())
        XCTAssertEqual(report.operations[0].outcome, .confirmed)
        XCTAssertEqual(report.operations[1].outcome, .chainBroken(revision: 6))
        XCTAssertFalse(report.passed)
    }

    func testRejectedRecordsDoNotAdvanceTheChain() throws {
        let rejected = UUID(), accepted = UUID()
        let report = VerifiedCheckpoint.check(
            contents: try contents([try record(rejected, seed: "a", before: 0, rejected: true), try record(accepted, seed: "b", before: 0)],
                                   name: "parse_header"),
            expectation: expectation([expectOp(rejected, seed: "a", before: 0, rejected: true, field: "comment", requested: "x"),
                                      expectOp(accepted, seed: "b", before: 0)]),
            reader: reader())
        XCTAssertEqual(outcomes(report), [.rejectedRecorded, .confirmed])
    }

    func testAuditAbsentOrEmptyIsUnattached() throws {
        let id = UUID()
        for stored in [try contents(nil, name: "parse_header"), try contents([], name: "parse_header")] {
            let report = VerifiedCheckpoint.check(contents: stored, expectation: expectation([expectOp(id)]), reader: reader())
            XCTAssertEqual(report.packageOutcome, .auditUnattached)
            XCTAssertFalse(report.passed)
        }
    }

    func testReaderSharingAnArchivedInstallationIsNotFresh() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader(installation: writerInstallation))
        XCTAssertEqual(report.packageOutcome, .installationNotFresh)
        XCTAssertFalse(report.passed)
        // An installation that appears only inside a record counts too.
        let recorded = UUID()
        let hidden = VerifiedCheckpoint.check(contents: try contents([try record(id, installation: recorded)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader(installation: recorded))
        XCTAssertEqual(hidden.packageOutcome, .installationNotFresh)
    }

    func testTargetSlotMissingIsATargetIdentityMismatch() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header", slotPresent: false),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(report).first?.code, "targetIdentityMismatch")
        let wrongSlot = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id, slot: 3)]), reader: reader())
        XCTAssertEqual(outcomes(wrongSlot).first?.code, "targetIdentityMismatch")
    }

    func testImageDigestExpectationIsEnforcedWhenGiven() throws {
        let id = UUID()
        var op = expectOp(id)
        op = .init(operationID: op.operationID, requestDigest: op.requestDigest, decision: op.decision, slot: op.slot,
                   address: op.address, field: op.field, requested: op.requested, baseline: op.baseline,
                   imageSHA256: digest("not the image"), beforeRevision: op.beforeRevision, afterRevision: op.afterRevision)
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([op]), reader: reader())
        XCTAssertEqual(outcomes(report), [.targetIdentityMismatch(reason: "image sha256 differs")])
    }

    func testWrongWorkspaceOrDocumentFailsEveryOperation() throws {
        let id = UUID()
        let stored = try contents([try record(id)], name: "parse_header")
        let wrongWorkspace = VerifiedCheckpointExpectation(schemaVersion: 1, workspaceID: UUID(), documentID: documentID,
            writerInstallationIDs: [], writerProcessID: 100, operations: [expectOp(id)])
        guard case let .mismatch(field, _, _)? = VerifiedCheckpoint.check(contents: stored, expectation: wrongWorkspace, reader: reader()).packageOutcome else {
            return XCTFail("workspace")
        }
        XCTAssertEqual(field, "workspaceID")
        let wrongDocument = VerifiedCheckpointExpectation(schemaVersion: 1, workspaceID: workspaceID, documentID: UUID(),
            writerInstallationIDs: [], writerProcessID: 100, operations: [expectOp(id)])
        guard case let .mismatch(documentField, _, _)? = VerifiedCheckpoint.check(contents: stored, expectation: wrongDocument, reader: reader()).packageOutcome else {
            return XCTFail("document")
        }
        XCTAssertEqual(documentField, "documentID")
    }

    // MARK: - Expectation bounds

    func testInvalidExpectationsAreTypedAndNeverReadTheRecords() throws {
        let id = UUID()
        let stored = try contents([try record(id)], name: "parse_header")
        func reason(_ expectation: VerifiedCheckpointExpectation) -> String? {
            guard case let .expectationInvalid(reason)? = VerifiedCheckpoint.check(contents: stored, expectation: expectation, reader: reader()).packageOutcome else { return nil }
            return reason
        }
        XCTAssertEqual(reason(expectation([])), "expectation-no-operations")
        XCTAssertEqual(reason(expectation([expectOp(id), expectOp(id)])), "expectation-duplicate-operation")
        XCTAssertEqual(reason(expectation((0...256).map { _ in expectOp(UUID()) })), "expectation-too-many-operations")
        XCTAssertEqual(reason(expectation([expectOp(id, requested: String(repeating: "n", count: 257))])), "expectation-value-too-large")
        XCTAssertEqual(reason(expectation([expectOp(id, field: "comment", requested: String(repeating: "c", count: 2_049))])), "expectation-value-too-large")
        XCTAssertNil(reason(expectation([expectOp(id, field: "comment", requested: String(repeating: "c", count: 2_048))])))
        XCTAssertEqual(reason(expectation([expectOp(id, field: "tag")])), "expectation-field")
        XCTAssertEqual(reason(expectation([expectOp(id, requested: "")])), "expectation-requested-empty")
        XCTAssertEqual(reason(.init(schemaVersion: 2, workspaceID: workspaceID, documentID: documentID,
            writerInstallationIDs: [], writerProcessID: nil, operations: [expectOp(id)])), "expectation-schema-version")
    }

    func testExpectationJSONIsBoundedAndStrict() throws {
        let id = UUID()
        let good = try JSONEncoder().encode(expectation([expectOp(id)]))
        XCTAssertEqual(try VerifiedCheckpointExpectation.decode(good).operations.count, 1)
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(good + Data(repeating: 0x20, count: 65_536)))
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(Data("{}".utf8)))
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(Data("not json".utf8)))
    }

    // MARK: - Report shape and the real reader

    func testReportJSONNamesPassAndEveryOperation() throws {
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader())
        guard case let .object(fields) = report.jsonValue(), case let .array(items)? = fields["operations"] else {
            return XCTFail("shape")
        }
        XCTAssertEqual(fields["passed"], .bool(true))
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(fields["packageOutcome"], .null)
    }

    func testProductionReaderCarriesTheAuditThroughASavedPackageAndMissingPackagesAreTyped() throws {
        let id = UUID()
        let source = try contents([try record(id)], name: "parse_header")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("vcp-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let package = root.appendingPathComponent("saved.mscope")
        try MacScopeDocumentPackage.writePackage(source.manifest, attachmentsByBinaryID: [:], to: package)
        let report = VerifiedCheckpoint.run(packageURL: package, expectation: expectation([expectOp(id)]), reader: reader())
        // The package has no image, so the record is read back through the production reader but the
        // target cannot be confirmed; that proves the audit bytes survive the save.
        XCTAssertEqual(report.packageOutcome, nil)
        XCTAssertEqual(outcomes(report).first?.code, "targetIdentityMismatch")
        XCTAssertEqual(report.workspaceID, workspaceID)

        let missing = VerifiedCheckpoint.run(packageURL: root.appendingPathComponent("absent.mscope"),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(missing.packageOutcome?.code, "packageUnreadable")
        XCTAssertFalse(missing.passed)
    }

    // MARK: - VA-SCOPE slice S5: expectation v2 (type at address)

    private let typeClass = VerifiedAnnotationAuditFieldClass.addressType

    private func typeOp(_ id: UUID, seed: String = "r", before: UInt64 = 0, rejected: Bool = false,
                        requested: String = "Header", baseline: String? = nil) -> VerifiedCheckpointExpectation.Operation {
        .addressType(operationID: id, requestDigest: digest(seed), decision: rejected ? .rejected : .accepted,
                     slot: 0, address: target, requested: requested, baseline: baseline,
                     beforeRevision: before, afterRevision: rejected ? nil : before + 1)
    }

    private func typedExpectation(_ ops: [VerifiedCheckpointExpectation.Operation]) -> VerifiedCheckpointExpectation {
        expectation(ops)
    }

    private func invalidReason(_ expectation: VerifiedCheckpointExpectation) -> String? {
        do { try expectation.validate(); return nil } catch { return (error as? VerifiedCheckpointInvalid)?.reason }
    }

    /// (a) T9 name/comment half. The literal was written by hand from the synthesized v1 encoder
    /// (sorted keys, nil optionals omitted) before any S5 change; nothing here depends on S5 code to derive it.
    private let goldenV1 = #"{"documentID":"00000000-0000-0000-0000-000000000002","operations":[{"address":16384,"afterRevision":1,"beforeRevision":0,"decision":"accepted","field":"name","operationID":"00000000-0000-0000-0000-0000000000A1","requestDigest":"1111111111111111111111111111111111111111111111111111111111111111","requested":"parse_header","slot":0}],"schemaVersion":1,"workspaceID":"00000000-0000-0000-0000-000000000001","writerInstallationIDs":["00000000-0000-0000-0000-000000000003"],"writerProcessID":100}"#

    private func goldenExpectation() -> VerifiedCheckpointExpectation {
        func id(_ n: Int) -> UUID { UUID(uuidString: String(format: "00000000-0000-0000-0000-%012X", n))! }
        let op = VerifiedCheckpointExpectation.Operation(
            operationID: id(0xA1), requestDigest: String(repeating: "1", count: 64), decision: .accepted, slot: 0,
            address: 0x4000, field: "name", requested: "parse_header", baseline: nil, imageSHA256: nil,
            beforeRevision: 0, afterRevision: 1)
        return .init(schemaVersion: 1, workspaceID: id(1), documentID: id(2), writerInstallationIDs: [id(3)],
                     writerProcessID: 100, operations: [op])
    }

    func testT9NameCommentV1BytesAreUnchangedAndStillJudged() throws {
        let bytes = try goldenExpectation().encoded()
        XCTAssertEqual(String(decoding: bytes, as: UTF8.self), goldenV1)
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains("fieldClass"))
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains("requestedDigest"))
        // The frozen bytes decode with both the current and the simulated old reader.
        XCTAssertEqual(try VerifiedCheckpointExpectation.decode(Data(goldenV1.utf8)), goldenExpectation())
        XCTAssertNoThrow(try VerifiedCheckpointExpectation.decode(Data(goldenV1.utf8), supportedSchemaVersions: 1...1))
        // A mixed name/comment expectation is still schema 1 and is judged as before.
        let id = UUID()
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id)], name: "parse_header"),
            expectation: expectation([expectOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(report), [.confirmed])
        XCTAssertEqual(expectation([expectOp(id)]).schemaVersion, 1)
    }

    /// (b)
    func testT9TypeV2AcceptedIsConfirmedAndRejectedKeepsBaselineSemantics() throws {
        let id = UUID()
        let confirmed = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "Header", definitions: ["Header", "Other"]),
            expectation: typedExpectation([typeOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(confirmed), [.confirmed], "\(confirmed.operations)")
        XCTAssertTrue(confirmed.allOperationsPass)
        XCTAssertEqual(typedExpectation([typeOp(id)]).schemaVersion, 2)

        // Rejected plus baseline still applied: rejectedRecorded.
        let rejected = VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: typeClass)], appliedType: "OldType", definitions: ["OldType"]),
            expectation: typedExpectation([typeOp(id, rejected: true, requested: "Header", baseline: "OldType")]), reader: reader())
        XCTAssertEqual(outcomes(rejected), [.rejectedRecorded])
        // Rejected, but the requested type is present: annotationWithoutReceipt, as for name/comment.
        let leaked = VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: typeClass)], appliedType: "Header", definitions: ["Header"]),
            expectation: typedExpectation([typeOp(id, rejected: true)]), reader: reader())
        XCTAssertEqual(outcomes(leaked), [.annotationWithoutReceipt])
        // Accepted but the baseline is still applied: receiptWithoutEffect.
        let noEffect = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "OldType", definitions: ["OldType", "Header"]),
            expectation: typedExpectation([typeOp(id, baseline: "OldType")]), reader: reader())
        XCTAssertEqual(outcomes(noEffect), [.receiptWithoutEffect])
        // A different type is a value mismatch; a v1-domain record for a typed operation is a fieldClass mismatch.
        let other = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "Other", definitions: ["Other"]),
            expectation: typedExpectation([typeOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(other).first?.code, "mismatch")
        let wrongClass = VerifiedCheckpoint.check(
            contents: try contents([try record(id)], appliedType: "Header", definitions: ["Header"]),
            expectation: typedExpectation([typeOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(wrongClass), [.mismatch(field: "fieldClass", expected: "addressType", observed: "nil")])
        // No receipt at all, type present: its own finding; type absent: operationAbsent.
        let orphan = VerifiedCheckpoint.check(
            contents: try contents([try record(UUID(), seed: "x", fieldClass: typeClass)], appliedType: "Header", definitions: ["Header"]),
            expectation: typedExpectation([typeOp(id)]), reader: reader())
        XCTAssertEqual(outcomes(orphan), [.annotationWithoutReceipt])
    }

    /// (c)
    func testT9ZeroOrAmbiguousTypeDefinitionIsATypedFindingNotAConfirm() throws {
        let id = UUID()
        for definitions in [[], ["Header", "Header"], ["Other"]] as [[String]] {
            let report = VerifiedCheckpoint.check(
                contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "Header", definitions: definitions),
                expectation: typedExpectation([typeOp(id)]), reader: reader())
            let expectedCount = String(definitions.filter { $0 == "Header" }.count)
            guard case let .mismatch(field, _, observed)? = outcomes(report).first else {
                return XCTFail("expected a typed finding for \(definitions): \(outcomes(report))")
            }
            XCTAssertEqual(field, "typeDefinition")
            XCTAssertEqual(observed, expectedCount)
            XCTAssertFalse(report.allOperationsPass)
        }
    }

    /// (d)
    func testT9OldReaderRefusesV2AndSchema1CannotCarryATypedField() throws {
        let id = UUID()
        let typed = typedExpectation([typeOp(id)])
        let bytes = try typed.encoded()
        let text = String(decoding: bytes, as: UTF8.self)
        XCTAssertTrue(text.contains("\"schemaVersion\":2"))
        XCTAssertTrue(text.contains("\"fieldClass\":\"addressType\""))
        XCTAssertEqual(try VerifiedCheckpointExpectation.decode(bytes), typed)
        // Simulated old reader (schema-1-only validate): the same bytes fail closed on the version.
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(bytes, supportedSchemaVersions: 1...1)) {
            XCTAssertEqual(($0 as? VerifiedCheckpointInvalid)?.reason, "expectation-schema-version")
        }
        XCTAssertEqual(invalidReason(typed), nil)
        XCTAssertThrowsError(try typed.validate(supportedSchemaVersions: 1...1)) {
            XCTAssertEqual(($0 as? VerifiedCheckpointInvalid)?.reason, "expectation-schema-version")
        }
        // A schema-1 document carrying a typed field fails with expectation-field, with or without fieldClass.
        let asV1 = VerifiedCheckpointExpectation(schemaVersion: 1, workspaceID: workspaceID, documentID: documentID,
            writerInstallationIDs: [], writerProcessID: nil, operations: [typeOp(id)])
        XCTAssertEqual(invalidReason(asV1), "expectation-field")
        let fieldOnly = VerifiedCheckpointExpectation(schemaVersion: 1, workspaceID: workspaceID, documentID: documentID,
            writerInstallationIDs: [], writerProcessID: nil, operations: [expectOp(id, field: "addressType", requested: "Header")])
        XCTAssertEqual(invalidReason(fieldOnly), "expectation-field")
        // Schema 2 exists only for typed edits; the writer enforces both directions.
        let emptyV2 = VerifiedCheckpointExpectation(schemaVersion: 2, workspaceID: workspaceID, documentID: documentID,
            writerInstallationIDs: [], writerProcessID: nil, operations: [expectOp(id)])
        XCTAssertEqual(invalidReason(emptyV2), "expectation-schema-version")
        XCTAssertThrowsError(try asV1.encoded())
        // A mixed v2 document keeps name/comment operations in the v1 shape.
        let mixed = typedExpectation([expectOp(UUID()), typeOp(UUID(), seed: "t")])
        XCTAssertEqual(mixed.schemaVersion, 2)
        XCTAssertNoThrow(try mixed.encoded())
        // A signature operation is judged by the S5b reader; invalid signature text is expectation-signature.
        let signature = VerifiedCheckpointExpectation(schemaVersion: 2, workspaceID: workspaceID, documentID: documentID,
            writerInstallationIDs: [], writerProcessID: nil, operations: [typeOp(UUID()),
                .init(operationID: UUID(), requestDigest: digest("s"), decision: .accepted, slot: 0, address: target,
                      field: "functionSignature", requested: "{}", baseline: nil, imageSHA256: nil, beforeRevision: 1,
                      afterRevision: 2, fieldClass: "functionSignature", requestedDigest: digest("{}"))])
        XCTAssertEqual(invalidReason(signature), "expectation-signature")
    }

    /// (e)
    func testT9TypeBoundsAndRequestedDigest() throws {
        let id = UUID()
        let atLimit = String(repeating: "T", count: 256)
        XCTAssertNil(invalidReason(typedExpectation([typeOp(id, requested: atLimit, baseline: atLimit)])))
        let over = String(repeating: "T", count: 257)
        XCTAssertEqual(invalidReason(typedExpectation([typeOp(id, requested: over)])), "expectation-value-too-large")
        XCTAssertEqual(invalidReason(typedExpectation([typeOp(id, baseline: over)])), "expectation-value-too-large")
        // Multi-byte: 129 two-byte characters is 258 bytes.
        XCTAssertEqual(invalidReason(typedExpectation([typeOp(id, requested: String(repeating: "\u{00E9}", count: 129))])),
                       "expectation-value-too-large")
        // The digest must match the value, and must be present.
        let good = typeOp(id)
        func with(digest newDigest: String?) -> VerifiedCheckpointExpectation.Operation {
            .init(operationID: good.operationID, requestDigest: good.requestDigest, decision: good.decision,
                  slot: good.slot, address: good.address, field: good.field, requested: good.requested,
                  baseline: good.baseline, imageSHA256: nil, beforeRevision: good.beforeRevision,
                  afterRevision: good.afterRevision, fieldClass: good.fieldClass, requestedDigest: newDigest)
        }
        XCTAssertEqual(invalidReason(typedExpectation([with(digest: digest("Other"))])), "expectation-requested-digest")
        XCTAssertEqual(invalidReason(typedExpectation([with(digest: nil)])), "expectation-requested-digest")
        XCTAssertEqual(invalidReason(typedExpectation([with(digest: String(digest("Header").uppercased()))])), "expectation-requested-digest")
        XCTAssertNil(invalidReason(typedExpectation([with(digest: digest("Header"))])))
        // Non-canonical or blank type names, and a digest on a name operation, are refused.
        XCTAssertEqual(invalidReason(typedExpectation([typeOp(id, requested: " Header")])), "expectation-type-name")
        XCTAssertEqual(invalidReason(typedExpectation([typeOp(id, requested: "He\nader")])), "expectation-type-name")
        XCTAssertEqual(invalidReason(typedExpectation([typeOp(id, requested: "")])), "expectation-requested-empty")
        let nameWithDigest = VerifiedCheckpointExpectation.Operation(operationID: id, requestDigest: digest("r"),
            decision: .accepted, slot: 0, address: target, field: "name", requested: "n", baseline: nil, imageSHA256: nil,
            beforeRevision: 0, afterRevision: 1, requestedDigest: digest("n"))
        XCTAssertEqual(invalidReason(expectation([nameWithDigest])), "expectation-requested-digest")
        // The 65,536-byte request-file bound is unchanged for v2.
        let bytes = try typedExpectation([typeOp(id)]).encoded()
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(bytes + Data(repeating: 0x20, count: 65_536))) {
            XCTAssertEqual(($0 as? VerifiedCheckpointInvalid)?.reason, "expectation-too-large")
        }
        // An invalid typed expectation never reads records.
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "Header", definitions: ["Header"]),
            expectation: typedExpectation([typeOp(id, requested: over)]), reader: reader())
        XCTAssertEqual(report.packageOutcome, .expectationInvalid(reason: "expectation-value-too-large"))
    }

    /// (f) in-process sub-case: a typed v2 audit record survives the production writer and reader. The
    /// child-process fresh-reader acceptance is slice G and is NOT RUN; the S4 commit path does not exist yet.
    func testT9TypedAuditRecordSurvivesASavedPackageThroughTheProductionReader() throws {
        let id = UUID()
        let source = try contents([try record(id, fieldClass: typeClass)], appliedType: "Header", definitions: ["Header"])
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("vcp-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let package = root.appendingPathComponent("typed.mscope")
        try MacScopeDocumentPackage.writePackage(source.manifest, attachmentsByBinaryID: [:], to: package)
        let report = VerifiedCheckpoint.run(packageURL: package, expectation: typedExpectation([typeOp(id)]), reader: reader())
        XCTAssertNil(report.packageOutcome, "\(String(describing: report.packageOutcome))")
        XCTAssertEqual(outcomes(report).first?.code, "targetIdentityMismatch")
        XCTAssertEqual(report.workspaceID, workspaceID)
    }

    // MARK: - VA-SCOPE slice S5b: checkpoint v2 judges function signatures, plus typed erase

    private let signatureClass = VerifiedAnnotationAuditFieldClass.functionSignature

    private func sig(_ returnType: String? = "int", _ rows: [(String, String)] = [("a", "int"), ("b", "char *")]) -> FunctionSignatureOverride {
        FunctionSignatureOverride(returnType: returnType,
            args: rows.enumerated().map { ArgOverride(index: $0.offset, name: $0.element.0, type: $0.element.1) })
    }

    private func canon(_ signature: FunctionSignatureOverride) throws -> String {
        try VerifiedFieldCodec.canonicalSignature(signature)
    }

    private func sigOp(_ id: UUID, seed: String = "r", before: UInt64 = 0, rejected: Bool = false,
                       requested: String, baseline: String? = nil,
                       erase: Bool = false) -> VerifiedCheckpointExpectation.Operation {
        .functionSignature(operationID: id, requestDigest: digest(seed), decision: rejected ? .rejected : .accepted,
                           slot: 0, address: target, requested: requested, baseline: baseline,
                           beforeRevision: before, afterRevision: rejected ? nil : before + 1, erase: erase)
    }

    /// (a) T9 "Checkpoint v2 judges type and signature; v1 still judges name/comment": frozen S5 type v2 bytes.
    /// Written by hand from the S5 FORMAT.md (sorted keys, nil optionals omitted) before the S5b change;
    /// no `erase` key may appear.
    private let goldenTypeV2 = #"{"documentID":"00000000-0000-0000-0000-000000000002","operations":[{"address":16384,"afterRevision":1,"beforeRevision":0,"decision":"accepted","field":"addressType","fieldClass":"addressType","operationID":"00000000-0000-0000-0000-0000000000A2","requestDigest":"1111111111111111111111111111111111111111111111111111111111111111","requested":"Header","requestedDigest":"ba5caa4285a84d88129280d2c3f6d796b4e2da069981e845bdaa55d9e6cfe7b5","slot":0}],"schemaVersion":2,"workspaceID":"00000000-0000-0000-0000-000000000001","writerInstallationIDs":["00000000-0000-0000-0000-000000000003"],"writerProcessID":100}"#

    func testT9SignatureV2GoldenTypeV2AndNameV1BytesAreUnchanged() throws {
        func id(_ n: Int) -> UUID { UUID(uuidString: String(format: "00000000-0000-0000-0000-%012X", n))! }
        let typed = VerifiedCheckpointExpectation.Operation.addressType(
            operationID: id(0xA2), requestDigest: String(repeating: "1", count: 64), decision: .accepted, slot: 0,
            address: 0x4000, requested: "Header", baseline: nil, beforeRevision: 0, afterRevision: 1)
        let expectationV2 = VerifiedCheckpointExpectation(schemaVersion: 2, workspaceID: id(1), documentID: id(2),
            writerInstallationIDs: [id(3)], writerProcessID: 100, operations: [typed])
        let text = String(decoding: try expectationV2.encoded(), as: UTF8.self)
        XCTAssertEqual(text, goldenTypeV2)
        XCTAssertFalse(text.contains("erase"))
        XCTAssertEqual(try VerifiedCheckpointExpectation.decode(Data(goldenTypeV2.utf8)), expectationV2)
        XCTAssertEqual(String(decoding: try goldenExpectation().encoded(), as: UTF8.self), goldenV1)
    }

    /// (b)
    func testT9SignatureV2AcceptedIsConfirmedAndDifferencesAreValueMismatches() throws {
        let id = UUID()
        let requested = try canon(sig())
        // Confirmed against an override carrying that signature; no TypeDefinition is needed.
        let confirmed = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: signatureClass)], signature: sig()),
            expectation: expectation([sigOp(id, requested: requested)]), reader: reader())
        XCTAssertEqual(outcomes(confirmed), [.confirmed], "\(confirmed.operations)")
        XCTAssertEqual(expectation([sigOp(id, requested: requested)]).schemaVersion, 2)
        // Parameter order and return type differences are value mismatches.
        for other in [sig("int", [("b", "char *"), ("a", "int")]), sig("long")] {
            let report = VerifiedCheckpoint.check(
                contents: try contents([try record(id, fieldClass: signatureClass)], signature: other),
                expectation: expectation([sigOp(id, requested: requested)]), reader: reader())
            guard case let .mismatch(field, _, _)? = outcomes(report).first else { return XCTFail("\(outcomes(report))") }
            XCTAssertEqual(field, "value")
        }
        // Baseline still applied: receiptWithoutEffect. Rejected + baseline: rejectedRecorded.
        let baseline = try canon(sig("void", []))
        let noEffect = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: signatureClass)], signature: sig("void", [])),
            expectation: expectation([sigOp(id, requested: requested, baseline: baseline)]), reader: reader())
        XCTAssertEqual(outcomes(noEffect), [.receiptWithoutEffect])
        let rejected = VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: signatureClass)], signature: sig("void", [])),
            expectation: expectation([sigOp(id, rejected: true, requested: requested, baseline: baseline)]), reader: reader())
        XCTAssertEqual(outcomes(rejected), [.rejectedRecorded])
        // Rejected but the requested signature is present; and no receipt at all with it present.
        let leaked = VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: signatureClass)], signature: sig()),
            expectation: expectation([sigOp(id, rejected: true, requested: requested, baseline: baseline)]), reader: reader())
        XCTAssertEqual(outcomes(leaked), [.annotationWithoutReceipt])
        let orphan = VerifiedCheckpoint.check(
            contents: try contents([try record(UUID(), seed: "x", fieldClass: signatureClass)], signature: sig()),
            expectation: expectation([sigOp(id, requested: requested)]), reader: reader())
        XCTAssertEqual(outcomes(orphan), [.annotationWithoutReceipt])
        // A record of another class for a signature operation is a fieldClass mismatch.
        let wrongClass = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], signature: sig()),
            expectation: expectation([sigOp(id, requested: requested)]), reader: reader())
        XCTAssertEqual(outcomes(wrongClass), [.mismatch(field: "fieldClass", expected: "functionSignature", observed: "addressType")])
    }

    /// (c)
    func testT9SignatureV2InvalidNonCanonicalDigestAndOversizeAreRefusedWithTypedReasons() throws {
        let id = UUID()
        let good = try canon(sig())
        XCTAssertNil(invalidReason(expectation([sigOp(id, requested: good, baseline: try canon(sig("void", [])))])))
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: "not json")])), "expectation-signature")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: good, baseline: "{}")])), "expectation-signature")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: " " + good)])), "expectation-signature")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: good + " ")])), "expectation-signature")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: "")])), "expectation-requested-empty")
        let over = String(repeating: "x", count: VerifiedFieldCodec.maximumSignatureBytes + 1)
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: over)])), "expectation-value-too-large")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: good, baseline: over)])), "expectation-value-too-large")
        let base = sigOp(id, requested: good)
        func with(digest newDigest: String?) -> VerifiedCheckpointExpectation.Operation {
            .init(operationID: base.operationID, requestDigest: base.requestDigest, decision: base.decision,
                  slot: base.slot, address: base.address, field: base.field, requested: base.requested,
                  baseline: base.baseline, imageSHA256: nil, beforeRevision: base.beforeRevision,
                  afterRevision: base.afterRevision, fieldClass: base.fieldClass, requestedDigest: newDigest)
        }
        XCTAssertEqual(invalidReason(expectation([with(digest: digest("other"))])), "expectation-requested-digest")
        XCTAssertEqual(invalidReason(expectation([with(digest: nil)])), "expectation-requested-digest")
        XCTAssertEqual(base.requestedDigest, digest(good))
        XCTAssertNil(invalidReason(expectation([with(digest: digest(good))])))
        // field and fieldClass must agree.
        let mismatched = VerifiedCheckpointExpectation.Operation(operationID: id, requestDigest: digest("r"),
            decision: .accepted, slot: 0, address: target, field: "addressType", requested: good, baseline: nil,
            imageSHA256: nil, beforeRevision: 0, afterRevision: 1, fieldClass: "functionSignature",
            requestedDigest: digest(good))
        XCTAssertEqual(invalidReason(expectation([mismatched])), "expectation-field")
        // An invalid signature expectation never reads records.
        let report = VerifiedCheckpoint.check(contents: try contents([try record(id, fieldClass: signatureClass)], signature: sig()),
            expectation: expectation([sigOp(id, requested: "not json")]), reader: reader())
        XCTAssertEqual(report.packageOutcome, .expectationInvalid(reason: "expectation-signature"))
    }

    /// (d)
    func testT9TypedEraseIsConfirmedWhenAbsentAndRefusedWhenMalformed() throws {
        let id = UUID()
        let oldSignature = try canon(sig())
        func erasedType(rejected: Bool = false, baseline: String? = "OldType") -> VerifiedCheckpointExpectation.Operation {
            .addressType(operationID: id, requestDigest: digest("r"), decision: rejected ? .rejected : .accepted,
                         slot: 0, address: target, requested: "", baseline: baseline, beforeRevision: 0,
                         afterRevision: rejected ? nil : 1, erase: true)
        }
        // Bytes: erase is written only when true.
        let eraseText = String(decoding: try expectation([erasedType()]).encoded(), as: UTF8.self)
        XCTAssertTrue(eraseText.contains("\"erase\":true"))
        XCTAssertTrue(eraseText.contains("\"requested\":\"\""))
        XCTAssertTrue(eraseText.contains("\"requestedDigest\":\"\(digest(""))\""))
        XCTAssertEqual(try VerifiedCheckpointExpectation.decode(Data(eraseText.utf8)), expectation([erasedType()]))
        // addressType erase: confirmed when the override has no type (no TypeDefinition needed).
        let typeGone = VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], name: "n"),
            expectation: expectation([erasedType()]), reader: reader())
        XCTAssertEqual(outcomes(typeGone), [.confirmed], "\(typeGone.operations)")
        // Still at baseline: receiptWithoutEffect; another type: value mismatch.
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "OldType", definitions: ["OldType"]),
            expectation: expectation([erasedType()]), reader: reader())), [.receiptWithoutEffect])
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: typeClass)], appliedType: "Other", definitions: ["Other"]),
            expectation: expectation([erasedType()]), reader: reader())).first?.code, "mismatch")
        // Rejected erase: baseline kept is rejectedRecorded; erased anyway is annotationWithoutReceipt.
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: typeClass)], appliedType: "OldType"),
            expectation: expectation([erasedType(rejected: true)]), reader: reader())), [.rejectedRecorded])
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: typeClass)], name: "n"),
            expectation: expectation([erasedType(rejected: true)]), reader: reader())), [.annotationWithoutReceipt])
        // Signature erase: confirmed when the override has no signature; receiptWithoutEffect at baseline.
        let signatureErase = sigOp(id, requested: "", baseline: oldSignature, erase: true)
        XCTAssertNil(invalidReason(expectation([signatureErase])))
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: signatureClass)], name: "n"),
            expectation: expectation([signatureErase]), reader: reader())), [.confirmed])
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: signatureClass)], signature: sig()),
            expectation: expectation([signatureErase]), reader: reader())), [.receiptWithoutEffect])
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, fieldClass: signatureClass)], signature: sig("long")),
            expectation: expectation([signatureErase]), reader: reader())).first?.code, "mismatch")
        // Refusals.
        XCTAssertEqual(invalidReason(expectation([erasedType(baseline: nil)])), "expectation-erase-without-baseline")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: "", baseline: nil, erase: true)])),
                       "expectation-erase-without-baseline")
        XCTAssertEqual(invalidReason(expectation([typeOp(id, requested: "")])), "expectation-requested-empty")
        XCTAssertEqual(invalidReason(expectation([sigOp(id, requested: "")])), "expectation-requested-empty")
        let nameErase = VerifiedCheckpointExpectation.Operation(operationID: id, requestDigest: digest("r"),
            decision: .accepted, slot: 0, address: target, field: "name", requested: "", baseline: "old", imageSHA256: nil,
            beforeRevision: 0, afterRevision: 1, erase: true)
        XCTAssertEqual(invalidReason(expectation([nameErase])), "expectation-field")
        let schema1Erase = VerifiedCheckpointExpectation(schemaVersion: 1, workspaceID: workspaceID, documentID: documentID,
            writerInstallationIDs: [], writerProcessID: nil, operations: [erasedType()])
        XCTAssertEqual(invalidReason(schema1Erase), "expectation-field")
        // Erase with a non-empty requested value, and an explicit erase:false, are not canonical.
        XCTAssertEqual(invalidReason(expectation([.addressType(operationID: id, requestDigest: digest("r"), decision: .accepted,
            slot: 0, address: target, requested: "Header", baseline: "OldType", beforeRevision: 0, afterRevision: 1,
            erase: true)])), "expectation-erase-requested-not-empty")
        let explicitFalse = VerifiedCheckpointExpectation.Operation(operationID: id, requestDigest: digest("r"),
            decision: .accepted, slot: 0, address: target, field: "addressType", requested: "Header", baseline: nil,
            imageSHA256: nil, beforeRevision: 0, afterRevision: 1, fieldClass: "addressType",
            requestedDigest: digest("Header"), erase: false)
        XCTAssertEqual(invalidReason(expectation([explicitFalse])), "expectation-field")
    }

    /// (e)
    func testT9SignatureV2IsRefusedByASchema1OnlyReader() throws {
        let op = sigOp(UUID(), requested: try canon(sig()))
        let typed = expectation([op])
        XCTAssertEqual(typed.schemaVersion, 2)
        let bytes = try typed.encoded()
        XCTAssertTrue(String(decoding: bytes, as: UTF8.self).contains("\"fieldClass\":\"functionSignature\""))
        XCTAssertEqual(try VerifiedCheckpointExpectation.decode(bytes), typed)
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(bytes, supportedSchemaVersions: 1...1)) {
            XCTAssertEqual(($0 as? VerifiedCheckpointInvalid)?.reason, "expectation-schema-version")
        }
        // The same holds for a typed erase.
        let erase = expectation([sigOp(UUID(), requested: "", baseline: try canon(sig()), erase: true)])
        XCTAssertThrowsError(try VerifiedCheckpointExpectation.decode(try erase.encoded(), supportedSchemaVersions: 1...1)) {
            XCTAssertEqual(($0 as? VerifiedCheckpointInvalid)?.reason, "expectation-schema-version")
        }
    }

    /// (f) in-process sub-case: a signature v2 audit record survives the production writer and reader.
    /// The child-process fresh-reader acceptance is slice G and is NOT RUN.
    func testT9SignatureAuditRecordSurvivesASavedPackageThroughTheProductionReader() throws {
        let id = UUID()
        let source = try contents([try record(id, fieldClass: signatureClass)], signature: sig())
        XCTAssertEqual(source.manifest.verifiedAnnotationAudit?.records.first?.recordedFieldClass, signatureClass)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("vcp-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let package = root.appendingPathComponent("signature.mscope")
        try MacScopeDocumentPackage.writePackage(source.manifest, attachmentsByBinaryID: [:], to: package)
        let report = VerifiedCheckpoint.run(packageURL: package,
            expectation: expectation([sigOp(id, requested: try canon(sig()))]), reader: reader())
        XCTAssertNil(report.packageOutcome, "\(String(describing: report.packageOutcome))")
        XCTAssertEqual(outcomes(report).first?.code, "targetIdentityMismatch")
        XCTAssertEqual(report.workspaceID, workspaceID)
    }

    /// S4 maps every rejected receipt to a v1 record with no fieldClass; a rejected typed operation must still
    /// be judged by value, and a record of a different class is still a fieldClass mismatch.
    func testT9RejectedTypedOperationAcceptsAV1RecordButNotAnotherClass() throws {
        let id = UUID()
        let signatureBaseline = try canon(sig("void", []))
        let signatureRequested = try canon(sig())
        let typeRejected = typeOp(id, rejected: true, requested: "Header", baseline: "OldType")
        let signatureRejected = sigOp(id, rejected: true, requested: signatureRequested, baseline: signatureBaseline)
        // v1 record (no fieldClass), observed == baseline: rejectedRecorded.
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true)], appliedType: "OldType", definitions: ["OldType"]),
            expectation: expectation([typeRejected]), reader: reader())), [.rejectedRecorded])
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true)], signature: sig("void", [])),
            expectation: expectation([signatureRejected]), reader: reader())), [.rejectedRecorded])
        // A different class on a rejected record is a mismatch.
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: signatureClass)], appliedType: "OldType"),
            expectation: expectation([typeRejected]), reader: reader())),
            [.mismatch(field: "fieldClass", expected: "addressType", observed: "functionSignature")])
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id, rejected: true, fieldClass: typeClass)], signature: sig("void", [])),
            expectation: expectation([signatureRejected]), reader: reader())),
            [.mismatch(field: "fieldClass", expected: "functionSignature", observed: "addressType")])
        // An accepted typed operation still needs the class.
        XCTAssertEqual(outcomes(VerifiedCheckpoint.check(
            contents: try contents([try record(id)], signature: sig()),
            expectation: expectation([sigOp(id, requested: signatureRequested)]), reader: reader())),
            [.mismatch(field: "fieldClass", expected: "functionSignature", observed: "nil")])
    }
}
