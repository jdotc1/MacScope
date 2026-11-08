import Foundation

/// VA7a-1: builds the `VerifiedAnnotationCommitRequest` for one name, comment, address type or function
/// signature edit. This is the release-build port of the DEBUG-only request builder in
/// `App/VerifiedCommitBatchCLI.swift`; the projector is injectable so tests can stamp with a fixture.
///
/// Everything that feeds the request digest is derived from the operation id, so a retry of the same
/// operation can rebuild the same digest (`requestDigest`) from the audit record's recorded stamps.
/// The evidence links are SYNTHETIC (one fixed placeholder digest per edit) until VA9 replaces them;
/// replies disclose this as `evidenceQuality: "synthetic-link"`.
@MainActor
enum VerifiedCommitRequestBuilder {
    nonisolated static let defaultRationale = "MCP verified-commit"
    nonisolated static let syntheticPreconditionDigest = String(repeating: "c", count: 64)

    enum Failure: Error, Equatable {
        case notFunctionEntry
        case unsupportedFieldClass
        case invalidReceipt(String)
    }

    /// A stable id derived from the operation id, so rebuilds agree.
    nonisolated static func derivedID(_ operationID: UUID, purpose: String) -> UUID {
        let hex = VerifiedAnnotationAuditCodec.sha256Hex(Data("\(operationID.uuidString)|\(purpose)".utf8))
        let head = Array(hex.prefix(32))
        let text = String(head[0..<8]) + "-" + String(head[8..<12]) + "-" + String(head[12..<16])
            + "-" + String(head[16..<20]) + "-" + String(head[20..<32])
        return UUID(uuidString: text) ?? UUID()
    }

    /// The immutable mutation request. Pure in its arguments.
    nonisolated static func mutation(
        operationID: UUID, key: ImageAddress, fieldClass: VerifiedFieldClass, value: String,
        rationale: String, before: VAProjectionStamp
    ) -> VAMutationRequest {
        VAMutationRequest(
            id: operationID, base: before,
            edits: [VAEditIntent(
                target: VATargetReference(componentID: derivedID(operationID, purpose: "component"),
                                          function: VAAddress64(key.address)),
                kind: fieldClass.editKind, value: value,
                evidenceIDs: [derivedID(operationID, purpose: "evidence")])],
            rationale: rationale)
    }

    /// The request digest for the given stamps; used to recognise an exact retry from the audit record.
    nonisolated static func requestDigest(
        operationID: UUID, key: ImageAddress, fieldClass: VerifiedFieldClass, value: String,
        rationale: String, before: VAProjectionStamp
    ) throws -> String {
        try mutation(operationID: operationID, key: key, fieldClass: fieldClass, value: value,
                     rationale: rationale, before: before).digest()
    }

    static func build(
        store: WorkspaceStore, key: ImageAddress, fieldClass: VerifiedFieldClass, value: String,
        operationID: UUID = UUID(), rationale: String = defaultRationale,
        projector: any VerifiedAnnotationProjecting = NativeAnnotationProjector(),
        isFunctionEntry: (WorkspaceSnapshot, ImageAddress) -> Bool = { NativeAddressFacts.isFunctionEntry(snapshot: $0, key: $1) }
    ) throws -> VerifiedAnnotationCommitRequest {
        // Name and comment require a function entry here; addressType and functionSignature are
        // judged by their stagers (containment, entry polarity, name resolution), not duplicated.
        if fieldClass == .name || fieldClass == .comment {
            guard isFunctionEntry(store.snapshot, key) else { throw Failure.notFunctionEntry }
        }
        let accepts = UInt64(store.verifiedAnnotationAudit.records.filter { $0.body.decision == .accepted }.count)
        let before = try projector.stamp(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, snapshot: store.snapshot, revision: accepts)
        var candidate = store.snapshot
        var overrides = candidate.addressOverrides
        var target = overrides[key] ?? AddressOverride()
        fieldClass.set(value, in: &target)
        overrides[key] = target.isEmpty ? nil : target
        candidate.addressOverrides = overrides
        let after = try projector.stamp(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, snapshot: candidate, revision: accepts + 1)
        let request = mutation(operationID: operationID, key: key, fieldClass: fieldClass, value: value,
                               rationale: rationale, before: before)
        let receipt: VAVerificationReceipt
        do {
            receipt = try VAVerificationReceipt(
                request: request, decision: .accepted, before: before, after: after,
                mechanical: .candidateReadbackVerified, persistence: .pendingFreshProcessCheckpoint)
        } catch {
            throw Failure.invalidReceipt(String(describing: error))
        }
        let projection = VAWorkspaceProjection(
            workspaceID: store.workspaceID, documentID: store.documentID,
            installationID: store.documentInstallationID, revision: accepts, components: [])
        let evidenceID = derivedID(operationID, purpose: "evidence")
        return VerifiedAnnotationCommitRequest(
            state: VAVerificationState(projection: projection, receipts: [receipt]), receipt: receipt,
            nativeEvidenceLinks: [.init(evidenceID: evidenceID, preconditionDigest: syntheticPreconditionDigest)],
            target: key, fieldClass: fieldClass, requested: value,
            expectingVersion: store.verifiedCommitVersionToken(), projector: projector)
    }
}
