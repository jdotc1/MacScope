import Foundation

/// VA4 slice B: the minimal production projector. It stamps exactly the fields the checkpoint gate
/// compares (the custom name, comment and, since VA-SCOPE S3, the applied type name of each annotated
/// address) and nothing else, so it needs no disassembly and does not move when unrelated analysis changes.
///
/// Domain (VA-SCOPE ruling 3): the v1 domain is kept. `type` is a new key that is OMITTED when nil, so a
/// name/comment-only state hashes to exactly the same bytes and digest as before S3. An old build hashing a
/// typed state leaves `type` out and computes a different digest, so it refuses (fail closed).
///
/// Revision convention (VA3b): `revision` is the count of ACCEPTED audit records. The commit
/// service computes it and passes it in; this type never derives or invents one. `acceptedOrdinal`
/// restates the same rule for readers that hold only an envelope.
///
/// Not wired into `NativeIntegrationGate`: that stays all-false until VA5.
@MainActor
struct NativeAnnotationProjector: VerifiedAnnotationProjecting {
    nonisolated static let domain = "com.jeff.macscope.verified-annotation-projection.v1"

    private struct Entry: Encodable {
        let slot: Int
        let address: UInt64
        let name: String?
        let comment: String?
        /// Omitted from the encoding when nil (synthesized `encodeIfPresent`).
        let type: String?
        /// Canonical signature string (VA-SCOPE S6a); omitted when nil, like `type`.
        let signature: String?
    }

    private struct Body: Encodable {
        let domain: String
        let entries: [Entry]
    }

    nonisolated init() {}

    /// Lowercase hex SHA-256 of the canonical, stably ordered (slot, address) projection of the
    /// name, comment, applied-type and canonical-signature fields. Addresses with none of them are omitted. An empty applied
    /// type name is the same as none (`AddressOverride.isEmpty`).
    nonisolated static func digest(_ overrides: [ImageAddress: AddressOverride]) -> String {
        func type(_ override: AddressOverride) -> String? {
            override.appliedTypeName.flatMap { $0.isEmpty ? nil : $0 }
        }
        func signature(_ override: AddressOverride) -> String? {
            guard let signature = override.signature else { return nil }
            if let text = try? VerifiedFieldCodec.canonicalSignature(signature) { return text }
            // Fail closed: a signature that cannot be canonicalised still moves the stamp.
            let raw = (try? JSONEncoder().encode(signature)) ?? Data()
            return "unencodable:" + VerifiedAnnotationAuditCodec.sha256Hex(raw)
        }
        let entries = overrides
            .filter { $0.value.customName != nil || $0.value.customComment != nil || type($0.value) != nil
                || signature($0.value) != nil }
            .sorted { ($0.key.slot.rawValue, $0.key.address) < ($1.key.slot.rawValue, $1.key.address) }
            .map { Entry(slot: $0.key.slot.rawValue, address: $0.key.address,
                         name: $0.value.customName, comment: $0.value.customComment, type: type($0.value),
                         signature: signature($0.value)) }
        let data = (try? VACanonicalJSON.encode(Body(domain: domain, entries: entries))) ?? Data()
        return VerifiedAnnotationAuditCodec.sha256Hex(data)
    }

    /// The accepted-record count of an audit envelope: the revision of the state it describes.
    nonisolated static func acceptedOrdinal(_ envelope: VerifiedAnnotationAuditEnvelope?) -> UInt64 {
        UInt64(envelope?.records.filter { $0.body.decision == .accepted }.count ?? 0)
    }

    func stamp(workspaceID: UUID, documentID: UUID, installationID: UUID,
               snapshot: WorkspaceSnapshot, revision: UInt64) throws -> VAProjectionStamp {
        VAProjectionStamp(workspaceID: workspaceID, documentID: documentID, installationID: installationID,
                          revision: revision, digest: Self.digest(snapshot.addressOverrides))
    }
}
