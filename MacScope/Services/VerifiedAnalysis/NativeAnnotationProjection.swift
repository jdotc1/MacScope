import Foundation

enum VerifiedAnnotationField: String, CaseIterable {
    case name, comment

    var maximumUTF8Bytes: Int { self == .name ? 256 : 2_048 }

    func value(in override: AddressOverride) -> String? {
        self == .name ? override.customName : override.customComment
    }

    func set(_ value: String?, in override: inout AddressOverride) {
        switch self {
        case .name: override.customName = value
        case .comment: override.customComment = value
        }
    }
}

/// A transient VA1 cut, not a persistence receipt or an isolated VA2 candidate.
/// Capture and compare on MainActor without suspension between setter and readback.
struct NativeAnnotationProjection: Equatable {
    let key: ImageAddress
    var target: AddressOverride
    var protectedDigest: String

    init(snapshot: WorkspaceSnapshot, key: ImageAddress) throws {
        self.key = key
        target = snapshot.addressOverrides[key] ?? AddressOverride()
        // AddressOverride deliberately omits session-only return authority from Codable.
        // Include it explicitly; a serialization-only digest would miss that protected field.
        struct ProtectedOverride: Encodable {
            let address: String
            let value: AddressOverride
            let ownReturnAuthorityFile: String?
        }
        let others = snapshot.addressOverrides
            .filter { $0.key.slot == key.slot && $0.key != key }
            .sorted { $0.key.address < $1.key.address }
            .map { ProtectedOverride(address: String($0.key.address, radix: 16), value: $0.value,
                                     ownReturnAuthorityFile: $0.value.ownReturnAuthorityFile) }
        protectedDigest = VASHA256Digest.hex(try VACanonicalJSON.encode(others))
    }

    /// CandidateVerifier's erase-exactly-the-requested-delta rule over the native override.
    /// No synthetic artifact identity or code evidence is invented to populate portable models.
    func mismatch(comparedTo before: Self, field: VerifiedAnnotationField, requested: String?) -> VerifiedAnnotationFailure.Stage? {
        guard field.value(in: target) == requested else { return .readback }
        var erased = self
        field.set(field.value(in: before.target), in: &erased.target)
        return erased == before ? nil : .protectedFields
    }

    /// The same erase-exactly-the-requested-delta rule for the type class. Only `appliedTypeName` is
    /// reset to its baseline. `dataShape` is deliberately not erased: an applied type does not change it
    /// (DATASHAPE-TRACE.md), so a shape change beside a type change stays `.protectedFields`.
    func typeMismatch(comparedTo before: Self, requested: String?) -> VerifiedAnnotationFailure.Stage? {
        guard target.appliedTypeName == requested else { return .readback }
        var erased = self
        erased.target.appliedTypeName = before.target.appliedTypeName
        return erased == before ? nil : .protectedFields
    }

    /// The erase rule for the signature class (VA-SCOPE T10). Readback compares canonical signatures, so a
    /// rowToken-only difference reads back as equal. The signature is then reset to its baseline and, only
    /// when the signature actually changed (`ArgOverride` equality includes rowToken, so a token-only change
    /// counts) and the `didSet` reset left the authority nil, `ownReturnAuthorityFile` is reset with it. Any
    /// other drift, including an authority change without a signature change, is `.protectedFields`.
    func signatureMismatch(comparedTo before: Self, requested: FunctionSignatureOverride?) -> VerifiedAnnotationFailure.Stage? {
        let observed: String?, wanted: String?
        do {
            observed = try target.signature.map(VerifiedFieldCodec.canonicalSignature)
            wanted = try requested.map(VerifiedFieldCodec.canonicalSignature)
        } catch { return .readback }
        guard observed == wanted else { return .readback }
        var erased = self
        let changed = target.signature != before.target.signature
        let authority = target.ownReturnAuthorityFile
        erased.target.signature = before.target.signature
        erased.target.ownReturnAuthorityFile = (changed && authority == nil) ? before.target.ownReturnAuthorityFile : authority
        return erased == before ? nil : .protectedFields
    }
}

/// Native producer of the `addressFacts` projection entry (VA-SCOPE S3, fixes the C10 blocker).
/// Pure over a snapshot value; it never mutates anything.
enum NativeAddressFacts {
    /// A forced procedure start or a recovered function start. Needs no segment layout, so the signature
    /// class (which has no containment requirement) can use it without a Mach-O layout.
    static func isFunctionEntry(snapshot: WorkspaceSnapshot, key: ImageAddress) -> Bool {
        snapshot.addressOverrides[key]?.markAsProcedure == true
            || (snapshot.analysis(in: key.slot)?.functions.contains { $0.startAddress == key.address } ?? false)
    }

    /// The entry for `key`, or a typed refusal when the address is not inside exactly one mapped
    /// segment of the slot. No segment layout means no proof of containment, so it refuses too.
    static func entry(snapshot: WorkspaceSnapshot, key: ImageAddress) throws -> VAAddressProjection {
        guard let records = snapshot.binary(in: key.slot)?.preferredSegmentLayout?.records else {
            throw VerifiedCandidateError(.addressOutsideSegments)
        }
        let owners = records.filter { record in
            guard record.name != "__PAGEZERO", record.preferredVMSize > 0 else { return false }
            let (end, overflow) = record.preferredVMStart.addingReportingOverflow(record.preferredVMSize)
            return !overflow && key.address >= record.preferredVMStart && key.address < end
        }
        guard owners.count == 1, let segment = owners.first?.name else {
            throw VerifiedCandidateError(.addressOutsideSegments)
        }
        let override = snapshot.addressOverrides[key]
        return VAAddressProjection(address: VAAddress64(key.address), segment: segment,
                                   isFunctionEntry: isFunctionEntry(snapshot: snapshot, key: key),
                                   appliedTypeName: override?.appliedTypeName.flatMap { $0.isEmpty ? nil : $0 })
    }
}

struct VerifiedAnnotationFailure {
    enum Stage: String {
        case normalize, candidate, commit, readback
        case protectedFields = "protected-fields"
    }
    enum Code: String {
        case valueTooLarge, unsupportedTarget, projectionUnavailable, commitFailed, candidateMismatch
        case missingCandidateField, changedIdentity, unexpectedAnnotation, measurementFailed
        case protectedFieldMismatch, expectedEffectMismatch, cancelled
        /// Type class (S3): typed refusals raised before any candidate is built.
        case invalidTypeName, unresolvedType, ambiguousType, functionEntryTarget, addressOutsideSegments
        /// Signature class (S6a): typed refusals raised before any candidate is built.
        case invalidSignature, notFunctionEntry
    }
    let code: Code
    let stage: Stage
    let recoveryHint: String
    var restored: Bool? = nil

    var value: ScriptValue {
        var fields: [String: ScriptValue] = [
            "code": .string(code.rawValue), "stage": .string(stage.rawValue),
            "recoveryHint": .string(recoveryHint),
        ]
        if let restored { fields["restored"] = .bool(restored) }
        return .object(fields)
    }

    static func isFailedReply(_ value: ScriptValue) -> Bool {
        value["ok"] == .bool(false) && value["verification"]?["code"] != nil
    }
}
