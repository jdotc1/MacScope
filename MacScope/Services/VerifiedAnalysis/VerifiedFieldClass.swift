import Foundation

/// The closed set of annotation field classes a verified write can target (VA-SCOPE slice S1).
///
/// `VerifiedAnnotationField` stays name/comment only and is unchanged; this enum is the wider
/// class vocabulary. The mapping to `VAEditKind` is total in one direction and partial in the
/// other, so a Core kind this slice does not know cannot be silently classified.
enum VerifiedFieldClass: String, CaseIterable, Equatable, Sendable {
    case name, comment, addressType, functionSignature

    init(_ field: VerifiedAnnotationField) {
        switch field {
        case .name: self = .name
        case .comment: self = .comment
        }
    }

    init(editKind: VAEditKind) {
        switch editKind {
        case .functionName: self = .name
        case .functionComment: self = .comment
        case .addressType: self = .addressType
        case .functionPrototype: self = .functionSignature
        }
    }

    var editKind: VAEditKind {
        switch self {
        case .name: return .functionName
        case .comment: return .functionComment
        case .addressType: return .addressType
        case .functionSignature: return .functionPrototype
        }
    }

    /// The legacy name/comment field, or nil for the classes that field cannot express.
    var annotationField: VerifiedAnnotationField? {
        switch self {
        case .name: return .name
        case .comment: return .comment
        case .addressType, .functionSignature: return nil
        }
    }
}

/// Typed failures of the type-name and signature codecs.
enum VerifiedFieldCodecError: Error, Equatable {
    case emptyTypeName
    case typeNameTooLong
    case typeNameInvalidCharacter
    case signatureTooLarge
    case tooManyParameters
    case tooManyLegacyArguments
    case returnTypeTooLong
    case parameterNameTooLong
    case parameterTypeTooLong
    case signatureInvalidCharacter
    case malformedSignature
    case nonCanonicalSignature
}

enum VerifiedFieldCodec {
    static let maximumTypeNameBytes = 256
    static let maximumSignatureBytes = 16_384
    static let maximumParameters = 64
    static let maximumParameterNameBytes = 256
    static let maximumParameterTypeBytes = 512

    // MARK: Type name

    /// Trims exactly as `WorkspaceStore.normalizedOverrideText` does (WorkspaceStore.swift:10144-10149).
    /// That function is MainActor-isolated through its class, so the two lines are replicated here to
    /// keep the codec nonisolated. A blank result throws; clearing a type is a nil value, handled above.
    static func canonicalTypeName(_ text: String) throws -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VerifiedFieldCodecError.emptyTypeName }
        guard trimmed.utf8.count <= maximumTypeNameBytes else { throw VerifiedFieldCodecError.typeNameTooLong }
        guard !trimmed.contains("\n"), !trimmed.contains("\r"), !trimmed.contains("\0") else {
            throw VerifiedFieldCodecError.typeNameInvalidCharacter
        }
        return trimmed
    }

    // MARK: Signature

    /// Fields covered: `returnType`, the `parameterList` state and its rows in order as (name, type),
    /// `variadicState`, `noReturnState` and `quarantinedLegacyArgs` (name, type, originalIndex, and
    /// originalOrder normalized to the array offset). Fields left out: `ArgOverride.rowToken` and
    /// `ArgOverride.provenance` (ruling 7: random or editor-minted identity, not authored content),
    /// `ArgOverride.index` (a read-only compatibility coordinate, array order is the truth), and the
    /// derived `isNoReturn` and `args` projections. The schema version is a codec constant.
    private struct Canonical: Codable, Equatable {
        struct Row: Codable, Equatable { var name: String; var type: String }
        struct Legacy: Codable, Equatable {
            var name: String; var type: String; var originalIndex: Int; var originalOrder: Int
        }
        var codec: Int
        var returnType: String?
        /// nil means `.unspecified`; an empty array is the explicit `(void)` list.
        var parameters: [Row]?
        var variadicState: FunctionSignatureOverride.VariadicState
        var noReturnState: FunctionSignatureOverride.NoReturnState
        var quarantinedLegacyArgs: [Legacy]
    }

    static func canonicalSignature(_ signature: FunctionSignatureOverride) throws -> String {
        let rows: [Canonical.Row]?
        switch signature.parameterList {
        case .unspecified: rows = nil
        case .authoritative(let args): rows = args.map { Canonical.Row(name: $0.name, type: $0.type) }
        }
        let canonical = Canonical(
            codec: 1, returnType: signature.returnType, parameters: rows,
            variadicState: signature.variadicState, noReturnState: signature.noReturnState,
            quarantinedLegacyArgs: signature.quarantinedLegacyArgs.enumerated().map { offset, legacy in
                Canonical.Legacy(name: legacy.name, type: legacy.type,
                                 originalIndex: legacy.originalIndex, originalOrder: offset)
            })
        try validate(canonical)
        let data: Data
        do { data = try VACanonicalJSON.encode(canonical) } catch { throw VerifiedFieldCodecError.malformedSignature }
        guard data.count <= maximumSignatureBytes, let text = String(data: data, encoding: .utf8) else {
            throw VerifiedFieldCodecError.signatureTooLarge
        }
        return text
    }

    /// The inverse. Rows come back as the requested form: source order, name and type only. Row tokens
    /// are the deterministic compatibility tokens of `ArgOverride(index:name:type:)` with `.user`
    /// provenance, so decoding is repeatable; they carry no meaning and `canonicalSignature` ignores them.
    static func decodeSignature(_ text: String) throws -> FunctionSignatureOverride {
        let data = Data(text.utf8)
        guard data.count <= maximumSignatureBytes else { throw VerifiedFieldCodecError.signatureTooLarge }
        let canonical: Canonical
        do { canonical = try VACanonicalJSON.decode(Canonical.self, from: data) }
        catch { throw VerifiedFieldCodecError.malformedSignature }
        guard canonical.codec == 1 else { throw VerifiedFieldCodecError.malformedSignature }
        try validate(canonical)
        var list = FunctionSignatureOverride.ParameterListState.unspecified
        if let rows = canonical.parameters {
            list = .authoritative(rows.enumerated().map {
                ArgOverride(index: $0.offset, name: $0.element.name, type: $0.element.type)
            })
        }
        let result = FunctionSignatureOverride(
            returnType: canonical.returnType, parameterList: list, variadicState: canonical.variadicState,
            quarantinedLegacyArgs: canonical.quarantinedLegacyArgs.map {
                LegacyArgOverride(originalIndex: $0.originalIndex, originalOrder: $0.originalOrder,
                                  name: $0.name, type: $0.type)
            },
            noReturnState: canonical.noReturnState)
        // Equal bytes after a re-encode rejects unknown keys, key reordering and non-normalized order.
        guard try canonicalSignature(result) == text else { throw VerifiedFieldCodecError.nonCanonicalSignature }
        return result
    }

    private static func validate(_ canonical: Canonical) throws {
        func check(_ text: String, tooLong: VerifiedFieldCodecError, limit: Int) throws {
            guard text.utf8.count <= limit else { throw tooLong }
            guard !text.contains("\0") else { throw VerifiedFieldCodecError.signatureInvalidCharacter }
        }
        if let returnType = canonical.returnType {
            try check(returnType, tooLong: .returnTypeTooLong, limit: maximumParameterTypeBytes)
        }
        let rows = canonical.parameters ?? []
        guard rows.count <= maximumParameters else { throw VerifiedFieldCodecError.tooManyParameters }
        guard canonical.quarantinedLegacyArgs.count <= maximumParameters else {
            throw VerifiedFieldCodecError.tooManyLegacyArguments
        }
        for row in rows {
            try check(row.name, tooLong: .parameterNameTooLong, limit: maximumParameterNameBytes)
            try check(row.type, tooLong: .parameterTypeTooLong, limit: maximumParameterTypeBytes)
        }
        for legacy in canonical.quarantinedLegacyArgs {
            try check(legacy.name, tooLong: .parameterNameTooLong, limit: maximumParameterNameBytes)
            try check(legacy.type, tooLong: .parameterTypeTooLong, limit: maximumParameterTypeBytes)
        }
    }
}
