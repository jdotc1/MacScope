import Foundation

/// The nominal-type kinds recovered from Swift reflection metadata (`__swift5_types`).
/// Maps the low 5 bits of a type context descriptor's `Flags` word
/// (`ContextDescriptorKind`: 16 = class, 17 = struct, 18 = enum).
enum SwiftTypeKind: String, Hashable, Codable, Sendable {
    case `class`
    case `struct`
    case `enum`
    /// A type-context kind this reader does not model (`SwiftTypeDescriptor.rawKind` holds the
    /// raw value). Labelled and kept rather than dropped, so a newer or unusual descriptor kind
    /// stays visible instead of silently vanishing.
    case unknown

    init?(contextDescriptorKind: UInt32) {
        switch contextDescriptorKind & 0x1f {
        case 16: self = .class
        case 17: self = .struct
        case 18: self = .enum
        default: return nil
        }
    }

    /// The Swift source keyword (`class`/`struct`/`enum`) for rendering. An unknown kind has no
    /// keyword; the renderer labels it with its raw kind instead.
    var keyword: String { self == .unknown ? "" : rawValue }
}

/// One graded failure while walking untrusted Swift or Objective-C metadata.
///
/// `skippedItem`: one method/field entry could not be read; the walk skipped it and continued.
/// `abandonedList`: a type/protocol/conformance descriptor could not be read; the rest of that
/// list was abandoned, because the list itself is no longer trustworthy.
/// `labelledUnknownKind`: a descriptor of an unmodelled kind was kept with a label.
/// `walkCapped`: a context-parent walk hit the depth cap or a cycle and stopped.
struct MetadataParseDiagnostic: Hashable, Codable, Sendable {
    /// Machine-readable reason for newly decoded generic metadata; older diagnostics omit it.
    enum Code: String, Hashable, Codable, Sendable {
        case truncatedGenericMetadata
        case invalidGenericRequirement
        case unresolvedGenericReference
        case unsupportedGenericMetadata
        case invalidPackShape
        case invalidGenericValue
        case invalidConformanceTail
    }
    enum Grade: String, Hashable, Codable, Sendable {
        case skippedItem
        case abandonedList
        case labelledUnknownKind
        case walkCapped
    }

    var grade: Grade
    var address: UInt64
    var message: String
    var code: Code? = nil
}

/// Collects `MetadataParseDiagnostic`s from a parser whose walk methods are non-mutating (the
/// Objective-C reader). A class so one log is shared across `parseClasses()` + `parseCategories()`.
final class MetadataParseDiagnosticLog {
    private(set) var entries: [MetadataParseDiagnostic] = []
    /// Bounds the log itself on hostile input; later entries are counted, not stored.
    static let maxEntries = 4_096
    private(set) var droppedCount = 0

    func record(_ grade: MetadataParseDiagnostic.Grade, at address: UInt64, _ message: String) {
        guard entries.count < Self.maxEntries else { droppedCount += 1; return }
        entries.append(MetadataParseDiagnostic(grade: grade, address: address, message: message))
    }
}

/// One stored property (struct/class) or case (enum) recovered from a `__swift5_fieldmd`
/// field record.
///
/// `typeName` is a best-effort *decoded* type (e.g. `Int`, `String`, `Int32`, or a referenced
/// nominal type's name). It is `nil` when the mangled type could not be resolved with confidence
/// (an exotic generic, an unresolvable symbolic reference, an empty enum case) — correctness over
/// coverage: an honest unknown beats a fabricated type. `mangledTypeName` preserves the raw mangled
/// string (control bytes rendered as `␛`-style placeholders are stripped) for diagnostics.
struct SwiftField: Hashable, Codable, Sendable {
    var name: String
    var typeName: String?
    var mangledTypeName: String?
    /// `var` (mutable) for stored properties. From the record `Flags`.
    var isVar: Bool
    /// An indirect enum case. From the record `Flags`; false when decoding older stored payloads.
    var isIndirectCase: Bool
    /// Offset from a fully emitted static metadata field-offset vector; never inferred from types.
    var byteOffset: UInt64? = nil
    /// Why `typeName` is nil although a mangled name was present (`needsFixup`, `unsupportedReference`,
    /// `unresolvedDescriptor`, `unnameableShape`); nil when the type was named or has no mangled name.
    var unresolvedReason: String? = nil

    init(name: String, typeName: String? = nil, mangledTypeName: String? = nil, isVar: Bool = false,
         isIndirectCase: Bool = false, byteOffset: UInt64? = nil, unresolvedReason: String? = nil) {
        self.name = name
        self.typeName = typeName
        self.mangledTypeName = mangledTypeName
        self.isVar = isVar
        self.isIndirectCase = isIndirectCase
        self.byteOffset = byteOffset
        self.unresolvedReason = unresolvedReason
    }

    private enum CodingKeys: String, CodingKey {
        case name, typeName, mangledTypeName, isVar, isIndirectCase, byteOffset, unresolvedReason
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        name = try values.decode(String.self, forKey: .name)
        typeName = try values.decodeIfPresent(String.self, forKey: .typeName)
        mangledTypeName = try values.decodeIfPresent(String.self, forKey: .mangledTypeName)
        isVar = try values.decode(Bool.self, forKey: .isVar)
        isIndirectCase = try values.decodeIfPresent(Bool.self, forKey: .isIndirectCase) ?? false
        byteOffset = try values.decodeIfPresent(UInt64.self, forKey: .byteOffset)
        unresolvedReason = try values.decodeIfPresent(String.self, forKey: .unresolvedReason)
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(name, forKey: .name)
        try values.encodeIfPresent(typeName, forKey: .typeName)
        try values.encodeIfPresent(mangledTypeName, forKey: .mangledTypeName)
        try values.encode(isVar, forKey: .isVar)
        try values.encode(isIndirectCase, forKey: .isIndirectCase)
        try values.encodeIfPresent(byteOffset, forKey: .byteOffset)
        try values.encodeIfPresent(unresolvedReason, forKey: .unresolvedReason)
    }
}

/// A nominal Swift type (class/struct/enum) recovered from reflection metadata: its kind, fully
/// qualified-as-emitted name, and its stored properties or enum cases.
///
/// This is the neutral model produced by `SwiftMetadataParser` and threaded through `LoadedBinary`
/// into the workspace snapshot, exactly like `ObjCClass` — see [[macscope-objc-class-parser]] for
/// the sibling Objective-C path.
struct SwiftTypeDescriptor: Hashable, Codable, Sendable {
    var kind: SwiftTypeKind
    var name: String
    var fields: [SwiftField]
    /// The raw `ContextDescriptorKind` when `kind == .unknown`; nil for a modelled kind.
    var rawKind: UInt32?
    /// RX-02a: the type context descriptor's virtual address (its stable identity in the image).
    /// nil for a hand-built or older-build value.
    var descriptorAddress: UInt64?
    /// Descriptor-backed class members. Nil means the table layout was not resolved.
    var methods: [SwiftMetadataMethod]? = nil
    /// `Module.Outer.Inner`, from the context-parent walk; `name` stays the simple name. nil when the
    /// walk could not reach a module (cycle, unreadable or unsupported parent): never a guessed module.
    /// Anonymous (private/local) contexts are transparent in the path; an extension of a type this
    /// reader cannot name prints as `<ext:mangled>`.
    var qualifiedName: String? = nil
    /// Resolved superclass name, or diagnostic mangling when superclassUnresolvedReason is set.
    /// Diagnostic manglings (including `…` symbolic placeholders) are never authoritative names.
    /// nil for a non-class, root class, or unreadable superclass name.
    var superclass: String? = nil
    /// Why the superclass could not resolve; nil for a resolved name or absent superclass.
    var superclassUnresolvedReason: String? = nil
    /// Context descriptor flag 0x80. nil for a hand-built or older-build value.
    var isGeneric: Bool? = nil
    /// An anonymous context (private discriminator or local scope) appears in the parent chain.
    var isPrivateOrLocal: Bool? = nil
    /// The parent chain ends at the `__C` module (a Clang-imported type).
    var isImportedCType: Bool? = nil
    /// Nil for absent, unsupported or malformed generic metadata; diagnostics distinguish failures.
    var genericSignature: SwiftGenericSignature? = nil

    init(kind: SwiftTypeKind, name: String, fields: [SwiftField] = [], rawKind: UInt32? = nil,
         descriptorAddress: UInt64? = nil, methods: [SwiftMetadataMethod]? = nil, qualifiedName: String? = nil,
         superclass: String? = nil, superclassUnresolvedReason: String? = nil, isGeneric: Bool? = nil, isPrivateOrLocal: Bool? = nil,
         isImportedCType: Bool? = nil, genericSignature: SwiftGenericSignature? = nil) {
        self.kind = kind
        self.name = name
        self.fields = fields
        self.rawKind = rawKind
        self.descriptorAddress = descriptorAddress
        self.methods = methods
        self.qualifiedName = qualifiedName
        self.superclass = superclass
        self.superclassUnresolvedReason = superclassUnresolvedReason
        self.isGeneric = isGeneric
        self.isPrivateOrLocal = isPrivateOrLocal
        self.isImportedCType = isImportedCType
        self.genericSignature = genericSignature
    }
}

/// A protocol descriptor listed in `__swift5_protos`.
struct SwiftProtocolDescriptor: Hashable, Codable, Sendable {
    var name: String
    var descriptorAddress: UInt64
    var requirementSignature: [SwiftGenericRequirement]? = nil
    /// Protocol declarations only; these are not nominal generic-parameter names.
    var associatedTypeNames: [String]? = nil
}

/// A recovered Swift protocol conformance (`<type>: <protocol>`), from a `ProtocolConformance
/// Descriptor` in `__swift5_proto`. Tier-1: in-module direct conformances (the conforming type and
/// the protocol are both in this image). A conformance to an EXTERNAL protocol (bound, not yet
/// nameable) is skipped rather than half-recovered — mirrors the type parser's external-type tier.
struct SwiftConformance: Hashable, Codable, Sendable {
    var typeName: String
    var protocolName: String
    var descriptorAddress: UInt64? = nil
    /// Local nominal descriptor identity; a name alone cannot establish method ownership.
    var typeDescriptorAddress: UInt64? = nil
    /// Nil for an unresolved/unsupported witness-table layout; nil implementations stay unknown.
    var methods: [SwiftMetadataMethod]? = nil
    /// Module-qualified names beside the simple ones. nil means the reference did not resolve to a
    /// module (the simple name is all that is known); the module is never guessed.
    var typeQualifiedName: String? = nil
    var protocolQualifiedName: String? = nil
    /// Empty means the descriptor explicitly has no conditional requirements; nil is unknown.
    var conditionalRequirements: [SwiftGenericRequirement]? = nil
    var resilientWitnessCount: UInt32? = nil
    var genericWitnessTable: SwiftGenericWitnessTable? = nil
    var retroactiveContextAddress: UInt64? = nil
    var conditionalPackShapes: [SwiftGenericPackShape]? = nil
}

/// One ABI record, retaining encoded identities independently of optional presentation names.
struct SwiftGenericRequirement: Hashable, Codable, Sendable {
    enum Kind: UInt32, Hashable, Codable, Sendable {
        case `protocol` = 0, sameType = 1, baseClass = 2, sameConformance = 3
        case sameShape = 4, invertedProtocols = 5, layout = 31
    }
    var address: UInt64
    var flags: UInt32
    var subjectMangledName: String?
    var subject: String?
    /// In-memory only (not persisted): the encoded value is unknown after decoding.
    var rawPayload: UInt32? = nil
    var subjectMangledBytes: [UInt8]? = nil
    var targetMangledName: String? = nil
    var targetMangledBytes: [UInt8]? = nil
    var target: String? = nil
    var protocolDescriptorAddress: UInt64? = nil
    var conformanceDescriptorAddress: UInt64? = nil
    var layout: UInt32? = nil
    /// Opaque upper half of the 32-bit union; no protocol bit names or set width are inferred.
    var invertedProtocols: UInt16? = nil
    var genericParameterIndex: UInt16? = nil
    var unresolvedReason: String? = nil

    /// `rawPayload`, `subjectMangledBytes` and `targetMangledBytes` are in-memory copies and are
    /// deliberately not part of the persisted form; the mangled names and addresses carry identity.
    private enum CodingKeys: String, CodingKey {
        case address, flags, subjectMangledName, subject, targetMangledName, target
        case protocolDescriptorAddress, conformanceDescriptorAddress, layout
        case invertedProtocols, genericParameterIndex, unresolvedReason
    }

    var kind: Kind? { Kind(rawValue: flags & 0x1f) }
    var hasKeyArgument: Bool { flags & 0x80 != 0 }
    var isPackRequirement: Bool { flags & 0x20 != 0 }
    var isValueRequirement: Bool { flags & 0x100 != 0 }
    /// Positional parameter spellings come from SwiftDemangler, not reconstructed source names.
    var rendered: String? {
        guard let subject, unresolvedReason == nil, let kind,
              !isPackRequirement, !isValueRequirement else { return nil }
        switch kind {
        case .protocol, .baseClass: return target.map { "\(subject): \($0)" }
        case .sameType: return target.map { "\(subject) == \($0)" }
        case .sameShape: return target.map { "sameShape(\(subject), \($0))" }
        case .layout: return layout == 0 ? "\(subject): AnyObject" : nil
        case .sameConformance, .invertedProtocols: return nil
        }
    }
}

struct SwiftGenericParameter: Hashable, Codable, Sendable {
    var rawValue: UInt8
    var kind: UInt8 { rawValue & 0x3f }
    var hasKeyArgument: Bool { rawValue & 0x80 != 0 }
}

struct SwiftGenericPackShape: Hashable, Codable, Sendable {
    var kind: UInt16
    var index: UInt16
    var shapeClass: UInt16
    var unused: UInt16
}

struct SwiftGenericSignature: Hashable, Codable, Sendable {
    var headerAddress: UInt64
    var numKeyArguments: UInt16
    var flags: UInt16
    var parameters: [SwiftGenericParameter]
    var requirements: [SwiftGenericRequirement]
    /// Raw relative offsets are data only; no instantiator or recovered function is invoked.
    var instantiationCacheRelativeOffset: Int32
    var defaultInstantiationPatternRelativeOffset: Int32
    var numShapeClasses: UInt16? = nil
    var packShapes: [SwiftGenericPackShape]? = nil
    var conditionalInvertedProtocols: UInt16? = nil
    var conditionalInvertedRequirementCounts: [UInt16]? = nil
    var conditionalInvertedRequirements: [SwiftGenericRequirement]? = nil
    var valueTypes: [UInt32]? = nil
}

struct SwiftGenericWitnessTable: Hashable, Codable, Sendable {
    var witnessTableSizeInWords: UInt16
    var privateSizeAndFlags: UInt16
    var instantiatorAddress: UInt64?
    var privateDataAddress: UInt64?
    /// CompactFunctionPointer representation is target-configured; preserve its unclassified word.
    var instantiatorRawValue: UInt32? = nil
    var requiresInstantiation: Bool { privateSizeAndFlags & 1 != 0 }
    var privateSizeInWords: UInt16 { privateSizeAndFlags >> 1 }
}

/// One table record, not an inferred source declaration. Distinct records may share code.
struct SwiftMetadataMethod: Hashable, Codable, Sendable {
    enum Source: String, Hashable, Codable, Sendable { case vtable, `override`, witness }
    /// Evidence from one exact, unique in-image symbol, never a user rename.
    struct ImplementationSymbol: Hashable, Codable, Sendable {
        var rawLinkageName: String
        var name: String
    }

    var source: Source
    var index: UInt64
    var descriptorAddress: UInt64
    var implementation: UInt64?
    /// MethodDescriptorFlags or ProtocolRequirementFlags, according to source; nil if unresolved.
    var flags: UInt32?
    /// Nil for legacy records, absent symbols, aliases, shared code or nil implementations.
    var implementationSymbol: ImplementationSymbol? = nil

    var isInstance: Bool? { flags.map { $0 & 0x10 != 0 } }
    /// Metadata tables do not contain source method names. This is a positional label only.
    var label: String { "\(source.rawValue) #\(index) (name unknown)" }
    /// Preferred model spelling; `label` remains the byte-compatible positional identity.
    var name: String { implementationSymbol?.name ?? label }
}

struct SwiftOpaqueTypeDescriptor: Hashable, Codable, Sendable {
    struct UnderlyingType: Hashable, Codable, Sendable {
        var mangledTypeName: String
        var typeName: String?
    }
    var descriptorAddress: UInt64
    var parentQualifiedName: String?
    var underlyingTypes: [UnderlyingType]
    var requirementCount: UInt32
}

struct SwiftTypes2Target: Hashable, Codable, Sendable {
    var descriptorAddress: UInt64
    var flags: UInt32
    var kind: UInt32
    var qualifiedName: String?
}

/// Section arrays describe an image. They do not establish ownership of partial functions.
struct SwiftAsyncMetadata: Hashable, Codable, Sendable {
    var entries: [SwiftAsyncFunctionRecord]
    var resumePartialAddresses: [UInt64]
    var continuationPartialAddresses: [UInt64]

    /// Optimized functions can share code. Preserve array multiplicity without
    /// assigning a particular pointer record to an indistinguishable entry.
    var entryGroups: [SwiftAsyncEntryGroup] {
        Dictionary(grouping: entries, by: \.entryAddress).map { address, entries in
            // The parser repeats the same candidate set for a shared address.
            // Taking it once bounds the work even for a highly repeated target.
            SwiftAsyncEntryGroup(entryAddress: address, entryCount: entries.count,
                pointerRecords: entries.first?.pointerRecords ?? [])
        }.sorted { $0.entryAddress < $1.entryAddress }
    }
}

struct SwiftAsyncEntryGroup: Hashable, Codable, Sendable {
    var entryAddress: UInt64
    var entryCount: Int
    var pointerRecords: [SwiftAsyncFunctionPointerRecord]
}

struct SwiftAsyncFunctionRecord: Hashable, Codable, Sendable {
    var entryAddress: UInt64
    var pointerRecords: [SwiftAsyncFunctionPointerRecord]
}

struct SwiftAsyncFunctionPointerRecord: Hashable, Codable, Sendable {
    var address: UInt64
    var expectedContextSize: UInt32
}

struct SwiftCaptureMetadataSource: Hashable, Codable, Sendable {
    var typeName: String
    var sourceName: String
}

struct SwiftCaptureDescriptor: Hashable, Codable, Sendable {
    var descriptorAddress: UInt64
    var captureTypeNames: [String]
    var metadataSources: [SwiftCaptureMetadataSource]
    var numBindings: UInt32
}

struct SwiftAssociatedTypeSubstitution: Hashable, Codable, Sendable {
    var name: String
    var substitutedTypeName: String
}

struct SwiftAssociatedTypeRecord: Hashable, Codable, Sendable {
    var descriptorAddress: UInt64
    var conformingTypeName: String
    var protocolTypeName: String
    var associatedTypes: [SwiftAssociatedTypeSubstitution]
}

struct SwiftBuiltinTypeRecord: Hashable, Codable, Sendable {
    var descriptorAddress: UInt64
    var typeName: String
    var size: UInt32
    var alignmentAndFlags: UInt32
    var stride: UInt32
    var extraInhabitantCount: UInt32
}

struct SwiftMultiPayloadEnumRecord: Hashable, Codable, Sendable {
    var descriptorAddress: UInt64
    var typeName: String
    var maskByteCount: UInt32
}

struct SwiftValueWitnessSummary: Hashable, Codable, Sendable {
    var descriptorAddress: UInt64
    var typeName: String
    var size: UInt64
    var stride: UInt64
    var alignment: UInt64
    var extraInhabitantCount: UInt32
    var isPOD: Bool
    var isBitwiseTakable: Bool
    var hasEnumWitnesses: Bool
    var isIncomplete: Bool
    var flags: UInt32
    var metadataAddress: UInt64
    var tableAddress: UInt64
}


/// Instruction-level witnesses use the epoch before the instruction executes.
struct SwiftAsyncContinuationStep: Hashable, Codable, Sendable {
    var address: UInt64
    var word: UInt32
    var epoch: Int
    var effect: String? = nil
}

enum SwiftAsyncContinuationKind: String, Hashable, Codable, Sendable {
    case calleeReturn, taskSwitch, continuation
}

struct SwiftAsyncIncomingContextBound: Hashable, Codable, Sendable {
    var record: UInt64
    var size: UInt32
    var symbol: String
}

/// A numeric argument actually supplied to a task allocation, not a claim
/// that an image word is an authentic Swift function-pointer record.
struct SwiftAsyncOutgoingAllocation: Hashable, Codable, Sendable {
    var size: UInt32
    var sizeInstruction: UInt64
    var loadAddress: UInt64?
}

struct SwiftAsyncContinuationCertificate: Hashable, Codable, Sendable {
    var digest: String
    var source: UInt64
    var allocation: UInt64
    var parentStore: UInt64
    var resumeStore: UInt64
    var transfer: UInt64
    var callee: UInt64?
    var boundCallee: String?
    var calleeEvidence: String
    var resume: UInt64
    var kind: SwiftAsyncContinuationKind
    var parentOffset: Int = 0
    var resumeOffset: Int = 8
    var incomingContext: SwiftAsyncIncomingContextBound? = nil
    var outgoingAllocation: SwiftAsyncOutgoingAllocation? = nil
    /// Non-nil certificates are invocation-scoped and fail ordinary replay.
    var incomingCallerDigest: String? = nil
    var steps: [SwiftAsyncContinuationStep]
}

struct SwiftAsyncInvocationCertificate: Hashable, Codable, Sendable {
    var digest: String
    var caller: SwiftAsyncContinuationCertificate
    var continuation: SwiftAsyncContinuationCertificate
}

/// Deliberately has no unconditional edge/chain or unlinked-partial fields.
struct SwiftAsyncInvocationReport: Hashable, Codable, Sendable {
    var certificate: SwiftAsyncInvocationCertificate?
    var abstention: SwiftAsyncContinuationAbstention?
}

/// Each successive certificate describes the callee invoked by its predecessor.
/// Resume relations belong to these frames, never to a global address owner.
struct SwiftAsyncInvocationChainCertificate: Hashable, Codable, Sendable {
    var digest: String
    var frames: [SwiftAsyncContinuationCertificate]
    /// Nil is the original descent-only format. Explicit events additionally
    /// prove returns and resumed partials, without address-only ownership.
    var transitions: [SwiftAsyncInvocationTransition]? = nil
}

enum SwiftAsyncInvocationTransition: Hashable, Codable, Sendable {
    case call(frameIndex: Int)
    case returnToCaller(SwiftAsyncReturnCertificate)
}

struct SwiftAsyncReturnCertificate: Hashable, Codable, Sendable {
    var digest: String
    var source: UInt64
    var callerDigest: String
    var previousReturnDigest: String?
    var transfer: UInt64
    var resume: UInt64
    var steps: [SwiftAsyncContinuationStep]
}

struct SwiftAsyncInvocationFrontier: Hashable, Codable, Sendable {
    var callerDigest: String?
    var source: UInt64
    var instruction: UInt64
    var reason: String
}

struct SwiftAsyncInvocationDiscoveryReport: Hashable, Codable, Sendable {
    var chains: [SwiftAsyncInvocationChainCertificate]
    var frontier: [SwiftAsyncInvocationFrontier]
    var examinedSources: Int
}

struct SwiftAsyncContinuationEdge: Hashable, Codable, Sendable {
    var source: UInt64
    var resume: UInt64
    var kind: SwiftAsyncContinuationKind
    var certificate: SwiftAsyncContinuationCertificate
}

struct SwiftAsyncContinuationAbstention: Hashable, Codable, Sendable {
    var source: UInt64
    var instruction: UInt64
    var reason: String
    var mnemonic: String? = nil
}

struct SwiftAsyncContinuationChain: Hashable, Codable, Sendable {
    var entry: UInt64
    var partials: [UInt64]
    var conflicts: [UInt64]
}

struct SwiftAsyncContinuationReport: Hashable, Codable, Sendable {
    var edges: [SwiftAsyncContinuationEdge]
    var chains: [SwiftAsyncContinuationChain]
    var abstentions: [SwiftAsyncContinuationAbstention]
    var unlinkedPartials: [UInt64]
}
