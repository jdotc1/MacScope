import Foundation

/// Captured identities are supplied by the existing image/function owner. This service does not
/// read an image, mint a replacement fingerprint, or authenticate a source receipt.
struct ObjCExportCapture: Equatable, Sendable {
    var workspace: Phase2ReadWorkspaceIdentity
    var image: Phase2ReadImageIdentity
    var selectedSliceSHA256: String
    var platform: String
    var functionUUID: UUID
    var functionStart: UInt64
    var functionEnd: UInt64
    var sourceReceiptReference: String
}

struct ObjCCallEvidenceBinding: Equatable, Sendable {
    var capture: ObjCExportCapture
    var instruction: MacIRInstruction.Identity
}

enum ObjCContractAuthority: Sendable {
    case unknown, runtimeMetadata, qualifiedDeclaration, authoredCallSiteContract
}

enum ObjCExportDispatchSide: Sendable { case unknown, instance, classMethod }
enum ObjCExportMethodFamily: Sendable { case unknown, ordinary, ownershipOrLifecycle }
enum ObjCExportCallingConvention: Sendable { case unknown, darwinObjectiveC, unsupported }
enum ObjCExportLinkageKind: Sendable { case unknown, capturedRuntimeImport, displayNameOnly }
enum ObjCExportReceiverKind: Sendable {
    case unknown, enclosingInstanceSelf, qualifiedObjectParameter, classObject
}

/// Raw evidence may be incomplete. In particular, absent Boolean facts are unknown; no gate
/// replaces them with false. Qualification must already resolve inherited/macro/API-note effects.
struct ObjCMethodContractEvidence: Sendable {
    var id: String
    var binding: ObjCCallEvidenceBinding
    var authority: ObjCContractAuthority
    var sourceReference: String
    var qualification: String
    var receiverEvidenceID: String
    var selector: String
    var sourceReturnType: String?
    var explicitParameterTypes: [String]?
    var isVariadic: Bool?
    var consumesSelf: Bool?
    var hasSpecialOwnership: Bool?
    var effectiveFamily: ObjCExportMethodFamily
    var dispatchSide: ObjCExportDispatchSide
    var semanticsComplete: Bool?
    var appliesToExactReceiverAtCall: Bool?
    var callingConvention: ObjCExportCallingConvention
    var isDirectMethod: Bool?
    var runtimeEncoding: String?
}

/// A receiver witness identifies a retained parameter row and entry binding, not an expression
/// string or copied call operand. The emitted identifier must also match that row in the context.
struct ObjCOperandEvidence: Sendable {
    var id: String
    var binding: ObjCCallEvidenceBinding
    var sourceReference: String
    var kind: ObjCExportReceiverKind
    var parameterRowID: MacIRParameterRowID
    var parameterBindingID: MacIRParameterBindingID
    var sourceIdentifier: String
    var sourceType: String
    var sourceObjectTypeComplete: Bool?
}

struct ObjCEnclosingMethodEvidence: Sendable {
    var id: String
    var capture: ObjCExportCapture
    var sourceReference: String
    var ownerName: String
    var dispatchSide: ObjCExportDispatchSide
    var selfParameterRowID: MacIRParameterRowID
    var selfBindingID: MacIRParameterBindingID
    var sourceSemanticsComplete: Bool?
}

/// The runtime symbol must come from captured linkage. A display rename or selector-stub suffix
/// is not a substitute, even when it happens to spell objc_msgSend.
struct ObjCDispatchLinkageEvidence: Sendable {
    var id: String
    var binding: ObjCCallEvidenceBinding
    var sourceReference: String
    var kind: ObjCExportLinkageKind
    var runtimeSymbol: String
}

struct ObjCExportRequest: Sendable {
    var capture: ObjCExportCapture
    var function: MacIRFunction
    var linkage: [ObjCDispatchLinkageEvidence]
    var contracts: [ObjCMethodContractEvidence]
    var operands: [ObjCOperandEvidence]
    var enclosingMethods: [ObjCEnclosingMethodEvidence]
}

enum ObjCExportRefusalCode: String, Sendable {
    case budgetExceeded = "EVIDENCE_BUDGET_EXCEEDED"
    case identityMismatch = "IDENTITY_MISMATCH"
    case duplicateInstruction = "INSTRUCTION_IDENTITY_AMBIGUOUS"
    case missingInstruction = "INSTRUCTION_IDENTITY_MISSING"
    case unsupportedTarget = "TARGET_UNSUPPORTED"
    case plainDispatchUnproven = "PLAIN_DISPATCH_UNPROVEN"
    case superDispatchUnsupported = "SUPER_DISPATCH_UNSUPPORTED"
    case stubWitnessMissing = "STUB_WITNESS_NOT_IN_FRAME"
    case abiShapeUnsupported = "ABI_SHAPE_UNSUPPORTED"
    case methodShapeUnsupported = "METHOD_SHAPE_UNSUPPORTED"
    case dynamicSelectorUnsupported = "DYNAMIC_SELECTOR_UNSUPPORTED"
    case methodContractMissing = "METHOD_CONTRACT_MISSING"
    case contractConflict = "CONTRACT_CONFLICT"
    case arcContractUnknown = "ARC_CONTRACT_UNKNOWN"
    case methodVariadicUnknown = "METHOD_VARIADIC_UNKNOWN"
    case variadicUnsupported = "VARIADIC_UNSUPPORTED"
    case ownershipUnsupported = "OWNERSHIP_LOWERING_UNSUPPORTED"
    case objectOperandUnproven = "OBJECT_OPERAND_UNPROVEN"
    case emissionBindingConflict = "EMISSION_BINDING_CONFLICT"
    case dispatchSideMismatch = "DISPATCH_SIDE_MISMATCH"
    case encodingUnsupported = "ENCODING_UNSUPPORTED"
    case voidResultUsed = "VOID_RESULT_USED"
    case unusedResultUnproven = "UNUSED_RESULT_UNPROVEN"
    case unsupportedSidecar = "SEMANTIC_SIDECAR_UNSUPPORTED"
}

struct ObjCExportRefusal: Error, Equatable, Sendable {
    let code: ObjCExportRefusalCode
    let callAddress: UInt64?
    let evidenceIDs: [String]
    let missingFact: String
}

enum ObjCExportRule: String, CaseIterable, Sendable {
    case capture = "CAPTURE-BINDING-REUSED"
    case linkage = "PLAIN-DISPATCH-LINKAGE"
    case selector = "SELREF-IDENTITY"
    case contract = "QUALIFIED-VOID0-CONTRACT"
    case operand = "NONCONSUMING-OBJECT-OPERAND"
    case result = "UNUSED-CATALOG-RESULT"
    case dispatch = "FIXED-TYPED-DISPATCH"
}

enum ObjCExportStatus: String, Sendable {
    case loweredUncompiled = "LOWERED_UNCOMPILED"
    case refused = "REFUSED"
}

enum ObjCExportLimits {
    static let instructions = 2_048
    static let evidenceRecords = 64
    static let valueVisits = 32_768
    static let valueDepth = 64
    static let inputs = 128
    static let totalPhiInputs = 4_096
    static let evidenceUTF8Bytes = 256 * 1_024
    static let identifierUTF8Bytes = 128
    static let encodingUTF8Bytes = 64
}
