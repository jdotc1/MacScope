import Foundation

struct ObjCMessageConstraint: Equatable, Sendable {
    enum DispatchKind: String, Equatable, Sendable {
        case directMessageSend
        case verifiedSelectorStub
    }

    enum MethodSide: String, Equatable, Sendable {
        case instance
        case `class`
    }

    enum PrototypeAuthority: String, Equatable, Sendable {
        /// Complete, fixed declaration whose rows all originate in qualified debug metadata.
        case debugFixed
        /// Reserved for a future context-bound persisted user decision.
        case contextBoundUserFixed
    }

    struct Parameter: Equatable, Sendable {
        var name: String
        var type: String
    }

    struct Evidence: Equatable, Sendable {
        var enclosingImplementation: UInt64
        var methodImplementations: [UInt64]
        var selectorReferenceAddress: UInt64?
        var ownerDescriptions: [String]
        var runtimeTypeEncodings: [String]
        var authority: PrototypeAuthority
    }

    let callAddress: UInt64
    let expectedInstructionBytes: [UInt8]
    let directTargetAddress: UInt64
    let targetSymbol: String
    let dispatchKind: DispatchKind
    let selector: String
    let receiverClassName: String
    let methodSide: MethodSide
    let returnType: String
    /// Full Objective-C method parameters, including `self` and `_cmd`.
    let methodParameters: [Parameter]
    let evidence: Evidence

    var explicitParameters: ArraySlice<Parameter> {
        methodParameters.dropFirst(2)
    }

    var selectorArity: Int {
        selector.unicodeScalars.reduce(into: 0) { count, scalar in
            if scalar == ":" { count += 1 }
        }
    }

    var isNativeInstallableInOSR1: Bool {
        dispatchKind == .directMessageSend
            && expectedInstructionBytes.count == 4
            && methodParameters.count == selectorArity + 2
            && evidence.authority == .debugFixed
    }
}

enum ObjCMessageConstraintOutcome: Equatable, Sendable {
    case installed(ObjCMessageConstraint)
    case macIROnly(ObjCMessageConstraint)
    case abstained(ObjCMessageConstraintReason)
    case contradiction(ObjCMessageConstraintReason)
}

enum ObjCMessageConstraintReason: String, Error, Equatable, Sendable {
    case notObjectiveCDispatch = "not-objective-c-dispatch"
    case selectorUnproven = "selector-unproven"
    case selectorStubNativeStorageUnsupported = "selector-stub-native-storage-unsupported"
    case receiverUnproven = "receiver-unproven"
    case methodOwnerNone = "method-owner-none"
    case methodOwnerAmbiguous = "method-owner-ambiguous"
    case methodNotFoundInStaticScope = "method-not-found-in-static-scope"
    case methodPrototypeConflict = "method-prototype-conflict"
    case fixednessUnproven = "fixedness-unproven"
    case prototypeIncomplete = "prototype-incomplete"
    case prototypeNotDebugBacked = "prototype-not-debug-backed"
    case implicitParametersUnproven = "implicit-parameters-unproven"
    case runtimeDebugTypeUnclassified = "runtime-debug-type-unclassified"
    case runtimeDebugTypeConflict = "runtime-debug-type-conflict"
    case unsupportedReturnType = "unsupported-return-type"
    case unsupportedParameterType = "unsupported-parameter-type"
    case unsupportedABILocation = "unsupported-abi-location"
    case instructionByteMismatch = "instruction-byte-mismatch"
    case directTargetMismatch = "direct-target-mismatch"
    case callAddressOutsideFunction = "call-address-outside-function"
    case constraintBudgetExceeded = "constraint-budget-exceeded"
}
