import Foundation

/// The stored function is a value snapshot. No gate accepts a caller-supplied instruction,
/// operand, replacement result, or mutable copy after this context has been admitted.
final class ObjCExportContext: Sendable {
    fileprivate let identity = UUID()
    fileprivate let request: ObjCExportRequest
    fileprivate let inspection: ObjCExportInspection

    fileprivate init(request: ObjCExportRequest, inspection: ObjCExportInspection) {
        self.request = request
        self.inspection = inspection
    }
}

fileprivate struct ObjCExportSiteKey: Equatable, Sendable {
    let context: UUID
    let instruction: MacIRInstruction.Identity
}

struct ObjCDispatchSite: Sendable {
    fileprivate let key: ObjCExportSiteKey
    fileprivate let index: Int
    fileprivate let selector: String
    fileprivate let linkageEvidenceID: String
    var callAddress: UInt64 { key.instruction.sourceAddress }
}

struct ObjCVoid0Encoding: Sendable {
    fileprivate init() {}
}

struct ObjCVoid0Contract: Sendable {
    fileprivate let key: ObjCExportSiteKey
    fileprivate let evidenceID: String
    fileprivate let receiverEvidenceID: String
    fileprivate let sourceReference: String
}

struct ObjCVoid0Operands: Sendable {
    fileprivate let key: ObjCExportSiteKey
    fileprivate let receiverIdentifier: String
    fileprivate let evidenceIDs: [String]
}

struct ObjCUnusedResult: Sendable {
    fileprivate let key: ObjCExportSiteKey
}

struct ObjCVoid0Plan: Sendable {
    fileprivate let key: ObjCExportSiteKey
    fileprivate let capture: ObjCExportCapture
    fileprivate let selector: String
    fileprivate let receiverIdentifier: String
    fileprivate let evidenceIDs: [String]
    fileprivate let sourceReference: String
}

enum ObjCVoid0Decision: Sendable {
    case lowered(ObjCVoid0Plan)
    case refused(ObjCExportRefusal)
}

struct ObjCEmittedCall: Equatable, Sendable {
    let callAddress: UInt64
    let statement: String
    let requiredHeaders: [String]
    let consumedEvidenceIDs: [String]
    let contractSourceReference: String
    let rules: [ObjCExportRule]
    let status: ObjCExportStatus
    let usesSourceAssistance: Bool
    // A statement proof never qualifies a method, class, or surrounding ownership region.
    let requiresCompleteBodyAdmission: Bool
}

struct ObjCExportReport: Sendable {
    let capture: ObjCExportCapture
    let calls: [ObjCEmittedCall]
    let refusals: [ObjCExportRefusal]
}

/// Assisted, ordinary, instance, fixed-arity void0 dispatch only. This service has no app,
/// printer, RG3, file export, compiler or runtime-execution integration.
enum ObjCVoid0ExportService {
    static func makeContext(_ request: ObjCExportRequest) -> Result<ObjCExportContext, ObjCExportRefusal> {
        attempt {
            // All nested and text bounds precede capture/evidence equality and hashing.
            let inspection = try ObjCExportInspection.inspect(request)
            let capture = request.capture
            guard capture.platform == "macos", capture.image.architecture == "arm64" else {
                throw refusal(.unsupportedTarget, "V1 requires captured Darwin arm64 macOS")
            }
            guard capture.functionStart < capture.functionEnd,
                  request.function.startAddress == capture.functionStart,
                  request.function.endAddress == capture.functionEnd,
                  let slice = capture.image.sliceIndex, slice >= 0,
                  isFingerprint(capture.selectedSliceSHA256),
                  capture.image.analysisFingerprintSHA256.map(isFingerprint) == true,
                  !capture.sourceReceiptReference.isEmpty else {
                throw refusal(.identityMismatch, "Complete existing capture, slice and function binding is required")
            }
            for instruction in request.function.instructions {
                guard instruction.source.address >= capture.functionStart,
                      instruction.source.address < capture.functionEnd else {
                    throw refusal(.identityMismatch, "Instruction is outside the captured function range",
                                  address: instruction.source.address)
                }
            }
            var evidenceIDs = Set<String>()
            func admitID(_ id: String) throws {
                guard !id.isEmpty, evidenceIDs.insert(id).inserted else {
                    throw refusal(.contractConflict, "Evidence IDs must be nonempty and unique")
                }
            }
            func admitBinding(_ binding: ObjCCallEvidenceBinding) throws {
                guard binding.capture == capture,
                      inspection.instructionIndices[binding.instruction] != nil else {
                    throw refusal(.identityMismatch, "Evidence must bind the exact retained capture and instruction",
                                  address: binding.instruction.sourceAddress)
                }
            }
            for linkage in request.linkage { try admitID(linkage.id); try admitBinding(linkage.binding) }
            for contract in request.contracts { try admitID(contract.id); try admitBinding(contract.binding) }
            for operand in request.operands { try admitID(operand.id); try admitBinding(operand.binding) }
            for method in request.enclosingMethods {
                try admitID(method.id)
                guard method.capture == capture else {
                    throw refusal(.identityMismatch, "Enclosing method belongs to another capture")
                }
            }
            return ObjCExportContext(request: request, inspection: inspection)
        }
    }

    /// Resolve exclusively by the unique identity in the immutable context. A copied or
    /// substituted instruction cannot become an input to any downstream gate.
    static func resolvePlainSend(_ identity: MacIRInstruction.Identity,
                                 in context: ObjCExportContext) -> Result<ObjCDispatchSite, ObjCExportRefusal> {
        attempt {
            guard let index = context.inspection.instructionIndices[identity] else {
                throw refusal(.missingInstruction, "Instruction identity is absent from the immutable context",
                              address: identity.sourceAddress)
            }
            let instruction = context.request.function.instructions[index]
            guard case let .call(frame, _) = instruction.operation else {
                throw refusal(.plainDispatchUnproven, "Stored instruction is not a call", address: identity.sourceAddress)
            }
            let target = canonicalRuntimeSymbol(frame.target)
            if target == "objc_msgSendSuper" || target == "objc_msgSendSuper2" {
                throw refusal(.superDispatchUnsupported, "Super dispatch needs a separate receiver/search-class proof",
                              address: identity.sourceAddress)
            }
            if target.hasPrefix("objc_msgSend$") {
                throw refusal(.stubWitnessMissing, "A selector-stub name does not retain the stub's x1 transformation",
                              address: identity.sourceAddress)
            }
            guard target == "objc_msgSend", instruction.source.mnemonic == "bl",
                  instruction.source.tailCallEffect == nil, instruction.returnTarget == nil,
                  frame.controlInputs.canonicalControlInputsForAudit.isEmpty,
                  frame.typedIndirectSignature == nil, frame.typedIndirectCalleeType == nil,
                  frame.richArguments == nil, frame.indirectResultPointer == nil,
                  frame.unknownArgumentCount == nil, frame.machineRenderArguments == nil else {
                throw refusal(.abiShapeUnsupported, "V1 requires an ordinary returning direct plain runtime send",
                              address: identity.sourceAddress)
            }
            let linkages = context.request.linkage.filter { $0.binding.instruction == identity }
            guard linkages.count == 1, let linkage = linkages.first,
                  linkage.kind == .capturedRuntimeImport, !linkage.sourceReference.isEmpty,
                  canonicalRuntimeSymbol(linkage.runtimeSymbol) == target else {
                throw refusal(.plainDispatchUnproven, "One captured runtime-import linkage is required",
                              address: identity.sourceAddress)
            }
            guard frame.arguments.count == 2, frame.arguments.observationScope == .none,
                  let receiver = frame.arguments.fixedArgument(at: 0),
                  let selector = frame.arguments.fixedArgument(at: 1),
                  receiver.location == .gpr(index: 0, carrierWidth: 64),
                  selector.location == .gpr(index: 1, carrierWidth: 64),
                  receiver.role == .fixed(sourcePosition: 0), selector.role == .fixed(sourcePosition: 1),
                  receiver.selectorEvidence == nil else {
                throw refusal(.abiShapeUnsupported, "Exactly the retained x0/x1 fixed operands are required",
                              address: identity.sourceAddress)
            }
            guard let resolved = selector.selectorEvidence, resolved.selrefAddress != 0 else {
                throw refusal(.dynamicSelectorUnsupported, "V1 requires positive structured selector-reference identity",
                              address: identity.sourceAddress)
            }
            guard isIdentifier(resolved.name), !resolved.name.contains(":"),
                  case .objectiveCSelectorColonCount(0) = frame.tailCountEvidence else {
                throw refusal(.methodShapeUnsupported,
                              "V1 admits zero explicit arguments; selector arity cannot supply absent tail values",
                              address: identity.sourceAddress)
            }
            // A present signature describes only the runtime entry, never method authority.
            guard let runtime = frame.knownSignature,
                  canonicalRuntimeSymbol(runtime.target) == target,
                  runtime.returnType == "id", runtime.isVariadic,
                  runtime.parameters.count == 2,
                  runtime.parameters[0].index == 0, runtime.parameters[0].register == "x0",
                  runtime.parameters[0].type == "id",
                  runtime.parameters[1].index == 1, runtime.parameters[1].register == "x1",
                  runtime.parameters[1].type == "SEL" else {
                throw refusal(.contractConflict, "Captured runtime frame disagrees with the ordinary msgSend entry",
                              address: identity.sourceAddress)
            }
            return .init(key: .init(context: context.identity, instruction: identity), index: index,
                         selector: resolved.name, linkageEvidenceID: linkage.id)
        }
    }

    /// Complete consumption of the one supported encoding; no prefix decoder or fallback type.
    static func decodeVoid0Encoding(_ raw: String) -> Result<ObjCVoid0Encoding, ObjCExportRefusal> {
        var count = 0
        for _ in raw.utf8 {
            guard count < ObjCExportLimits.encodingUTF8Bytes else {
                return .failure(refusal(.budgetExceeded, "Raw method encoding exceeds 64 UTF-8 bytes"))
            }
            count += 1
        }
        guard raw == "v16@0:8" else {
            return .failure(refusal(.encodingUnsupported, "Present encoding must be exactly v16@0:8"))
        }
        return .success(.init())
    }

    static func admitVoid0Contract(for site: ObjCDispatchSite,
                                  in context: ObjCExportContext) -> Result<ObjCVoid0Contract, ObjCExportRefusal> {
        attempt {
            try requireContext(site.key, context)
            let records = context.request.contracts.filter { $0.binding.instruction == site.key.instruction }
            guard records.count == 1, let evidence = records.first else {
                throw refusal(records.isEmpty ? .methodContractMissing : .contractConflict,
                              "Exactly one qualified, nonconflicting method contract is required", address: site.callAddress)
            }
            func fail(_ code: ObjCExportRefusalCode, _ fact: String) -> ObjCExportRefusal {
                refusal(code, fact, address: site.callAddress, evidence: [evidence.id])
            }
            guard evidence.authority == .qualifiedDeclaration || evidence.authority == .authoredCallSiteContract,
                  !evidence.sourceReference.isEmpty, !evidence.qualification.isEmpty else {
                throw fail(.methodContractMissing, "Runtime encoding alone does not supply a source/ARC contract")
            }
            guard evidence.selector == site.selector, evidence.appliesToExactReceiverAtCall == true else {
                throw fail(.contractConflict, "Contract must apply to this exact receiver, selector and call")
            }
            guard evidence.dispatchSide == .instance else {
                throw fail(.dispatchSideMismatch, "V1 admits instance methods only")
            }
            guard let isVariadic = evidence.isVariadic else {
                throw fail(.methodVariadicUnknown, "Method variadic status must be explicit")
            }
            guard !isVariadic else { throw fail(.variadicUnsupported, "Variadic methods are outside V1") }
            guard evidence.semanticsComplete == true, let consumes = evidence.consumesSelf,
                  let special = evidence.hasSpecialOwnership,
                  evidence.effectiveFamily != .unknown, let direct = evidence.isDirectMethod else {
                throw fail(.arcContractUnknown, "Resolved source/ownership/dispatch semantics must be complete")
            }
            guard !consumes, !special, evidence.effectiveFamily == .ordinary,
                  !isOwnershipSelector(site.selector) else {
                throw fail(.ownershipUnsupported, "Receiver consumption and ownership/lifecycle methods are unsupported")
            }
            guard !direct, evidence.callingConvention == .darwinObjectiveC else {
                throw fail(.abiShapeUnsupported, "An ordinary dynamic Objective-C calling convention is required")
            }
            guard evidence.sourceReturnType == "void", let parameters = evidence.explicitParameterTypes,
                  parameters.isEmpty else {
                throw fail(.methodShapeUnsupported, "V1 requires exact void and zero explicit source parameters")
            }
            if let encoding = evidence.runtimeEncoding {
                switch decodeVoid0Encoding(encoding) {
                case .success: break
                case let .failure(error): throw fail(error.code, error.missingFact)
                }
            }
            return .init(key: site.key, evidenceID: evidence.id,
                         receiverEvidenceID: evidence.receiverEvidenceID, sourceReference: evidence.sourceReference)
        }
    }

    static func bindVoid0Operands(_ site: ObjCDispatchSite, contract: ObjCVoid0Contract,
                                 in context: ObjCExportContext) -> Result<ObjCVoid0Operands, ObjCExportRefusal> {
        attempt {
            try requireContext(site.key, context)
            guard site.key == contract.key else {
                throw refusal(.identityMismatch, "Contract and site belong to different contexts or calls",
                              address: site.callAddress)
            }
            let function = context.request.function
            // These rows and their identifier bytes were bounded before context admission.
            // A known local binding must not shadow the runtime function or cast typedefs.
            // Absence here is only this captured-scope check, not complete-body lexical proof.
            let fixedIdentifiers: Set<String> = ["objc_msgSend", "id", "SEL"]
            let knownNames = function.parameters.map(\.name) + function.localVariables.map(\.name)
                + function.nameBindings.map(\.name)
            guard !knownNames.contains(where: { fixedIdentifiers.contains($0) }) else {
                throw refusal(.emissionBindingConflict,
                              "A retained source binding shadows objc_msgSend, id or SEL used by the emitted statement",
                              address: site.callAddress)
            }
            let records = context.request.operands.filter { $0.binding.instruction == site.key.instruction }
            guard records.count == 1, let evidence = records.first,
                  evidence.id == contract.receiverEvidenceID,
                  evidence.sourceObjectTypeComplete == true, !evidence.sourceReference.isEmpty,
                  isIdentifier(evidence.sourceIdentifier), isObjectType(evidence.sourceType),
                  evidence.kind == .enclosingInstanceSelf || evidence.kind == .qualifiedObjectParameter else {
                throw refusal(.objectOperandUnproven, "One complete retained source-object parameter binding is required",
                              address: site.callAddress)
            }
            let rows = function.parameters.filter { $0.id == evidence.parameterRowID }
            guard rows.count == 1, let row = rows.first,
                  row.bindingID == evidence.parameterBindingID, let position = row.sourcePosition, position >= 0,
                  row.type == evidence.sourceType, row.name == evidence.sourceIdentifier,
                  row.richLocation == nil,
                  row.evidence == .authoritativeDebug || row.evidence == .authoritativeUser,
                  case .gpr(_, 64) = row.abiLocation,
                  function.parameters.filter({ $0.bindingID == evidence.parameterBindingID }).count == 1,
                  function.parameters.filter({ $0.name == row.name }).count == 1,
                  !function.localVariables.contains(where: { $0.name == row.name }),
                  !function.nameBindings.contains(where: { $0.name == row.name }) else {
                throw refusal(.objectOperandUnproven, "Source identifier/type must match a unique authoritative parameter row",
                              address: site.callAddress, evidence: [evidence.id])
            }
            guard case let .call(frame, _) = function.instructions[site.index].operation,
                  let receiver = frame.arguments.fixedArgument(at: 0),
                  let entry = resolvedEntryBinding(receiver.value, before: site.index, in: context),
                  entry == evidence.parameterBindingID else {
                throw refusal(.objectOperandUnproven, "Receiver is not an unambiguous identity-preserving entry binding",
                              address: site.callAddress, evidence: [evidence.id])
            }
            var consumed = [evidence.id]
            if evidence.kind == .enclosingInstanceSelf {
                guard row.name == "self", evidence.parameterBindingID == .gpr(0),
                      context.request.enclosingMethods.count == 1,
                      let method = context.request.enclosingMethods.first,
                      method.dispatchSide == .instance, method.sourceSemanticsComplete == true,
                      !method.sourceReference.isEmpty, isIdentifier(method.ownerName),
                      method.selfParameterRowID == row.id, method.selfBindingID == evidence.parameterBindingID else {
                    throw refusal(.objectOperandUnproven, "self requires one qualified enclosing instance method",
                                  address: site.callAddress, evidence: [evidence.id])
                }
                consumed.append(method.id)
            } else if row.name == "self" || isReservedIdentifier(row.name) {
                throw refusal(.objectOperandUnproven, "Parameter identifier is reserved or claims unproven self",
                              address: site.callAddress, evidence: [evidence.id])
            }
            return .init(key: site.key, receiverIdentifier: row.name, evidenceIDs: consumed)
        }
    }

    static func proveUnusedResult(of site: ObjCDispatchSite,
                                  in context: ObjCExportContext) -> Result<ObjCUnusedResult, ObjCExportRefusal> {
        attempt {
            try requireContext(site.key, context)
            guard case let .call(_, result) = context.request.function.instructions[site.index].operation else {
                throw refusal(.identityMismatch, "Stored site is no longer a call", address: site.callAddress)
            }
            if let result {
                guard case let .register(name, version) = result,
                      name == "x0" || name == "w0", version > 0,
                      let identity = ObjCExportValueIdentity.leaf(result),
                      let definitions = context.inspection.definitions[identity],
                      definitions.count == 1, definitions[0].instructionIndex == site.index else {
                    throw refusal(.unusedResultUnproven, "Only a unique catalog x0 result may be suppressed",
                                  address: site.callAddress)
                }
                guard !context.inspection.uses.contains(identity) else {
                    throw refusal(.voidResultUsed, "Catalog result is used by a nested operand, control input, phi or return",
                                  address: site.callAddress)
                }
            }
            return .init(key: site.key)
        }
    }

    static func planVoid0Send(_ site: ObjCDispatchSite, contract: ObjCVoid0Contract,
                             operands: ObjCVoid0Operands, unusedResult: ObjCUnusedResult,
                             in context: ObjCExportContext) -> ObjCVoid0Decision {
        guard site.key.context == context.identity, site.key == contract.key,
              site.key == operands.key, site.key == unusedResult.key else {
            return .refused(refusal(.identityMismatch, "All gate certificates must come from the same immutable call context",
                                    address: site.callAddress))
        }
        return .lowered(.init(key: site.key, capture: context.request.capture, selector: site.selector,
                              receiverIdentifier: operands.receiverIdentifier,
                              evidenceIDs: [site.linkageEvidenceID, contract.evidenceID] + operands.evidenceIDs,
                              sourceReference: contract.sourceReference))
    }

    static func lower(_ identity: MacIRInstruction.Identity, in context: ObjCExportContext) -> ObjCVoid0Decision {
        do {
            let site = try resolvePlainSend(identity, in: context).get()
            let contract = try admitVoid0Contract(for: site, in: context).get()
            let operands = try bindVoid0Operands(site, contract: contract, in: context).get()
            let unused = try proveUnusedResult(of: site, in: context).get()
            return planVoid0Send(site, contract: contract, operands: operands, unusedResult: unused, in: context)
        } catch let error as ObjCExportRefusal {
            return .refused(error)
        } catch {
            return .refused(refusal(.unusedResultUnproven, "Call admission did not produce a complete certificate",
                                    address: identity.sourceAddress))
        }
    }

    static func emit(_ plan: ObjCVoid0Plan) -> ObjCEmittedCall {
        .init(callAddress: plan.key.instruction.sourceAddress,
              statement: "((void (*)(id, SEL))objc_msgSend)(\(plan.receiverIdentifier), @selector(\(plan.selector)));",
              requiredHeaders: ["<objc/message.h>"], consumedEvidenceIDs: plan.evidenceIDs,
              contractSourceReference: plan.sourceReference, rules: ObjCExportRule.allCases,
              status: .loweredUncompiled, usesSourceAssistance: true, requiresCompleteBodyAdmission: true)
    }

    static func report(_ decisions: [ObjCVoid0Decision],
                       in context: ObjCExportContext) -> Result<ObjCExportReport, ObjCExportRefusal> {
        guard decisions.count <= ObjCExportLimits.evidenceRecords else {
            return .failure(refusal(.budgetExceeded, "Too many report decisions"))
        }
        var calls: [ObjCEmittedCall] = []
        var refusals: [ObjCExportRefusal] = []
        for decision in decisions {
            switch decision {
            case let .lowered(plan):
                guard plan.key.context == context.identity else {
                    return .failure(refusal(.identityMismatch, "Report cannot mix immutable call contexts"))
                }
                calls.append(emit(plan))
            case let .refused(error): refusals.append(error)
            }
        }
        return .success(.init(capture: context.request.capture, calls: calls, refusals: refusals))
    }

    private static func resolvedEntryBinding(_ value: MacIRValue, before index: Int,
                                             in context: ObjCExportContext) -> MacIRParameterBindingID? {
        // Reject a narrowed/unknown-width receiver before W/X liveness normalization can
        // conceal its width. Every subsequent alias edge was separately certified as X64.
        guard var current = ObjCExportValueIdentity.objectAliasLeaf(value) else { return nil }
        var seen = Set<ObjCExportValueIdentity>()
        var priorIndex = index
        for _ in 0..<ObjCExportLimits.valueDepth {
            guard seen.insert(current).inserted else { return nil }
            if case let .parameter(binding) = current {
                // Parameter definitions are entry facts; an assignment to that identity is a conflict.
                return context.inspection.definitions[current] == nil ? binding : nil
            }
            // Lexical order alone is not dominance. Copy chains are admitted only in a
            // straight-line function; joins and branches need a separate proof.
            guard !context.inspection.hasControlFlow,
                  !context.request.function.instructions.prefix(index).contains(where: {
                      if case .returnValue = $0.operation { return true }
                      return false
                  }),
                  let definitions = context.inspection.definitions[current], definitions.count == 1,
                  let definition = definitions.first, definition.instructionIndex >= 0,
                  definition.instructionIndex < priorIndex, let source = definition.aliasSource else { return nil }
            priorIndex = definition.instructionIndex
            current = source
        }
        return nil
    }

    private static func requireContext(_ key: ObjCExportSiteKey, _ context: ObjCExportContext) throws {
        guard key.context == context.identity,
              context.inspection.instructionIndices[key.instruction] != nil else {
            throw refusal(.identityMismatch, "Certificate belongs to another immutable context",
                          address: key.instruction.sourceAddress)
        }
    }

    private static func canonicalRuntimeSymbol(_ value: String) -> String {
        value.hasPrefix("_") ? String(value.dropFirst()) : value
    }

    private static func isFingerprint(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0) || (65...70).contains($0)
        }
    }

    private static func isIdentifier(_ value: String) -> Bool {
        let bytes = Array(value.utf8.prefix(ObjCExportLimits.identifierUTF8Bytes + 1))
        guard let first = bytes.first, bytes.count <= ObjCExportLimits.identifierUTF8Bytes,
              first == 95 || (65...90).contains(first) || (97...122).contains(first) else { return false }
        return bytes.dropFirst().allSatisfy {
            $0 == 95 || (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
        }
    }

    private static func isObjectType(_ value: String) -> Bool {
        if value == "id" { return true }
        // Positive sourceObjectTypeComplete authority supplies object-ness. This grammar
        // only ensures a simple existing nominal object pointer, with no injected qualifiers.
        guard value.hasSuffix(" *") else { return false }
        let nominal = String(value.dropLast(2))
        return isIdentifier(nominal) && !isReservedIdentifier(nominal)
    }

    private static func isReservedIdentifier(_ value: String) -> Bool {
        ["auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
         "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
         "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
         "union", "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
         "id", "Class", "SEL", "super", "_cmd", "nil", "YES", "NO", "objc_msgSend"].contains(value)
    }

    private static func isOwnershipSelector(_ value: String) -> Bool {
        if ["retain", "release", "autorelease", "dealloc", "retainCount", "finalize", "initialize",
            "load", "retainWeakReference", "allowsWeakReference"].contains(value) { return true }
        // Family prefixes followed by a non-lowercase character are semantic, not mere
        // substring matches (for example, newToken versus newspaper).
        let trimmed = value.drop(while: { $0 == "_" })
        for prefix in ["alloc", "new", "copy", "mutableCopy", "init"] where trimmed.hasPrefix(prefix) {
            let suffix = trimmed.dropFirst(prefix.count)
            guard let next = suffix.utf8.first else { return true }
            if !(97...122).contains(next) { return true }
        }
        return false
    }

    private static func refusal(_ code: ObjCExportRefusalCode, _ fact: String,
                                address: UInt64? = nil, evidence: [String] = []) -> ObjCExportRefusal {
        .init(code: code, callAddress: address, evidenceIDs: evidence, missingFact: fact)
    }

    private static func attempt<T>(_ body: () throws -> T) -> Result<T, ObjCExportRefusal> {
        do { return .success(try body()) }
        catch let error as ObjCExportRefusal { return .failure(error) }
        catch { return .failure(refusal(.unusedResultUnproven, "Admission did not produce a complete certificate")) }
    }
}
