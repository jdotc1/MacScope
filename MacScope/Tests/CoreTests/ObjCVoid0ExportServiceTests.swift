import Foundation
#if !RG5_VOID0_STANDALONE
import XCTest
@testable import MacScope

final class ObjCVoid0ExportServiceTests: XCTestCase {
    func testQualifiedSelfVoid0EmitsFixedCast() throws { try ObjCVoid0ExportScenarios.qualifiedSelf() }
    func testUnknownNominalReceiverKeepsQualifiedID() throws { try ObjCVoid0ExportScenarios.qualifiedParameter() }
    func testEncodingDoesNotInventOwnership() throws { try ObjCVoid0ExportScenarios.encodingAndOwnership() }
    func testDynamicSELDoesNotBorrowNearbyMethod() throws { try ObjCVoid0ExportScenarios.dynamicSelector() }
    func testTailCountCannotCreateArgumentValues() throws { try ObjCVoid0ExportScenarios.absentTail() }
    func testVoid0RequiresExactResultAndEncoding() throws { try ObjCVoid0ExportScenarios.exactContract() }
    func testSuperAndStubStayDistinct() throws { try ObjCVoid0ExportScenarios.distinctDispatch() }
    func testUnusedResultProofIncludesNestedAndPhiUses() throws { try ObjCVoid0ExportScenarios.allResultUses() }
    func testCopiedInstructionCannotSubstituteStoredResult() throws { try ObjCVoid0ExportScenarios.immutableInstruction() }
    func testReturnTargetOnlyUseRefuses() throws { try ObjCVoid0ExportScenarios.returnTarget() }
    func testUnknownAndSemanticSidecarsRefuse() throws { try ObjCVoid0ExportScenarios.opaqueAndSidecars() }
    func testInstructionAndContextIdentityConflictsRefuse() throws { try ObjCVoid0ExportScenarios.identityConflicts() }
    func testReceiverRequiresUniqueSourceBinding() throws { try ObjCVoid0ExportScenarios.receiverBindings() }
    func testObjectReceiverCopiesRequireFullWidthRegisters() throws { try ObjCVoid0ExportScenarios.receiverCopyWidths() }
    func testFixedEmissionIdentifiersRejectKnownScopeCollisions() throws { try ObjCVoid0ExportScenarios.emissionIdentifierCollisions() }
    func testValueNodeAndDepthBudgetEdges() throws { try ObjCVoid0ExportScenarios.valueBudgets() }
    func testPerPhiAndAggregatePhiBudgetEdges() throws { try ObjCVoid0ExportScenarios.phiBudgets() }
    func testTextSelectorIdentifierAndEncodingBudgetEdges() throws { try ObjCVoid0ExportScenarios.textBudgets() }
    func testInstructionAndEvidenceRecordBudgetEdges() throws { try ObjCVoid0ExportScenarios.recordBudgets() }
}
#endif

/// Shared synthetic scenarios let a separately authorized module-level runner use these same
/// assertions without rebuilding the app. No generated Objective-C statement is executed.
enum ObjCVoid0ExportScenarios {
    struct Failure: Error { let message: String }
    private static let callAddress: UInt64 = 0x1010
    private static let result = MacIRValue.register(name: "x0", version: 1)
    private static let identity = MacIRInstruction.Identity(sourceAddress: callAddress, effectOrdinal: 0)

    private static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        if !value() { throw Failure(message: message) }
    }

    private static func unwrap<T>(_ value: T?, _ message: String) throws -> T {
        guard let value else { throw Failure(message: message) }
        return value
    }

    private static func row(name: String, binding: MacIRParameterBindingID = .gpr(0),
                            evidence: MacIRParameterEvidence = .authoritativeUser) throws -> MacIRFunctionParameter {
        try unwrap(MacIRFunctionParameter(id: .init(rawValue: "source.receiver"), bindingID: binding,
                                          sourcePosition: 0,
                                          abiLocation: .gpr(index: binding.value, carrierWidth: 64),
                                          type: "id", name: name, evidence: evidence), "Invalid synthetic parameter")
    }

    private static func call(target: String = "_objc_msgSend", selector: String? = "refresh",
                             receiver: MacIRValue = .argument(bindingID: .gpr(0)),
                             result: MacIRValue? = ObjCVoid0ExportScenarios.result) throws -> MacIRInstruction {
        let plain = target == "_objc_msgSend" || target == "objc_msgSend"
        let selectorEvidence: MacIRCallSelectorEvidence?
        if plain, let selector {
            selectorEvidence = try unwrap(MacIRCallSelectorEvidence(name: selector, selrefAddress: 0x9000),
                                          "Invalid synthetic selector")
        } else {
            selectorEvidence = nil
        }
        let signature = MacIRCallSignature(target: target, returnType: "id", parameters: [
            .init(index: 0, register: "x0", type: "id"), .init(index: 1, register: "x1", type: "SEL")
        ], isVariadic: true)
        let arguments = try unwrap(MacIRCallArguments([
            .init(location: .gpr(index: 0, carrierWidth: 64), role: .fixed(sourcePosition: 0), value: receiver),
            .init(location: .gpr(index: 1, carrierWidth: 64), role: .fixed(sourcePosition: 1),
                  value: selector.map { .symbol("\"\($0)\"") } ?? .argument(bindingID: .gpr(1)),
                  selectorEvidence: selectorEvidence)
        ]), "Invalid synthetic arguments")
        let tail: MacIRCallTailCountEvidence? = selectorEvidence.map {
            .objectiveCSelectorColonCount($0.name.filter { $0 == ":" }.count)
        }
        let frame = try unwrap(MacIRCallFrame(target: target, knownSignature: signature,
                                             tailCountEvidence: tail, controlInputs: .none, arguments: arguments),
                               "Invalid synthetic call frame")
        return .init(source: .init(address: callAddress, byteText: "", mnemonic: "bl", operands: target),
                     operation: .call(frame: frame, result: result))
    }

    private static func fixture(name: String = "self", selector: String? = "refresh",
                                result: MacIRValue? = ObjCVoid0ExportScenarios.result) throws -> ObjCExportRequest {
        let capture = ObjCExportCapture(
            workspace: .init(document: .init(instanceID: UUID()), instanceID: UUID()),
            image: .init(owner: .init(slot: .primary, binaryID: UUID(), architecture: "arm64",
                                      sliceIndex: 0, ownerGeneration: 1),
                         analysisRevision: 1, analysisFingerprintSHA256: String(repeating: "a", count: 64)),
            selectedSliceSHA256: String(repeating: "b", count: 64), platform: "macos", functionUUID: UUID(),
            functionStart: 0x1000, functionEnd: 0x20000, sourceReceiptReference: "fixture:retained-capture")
        let binding = ObjCCallEvidenceBinding(capture: capture, instruction: identity)
        let parameter = try row(name: name)
        let function = MacIRFunction(name: "synthetic_refresh", startAddress: capture.functionStart,
                                     endAddress: capture.functionEnd, returnType: "void", parameters: [parameter],
                                     instructions: [try call(selector: selector, result: result),
                                                    instruction(.returnValue(nil), address: 0x1014)])
        return .init(capture: capture, function: function, linkage: [
            .init(id: "linkage", binding: binding, sourceReference: "fixture:runtime-import",
                  kind: .capturedRuntimeImport, runtimeSymbol: "_objc_msgSend")
        ], contracts: [
            .init(id: "contract", binding: binding, authority: .qualifiedDeclaration,
                  sourceReference: "fixture:ordinary-void0-declaration", qualification: "resolved source attributes",
                  receiverEvidenceID: "receiver", selector: selector ?? "refresh", sourceReturnType: "void",
                  explicitParameterTypes: [], isVariadic: false, consumesSelf: false, hasSpecialOwnership: false,
                  effectiveFamily: .ordinary, dispatchSide: .instance, semanticsComplete: true,
                  appliesToExactReceiverAtCall: true, callingConvention: .darwinObjectiveC,
                  isDirectMethod: false, runtimeEncoding: "v16@0:8")
        ], operands: [
            .init(id: "receiver", binding: binding, sourceReference: "fixture:source-object-parameter",
                  kind: name == "self" ? .enclosingInstanceSelf : .qualifiedObjectParameter,
                  parameterRowID: parameter.id, parameterBindingID: .gpr(0), sourceIdentifier: name,
                  sourceType: "id", sourceObjectTypeComplete: true)
        ], enclosingMethods: name == "self" ? [
            .init(id: "owner", capture: capture, sourceReference: "fixture:enclosing-instance-method",
                  ownerName: "ExampleController", dispatchSide: .instance, selfParameterRowID: parameter.id,
                  selfBindingID: .gpr(0), sourceSemanticsComplete: true)
        ] : [])
    }

    private static func instruction(_ operation: MacIROperation, address: UInt64 = 0x1020,
                                     returnTarget: MacIRValue? = nil) -> MacIRInstruction {
        .init(source: .init(address: address, byteText: "", mnemonic: "mov", operands: ""),
              operation: operation, returnTarget: returnTarget)
    }

    private static func decision(_ request: ObjCExportRequest) -> ObjCVoid0Decision {
        switch ObjCVoid0ExportService.makeContext(request) {
        case let .success(context): return ObjCVoid0ExportService.lower(identity, in: context)
        case let .failure(error): return .refused(error)
        }
    }

    private static func emitted(_ request: ObjCExportRequest) throws -> ObjCEmittedCall {
        switch decision(request) {
        case let .lowered(plan): return ObjCVoid0ExportService.emit(plan)
        case let .refused(error): throw Failure(message: "Unexpected refusal: \(error.code.rawValue): \(error.missingFact)")
        }
    }

    private static func refused(_ request: ObjCExportRequest, _ code: ObjCExportRefusalCode) throws {
        switch decision(request) {
        case .lowered: throw Failure(message: "Expected refusal: \(code.rawValue)")
        case let .refused(error):
            try require(error.code == code, "Expected \(code.rawValue), got \(error.code.rawValue)")
        }
    }

    static func qualifiedSelf() throws {
        for catalogResult in [nil, result] as [MacIRValue?] {
            let request = try fixture(result: catalogResult)
            let output = try emitted(request)
            try require(output.statement == "((void (*)(id, SEL))objc_msgSend)(self, @selector(refresh));", "Wrong fixed cast")
            try require(output.requiredHeaders == ["<objc/message.h>"], "Runtime header missing")
            try require(output.rules == ObjCExportRule.allCases && output.rules.count == 7, "Rule log incomplete")
            try require(output.status == .loweredUncompiled && output.usesSourceAssistance,
                        "Assisted uncompiled status must remain explicit")
            try require(output.requiresCompleteBodyAdmission, "A statement cannot qualify the complete body")
            try require(Set(output.consumedEvidenceIDs) == Set(["linkage", "contract", "receiver", "owner"]),
                        "Evidence IDs incomplete")
            let context = try ObjCVoid0ExportService.makeContext(request).get()
            let report = try ObjCVoid0ExportService.report([ObjCVoid0ExportService.lower(identity, in: context)], in: context).get()
            try require(report.calls.count == 1 && report.refusals.isEmpty, "Report lost admitted statement")
        }
    }

    static func qualifiedParameter() throws {
        var request = try fixture(name: "receiver")
        request.contracts[0].authority = .authoredCallSiteContract
        request.contracts[0].runtimeEncoding = nil
        let output = try emitted(request)
        try require(output.statement == "((void (*)(id, SEL))objc_msgSend)(receiver, @selector(refresh));",
                    "Unknown nominal class must preserve the qualified id parameter")
        try require(!output.statement.contains("bridge") && !output.statement.contains("..."), "Invented conversion or variadic cast")
        try require(!output.consumedEvidenceIDs.contains("owner"), "Parameter binding fabricated a class owner")
    }

    static func encodingAndOwnership() throws {
        var request = try fixture()
        request.contracts.removeAll()
        try refused(request, .methodContractMissing)
        request = try fixture()
        request.contracts[0].authority = .runtimeMetadata
        try refused(request, .methodContractMissing)
        request.contracts[0].authority = .qualifiedDeclaration
        request.contracts[0].consumesSelf = nil
        try refused(request, .arcContractUnknown)
        request.contracts[0].consumesSelf = true
        try refused(request, .ownershipUnsupported)
        request.contracts[0].consumesSelf = false
        request.contracts[0].isVariadic = nil
        try refused(request, .methodVariadicUnknown)
        request.contracts[0].isVariadic = true
        try refused(request, .variadicUnsupported)
        request.contracts[0].isVariadic = false
        request.contracts[0].semanticsComplete = nil
        try refused(request, .arcContractUnknown)
    }

    static func dynamicSelector() throws {
        let request = try fixture(selector: nil)
        try refused(request, .dynamicSelectorUnsupported)
    }

    static func absentTail() throws {
        for type in ["id", "double", "TwoDoubleHFA"] {
            for variadic in [false, true] {
                var request = try fixture(selector: "setValue:")
                request.contracts[0].explicitParameterTypes = [type]
                request.contracts[0].isVariadic = variadic
                try refused(request, .methodShapeUnsupported)
            }
        }
    }

    static func exactContract() throws {
        for encoding in ["", "v", "v16@0:8junk", "v16@0:8 ", "v16@0:8\0", "@16@0:8", "v24@0:8", "v16@0:9", "v16@?:8"] {
            var request = try fixture()
            request.contracts[0].runtimeEncoding = encoding
            try refused(request, .encodingUnsupported)
        }
        for type in ["id", "double", "void *", " void", "Void"] {
            var request = try fixture()
            request.contracts[0].sourceReturnType = type
            try refused(request, .methodShapeUnsupported)
        }
        for selector in ["release", "dealloc", "init", "newToken", "copy", "mutableCopy"] {
            try refused(fixture(selector: selector), .ownershipUnsupported)
        }
        var conflict = try fixture()
        conflict.contracts[0].selector = "other"
        try refused(conflict, .contractConflict)
        conflict = try fixture()
        conflict.contracts[0].dispatchSide = .classMethod
        try refused(conflict, .dispatchSideMismatch)
        conflict = try fixture()
        conflict.contracts[0].isDirectMethod = true
        try refused(conflict, .abiShapeUnsupported)
    }

    static func distinctDispatch() throws {
        for (target, expected) in [("_objc_msgSendSuper2", ObjCExportRefusalCode.superDispatchUnsupported),
                                   ("_objc_msgSendSuper", .superDispatchUnsupported),
                                   ("_objc_msgSend$refresh", .stubWitnessMissing)] {
            var request = try fixture()
            request.function.instructions[0] = try call(target: target)
            request.linkage[0].runtimeSymbol = target
            try refused(request, expected)
        }
        var displayOnly = try fixture()
        displayOnly.linkage[0].kind = .displayNameOnly
        try refused(displayOnly, .plainDispatchUnproven)
        var tail = try fixture()
        tail.function.instructions[0].source.mnemonic = "b"
        try refused(tail, .abiShapeUnsupported)
    }

    static func allResultUses() throws {
        _ = try emitted(fixture())
        var request = try fixture()
        request.function.instructions.append(instruction(.store(source: .unary(op: "~", value: .binaryExpression(
            op: "+", left: .immediate(1), right: result)), address: .immediate(0))))
        try refused(request, .voidResultUsed)
        request = try fixture()
        request.function.phis = [.init(blockAddress: 0x1020, destination: .temporary(7), bitWidth: 64,
                                      incoming: [.init(predecessor: .machine(0x1014), value: result)])]
        try refused(request, .voidResultUsed)
        request = try fixture()
        request.function.returnValue = result
        try refused(request, .voidResultUsed)
        request = try fixture()
        request.function.instructions[1].operation = .returnValue(.unary(op: "(int)", value: result))
        try refused(request, .voidResultUsed)
        request = try fixture()
        request.function.instructions.append(instruction(.switchDispatch(index: .immediate(0),
            cases: [.init(value: 1, target: result)], defaultTarget: nil)))
        try refused(request, .voidResultUsed)
        request = try fixture()
        request.function.instructions.append(instruction(.switchDispatch(index: .immediate(0), cases: [], defaultTarget: result)))
        try refused(request, .voidResultUsed)
        request = try fixture()
        let controls = try unwrap(MacIRCallControlInputs([
            .init(role: .indirectTarget, register: .gpr(index: 12), value: result)
        ]), "Invalid synthetic control input")
        let empty = try unwrap(MacIRCallArguments([]), "Invalid empty arguments")
        let indirect = try unwrap(MacIRCallFrame(target: "(*x12)", knownSignature: nil,
                                               controlInputs: controls, arguments: empty), "Invalid indirect call")
        request.function.instructions.append(instruction(.call(frame: indirect, result: nil)))
        try refused(request, .voidResultUsed)
        request = try fixture()
        let args = try unwrap(MacIRCallArguments([
            .init(location: .gpr(index: 0, carrierWidth: 64), role: .fixed(sourcePosition: 0),
                  value: .unary(op: "~", value: result))
        ]), "Invalid nested call arguments")
        let nested = try unwrap(MacIRCallFrame(target: "_other", knownSignature: .init(target: "_other",
            returnType: "void", parameters: [.init(index: 0, register: "x0", type: "uint64_t")]),
            controlInputs: .none, arguments: args), "Invalid nested call")
        request.function.instructions.append(instruction(.call(frame: nested, result: nil)))
        try refused(request, .voidResultUsed)
    }

    static func immutableInstruction() throws {
        var request = try fixture()
        request.function.returnValue = result
        let context = try ObjCVoid0ExportService.makeContext(request).get()
        var substituted = request.function.instructions[0]
        guard case let .call(frame, _) = substituted.operation else { throw Failure(message: "Fixture is not a call") }
        substituted.operation = .call(frame: frame, result: nil)
        request.function.instructions[0] = substituted
        // Only the identity can cross the API. Its copied nil result cannot replace the
        // stored live result, including after the original request is mutated.
        switch ObjCVoid0ExportService.lower(substituted.id, in: context) {
        case .lowered: throw Failure(message: "Copied result was substituted into the context")
        case let .refused(error): try require(error.code == .voidResultUsed, "Wrong substituted-result refusal")
        }
    }

    static func returnTarget() throws {
        var request = try fixture()
        request.function.instructions[1].operation = .returnValue(nil)
        request.function.instructions[1].returnTarget = .register(name: "w0", version: 1)
        try refused(request, .voidResultUsed)
    }

    static func opaqueAndSidecars() throws {
        var request = try fixture()
        request.function.instructions.append(instruction(.unknown(destination: nil, inputs: .none,
                                                                   mnemonic: "opaque", operands: "")))
        try refused(request, .unusedResultUnproven)
        request = try fixture()
        request.function.instructions.append(instruction(.intrinsic(destination: nil, name: "opaque", arguments: [])))
        try refused(request, .unusedResultUnproven)
        request = try fixture()
        request.function.instructions[1].neonQCIsSeparate = true
        try refused(request, .unsupportedSidecar)
        request = try fixture()
        request.function.instructions[1].source.syntheticPhiEdge = .init(blockAddress: 0x1014,
            predecessor: .functionEntry, destination: result)
        try refused(request, .unsupportedSidecar)
        request = try fixture()
        request.function.ssaOriginalInstructions = []
        try refused(request, .unsupportedSidecar)
        request = try fixture()
        request.function.instructions[1].operation = .returnValue(.unknown("uninspected"))
        try refused(request, .unusedResultUnproven)
    }

    static func identityConflicts() throws {
        var request = try fixture()
        request.function.instructions.append(request.function.instructions[0])
        try refused(request, .duplicateInstruction)
        request = try fixture()
        request.contracts[0].binding.capture.functionUUID = UUID()
        try refused(request, .identityMismatch)
        request = try fixture()
        request.contracts[0].binding.capture.image = .init(owner: request.capture.image.owner,
                                                         analysisRevision: 2,
                                                         analysisFingerprintSHA256: request.capture.image.analysisFingerprintSHA256)
        try refused(request, .identityMismatch)
        request = try fixture()
        let first = try ObjCVoid0ExportService.makeContext(request).get()
        let second = try ObjCVoid0ExportService.makeContext(request).get()
        let firstSite = try ObjCVoid0ExportService.resolvePlainSend(identity, in: first).get()
        let secondSite = try ObjCVoid0ExportService.resolvePlainSend(identity, in: second).get()
        let contract = try ObjCVoid0ExportService.admitVoid0Contract(for: firstSite, in: first).get()
        let operands = try ObjCVoid0ExportService.bindVoid0Operands(firstSite, contract: contract, in: first).get()
        let otherUnused = try ObjCVoid0ExportService.proveUnusedResult(of: secondSite, in: second).get()
        switch ObjCVoid0ExportService.planVoid0Send(firstSite, contract: contract, operands: operands,
                                                   unusedResult: otherUnused, in: first) {
        case .lowered: throw Failure(message: "Certificates from different immutable contexts were mixed")
        case let .refused(error): try require(error.code == .identityMismatch, "Wrong mixed-context refusal")
        }
        let absent = MacIRInstruction.Identity(sourceAddress: 0x1234, effectOrdinal: 0)
        switch ObjCVoid0ExportService.resolvePlainSend(absent, in: first) {
        case .success: throw Failure(message: "Missing instruction was resolved")
        case let .failure(error): try require(error.code == .missingInstruction, "Wrong missing-instruction refusal")
        }
        request.contracts.append(request.contracts[0])
        request.contracts[1].id = "conflicting-contract"
        try refused(request, .contractConflict)
    }

    static func receiverBindings() throws {
        var request = try fixture()
        request.function.parameters[0] = try row(name: "self", evidence: .heuristicEntryRead)
        try refused(request, .objectOperandUnproven)
        request = try fixture()
        request.function.instructions[0] = try call(receiver: .immediate(7))
        try refused(request, .objectOperandUnproven)
        request = try fixture()
        request.enclosingMethods.removeAll()
        try refused(request, .objectOperandUnproven)
        request = try fixture(name: "receiver")
        request.function.parameters.append(try row(name: "receiver", binding: .gpr(1)))
        try refused(request, .objectOperandUnproven)
        request = try fixture(name: "return")
        try refused(request, .objectOperandUnproven)
        request = try fixture()
        let alias = MacIRValue.register(name: "x2", version: 1)
        request.function.instructions[0] = try call(receiver: alias)
        request.function.instructions.insert(instruction(.assign(destination: alias, source: .argument(bindingID: .gpr(0))),
                                                        address: 0x1004), at: 0)
        _ = try emitted(request)
        request.function.instructions.insert(instruction(.conditionalBranch(condition: "eq", left: .immediate(0),
            right: .immediate(0), target: .immediate(0x1010)), address: 0x1008), at: 1)
        try refused(request, .objectOperandUnproven)
    }

    static func receiverCopyWidths() throws {
        let entry = MacIRValue.argument(bindingID: .gpr(0))
        let x2 = MacIRValue.register(name: "x2", version: 1)
        let w2 = MacIRValue.register(name: "w2", version: 1)
        let x3 = MacIRValue.register(name: "x3", version: 1)
        func copied(_ copies: [(MacIRValue, MacIRValue)], receiver: MacIRValue) throws -> ObjCExportRequest {
            var request = try fixture()
            request.function.instructions[0] = try call(receiver: receiver)
            let assignments = copies.enumerated().map { index, copy in
                instruction(.assign(destination: copy.0, source: copy.1), address: 0x1000 + UInt64(index * 4))
            }
            request.function.instructions.insert(contentsOf: assignments, at: 0)
            return request
        }

        // A W destination followed by an X-view read is a narrowing/zero-extension, not an
        // object-preserving copy, even though both views share an SSA liveness identity.
        try refused(copied([(w2, entry)], receiver: x2), .objectOperandUnproven)
        // The destination width alone cannot repair a preceding W-view source read.
        try refused(copied([(x2, entry), (x3, w2)], receiver: x3), .objectOperandUnproven)
        // A direct narrowed leaf must not bypass the copy-edge check through normalization.
        try refused(copied([(x2, entry)], receiver: w2), .objectOperandUnproven)
        for unknownWidth in [MacIRValue.temporary(7), .register(name: "d2", version: 1),
                             .register(name: "x02", version: 1)] {
            try refused(copied([(unknownWidth, entry)], receiver: unknownWidth), .objectOperandUnproven)
            try refused(copied([(unknownWidth, entry), (x3, unknownWidth)], receiver: x3), .objectOperandUnproven)
        }

        var fullWidth = try copied([(x2, entry), (x3, x2)], receiver: x3)
        _ = try emitted(fullWidth)
        // Keep the intentionally conservative W/X result-use matching after the receiver fix.
        fullWidth.function.instructions[3].returnTarget = .register(name: "w0", version: 1)
        try refused(fullWidth, .voidResultUsed)
    }

    static func emissionIdentifierCollisions() throws {
        func secondParameter(_ name: String) throws -> MacIRFunctionParameter {
            try unwrap(MacIRFunctionParameter(id: .init(rawValue: "source.second-parameter"), bindingID: .gpr(2),
                sourcePosition: 1, abiLocation: .gpr(index: 2, carrierWidth: 64), type: "id", name: name,
                evidence: .authoritativeUser), "Invalid synthetic second parameter")
        }
        for name in ["objc_msgSend", "id", "SEL"] {
            var request = try fixture()
            request.function.parameters.append(try secondParameter(name))
            try refused(request, .emissionBindingConflict)
            request = try fixture()
            request.function.localVariables.append(.init(offset: -8, name: name, type: "id", byteWidth: 8))
            try refused(request, .emissionBindingConflict)
            request = try fixture()
            request.function.nameBindings.append(.init(target: .register(name: "x5", version: 1), name: name,
                                                        type: "id", kind: .registerTemporary))
            try refused(request, .emissionBindingConflict)
        }
        var ordinary = try fixture()
        ordinary.function.parameters.append(try secondParameter("otherReceiver"))
        ordinary.function.localVariables.append(.init(offset: -8, name: "otherLocal", type: "id", byteWidth: 8))
        let output = try emitted(ordinary)
        try require(output.statement == "((void (*)(id, SEL))objc_msgSend)(self, @selector(refresh));",
                    "Nonconflicting scope must preserve the ordinary receiver statement")
        try require(output.requiresCompleteBodyAdmission, "Known-scope screening cannot certify the complete lexical body")
    }

    private static func tree(nodes: Int) -> MacIRValue {
        if nodes <= 1 { return .immediate(0) }
        if nodes == 2 { return .abiComposite(type: "", fragments: [.immediate(0)]) }
        let left = (nodes - 1) / 2
        return .abiComposite(type: "", fragments: [tree(nodes: left), tree(nodes: nodes - 1 - left)])
    }

    static func valueBudgets() throws {
        var request = try fixture()
        let baseline = try ObjCExportInspection.inspect(request).valueVisits
        let allowedTreeNodes = ObjCExportLimits.valueVisits - baseline - 1
        request.function.instructions.append(instruction(.store(source: tree(nodes: allowedTreeNodes), address: .immediate(0))))
        let inspection = try ObjCExportInspection.inspect(request)
        try require(inspection.valueVisits == ObjCExportLimits.valueVisits, "Node edge fixture did not reach its exact limit")
        _ = try emitted(request)
        request.function.instructions[2].operation = .store(source: tree(nodes: allowedTreeNodes + 1), address: .immediate(0))
        try refused(request, .budgetExceeded)
        for depth in [ObjCExportLimits.valueDepth, ObjCExportLimits.valueDepth + 1] {
            request = try fixture()
            var nested = MacIRValue.immediate(0)
            for _ in 1..<depth { nested = .unary(op: "~", value: nested) }
            request.function.instructions.append(instruction(.store(source: nested, address: .immediate(0))))
            if depth == ObjCExportLimits.valueDepth { _ = try emitted(request) }
            else { try refused(request, .budgetExceeded) }
        }
    }

    static func phiBudgets() throws {
        func phi(_ index: Int, _ count: Int) -> MacIRPhi {
            .init(blockAddress: 0x1100 + UInt64(index * 4), destination: .temporary(index + 100), bitWidth: 64,
                  incoming: (0..<count).map { .init(predecessor: .machine(UInt64($0) + 0x1200), value: .immediate(0)) })
        }
        var request = try fixture()
        request.function.phis = [phi(0, ObjCExportLimits.inputs)]
        _ = try emitted(request)
        request.function.phis = [phi(0, ObjCExportLimits.inputs + 1)]
        try refused(request, .budgetExceeded)
        request.function.phis = (0..<32).map { phi($0, 128) }
        let inspection = try ObjCExportInspection.inspect(request)
        try require(inspection.phiInputs == ObjCExportLimits.totalPhiInputs, "Aggregate phi fixture missed its limit")
        _ = try emitted(request)
        request.function.phis.append(phi(33, 1))
        try refused(request, .budgetExceeded)
    }

    static func textBudgets() throws {
        var request = try fixture()
        let baseline = try ObjCExportInspection.inspect(request).evidenceUTF8Bytes
        request.contracts[0].qualification += String(repeating: "q", count: ObjCExportLimits.evidenceUTF8Bytes - baseline)
        _ = try emitted(request)
        request.contracts[0].qualification += "q"
        try refused(request, .budgetExceeded)
        _ = try emitted(fixture(selector: String(repeating: "s", count: ObjCExportLimits.identifierUTF8Bytes)))
        try refused(fixture(selector: String(repeating: "s", count: ObjCExportLimits.identifierUTF8Bytes + 1)), .budgetExceeded)
        _ = try emitted(fixture(name: String(repeating: "r", count: ObjCExportLimits.identifierUTF8Bytes)))
        try refused(fixture(name: String(repeating: "r", count: ObjCExportLimits.identifierUTF8Bytes + 1)), .budgetExceeded)
        for (count, expected) in [(64, ObjCExportRefusalCode.encodingUnsupported), (65, .budgetExceeded)] {
            switch ObjCVoid0ExportService.decodeVoid0Encoding(String(repeating: "v", count: count)) {
            case .success: throw Failure(message: "Unsupported encoding was accepted")
            case let .failure(error): try require(error.code == expected, "Wrong encoding byte-budget boundary")
            }
        }
        // Byte bounds cannot be bypassed using fewer multi-byte characters.
        try refused(fixture(selector: String(repeating: "é", count: 65)), .budgetExceeded)
    }

    static func recordBudgets() throws {
        var request = try fixture()
        for index in 0..<(ObjCExportLimits.instructions - request.function.instructions.count) {
            request.function.instructions.append(instruction(.store(source: .immediate(0), address: .immediate(0)),
                                                             address: 0x2000 + UInt64(index * 4)))
        }
        _ = try emitted(request)
        request.function.instructions.append(instruction(.store(source: .immediate(0), address: .immediate(0)), address: 0x8000))
        try refused(request, .budgetExceeded)
        request = try fixture()
        // Additional contracts are structurally bounded first, then refused as ambiguous;
        // they cannot be silently truncated to the first apparently valid record.
        for index in 0..<60 {
            var extra = request.contracts[0]
            extra.id = "contract-\(index)"
            request.contracts.append(extra)
        }
        try refused(request, .contractConflict)
        var extra = request.contracts[0]
        extra.id = "over-limit"
        request.contracts.append(extra)
        try refused(request, .budgetExceeded)
    }
}
