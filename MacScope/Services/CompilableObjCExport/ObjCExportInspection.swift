import Foundation

/// Only leaf identities are compared or hashed. MacIRValue's recursive synthesized equality
/// is deliberately never used by this service, including during admission and alias lookup.
enum ObjCExportValueIdentity: Hashable, Sendable {
    case register(String, Int)
    case parameter(MacIRParameterBindingID)
    case temporary(Int)

    static func leaf(_ value: MacIRValue) -> Self? {
        switch value {
        case let .register(name, version):
            // wN and xN are views of one SSA definition, including the catalog's x0 result.
            let bytes = Array(name.utf8)
            if bytes.count >= 2, bytes.count <= 3, bytes[0] == 119 || bytes[0] == 120,
               bytes.dropFirst().allSatisfy({ (48...57).contains($0) }),
               let index = Int(name.dropFirst()), (0...30).contains(index),
               String(index) == String(name.dropFirst()) {
                return .register("x\(index)", version)
            }
            return .register(name, version)
        case let .argument(binding): return .parameter(binding)
        case let .temporary(index): return .temporary(index)
        default: return nil
        }
    }

    /// Receiver copies need a width proof in addition to the conservative identity used
    /// for liveness. A W-register write zero-extends a narrowed value; neither it nor an
    /// unknown-width temporary can certify preservation of a 64-bit object pointer.
    static func objectAliasLeaf(_ value: MacIRValue) -> Self? {
        switch value {
        case let .argument(binding):
            return binding.kind == .gpr ? .parameter(binding) : nil
        case let .register(name, version):
            let bytes = Array(name.utf8.prefix(4))
            guard version > 0, (2...3).contains(bytes.count), bytes[0] == 120,
                  bytes.dropFirst().allSatisfy({ (48...57).contains($0) }),
                  let index = Int(name.dropFirst()), (0...30).contains(index),
                  String(index) == String(name.dropFirst()) else { return nil }
            return .register(name, version)
        default:
            return nil
        }
    }
}

struct ObjCExportDefinition: Sendable {
    let instructionIndex: Int
    /// Present only for a positively full-width X-register copy from an entry GPR or X register.
    let aliasSource: ObjCExportValueIdentity?
}

struct ObjCExportInspection: Sendable {
    let instructionIndices: [MacIRInstruction.Identity: Int]
    let uses: Set<ObjCExportValueIdentity>
    let definitions: [ObjCExportValueIdentity: [ObjCExportDefinition]]
    let hasControlFlow: Bool
    let valueVisits: Int
    let evidenceUTF8Bytes: Int
    let phiInputs: Int

    static func inspect(_ request: ObjCExportRequest) throws -> Self {
        var inspector = Inspector()
        return try inspector.inspect(request)
    }
}

private struct Inspector {
    private var remainingText = ObjCExportLimits.evidenceUTF8Bytes
    private var visitedValues = 0
    private var totalPhiInputs = 0
    private var address: UInt64?
    private var uses = Set<ObjCExportValueIdentity>()
    private var definitions: [ObjCExportValueIdentity: [ObjCExportDefinition]] = [:]
    private var hasControlFlow = false

    private func refusal(_ code: ObjCExportRefusalCode, _ fact: String) -> ObjCExportRefusal {
        .init(code: code, callAddress: address, evidenceIDs: [], missingFact: fact)
    }

    private func boundedCount(_ count: Int, _ maximum: Int, _ what: String) throws {
        guard count <= maximum else { throw refusal(.budgetExceeded, what) }
    }

    /// Stop after the first disallowed byte; do not count or copy an unbounded string first.
    private mutating func text(_ value: String?, maximum: Int? = nil) throws {
        guard let value else { return }
        let allowed = min(remainingText, maximum ?? remainingText)
        var count = 0
        for _ in value.utf8 {
            guard count < allowed else { throw refusal(.budgetExceeded, "UTF-8 evidence text exceeds its budget") }
            count += 1
        }
        remainingText -= count
    }

    private mutating func identifier(_ value: String) throws {
        try text(value, maximum: ObjCExportLimits.identifierUTF8Bytes)
    }

    private mutating func capture(_ value: ObjCExportCapture) throws {
        try identifier(value.image.architecture)
        try identifier(value.platform)
        try text(value.selectedSliceSHA256, maximum: 64)
        try text(value.image.analysisFingerprintSHA256, maximum: 64)
        try text(value.sourceReceiptReference)
    }

    private mutating func signature(_ value: MacIRCallSignature?) throws {
        guard let value else { return }
        try boundedCount(value.parameters.count, ObjCExportLimits.inputs, "Too many signature parameters")
        try text(value.target)
        try text(value.returnType)
        try text(value.source)
        // This V1 inspector does not interpret format-attribute sidecars.
        guard value.format == nil else { throw refusal(.unsupportedSidecar, "Call format attribute is not inspected") }
        for parameter in value.parameters {
            try identifier(parameter.register)
            try identifier(parameter.name)
            try text(parameter.type)
        }
    }

    private mutating func frame(_ frame: MacIRCallFrame) throws -> [MacIRValue] {
        try boundedCount(frame.arguments.count, ObjCExportLimits.inputs, "Too many call arguments")
        try boundedCount(frame.arguments.observationScope.canonicalCallStackRangesForAudit.count,
                         ObjCExportLimits.inputs, "Too many observed call-stack ranges")
        try text(frame.target)
        try signature(frame.knownSignature)
        try signature(frame.typedIndirectSignature)
        try text(frame.typedIndirectCalleeType)
        if case .formatString = frame.tailCountEvidence {
            throw refusal(.unsupportedSidecar, "Call format evidence is not inspected")
        }
        var values: [MacIRValue] = []
        for argument in frame.arguments.canonicalPhysicalEntriesForAudit {
            if let selector = argument.selectorEvidence { try identifier(selector.name) }
            values.append(argument.value)
        }
        // The control-input initializer bounds its closed role set. Keep the explicit cap here
        // as well so a future extension cannot create an unbudgeted walk.
        let controls = frame.controlInputs.canonicalControlInputsForAudit
        try boundedCount(controls.count, ObjCExportLimits.inputs, "Too many call control inputs")
        values.append(contentsOf: controls.map(\.value))
        if let rich = frame.richArguments {
            try boundedCount(rich.count, ObjCExportLimits.inputs, "Too many rich call arguments")
            for argument in rich {
                try identifier(argument.rowID.rawValue)
                try text(argument.type)
                try boundedCount(argument.pieces.count, ObjCExportLimits.inputs, "Too many rich argument pieces")
                // Bound the aggregate before creating the flattened input list.
                try boundedCount(values.count + argument.pieces.count, ObjCExportLimits.inputs,
                                 "Too many aggregate call inputs")
                values.append(contentsOf: argument.pieces.map(\.value))
            }
        }
        if let pointer = frame.indirectResultPointer { values.append(pointer) }
        try boundedCount(values.count, ObjCExportLimits.inputs, "Too many aggregate call inputs")
        return values
    }

    /// Iterative, depth-limited traversal. Nested signed-bitfield provenance is inspected as
    /// well as its source; an unknown value cannot certify that another value is dead.
    private mutating func value(_ root: MacIRValue, isUse: Bool) throws {
        var pending: [(MacIRValue, Int)] = [(root, 1)]
        while let (node, depth) = pending.popLast() {
            guard depth <= ObjCExportLimits.valueDepth,
                  visitedValues < ObjCExportLimits.valueVisits else {
                throw refusal(.budgetExceeded, "Value depth or aggregate node budget exceeded")
            }
            visitedValues += 1
            switch node {
            case let .register(name, _): try identifier(name)
            case .argument, .immediate, .stackSlot, .temporary: break
            case let .argumentFragment(rowID, _, _): try identifier(rowID.rawValue)
            case let .symbol(name): try text(name)
            case let .bitTest(inner, _): pending.append((inner, depth + 1))
            case let .unary(op, inner):
                try text(op)
                pending.append((inner, depth + 1))
            case let .binaryExpression(op, left, right):
                try text(op)
                pending.append((right, depth + 1))
                pending.append((left, depth + 1))
            case let .abiComposite(type, fragments):
                try text(type)
                try boundedCount(fragments.count, ObjCExportLimits.inputs, "Too many composite fragments")
                for fragment in fragments.reversed() { pending.append((fragment, depth + 1)) }
            case let .signedBitfield(field):
                try identifier(field.origin.functionName)
                try identifier(field.origin.mnemonic)
                try identifier(field.origin.sourceRegister)
                try identifier(field.origin.destinationRegister)
                pending.append((field.origin.definition, depth + 1))
                pending.append((field.source, depth + 1))
            case .unknown:
                throw refusal(.unusedResultUnproven, "An unknown value prevents complete use inspection")
            }
            if isUse, let identity = ObjCExportValueIdentity.leaf(node) { uses.insert(identity) }
        }
    }

    private mutating func define(_ value: MacIRValue?, index: Int, alias: MacIRValue? = nil) throws {
        guard let value else { return }
        try self.value(value, isUse: false)
        guard let identity = ObjCExportValueIdentity.leaf(value) else {
            throw refusal(.unusedResultUnproven, "Non-leaf definition is outside the V1 use proof")
        }
        let aliasSource: ObjCExportValueIdentity?
        if case .register = identity, ObjCExportValueIdentity.objectAliasLeaf(value) != nil {
            aliasSource = alias.flatMap(ObjCExportValueIdentity.objectAliasLeaf)
        } else {
            aliasSource = nil
        }
        definitions[identity, default: []].append(.init(
            instructionIndex: index, aliasSource: aliasSource))
    }

    private mutating func instruction(_ instruction: MacIRInstruction, index: Int) throws {
        address = instruction.source.address
        try text(instruction.source.byteText)
        try identifier(instruction.source.mnemonic)
        try text(instruction.source.operands)
        try text(instruction.source.comment)
        guard !instruction.hasObjCExportUninspectedSidecar else {
            throw refusal(.unsupportedSidecar, "Instruction carries a semantic sidecar not inspected by V1")
        }
        var inputs: [MacIRValue] = []
        switch instruction.operation {
        case let .assign(destination, source):
            inputs = [source]
            // Validate the alias source before deriving a leaf identity from it.
            try value(source, isUse: false)
            try define(destination, index: index, alias: source)
        case let .binary(destination, op, left, right):
            try text(op)
            inputs = [left, right]
            try define(destination, index: index)
        case let .load(destination, address):
            inputs = [address]
            try define(destination, index: index)
        case let .store(source, address): inputs = [source, address]
        case let .loadWriteback(destination, baseDestination, baseSource, _, _):
            inputs = [baseSource]
            try define(destination, index: index)
            try define(baseDestination, index: index)
        case let .storeWriteback(source, baseDestination, baseSource, _, _):
            inputs = [source, baseSource]
            try define(baseDestination, index: index)
        case let .stackSlotRead(destination, slot, stored):
            inputs = [slot, stored]
            try define(destination, index: index)
        case let .stackSlotPairRead(firstDestination, firstSlot, firstValue,
                                    secondDestination, secondSlot, secondValue):
            inputs = [firstSlot, firstValue, secondSlot, secondValue]
            try define(firstDestination, index: index)
            try define(secondDestination, index: index)
        case let .call(callFrame, result):
            inputs = try frame(callFrame)
            try define(result, index: index)
        case let .conditionalBranch(condition, left, right, target):
            try text(condition)
            hasControlFlow = true
            inputs = [left, right, target]
        case let .select(destination, condition, left, right, trueValue, falseValue):
            try text(condition)
            inputs = [left, right, trueValue, falseValue]
            try define(destination, index: index)
        case let .compareToBool(destination, condition, left, right):
            try text(condition)
            inputs = [left, right]
            try define(destination, index: index)
        case let .returnValue(returned): inputs = returned.map { [$0] } ?? []
        case let .intrinsic(destination, name, arguments):
            // Intrinsics may hide memory/ownership/control effects that are not represented
            // by their input list. This first implementation grants no dead-result proof.
            _ = destination
            _ = name
            _ = arguments
            throw refusal(.unusedResultUnproven, "Opaque intrinsic semantics are outside the V1 use proof")
        case let .switchDispatch(index, cases, defaultTarget):
            try boundedCount(cases.count, ObjCExportLimits.inputs, "Too many switch cases")
            hasControlFlow = true
            inputs = [index] + cases.map(\.target) + (defaultTarget.map { [$0] } ?? [])
        case .unknown:
            throw refusal(.unusedResultUnproven, "An unknown operation prevents complete use inspection")
        }
        if let target = instruction.returnTarget { inputs.append(target) }
        for input in inputs { try value(input, isUse: true) }
    }

    mutating func inspect(_ request: ObjCExportRequest) throws -> ObjCExportInspection {
        let function = request.function
        try boundedCount(function.instructions.count, ObjCExportLimits.instructions, "Too many instructions")
        for count in [request.linkage.count, request.contracts.count, request.operands.count,
                      request.enclosingMethods.count] {
            try boundedCount(count, ObjCExportLimits.evidenceRecords, "Too many evidence records")
        }
        try boundedCount(request.linkage.count + request.contracts.count + request.operands.count
                         + request.enclosingMethods.count, ObjCExportLimits.evidenceRecords,
                         "Too many combined evidence records")
        try capture(request.capture)
        for row in request.linkage {
            try identifier(row.id)
            try capture(row.binding.capture)
            try text(row.sourceReference)
            try identifier(row.runtimeSymbol)
        }
        for row in request.contracts {
            try identifier(row.id)
            try capture(row.binding.capture)
            try text(row.sourceReference)
            try text(row.qualification)
            try identifier(row.receiverEvidenceID)
            try identifier(row.selector)
            try text(row.sourceReturnType)
            if let types = row.explicitParameterTypes {
                try boundedCount(types.count, ObjCExportLimits.inputs, "Too many contract parameters")
                for type in types { try text(type) }
            }
            try text(row.runtimeEncoding, maximum: ObjCExportLimits.encodingUTF8Bytes)
        }
        for row in request.operands {
            try identifier(row.id)
            try capture(row.binding.capture)
            try text(row.sourceReference)
            try identifier(row.parameterRowID.rawValue)
            try identifier(row.sourceIdentifier)
            try text(row.sourceType)
        }
        for row in request.enclosingMethods {
            try identifier(row.id)
            try capture(row.capture)
            try text(row.sourceReference)
            try identifier(row.ownerName)
            try identifier(row.selfParameterRowID.rawValue)
        }
        try text(function.name)
        try text(function.returnType)
        // These retained semantic models are not visited by V1. Check for presence without
        // recursively comparing, hashing, resolving or constructing any of them.
        guard function.cfg == nil, function.ssaInfo == nil,
              function.ssaOriginalInstructions == nil, function.ssaOriginalPhis == nil,
              function.ssaFlagPhiComparisons.isEmpty, function.ssaElidedChainRows.isEmpty,
              function.refusals.isEmpty, !function.observesFPSR else {
            throw refusal(.unsupportedSidecar, "Function carries an uninspected semantic model")
        }
        for count in [function.parameters.count, function.localVariables.count,
                      function.nameBindings.count, function.callTargets.count, function.callSignatures.count] {
            try boundedCount(count, ObjCExportLimits.inputs, "Too many function metadata rows")
        }
        for parameter in function.parameters {
            try identifier(parameter.id.rawValue)
            try identifier(parameter.name)
            try identifier(parameter.register)
            try text(parameter.type)
            if case let .unbound(reason: .unsupportedType(type)) = parameter.abiLocation { try text(type) }
            // A rich parameter's piece metadata is not a qualified object receiver in V1.
            guard parameter.richLocation == nil else {
                throw refusal(.unsupportedSidecar, "Rich function parameter is not inspected")
            }
        }
        for local in function.localVariables {
            try identifier(local.name)
            try text(local.type)
            try text(local.stackStorage?.identity)
        }
        for binding in function.nameBindings {
            try identifier(binding.name)
            try text(binding.type)
            if case let .register(name, _) = binding.target { try identifier(name) }
        }
        for target in function.callTargets { try text(target) }
        for callSignature in function.callSignatures { try signature(callSignature) }
        var indices: [MacIRInstruction.Identity: Int] = [:]
        for (index, instruction) in function.instructions.enumerated() {
            try self.instruction(instruction, index: index)
            guard indices.updateValue(index, forKey: instruction.id) == nil else {
                throw refusal(.duplicateInstruction, "Instruction identity must occur exactly once")
            }
        }
        address = nil
        try boundedCount(function.phis.count, ObjCExportLimits.totalPhiInputs, "Too many phis")
        for phi in function.phis {
            try boundedCount(phi.incoming.count, ObjCExportLimits.inputs, "Too many inputs in one phi")
            totalPhiInputs += phi.incoming.count
            try boundedCount(totalPhiInputs, ObjCExportLimits.totalPhiInputs, "Too many aggregate phi inputs")
            hasControlFlow = true
            try define(phi.destination, index: -1)
            for incoming in phi.incoming { try value(incoming.value, isUse: true) }
        }
        if let returned = function.returnValue { try value(returned, isUse: true) }
        return .init(instructionIndices: indices, uses: uses,
                     definitions: definitions, hasControlFlow: hasControlFlow,
                     valueVisits: visitedValues,
                     evidenceUTF8Bytes: ObjCExportLimits.evidenceUTF8Bytes - remainingText,
                     phiInputs: totalPhiInputs)
    }
}

private extension MacIRInstruction {
    /// Explicitly reject every semantic sidecar outside this inspector's closed envelope.
    /// memoryAccess has only scalar width/extension facts; returnTarget is visited above.
    var hasObjCExportUninspectedSidecar: Bool {
        source.syntheticPhiEdge != nil || source.tailCallEffect != nil ||
        scalarFP != nil || fpEnvironment != nil || fpBlockedEffect != nil ||
        neonQC != nil || neonQCIsSeparate || vectorFP != nil || vectorFPStatus != nil ||
        fpArchitecturalClobber != nil || neonPermutation != nil || neonLogical != nil ||
        neonExtract != nil || neonTableLookup != nil || neonModular != nil ||
        neonComparison != nil || neonBufferMemory != nil || neonBitView != nil ||
        neonBufferSequence != nil || neonShiftInsert != nil || neonMultiply != nil ||
        neonImmediate != nil || neonReduction != nil || neonPacking != nil ||
        neonLaneMemory != nil || neonWideningPairwise != nil || neonPredicate != nil ||
        neonShiftNarrow != nil || neonContiguousGroup != nil || neonMagnitudeClamp != nil ||
        neonPairwise != nil || neonBroadcastMemory != nil || neonBitCount != nil ||
        neonOrderConversion != nil || neonInterleavedMemory != nil || neonStructureLaneMemory != nil ||
        neonIndexedMemory != nil || neonWideningAddSubtract != nil || neonSignedLongMultiply != nil ||
        neonScalarShiftCompilerComposition != nil || neonScalarMaskSelection != nil ||
        neonScalarIntegerComparison != nil || neonLaneCoefficientProduct != nil ||
        neonReplicatedIndexedProduct != nil || neonWiderMultiChannelLane != nil ||
        neonWiderMultiChannelReplicate != nil || neonScalarVariableShift != nil ||
        neonWiderChannelMemory != nil || neonMultiChannelLane != nil ||
        neonMultiChannelReplicate != nil || neonFourChannelMemory != nil || neonLaneOp != nil ||
        neonThreeChannelMemory != nil || neonByteMatrixAccumulate != nil ||
        neonIndexedMixedByteDotProduct != nil || neonMixedByteDotProduct != nil ||
        neonFullWidthShift != nil || neonRoundedShift != nil || neonSelectedSignedMultiply != nil ||
        neonSelectedWideningAccumulate != nil || neonIndexedByteDotProduct != nil ||
        neonByteDotProduct != nil || neonSelectedUnsignedMultiply != nil || neonBytePolynomialMultiply != nil
    }
}
