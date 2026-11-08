import Foundation

// Pure resolver: consumes typed IR and immutable image facts. It never parses
// pseudocode text and never returns a concrete dynamic-dispatch target.
// Nothing in product code calls it yet (OSR-1 PR B slice 1).
//
// Prototype authority is the immutable, qualified `DWARFFunctionDeclaration` keyed by
// IMP (`explicitObjectiveCParameters(selectorArity:)` proves the artificial self/_cmd pair
// and refuses objc_direct). Conflicting DWARF declarations at one address never reach
// `declarationsByImplementation`: `DWARFFunctionSignatureReader.recoverSignaturesAndDeclarations`
// drops them and records `refusedAddresses` (DWARFFunctionSignatureReader.swift:76,81).
// Editable `FunctionSignatureOverride` rows may only restrict that authority; a missing
// row never blocks success (AM-10-PR-B.md:27).

enum ObjCMessagePrototypeResolver {
    static let maximumConstraintsPerFunction = 256

    struct InstructionAuthority: Sendable {
        /// Exact effective bytes keyed by the call instruction address.
        var bytesByAddress: [UInt64: [UInt8]]
        /// Direct BL target decoded from the same effective bytes.
        var directTargetByAddress: [UInt64: UInt64]
        /// Loader-owned callable symbol at each exact target.
        var callableSymbolByAddress: [UInt64: String]
        /// Target address -> selector, produced only by verified stub recovery.
        var verifiedSelectorStubByAddress: [UInt64: String]
        var functionRange: Range<UInt64>
    }

    struct Input: Sendable {
        var function: MacIRFunction
        var classes: [ObjCClass]
        var categories: [ObjCCategory]
        // Supplied only after immutable capture and image/debug qualification (AM-10).
        // Missing values never fall back to editable override rows.
        var declarationsByImplementation: [UInt64: DWARFFunctionDeclaration] = [:]
        var signatureOverrides: [UInt64: FunctionSignatureOverride]
        // Qualified, resolved DWARF facts. Missing entries fail closed.
        var debugABIByImplementation: [UInt64: ObjCMessageABIComparison.DebugPrototype] = [:]
        var instructionAuthority: InstructionAuthority
    }

    struct Result: Sendable {
        var outcomes: [UInt64: ObjCMessageConstraintOutcome]
        var orderedConstraints: [ObjCMessageConstraint]
    }

    static func resolve(_ input: Input) -> Result {
        let ownerLookup = ObjCMethodOwnerIndex.owner(
            implementation: input.function.startAddress,
            classes: input.classes,
            categories: input.categories
        )
        guard case .unique(let enclosing) = ownerLookup else {
            let reason: ObjCMessageConstraintReason = {
                if case .none = ownerLookup { return .methodOwnerNone }
                return .methodOwnerAmbiguous
            }()
            let calls = input.function.instructions.compactMap { instruction -> UInt64? in
                if case .call = instruction.operation { return instruction.source.address }
                return nil
            }
            return Result(
                outcomes: Dictionary(uniqueKeysWithValues: calls.map { ($0, .abstained(reason)) }),
                orderedConstraints: []
            )
        }

        let receiverClass = ObjCMethodOwnerIndex.receiverClassName(for: enclosing.owner)
        var outcomes: [UInt64: ObjCMessageConstraintOutcome] = [:]
        var constraints: [ObjCMessageConstraint] = []

        for instruction in input.function.instructions {
            guard case let .call(frame, _) = instruction.operation else { continue }
            let address = instruction.source.address
            guard constraints.count < maximumConstraintsPerFunction else {
                outcomes[address] = .abstained(.constraintBudgetExceeded)
                continue
            }
            guard input.instructionAuthority.functionRange.contains(address) else {
                outcomes[address] = .contradiction(.callAddressOutsideFunction)
                continue
            }
            guard let bytes = input.instructionAuthority.bytesByAddress[address], bytes.count == 4 else {
                outcomes[address] = .contradiction(.instructionByteMismatch)
                continue
            }
            guard let directTarget = input.instructionAuthority.directTargetByAddress[address],
                  let symbol = input.instructionAuthority.callableSymbolByAddress[directTarget] else {
                outcomes[address] = .abstained(.notObjectiveCDispatch)
                continue
            }

            let dispatch = dispatchFact(
                frame: frame,
                directTarget: directTarget,
                symbol: symbol,
                verifiedSelectorStubs: input.instructionAuthority.verifiedSelectorStubByAddress
            )
            guard let dispatch else {
                outcomes[address] = .abstained(.notObjectiveCDispatch)
                continue
            }
            guard let receiver = receiverValue(frame: frame, dispatch: dispatch.kind),
                  isCurrentMethodSelf(receiver) else {
                outcomes[address] = .abstained(.receiverUnproven)
                continue
            }

            let candidates = ObjCMethodOwnerIndex.methodsInStaticScope(
                selector: dispatch.selector,
                receiverClassName: receiverClass,
                isClassMethod: enclosing.owner.isClassMethod,
                classes: input.classes,
                categories: input.categories
            )
            guard !candidates.isEmpty else {
                outcomes[address] = .abstained(.methodNotFoundInStaticScope)
                continue
            }

            var prototypes: [ResolvedPrototype] = []
            var failures: [ObjCMessageConstraintReason] = []
            for candidate in candidates {
                switch fixedDebugPrototype(
                    candidate: candidate,
                    declarations: input.declarationsByImplementation,
                    overrides: input.signatureOverrides,
                    debugABI: input.debugABIByImplementation
                ) {
                case .success(let prototype):
                    prototypes.append(prototype)
                case .failure(let reason):
                    failures.append(reason)
                }
            }
            // Definite contradiction wins over missing/unclassified evidence;
            // otherwise lexicographic reason order is deterministic. No candidate
            // ordering can hide a proven mismatch or produce a partial constraint.
            if failures.contains(.runtimeDebugTypeConflict) {
                outcomes[address] = .contradiction(.runtimeDebugTypeConflict)
                continue
            }
            if let reason = failures.sorted(by: { $0.rawValue < $1.rawValue }).first {
                outcomes[address] = .abstained(reason)
                continue
            }
            guard let first = prototypes.first else {
                outcomes[address] = .abstained(.fixednessUnproven)
                continue
            }
            guard prototypes.dropFirst().allSatisfy({ $0.abiIdentity == first.abiIdentity }) else {
                outcomes[address] = .contradiction(.methodPrototypeConflict)
                continue
            }

            let constraint = ObjCMessageConstraint(
                callAddress: address,
                expectedInstructionBytes: bytes,
                directTargetAddress: directTarget,
                targetSymbol: symbol,
                dispatchKind: dispatch.kind,
                selector: dispatch.selector,
                receiverClassName: receiverClass,
                methodSide: enclosing.owner.isClassMethod ? .class : .instance,
                returnType: first.returnType,
                methodParameters: first.parameters.map {
                    .init(name: $0.name, type: $0.type)
                },
                evidence: .init(
                    enclosingImplementation: input.function.startAddress,
                    methodImplementations: prototypes.compactMap(\.implementation).sorted(),
                    selectorReferenceAddress: dispatch.selrefAddress,
                    ownerDescriptions: candidates.map { $0.owner.displayName }.sorted(),
                    runtimeTypeEncodings: candidates.compactMap { $0.method.typeEncoding }.sorted(),
                    authority: .debugFixed
                )
            )
            constraints.append(constraint)
            outcomes[address] = constraint.isNativeInstallableInOSR1
                ? .installed(constraint)
                : .macIROnly(constraint)
        }

        constraints.sort { $0.callAddress < $1.callAddress }
        return Result(outcomes: outcomes, orderedConstraints: constraints)
    }

    private struct DispatchFact {
        var kind: ObjCMessageConstraint.DispatchKind
        var selector: String
        var selrefAddress: UInt64?
    }

    private static func dispatchFact(
        frame: MacIRCallFrame,
        directTarget: UInt64,
        symbol: String,
        verifiedSelectorStubs: [UInt64: String]
    ) -> DispatchFact? {
        let canonical = symbol.hasPrefix("_") ? String(symbol.dropFirst()) : symbol
        if canonical == "objc_msgSend" {
            guard let evidence = frame.arguments.fixedArgument(at: 1)?.selectorEvidence else {
                return nil
            }
            return .init(
                kind: .directMessageSend,
                selector: evidence.name,
                selrefAddress: evidence.selrefAddress
            )
        }
        guard let selector = verifiedSelectorStubs[directTarget], !selector.isEmpty else {
            return nil
        }
        return .init(kind: .verifiedSelectorStub, selector: selector, selrefAddress: nil)
    }

    private static func receiverValue(
        frame: MacIRCallFrame,
        dispatch: ObjCMessageConstraint.DispatchKind
    ) -> MacIRValue? {
        switch dispatch {
        case .directMessageSend:
            return frame.arguments.fixedArgument(at: 0)?.value
        case .verifiedSelectorStub:
            return frame.arguments.argument(at: .gpr(index: 0))?.value
                ?? frame.arguments.fixedArgument(at: 0)?.value
        }
    }

    private static func isCurrentMethodSelf(_ value: MacIRValue) -> Bool {
        switch value {
        case .argument(bindingID: .gpr(0)):
            return true
        case let .unary(op, inner)
            where ["(uint64_t)", "(int64_t)", "(void *)", "(id)"].contains(op):
            return isCurrentMethodSelf(inner)
        default:
            return false
        }
    }

    private struct ResolvedPrototype {
        struct Parameter: Hashable {
            var name: String
            var type: String
        }
        var implementation: UInt64?
        var returnType: String
        var parameters: [Parameter]
        var abiIdentity: ABIIdentity
    }

    private struct ABIIdentity: Hashable {
        var returnType: ObjCMessageABIComparison.Shape
        var parameters: [ObjCMessageABIComparison.Shape]
    }

    private enum PrototypeResolutionError: Error {
        case reason(ObjCMessageConstraintReason)
    }

    private static func fixedDebugPrototype(
        candidate: ObjCMethodOwnerIndex.Candidate,
        declarations: [UInt64: DWARFFunctionDeclaration],
        overrides: [UInt64: FunctionSignatureOverride],
        debugABI: [UInt64: ObjCMessageABIComparison.DebugPrototype]
    ) -> Swift.Result<ResolvedPrototype, ObjCMessageConstraintReason> {
        guard let implementation = candidate.method.implementation else {
            return .failure(.fixednessUnproven)
        }
        let arity = candidate.method.selector.filter { $0 == ":" }.count
        guard let declaration = declarations[implementation] else {
            return .failure(.prototypeIncomplete)
        }
        guard declaration.hasAuthoritativeParameterList, !declaration.isVariadic else {
            return .failure(.fixednessUnproven)
        }
        guard declaration.explicitObjectiveCParameters(selectorArity: arity) != nil else {
            return .failure(.prototypeIncomplete)
        }
        // Return and parameter types come only from the qualified declaration. A missing
        // editable row never blocks; a present row may only restrict (never add facts).
        guard let returnType = declaration.returnType else {
            return .failure(.prototypeIncomplete)
        }
        let rows: [ResolvedPrototype.Parameter] = declaration.parameters.map {
            .init(name: $0.name ?? "", type: $0.type ?? "")
        }
        guard declaration.parameters.allSatisfy({ $0.type != nil }),
              rows.count == arity + 2 else {
            return .failure(.prototypeIncomplete)
        }
        if let override = overrides[implementation] {
            if override.parameterList != .unspecified || override.returnType != nil {
                guard let overrideReturn = override.returnType,
                      case let .authoritative(overrideRows) = override.parameterList else {
                    return .failure(.prototypeIncomplete)
                }
                guard override.variadicState != .variadic else {
                    return .failure(.fixednessUnproven)
                }
                guard override.noReturnState != .noReturn else {
                    return .failure(.prototypeIncomplete)
                }
                guard overrideRows.count == arity + 2 else {
                    return .failure(.prototypeIncomplete)
                }
                guard overrideRows.allSatisfy({ $0.provenance == .debug }) else {
                    return .failure(.prototypeNotDebugBacked)
                }
                guard overrideReturn == returnType,
                      zip(rows, overrideRows).allSatisfy({ $0.type == $1.type }) else {
                    return .failure(.prototypeIncomplete)
                }
            } else if override.variadicState == .variadic {
                return .failure(.fixednessUnproven)
            } else if override.noReturnState == .noReturn {
                return .failure(.prototypeIncomplete)
            }
        }

        guard let encoding = candidate.method.typeEncoding,
              let runtime = ObjCMessageABIComparison.decode(encoding, arity: arity),
              let debug = debugABI[implementation],
              debug.returnType.spelling == returnType,
              debug.parameters.count == rows.count,
              zip(debug.parameters, rows).allSatisfy({ $0.spelling == $1.type }) else {
            return .failure(.runtimeDebugTypeUnclassified)
        }
        let comparisons = [ObjCMessageABIComparison.compare(
            runtime: runtime[0], debug: debug.returnType.shape, isReturn: true
        )] + zip(runtime.dropFirst(3), debug.parameters.dropFirst(2)).map {
            ObjCMessageABIComparison.compare(runtime: $0, debug: $1.shape, isReturn: false)
        }
        // A definite conflict remains a conflict even if another field is unknown.
        if comparisons.contains(where: { if case .contradiction = $0 { return true }; return false }) {
            return .failure(.runtimeDebugTypeConflict)
        }
        if comparisons.contains(where: { if case .unclassified = $0 { return true }; return false }) {
            return .failure(.runtimeDebugTypeUnclassified)
        }

        return .success(.init(
            implementation: implementation,
            returnType: returnType,
            parameters: rows.map { .init(name: $0.name, type: $0.type) },
            // Runtime shapes agreed with qualified debug shapes; use these class
            // identities, not typedef/class spellings, across candidates.
            abiIdentity: .init(returnType: runtime[0], parameters: Array(runtime.dropFirst(1)))
        ))
    }

}
