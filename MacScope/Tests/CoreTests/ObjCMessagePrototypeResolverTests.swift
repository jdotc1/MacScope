import XCTest
@testable import MacScope

/// OSR-1 PR B slice 1. Rows C24-C28, G12, G13 port the accepted 347 v2 suite; C29-C32 are the
/// AM-10.2 implicit-parameter authority rows. Every fixture declares a raw
/// `DWARFFunctionDeclaration` per candidate: editable `FunctionSignatureOverride` rows are
/// never promoted to authority.
final class ObjCMessagePrototypeResolverTests: XCTestCase {
    private let functionAddress: UInt64 = 0x1000
    private let callAddress: UInt64 = 0x1010
    private let dispatchAddress: UInt64 = 0x4000
    private let methodAddress: UInt64 = 0x2000

    func testPlainMessageSendInstallsOnlyWithEntrySelfAndFixedDebugPrototype() throws {
        let function = try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0)))
        let input = makeInput(
            function: function,
            method: method(),
            signature: debugSignature(
                returnType: "int64_t",
                explicit: [("first", "int64_t"), ("second", "int64_t")]
            )
        )

        let result = resolveWithPreconditions(input)
        let constraint = try XCTUnwrap(result.orderedConstraints.single)
        XCTAssertEqual(constraint.callAddress, callAddress)
        XCTAssertEqual(constraint.directTargetAddress, dispatchAddress)
        XCTAssertEqual(constraint.selector, "combine:with:")
        XCTAssertEqual(constraint.receiverClassName, "Calculator")
        XCTAssertEqual(constraint.dispatchKind, .directMessageSend)
        XCTAssertTrue(constraint.isNativeInstallableInOSR1)
        guard case .installed = result.outcomes[callAddress] else {
            return XCTFail("expected an installed constraint")
        }
    }

    func testPhysicalX0AfterCallDoesNotProveSelf() throws {
        let function = try makePlainMessageFunction(receiver: .register(name: "x0", version: 4))
        let input = makeInput(
            function: function,
            method: method(),
            signature: debugSignature(
                returnType: "int64_t",
                explicit: [("first", "int64_t"), ("second", "int64_t")]
            )
        )

        let result = resolveWithPreconditions(input)
        XCTAssertTrue(result.orderedConstraints.isEmpty)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.receiverUnproven))
    }

    func testRuntimeEncodingWithoutFixedDeclarationDoesNotInstall() throws {
        var input = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: nil
        )
        // No declaration and no editable signature: the runtime encoding alone is not authority.
        XCTAssertTrue(input.declarationsByImplementation.isEmpty)
        XCTAssertTrue(input.signatureOverrides.isEmpty)
        var result = resolveWithPreconditions(input)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.prototypeIncomplete))
        XCTAssertTrue(result.orderedConstraints.isEmpty)
        // OS2-B2a: a missing editable row no longer blocks. The declaration is the authority; with
        // no qualified debug ABI shapes supplied here the runtime encoding stays unclassified.
        input.declarationsByImplementation[methodAddress] = declaration(
            from: debugSignature(returnType: "int64_t", explicit: [("first", "int64_t"), ("second", "int64_t")]))
        XCTAssertNil(input.signatureOverrides[methodAddress])
        XCTAssertNil(input.debugABIByImplementation[methodAddress])
        result = resolveWithPreconditions(input)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.runtimeDebugTypeUnclassified))
        XCTAssertTrue(result.orderedConstraints.isEmpty)
    }

    // 348 C23: variadic or non-authoritative lists keep fixedness-unproven.
    func testVariadicDebugDeclarationDoesNotInstall() throws {
        var signature = debugSignature(
            returnType: "int64_t",
            explicit: [("first", "int64_t"), ("second", "int64_t")]
        )
        signature.variadicState = .variadic
        let variadicInput = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: signature
        )
        XCTAssertTrue(variadicInput.declarationsByImplementation[methodAddress]?.isVariadic == true)
        XCTAssertEqual(resolveWithPreconditions(variadicInput).outcomes[callAddress],
                       .abstained(.fixednessUnproven))

        // A fixed declaration whose editable row says variadic is restricted, not trusted.
        var restricted = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: signature
        )
        restricted.declarationsByImplementation[methodAddress]?.isVariadic = false
        XCTAssertEqual(restricted.signatureOverrides[methodAddress]?.variadicState, .variadic)
        XCTAssertEqual(resolveWithPreconditions(restricted).outcomes[callAddress],
                       .abstained(.fixednessUnproven))

        var nonAuthoritative = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: debugSignature(returnType: "int64_t",
                                      explicit: [("first", "int64_t"), ("second", "int64_t")])
        )
        nonAuthoritative.declarationsByImplementation[methodAddress]?.hasAuthoritativeParameterList = false
        XCTAssertEqual(resolveWithPreconditions(nonAuthoritative).outcomes[callAddress],
                       .abstained(.fixednessUnproven))
    }

    func testUserRowsDoNotBecomeAutomaticCallSiteAuthority() throws {
        let rows = [
            ArgOverride(name: "self", type: "id", provenance: .user),
            ArgOverride(name: "_cmd", type: "SEL", provenance: .user),
            ArgOverride(name: "first", type: "int64_t", provenance: .user),
            ArgOverride(name: "second", type: "int64_t", provenance: .user),
        ]
        let signature = FunctionSignatureOverride(
            returnType: "int64_t",
            parameterList: .authoritative(rows),
            variadicState: .fixed
        )
        let result = resolveWithPreconditions(makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: signature
        ))
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.prototypeNotDebugBacked))
    }

    // AM-10.2: complete debug-provenance editable rows without a declaration cannot authorize.
    func testEditableRowsWithoutDeclarationAbstainPrototypeIncomplete() throws {
        var input = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: debugSignature(returnType: "int64_t",
                                      explicit: [("first", "int64_t"), ("second", "int64_t")])
        )
        input.declarationsByImplementation.removeAll()
        XCTAssertEqual(input.signatureOverrides[methodAddress]?.args.count, 4)
        XCTAssertNotNil(input.debugABIByImplementation[methodAddress])
        let result = resolveWithPreconditions(input)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.prototypeIncomplete))
        XCTAssertTrue(result.orderedConstraints.isEmpty)
    }

    // AM-10.2: the editable signature may only restrict the declaration authority.
    func testEditableRowsDisagreeingWithDeclarationAbstain() throws {
        var input = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: debugSignature(returnType: "int64_t",
                                      explicit: [("first", "int64_t"), ("second", "int64_t")])
        )
        input.declarationsByImplementation[methodAddress]?.parameters[2].type = "double"
        XCTAssertEqual(input.declarationsByImplementation[methodAddress]?.parameters.map(\.type),
                       ["id", "SEL", "double", "int64_t"])
        XCTAssertEqual(input.signatureOverrides[methodAddress]?.args.map(\.type),
                       ["id", "SEL", "int64_t", "int64_t"])
        let result = resolveWithPreconditions(input)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.prototypeIncomplete))
        XCTAssertTrue(result.orderedConstraints.isEmpty)
    }

    func testRuntimeAndDebugTypeConflictIsContradiction() throws {
        let conflicting = debugSignature(
            returnType: "int64_t",
            explicit: [("first", "double"), ("second", "int64_t")]
        )
        let result = resolveWithPreconditions(makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
            method: method(),
            signature: conflicting
        ))
        XCTAssertEqual(result.outcomes[callAddress], .contradiction(.runtimeDebugTypeConflict))
    }

    func testVerifiedSelectorStubIsMacIROnlyInOSR1() throws {
        let function = try makeStubMessageFunction(receiver: .argument(bindingID: .gpr(0)))
        let result = resolveWithPreconditions(makeInput(
            function: function,
            method: method(),
            signature: debugSignature(
                returnType: "int64_t",
                explicit: [("first", "int64_t"), ("second", "int64_t")]
            ),
            targetSymbol: "_objc_msgSend$combine:with:",
            verifiedStubSelector: "combine:with:"
        ))
        let constraint = try XCTUnwrap(result.orderedConstraints.single)
        XCTAssertEqual(constraint.dispatchKind, .verifiedSelectorStub)
        XCTAssertFalse(constraint.isNativeInstallableInOSR1)
        guard case .macIROnly = result.outcomes[callAddress] else {
            return XCTFail("verified selector stub must remain MacIR-only in OSR-1")
        }
    }

    func testLookalikeStubNameWithoutVerifiedStubProofAbstains() throws {
        let function = try makeStubMessageFunction(receiver: .argument(bindingID: .gpr(0)))
        let result = resolveWithPreconditions(makeInput(
            function: function,
            method: method(),
            signature: debugSignature(
                returnType: "int64_t",
                explicit: [("first", "int64_t"), ("second", "int64_t")]
            ),
            targetSymbol: "_objc_msgSend$combine:with:",
            verifiedStubSelector: nil
        ))
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.notObjectiveCDispatch))
    }

    // C24: table v/VOID return (343 row 137) differs from missing authority.
    func testVoidReturnVersusUnresolvedReturn() throws {
        var m = method(); m.typeEncoding = "v32@0:8q16q24"
        var input = makeInput(function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
                              method: m, signature: debugSignature(returnType: "void",
                              explicit: [("first", "int64_t"), ("second", "int64_t")]))
        guard case .installed = resolveWithPreconditions(input).outcomes[callAddress] else {
            return XCTFail("void is a complete no-result declaration")
        }
        let unresolved = debugSignature(returnType: "undefined", explicit: [("first", "int64_t"), ("second", "int64_t")])
        input.signatureOverrides[methodAddress] = unresolved
        input.declarationsByImplementation[methodAddress] = declaration(from: unresolved)
        input.debugABIByImplementation[methodAddress] = fixtureABI(unresolved)
        XCTAssertEqual(input.debugABIByImplementation[methodAddress]?.returnType.shape, .unknown)
        XCTAssertEqual(resolveWithPreconditions(input).outcomes[callAddress], .abstained(.runtimeDebugTypeUnclassified))
        input.signatureOverrides[methodAddress]?.returnType = nil
        XCTAssertNil(input.signatureOverrides[methodAddress]?.returnType)
        XCTAssertEqual(resolveWithPreconditions(input).outcomes[callAddress], .abstained(.prototypeIncomplete))
    }

    // C25: table rows 131-134, 142; over-bound is parser policy.
    func testMalformedMissingAndOverBoundEncodingsAbstain() throws {
        let encodings: [String?] = [nil, "", "q32@0:8q16", "q32@0:8^", "q32@0:8z16q24",
            "q32@0:8@\"unterminated", "q32@0:8q16q24q32", "q32@0:8@?<v@?i>16q24",
            String(repeating: "r", count: 4097) + "q32@0:8q16q24"]
        for encoding in encodings {
            var m = method(); m.typeEncoding = encoding
            let input = makeInput(function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
                                  method: m, signature: debugSignature(returnType: "int64_t",
                                  explicit: [("first", "int64_t"), ("second", "int64_t")]))
            XCTAssertEqual(input.classes[0].instanceMethods.last?.typeEncoding, encoding)
            XCTAssertEqual(resolveWithPreconditions(input).outcomes[callAddress],
                           .abstained(.runtimeDebugTypeUnclassified), "encoding: \(String(describing: encoding))")
        }
    }

    // C26: q/F64 conflict (343:58) wins over absent fixed declaration in either order.
    func testMixedCandidateConflictPrecedenceIsOrderIndependent() throws {
        let function = try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0)))
        let bad = debugSignature(returnType: "int64_t", explicit: [("first", "double"), ("second", "int64_t")])
        for missingIMP in [UInt64(0x1800), UInt64(0x2100)] {
            var input = makeInput(function: function, method: method(), signature: bad)
            var missing = method(); missing.implementation = missingIMP
            input.classes[0].instanceMethods.append(missing)
            XCTAssertNil(input.signatureOverrides[missingIMP])
            XCTAssertNil(input.declarationsByImplementation[missingIMP])
            let candidates = ObjCMethodOwnerIndex.methodsInStaticScope(selector: "combine:with:",
                receiverClassName: "Calculator", isClassMethod: false, classes: input.classes, categories: [])
            XCTAssertEqual(candidates.count, 2)
            let expectedOrder: [UInt64] = missingIMP < methodAddress
                ? [missingIMP, methodAddress] : [methodAddress, missingIMP]
            XCTAssertEqual(candidates.compactMap { $0.method.implementation }, expectedOrder)
            let result = resolveWithPreconditions(input)
            XCTAssertEqual(result.outcomes[callAddress], .contradiction(.runtimeDebugTypeConflict))
            XCTAssertTrue(result.orderedConstraints.isEmpty)
        }
    }

    // C27 / table q/opaque-name (343:136): matching spelling is not resolved type evidence.
    func testUnclassifiedDebugShapeAbstains() throws {
        var input = makeInput(function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
                              method: method(), signature: debugSignature(returnType: "int64_t",
                              explicit: [("first", "int64_t"), ("second", "int64_t")]))
        input.debugABIByImplementation.removeValue(forKey: methodAddress)
        XCTAssertNil(input.debugABIByImplementation[methodAddress])
        XCTAssertEqual(resolveWithPreconditions(input).outcomes[callAddress], .abstained(.runtimeDebugTypeUnclassified))
    }

    // G12: comparison authority rows: q/S64:26; q/F64:58; @/OBJPTR64:61;
    // @/DATAPTR64:74; l/S64:22; D/F64:52; B/BOOL8:44; v/VOID:137.
    func testABIClassComparisonPreservesThreeVerdicts() {
        typealias S = ObjCMessageABIComparison.Shape
        let rows: [(S, S, Bool, ObjCMessageABIComparison.Verdict)] = [
            (.s64, .s64, false, .agree), (.s64, .f64, false, .contradiction),
            (.object, .object, false, .agree), (.object, .dataPointer, false, .unclassified),
            (.s32, .s64, false, .contradiction), (.f64, .f64, true, .agree),
            (.bool, .bool, false, .agree), (.void, .void, true, .agree),
            (.void, .void, false, .unclassified), (.s32, .lossyEnum(.other), false, .unclassified)
        ]
        for (runtime, debug, isReturn, expected) in rows {
            XCTAssertEqual(ObjCMessageABIComparison.compare(runtime: runtime, debug: debug, isReturn: isReturn), expected)
        }
    }

    // G13: q/S64 (343:26,39): matching class with different debug spelling is not conflict.
    func testCandidateABIIdentityIgnoresTypedefSpelling() throws {
        var input = makeInput(function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0))),
                              method: method(), signature: debugSignature(returnType: "int64_t",
                              explicit: [("first", "int64_t"), ("second", "int64_t")]))
        var alias = method(); alias.implementation = 0x2100
        input.classes[0].instanceMethods.append(alias)
        let signature = debugSignature(returnType: "long", explicit: [("first", "long"), ("second", "long")])
        input.signatureOverrides[0x2100] = signature
        input.declarationsByImplementation[0x2100] = declaration(from: signature)
        input.debugABIByImplementation[0x2100] = fixtureABI(signature)
        XCTAssertEqual(input.classes[0].instanceMethods.filter { $0.selector == "combine:with:" }.count, 2)
        let result = resolveWithPreconditions(input)
        let constraint = try XCTUnwrap(result.orderedConstraints.single)
        XCTAssertEqual(constraint.evidence.methodImplementations, [methodAddress, 0x2100])
        XCTAssertEqual(constraint.returnType, "int64_t") // deterministic first evidence spelling retained
        guard case .installed = result.outcomes[callAddress] else { return XCTFail("same ABI class") }
    }

    // MARK: - AM-10.2 rows C29-C32

    func testC29NoArtificialEvidenceAbstainsPrototypeIncomplete() throws {
        let declaration = ordinaryDeclaration(receiverArtificial: false, selectorArtificial: false)
        XCTAssertFalse(declaration.isObjectiveCDirect)
        XCTAssertEqual(declaration.parameters.map(\.name), ["self", "_cmd", "value"])
        XCTAssertEqual(declaration.parameters.map(\.type), ["id", "SEL", "int"])
        XCTAssertEqual(declaration.parameters.map(\.isArtificial), [false, false, false])
        try assertRefused(declaration, selector: "value:", expectedCount: 3)
    }

    func testC30MixedArtificialEvidenceAbstainsPrototypeIncomplete() throws {
        let declaration = ordinaryDeclaration(receiverArtificial: true, selectorArtificial: false)
        XCTAssertFalse(declaration.isObjectiveCDirect)
        XCTAssertEqual(declaration.parameters.map(\.isArtificial), [true, false, false])
        try assertRefused(declaration, selector: "value:", expectedCount: 3)
    }

    func testC31DirectDeclarationAndDefinitionAbstainPrototypeIncomplete() throws {
        for inherited in [false, true] {
            let fixture = DirectMethodDWARF.sections(inherited: inherited, concreteOnly: false)
            try assertDirectDIEShape(fixture.sections, inherited: inherited, concreteOnly: false)
            let recovery = DWARFFunctionSignatureReader(sections: fixture.sections)
                .recoverSignaturesAndDeclarations()
            let declaration = try XCTUnwrap(recovery.declarations[methodAddress])
            XCTAssertTrue(recovery.refusedAddresses.isEmpty)
            XCTAssertNotNil(recovery.signatures[methodAddress])
            XCTAssertTrue(declaration.isObjectiveCDirect)
            XCTAssertEqual(declaration.parameters.map(\.name), ["self", "_cmd", "value"])
            XCTAssertEqual(declaration.parameters.map(\.type), ["id", "SEL", "int"])
            XCTAssertEqual(declaration.parameters.map(\.isArtificial), [true, true, false])
            try assertRefused(declaration, selector: "directOne:", expectedCount: 3, expectedReturn: "int")
        }
    }

    func testC32ConcreteOnlyDirectDefinitionAbstainsPrototypeIncomplete() throws {
        let fixture = DirectMethodDWARF.sections(inherited: false, concreteOnly: true)
        try assertDirectDIEShape(fixture.sections, inherited: false, concreteOnly: true)
        let recovery = DWARFFunctionSignatureReader(sections: fixture.sections)
            .recoverSignaturesAndDeclarations()
        let declaration = try XCTUnwrap(recovery.declarations[methodAddress])
        XCTAssertTrue(recovery.refusedAddresses.isEmpty)
        XCTAssertNotNil(recovery.signatures[methodAddress])
        XCTAssertTrue(declaration.isObjectiveCDirect)
        XCTAssertEqual(declaration.parameters.map(\.name), ["self", "value"])
        XCTAssertEqual(declaration.parameters.map(\.type), ["id", "int"])
        XCTAssertEqual(declaration.parameters.map(\.isArtificial), [true, false])
        try assertRefused(declaration, selector: "directOne:", expectedCount: 2, expectedReturn: "int")
    }

    /// Shared positive control for C29-C32: same fixture shape, ordinary artificial pair.
    func testC29C32OrdinaryArtificialPairControlInstalls() throws {
        let declaration = ordinaryDeclaration(receiverArtificial: true, selectorArtificial: true)
        XCTAssertEqual(declaration.parameters.map(\.isArtificial), [true, true, false])
        XCTAssertFalse(declaration.isObjectiveCDirect)
        XCTAssertEqual(try XCTUnwrap(declaration.explicitObjectiveCParameters(selectorArity: 1)),
                       [.init(name: "value", type: "int", isArtificial: false)])
        let input = try qualifiedFixture(declaration, selector: "value:")
        let result = resolveWithPreconditions(input)
        XCTAssertEqual(result.orderedConstraints.count, 1)
        guard case .installed = result.outcomes[callAddress] else {
            return XCTFail("the shared nonnegative fixture must reach installation")
        }
    }

    // MARK: - C29-C32 helpers

    private func assertDirectDIEShape(_ sections: DWARFReader.Sections,
                                      inherited: Bool, concreteOnly: Bool) throws {
        let roots = DWARFDIETree(sections: sections).parse()
        XCTAssertEqual(roots.count, 1)
        let root = try XCTUnwrap(roots.first)
        let subprograms = root.children.filter { $0.tag == DWARFConstants.tagSubprogram }
        XCTAssertEqual(subprograms.count, inherited ? 2 : 1)
        let source = try XCTUnwrap(subprograms.first)
        guard case .uint(1)? = source.attributes[DWARFConstants.atAppleObjCDirect] else {
            return XCTFail("source DIE must carry direct flag_present")
        }
        let formals = source.children.filter { $0.tag == DWARFConstants.tagFormalParameter }
        XCTAssertEqual(formals.count, concreteOnly ? 2 : 3)
        if concreteOnly {
            XCTAssertNil(source.attributes[0x3c]) // no DW_AT_declaration
        } else {
            guard case .uint(1)? = source.attributes[0x3c] else {
                return XCTFail("source must be a declaration DIE")
            }
        }
        if inherited {
            XCTAssertNil(source.attributes[DWARFConstants.atLowPC])
            let definition = try XCTUnwrap(subprograms.last)
            XCTAssertTrue(definition.children.isEmpty)
            XCTAssertNil(definition.attributes[DWARFConstants.atAppleObjCDirect])
            guard case .uint(let offset)? = definition.attributes[DWARFConstants.atSpecification] else {
                return XCTFail("definition must reference the declaration")
            }
            XCTAssertEqual(Int(exactly: offset), source.cuOffset)
            guard case .address(0x2000)? = definition.attributes[DWARFConstants.atLowPC] else {
                return XCTFail("definition must be the candidate IMP")
            }
        } else {
            guard case .address(0x2000)? = source.attributes[DWARFConstants.atLowPC] else {
                return XCTFail("address-bearing view must be the candidate IMP")
            }
        }
    }

    private func ordinaryDeclaration(receiverArtificial: Bool, selectorArtificial: Bool)
        -> DWARFFunctionDeclaration {
        .init(returnType: "id", parameters: [
            .init(name: "self", type: "id", isArtificial: receiverArtificial),
            .init(name: "_cmd", type: "SEL", isArtificial: selectorArtificial),
            .init(name: "value", type: "int", isArtificial: false)
        ], hasAuthoritativeParameterList: true, isVariadic: false, isObjectiveCDirect: false)
    }

    private func assertRefused(_ declaration: DWARFFunctionDeclaration, selector: String,
                               expectedCount: Int, expectedReturn: String = "id", file: StaticString = #filePath,
                               line: UInt = #line) throws {
        XCTAssertEqual(selector.filter { $0 == ":" }.count, 1, file: file, line: line)
        XCTAssertTrue(declaration.hasAuthoritativeParameterList, file: file, line: line)
        XCTAssertFalse(declaration.isVariadic, file: file, line: line)
        XCTAssertEqual(declaration.returnType, expectedReturn, file: file, line: line)
        XCTAssertEqual(declaration.parameters.count, expectedCount, file: file, line: line)
        let input = try qualifiedFixture(declaration, selector: selector)
        XCTAssertEqual(input.declarationsByImplementation[methodAddress], declaration, file: file, line: line)
        // Complete, plausible editable rows are retained even for C32. They are a decoy,
        // not synthesized authority: an implementation using them alone would install.
        XCTAssertEqual(input.signatureOverrides[methodAddress]?.args.count, 3, file: file, line: line)
        XCTAssertNil(declaration.explicitObjectiveCParameters(selectorArity: 1), file: file, line: line)
        let result = resolveWithPreconditions(input, file: file, line: line)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.prototypeIncomplete), file: file, line: line)
        XCTAssertTrue(result.orderedConstraints.isEmpty, file: file, line: line)
    }

    private func qualifiedFixture(_ declaration: DWARFFunctionDeclaration, selector: String)
        throws -> ObjCMessagePrototypeResolver.Input {
        let resultType = try XCTUnwrap(declaration.returnType)
        let encoding = resultType == "int" ? "i24@0:8i16" : "@24@0:8i16"
        let signature = FunctionSignatureOverride(returnType: resultType, parameterList: .authoritative([
            ArgOverride(name: "self", type: "id", provenance: .debug),
            ArgOverride(name: "_cmd", type: "SEL", provenance: .debug),
            ArgOverride(name: "value", type: "int", provenance: .debug)
        ]), variadicState: .fixed, noReturnState: .returns)
        let input = makeInput(
            function: try makePlainMessageFunction(receiver: .argument(bindingID: .gpr(0)),
                                                   selectorName: selector, colonCount: 1),
            method: .init(selector: selector, typeEncoding: encoding, isClassMethod: false,
                          implementation: methodAddress), signature: signature, declaration: declaration)
        XCTAssertEqual(input.classes[0].instanceMethods.last?.selector, selector)
        XCTAssertEqual(input.classes[0].instanceMethods.last?.typeEncoding, encoding)
        let candidates = ObjCMethodOwnerIndex.methodsInStaticScope(selector: selector,
            receiverClassName: "Calculator", isClassMethod: false, classes: input.classes, categories: [])
        XCTAssertEqual(candidates.count, 1)
        XCTAssertEqual(candidates.compactMap { $0.method.implementation }, [methodAddress])
        XCTAssertNotNil(input.debugABIByImplementation[methodAddress])
        XCTAssertEqual(input.function.instructions.count, 1)
        guard case .call(let frame, _) = input.function.instructions[0].operation else {
            XCTFail("fixture must contain the tested send")
            return input
        }
        XCTAssertEqual(frame.target, "_objc_msgSend")
        XCTAssertEqual(frame.arguments.fixedArgument(at: 1)?.selectorEvidence?.name, selector)
        guard case .argument(bindingID: .gpr(0))? = frame.arguments.fixedArgument(at: 0)?.value else {
            XCTFail("receiver must be entry self, not a prior result")
            return input
        }
        return input
    }

    // MARK: - Shared preconditions

    // Preconditions are shared by EVERY resolver test, including negative tests.
    // They inspect the fixture, not the resolver outcome. The local BL arithmetic
    // is independent of the authority target dictionary; no product decoder is run.
    private func resolveWithPreconditions(_ input: ObjCMessagePrototypeResolver.Input,
                                         file: StaticString = #filePath, line: UInt = #line)
        -> ObjCMessagePrototypeResolver.Result {
        guard case .unique(let owner) = ObjCMethodOwnerIndex.owner(implementation: functionAddress,
                classes: input.classes, categories: input.categories) else {
            XCTFail("fixture must have a unique enclosing owner", file: file, line: line)
            return .init(outcomes: [:], orderedConstraints: [])
        }
        XCTAssertEqual(owner.method.selector, "caller", file: file, line: line)
        XCTAssertEqual(input.function.startAddress, functionAddress, file: file, line: line)
        let bytes = input.instructionAuthority.bytesByAddress[callAddress] ?? []
        XCTAssertEqual(bytes, [0xfc, 0x0b, 0x00, 0x94], file: file, line: line)
        if bytes.count == 4 {
            let word = UInt32(bytes[0]) | UInt32(bytes[1]) << 8 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
            XCTAssertEqual(word & 0xfc000000, 0x94000000, file: file, line: line)
            let delta = Int64(Int32(bitPattern: (word & 0x03ffffff) << 6) >> 4)
            XCTAssertEqual(Int64(callAddress) + delta, Int64(dispatchAddress), file: file, line: line)
        }
        XCTAssertEqual(input.instructionAuthority.directTargetByAddress[callAddress], dispatchAddress, file: file, line: line)
        XCTAssertNotNil(input.instructionAuthority.callableSymbolByAddress[dispatchAddress], file: file, line: line)
        XCTAssertTrue(input.instructionAuthority.functionRange.contains(callAddress), file: file, line: line)
        return ObjCMessagePrototypeResolver.resolve(input)
    }

    // Test-only resolved catalog facts, NOT a production spelling classifier.
    // Every admitted spelling here is an explicit synthetic DWARF fixture shape.
    private func fixtureABI(_ signature: FunctionSignatureOverride) -> ObjCMessageABIComparison.DebugPrototype? {
        guard let returnType = signature.returnType, case .authoritative(let rows) = signature.parameterList else { return nil }
        func type(_ spelling: String) -> ObjCMessageABIComparison.DebugType {
            let shapes: [String: ObjCMessageABIComparison.Shape] = ["id": .object, "SEL": .selector,
                "int64_t": .s64, "long": .s64, "int": .s32, "double": .f64, "void": .void]
            return .init(spelling: spelling, shape: shapes[spelling] ?? .unknown)
        }
        return .init(returnType: type(returnType), parameters: rows.map { type($0.type) })
    }

    // Test-only raw declaration standing in for a recovered, qualified DWARF declaration:
    // explicit artificial self/_cmd, fixed authoritative list. Never derived from product code.
    private func declaration(from signature: FunctionSignatureOverride) -> DWARFFunctionDeclaration {
        .init(
            returnType: signature.returnType,
            parameters: signature.args.enumerated().map { offset, row in
                .init(name: row.name, type: row.type, isArtificial: offset < 2)
            },
            hasAuthoritativeParameterList: true,
            isVariadic: signature.variadicState == .variadic,
            isObjectiveCDirect: false
        )
    }

    // MARK: - Fixtures

    private func method() -> ObjCMethod {
        .init(
            selector: "combine:with:",
            typeEncoding: "q32@0:8q16q24",
            isClassMethod: false,
            implementation: methodAddress
        )
    }

    private func debugSignature(
        returnType: String,
        explicit: [(String, String)]
    ) -> FunctionSignatureOverride {
        let rows = [
            ArgOverride(name: "self", type: "id", provenance: .debug),
            ArgOverride(name: "_cmd", type: "SEL", provenance: .debug),
        ] + explicit.map { ArgOverride(name: $0.0, type: $0.1, provenance: .debug) }
        return .init(
            returnType: returnType,
            parameterList: .authoritative(rows),
            variadicState: .fixed,
            noReturnState: .returns
        )
    }

    private func makeInput(
        function: MacIRFunction,
        method: ObjCMethod,
        signature: FunctionSignatureOverride?,
        declaration explicitDeclaration: DWARFFunctionDeclaration? = nil,
        targetSymbol: String = "_objc_msgSend",
        verifiedStubSelector: String? = nil
    ) -> ObjCMessagePrototypeResolver.Input {
        let objcClass = ObjCClass(
            name: "Calculator",
            superclassName: nil,
            adoptedProtocols: [],
            classMethods: [],
            instanceMethods: [.init(selector: "caller", typeEncoding: "v16@0:8",
                                    isClassMethod: false, implementation: functionAddress), method],
            ivars: [],
            properties: []
        )
        let declarations = (explicitDeclaration ?? signature.map(declaration(from:)))
            .map { [methodAddress: $0] } ?? [:]
        return .init(
            function: function,
            classes: [objcClass],
            categories: [],
            declarationsByImplementation: declarations,
            signatureOverrides: signature.map { [methodAddress: $0] } ?? [:],
            debugABIByImplementation: signature.flatMap(fixtureABI).map { [methodAddress: $0] } ?? [:],
            instructionAuthority: .init(
                bytesByAddress: [callAddress: [0xfc, 0x0b, 0x00, 0x94]],
                directTargetByAddress: [callAddress: dispatchAddress],
                callableSymbolByAddress: [dispatchAddress: targetSymbol],
                verifiedSelectorStubByAddress: verifiedStubSelector.map { [dispatchAddress: $0] } ?? [:],
                functionRange: functionAddress ..< 0x1100
            )
        )
    }

    private func makePlainMessageFunction(receiver: MacIRValue, selectorName: String = "combine:with:",
                                          colonCount: Int = 2) throws -> MacIRFunction {
        let selector = try XCTUnwrap(MacIRCallSelectorEvidence(
            name: selectorName, selrefAddress: 0x3000
        ))
        let args = try XCTUnwrap(MacIRCallArguments([
            .init(location: .gpr(index: 0, carrierWidth: 64), role: .fixed(sourcePosition: 0), value: receiver),
            .init(location: .gpr(index: 1, carrierWidth: 64), role: .fixed(sourcePosition: 1),
                  value: .symbol("\"\(selectorName)\""), selectorEvidence: selector),
        ]))
        let frame = try XCTUnwrap(MacIRCallFrame(
            target: "_objc_msgSend",
            knownSignature: CallSignatureCatalog.standard.signature(for: "_objc_msgSend"),
            tailCountEvidence: .objectiveCSelectorColonCount(colonCount),
            controlInputs: .none,
            arguments: args
        ))
        return function(frame: frame)
    }

    private func makeStubMessageFunction(receiver: MacIRValue) throws -> MacIRFunction {
        let scope = try XCTUnwrap(MacIRCallArgumentObservationScope(gprIndices: [0, 2, 3]))
        let args = try XCTUnwrap(MacIRCallArguments([
            .init(location: .gpr(index: 0, carrierWidth: 64), role: .unknown, value: receiver),
            .init(location: .gpr(index: 2, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(2))),
            .init(location: .gpr(index: 3, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(3))),
        ], observationScope: scope))
        let frame = try XCTUnwrap(MacIRCallFrame(
            target: "_objc_msgSend$combine:with:",
            knownSignature: nil,
            controlInputs: .none,
            arguments: args
        ))
        return function(frame: frame)
    }

    private func function(frame: MacIRCallFrame) -> MacIRFunction {
        let source = MacIRSourceSpan(
            address: callAddress,
            byteText: "fc 0b 00 94",
            mnemonic: "bl",
            operands: frame.target
        )
        return MacIRFunction(
            name: "-[Calculator caller]",
            startAddress: functionAddress,
            instructions: [.init(source: source, operation: .call(frame: frame, result: nil))]
        )
    }
}

private extension Collection {
    var single: Element? { count == 1 ? first : nil }
}

// Bounded synthetic DWARF v4 section builder, patterned after the supplied
// SyntheticSignatureDWARF / DIEBuilder. It does not invoke clang or dwarfdump.
private enum DirectMethodDWARF {
    struct Fixture {
        let sections: DWARFReader.Sections
    }

    static func sections(inherited: Bool, concreteOnly: Bool) -> Fixture {
        // 1 CU; 2 addressed declaration; 3 unaddressed declaration;
        // 4 concrete definition -> specification; 5 formal; 6 base type;
        // 7 addressed concrete definition with its own formals.
        let abbrev: [UInt8] = [
            1, 0x11, 1, 0, 0,
            2, 0x2e, 1, 0x11, 1, 0x03, 8, 0x49, 0x13, 0x3c, 0x19, 0xee, 0x7f, 0x19, 0, 0,
            3, 0x2e, 1, 0x03, 8, 0x49, 0x13, 0x3c, 0x19, 0xee, 0x7f, 0x19, 0, 0,
            4, 0x2e, 0, 0x11, 1, 0x47, 0x13, 0, 0,
            5, 0x05, 0, 0x03, 8, 0x49, 0x13, 0x34, 0x0c, 0, 0,
            6, 0x24, 0, 0x03, 8, 0x0b, 0x0b, 0, 0,
            7, 0x2e, 1, 0x11, 1, 0x03, 8, 0x49, 0x13, 0xee, 0x7f, 0x19, 0, 0,
            0
        ]
        var b = Builder()
        b.byte(1)
        b.mark("source")
        b.byte(concreteOnly ? 7 : (inherited ? 3 : 2))
        if !inherited { b.u64(0x2000) }
        b.string("-[Calculator directOne:]")
        b.ref("int")
        // Direct and declaration attributes use flag_present and consume no bytes.
        b.byte(5); b.string("self"); b.ref("id"); b.byte(1)
        if !concreteOnly {
            b.byte(5); b.string("_cmd"); b.ref("SEL"); b.byte(1)
        }
        b.byte(5); b.string("value"); b.ref("int"); b.byte(0)
        b.byte(0)
        if inherited {
            b.byte(4); b.u64(0x2000); b.ref("source")
        }
        for (name, size) in [("id", UInt8(8)), ("SEL", UInt8(8)), ("int", UInt8(4))] {
            b.mark(name); b.byte(6); b.string(name); b.byte(size)
        }
        b.byte(0)
        let die = b.resolved()
        let body: [UInt8] = [4, 0, 0, 0, 0, 0, 8] + die
        let size = UInt32(body.count)
        let length = (0..<4).map { UInt8((size >> (8 * $0)) & 0xff) }
        return .init(sections: .init(debugInfo: Data(length + body), debugAbbrev: Data(abbrev)))
    }

    private struct Builder {
        var bytes: [UInt8] = []
        var labels: [String: Int] = [:]
        var references: [(Int, String)] = []
        mutating func byte(_ value: UInt8) { bytes.append(value) }
        mutating func string(_ value: String) { bytes += Array(value.utf8) + [0] }
        mutating func u64(_ value: UInt64) {
            bytes += (0..<8).map { UInt8((value >> (8 * $0)) & 0xff) }
        }
        mutating func mark(_ name: String) { labels[name] = 11 + bytes.count }
        mutating func ref(_ name: String) {
            references.append((bytes.count, name)); bytes += [0, 0, 0, 0]
        }
        func resolved() -> [UInt8] {
            var result = bytes
            for (position, name) in references {
                // All labels are literal fixture labels above, not untrusted input.
                let offset = UInt32(labels[name]!)
                for i in 0..<4 { result[position + i] = UInt8((offset >> (8 * i)) & 0xff) }
            }
            return result
        }
    }
}
