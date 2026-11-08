import Foundation
import XCTest
@testable import MacScope

/// OSR-1 PR B slice 2a: the production input adapter for `ObjCMessagePrototypeResolver`.
/// The adapter fills `debugABIByImplementation` from the shapes the DWARF binder attached to
/// the admitted declarations (authoritative, non-variadic only). Tests that need a different
/// ABI inject a test-only prototype AFTER asserting what the adapter produced.
@MainActor
final class ObjCMessagePrototypeInputTests: XCTestCase {
    private let functionAddress: UInt64 = 0x1000
    private let callAddress: UInt64 = 0x1010
    private let dispatchAddress: UInt64 = 0x4000
    private let methodAddress: UInt64 = 0x2000
    private let selector = "combine:with:"
    private let imageUUID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!

    // (a) qualified batch + matching image: declaration present, success with no editable row.
    func testQualifiedDeclarationWithoutEditableRowInstalls() throws {
        let store = makeStore()
        store.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        XCTAssertTrue(store.snapshot.functionSignatureOverrides(in: .primary).isEmpty)
        let input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
        XCTAssertNotNil(input.declarationsByImplementation[methodAddress])
        XCTAssertTrue(input.signatureOverrides.isEmpty)
        XCTAssertEqual(input.debugABIByImplementation.keys.sorted(), [methodAddress])
        XCTAssertEqual(input.instructionAuthority.bytesByAddress[callAddress], [0xfc, 0x0b, 0x00, 0x94])
        XCTAssertEqual(input.instructionAuthority.directTargetByAddress[callAddress], dispatchAddress)
        XCTAssertEqual(input.instructionAuthority.callableSymbolByAddress[dispatchAddress], "_objc_msgSend")
        XCTAssertTrue(input.instructionAuthority.verifiedSelectorStubByAddress.isEmpty)
        XCTAssertEqual(input.instructionAuthority.functionRange, functionAddress ..< 0x1100)
        // The adapter's own ABI shapes install the send; nothing is injected.
        let result = ObjCMessagePrototypeResolver.resolve(input)
        let constraint = try XCTUnwrap(result.orderedConstraints.first)
        XCTAssertEqual(result.orderedConstraints.count, 1)
        XCTAssertEqual(constraint.returnType, "int64_t")
        XCTAssertEqual(constraint.selector, selector)
        guard case .installed = result.outcomes[callAddress] else {
            return XCTFail("declaration alone, with ABI shapes, must install")
        }
    }

    // (b) foreign image, different slice, stale generation: empty map, prototype-incomplete.
    func testForeignOrStaleDeclarationBatchYieldsEmptyMap() throws {
        var wrongUUID = debugImport()
        wrongUUID.matchedUUID = UUID().uuidString
        var cases: [(String, WorkspaceStore)] = []
        let foreign = makeStore()
        foreign.retainObjCSignatureDeclarations(wrongUUID, in: .primary)
        cases.append(("uuid", foreign))
        let slice = makeStore()
        slice.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        slice.snapshot.binaries[0].selectedSliceIndex = 2
        cases.append(("slice", slice))
        let stale = makeStore()
        stale.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        stale.objcDeclarationSourceGenerations[.primary] = UUID()
        cases.append(("generation", stale))
        // Control: the same fixture, unspoiled, does populate the map.
        let control = makeStore()
        control.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        XCTAssertNotNil(try XCTUnwrap(control.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
            .declarationsByImplementation[methodAddress])
        for (label, store) in cases {
            var input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary), label)
            XCTAssertTrue(input.declarationsByImplementation.isEmpty, label)
            input.debugABIByImplementation[methodAddress] = fixtureABI()
            XCTAssertEqual(ObjCMessagePrototypeResolver.resolve(input).outcomes[callAddress],
                           .abstained(.prototypeIncomplete), label)
        }
    }

    // (c) a verified selector stub populates the map; unverified stub names do not.
    func testOnlyVerifiedSelectorStubPopulatesStubMap() throws {
        let stubName = ObjCStubSelectorRecovery.symbolPrefix + selector
        let stubSection = SectionSummary(id: UUID(), name: "__TEXT,__objc_stubs", address: 0x4000,
                                         size: 0x20, fileOffset: 0x4000, isExecutable: true)
        func stub(name: String = stubName, raw: String? = nil) -> SymbolSummary {
            .init(id: UUID(), name: name, address: dispatchAddress, kind: "stub", libraryName: nil,
                  rawLinkageName: raw)
        }

        let verified = makeStore(symbols: [stub()], sections: [stubSection])
        verified.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        var input = try XCTUnwrap(verified.objcMessagePrototypeInput(for: try stubFunction(), in: .primary))
        XCTAssertEqual(input.instructionAuthority.verifiedSelectorStubByAddress, [dispatchAddress: selector])
        XCTAssertEqual(input.instructionAuthority.callableSymbolByAddress[dispatchAddress], stubName)
        input.debugABIByImplementation[methodAddress] = fixtureABI()
        let result = ObjCMessagePrototypeResolver.resolve(input)
        XCTAssertEqual(result.orderedConstraints.first?.dispatchKind, .verifiedSelectorStub)
        guard case .macIROnly = result.outcomes[callAddress] else {
            return XCTFail("verified stub must stay MacIR-only in OSR-1")
        }

        let unverified: [(String, WorkspaceStore)] = [
            ("selector not in selector table",
             makeStore(symbols: [stub(name: ObjCStubSelectorRecovery.symbolPrefix + "other:")], sections: [stubSection])),
            ("outside __objc_stubs", makeStore(symbols: [stub()], sections: [])),
            ("loader-named lookalike", makeStore(symbols: [stub(raw: stubName)], sections: [stubSection])),
            ("no symbol", makeStore(symbols: [], sections: [stubSection])),
        ]
        for (label, store) in unverified {
            store.retainObjCSignatureDeclarations(debugImport(), in: .primary)
            var input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try stubFunction(), in: .primary), label)
            XCTAssertTrue(input.instructionAuthority.verifiedSelectorStubByAddress.isEmpty, label)
            input.debugABIByImplementation[methodAddress] = fixtureABI()
            XCTAssertEqual(ObjCMessagePrototypeResolver.resolve(input).outcomes[callAddress],
                           .abstained(.notObjectiveCDispatch), label)
        }
    }

    // (d) an editable row may only restrict: disagreement abstains, agreement is the (a) success.
    func testEditableRowOnlyRestricts() throws {
        func row(first: String) -> FunctionSignatureOverride {
            .init(returnType: "int64_t", parameterList: .authoritative([
                ArgOverride(name: "self", type: "id", provenance: .debug),
                ArgOverride(name: "_cmd", type: "SEL", provenance: .debug),
                ArgOverride(name: "first", type: first, provenance: .debug),
                ArgOverride(name: "second", type: "int64_t", provenance: .debug),
            ]), variadicState: .fixed, noReturnState: .returns)
        }
        let disagreeing = makeStore()
        disagreeing.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        disagreeing.setSignature(methodAddress, row(first: "double"))
        var input = try XCTUnwrap(disagreeing.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
        XCTAssertNotNil(input.signatureOverrides[methodAddress])
        input.debugABIByImplementation[methodAddress] = fixtureABI()
        var result = ObjCMessagePrototypeResolver.resolve(input)
        XCTAssertEqual(result.outcomes[callAddress], .abstained(.prototypeIncomplete))
        XCTAssertTrue(result.orderedConstraints.isEmpty)

        let agreeing = makeStore()
        agreeing.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        agreeing.setSignature(methodAddress, row(first: "int64_t"))
        input = try XCTUnwrap(agreeing.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
        XCTAssertNotNil(input.signatureOverrides[methodAddress])
        input.debugABIByImplementation[methodAddress] = fixtureABI()
        result = ObjCMessagePrototypeResolver.resolve(input)
        XCTAssertEqual(result.orderedConstraints.count, 1)
        guard case .installed = result.outcomes[callAddress] else {
            return XCTFail("agreeing row must give the same success as (a)")
        }
    }

    // (e) a qualified declaration with no return type cannot supply a prototype.
    func testDeclarationWithoutReturnTypeIsPrototypeIncomplete() throws {
        var result = debugImport()
        result.signatureDeclarations[methodAddress]?.returnType = nil
        let store = makeStore()
        store.retainObjCSignatureDeclarations(result, in: .primary)
        var input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
        XCTAssertNil(try XCTUnwrap(input.declarationsByImplementation[methodAddress]).returnType)
        input.debugABIByImplementation[methodAddress] = fixtureABI()
        let outcome = ObjCMessagePrototypeResolver.resolve(input)
        XCTAssertEqual(outcome.outcomes[callAddress], .abstained(.prototypeIncomplete))
        XCTAssertTrue(outcome.orderedConstraints.isEmpty)
    }

    // (f) qualified variadic / non-authoritative declarations reach the resolver and keep their reason.
    func testQualifiedVariadicOrNonAuthoritativeDeclarationIsFixednessUnproven() throws {
        for variant in ["variadic", "non-authoritative"] {
            var result = debugImport()
            if variant == "variadic" {
                result.signatureDeclarations[methodAddress]?.isVariadic = true
            } else {
                result.signatureDeclarations[methodAddress]?.hasAuthoritativeParameterList = false
            }
            let store = makeStore()
            store.retainObjCSignatureDeclarations(result, in: .primary)
            var input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary), variant)
            let declaration = try XCTUnwrap(input.declarationsByImplementation[methodAddress], variant)
            XCTAssertNil(declaration.explicitObjectiveCParameters(selectorArity: 2), variant)
            input.debugABIByImplementation[methodAddress] = fixtureABI()
            let outcome = ObjCMessagePrototypeResolver.resolve(input)
            XCTAssertEqual(outcome.outcomes[callAddress], .abstained(.fixednessUnproven), variant)
            XCTAssertTrue(outcome.orderedConstraints.isEmpty, variant)
        }
    }

    // (g) an admitted authoritative declaration yields a debugABI entry with its shapes in order,
    // and the resolver installs a C24-style send with no injected ABI.
    func testAdmittedAuthoritativeDeclarationYieldsDebugABIAndInstalls() throws {
        let store = makeStore()
        store.retainObjCSignatureDeclarations(debugImport(), in: .primary)
        let input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
        let abi = try XCTUnwrap(input.debugABIByImplementation[methodAddress])
        XCTAssertEqual(abi.returnType, .init(spelling: "int64_t", shape: .s64))
        XCTAssertEqual(abi.parameters, [
            .init(spelling: "id", shape: .object), .init(spelling: "SEL", shape: .selector),
            .init(spelling: "int64_t", shape: .s64), .init(spelling: "int64_t", shape: .s64),
        ])
        let result = ObjCMessagePrototypeResolver.resolve(input)
        XCTAssertEqual(result.orderedConstraints.count, 1)
        guard case .installed = result.outcomes[callAddress] else {
            return XCTFail("adapter-produced ABI shapes must install without injection")
        }
    }

    // (h) variadic or non-authoritative declarations are admitted but get no debugABI entry.
    func testVariadicOrNonAuthoritativeDeclarationHasNoDebugABIEntry() throws {
        for variant in ["variadic", "non-authoritative"] {
            var result = debugImport()
            if variant == "variadic" {
                result.signatureDeclarations[methodAddress]?.isVariadic = true
            } else {
                result.signatureDeclarations[methodAddress]?.hasAuthoritativeParameterList = false
            }
            let store = makeStore()
            store.retainObjCSignatureDeclarations(result, in: .primary)
            let input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary), variant)
            XCTAssertNotNil(input.declarationsByImplementation[methodAddress], variant)
            XCTAssertTrue(input.debugABIByImplementation.isEmpty, variant)
            XCTAssertEqual(ObjCMessagePrototypeResolver.resolve(input).outcomes[callAddress],
                           .abstained(.fixednessUnproven), variant)
        }
    }

    // (i) a declaration batch for the wrong image yields no entry in either map.
    func testWrongImageDeclarationYieldsNoEntryInEitherMap() throws {
        var wrongUUID = debugImport()
        wrongUUID.matchedUUID = UUID().uuidString
        let store = makeStore()
        store.retainObjCSignatureDeclarations(wrongUUID, in: .primary)
        let input = try XCTUnwrap(store.objcMessagePrototypeInput(for: try plainFunction(), in: .primary))
        XCTAssertTrue(input.declarationsByImplementation.isEmpty)
        XCTAssertTrue(input.debugABIByImplementation.isEmpty)
    }

    // DWARFTypeShape maps 1:1 onto the comparison shapes.
    func testDWARFTypeShapeMapsOneToOne() {
        typealias S = ObjCMessageABIComparison.Shape
        let pairs: [(DWARFTypeShape, S)] = [
            (.s8, .s8), (.u8, .u8), (.s16, .s16), (.u16, .u16), (.s32, .s32), (.u32, .u32),
            (.s64, .s64), (.u64, .u64), (.bool, .bool), (.f32, .f32), (.f64, .f64),
            (.object, .object), (.classPointer, .classPointer), (.selector, .selector),
            (.block, .block), (.dataPointer, .dataPointer), (.void, .void),
            (.lossyEnum(.s32), .lossyEnum(.s32)), (.lossyEnum(.other), .lossyEnum(.other)),
            (.unknown, .unknown),
        ]
        XCTAssertEqual(Set(pairs.map(\.1)).count, pairs.count, "mapping must be injective")
        for (source, expected) in pairs {
            XCTAssertEqual(WorkspaceStore.abiShape(source), expected, "\(source)")
        }
    }

    // OS2-B2b: precheck + store-side outcomes for the pane.
    func testObjCCandidatePrecheckSelectsOnlyMessageSendCalls() {
        func row(_ mnemonic: String, _ operands: String, comment: String? = nil) -> InstructionRow {
            .init(address: 0x1000, bytes: "00 00 00 00", mnemonic: mnemonic, operands: operands,
                  hasBreakpoint: false, comment: comment)
        }
        XCTAssertTrue(WorkspaceStore.mayContainObjCDispatchCandidate([row("bl", "_objc_msgSend")]))
        XCTAssertTrue(WorkspaceStore.mayContainObjCDispatchCandidate([row("bl", "_objc_msgSend$combine:with:")]))
        XCTAssertTrue(WorkspaceStore.mayContainObjCDispatchCandidate([row("bl", "0x4000", comment: "_objc_msgSend")]))
        XCTAssertFalse(WorkspaceStore.mayContainObjCDispatchCandidate([row("bl", "_puts"), row("mov", "_objc_msgSend")]))
        XCTAssertFalse(WorkspaceStore.mayContainObjCDispatchCandidate([]))
    }

    func testPaneOutcomesAreEmptyWithoutCandidateAndCachedWithOne() {
        let store = makeStore()
        func input(_ rows: [InstructionRow]) -> PseudocodeRenderInput {
            .init(imageSlot: .primary, functionName: "-[Calculator caller]", startAddress: functionAddress,
                  jumpTables: [:], objcSelectors: [:], nameOverrides: [:], signatureOverrides: [:],
                  registerNameOverrides: [:], types: [], instructions: rows)
        }
        let plain = input([.init(address: functionAddress, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "",
                                 hasBreakpoint: false, comment: nil)])
        XCTAssertEqual(store.withObjCMessageOutcomes(plain), plain)
        let candidate = input([
            .init(address: callAddress, bytes: "fc 0b 00 94", mnemonic: "bl", operands: "_objc_msgSend",
                  hasBreakpoint: false, comment: nil),
            .init(address: callAddress + 4, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "",
                  hasBreakpoint: false, comment: nil),
        ])
        let first = store.objcMessageOutcomes(for: candidate)
        XCTAssertEqual(first[callAddress], .abstained(.notObjectiveCDispatch))
        XCTAssertEqual(store.objcMessageOutcomes(for: candidate), first)
    }

    // MARK: - Fixtures

    private func fixtureABI() -> ObjCMessageABIComparison.DebugPrototype {
        func type(_ spelling: String, _ shape: ObjCMessageABIComparison.Shape) -> ObjCMessageABIComparison.DebugType {
            .init(spelling: spelling, shape: shape)
        }
        return .init(returnType: type("int64_t", .s64),
                     parameters: [type("id", .object), type("SEL", .selector),
                                  type("int64_t", .s64), type("int64_t", .s64)])
    }

    private func debugImport() -> DSYMImportResult {
        .init(functions: [], signatureDeclarations: [methodAddress: .init(
            returnType: "int64_t", parameters: [
                .init(name: "self", type: "id", isArtificial: true, shape: .object),
                .init(name: "_cmd", type: "SEL", isArtificial: true, shape: .selector),
                .init(name: "first", type: "int64_t", isArtificial: false, shape: .s64),
                .init(name: "second", type: "int64_t", isArtificial: false, shape: .s64),
            ], hasAuthoritativeParameterList: true, isVariadic: false, returnShape: .s64
        )], matchedUUID: imageUUID.uuidString, dwarfURL: URL(fileURLWithPath: "/tmp/Calculator.dSYM"),
              debugArtifactSeal: .init(uuid: imageUUID, selectedMachOSHA256: String(repeating: "a", count: 64),
                                       selectedMachOByteCount: 128),
              matchedSliceArchitecture: "arm64")
    }

    private func makeStore(symbols: [SymbolSummary]? = nil, sections: [SectionSummary] = []) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.instructions = [
            .init(address: callAddress, bytes: "fc 0b 00 94", mnemonic: "bl", operands: "0x4000",
                  hasBreakpoint: false, comment: nil),
            .init(address: callAddress + 4, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "",
                  hasBreakpoint: false, comment: nil),
        ]
        analysis.symbols = symbols ?? [
            .init(id: UUID(), name: "_objc_msgSend", address: dispatchAddress, kind: "import",
                  libraryName: nil, rawLinkageName: "_objc_msgSend")
        ]
        analysis.sections = sections
        analysis.objcSelectors = [0x3000: selector]
        analysis.objcClasses = [.init(
            name: "Calculator", superclassName: nil, adoptedProtocols: [], classMethods: [],
            instanceMethods: [
                .init(selector: "caller", typeEncoding: "v16@0:8", isClassMethod: false, implementation: functionAddress),
                .init(selector: selector, typeEncoding: "q32@0:8q16q24", isClassMethod: false, implementation: methodAddress),
            ], ivars: [], properties: [])]
        let binary = BinaryImage(id: UUID(), name: "Calculator", path: "/tmp/Calculator", kind: "Mach-O",
                                 architecture: "arm64",
                                 metadata: .init(uuid: imageUUID.uuidString, platformName: "macOS",
                                                 minimumOSVersion: "27.0", sdkVersion: "27.2"),
                                 selectedSliceIndex: 1)
        return WorkspaceStore(workspaceName: "Prototype input", snapshot: .init(
            binaries: [binary], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func plainFunction() throws -> MacIRFunction {
        let evidence = try XCTUnwrap(MacIRCallSelectorEvidence(name: selector, selrefAddress: 0x3000))
        let args = try XCTUnwrap(MacIRCallArguments([
            .init(location: .gpr(index: 0, carrierWidth: 64), role: .fixed(sourcePosition: 0),
                  value: .argument(bindingID: .gpr(0))),
            .init(location: .gpr(index: 1, carrierWidth: 64), role: .fixed(sourcePosition: 1),
                  value: .symbol("\"\(selector)\""), selectorEvidence: evidence),
        ]))
        let frame = try XCTUnwrap(MacIRCallFrame(
            target: "_objc_msgSend",
            knownSignature: CallSignatureCatalog.standard.signature(for: "_objc_msgSend"),
            tailCountEvidence: .objectiveCSelectorColonCount(2),
            controlInputs: .none,
            arguments: args
        ))
        return function(frame: frame)
    }

    private func stubFunction() throws -> MacIRFunction {
        let scope = try XCTUnwrap(MacIRCallArgumentObservationScope(gprIndices: [0, 2, 3]))
        let args = try XCTUnwrap(MacIRCallArguments([
            .init(location: .gpr(index: 0, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(0))),
            .init(location: .gpr(index: 2, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(2))),
            .init(location: .gpr(index: 3, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(3))),
        ], observationScope: scope))
        let frame = try XCTUnwrap(MacIRCallFrame(
            target: ObjCStubSelectorRecovery.symbolPrefix + selector,
            knownSignature: nil,
            controlInputs: .none,
            arguments: args
        ))
        return function(frame: frame)
    }

    private func function(frame: MacIRCallFrame) -> MacIRFunction {
        let source = MacIRSourceSpan(address: callAddress, byteText: "fc 0b 00 94", mnemonic: "bl",
                                     operands: frame.target)
        var function = MacIRFunction(
            name: "-[Calculator caller]",
            startAddress: functionAddress,
            instructions: [.init(source: source, operation: .call(frame: frame, result: nil))]
        )
        function.endAddress = 0x1100
        return function
    }
}
