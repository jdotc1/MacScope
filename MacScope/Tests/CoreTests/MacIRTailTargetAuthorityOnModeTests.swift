import XCTest
@testable import MacScope

// Test definitions only.
final class MacIRTailTargetAuthorityOnModeTests: XCTestCase {
    private func row(_ address: UInt64, _ bytes: String, _ mnemonic: String,
                     _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: bytes, mnemonic: mnemonic,
                       operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func offMode(_ body: () -> Void) {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) { body() }
        }
    }

    private func declaredTailSnapshot(
        rows: [InstructionRow], start: UInt64 = 0x1000, end: UInt64? = nil,
        target: UInt64 = 0x2000, sourceName: String = "_declared_source",
        targetName: String = "_declared_callee", callerType: String? = "void",
        calleeType: String? = "void", extras: [FunctionSummary] = [],
        indirectSymbols: [IndirectSymbolSummary] = [], includeCallee: Bool = true
    ) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.functions = [FunctionSummary(id: UUID(), name: sourceName, startAddress: start,
            endAddress: end ?? (rows.last!.address + 4), confidence: 1)]
        if includeCallee {
            analysis.functions.append(FunctionSummary(id: UUID(), name: targetName,
                startAddress: target, endAddress: target + 4, confidence: 1))
        }
        analysis.functions += extras
        analysis.instructions = rows
        analysis.indirectSymbols = indirectSymbols
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "fixture",
            path: "/fixture/declared-tail", kind: "executable", architecture: "arm64", slot: .primary),
            analysis: analysis)
        if let callerType {
            snapshot.addressOverrides[.primary(start)] = AddressOverride(
                signature: .init(returnType: callerType))
        }
        if let calleeType, includeCallee {
            snapshot.addressOverrides[.primary(target)] = AddressOverride(
                signature: .init(returnType: calleeType))
        }
        return snapshot
    }

    private func stub(_ name: String? = "_free", address: UInt64 = 0x2100,
                      section: String = "__TEXT,__stubs", kind: String = MachOIndirectSymbolKind.symbolStub.rawValue,
                      local: Bool = false, absolute: Bool = false, size: UInt32 = 12) -> IndirectSymbolSummary {
        IndirectSymbolSummary(id: UUID(), kind: kind, sourceSection: section,
            address: address, entrySize: size, tableIndex: 0, rawSymbolIndex: 0,
            symbolIndex: 0, symbolName: name, libraryOrdinal: nil, libraryName: nil,
            isLocal: local, isAbsolute: absolute)
    }

    private func input(_ snapshot: WorkspaceSnapshot) -> PseudocodeRenderInput {
        snapshot.pseudocodeRenderInput(selectedAddress: 0x1000, in: .primary)
    }

    private func build(_ input: PseudocodeRenderInput) -> MacIRFunction {
        PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides,
            authoredCallSignaturesByTarget: input.authoredCallSignaturesByTarget,
            knownTailCallTargets: input.knownTailCallTargets, instructions: input.instructions)
    }

    private func onMode(_ body: () -> Void) {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(true) { body() }
        }
    }

    private func stubSnapshot(_ symbols: [IndirectSymbolSummary], callerType: String? = "void") -> WorkspaceSnapshot {
        declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
            callerType: callerType, indirectSymbols: symbols, includeCallee: false)
    }

    private func assertAdmitted(_ snapshot: WorkspaceSnapshot, name: String,
                                premise: String, file: StaticString = #filePath, line: UInt = #line) {
        let handoff = input(snapshot)
        XCTAssertEqual(handoff.knownTailCallTargets[0x2100], name, premise, file: file, line: line)
        let function = build(handoff)
        XCTAssertTrue(function.instructions.contains {
            if case let .call(frame, _) = $0.operation { return frame.target == name }; return false
        }, premise, file: file, line: line)
        XCTAssertEqual(function.instructions.last?.operation, .returnValue(nil), premise, file: file, line: line)
        XCTAssertFalse(function.refusals.contains { $0.reason == .targetOutsideFunction }, premise, file: file, line: line)
    }

    private func assertRefused(_ snapshot: WorkspaceSnapshot, premise: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        let handoff = input(snapshot)
        XCTAssertNil(handoff.knownTailCallTargets[0x2100], premise, file: file, line: line)
        let function = build(handoff)
        XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction }, premise, file: file, line: line)
        XCTAssertFalse(function.instructions.contains {
            if case .call = $0.operation { return true }; return false
        }, premise, file: file, line: line)
    }

    func testB1CatalogVoidStubAdmits() {
        onMode { assertAdmitted(stubSnapshot([stub()]), name: "_free", premise: "B1 WS:2095 catalog void") }
    }

    func testB2UncataloguedStubDiscardsResult() {
        onMode {
            let snapshot = stubSnapshot([stub("_mscope_uncatalogued_stub")])
            let premise = "B2 WS:2095 absent catalog signature; WS:2022 caller void"
            assertAdmitted(snapshot, name: "_mscope_uncatalogued_stub", premise: premise)
            let function = build(input(snapshot))
            XCTAssertTrue(function.instructions.contains {
                if case let .call(frame, result) = $0.operation {
                    return frame.target == "_mscope_uncatalogued_stub" && frame.knownSignature == nil && result != nil
                }
                return false
            }, premise)
            XCTAssertEqual(function.instructions.last?.operation, .returnValue(nil), premise)
        }
    }

    func testB3CatalogNonVoidStubsRefuse() {
        onMode {
            for name in ["_memcpy", "_malloc"] {
                assertRefused(stubSnapshot([stub(name)]), premise: "B3 WS:2095 refuses " + name)
            }
        }
    }

    func testB4CallerNotDeclaredVoidRefuses() {
        onMode {
            let callerTypes: [String?] = [nil, "uint32_t"]
            for callerType in callerTypes {
                assertRefused(stubSnapshot([stub()], callerType: callerType), premise: "B4 WS:2022 declaration required")
            }
        }
    }

    func testB5RegisterBranchRefuses() {
        onMode {
            assertRefused(declaredTailSnapshot(rows: [row(0x1000, "00 02 1f d6", "br", "x16"),
                row(0x1004, "3f 04 00 14", "b", "0x2100")], indirectSymbols: [stub()], includeCallee: false),
                premise: "B5 WS:2023 br guard")
        }
    }

    func testB6IndirectCallDoesNotAuthorizeStubTail() {
        onMode {
            let premise = "B6 WS:2023 blr guard; MB:1676-1734 ordinary call retained"
            let handoff = input(declaredTailSnapshot(rows: [row(0x1000, "00 01 3f d6", "blr", "x8"),
                row(0x1004, "3f 04 00 14", "b", "0x2100")], indirectSymbols: [stub()], includeCallee: false))
            XCTAssertNil(handoff.knownTailCallTargets[0x2100], premise)
            let function = build(handoff)
            XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction }, premise)
            // The ordinary indirect call at 0x1000 is (*x8), not a leaked stub tail.
            XCTAssertTrue(function.instructions.contains {
                if case let .call(frame, result) = $0.operation {
                    return $0.source.address == 0x1000 && frame.target == "(*x8)"
                        && frame.knownSignature == nil && result != nil
                }
                return false
            }, premise)
            XCTAssertFalse(function.instructions.contains {
                if case let .call(frame, _) = $0.operation { return frame.target == "_free" }
                return false
            }, premise)
            let stubResults: [MacIRValue] = function.instructions.compactMap { instruction in
                if case let .call(frame, result) = instruction.operation, frame.target == "_free" { return result }
                return nil
            }
            XCTAssertFalse(function.instructions.contains {
                if case let .returnValue(value) = $0.operation, let value { return stubResults.contains(value) }
                return false
            }, premise)
        }
    }

    func testB7MalformedAndAmbiguousStubRowsRefuse() {
        onMode {
            let invalid: [[IndirectSymbolSummary]] = [
                [stub(section: "__DATA_CONST,__got", kind: "pointer")],
                [stub(section: "__DATA,__auth_got")],
                [stub(section: "__DATA,__la_symbol_ptr")],
                [stub(section: "__DATA,__nl_symbol_ptr")],
                [stub(section: "__TEXT,__objc_stubs")], [stub(kind: "pointer")],
                [stub(local: true)], [stub(absolute: true)], [stub("")], [stub(nil)],
                [stub(" _free ")], [stub("_first,_second")], [stub("x8")],
                [stub(), stub("_bzero")], [stub(), stub(address: 0x2200)],
                [stub(), stub("_bzero", address: 0x2104)],
                [stub(size: 0)], [stub(address: UInt64.max - 3)]
            ]
            for symbols in invalid {
                assertRefused(stubSnapshot(symbols), premise: "B7 WS:2075-2110 malformed or ambiguous stub")
            }
        }
    }

    func testB8FunctionStubCollisionKeepsFunctionEntry() {
        onMode {
            let handoff = input(declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                target: 0x2100, targetName: "_free", indirectSymbols: [stub()]))
            XCTAssertEqual(handoff.knownTailCallTargets[0x2100], "_free", "B8 WS:1998 function identity; WS:2087 helper exclusion")
            XCTAssertFalse(build(handoff).refusals.contains { $0.reason == .targetOutsideFunction }, "B8 WS:1998 function route preserved")
        }
    }

    func testB9FunctionTailReturnTypesUnchanged() {
        onMode {
            for calleeType in ["void", "uint32_t"] {
                let handoff = input(declaredTailSnapshot(rows: [row(0x1000, "00 04 00 14", "b", "0x2000")],
                    calleeType: calleeType))
                XCTAssertEqual(handoff.knownTailCallTargets[0x2000], "_declared_callee", "B9 WS:1998 no return-type filter")
            }
        }
    }

    func testB10DataPointerDoesNotContribute() {
        onMode {
            let snapshot = stubSnapshot([stub(), stub(address: 0x2200, section: "__DATA_CONST,__got", kind: "pointer")])
            assertAdmitted(snapshot, name: "_free", premise: "B10 WS:2088 executable linkage only")
            XCTAssertNil(input(snapshot).knownTailCallTargets[0x2200], "B10 WS:2088 data pointer excluded")
        }
    }

    func testB11OffModeUnaffected() {
        offMode {
            let snapshot = stubSnapshot([stub()])
            assertAdmitted(snapshot, name: "_free", premise: "B11 WS:2053-2057 OFF merge unchanged")
            XCTAssertEqual(input(snapshot).knownTailCallTargets, [0x2100: "_free"], "B11 WS:2057 OFF map")
        }
    }
}
