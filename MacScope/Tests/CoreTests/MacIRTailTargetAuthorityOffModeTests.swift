import XCTest
@testable import MacScope

final class MacIRTailTargetAuthorityOffModeTests: XCTestCase {
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

    private func assertAdmitted(_ snapshot: WorkspaceSnapshot, target: UInt64, name: String,
                                file: StaticString = #filePath, line: UInt = #line) {
        let handoff = input(snapshot)
        XCTAssertEqual(handoff.knownTailCallTargets, [target: name], file: file, line: line)
        let function = build(handoff)
        XCTAssertTrue(function.instructions.contains {
            if case .call = $0.operation { return true }; return false
        }, file: file, line: line)
        XCTAssertTrue(function.instructions.contains {
            if case let .call(frame, _) = $0.operation { return frame.target == name }; return false
        }, file: file, line: line)
        XCTAssertEqual(function.instructions.last?.operation, .returnValue(nil), file: file, line: line)
        XCTAssertFalse(function.refusals.contains { $0.reason == .targetOutsideFunction }, file: file, line: line)
    }

    private func assertRefused(_ snapshot: WorkspaceSnapshot,
                              file: StaticString = #filePath, line: UInt = #line) {
        let handoff = input(snapshot)
        XCTAssertTrue(handoff.knownTailCallTargets.isEmpty, file: file, line: line)
        let function = build(handoff)
        XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction }, file: file, line: line)
        XCTAssertFalse(function.instructions.contains {
            if case .call = $0.operation { return true }; return false
        }, file: file, line: line)
    }

    private func assertUnknownCalleeResultIsDiscarded(_ snapshot: WorkspaceSnapshot,
                                                     file: StaticString = #filePath, line: UInt = #line) {
        let function = build(input(snapshot))
        XCTAssertTrue(function.instructions.contains {
            if case let .call(frame, result) = $0.operation {
                return frame.knownSignature == nil && result != nil
            }
            return false
        }, file: file, line: line)
        XCTAssertEqual(function.instructions.last?.operation, .returnValue(nil), file: file, line: line)
    }

    func testTC1UndeclaredFunctionEntryAdmits() {
        offMode {
            let snapshot = declaredTailSnapshot(rows: [row(0x1000, "00 04 00 14", "b", "0x2000")],
                calleeType: nil)
            assertAdmitted(snapshot, target: 0x2000, name: "_declared_callee")
            assertUnknownCalleeResultIsDiscarded(snapshot)
        }
    }

    func testTC2DeclaredVoidFunctionEntryAdmits() {
        offMode {
            assertAdmitted(declaredTailSnapshot(rows: [row(0x1000, "00 04 00 14", "b", "0x2000")]),
                target: 0x2000, name: "_declared_callee")
        }
    }

    func testTC3CatalogVoidStubAdmits() {
        offMode {
            assertAdmitted(declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                indirectSymbols: [stub()], includeCallee: false), target: 0x2100, name: "_free")
        }
    }

    func testTC4UncataloguedStubAdmits() {
        offMode {
            let snapshot = declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                indirectSymbols: [stub("_mscope_uncatalogued_stub")], includeCallee: false)
            assertAdmitted(snapshot, target: 0x2100, name: "_mscope_uncatalogued_stub")
            assertUnknownCalleeResultIsDiscarded(snapshot)
        }
    }

    func testTC5CatalogNonVoidStubsRefuse() {
        offMode {
            for name in ["_memcpy", "_malloc"] {
                assertRefused(declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                    indirectSymbols: [stub(name)], includeCallee: false))
            }
        }
    }

    func testTC6NonEntryAndUnknownTargetsRefuseWithoutErasingOtherIdentities() {
        offMode {
            let snapshots: [(UInt64, WorkspaceSnapshot, [UInt64: String])] = [
                (0x2004, declaredTailSnapshot(
                    rows: [row(0x1000, "01 04 00 14", "b", "0x2004")]),
                    [0x2000: "_declared_callee"]),
                (0x2102, declaredTailSnapshot(
                    rows: [row(0x1000, "", "b", "0x2102")],
                    indirectSymbols: [stub()], includeCallee: false), [0x2100: "_free"]),
                (0x9000, declaredTailSnapshot(
                    rows: [row(0x1000, "00 20 00 14", "b", "0x9000")],
                    includeCallee: false), [:])
            ]
            // 0x2102 is deliberately unaligned: operands exercise exact-address authority.
            for (invalidTarget, snapshot, validIdentities) in snapshots {
                let handoff = input(snapshot)
                XCTAssertNil(handoff.knownTailCallTargets[invalidTarget])
                XCTAssertEqual(handoff.knownTailCallTargets, validIdentities)
                let function = build(handoff)
                XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction })
                XCTAssertFalse(function.instructions.contains {
                    if case .call = $0.operation { return true }; return false
                })
            }
        }
    }

    func testTC8FunctionStubCollisionVetoesBothContributions() {
        offMode {
            let snapshot = declaredTailSnapshot(
                rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                target: 0x2100, targetName: "_free", indirectSymbols: [stub()])
            XCTAssertNil(input(snapshot).knownTailCallTargets[0x2100])
            assertRefused(snapshot)
        }
    }

    func testDataPointerNameDoesNotDuplicateExecutableStubIdentity() {
        offMode {
            assertAdmitted(declaredTailSnapshot(
                rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                indirectSymbols: [stub(), stub(address: 0x2200, section: "__DATA_CONST,__got", kind: "pointer")],
                includeCallee: false), target: 0x2100, name: "_free")
        }
    }

    func testTC7DataMalformedAndAmbiguousStubRowsRefuse() {
        offMode {
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
                assertRefused(declaredTailSnapshot(rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                    indirectSymbols: symbols, includeCallee: false))
            }
        }
    }

    func testTC8FunctionIdentityAndCallerGuardsRefuse() {
        offMode {
            let rows = [row(0x1000, "00 04 00 14", "b", "0x2000")]
            let duplicateName = FunctionSummary(id: UUID(), name: "_declared_callee",
                startAddress: 0x3000, endAddress: 0x3004, confidence: 1)
            let duplicateStart = FunctionSummary(id: UUID(), name: "_other",
                startAddress: 0x2000, endAddress: 0x2004, confidence: 1)
            let duplicateSource = FunctionSummary(id: UUID(), name: "_other_source",
                startAddress: 0x1000, endAddress: 0x1004, confidence: 1)
            for snapshot in [
                declaredTailSnapshot(rows: rows, calleeType: nil, extras: [duplicateName]),
                declaredTailSnapshot(rows: rows, calleeType: nil, extras: [duplicateStart]),
                declaredTailSnapshot(rows: rows, extras: [duplicateSource]),
                declaredTailSnapshot(rows: rows, calleeType: "uint32_t"),
                declaredTailSnapshot(rows: rows, callerType: nil),
                declaredTailSnapshot(rows: rows, callerType: "uint32_t"),
                declaredTailSnapshot(rows: [row(0x1000, "00 02 1f d6", "br", "x16"),
                    row(0x1004, "ff 03 00 14", "b", "0x2000")])
            ] { assertRefused(snapshot) }
        }
    }
}
