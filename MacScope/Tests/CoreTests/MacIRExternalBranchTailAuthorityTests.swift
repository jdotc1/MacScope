import XCTest
@testable import MacScope

// Machine bytes are retained vectors,
// except the explicitly synthetic mid-target and frame-guard counterexamples.
final class MacIRExternalBranchTailAuthorityTests: XCTestCase {
    private func row(_ address: UInt64, _ bytes: String, _ mnemonic: String,
                     _ operands: String) -> InstructionRow {
        InstructionRow(address: address, bytes: bytes, mnemonic: mnemonic,
                       operands: operands, hasBreakpoint: false, comment: nil)
    }

    func testFourRetainedLeafWrappersWithIndependentVoidContracts() {
        let vectors: [(String, UInt64, String, UInt64, String)] = [
            ("_jpeg_destroy_compress", 0xe3c, "d3 69 00 14", 0x1b588, "_jpeg_destroy"),
            ("_jpeg_abort_compress", 0xe40, "bc 69 00 14", 0x1b530, "_jpeg_abort"),
            ("_jpeg_destroy_decompress", 0x213e0, "6a e8 ff 17", 0x1b588, "_jpeg_destroy"),
            ("_jpeg_abort_decompress", 0x213e4, "53 e8 ff 17", 0x1b530, "_jpeg_abort")
        ]
        // jpeglib.h declares both wrapper and generic callee void. These are
        // independent injected contracts, not inferred from a missing X0 read.
        for (name, start, bytes, target, callee) in vectors {
            let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
                name: name, startAddress: start,
                authoritativeReturnLocation: .void, authoritativeReturnType: "void",
                authoredCallSignaturesByTarget: [callee: .init(returnType: "void")],
                knownTailCallTargets: [target: callee],
                instructions: [row(start, bytes, "b", "0x" + String(target, radix: 16))])
            XCTAssertTrue(result.instructions.contains { if case .call = $0.operation { return true }; return false })
            XCTAssertEqual(result.instructions.last?.operation, .returnValue(nil))
            XCTAssertFalse(result.refusals.contains { $0.reason == .targetOutsideFunction })
        }
    }

    func testUnknownReturnAuthorityIsNotVoid() {
        let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false).buildFunction(
            name: "_unknown_contract", startAddress: 0xe3c,
            knownTailCallTargets: [0x1b588: "_jpeg_destroy"],
            instructions: [row(0xe3c, "d3 69 00 14", "b", "0x1b588")])
        XCTAssertEqual(result.returnValue, .unknown("unresolved_return_contract"))
    }

    func testMidFunctionTargetDoesNotInheritStartIdentity() {
        // Synthetic B 0x1000 -> 0x2004; only 0x2000 is a proven start.
        let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
            name: "_mid_target", startAddress: 0x1000,
            knownTailCallTargets: [0x2000: "_callee"],
            instructions: [row(0x1000, "01 04 00 14", "b", "0x2004")])
        XCTAssertTrue(result.refusals.contains { $0.reason == .targetOutsideFunction })
        XCTAssertFalse(result.instructions.contains { if case .call = $0.operation { return true }; return false })
    }

    func testUnbalancedFrameMustRetainExternalBranchRefusal() {
        // Synthetic SUB SP,#16; B to exact known start. This expectation exposes
        // the preimage CFG gap; the postimage must honor per-site frame proof.
        let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
            name: "_frame_guard", startAddress: 0x1000,
            knownTailCallTargets: [0x2000: "_callee"],
            instructions: [row(0x1000, "ff 43 00 d1", "sub", "sp, sp, #0x10"),
                           row(0x1004, "ff 03 00 14", "b", "0x2000")])
        XCTAssertFalse(result.instructions.contains { if case .call = $0.operation { return true }; return false })
        XCTAssertTrue(result.refusals.contains { $0.reason == .targetOutsideFunction })
    }

    func testOneProvenSiteCannotMaskAnotherSiteToSameTarget() {
        let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
            name: "_same_target", startAddress: 0x1000,
            knownTailCallTargets: [0x2000: "_callee"],
            instructions: [row(0x1000, "00 04 00 14", "b", "0x2000"),
                           row(0x1004, "ff 03 00 14", "b", "0x2000")])
        XCTAssertFalse(result.refusals.contains {
            $0.reason == .targetOutsideFunction && $0.scope == .row(0x1000)
        })
        XCTAssertTrue(result.refusals.contains {
            $0.reason == .targetOutsideFunction && $0.scope == .row(0x1004)
        })
    }

    func testDuplicateAddressRowsCannotBorrowTailProof() {
        let ambiguous = [row(0x1000, "00 04 00 14", "b", "0x2000"),
                         row(0x1000, "00 08 00 14", "b", "0x3000")]
        let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
            name: "_duplicate_site", startAddress: 0x1000,
            knownTailCallTargets: [0x2000: "_first", 0x3000: "_second"],
            instructions: ambiguous)
        XCTAssertFalse(result.instructions.contains { if case .call = $0.operation { return true }; return false })
        XCTAssertTrue(result.refusals.contains { $0.reason == .targetOutsideFunction })
        XCTAssertTrue(MacIRBuilder.provenTailCalls(rows: ambiguous, entry: 0x1000,
            knownTargets: [0x2000: "_first", 0x3000: "_second"], recoveredSwitches: []).isEmpty)
    }

    private func declaredTailSnapshot(
        rows: [InstructionRow], start: UInt64 = 0x1000, end: UInt64? = nil,
        target: UInt64 = 0x2000, sourceName: String = "_declared_source",
        targetName: String = "_declared_callee", callerType: String? = "void",
        calleeType: String? = "void", extras: [FunctionSummary] = []
    ) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.functions = [
            FunctionSummary(id: UUID(), name: sourceName, startAddress: start,
                endAddress: end ?? (rows.last!.address + 4), confidence: 1),
            FunctionSummary(id: UUID(), name: targetName, startAddress: target,
                endAddress: target + 4, confidence: 1)
        ] + extras
        analysis.instructions = rows
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "fixture",
            path: "/fixture/declared-tail", kind: "executable", architecture: "arm64", slot: .primary),
            analysis: analysis)
        if let callerType {
            snapshot.addressOverrides[.primary(start)] = AddressOverride(
                signature: .init(returnType: callerType))
        }
        if let calleeType {
            snapshot.addressOverrides[.primary(target)] = AddressOverride(
                signature: .init(returnType: calleeType))
        }
        return snapshot
    }

    private func buildDeclaredTail(_ input: PseudocodeRenderInput) -> MacIRFunction {
        PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides,
            authoredCallSignaturesByTarget: input.authoredCallSignaturesByTarget,
            knownTailCallTargets: input.knownTailCallTargets,
            instructions: input.instructions)
    }

    private func assertDeclaredLeafTail(name: String, start: UInt64, bytes: String,
                                        target: UInt64, callee: String) {
        // Fresh inputs in each mode: an SSA handoff is not reused as legacy authority.
        for enabled in [false, true] {
            MacIRConfiguration.$ssaOverride.withValue(enabled) {
                MacIRConfiguration.$returnContractOverride.withValue(false) {
                    let snapshot = declaredTailSnapshot(
                        rows: [row(start, bytes, "b", "0x" + String(target, radix: 16))],
                        start: start, target: target, sourceName: name, targetName: callee)
                    let input = snapshot.pseudocodeRenderInput(selectedAddress: start, in: .primary)
                    XCTAssertEqual(input.knownTailCallTargets[target], enabled ? callee : nil)
                    let function = buildDeclaredTail(input)
                    XCTAssertEqual(function.instructions.contains {
                        if case .call = $0.operation { return true }; return false
                    }, enabled)
                    if enabled {
                        XCTAssertEqual(function.instructions.last?.operation, .returnValue(nil))
                        XCTAssertFalse(function.refusals.contains { $0.reason == .targetOutsideFunction })
                    }
                }
            }
        }
    }

    func testDeclaredVoidCompressionWrappersUseSSAOnlyIdentityHandoff() {
        assertDeclaredLeafTail(name: "_jpeg_destroy_compress", start: 0xe3c,
            bytes: "d3 69 00 14", target: 0x1b588, callee: "_jpeg_destroy")
        assertDeclaredLeafTail(name: "_jpeg_abort_compress", start: 0xe40,
            bytes: "bc 69 00 14", target: 0x1b530, callee: "_jpeg_abort")
    }

    func testDeclaredVoidDecompressionWrappersUseSSAOnlyIdentityHandoff() {
        assertDeclaredLeafTail(name: "_jpeg_destroy_decompress", start: 0x213e0,
            bytes: "6a e8 ff 17", target: 0x1b588, callee: "_jpeg_destroy")
        assertDeclaredLeafTail(name: "_jpeg_abort_decompress", start: 0x213e4,
            bytes: "53 e8 ff 17", target: 0x1b530, callee: "_jpeg_abort")
    }

    func testVoidTailHandoffDoesNotInventEitherContractOrUniqueIdentity() {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) {
                let rows = [row(0x1000, "00 04 00 14", "b", "0x2000")]
                let duplicateTarget = FunctionSummary(id: UUID(), name: "_other",
                    startAddress: 0x2000, endAddress: 0x2004, confidence: 1)
                let duplicateName = FunctionSummary(id: UUID(), name: "_declared_callee",
                    startAddress: 0x3000, endAddress: 0x3004, confidence: 1)
                let duplicateSource = FunctionSummary(id: UUID(), name: "_other_source",
                    startAddress: 0x1000, endAddress: 0x1004, confidence: 1)
                // The callee is no longer required to carry an authored type.
                let cases = [
                    declaredTailSnapshot(rows: rows, callerType: nil),
                    declaredTailSnapshot(rows: rows, callerType: "uint32_t"),
                    declaredTailSnapshot(rows: rows, calleeType: "uint32_t"),
                    declaredTailSnapshot(rows: rows, targetName: ""),
                    declaredTailSnapshot(rows: rows, targetName: " _padded "),
                    declaredTailSnapshot(rows: rows, targetName: "_first,_second"),
                    declaredTailSnapshot(rows: rows, targetName: "x8"),
                    declaredTailSnapshot(rows: rows, extras: [duplicateTarget]),
                    declaredTailSnapshot(rows: rows, extras: [duplicateName]),
                    declaredTailSnapshot(rows: rows, extras: [duplicateSource])
                ]
                for snapshot in cases {
                    let input = snapshot.pseudocodeRenderInput(selectedAddress: 0x1000, in: .primary)
                    XCTAssertEqual(input.instructions.map(\.address), [0x1000])
                    XCTAssertTrue(input.knownTailCallTargets.isEmpty)
                    let function = buildDeclaredTail(input)
                    XCTAssertFalse(function.instructions.contains {
                        if case .call = $0.operation { return true }; return false
                    })
                    XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction })
                }
            }
        }
    }

    func testVoidTailHandoffRetainsPerSiteFrameAndExactTargetChecks() {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) {
                let cases = [
                    [row(0x1000, "ff 43 00 d1", "sub", "sp, sp, #0x10"),
                     row(0x1004, "ff 03 00 14", "b", "0x2000")],
                    [row(0x1000, "01 04 00 14", "b", "0x2004")]
                ]
                for rows in cases {
                    let input = declaredTailSnapshot(rows: rows)
                        .pseudocodeRenderInput(selectedAddress: 0x1000, in: .primary)
                    XCTAssertEqual(input.knownTailCallTargets[0x2000], "_declared_callee")
                    let function = buildDeclaredTail(input)
                    XCTAssertFalse(function.instructions.contains {
                        if case .call = $0.operation { return true }; return false
                    })
                    XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction })
                }
            }
        }
    }

    func testVoidTailHandoffRejectsIntraFunctionTargetBeyondRetainedRows() {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) {
                // Only the entry B is retained, but the declared owner includes 0x2000.
                // A second discovered start does not override that ownership interval.
                let snapshot = declaredTailSnapshot(
                    rows: [row(0x1000, "00 04 00 14", "b", "0x2000")], end: 0x2004)
                let input = snapshot.pseudocodeRenderInput(selectedAddress: 0x1000, in: .primary)
                XCTAssertTrue(input.knownTailCallTargets.isEmpty)
                let function = buildDeclaredTail(input)
                XCTAssertFalse(function.instructions.contains {
                    if case .call = $0.operation { return true }; return false
                })
                XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction })
            }
        }
    }

    func testVoidTailHandoffKeepsIndirectTransferBarrier() {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) {
                for (bytes, mnemonic) in [("00 01 1f d6", "br"), ("00 01 3f d6", "blr")] {
                    let snapshot = declaredTailSnapshot(rows: [
                        row(0x1000, bytes, mnemonic, "x8"),
                        row(0x1004, "ff 03 00 14", "b", "0x2000")])
                    let input = snapshot.pseudocodeRenderInput(selectedAddress: 0x1000, in: .primary)
                    XCTAssertTrue(input.knownTailCallTargets.isEmpty)
                }
            }
        }
    }

    func testVoidTailHandoffDoesNotReclassifySourceJumpTableAuthority() {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) {
                let rows = [row(0x1000, "00 04 00 14", "b", "0x2000")]
                var snapshot = declaredTailSnapshot(rows: rows)
                // Even conflicting source-row switch authority prevents this fallback.
                snapshot.jumpTables = [0x1000: [0x2000]]
                XCTAssertTrue(snapshot.pseudocodeRenderInput(selectedAddress: 0x1000,
                    in: .primary).knownTailCallTargets.isEmpty)
                // An unrelated image-wide table must not block this direct leaf.
                snapshot.jumpTables = [0x3000: [0x4000]]
                XCTAssertEqual(snapshot.pseudocodeRenderInput(selectedAddress: 0x1000,
                    in: .primary).knownTailCallTargets[0x2000], "_declared_callee")
            }
        }
    }

    func testVoidTailHandoffRejectsUnknownDeclaredSourceExtent() {
        MacIRConfiguration.$ssaOverride.withValue(true) {
            MacIRConfiguration.$returnContractOverride.withValue(false) {
                for end in [UInt64(0x1000), UInt64(0x0ffc)] {
                    let snapshot = declaredTailSnapshot(
                        rows: [row(0x1000, "00 04 00 14", "b", "0x2000")], end: end)
                    let source = snapshot.analysis(in: .primary)!.functions[0]
                    // The exact-ID API explicitly retains the entry row for a degenerate range.
                    guard let input = snapshot.pseudocodeRenderInput(exactFunctionID: source.id,
                        in: .primary) else { XCTFail("missing exact source fixture"); continue }
                    XCTAssertEqual(input.instructions.map(\.address), [0x1000])
                    XCTAssertTrue(input.knownTailCallTargets.isEmpty)
                    let function = buildDeclaredTail(input)
                    XCTAssertTrue(function.refusals.contains { $0.reason == .targetOutsideFunction })
                    XCTAssertFalse(function.instructions.contains {
                        if case .call = $0.operation { return true }; return false
                    })
                }
            }
        }
    }

    // Synthetic A64 words are fixed vectors, not assembled/decoded at runtime.
    // Each assertion covers legacy/SSA and return-contract OFF/ON independently.
    private func assertPathVector(_ rows: [InstructionRow], terminal: UInt64,
                                  certified: Bool, admitted: Bool? = nil, file: StaticString = #filePath, line: UInt = #line) {
        let admission = admitted ?? certified
        let proofRows = rows.map { MacIRTailCallProof.Instruction(address: $0.address,
            mnemonic: $0.mnemonic, operands: $0.operands) }
        let decision = MacIRTailCallProof.certifyRetainedFramePaths(proofRows,
            at: rows.firstIndex { $0.address == terminal }!, entry: 0x1000,
            knownFunctionStarts: [0x2000], recoveredSwitches: [])
        XCTAssertEqual(decision.certified, certified, decision.reason, file: file, line: line)
        for ssa in [false, true] {
            for contracts in [false, true] {
                MacIRConfiguration.$returnContractOverride.withValue(contracts) {
                    let tails = MacIRBuilder.provenTailCalls(rows: rows, entry: 0x1000,
                        knownTargets: [0x2000: "_path_target"], recoveredSwitches: [],
                        pathCompleteEnabled: ssa && contracts)
                    XCTAssertEqual(tails[terminal] != nil, admission && ssa && contracts,
                                   file: file, line: line)
                    let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: ssa).buildFunction(
                        name: "_path_source", startAddress: 0x1000,
                        knownTailCallTargets: [0x2000: "_path_target"], instructions: rows)
                    XCTAssertEqual(result.instructions.contains { instruction in
                        guard instruction.source.address == terminal else { return false }
                        if case .call = instruction.operation { return true }
                        return false
                    }, admission && ssa && contracts, file: file, line: line)
                    if admission && ssa && contracts {
                        XCTAssertTrue(result.instructions.contains {
                            $0.operation == .returnValue(.unknown("unresolved_return_contract"))
                        }, file: file, line: line)
                    }
                }
            }
        }
    }

    private func diamond(_ middle: InstructionRow? = nil) -> [InstructionRow] {
        [row(0x1000, "60 00 00 b4", "cbz", "x0, 0x100c"),
         middle ?? row(0x1004, "1f 20 03 d5", "nop", ""),
         row(0x1008, "02 00 00 14", "b", "0x1010"),
         row(0x100c, "1f 20 03 d5", "nop", ""),
         row(0x1010, "fc 03 00 14", "b", "0x2000")]
    }

    func testPathCompleteFramelessDiamondPreservesUnknownReturn() {
        assertPathVector(diamond(), terminal: 0x1010, certified: true)
    }

    func testPathCompleteFramelessConditionalJoin() {
        assertPathVector([row(0x1000, "40 00 00 b4", "cbz", "x0, 0x1008"),
            row(0x1004, "1f 20 03 d5", "nop", ""),
            row(0x1008, "fe 03 00 14", "b", "0x2000")], terminal: 0x1008, certified: true)
    }

    func testPathCompleteEqualStateBackedgeConvergesWithoutAnalyzabilityClaim() {
        assertPathVector([row(0x1000, "60 00 00 b4", "cbz", "x0, 0x100c"),
            row(0x1004, "1f 20 03 d5", "nop", ""),
            row(0x1008, "fe ff ff 17", "b", "0x1000"),
            row(0x100c, "fd 03 00 14", "b", "0x2000")], terminal: 0x100c, certified: true)
    }

    private func restoredFrame(_ mutation: InstructionRow? = nil) -> [InstructionRow] {
        [row(0x1000, "fd 7b bf a9", "stp", "x29, x30, [sp, #-0x10]!"),
         row(0x1004, "fd 03 00 91", "mov", "x29, sp"),
         row(0x1008, "fe 03 1f aa", "mov", "x30, xzr"),
         row(0x100c, "60 00 00 b4", "cbz", "x0, 0x1018"),
         mutation ?? row(0x1010, "1f 20 03 d5", "nop", ""),
         row(0x1014, "02 00 00 14", "b", "0x101c"),
         row(0x1018, "1f 20 03 d5", "nop", ""),
         row(0x101c, "fd 7b c1 a8", "ldp", "x29, x30, [sp], #0x10"),
         row(0x1020, "f8 03 00 14", "b", "0x2000")]
    }

    func testPathCompleteSavedLRDiamondRestoresExactEntryValue() {
        assertPathVector(restoredFrame(), terminal: 0x1020, certified: true)
    }

    func testPathCompleteFPAliasLoadRestoresExactLR() {
        var rows = restoredFrame()
        rows[7] = row(0x101c, "be 07 40 f9", "ldr", "x30, [x29, #0x8]")
        rows[8] = row(0x1020, "ff 43 00 91", "add", "sp, sp, #0x10")
        rows.append(row(0x1024, "f7 03 00 14", "b", "0x2000"))
        assertPathVector(rows, terminal: 0x1024, certified: true)
        let facts = MacIRTailCallProof.certifyRetainedFramePaths(rows.map {
            .init(address: $0.address, mnemonic: $0.mnemonic, operands: $0.operands)
        }, at: 9, entry: 0x1000, knownFunctionStarts: [0x2000], recoveredSwitches: [])
        XCTAssertFalse(facts.entryFPPreserved) // LR restoration does not establish entry-FP preservation.
    }

    func testPathCompleteCopiedLRTokenSurvivesDiamond() {
        var rows = diamond()
        rows.insert(row(0x0ffc, "e9 03 1e aa", "mov", "x9, x30"), at: 0)
        // Relocate the fixed vector by four bytes; branch displacements stay fixed.
        rows = rows.map { row($0.address + 4, $0.bytes, $0.mnemonic,
            $0.operands == "x0, 0x100c" ? "x0, 0x1010" : $0.operands == "0x1010" ? "0x1014" : $0.operands) }
        rows[2] = row(0x1008, "fe 03 09 aa", "mov", "x30, x9")
        rows[5] = row(0x1014, "fb 03 00 14", "b", "0x2000")
        assertPathVector(rows, terminal: 0x1014, certified: true)
    }

    func testPathCompleteOneBadSPPathVetoesGoodSibling() {
        assertPathVector(diamond(row(0x1004, "ff 43 00 d1", "sub", "sp, sp, #0x10")),
                         terminal: 0x1010, certified: false)
    }

    func testPathCompleteOneBadLRPathVetoesGoodSibling() {
        assertPathVector(diamond(row(0x1004, "fe 03 1f aa", "mov", "x30, xzr")),
                         terminal: 0x1010, certified: false)
    }

    func testPathCompletePartialSavedLRStoreVetoesRestore() {
        assertPathVector(restoredFrame(row(0x1010, "bf 23 00 39", "strb", "wzr, [x29, #0x8]")),
                         terminal: 0x1020, certified: false)
    }

    func testPathCompleteUnknownAliasStoreVetoesSavedSlot() {
        assertPathVector(restoredFrame(row(0x1010, "1f 00 00 f9", "str", "xzr, [x0]")),
                         terminal: 0x1020, certified: false)
    }

    func testPathCompleteEscapedStackAcrossCallRemainsRefused() {
        var rows = restoredFrame(row(0x1010, "e0 03 00 91", "mov", "x0, sp"))
        rows[6] = row(0x1018, "00 01 3f d6", "blr", "x8")
        assertPathVector(rows, terminal: 0x1020, certified: false)
    }

    func testPathCompleteChangingLoopStateRefuses() {
        assertPathVector([row(0x1000, "60 00 00 b4", "cbz", "x0, 0x100c"),
            row(0x1004, "ff 43 00 d1", "sub", "sp, sp, #0x10"),
            row(0x1008, "fe ff ff 17", "b", "0x1000"),
            row(0x100c, "fd 03 00 14", "b", "0x2000")], terminal: 0x100c, certified: false)
    }

    func testPathCompleteUnreachableIncomingPredecessorRefuses() {
        assertPathVector([row(0x1000, "02 00 00 14", "b", "0x1008"),
            row(0x1004, "01 00 00 14", "b", "0x1008"),
            row(0x1008, "fe 03 00 14", "b", "0x2000")], terminal: 0x1008, certified: false)
    }

    func testPathCompleteOpaqueTargetCannotBorrowExactEntryAuthority() {
        var rows = diamond()
        rows[1] = row(0x1004, "00 01 1f d6", "br", "x8")
        assertPathVector(rows, terminal: 0x1010, certified: false)
        let intra = [row(0x1000, "40 00 00 b4", "cbz", "x0, 0x1008"),
            row(0x1004, "1f 20 03 d5", "nop", ""),
            row(0x1008, "fe ff ff 17", "b", "0x1000")]
        for enabled in [false, true] {
            XCTAssertTrue(MacIRBuilder.provenTailCalls(rows: intra, entry: 0x1000,
                knownTargets: [0x1000: "_same_entry"], recoveredSwitches: [],
                pathCompleteEnabled: enabled).isEmpty)
        }
    }

    private func indexedLoadSidecar(width: Int = 64, writeback: Bool = false) -> InstructionRow {
        var instruction = row(0x1004, "2a 79 68 f8", "ldr", "x10, [x9, x8, lsl #3]")
        instruction.structuredOperands = .init(coverage: .complete, opcodeClass: "ldr",
            operands: [.register(.init(index: 10, width: 64)),
                .memory(.init(base: .init(index: 9, width: 64), index: .init(index: 8, width: 64),
                    modifier: .init(.lsl, amount: 3), writeback: writeback))],
            presentation: .init(mnemonic: "ldr"),
            semantics: .init(memoryAccessWidth: width, memoryAccess: .read))
        return instruction
    }

    func testPathCompleteIndexedSidecarAgreesWithoutChangingDefaultGate() {
        assertPathVector(diamond(indexedLoadSidecar()), terminal: 0x1010, certified: true)
    }

    func testPathCompleteSidecarWidthMismatchRefusesAdmission() {
        assertPathVector(diamond(indexedLoadSidecar(width: 32)), terminal: 0x1010,
                         certified: true, admitted: false)
    }

    func testPathCompleteSidecarHiddenWritebackRefusesAdmission() {
        assertPathVector(diamond(indexedLoadSidecar(writeback: true)), terminal: 0x1010,
                         certified: true, admitted: false)
    }

    func testPathCompleteDoesNotChangeExistingNumericLeafOrOrdinaryBL() {
        let leaf = [row(0x1000, "00 04 00 14", "b", "0x2000")]
        let ordinary = [row(0x1000, "00 04 00 94", "bl", "0x2000"),
                        row(0x1004, "c0 03 5f d6", "ret", "")]
        for ssa in [false, true] {
            for contracts in [false, true] {
                MacIRConfiguration.$returnContractOverride.withValue(contracts) {
                    let tails = MacIRBuilder.provenTailCalls(rows: leaf, entry: 0x1000,
                        knownTargets: [0x2000: ""], recoveredSwitches: [],
                        pathCompleteEnabled: ssa && contracts)
                    XCTAssertEqual(tails[0x1000]?.callOperands, "0x2000")
                    let result = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: ssa).buildFunction(
                        name: "_ordinary", startAddress: 0x1000,
                        authoritativeReturnLocation: .void, authoritativeReturnType: "void",
                        knownTailCallTargets: [0x2000: ""], instructions: ordinary)
                    XCTAssertEqual(result.instructions.filter { if case .call = $0.operation { return true }; return false }.count, 1)
                    XCTAssertFalse(result.refusals.contains { $0.reason == .targetOutsideFunction })
                }
            }
        }
    }
}

extension MacIRExternalBranchTailAuthorityTests {
    private func tailV2Function(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
        .init(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
    }

    private func tailV2Stub(_ address: UInt64 = 0x2100, size: UInt32 = 12,
                            name: String = "_free") -> IndirectSymbolSummary {
        .init(id: UUID(), kind: MachOIndirectSymbolKind.symbolStub.rawValue,
            sourceSection: "__TEXT,__stubs", address: address, entrySize: size,
            tableIndex: 0, rawSymbolIndex: 0, symbolIndex: 0, symbolName: name,
            libraryOrdinal: nil, libraryName: nil, isLocal: false, isAbsolute: false)
    }

    private func tailV2Snapshot(_ functions: [FunctionSummary], rows: [InstructionRow],
                                stubs: [IndirectSymbolSummary] = [],
                                callerStart: UInt64? = 0x1000) -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        analysis.functions = functions
        analysis.instructions = rows
        analysis.indirectSymbols = stubs
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "fixture",
            path: "/fixture/tail-v2", kind: "executable", architecture: "arm64", slot: .primary),
            analysis: analysis)
        if let callerStart {
            snapshot.addressOverrides[.primary(callerStart)] =
                AddressOverride(signature: .init(returnType: "void"))
        }
        return snapshot
    }

    private func tailV2Modes(_ body: (Bool, Bool) throws -> Void) rethrows {
        for ssa in [false, true] {
            for contracts in [false, true] {
                try MacIRConfiguration.$ssaOverride.withValue(ssa) {
                    try MacIRConfiguration.$returnContractOverride.withValue(contracts) {
                        try body(ssa, contracts)
                    }
                }
            }
        }
    }

    private func tailV2Inputs(_ snapshot: WorkspaceSnapshot,
                               source: FunctionSummary) throws -> [PseudocodeRenderInput] {
        let selected = snapshot.pseudocodeRenderInput(selectedAddress: source.startAddress, in: .primary)
        let exact = try XCTUnwrap(snapshot.pseudocodeRenderInput(exactFunctionID: source.id, in: .primary))
        XCTAssertEqual(selected.knownTailCallTargets, exact.knownTailCallTargets)
        XCTAssertEqual(selected.instructions.map(\.address), exact.instructions.map(\.address))
        return [selected, exact]
    }

    private func assertTailV2DegenerateRoute(exact: Bool) throws {
        // AnalysisModels.swift:1433-1438 and AnalysisModels+WorkspaceSnapshot.swift:2127-2134.
        let extents: [(UInt64, UInt64)] = [
            (0x1000, 0x1000), (0x1000, 0x0ffc),
            (UInt64.max, UInt64.max), (UInt64.max, 0)
        ]
        try tailV2Modes { ssa, contracts in
            for (start, end) in extents {
                for includeStart in [false, true] {
                    let source = tailV2Function("_degenerate", start, end)
                    let other = tailV2Function("_other", 0x2000, 0x2008)
                    let target = tailV2Function("_target", 0x3000, 0x3004)
                    // Deliberately unsorted input, with rows outside the singleton.
                    var rows = [row(0x2004, "1f 20 03 d5", "nop", ""),
                                row(0x1004, "1f 20 03 d5", "nop", "")]
                    if includeStart {
                        rows.append(start == UInt64.max
                            ? row(start, "1f 20 03 d5", "nop", "")
                            : row(start, "00 08 00 14", "b", "0x3000"))
                    }
                    let snapshot = tailV2Snapshot([source, other, target], rows: rows, callerStart: start)
                    let input: PseudocodeRenderInput
                    if exact {
                        input = try XCTUnwrap(snapshot.pseudocodeRenderInput(exactFunctionID: source.id,
                            in: .primary))
                    } else {
                        input = snapshot.pseudocodeRenderInput(selectedAddress: start, in: .primary)
                    }
                    XCTAssertEqual(input.startAddress, start)
                    XCTAssertEqual(input.instructions.map(\.address), includeStart ? [start] : [])
                    XCTAssertTrue(input.knownTailCallTargets.isEmpty)
                    XCTAssertTrue(MacIRBuilder.provenTailCalls(rows: input.instructions, entry: start,
                        knownTargets: input.knownTailCallTargets, recoveredSwitches: [],
                        pathCompleteEnabled: ssa && contracts).isEmpty)
                    // AnalysisModels+WorkspaceSnapshot.swift:1733-1738 selects the OTHER real range.
                    let selectedOther = snapshot.pseudocodeRenderInput(selectedAddress: 0x2004, in: .primary)
                    let exactOther = try XCTUnwrap(snapshot.pseudocodeRenderInput(exactFunctionID: other.id,
                        in: .primary))
                    XCTAssertEqual(selectedOther.startAddress, other.startAddress)
                    XCTAssertEqual(selectedOther.instructions.map(\.address), [0x2004])
                    XCTAssertEqual(selectedOther.instructions.map(\.address), exactOther.instructions.map(\.address))
                    XCTAssertEqual(selectedOther.knownTailCallTargets, exactOther.knownTailCallTargets)
                }
            }
        }
    }

    func testSelectedAddressDegenerateSourceRowsAndAuthority() throws {
        try assertTailV2DegenerateRoute(exact: false)
    }

    func testExactIDDegenerateSourceRowsAndAuthority() throws {
        try assertTailV2DegenerateRoute(exact: true)
    }

    func testImportCatalogReturnTypeAloneDiscriminatesBothMerges() throws {
        // AnalysisModels+WorkspaceSnapshot.swift:2318-2320; CallSignatureCatalog.swift:181-197.
        let source = tailV2Function("_source", 0x1000, 0x1004)
        let ordinary = tailV2Function("_ordinary", 0x3000, 0x3004)
        let baseline = tailV2Stub()
        try tailV2Modes { ssa, contracts in
            for (name, returnType) in [("_free", "void"), ("_malloc", "void *"),
                                       ("_memcpy", "void *"), ("_strlen", "size_t")] {
                var symbol = baseline
                symbol.symbolName = name // Only the name changes; UUID and every other field stay fixed.
                XCTAssertEqual(CallSignatureCatalog.standard.signature(for: name)?.returnType, returnType)
                let snapshot = tailV2Snapshot([source, ordinary],
                    rows: [row(0x1000, "40 04 00 14", "b", "0x2100")], stubs: [symbol])
                for input in try tailV2Inputs(snapshot, source: source) {
                    let admitted = ssa && returnType == "void"
                    XCTAssertEqual(input.knownTailCallTargets[0x2100], admitted ? name : nil)
                    XCTAssertEqual(input.knownTailCallTargets[0x3000],
                        ssa || contracts ? ordinary.name : nil)
                    let proof = MacIRBuilder.provenTailCalls(rows: input.instructions, entry: 0x1000,
                        knownTargets: input.knownTailCallTargets, recoveredSwitches: [],
                        pathCompleteEnabled: ssa && contracts)
                    XCTAssertEqual(proof[0x1000]?.callOperands, admitted ? name : nil)
                }
            }
        }
    }

    func testThirdDeclarationOverlapPolicyIsSymmetricAndHalfOpen() throws {
        // extension of AnalysisModels+WorkspaceSnapshot.swift:2201,2259,2290-2293.
        let source = tailV2Function("_source", 0x1000, 0x1100)
        let target = tailV2Function("_target", 0x2000, 0x2010)
        let cases: [(UInt64, UInt64, Bool)] = [
            (0x1ff0, 0x2000, true), (0x2010, 0x2020, true),
            (0x1ffc, 0x2004, false), (0x2004, 0x2008, false),
            (0x1ff0, 0x2020, false), (0x2000, 0x2010, false),
            (0x2000, 0x2000, false), (0x2004, 0x2004, true),
            (0x2008, 0x2004, true), (UInt64.max - 7, 4, true)
        ]
        try tailV2Modes { ssa, contracts in
            for (start, end, allowed) in cases {
                let third = tailV2Function("_third", start, end)
                for declarations in [[source, target, third], [third, target, source]] {
                    let snapshot = tailV2Snapshot(declarations,
                        rows: [row(0x1000, "00 04 00 14", "b", "0x2000")])
                    for input in try tailV2Inputs(snapshot, source: source) {
                        XCTAssertEqual(input.knownTailCallTargets[target.startAddress],
                            allowed && (ssa || contracts) ? target.name : nil)
                        if !allowed && end > start {
                            XCTAssertNil(input.knownTailCallTargets[third.startAddress])
                        }
                    }
                }
            }
            // A long enclosing interval must veto BOTH non-overlapping children.
            let enclosing = tailV2Function("_enclosing", 0x1ff0, 0x2040)
            let later = tailV2Function("_later", 0x2020, 0x2030)
            let snapshot = tailV2Snapshot([later, target, enclosing, source],
                rows: [row(0x1000, "00 04 00 14", "b", "0x2000")])
            for input in try tailV2Inputs(snapshot, source: source) {
                for start in [UInt64(0x1ff0), 0x2000, 0x2020] {
                    XCTAssertNil(input.knownTailCallTargets[start])
                }
            }
        }
    }

    func testWholeImportExtentAgainstSourceAndThirdDeclarations() throws {
        // AnalysisModels+WorkspaceSnapshot.swift:2322-2324 misses a stub beginning before an owner.
        let source = tailV2Function("_source", 0x1000, 0x1004)
        let third = tailV2Function("_third", 0x2000, 0x2008)
        let empty = tailV2Function("_empty", 0x2000, 0x2000)
        let reversed = tailV2Function("_reversed", 0x2000, 0x1ffc)
        let high = tailV2Function("_high", UInt64.max - 7, UInt64.max)
        let wrapped = tailV2Function("_wrapped", UInt64.max - 7, 4)
        let cases: [(UInt64, UInt32, [FunctionSummary], Bool)] = [
            (0x0ffc, 12, [], false), (0x0ffc, 4, [], true),
            (0x1004, 12, [], true), (0x1ffc, 8, [third], false),
            (0x1ffc, 4, [third], true), (0x2004, 4, [third], false),
            (0x2008, 4, [third], true), (0x1ffc, 12, [empty], true),
            (0x1ffc, 12, [reversed], true), (0x2000, 4, [empty], false),
            (0x2000, 4, [reversed], false), (0x2100, 0, [], false),
            (UInt64.max - 15, 8, [high], true),
            (UInt64.max - 15, 12, [high], false),
            (UInt64.max - 15, 12, [wrapped], true),
            (UInt64.max - 3, 8, [], false)
        ]
        try tailV2Modes { ssa, _ in
            for (address, size, extras, allowed) in cases {
                let symbol = tailV2Stub(address, size: size)
                XCTAssertEqual(StubCallSymbolicator.linkageSlotClass(for: symbol), .executableImportStub)
                let snapshot = tailV2Snapshot([source] + extras,
                    rows: [row(0x1000, "1f 20 03 d5", "nop", "")], stubs: [symbol])
                for input in try tailV2Inputs(snapshot, source: source) {
                    XCTAssertEqual(input.knownTailCallTargets[address], ssa && allowed ? "_free" : nil)
                }
            }
        }
    }

    func testTouchingImportAdmitsProofButCoveringImportDoesNot() throws {
        // The first address is outside; only entrySize distinguishes touch from overlap.
        let source = tailV2Function("_source", 0x1000, 0x1004)
        try tailV2Modes { ssa, contracts in
            for size in [UInt32(4), UInt32(12)] {
                let snapshot = tailV2Snapshot([source],
                    rows: [row(0x1000, "ff ff ff 17", "b", "0x0ffc")],
                    stubs: [tailV2Stub(0x0ffc, size: size)])
                for input in try tailV2Inputs(snapshot, source: source) {
                    let admitted = ssa && size == 4
                    XCTAssertEqual(input.knownTailCallTargets[0x0ffc], admitted ? "_free" : nil)
                    let proof = MacIRBuilder.provenTailCalls(rows: input.instructions, entry: 0x1000,
                        knownTargets: input.knownTailCallTargets, recoveredSwitches: [],
                        pathCompleteEnabled: ssa && contracts)
                    XCTAssertEqual(proof[0x1000]?.callOperands, admitted ? "_free" : nil)
                }
            }
        }
    }

    func testD2KeepsFunctionIdentityAtAnImportAddressOnlyWithContracts() throws {
        // D2 retains B8 and TC8 unchanged; supplied source decisions:
        // AnalysisModels+WorkspaceSnapshot.swift:2197-2203,2262,2311.
        let source = tailV2Function("_source", 0x1000, 0x1004)
        let function = tailV2Function("_function", 0x0ffc, 0x1000)
        try tailV2Modes { _, contracts in
            for size in [UInt32(4), UInt32(12)] {
                let snapshot = tailV2Snapshot([source, function],
                    rows: [row(0x1000, "ff ff ff 17", "b", "0x0ffc")],
                    stubs: [tailV2Stub(0x0ffc, size: size)])
                for input in try tailV2Inputs(snapshot, source: source) {
                    XCTAssertEqual(input.knownTailCallTargets[0x0ffc], contracts ? "_function" : nil)
                }
            }
        }
    }

    func testImportNameAndIndependentIdentityGuardsRemainDistinct() throws {
        // AnalysisModels+WorkspaceSnapshot.swift:2305-2317 counts stub names, not function names.
        let source = tailV2Function("_source", 0x1000, 0x1004)
        let sameName = tailV2Function("_free", 0x3000, 0x3004)
        let valid = tailV2Stub()
        var pointer = valid; pointer.sourceSection = "__DATA_CONST,__got"
        var objc = valid; objc.sourceSection = "__TEXT,__objc_stubs"
        var wrongKind = valid; wrongKind.kind = "pointer"
        var local = valid; local.isLocal = true
        var absolute = valid; absolute.isAbsolute = true
        var nameless = valid; nameless.symbolName = nil
        var emptyName = valid; emptyName.symbolName = ""
        var malformed = valid; malformed.symbolName = "_a,_b"
        var register = valid; register.symbolName = "x8"
        var duplicateName = valid; duplicateName.address = 0x2200
        var overlap = valid; overlap.address = 0x2104; overlap.symbolName = "_bzero"
        let invalid: [[IndirectSymbolSummary]] = [
            [pointer], [objc], [wrongKind], [local], [absolute], [nameless],
            [emptyName], [malformed], [register], [valid, valid],
            [valid, duplicateName], [valid, overlap]
        ]
        try tailV2Modes { ssa, contracts in
            for symbols in [[valid]] + invalid {
                let snapshot = tailV2Snapshot([source, sameName],
                    rows: [row(0x1000, "40 04 00 14", "b", "0x2100")], stubs: symbols)
                for input in try tailV2Inputs(snapshot, source: source) {
                    let validStub = symbols.count == 1 && symbols[0].sourceSection == valid.sourceSection
                        && symbols[0].kind == valid.kind && !symbols[0].isLocal && !symbols[0].isAbsolute
                        && symbols[0].symbolName == valid.symbolName
                    XCTAssertEqual(input.knownTailCallTargets[0x2100], ssa && validStub ? "_free" : nil)
                    XCTAssertEqual(input.knownTailCallTargets[0x3000], ssa || contracts ? "_free" : nil)
                    XCTAssertNil(input.knownTailCallTargets[0x2200])
                }
            }
        }
    }

    func testContractsOnKeepsNoCallerVoidAndIndirectSourceIdentities() throws {
        // AnalysisModels+WorkspaceSnapshot.swift:2194-2203 is independent of the stub-merge gates.
        let source = tailV2Function("_source", 0x1000, 0x1008)
        let target = tailV2Function("_target", 0x2000, 0x2004)
        try tailV2Modes { _, contracts in
            let snapshot = tailV2Snapshot([source, target],
                rows: [row(0x1000, "00 04 00 14", "b", "0x2000"),
                       row(0x1004, "20 00 1f d6", "br", "x1")], callerStart: nil)
            for input in try tailV2Inputs(snapshot, source: source) {
                XCTAssertEqual(input.knownTailCallTargets[0x2000], contracts ? target.name : nil)
                XCTAssertNil(input.signatureOverrides[0x1000])
            }
        }
    }

    func testIncompatibleImportNameDoesNotEraseSeparateFunctionIdentity() throws {
        // AnalysisModels+WorkspaceSnapshot.swift:2265-2266 uses authored, not catalog, returns.
        let source = tailV2Function("_source", 0x1000, 0x1004)
        try tailV2Modes { ssa, contracts in
            for name in ["_malloc", "_memcpy", "_strlen"] {
                let function = tailV2Function(name, 0x3000, 0x3004)
                let snapshot = tailV2Snapshot([source, function],
                    rows: [row(0x1000, "40 04 00 14", "b", "0x2100")],
                    stubs: [tailV2Stub(name: name)])
                for input in try tailV2Inputs(snapshot, source: source) {
                    XCTAssertNil(input.knownTailCallTargets[0x2100])
                    XCTAssertEqual(input.knownTailCallTargets[0x3000], ssa || contracts ? name : nil)
                }
            }
        }
    }

    func testContractsOnMalformedNameCannotRetainTailCFGAuthority() throws {
        // MacIRBuilder.swift:253-255 records proof before :429-460 attempts call conversion.
        // MacIRCFG.swift:363-365,594 must not turn a rejected synthetic BL into a tail exit.
        try MacIRConfiguration.$ssaOverride.withValue(false) {
            try MacIRConfiguration.$returnContractOverride.withValue(true) {
                let source = tailV2Function("_source", 0x1000, 0x1004)
                for name in ["x8", "_a,_b", " _padded ", "", "_valid"] {
                    let target = tailV2Function(name, 0x2000, 0x2004)
                    let snapshot = tailV2Snapshot([source, target],
                        rows: [row(0x1000, "00 04 00 14", "b", "0x2000")])
                    let allowed = name.isEmpty || name == "_valid"
                    for input in try tailV2Inputs(snapshot, source: source) {
                        XCTAssertEqual(input.knownTailCallTargets[0x2000], allowed ? name : nil)
                        let function = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: false)
                            .buildFunction(name: input.functionName, startAddress: input.startAddress,
                                authoritativeReturnLocation: .void, authoritativeReturnType: "void",
                                knownTailCallTargets: input.knownTailCallTargets, instructions: input.instructions)
                        XCTAssertEqual(function.instructions.contains {
                            if case .call = $0.operation { return true }; return false
                        }, allowed)
                        XCTAssertEqual(function.refusals.contains { $0.reason == .targetOutsideFunction }, !allowed)
                        if !allowed {
                            let cfg = try XCTUnwrap(function.cfg)
                            XCTAssertFalse(cfg.blocks.flatMap(\.successors).contains { $0.kind == .tail })
                        }
                        if name.isEmpty {
                            let proof = MacIRBuilder.provenTailCalls(rows: input.instructions, entry: 0x1000,
                                knownTargets: input.knownTailCallTargets, recoveredSwitches: [])
                            XCTAssertEqual(proof[0x1000]?.callOperands, "0x2000")
                        }
                    }
                }
            }
        }
    }

    func testDeclaredFunctionExtentVetoesOverlappingTailTargets() throws {
        func summary(_ name: String, _ start: UInt64, _ end: UInt64) -> FunctionSummary {
            .init(id: UUID(), name: name, startAddress: start, endAddress: end, confidence: 1)
        }
        let source = summary("_source", 0x1000, 0x2004)
        let interior = summary("_interior", 0x2000, 0x2004)
        let overlapsFromBefore = summary("_overlap", 0x0ff0, 0x1008)
        let disjoint = summary("_disjoint", 0x3000, 0x3004)
        var analysis = ImageAnalysis()
        analysis.functions = [source, interior, overlapsFromBefore, disjoint]
        analysis.instructions = [row(0x1000, "00 04 00 14", "b", "0x2000")]
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: BinaryImage(id: UUID(), name: "fixture", path: "/fixture/boundary",
            kind: "executable", architecture: "arm64", slot: .primary), analysis: analysis)
        snapshot.addressOverrides[.primary(source.startAddress)] = AddressOverride(signature: .init(returnType: "void"))
        for enabled in [false, true] {
            try MacIRConfiguration.$ssaOverride.withValue(true) {
                try MacIRConfiguration.$returnContractOverride.withValue(enabled) {
                    let input = try XCTUnwrap(snapshot.pseudocodeRenderInput(exactFunctionID: source.id, in: .primary))
                    XCTAssertNil(input.knownTailCallTargets[0x2000])
                    XCTAssertNil(input.knownTailCallTargets[0x0ff0])
                    XCTAssertEqual(input.knownTailCallTargets[0x3000], "_disjoint")
                }
            }
        }
    }
}
