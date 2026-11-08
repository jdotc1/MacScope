import Foundation
import XCTest
@testable import MacScope

/// Source-authored expectations at 072419b9d plus the void-only mixed-call gate.
/// Population metadata only: 118 indirect sites, 82 error-exit chains,
/// 36 other chains and 18 used-result sites. No census is a test input (SC12).
@MainActor
final class VoidSlotCallReasonTests: XCTestCase {
    private let start: UInt64 = 0x1000
    private let header = """
    typedef int boolean;
    typedef unsigned long size_t;
    typedef struct jpeg_common_struct *j_common_ptr;
    struct jpeg_error_mgr { void (*error_exit)(j_common_ptr cinfo); };
    struct jpeg_memory_mgr {
        void *(*alloc_small)(j_common_ptr cinfo, int pool_id, size_t sizeofobject);
    };
    struct jpeg_progress_mgr {
        void (*progress_monitor)(j_common_ptr cinfo);
        long pass_counter; long pass_limit; int completed_passes; int total_passes;
    };
    struct jpeg_common_struct {
        struct jpeg_error_mgr *err; struct jpeg_memory_mgr *mem;
        struct jpeg_progress_mgr *progress; void *client_data;
        boolean is_decompressor; int global_state;
    };
    struct jpeg_compress_struct {
        struct jpeg_error_mgr *err; struct jpeg_memory_mgr *mem;
        struct jpeg_progress_mgr *progress; void *client_data;
        boolean is_decompressor; int global_state;
    };
    """
    private var baseline: [(String, String)] {
        [("mov", "x19, x0"), ("ldr", "x9, [x19]"), ("ldr", "x8, [x9]"),
         ("mov", "x0, x19"), ("blr", "x8"), ("ret", "")]
    }
    private let baselineWords: [UInt32] = [
        0xaa0003f3, 0xf9400269, 0xf9400128, 0xaa1303e0, 0xd63f0100, 0xd65f03c0
    ]
    private struct Value {
        let report: SlotTypedPrototypeBinding.Report
        let generic: MacIRFunction
        let function: MacIRFunction
        let text: String
        let genericText: String
    }

    // SC1 Pre = Post: one typed void call, one proof, one argument, no result.
    func testSC1BaselineTypedVoid() throws {
        let value = try production(baselineWords)
        try typed(value, at: start + 16, arity: 1, hasResult: false)
        XCTAssertEqual(value.report.callProofRows.count, 1)
        XCTAssertEqual(calls(in: value.text).count, 1)
    }

    // SC2 Pre: both untyped. Post: only the first site's void contract survives.
    func testSC2MixedUntypedBLRSiblingRetainsOnlyVoid() throws {
        var operations = baseline
        operations.insert(contentsOf: [("ldr", "x8, [x19, #16]"), ("blr", "x8")], at: 5)
        let value = try decider(operations)
        XCTAssertEqual(Set(value.report.callContracts.keys), [start + 16])
        XCTAssertEqual(value.report.callProofRows.count, 1)
        try typed(value, at: start + 16, arity: 1, hasResult: false)
        try untyped(value, at: start + 24)
        refusal(value, at: start + 24, reason: "unproved_or_unsupported_indirect_contract")
        XCTAssertFalse(value.report.refusals.contains { $0.reason == "mixed_untyped_indirect_footprint" && $0.address == start + 16 })
        let rendered = calls(in: value.text)
        XCTAssertEqual(rendered.count, 2)
        XCTAssertEqual(rendered.map(\.hasResult), [false, true])
        // This is exactly the predicate of both WSS isolated reads: still false.
        XCTAssertFalse([start + 16, start + 24].allSatisfy { value.report.callContracts[$0] != nil })
    }

    // SC3 Pre = Post: a forward BR sibling retains whole-function refusal.
    func testSC3ForwardBRSiblingRefusesWholeFunction() throws {
        var operations = baseline
        operations.removeLast()
        operations += [("ldr", "x8, [x19, #16]"), ("br", "x8")]
        let value = try decider(operations)
        XCTAssertTrue(value.report.callContracts.isEmpty)
        XCTAssertTrue(value.report.callProofRows.isEmpty)
        refusal(value, at: start + 16, reason: "mixed_untyped_indirect_footprint")
        try untyped(value, at: start + 16)
        XCTAssertEqual(value.function.instructions, value.generic.instructions)
    }

    // SC4 Pre = Post: no declaration means no imported H1 root.
    func testSC4NoHeaderRootRemainsUntyped() throws {
        let value = try decider(baseline, declared: false)
        XCTAssertTrue(value.report.callContracts.isEmpty)
        XCTAssertTrue(value.report.callProofRows.isEmpty)
        XCTAssertTrue(value.report.refusals.contains { $0.reason == "no_imported_H1_parameter_root" })
        try untyped(value, at: start + 16)
        XCTAssertEqual(value.function.instructions, value.generic.instructions)
    }

    // SC5 Pre = Post: CBZ drops the non-root chased x9 before the field load.
    func testSC5BarrierDropsChasedPointer() throws {
        let value = try decider([
            ("mov", "x19, x0"), ("ldr", "x9, [x19]"), ("cbz", "x1, 0x1018"),
            ("ldr", "x8, [x9]"), ("mov", "x0, x19"), ("blr", "x8"), ("ret", "")])
        XCTAssertTrue(value.report.callContracts.isEmpty)
        XCTAssertTrue(value.report.callProofRows.isEmpty)
        refusal(value, at: start + 20, reason: "unproved_or_unsupported_indirect_contract")
        try untyped(value, at: start + 20)
    }

    // SC6 Pre = Post: the root copy survives both the barrier and the join.
    func testSC6JoinKeepsRootCopy() throws {
        let value = try decider([
            ("mov", "x19, x0"), ("cbz", "x1, 0x100c"), ("mov", "x2, x1"),
            ("ldr", "x9, [x19]"), ("ldr", "x8, [x9]"), ("mov", "x0, x19"),
            ("blr", "x8"), ("ret", "")])
        XCTAssertEqual(value.report.callProofRows.count, 1)
        try typed(value, at: start + 24, arity: 1, hasResult: false)
    }

    // SC7 Pre = Post: the loop leader is after the chase, before the field load.
    func testSC7LeaderResetDoesNotSeedChasedPointer() throws {
        let value = try decider([
            ("stp", "x19, x20, [sp, #-32]!"), ("str", "x30, [sp, #16]"),
            ("mov", "x19, x0"), ("ldr", "x21, [x19]"), ("b", "0x1014"),
            ("ldr", "x8, [x21]"), ("mov", "x0, x19"), ("blr", "x8"),
            ("cbnz", "w1, 0x1014"), ("ldr", "x30, [sp, #16]"),
            ("ldp", "x19, x20, [sp], #32"), ("ret", "")])
        XCTAssertEqual(value.report.census["invariant_carrier_functions"], 1)
        XCTAssertFalse(value.report.refusals.contains { $0.reason == "unsupported_nonforward_or_incomplete_cfg" })
        XCTAssertTrue(value.report.callContracts.isEmpty)
        XCTAssertTrue(value.report.callProofRows.isEmpty)
        refusal(value, at: start + 28, reason: "unproved_or_unsupported_indirect_contract")
        try untyped(value, at: start + 28)
    }

    // SC8 Pre = Post: the row string, not decoder alias canonicalization, is tested.
    func testSC8UnmodeledWriteClearsFacts() throws {
        var operations = baseline
        operations.insert(("sbfiz", "x10, x11, #1, #8"), at: 2)
        let value = try decider(operations)
        XCTAssertTrue(value.report.callContracts.isEmpty)
        XCTAssertTrue(value.report.callProofRows.isEmpty)
        refusal(value, at: start + 8, reason: "unknown_physical_write_footprint")
        refusal(value, at: start + 20, reason: "unproved_or_unsupported_indirect_contract")
        try untyped(value, at: start + 20)
    }

    // SC9 Pre = Post: alloc_small is typed, non-void and its result is read.
    func testSC9UsedNonVoidResultAndRenderingUnchanged() throws {
        let words: [UInt32] = [0xaa0003f3, 0xf9400669, 0xf9400128,
            0xaa1303e0, 0xd63f0100, 0xaa0003e1, 0xd65f03c0]
        let value = try production(words, pinnedNonVoidAt: start + 16)
        try typed(value, at: start + 16, arity: 3, hasResult: true)
        XCTAssertEqual(value.report.callContracts[start + 16]?.returnType, "void *")
        XCTAssertEqual(value.report.callProofRows.count, 1)
        let rendered = try XCTUnwrap(calls(in: value.text).first)
        XCTAssertTrue(rendered.hasResult)
        XCTAssertEqual(rendered.arguments.count, 3)
        // production pins the contract to the imported alloc_small field and
        // compares the final IR/text to an independently supplied singleton
        // contract, the pre-patch isolated-call behavior (not this report).
        XCTAssertFalse(value.report.refusals.contains { $0.reason == "mixed_untyped_indirect_footprint" })
    }

    // SC9b Pre: all untyped. Post: void only; non-void still has a result.
    func testSC9bMixedGateDoesNotRetainNonVoidContract() throws {
        let words: [UInt32] = [
            0xaa0003f3, 0xf9400669, 0xf9400128, 0xaa1303e0, 0xd63f0100,
            0xaa0003e1, 0xf9400269, 0xf9400128, 0xaa1303e0, 0xd63f0100,
            0xf9400a68, 0xd63f0100, 0xd65f03c0]
        let value = try production(words)
        XCTAssertEqual(Set(value.report.callContracts.keys), [start + 36])
        XCTAssertEqual(value.report.callProofRows.count, 1)
        try untyped(value, at: start + 16)
        try typed(value, at: start + 36, arity: 1, hasResult: false)
        try untyped(value, at: start + 44)
        refusal(value, at: start + 16, reason: "mixed_untyped_indirect_footprint")
        refusal(value, at: start + 44, reason: "unproved_or_unsupported_indirect_contract")
        XCTAssertEqual(calls(in: value.text).map(\.hasResult), [true, false, true])
        let genericCall = try call(value.generic, at: start + 16)
        let retainedCall = try call(value.function, at: start + 16)
        XCTAssertEqual(retainedCall.1 != nil, genericCall.1 != nil)
        XCTAssertNil(retainedCall.0.typedIndirectSignature)
    }

    // SC10 Pre = Post: a following x0 read does not invent a void result.
    func testSC10VoidResultReadDoesNotChangeContract() throws {
        var words = baselineWords
        words.insert(0xaa0003e1, at: 5) // MOV x1,x0, after the void BLR.
        let value = try production(words)
        try typed(value, at: start + 16, arity: 1, hasResult: false)
        XCTAssertEqual(value.report.callProofRows.count, 1)
        XCTAssertFalse(try XCTUnwrap(calls(in: value.text).first).hasResult)
    }

    private func decider(_ operations: [(String, String)], declared: Bool = true) throws -> Value {
        let parsed = CTypeHeaderParser.parse(header + "\nvoid dispatch(struct jpeg_compress_struct *cinfo, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6);")
        let signature = try XCTUnwrap(parsed.prototypes.first { $0.name == "dispatch" }?.signature)
        let rows = operations.enumerated().map {
            InstructionRow(address: start + UInt64($0.offset * 4), bytes: "00 00 00 00",
                mnemonic: $0.element.0, operands: $0.element.1, hasBreakpoint: false, comment: nil)
        }
        let overrides = declared ? [start: signature] : [:]
        let generic = PseudocodePrinter().buildFunction(functionName: "dispatch", startAddress: start,
            signatureOverrides: overrides, types: parsed.types, instructions: rows)
        let report = SlotTypedPrototypeBinding.analyze(builtFunctions: [generic], originalInstructions: rows,
            functionStarts: [start], importedPrototypes: overrides, effectiveSignatures: overrides,
            types: parsed.types, headerLayoutDefinitions: parsed.types, includeSlotTails: false)
        let function = PseudocodePrinter().buildFunction(functionName: "dispatch", startAddress: start,
            signatureOverrides: overrides, slotCallContracts: report.callContracts,
            types: parsed.types, instructions: rows)
        return Value(report: report, generic: generic, function: function,
            text: PseudocodePrinter().print(function: function, types: parsed.types).text,
            genericText: PseudocodePrinter().print(function: generic, types: parsed.types).text)
    }

    // Production render route copied locally: existing ICA helpers are private.
    private func production(_ words: [UInt32], pinnedNonVoidAt address: UInt64? = nil) throws -> Value {
        let image = S1RecoveryMachOFixture.make(bodies: [start: ("dispatch", words)], exported: ["dispatch"])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("void-slot-\(UUID().uuidString).dylib")
        try image.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        var snapshot = try AnalysisEngine().analyze(url: url)
        let analysis = try XCTUnwrap(snapshot.analysis(in: .primary))
        XCTAssertEqual(analysis.imageBytes, image)
        let expectedBytes = words.flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) } }
        let decoded = ARM64Decoder().decode(Data(expectedBytes), baseAddress: start, maxInstructionCount: words.count)
        XCTAssertEqual(decoded.count, words.count)
        for instruction in decoded {
            let row = try XCTUnwrap(analysis.instructions.first { $0.address == instruction.address })
            XCTAssertEqual(row.bytes, instruction.byteText)
            XCTAssertEqual(row.mnemonic, instruction.mnemonic)
            XCTAssertEqual(row.operands, instruction.operands)
        }
        if words == baselineWords {
            XCTAssertEqual(decoded.map(\.mnemonic), baseline.map { $0.0 })
            for (instruction, expected) in zip(decoded, baseline) {
                let normalize: (String) -> String = { $0.lowercased().filter { !$0.isWhitespace } }
                XCTAssertEqual(normalize(instruction.operands), normalize(expected.1))
            }
        }
        let declaration = header + "\nvoid dispatch(struct jpeg_compress_struct *cinfo, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6);"
#if os(Linux)
        let imported = HeaderImportCore.prepare(source: declaration, typeDefinitions: snapshot.typeDefinitions,
            exports: analysis.exports, functions: analysis.functions, importedPrototypes: snapshot.importedPrototypes, slot: .primary)
        snapshot.typeDefinitions = imported.types
        snapshot.importedPrototypes = imported.prototypes
        snapshot.recordHeaderImportEvidence(imported.headerLayoutDefinitions)
#else
        let store = WorkspaceStore(workspaceName: "Void slot reasons", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        store.defineTypesFromCHeader(declaration)
        snapshot = store.snapshot
#endif
        XCTAssertNotNil(snapshot.importedPrototypes[.primary(start)])
        _ = snapshot.imageWideIndirectCalls(in: .primary, compute: true)
        let report = try XCTUnwrap(snapshot.slotTypedPrototypeReport(in: .primary, compute: false))
        let input = snapshot.pseudocodeRenderInput(selectedAddress: start, in: .primary)
        let function = PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides, slotCallContracts: input.slotCallContracts,
            types: input.types, instructions: input.instructions)
        let generic = PseudocodePrinter().buildFunction(functionName: input.functionName,
            startAddress: input.startAddress, jumpTables: input.jumpTables,
            signatureOverrides: input.signatureOverrides, types: input.types, instructions: input.instructions)
        if let address {
            let owner = try XCTUnwrap(input.types.first { $0.name == "jpeg_memory_mgr" })
            let catalog = Dictionary(uniqueKeysWithValues: input.types.map { ($0.name, $0) })
            let field = try XCTUnwrap(owner.memberLayout(in: catalog).first { $0.field.name == "alloc_small" }?.field)
            let expected = try XCTUnwrap(field.functionPointerSignatureV1)
            XCTAssertEqual(report.callContracts, [address: expected])
            let pinned = PseudocodePrinter().buildFunction(functionName: input.functionName,
                startAddress: input.startAddress, jumpTables: input.jumpTables,
                signatureOverrides: input.signatureOverrides, slotCallContracts: [address: expected],
                types: input.types, instructions: input.instructions)
            XCTAssertEqual(function.instructions, pinned.instructions)
            XCTAssertEqual(PseudocodePrinter().print(function: function, types: input.types).text,
                           PseudocodePrinter().print(function: pinned, types: input.types).text)
        }
        return Value(report: report, generic: generic, function: function,
            text: DocumentExportService().pseudocodeText(for: input, options: .default),
            genericText: PseudocodePrinter().print(function: generic, types: input.types).text)
    }

    private func call(_ function: MacIRFunction, at address: UInt64) throws -> (MacIRCallFrame, MacIRValue?) {
        let instruction = try XCTUnwrap(function.instructions.first { $0.source.address == address && $0.source.mnemonic == "blr" })
        guard case let .call(frame, result) = instruction.operation else {
            throw NSError(domain: "VoidSlotCallReasonTests.ExpectedCall", code: 1)
        }
        return (frame, result)
    }
    private func typed(_ value: Value, at address: UInt64, arity: Int, hasResult: Bool) throws {
        let contract = try XCTUnwrap(value.report.callContracts[address])
        XCTAssertEqual(contract.parameters.count, arity)
        XCTAssertEqual(contract.returnType == "void", !hasResult)
        let (frame, result) = try call(value.function, at: address)
        XCTAssertEqual(frame.typedIndirectSignature?.parameters.count, arity)
        XCTAssertEqual(frame.arguments.canonicalPhysicalEntriesForAudit.count, arity)
        XCTAssertEqual(result != nil, hasResult)
        XCTAssertNotNil(frame.controlInputs.indirectTarget)
        XCTAssertEqual(value.report.callProofRows.filter { $0.callAddress == address }.count, 1)
        let addresses = value.function.instructions.filter { $0.source.mnemonic == "blr" }.map { $0.source.address }
        let index = try XCTUnwrap(addresses.firstIndex(of: address))
        let rendered = calls(in: value.text)
        XCTAssertTrue(rendered.indices.contains(index))
        if rendered.indices.contains(index) {
            XCTAssertEqual(rendered[index].arguments.count, arity)
            XCTAssertEqual(rendered[index].hasResult, hasResult)
        }
    }
    private func untyped(_ value: Value, at address: UInt64) throws {
        XCTAssertNil(value.report.callContracts[address])
        let (frame, result) = try call(value.function, at: address)
        XCTAssertNil(frame.typedIndirectSignature)
        XCTAssertNotNil(result)
        let addresses = value.function.instructions.filter { $0.source.mnemonic == "blr" }.map { $0.source.address }
        let index = try XCTUnwrap(addresses.firstIndex(of: address))
        let rendered = calls(in: value.text)
        XCTAssertTrue(rendered.indices.contains(index))
        if rendered.indices.contains(index) { XCTAssertTrue(rendered[index].hasResult) }
    }
    private func refusal(_ value: Value, at address: UInt64, reason: String) {
        XCTAssertTrue(value.report.refusals.contains { $0.address == address && $0.reason == reason })
    }

    private struct Call {
        let arguments: [String]
        let hasResult: Bool
    }
    /// Balanced call lists: no fixed temporary or result-variable names.
    private func calls(in text: String) -> [Call] {
        text.components(separatedBy: .newlines).compactMap { line in
            guard let semicolon = line.firstIndex(of: ";") else { return nil }
            var statement = String(line[..<semicolon]).trimmingCharacters(in: .whitespaces)
            if let annotation = statement.range(of: " /* unproven args: "), statement.hasSuffix(" */") {
                statement = String(statement[..<annotation.lowerBound])
            }
            guard statement.last == ")" else { return nil }
            let characters = Array(statement)
            var depth = 0
            var open: Int?
            for index in characters.indices.reversed() {
                if characters[index] == ")" { depth += 1 }
                if characters[index] == "(" {
                    depth -= 1
                    if depth == 0 { open = index; break }
                }
            }
            guard let open else { return nil }
            let prefix = String(characters[..<open])
            let assignment = prefix.firstIndex(of: "=")
            let callee = (assignment.map { String(prefix[prefix.index(after: $0)...]) } ?? prefix)
                .trimmingCharacters(in: .whitespaces)
            guard (callee.hasPrefix("(") && callee.contains("*") && callee.hasSuffix(")"))
                    || callee.contains("->") || callee.contains(".") else { return nil }
            var arguments: [String] = []
            var current = ""
            depth = 0
            for character in characters[(open + 1)..<(characters.count - 1)] {
                if character == "," && depth == 0 {
                    arguments.append(current.trimmingCharacters(in: .whitespaces)); current = ""
                } else {
                    current.append(character)
                    if "([{".contains(character) { depth += 1 }
                    if ")]}".contains(character) { depth -= 1 }
                }
            }
            if !current.trimmingCharacters(in: .whitespaces).isEmpty {
                arguments.append(current.trimmingCharacters(in: .whitespaces))
            }
            return Call(arguments: arguments, hasResult: assignment != nil)
        }
    }
}
