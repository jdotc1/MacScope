import Foundation
import XCTest
@testable import MacScope

/// ITEM 1273, revision 1273-v1-r1-20261106. Fixed fixtures; authored, not run.
final class ARCFoldClosureTests: XCTestCase {
    // Copied/adapted from ARCFoldProjectionTests:7-57. No landed private helper is called.
    private func reg(_ name: String, _ version: Int) -> MacIRValue {
        .register(name: name, version: version)
    }

    private func row(_ address: UInt64, _ operation: MacIROperation,
                     _ mnemonic: String = "mov") -> MacIRInstruction {
        MacIRInstruction(source: MacIRSourceSpan(address: address, byteText: "",
            mnemonic: mnemonic, operands: "", comment: nil), operation: operation)
    }

    private func frame(_ name: String, argument: MacIRValue?,
                       indirectResultPointer: MacIRValue? = nil) throws -> MacIRCallFrame {
        let signature = MacIRCallSignature(target: name, returnType: "id",
            parameters: [MacIRCallParameter(index: 0, register: "x0", type: "id", name: "obj")])
        let arguments = argument.map { [MacIRCallArgument(location: .gpr(index: 0, carrierWidth: 64),
            role: .fixed(sourcePosition: 0), value: $0)] } ?? []
        return try XCTUnwrap(MacIRCallFrame(target: name, knownSignature: signature,
            controlInputs: .none, arguments: try XCTUnwrap(MacIRCallArguments(arguments)),
            indirectResultPointer: indirectResultPointer))
    }

    private func call(_ address: UInt64, _ name: String = "objc_retain",
                      argument: MacIRValue?, result: MacIRValue?) throws -> MacIRInstruction {
        row(address, .call(frame: try frame(name, argument: argument), result: result), "bl")
    }

    private func function(_ rows: [MacIRInstruction]) -> MacIRFunction {
        MacIRFunction(name: "caller", startAddress: 0x1000, returnType: "void",
            callTargets: ["objc_retain", "objc_release"], instructions: rows)
    }

    private func identity(_ symbol: String = "objc_retain", role: ARCRole = .retain) -> ARCCalleeIdentity {
        ARCCalleeIdentity(family: .objc, role: role, importSymbol: symbol, libraryName: nil,
            isCountVariant: false, objectRegisterIndex: 0)
    }

    private func prologue() -> MacIRInstruction {
        row(0x1000, .assign(destination: reg("x19", 1), source: reg("x0", 0)))
    }

    private func ret(_ address: UInt64) -> MacIRInstruction {
        row(address, .returnValue(nil), "ret")
    }

    private func calls(in function: MacIRFunction) -> Int {
        function.instructions.filter { if case .call = $0.operation { return true }; return false }.count
    }

    private func assertOnlyRefusal(_ original: MacIRFunction, reason: String,
                                   functionLevel: Bool = false,
                                   file: StaticString = #filePath, line: UInt = #line) {
        let result = PseudocodePrinter.projectARCFold(original,
            request: PseudocodeFoldRequest(kinds: [.arc], arcCallSites: [0x1004: identity()]))
        XCTAssertEqual(result.function, original, reason, file: file, line: line)
        XCTAssertEqual(result.report.events, [], reason, file: file, line: line)
        XCTAssertTrue(result.report.counts.isEmpty, reason, file: file, line: line)
        XCTAssertEqual(result.report.refused, [FoldRefusal(
            address: functionLevel ? nil : 0x1004,
            callee: functionLevel ? nil : "objc_retain", reason: reason)], file: file, line: line)
    }

    func testUnknownOperationHasOnlyItsFunctionRefusal() throws {
        let original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: nil),
            row(0x1008, .unknown(mnemonic: "unmodelled", operands: "")), ret(0x100c)])
        assertOnlyRefusal(original, reason: "unknown-operation", functionLevel: true)
    }

    func testExplicitCFGHasOnlyItsFunctionRefusal() throws {
        var original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: nil), ret(0x1008)])
        // Exact factory argument list is supplied by MacIRBuilder.swift:218-222.
        original.cfg = try XCTUnwrap(MacIRCFG.build(instructions: original.instructions,
            jumpTables: [:], knownTailCallTargets: [:], provenTailCallTargets: [:],
            authoredCallSignaturesByTarget: [:], owningFunctionRange: nil))
        XCTAssertNotNil(original.cfg)
        XCTAssertFalse(original.ssaEnabled)
        XCTAssertTrue(original.phis.isEmpty)
        assertOnlyRefusal(original, reason: "explicit-cfg", functionLevel: true)
    }

    func testTypedSidecarHasOnlyItsFunctionRefusal() throws {
        var tagged = row(0x1008, .assign(destination: reg("x20", 1), source: .immediate(7)))
        tagged.neonQCIsSeparate = true
        let original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: nil), tagged, ret(0x100c)])
        assertOnlyRefusal(original, reason: "typed-sidecars", functionLevel: true)
    }

    func testUnknownValueHasOnlyItsFunctionRefusal() throws {
        let original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: nil),
            row(0x1008, .store(source: .unknown("opaque_arc_input"), address: reg("x20", 0)), "str"),
            ret(0x100c)])
        assertOnlyRefusal(original, reason: "unknown-value", functionLevel: true)
    }

    func testDuplicateAddressHasOnlyAmbiguousAddressRefusal() throws {
        let original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: nil),
            row(0x1004, .assign(destination: reg("x20", 1), source: .immediate(7))), ret(0x1008)])
        assertOnlyRefusal(original, reason: "ambiguous-address")
    }

    func testIndirectResultPointerHasOnlyFrameShapeRefusal() throws {
        let shaped = try frame("objc_retain", argument: reg("x19", 1),
                               indirectResultPointer: reg("x8", 0))
        let original = function([prologue(), row(0x1004, .call(frame: shaped, result: nil), "bl"), ret(0x1008)])
        assertOnlyRefusal(original, reason: "frame-shape")
    }

    func testNonCarrierResultHasOnlyResultShapeRefusal() throws {
        let original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: reg("x1", 1)), ret(0x1008)])
        assertOnlyRefusal(original, reason: "result-shape")
    }

    func testMissingObjectArgumentHasOnlyArgumentUnavailableRefusal() throws {
        let original = function([prologue(), try call(0x1004, argument: nil, result: reg("x0", 1)),
            row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str"), ret(0x100c)])
        assertOnlyRefusal(original, reason: "argument-unavailable")
    }

    func testReturnTargetUseHasOnlyUnrewritableUseRefusal() throws {
        var returning = ret(0x1008)
        returning.returnTarget = reg("x0", 1)
        let original = function([prologue(),
            try call(0x1004, argument: reg("x19", 1), result: reg("x0", 1)), returning])
        assertOnlyRefusal(original, reason: "unrewritable-use")
    }

    func testSourceRefusalLiteralsMatchClosedTwentyReasonVocabulary() throws {
        let expected: Set<String> = [
            "ssa-mode", "phis", "explicit-cfg", "unknown-operation", "typed-sidecars",
            "indirect-branch", "unknown-value", "ambiguous-address", "branch-target", "frame-shape",
            "result-shape", "result-used-release", "result-used-count-variant",
            "result-used-register-helper", "w0-view", "argument-unavailable", "argument-not-simple",
            "use-before-call", "branch-target-in-range", "unrewritable-use",
        ]
        XCTAssertEqual(expected.count, 20)
        // The source tree is required, not optional. A missing source file throws; do not skip.
        let macScope = TestSourceRoot.fileURL(#filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: macScope.appendingPathComponent(
            "Services/Decompiler/MacIRARCFoldProjection.swift"), encoding: .utf8)
        // Include direct reason: literals as well as both local refusal helpers.
        let pattern = #"(?:\brefuse(?:d)?\s*\(\s*|\breason\s*:\s*)"([^"\\]*(?:\\.[^"\\]*)*)""#
        let matcher = try NSRegularExpression(pattern: pattern)
        let matches = matcher.matches(in: source, range: NSRange(source.startIndex..., in: source))
        XCTAssertEqual(matches.count, 21, "Twenty reasons, with unrewritable-use emitted at two sites")
        func occurrences(_ pattern: String) throws -> Int {
            try NSRegularExpression(pattern: pattern).numberOfMatches(
                in: source, range: NSRange(source.startIndex..., in: source))
        }
        // Deliberately source-structure coupled: dynamic additions/replacements require review.
        XCTAssertEqual(try occurrences(#"\brefuse(?:d)?\s*\("#), 23,
                       "Two helper declarations plus 21 literal calls; no dynamic call sites")
        XCTAssertEqual(try occurrences(#"\bFoldRefusal\s*\("#), 2,
                       "Only the two forwarding helpers construct refusals")
        XCTAssertEqual(try occurrences(#"\breason\s*:\s*reason\b"#), 2,
                       "Both constructors must forward their literal-backed helper argument")
        XCTAssertEqual(try occurrences(#"\breason\s*:"#), 5,
                       "Two declarations, two forwardings and one existing documentation label")
        let actual = try Set(matches.map { match -> String in
            let range = try XCTUnwrap(Range(match.range(at: 1), in: source))
            return String(source[range])
        })
        XCTAssertEqual(actual, expected, "Adding, removing or changing a source refusal literal requires review")
    }

    func testThreeRemovedCallsAndOneRefusalMatchUnshapedReplyCounts() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil),
            try call(0x1008, "objc_release", argument: reg("x19", 1), result: nil),
            try call(0x100c, "objc_release", argument: reg("x19", 1), result: nil),
            try call(0x1010, "objc_release", argument: reg("x19", 1), result: reg("x0", 1)),
            row(0x1014, .store(source: reg("x0", 1), address: reg("x20", 0)), "str"), ret(0x1018)])
        let release = identity("objc_release", role: .release)
        let request = PseudocodeFoldRequest(kinds: [.arc], arcCallSites: [
            0x1004: release, 0x1008: release, 0x100c: release, 0x1010: release,
        ])
        let projected = PseudocodePrinter.projectARCFold(original, request: request)
        let removedCalls = calls(in: original) - calls(in: projected.function)
        XCTAssertEqual(calls(in: original), 4)
        XCTAssertEqual(calls(in: projected.function), 1)
        XCTAssertEqual(removedCalls, 3)
        XCTAssertEqual(projected.report.counts[.arc], removedCalls)
        XCTAssertEqual(projected.report.events.map(\.address), [0x1004, 0x1008, 0x100c])
        XCTAssertEqual(projected.report.refused, [FoldRefusal(address: 0x1010,
            callee: "objc_release", reason: "result-used-release")])
        let off = PseudocodePrinter().print(function: original)
        let on = PseudocodePrinter().print(function: projected.function)
        let offCallLines = off.lines.filter { $0.text.contains("objc_release(") }.count
        let onCallLines = on.lines.filter { $0.text.contains("objc_release(") }.count
        XCTAssertEqual(offCallLines, 4)
        XCTAssertEqual(onCallLines, 1)
        let removedCallLines = offCallLines - onCallLines
        XCTAssertEqual(removedCallLines, removedCalls)
        XCTAssertEqual(projected.report.counts[.arc], removedCallLines)
        // The real reply serializer, deliberately without firstLine/lastLine: unshaped.
        var reply: [String: ScriptValue] = [:]
        WorkspaceScriptingAPI.applyFoldFields(&reply, kinds: [.arc], report: projected.report)
        let count = try XCTUnwrap(reply["folded"]?["arc"]?.intValue)
        XCTAssertEqual(count, Int64(removedCalls))
        XCTAssertEqual(count, Int64(removedCallLines))
        XCTAssertEqual(Int64(try XCTUnwrap(reply["foldedEvents"]?.arrayValue).count), count)
        XCTAssertEqual(reply["foldedEventsTruncated"], .bool(false))
        XCTAssertEqual(reply["foldRefused"]?["count"], .int(1))
        XCTAssertEqual(reply["foldRefused"]?["reasons"], .object(["result-used-release": .int(1)]))
    }

    func testRenderedCallDisappearsAndSurvivingStoreTextIsUnchanged() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil),
            row(0x1008, .store(source: reg("x19", 1), address: reg("x20", 0)), "str"), ret(0x100c)])
        let off = PseudocodePrinter().print(function: original)
        let on = PseudocodePrinter().print(function: original, fold: PseudocodeFoldRequest(
            kinds: [.arc], arcCallSites: [0x1004: identity("objc_release", role: .release)]))
        XCTAssertTrue(off.text.contains("objc_release("), off.text)
        XCTAssertFalse(on.text.contains("objc_release("), on.text)
        let before = off.lines.filter { $0.sourceAddress == 0x1008 }.map(\.text)
        let after = on.lines.filter { $0.sourceAddress == 0x1008 }.map(\.text)
        XCTAssertFalse(before.isEmpty, "The surviving store must really be rendered")
        XCTAssertEqual(after, before)
        XCTAssertEqual(on.foldReport?.counts[.arc], 1)
    }

    func testExplicitEmptyKindsEqualsAbsentPrinterRequest() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil), ret(0x1008)])
        let printer = PseudocodePrinter()
        let absent = printer.print(function: original)
        let empty = printer.print(function: original, fold: PseudocodeFoldRequest(
            kinds: [], arcCallSites: [0x1004: identity("objc_release", role: .release)]))
        XCTAssertTrue(absent.text.contains("objc_release("), absent.text)
        XCTAssertEqual(empty.lines, absent.lines)
        XCTAssertEqual(empty.regionTree, absent.regionTree)
        XCTAssertEqual(Array(empty.text.utf8), Array(absent.text.utf8))
        // The direct printer may attach an empty report for a nonnil request.
        let projection = PseudocodePrinter.projectARCFold(original,
            request: PseudocodeFoldRequest(kinds: [], arcCallSites: [0x1004: identity("objc_release", role: .release)]))
        XCTAssertEqual(projection.function, original)
        XCTAssertEqual(projection.report, PseudocodeFoldReport())
    }
}

@MainActor
final class ARCFoldSSAEmptyClosureTests: XCTestCase {
    // Copied/adapted from ARCFoldAPITests:19-65. Independent private helpers.
    private func makeStore() -> WorkspaceStore {
        func instruction(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
            InstructionRow(address: address, bytes: "00 00 00 00", mnemonic: mnemonic,
                operands: operands, hasBreakpoint: false, comment: nil)
        }
        let rows = [instruction(0x1000, "mov", "x19, x0"), instruction(0x1004, "mov", "x0, x19"),
                    instruction(0x1008, "bl", "0x3000"), instruction(0x100c, "ret", "")]
        let mainID = UUID()
        let stub = IndirectSymbolSummary(id: UUID(), kind: MachOIndirectSymbolKind.symbolStub.rawValue,
            sourceSection: "__TEXT,__stubs", address: 0x3000, entrySize: 12, tableIndex: 0,
            rawSymbolIndex: 0, symbolIndex: 0, symbolName: "_objc_release", libraryOrdinal: nil,
            libraryName: "/usr/lib/libobjc.A.dylib", isLocal: false, isAbsolute: false)
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "fold", path: "/tmp/fold",
                kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: mainID, name: "_main", startAddress: 0x1000,
                endAddress: 0x1010, confidence: 1)], indirectSymbols: [stub],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: mainID, startAddress: 0x1000,
                endAddress: 0x1010, instructionCount: rows.count)],
            instructions: rows, xrefs: [], controlFlowEdges: [], hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000, size: 0x2000,
                fileOffset: 0x1000, isExecutable: true),
                SectionSummary(id: UUID(), name: "__TEXT,__stubs", address: 0x3000, size: 0x40,
                fileOffset: 0x3000, isExecutable: true)])
        return WorkspaceStore(workspaceName: "ARC fold", snapshot: snapshot, engine: AnalysisEngine(),
            autosaveScheduler: nil)
    }

    private func sync(_ api: WorkspaceScriptingAPI, _ extra: [String: ScriptValue],
                      ssa: Bool = true) throws -> ScriptValue {
        try MacIRConfiguration.$ssaOverride.withValue(ssa) {
            try MacIRConfiguration.$explicitCFGOverride.withValue(false) {
                try api.execute("decompile", arguments: .object(
                    ["function": .string("_main")].merging(extra) { _, new in new }))
            }
        }
    }

    func testSSAEmptyRequestEqualsAbsentOnAPIPath() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let absent = try sync(api, [:])
        let baselineBytes = Array(try XCTUnwrap(absent["pseudocode"]?.stringValue).utf8)
        XCTAssertFalse(baselineBytes.isEmpty)
        for empty in [ScriptValue.array([]), .null] {
            let reply = try sync(api, ["fold": empty])
            XCTAssertEqual(reply, absent)
            XCTAssertEqual(Array(try XCTUnwrap(reply["pseudocode"]?.stringValue).utf8), baselineBytes)
            XCTAssertNil(reply["folded"])
            XCTAssertNil(reply["foldedEvents"])
            XCTAssertNil(reply["foldRefused"])
            let shape: [String: ScriptValue] = ["format": .string("lines"), "lineRange": .string("1-2")]
            let shapedAbsent = try sync(api, shape)
            let shapedEmpty = try sync(api, shape.merging(["fold": empty]) { _, new in new })
            XCTAssertEqual(shapedEmpty, shapedAbsent)
        }
        // Non-empty SSA disclosure remains pinned by ARCFoldAPITests:135-148.
    }

    // Requires FD-SCHEMA. Intentionally fails the pinned maxItems: 8 schema until that
    // separately reviewed design is implemented. This patch does not modify the schema.
    func testSchemaAllowsParserAcceptedNineRepeatedArcKindsAfterFDSchema() throws {
        let repeated = ScriptValue.array(Array(repeating: .string("arc"), count: 9))
        XCTAssertEqual(try WorkspaceScriptingAPI.decompileFold(.object(["fold": repeated])),
                       Set([PseudocodeFoldKind.arc]))
        let server = MCPServer(api: WorkspaceScriptingAPI(store: makeStore()))
        let response = server.handle(.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list"),
        ]))
        let tool = try XCTUnwrap(response?["result"]?["tools"]?.arrayValue?.first {
            $0["name"] == .string("decompile")
        })
        let fold = try XCTUnwrap(tool["inputSchema"]?["properties"]?["fold"])
        XCTAssertEqual(fold["type"], .string("array"))
        XCTAssertEqual(fold["items"]?["type"], .string("string"))
        XCTAssertEqual(fold["items"]?["enum"], .array([.string("arc")]))
        XCTAssertNil(fold["maxItems"])
    }

    // Requires FD-COMPARISON. The two keys are not present at the pin. This is a
    // design-dependent control, not a claim that the metadata implementation landed.
    func testOneFoldedReplyCarriesMeasuredLineCountsAfterFDComparison() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let base: [String: ScriptValue] = ["backend": .string("macir")]
        let folded = base.merging(["fold": .array([.string("arc")])]) { _, new in new }
        let off = try sync(api, base, ssa: false)
        let on = try sync(api, folded, ssa: false)
        let offCount = Int64(try XCTUnwrap(off["lines"]?.arrayValue).count)
        let onCount = Int64(try XCTUnwrap(on["lines"]?.arrayValue).count)
        XCTAssertGreaterThan(offCount, 0)
        XCTAssertLessThan(onCount, offCount)
        XCTAssertEqual(on["folded"]?["arc"], .int(1))
        XCTAssertEqual(on["unfoldedLineCount"], .int(offCount))
        XCTAssertEqual(on["foldedLineCount"], .int(onCount))
        let shaped = try sync(api, folded.merging(["format": .string("lines")]) { _, new in new }, ssa: false)
        XCTAssertEqual(shaped["lineCount"], .int(onCount))
        XCTAssertEqual(shaped["foldedLineCount"], shaped["lineCount"])
        XCTAssertEqual(shaped["unfoldedLineCount"], .int(offCount))
        for reply in [off,
                      try sync(api, base.merging(["fold": .array([])]) { _, new in new }, ssa: false),
                      try sync(api, base.merging(["fold": .null]) { _, new in new }, ssa: false)] {
            XCTAssertNil(reply["unfoldedLineCount"])
            XCTAssertNil(reply["foldedLineCount"])
        }
    }
}
