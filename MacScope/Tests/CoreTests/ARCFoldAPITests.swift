import Foundation
import XCTest
@testable import MacScope

private struct FoldNativeStub: ScriptingNativeDecompiling {
    let text: String
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        .completed(.init(text: text, language: "c", isComplete: true, isTruncated: false))
    }
}

/// E4 slice C: the opt-in `fold` option on `decompile`: routing, refusals, paging, bounds and schema.
@MainActor
final class ARCFoldAPITests: XCTestCase {
    private let stubAddress: UInt64 = 0x3000

    /// `_main` calls the `_objc_release` import stub `calls` times. Each call is preceded by a
    /// register move so the function has several rendered lines.
    private func makeStore(calls: Int = 1) -> WorkspaceStore {
        func instruction(_ address: UInt64, _ mnemonic: String, _ operands: String) -> InstructionRow {
            InstructionRow(address: address, bytes: "00 00 00 00", mnemonic: mnemonic, operands: operands,
                           hasBreakpoint: false, comment: nil)
        }
        var rows = [instruction(0x1000, "mov", "x19, x0")]
        var address: UInt64 = 0x1004
        for _ in 0..<calls {
            rows.append(instruction(address, "mov", "x0, x19")); address += 4
            rows.append(instruction(address, "bl", "0x" + String(stubAddress, radix: 16))); address += 4
        }
        rows.append(instruction(address, "ret", ""))
        let end = address + 4
        let mainID = UUID()
        let stub = IndirectSymbolSummary(id: UUID(), kind: MachOIndirectSymbolKind.symbolStub.rawValue,
            sourceSection: "__TEXT,__stubs", address: stubAddress, entrySize: 12, tableIndex: 0,
            rawSymbolIndex: 0, symbolIndex: 0, symbolName: "_objc_release", libraryOrdinal: nil,
            libraryName: "/usr/lib/libobjc.A.dylib", isLocal: false, isAbsolute: false)
        let snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "fold", path: "/tmp/fold",
                                   kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: mainID, name: "_main", startAddress: 0x1000, endAddress: end, confidence: 1)],
            indirectSymbols: [stub],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: mainID, startAddress: 0x1000,
                                           endAddress: end, instructionCount: rows.count)],
            instructions: rows, xrefs: [], controlFlowEdges: [], hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000, size: 0x2000,
                                      fileOffset: 0x1000, isExecutable: true),
                       SectionSummary(id: UUID(), name: "__TEXT,__stubs", address: stubAddress, size: 0x40,
                                      fileOffset: 0x3000, isExecutable: true)])
        return WorkspaceStore(workspaceName: "ARC fold", snapshot: snapshot, engine: AnalysisEngine(),
                              autosaveScheduler: nil)
    }

    private func args(_ extra: [String: ScriptValue] = [:]) -> ScriptValue {
        .object(["function": .string("_main")].merging(extra) { _, new in new })
    }
    private let arc = ScriptValue.array([.string("arc")])

    /// Synchronous MacIR decompile, non-SSA unless a test says otherwise.
    private func sync(_ api: WorkspaceScriptingAPI, _ extra: [String: ScriptValue] = [:],
                      ssa: Bool = false) throws -> ScriptValue {
        try MacIRConfiguration.$ssaOverride.withValue(ssa) {
            try MacIRConfiguration.$explicitCFGOverride.withValue(false) {
                try api.execute("decompile", arguments: args(extra))
            }
        }
    }

    private func request(_ arguments: ScriptValue) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("decompile"), "arguments": arguments])])
    }
    private func mcp(_ server: MCPServer, _ arguments: ScriptValue) async throws -> ScriptValue {
        let bytes = await server.handleMessageAsync(try request(arguments).jsonData())
        let envelope = try ScriptValue.decode(try XCTUnwrap(bytes))
        return try XCTUnwrap(envelope["result"] ?? envelope["error"])
    }
    private func payload(_ response: ScriptValue) throws -> ScriptValue {
        XCTAssertEqual(response["isError"], .bool(false), "\(response)")
        let text = try XCTUnwrap(response["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }
    private func errorText(_ response: ScriptValue) -> String {
        response["content"]?.arrayValue?.first?["text"]?.stringValue ?? "\(response)"
    }

    private func assertInvalid(_ body: () throws -> ScriptValue, _ detail: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        do { _ = try body(); XCTFail("Expected refusal", file: file, line: line) }
        catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail), file: file, line: line) }
    }

    // SPEC-1 (API level)
    func testFoldAbsentIsByteIdentical() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let absent = try sync(api)
        XCTAssertNil(absent["folded"]); XCTAssertNil(absent["foldedEvents"]); XCTAssertNil(absent["foldRefused"])
        XCTAssertFalse(try XCTUnwrap(absent["pseudocode"]?.stringValue).isEmpty)
        for empty in [ScriptValue.array([]), .null] {
            let reply = try sync(api, ["fold": empty])
            XCTAssertEqual(reply, absent)
            XCTAssertNil(reply["folded"])
        }
        // The shaped reply is also unchanged by an empty fold, including cursor encoding.
        let shapedAbsent = try sync(api, ["format": .string("lines"), "lineRange": .string("1-2")])
        let shapedEmpty = try sync(api, ["format": .string("lines"), "lineRange": .string("1-2"), "fold": .array([])])
        XCTAssertEqual(shapedAbsent, shapedEmpty)
        if let cursor = shapedAbsent["nextCursor"]?.stringValue {
            let body = String(data: try XCTUnwrap(Data(base64Encoded: cursor)), encoding: .utf8) ?? ""
            XCTAssertTrue(body.hasPrefix("d1|"), body)
            XCTAssertEqual(body.split(separator: "|", omittingEmptySubsequences: false).count, 6)
        }
    }

    func testFoldedReplyRemovesProvenCallAndReportsEvent() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let off = try sync(api)
        let on = try sync(api, ["fold": arc])
        XCTAssertEqual(on["backend"], .string("macir"))
        XCTAssertEqual(on["folded"], .object(["arc": .int(1)]), "\(on)")
        XCTAssertFalse(try XCTUnwrap(on["pseudocode"]?.stringValue).contains("objc_release("))
        let onLines = try XCTUnwrap(on["lines"]?.arrayValue)
        let offLines = try XCTUnwrap(off["lines"]?.arrayValue)
        XCTAssertLessThan(onLines.count, offLines.count)
        let events = try XCTUnwrap(on["foldedEvents"]?.arrayValue)
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events.first?["address"], .hex(0x1008))
        XCTAssertEqual(events.first?["kind"], .string("arc"))
        XCTAssertEqual(events.first?["callee"], .string("objc_release"))
        XCTAssertEqual(events.first?["role"], .string("release"))
        XCTAssertEqual(on["foldedEventsTruncated"], .bool(false))
        XCTAssertNil(on["foldRefused"])
    }

    // Required: SSA mode is refused and disclosed (Q1).
    func testSSAModeIsRefusedAndDisclosed() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let off = try sync(api, ssa: true)
        let on = try sync(api, ["fold": arc], ssa: true)
        XCTAssertEqual(on["pseudocode"], off["pseudocode"], "SSA output must be unchanged by a fold request")
        XCTAssertEqual(on["lines"], off["lines"])
        XCTAssertEqual(on["folded"], .object(["arc": .int(0)]))
        XCTAssertEqual(on["foldedEvents"], .array([]))
        let refused = try XCTUnwrap(on["foldRefused"])
        XCTAssertEqual(refused["count"], .int(1))
        XCTAssertEqual(refused["reasons"], .object(["ssa-mode": .int(1)]))
        XCTAssertEqual(refused["entries"]?.arrayValue?.first?["reason"], .string("ssa-mode"))
    }

    // SPEC-2
    func testUnknownFoldKindIsTypedArgumentRefusal() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let unknown = ScriptValue.array([.string("arc"), .string("nope")])
        assertInvalid({ try self.sync(api, ["fold": unknown]) }, "fold: unknown kind 'nope'; supported: arc")
        assertInvalid({ try self.sync(api, ["fold": .string("arc")]) }, "fold must be an array of strings; supported: arc")
        assertInvalid({ try self.sync(api, ["fold": .array([.int(1)])]) }, "fold must be an array of strings; supported: arc")
        for bad in [unknown, .string("arc")] {
            let response = try await mcp(MCPServer(api: api), args(["fold": bad]))
            XCTAssertEqual(response["isError"], .bool(true), "\(response)")
            XCTAssertTrue(errorText(response).contains("fold"), errorText(response))
        }
        do {
            try HeadlessAutomationAuthority.validateDiagnosed(command: "decompile",
                arguments: args(["fold": unknown]))
            XCTFail("validateDiagnosed accepted an unknown fold kind")
        } catch {
            XCTAssertTrue("\(error)".contains("fold"), "\(error)")
        }
    }

    // SPEC-17
    func testFoldRoutesToMacIRWhenBackendAbsent() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore(), nativeDecompiler: FoldNativeStub(text: "native text"))
        let control = try await api.executeAsync("decompile", arguments: args())
        XCTAssertEqual(control["backend"], .string("native"))
        XCTAssertNil(control["folded"])
        let folded = try await api.executeAsync("decompile", arguments: args(["fold": arc]))
        XCTAssertEqual(folded["backend"], .string("macir"))
        XCTAssertNotEqual(folded["pseudocode"], .string("native text"))
        XCTAssertEqual(folded["fallbackReason"], .string("fold-requires-macir"))
        XCTAssertEqual(folded["fallbackCause"], .string("notApplicable"))
        XCTAssertEqual(folded["fallbackDetail"], .string("native-ignores-fold"))
        XCTAssertNotNil(folded["folded"])
        XCTAssertNotNil(folded["foldedEvents"])
        // An explicit macir backend is accepted with a fold and reports the request, not a fallback.
        let explicit = try await api.executeAsync("decompile", arguments: args(["fold": arc, "backend": .string("macir")]))
        XCTAssertEqual(explicit["backend"], .string("macir"))
        XCTAssertEqual(explicit["backendRequested"], .string("macir"))
        XCTAssertNotNil(explicit["folded"])
        XCTAssertNil(explicit["fallbackReason"])
        // An empty fold does not change routing.
        let empty = try await api.executeAsync("decompile", arguments: args(["fold": .array([])]))
        XCTAssertEqual(empty["backend"], .string("native"))
    }

    // SPEC-18 (Q3)
    func testFoldWithNativeOrBothRefused() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore(), nativeDecompiler: FoldNativeStub(text: "native text"))
        for backend in ["native", "both"] {
            let detail = "fold: backend \(backend) cannot accompany fold; use backend macir or omit backend"
            do {
                _ = try await api.executeAsync("decompile", arguments: args(["fold": arc, "backend": .string(backend)]))
                XCTFail("Expected refusal for \(backend)")
            } catch { XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail)) }
            let response = try await mcp(MCPServer(api: api), args(["fold": arc, "backend": .string(backend)]))
            XCTAssertEqual(response["isError"], .bool(true), backend)
            XCTAssertTrue(errorText(response).contains("cannot accompany fold"), errorText(response))
            // The same backend without a fold is still accepted.
            let accepted = try await api.executeAsync("decompile", arguments: args(["backend": .string(backend)]))
            XCTAssertNotNil(accepted["backend"] ?? accepted["native"], backend)
        }
    }

    // SPEC-19 (Q5)
    func testPagingUsesFoldedNumbering() throws {
        let api = WorkspaceScriptingAPI(store: makeStore(calls: 3))
        let unfolded = try sync(api, ["format": .string("lines")])
        let folded = try sync(api, ["format": .string("lines"), "fold": arc])
        let unfoldedCount = try XCTUnwrap(unfolded["lineCount"]?.intValue)
        let foldedCount = try XCTUnwrap(folded["lineCount"]?.intValue)
        XCTAssertEqual(foldedCount, unfoldedCount - 3, "three call lines are removed from the numbering")
        let foldedRows = try XCTUnwrap(folded["lines"]?.arrayValue)
        XCTAssertEqual(Int64(foldedRows.count), foldedCount)
        XCTAssertGreaterThan(foldedCount, 4, "the fixture must span more than one page")
        // Page through the folded document two lines at a time and reassemble it.
        var collected: [String] = []
        var reply = try sync(api, ["format": .string("lines"), "lineRange": .string("1-2"), "fold": arc])
        var guardCount = 0
        var firstCursor: String?
        while true {
            let lines = try XCTUnwrap(reply["lines"]?.arrayValue)
            collected += lines.compactMap { $0["text"]?.stringValue }
            XCTAssertEqual(reply["folded"], .object(["arc": .int(3)]))
            guard let cursor = reply["nextCursor"]?.stringValue else { break }
            firstCursor = firstCursor ?? cursor
            let body = String(data: try XCTUnwrap(Data(base64Encoded: cursor)), encoding: .utf8) ?? ""
            XCTAssertTrue(body.hasPrefix("d2|"), body)
            XCTAssertTrue(body.hasSuffix("|arc"), body)
            reply = try sync(api, ["format": .string("lines"), "cursor": .string(cursor), "fold": arc])
            guardCount += 1
            XCTAssertLessThan(guardCount, 200)
        }
        XCTAssertEqual(collected, foldedRows.compactMap { $0["text"]?.stringValue })
        // The line range uses folded numbering: the final folded line number is the folded count.
        let tail = try sync(api, ["format": .string("lines"), "lineRange": .string("\(foldedCount)-\(foldedCount)"),
                                  "fold": arc])
        XCTAssertEqual(tail["lastLine"], .int(Int64(foldedCount)))
        XCTAssertEqual(tail["nextCursor"], .null)
        // A cursor from a fold page is rejected for an unfolded request, and the reverse.
        let foldedCursor = try XCTUnwrap(firstCursor)
        let plain = try sync(api, ["format": .string("lines"), "lineRange": .string("1-2")])
        let plainCursor = try XCTUnwrap(plain["nextCursor"]?.stringValue)
        func staleDetail(_ extra: [String: ScriptValue]) -> String? {
            do { _ = try sync(api, extra); return nil }
            catch let ScriptingError.invalidArgument(detail) { return detail }
            catch { return "\(error)" }
        }
        let unfoldedWithFoldCursor = staleDetail(["format": .string("lines"), "cursor": .string(foldedCursor)])
        XCTAssertTrue(unfoldedWithFoldCursor?.hasPrefix("staleCursor") ?? false, "\(String(describing: unfoldedWithFoldCursor))")
        XCTAssertTrue(unfoldedWithFoldCursor?.contains("fold mode") ?? false)
        let foldedWithPlainCursor = staleDetail(["format": .string("lines"), "cursor": .string(plainCursor), "fold": arc])
        XCTAssertTrue(foldedWithPlainCursor?.hasPrefix("staleCursor") ?? false, "\(String(describing: foldedWithPlainCursor))")
        XCTAssertTrue(foldedWithPlainCursor?.contains("fold mode") ?? false)
    }

    // SPEC-20 (Q4)
    func testFoldedEventsPageBounded() throws {
        let count = 520
        let api = WorkspaceScriptingAPI(store: makeStore(calls: count))
        let whole = try sync(api, ["fold": arc])
        XCTAssertEqual(whole["folded"], .object(["arc": .int(Int64(count))]))
        XCTAssertEqual(try XCTUnwrap(whole["foldedEvents"]?.arrayValue).count, WorkspaceScriptingAPI.maximumFoldedEvents)
        XCTAssertEqual(WorkspaceScriptingAPI.maximumFoldedEvents, 500)
        XCTAssertEqual(whole["foldedEventsTruncated"], .bool(true))
        // A small page returns only the events anchored inside it, and is not marked truncated.
        let page = try sync(api, ["format": .string("lines"), "lineRange": .string("20-30"), "fold": arc])
        let first = try XCTUnwrap(page["firstLine"]?.intValue)
        let last = try XCTUnwrap(page["lastLine"]?.intValue)
        let pageEvents = try XCTUnwrap(page["foldedEvents"]?.arrayValue)
        XCTAssertLessThan(pageEvents.count, 50)
        XCTAssertGreaterThan(pageEvents.count, 0)
        for event in pageEvents {
            let line = try XCTUnwrap(event["beforeLine"]?.intValue)
            XCTAssertTrue(line >= first && line <= last, "\(line) outside \(first)-\(last)")
        }
        XCTAssertEqual(page["foldedEventsTruncated"], .bool(false))
        XCTAssertEqual(page["folded"], .object(["arc": .int(Int64(count))]), "the count is not page-scoped")
    }

    // SPEC-21: cancellation inside the fold stops the render with no partial document.
    func testCancellationDuringFold() throws {
        var rows: [MacIRInstruction] = []
        let signature = MacIRCallSignature(target: "objc_release", returnType: "void",
            parameters: [MacIRCallParameter(index: 0, register: "x0", type: "id", name: "obj")])
        var sites: [UInt64: ARCCalleeIdentity] = [:]
        for index in 0..<300 {
            let address = 0x1004 + UInt64(index) * 4
            let frame = try XCTUnwrap(MacIRCallFrame(target: "objc_release", knownSignature: signature,
                controlInputs: .none, arguments: try XCTUnwrap(MacIRCallArguments([
                    MacIRCallArgument(location: .gpr(index: 0, carrierWidth: 64), role: .fixed(sourcePosition: 0),
                                      value: .register(name: "x19", version: 1))]))))
            rows.append(MacIRInstruction(source: MacIRSourceSpan(address: address, byteText: "", mnemonic: "bl",
                operands: "0x3000"), operation: .call(frame: frame, result: nil)))
            sites[address] = ARCCalleeIdentity(family: .objc, role: .release, importSymbol: "objc_release",
                libraryName: nil, isCountVariant: false, objectRegisterIndex: 0)
        }
        rows.append(MacIRInstruction(source: MacIRSourceSpan(address: 0x1004 + 300 * 4, byteText: "",
            mnemonic: "ret", operands: ""), operation: .returnValue(nil)))
        let function = MacIRFunction(name: "many", startAddress: 0x1000, returnType: "void",
            callTargets: ["objc_release"], callSignatures: [signature], instructions: rows)
        let request = PseudocodeFoldRequest(kinds: [.arc], arcCallSites: sites)
        struct Stop: Error {}
        var checkpoints = 0
        XCTAssertThrowsError(try PseudocodePrinter().print(function: function, fold: request, checkpoint: {
            checkpoints += 1
            throw Stop()
        })) { XCTAssertTrue($0 is Stop) }
        XCTAssertGreaterThanOrEqual(checkpoints, 1)
        // The same render, not cancelled, folds every call.
        var passes = 0
        let document = try PseudocodePrinter().print(function: function, fold: request, checkpoint: { passes += 1 })
        XCTAssertEqual(document.foldReport?.counts[.arc], 300)
        XCTAssertGreaterThan(passes, 0)
    }

    // SPEC-22
    func testSchemaListsFold() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let server = MCPServer(api: api)
        let response = server.handle(.object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/list")]))
        let tool = try XCTUnwrap(response?["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string("decompile") })
        let schema = try XCTUnwrap(tool["inputSchema"])
        let fold = try XCTUnwrap(schema["properties"]?["fold"])
        XCTAssertEqual(fold["type"], .string("array"))
        XCTAssertEqual(fold["items"]?["type"], .string("string"))
        XCTAssertEqual(fold["items"]?["enum"], .array([.string("arc")]))
        XCTAssertNil(schema["required"])
        // Unknown keys are still rejected.
        let rejected = try await mcp(server, args(["not_a_decompile_argument": .int(1)]))
        XCTAssertEqual(rejected["isError"], .bool(true), "\(rejected)")
    }
}
