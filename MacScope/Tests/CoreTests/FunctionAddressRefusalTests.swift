import Foundation
import XCTest
@testable import MacScope

@MainActor
final class FunctionAddressRefusalTests: XCTestCase {
    private func makeStore(gap: Bool = false, twoImages: Bool = false) -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        func analysis(_ slot: ImageSlot) -> ImageAnalysis {
            let second: UInt64 = gap ? 0x1010 : 0x1008
            let prefix = slot == .primary ? "" : "sibling_"
            var value = ImageAnalysis()
            value.functions = [
                FunctionSummary(id: UUID(), name: prefix + "_main", startAddress: 0x1000,
                                endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: prefix + "helper", startAddress: second,
                                endAddress: second + (gap ? 8 : 4), confidence: 1),
            ]
            value.instructions = [
                InstructionRow(address: 0x1000, bytes: "e0 03 01 aa", mnemonic: "mov",
                               operands: "x0, x1", hasBreakpoint: false, comment: nil),
                InstructionRow(address: 0x1004, bytes: "01 00 00 94", mnemonic: "bl",
                               operands: prefix + "helper", hasBreakpoint: false, comment: "call"),
                InstructionRow(address: second, bytes: "c0 03 5f d6", mnemonic: "ret",
                               operands: "", hasBreakpoint: false, comment: nil),
            ]
            value.basicBlocks = [
                BasicBlockSummary(id: UUID(), functionID: value.functions[0].id,
                                  startAddress: 0x1000, endAddress: 0x1008, instructionCount: 2)
            ]
            value.xrefs = [XRef(id: UUID(), from: 0x1004, to: second, kind: XRefKind.call)]
            value.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: 0x1004, to: second, kind: "call")]
            value.stringLiterals = [
                StringLiteralSummary(id: UUID(), value: "hello world", address: 0x2000,
                                     sourceSection: "__TEXT,__cstring", byteLength: 12)
            ]
            let sectionPrefix = slot == .primary ? "__TEXT," : "__SIBLING,"
            value.sections = [
                SectionSummary(id: UUID(), name: sectionPrefix + "__text", address: 0x1000,
                               size: 0x200, fileOffset: 0x1000, isExecutable: true),
                SectionSummary(id: UUID(), name: sectionPrefix + "__stubs", address: 0x1200,
                               size: 0x20, fileOffset: 0x1200, isExecutable: true),
                SectionSummary(id: UUID(), name: sectionPrefix + "__cstring", address: 0x2000,
                               size: 0x40, fileOffset: 0x2000, isExecutable: false),
            ]
            return value
        }
        let sibling = ImageSlot(rawValue: 1)
        let snapshot = twoImages
            ? WorkspaceSnapshot(binaries: [image(.primary), image(sibling)],
                                analysisBySlot: [.primary: analysis(.primary), sibling: analysis(sibling)])
            : WorkspaceSnapshot(binaries: [image(.primary)], analysisBySlot: [.primary: analysis(.primary)])
        return WorkspaceStore(workspaceName: "function-addresses", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func refusal(_ address: UInt64, nearest: String?, start: UInt64?,
                         section: MCPRefusalSection? = nil, slot: Int = 0) -> ScriptingError {
        let nearestText: String
        if let nearest, let start {
            nearestText = "nearest preceding function \(nearest) at 0x\(String(start, radix: 16))"
        } else {
            nearestText = "nearest preceding function none"
        }
        let sectionText = section.map {
            "\($0.name) [0x\(String($0.start, radix: 16)), 0x\(String($0.end, radix: 16)))"
        } ?? "none"
        return .structuredRefusal(MCPToolRefusal(code: .unknownSubject,
            detail: "address 0x\(String(address, radix: 16)) is outside every function in image slot \(slot); " +
                nearestText + "; section " + sectionText,
            requestedAddress: address, imageSlot: slot,
            nearestFunction: nearest.flatMap { name in start.map { MCPRefusalFunction(name: name, address: $0) } },
            section: section))
    }

    private func assertReadRefuses(_ command: String, arguments: ScriptValue,
                                   store: WorkspaceStore, expected: ScriptingError,
                                   file: StaticString = #filePath, line: UInt = #line) async {
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertThrowsError(try api.execute(command, arguments: arguments), file: file, line: line) {
            XCTAssertEqual($0 as? ScriptingError, expected, file: file, line: line)
        }
        do {
            _ = try await api.executeAsync(command, arguments: arguments)
            XCTFail("detached read returned a preceding function result", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? ScriptingError, expected, file: file, line: line)
        }
        // Each isolated assertion has its own connection rate state.
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        do {
            _ = try await attached.execute(command, arguments)
            XCTFail("attached read returned a preceding function result", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? ScriptingError, expected, file: file, line: line)
        }
    }

    // Fails before the fix. On the callers-only fix, callers fails on the exact refusal detail.
    func testUncoveredReadAddressesRefuseAcrossAllThreeRoutes() async {
        let store = makeStore()
        let cases: [(UInt64, String?, UInt64?, MCPRefusalSection?)] = [
            (0x1204, "helper", 0x1008, .init(name: "__TEXT,__stubs", start: 0x1200, end: 0x1220)),
            (0x2000, "helper", 0x1008, .init(name: "__TEXT,__cstring", start: 0x2000, end: 0x2040)),
            (0x1100, "helper", 0x1008, .init(name: "__TEXT,__text", start: 0x1000, end: 0x1200)),
            (0x5000, "helper", 0x1008, nil),
            (0x0800, nil, nil, nil),
        ]
        let commands = ["decompile", "callers", "callees", "basic-blocks", "parameter-binding-audit",
                        "register-names", "stack-locals", "recover-struct-candidate", "indirect-call-targets"]
        for (address, nearest, start, section) in cases {
            for command in commands {
                var fields: [String: ScriptValue] = ["address": .hex(address)]
                if command == "recover-struct-candidate" { fields["parameter"] = .int(0) }
                await assertReadRefuses(command, arguments: .object(fields), store: store,
                    expected: refusal(address, nearest: nearest, start: start, section: section))
            }
        }
    }

    // Fails before the fix: an explicit stored/synthetic gap is not the preceding function.
    func testGapRefusesWithNearestFunctionAndHoldingSection() async {
        let store = makeStore(gap: true)
        let expected = refusal(0x100c, nearest: "_main", start: 0x1000,
                               section: .init(name: "__TEXT,__text", start: 0x1000, end: 0x1200))
        for command in ["decompile", "callers", "callees", "basic-blocks"] {
            await assertReadRefuses(command, arguments: .object(["address": .hex(0x100c)]),
                                   store: store, expected: expected)
        }
    }

    // Fails before the fix: every piece of refusal context must come from the selected image.
    func testSiblingRefusalDoesNotBorrowPrimaryContext() async {
        let store = makeStore(twoImages: true)
        let expected = refusal(0x1204, nearest: "sibling_helper", start: 0x1008,
                               section: .init(name: "__SIBLING,__stubs", start: 0x1200, end: 0x1220), slot: 1)
        for command in ["decompile", "callers", "callees"] {
            let imageKey = command == "decompile" ? "image" : "imageSlot"
            await assertReadRefuses(command, arguments: .object([
                "address": .hex(0x1204), imageKey: .int(1)
            ]), store: store, expected: expected)
        }
    }

    // Fails before the fix; the MCP transport reports one exact tool-failure message.
    func testMCPRefusalIsAnErrorResultWithExactContext() async throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let server = MCPServer(api: api)
        let request = ScriptValue.object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string("callers"),
                              "arguments": .object(["address": .hex(0x1204)])]),
        ])
        let response = await server.handleMessageAsync(try request.jsonData())
        let reply = try XCTUnwrap(response)
        let envelope = try ScriptValue.decode(reply)
        XCTAssertNil(envelope["error"])
        XCTAssertEqual(envelope["result"]?["isError"], .bool(true))
        let expected = refusal(0x1204, nearest: "helper", start: 0x1008,
            section: .init(name: "__TEXT,__stubs", start: 0x1200, end: 0x1220))
        XCTAssertEqual(envelope["result"]?["content"]?.arrayValue?.first?["text"],
            .string(try XCTUnwrap(MCPToolRefusal.executionRefusal(expected)).text))
    }

    // Positive controls (pass before): existing fields and bare arrays only, not the new envelope.
    func testExactInteriorAndNameSelectorsKeepExistingResults() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let cases: [(ScriptValue, UInt64, String)] = [
            (.object(["address": .hex(0x1000)]), 0x1000, "_main"),
            (.object(["address": .hex(0x1002)]), 0x1000, "_main"),
            (.object(["address": .hex(0x1008)]), 0x1008, "helper"),
            (.object(["function": .string("helper")]), 0x1008, "helper"),
        ]
        let edge = ScriptValue.object(["from": .hex(0x1004), "to": .hex(0x1008), "imageSlot": .int(0),
            "toName": .string("helper"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main")])
        let block = ScriptValue.object([
            "start": .hex(0x1000), "end": .hex(0x1008), "instructionCount": .int(2),
            "successors": .array([.object(["to": .hex(0x1008), "kind": .string("call")])]),
        ])
        for (selector, start, name) in cases {
            let decompiled = try api.execute("decompile", arguments: selector)
            XCTAssertEqual(decompiled["address"], .hex(start))
            XCTAssertEqual(decompiled["function"], .string(name))
            XCTAssertEqual(try api.execute("callers", arguments: selector),
                           .array(start == 0x1008 ? [edge] : []))
            XCTAssertEqual(try api.execute("callees", arguments: selector),
                           .array(start == 0x1000 ? [edge] : []))
            XCTAssertEqual(try api.execute("basic-blocks", arguments: selector),
                           .array(start == 0x1000 ? [block] : []))
            guard case .object(var fields) = selector else { return XCTFail("bad fixture") }
            fields["register"] = .string("x19"); fields["name"] = .string("ctx")
            XCTAssertEqual(try api.execute("rename-register", arguments: .object(fields))["address"], .hex(start))
        }
    }

    // Fails before both fixes: object replies must expose exact versus containing resolution.
    func testDecompileAndRegisterMutationEnvelopes() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let cases: [(ScriptValue, UInt64?, UInt64, String)] = [
            (.object(["address": .hex(0x1000)]), 0x1000, 0x1000, "exact"),
            (.object(["address": .hex(0x1002)]), 0x1002, 0x1000, "containing"),
            (.object(["address": .hex(0x1008)]), 0x1008, 0x1008, "exact"),
            (.object(["function": .string("helper")]), nil, 0x1008, "exact"),
            (.object(["function": .string("helper"), "address": .hex(0x5000)]), nil, 0x1008, "exact"),
        ]
        for (selector, requested, resolved, resolution) in cases {
            let decompiled = try api.execute("decompile", arguments: selector)
            guard case .object(var fields) = selector else { return XCTFail("bad fixture") }
            fields["register"] = .string("x19"); fields["name"] = .string("ctx")
            let renamed = try api.execute("rename-register", arguments: .object(fields))
            for reply in [decompiled, renamed] {
                XCTAssertEqual(reply["resolvedFunction"], .hex(resolved))
                XCTAssertEqual(reply["resolution"], .string(resolution))
                if let requested { XCTAssertEqual(reply["requestedAddress"], .hex(requested)) }
                else { XCTAssertNil(reply["requestedAddress"]) }
            }
        }
    }

    // Fails before both fixes: synchronous and snapshot object replies must gain identical fields.
    func testObjectReadEnvelopesMatchAcrossRoutes() async throws {
        let store = makeStore()
        let api = WorkspaceScriptingAPI(store: store)
        for command in ["decompile", "parameter-binding-audit", "register-names",
                        "stack-locals", "recover-struct-candidate", "indirect-call-targets"] {
            var fields: [String: ScriptValue] = ["address": .hex(0x1002)]
            if command == "recover-struct-candidate" { fields["parameter"] = .int(0) }
            let arguments = ScriptValue.object(fields)
            let inline = try api.execute(command, arguments: arguments)
            XCTAssertEqual(inline["requestedAddress"], .hex(0x1002))
            XCTAssertEqual(inline["resolvedFunction"], .hex(0x1000))
            XCTAssertEqual(inline["resolution"], .string("containing"))
            let detached = try await api.executeAsync(command, arguments: arguments)
            let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
            attached.setConsent(.allowed)
            let attachedReply = try await attached.execute(command, arguments)
            XCTAssertEqual(try detached.jsonData(), try inline.jsonData(), command)
            XCTAssertEqual(try attachedReply.jsonData(), try inline.jsonData(), command)
        }
    }

    // Fails before both fixes: the request must not mutate the preceding function.
    func testUncoveredRegisterAndStackEditsLeaveOverridesUnchanged() throws {
        for command in ["rename-register", "set-stack-local"] {
            let store = makeStore()
            let api = WorkspaceScriptingAPI(store: store)
            let before = store.snapshot.addressOverrides
            var fields: [String: ScriptValue] = ["address": .hex(0x1100), "name": .string("ctx")]
            if command == "rename-register" { fields["register"] = .string("x19") }
            else { fields["local"] = .string("-8:0") }
            XCTAssertThrowsError(try api.execute(command, arguments: .object(fields))) {
                XCTAssertEqual($0 as? ScriptingError, self.refusal(0x1100, nearest: "helper", start: 0x1008,
                    section: .init(name: "__TEXT,__text", start: 0x1000, end: 0x1200)))
            }
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            let names = try api.execute("register-names", arguments: .object(["function": .string("helper")]))
            XCTAssertEqual(names["renames"], .object([:]))
            XCTAssertTrue(store.snapshot.stackLocalOverrides(forProcedureAt: 0x1008, in: .primary).isEmpty)
        }
    }

    // Positive control (passes before): exact-address naming is not function selection.
    func testRenameAndNameAtRemainExactAddressOperations() throws {
        let api = WorkspaceScriptingAPI(store: makeStore())
        let renamed = try api.execute("rename", arguments: .object([
            "address": .hex(0x1100), "name": .string("uncovered_label")
        ]))
        XCTAssertEqual(renamed["ok"], .bool(true))
        let named = try api.execute("name-at", arguments: .object(["address": .hex(0x1100)]))
        XCTAssertEqual(named, .string("uncovered_label"))
        XCTAssertEqual(try api.execute("register-names", arguments: .object(["function": .string("helper")]))["renames"],
                       .object([:]))
    }
}
