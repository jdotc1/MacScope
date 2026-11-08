import XCTest
@testable import MacScope

/// DEF-A03, DEF-A04, DEF-A06 and DEF-A09 on the search/graph MCP surface: typed refusal of an
/// invalid regex and of an over-long query, `imageSlot` on every `search`, `callers`, `callees`
/// and `xrefs` row (and as an optional row filter) on a hermetic two-image workspace, and the
/// attached allowlist additions.
@MainActor
final class MCPSearchHygieneTests: XCTestCase {
    private let sibling = ImageSlot(rawValue: 1)
    private let callerStart: UInt64 = 0x1000
    private let calleeStart: UInt64 = 0x2000

    // MARK: - Fixture

    /// Two arm64 images whose addresses collide. Both hold a `caller` at 0x1000 and a `callee`
    /// at 0x2000 and an instruction at 0x1000 whose mnemonic is `mov`. The primary image has one
    /// call edge 0x1004 -> 0x2000; the sibling has two (0x1004 and 0x1008 -> 0x2000), so the
    /// image that answered is visible in the row count as well as in `imageSlot`.
    private func makeTwoImageStore() -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(
                id: UUID(), name: "image\(slot.rawValue)", path: "/tmp/p4-hygiene-image\(slot.rawValue)",
                kind: "Mach-O executable", architecture: "arm64", slot: slot
            )
        }
        func analysis(operands: String, callSites: [UInt64]) -> ImageAnalysis {
            var result = ImageAnalysis()
            result.functions = [
                FunctionSummary(id: UUID(), name: "caller", startAddress: callerStart,
                                endAddress: callerStart + 0x10, confidence: 1),
                FunctionSummary(id: UUID(), name: "callee", startAddress: calleeStart,
                                endAddress: calleeStart + 0x10, confidence: 1),
            ]
            result.instructions = [InstructionRow(
                address: callerStart, bytes: "e0 03 01 aa", mnemonic: "mov", operands: operands,
                hasBreakpoint: false, comment: nil
            )]
            result.xrefs = callSites.map {
                XRef(id: UUID(), from: $0, to: calleeStart, kind: XRefKind.call)
            }
            return result
        }
        let snapshot = WorkspaceSnapshot(
            binaries: [image(.primary), image(sibling)],
            analysisBySlot: [
                .primary: analysis(operands: "x0, x1", callSites: [0x1004]),
                sibling: analysis(operands: "x2, x3", callSites: [0x1004, 0x1008]),
            ]
        )
        return WorkspaceStore(
            workspaceName: "P4 hygiene", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil
        )
    }

    private func requestValue(_ name: String, _ arguments: ScriptValue) -> ScriptValue {
        .object([
            "jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
            "params": .object(["name": .string(name), "arguments": arguments]),
        ])
    }

    private func request(_ name: String, _ arguments: ScriptValue) throws -> Data {
        try requestValue(name, arguments).jsonData()
    }

    /// The decoded tool result text of a `tools/call` response, asserting it is not a tool failure.
    private func toolOutput(_ response: Data?, file: StaticString = #filePath, line: UInt = #line) throws -> ScriptValue {
        try toolOutput(envelope: try ScriptValue.decode(try XCTUnwrap(response, file: file, line: line)), file: file, line: line)
    }

    private func toolOutput(envelope: ScriptValue?, file: StaticString = #filePath, line: UInt = #line) throws -> ScriptValue {
        let envelope = try XCTUnwrap(envelope, file: file, line: line)
        XCTAssertNil(envelope["error"], file: file, line: line)
        XCTAssertEqual(envelope["result"]?["isError"], .bool(false), file: file, line: line)
        let text = try XCTUnwrap(
            envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue, file: file, line: line)
        return try ScriptValue.decode(Data(text.utf8))
    }

    private func slots(_ rows: ScriptValue?) -> [Int64] {
        (rows?.arrayValue ?? []).compactMap { $0["imageSlot"]?.intValue }
    }

    // MARK: - DEF-A09 / DEF-A03: typed refusals

    func testDirectHexRefusalPreservesAuthoritySearchBehavior() async throws {
        let api = WorkspaceScriptingAPI(store: makeTwoImageStore())
        for query in ["A", "?", "??", "GG"] {
            let arguments: ScriptValue = .object(["query": .string(query), "mode": .string("hex")])
            let detail = try XCTUnwrap(BinarySearchService().validate(query: query, mode: .hex))
            XCTAssertThrowsError(try api.execute("search", arguments: arguments)) {
                XCTAssertEqual($0 as? ScriptingError, .invalidArgument(detail))
            }
            do {
                _ = try await api.executeAsync("search", arguments: arguments)
                XCTFail("malformed hex should be refused: \(query)")
            } catch {
                XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail))
            }
            let inline = try HeadlessAutomationAuthority.execute(command: "search", arguments: arguments, api: api)
            let detached = try await HeadlessAutomationAuthority.executeAsync(command: "search", arguments: arguments, api: api)
            XCTAssertEqual(inline["results"], .array([]))
            XCTAssertNil(inline["error"])
            XCTAssertEqual(detached["results"], .array([]))
            XCTAssertNil(detached["error"])
        }
        for query in ["", "A?", "48 89", "48??"] {
            let arguments: ScriptValue = .object(["query": .string(query), "mode": .string("hex")])
            _ = try api.execute("search", arguments: arguments)
            _ = try await api.executeAsync("search", arguments: arguments)
        }
        let cursorFirst: ScriptValue = .object([
            "query": .string("GG"), "mode": .string("hex"), "cursor": .string("invalid")
        ])
        XCTAssertThrowsError(try api.execute("search", arguments: cursorFirst)) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument("cursor is accepted only by the bounded search"))
        }
        let invalidKind: ScriptValue = .object([
            "query": .string("GG"), "mode": .string("hex"), "kind": .string("function")
        ])
        XCTAssertThrowsError(try api.execute("search", arguments: invalidKind)) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument(
                "search kind must be bytes for mode hex, or instruction, string, symbol, function for text/regex"))
        }
        do {
            _ = try await api.executeAsync("search", arguments: invalidKind)
            XCTFail("invalid kind should take precedence")
        } catch {
            XCTAssertEqual(error as? ScriptingError, .invalidArgument(
                "search kind must be bytes for mode hex, or instruction, string, symbol, function for text/regex"))
        }
        let server = MCPServer(api: api)
        let malformed: ScriptValue = .object(["query": .string("GG"), "mode": .string("hex")])
        let wire = try toolOutput(await server.handleMessageAsync(try request("search", malformed)))
        XCTAssertEqual(wire["results"], .array([]))
        XCTAssertNil(wire["error"])
    }

    func testDirectSearchModeValidationOnBothRoutes() async throws {
        let api = WorkspaceScriptingAPI(store: makeTwoImageStore())
        let invalidModes: [ScriptValue] = [.string("unknown"), .int(1), .bool(true), .array([]), .object([:])]
        for mode in invalidModes {
            let arguments: ScriptValue = .object(["query": .string("mov"), "mode": mode])
            XCTAssertThrowsError(try api.execute("search", arguments: arguments)) {
                XCTAssertEqual($0 as? ScriptingError, .invalidArgument("search mode must be text, regex or hex"))
            }
            do {
                _ = try await api.executeAsync("search", arguments: arguments)
                XCTFail("invalid mode should be refused: \(mode)")
            } catch {
                XCTAssertEqual(error as? ScriptingError, .invalidArgument("search mode must be text, regex or hex"))
            }
        }
        let omitted: ScriptValue = .object(["query": .string("mov")])
        let explicitNull: ScriptValue = .object(["query": .string("mov"), "mode": .null])
        let explicitText: ScriptValue = .object(["query": .string("mov"), "mode": .string("text")])
        let inlineDefault = try api.execute("search", arguments: omitted)
        XCTAssertEqual(try api.execute("search", arguments: explicitNull), inlineDefault)
        XCTAssertEqual(try api.execute("search", arguments: explicitText), inlineDefault)
        let asyncDefault = try await api.executeAsync("search", arguments: omitted)
        let asyncNull = try await api.executeAsync("search", arguments: explicitNull)
        let asyncText = try await api.executeAsync("search", arguments: explicitText)
        XCTAssertEqual(asyncNull, asyncDefault)
        XCTAssertEqual(asyncText, asyncDefault)
        for (mode, query) in [("regex", "mov"), ("hex", "00")] {
            let arguments: ScriptValue = .object(["query": .string(query), "mode": .string(mode)])
            _ = try api.execute("search", arguments: arguments)
            _ = try await api.executeAsync("search", arguments: arguments)
        }
    }

    func testDirectSearchRejectsMalformedRegexOnBothRoutes() async throws {
        let api = WorkspaceScriptingAPI(store: makeTwoImageStore())
        let detail = try XCTUnwrap(BinarySearchService().validate(query: "[", mode: .regex))
        let malformed: ScriptValue = .object(["query": .string("["), "mode": .string("regex")])
        XCTAssertThrowsError(try api.execute("search", arguments: malformed)) {
            XCTAssertEqual($0 as? ScriptingError, .invalidArgument(detail))
        }
        do {
            _ = try await api.executeAsync("search", arguments: malformed)
            XCTFail("malformed regex should be refused")
        } catch {
            XCTAssertEqual(error as? ScriptingError, .invalidArgument(detail))
        }
        let valid: ScriptValue = .object(["query": .string("mov"), "mode": .string("regex")])
        XCTAssertGreaterThan(try XCTUnwrap(api.execute("search", arguments: valid)["total"]?.intValue), 0)
        let asyncResult = try await api.executeAsync("search", arguments: valid)
        XCTAssertGreaterThan(try XCTUnwrap(asyncResult["total"]?.intValue), 0)
    }

    func testQueryCapIs256BytesAndDocumentedInTheSchema() throws {
        XCTAssertEqual(HeadlessAutomationAuthority.maximumSearchQueryBytes, 256)
        let search = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "search" })
        let schema = HeadlessAutomationAuthority.inputSchema(for: search)
        let description = try XCTUnwrap(schema["properties"]?["query"]?["description"]?.stringValue)
        XCTAssertTrue(description.contains("256"), description)
        XCTAssertNotNil(schema["properties"]?["imageSlot"])
    }

    func testOverLongQueryIsRefusedWithTypedTooLongOnEveryTransport() async throws {
        let store = makeTwoImageStore()
        let api = WorkspaceScriptingAPI(store: store)
        let expected = ScriptValue.object(["error": .string("invalidPattern"), "detail": .string("tooLong")])
        let queries = [
            String(repeating: "a", count: 300),
            String(repeating: "\u{e9}", count: 150), // 150 characters, 300 UTF-8 bytes
            String(repeating: "a", count: 257),
        ]
        for query in queries {
            let arguments = ScriptValue.object(["query": .string(query)])
            // validate no longer throws: the refusal is a typed result, not a -32602.
            XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(command: "search", arguments: arguments))
            XCTAssertEqual(try HeadlessAutomationAuthority.execute(
                command: "search", arguments: arguments, api: api), expected)
            let asyncResult = try await HeadlessAutomationAuthority.executeAsync(
                command: "search", arguments: arguments, api: api)
            XCTAssertEqual(asyncResult, expected)
        }
        let server = MCPServer(api: api)
        let arguments = ScriptValue.object(["query": .string(String(repeating: "a", count: 300))])
        XCTAssertEqual(try toolOutput(envelope: server.handle(requestValue("search", arguments))), expected)
        let response = await server.handleMessageAsync(try request("search", arguments))
        XCTAssertEqual(try toolOutput(response), expected)
    }

    func testQueryAtTheCapAndTrimmedQueriesAreNotRefused() throws {
        let api = WorkspaceScriptingAPI(store: makeTwoImageStore())
        let atCap = String(repeating: "a", count: 256)
        for query in [atCap, "   " + atCap + "\n\n  "] {
            let output = try HeadlessAutomationAuthority.execute(
                command: "search", arguments: .object(["query": .string(query)]), api: api)
            XCTAssertNil(output["error"], query)
            XCTAssertEqual(output["total"], .int(0))
            XCTAssertEqual(output["results"], .array([]))
        }
    }

    func testInvalidRegexIsATypedRefusalNotAnEmptyResult() async throws {
        let api = WorkspaceScriptingAPI(store: makeTwoImageStore())
        let arguments = ScriptValue.object(["query": .string("(unclosed"), "mode": .string("regex")])
        let inline = try HeadlessAutomationAuthority.execute(command: "search", arguments: arguments, api: api)
        let detached = try await HeadlessAutomationAuthority.executeAsync(
            command: "search", arguments: arguments, api: api)
        XCTAssertEqual(inline["error"], .string("invalidPattern"))
        XCTAssertEqual(inline["detail"], .string("Invalid regular expression."))
        XCTAssertNil(inline["results"])
        XCTAssertEqual(detached, inline)

        let server = MCPServer(api: api)
        let response = await server.handleMessageAsync(try request("search", arguments))
        XCTAssertEqual(try toolOutput(response), inline)

        // The same text in text mode is a literal search, and a valid regex still searches.
        let literal = try HeadlessAutomationAuthority.execute(
            command: "search", arguments: .object(["query": .string("(unclosed")]), api: api)
        XCTAssertNil(literal["error"])
        XCTAssertEqual(literal["results"], .array([]))
        let valid = try HeadlessAutomationAuthority.execute(
            command: "search", arguments: .object(["query": .string("^mov\\b"), "mode": .string("regex")]), api: api)
        XCTAssertNil(valid["error"])
        XCTAssertEqual(slots(valid["results"]), [0, 1])
    }

    // MARK: - DEF-A04: imageSlot on rows, and as a filter

    func testSearchOnTwoImagesTagsEveryRowWithItsImage() async throws {
        let store = makeTwoImageStore()
        let api = WorkspaceScriptingAPI(store: store)
        let arguments = ScriptValue.object(["query": .string("mov")])
        let inline = try api.execute("search", arguments: arguments)
        XCTAssertEqual(inline["results"]?.arrayValue?.count, 2)
        XCTAssertEqual(slots(inline["results"]), [0, 1])
        XCTAssertEqual(inline["results"]?.arrayValue?.map { $0["preview"]?.stringValue },
                       ["mov x0, x1", "mov x2, x3"])
        XCTAssertEqual(inline["results"]?.arrayValue?.first, .object([
            "address": .hex(callerStart), "kind": .string("instruction"),
            "preview": .string("mov x0, x1"), "imageSlot": .int(0),
        ]))

        // The detached (MCP default) handler emits the same rows as the inline handler.
        let detached = try await api.executeAsync("search", arguments: arguments)
        XCTAssertEqual(detached["results"], inline["results"])
        let server = MCPServer(api: api)
        let viaServer = try toolOutput(await server.handleMessageAsync(try request("search", arguments)))
        XCTAssertEqual(viaServer["results"], inline["results"])
    }

    func testSearchImageSlotFilterRestrictsToOneImageAndRejectsUnknownSlots() async throws {
        let store = makeTwoImageStore()
        let api = WorkspaceScriptingAPI(store: store)
        for slot in [0, 1] {
            let arguments = ScriptValue.object(["query": .string("mov"), "imageSlot": .int(Int64(slot))])
            let inline = try api.execute("search", arguments: arguments)
            let detached = try await api.executeAsync("search", arguments: arguments)
            XCTAssertEqual(slots(inline["results"]), [Int64(slot)])
            XCTAssertEqual(inline["total"], .int(1))
            XCTAssertEqual(detached["results"], inline["results"])
        }
        // A decimal-string selector names the same image.
        let byString = try api.execute("search", arguments: .object([
            "query": .string("mov"), "imageSlot": .string("1"),
        ]))
        XCTAssertEqual(slots(byString["results"]), [1])
        // The filter is a row filter: the focused image does not change what an unfiltered search sees.
        store.focusImage(sibling)
        XCTAssertEqual(slots(try api.execute("search", arguments: .object(["query": .string("mov")]))["results"]), [0, 1])

        let unknown = ScriptValue.object(["query": .string("mov"), "imageSlot": .int(7)])
        XCTAssertThrowsError(try api.execute("search", arguments: unknown)) { error in
            XCTAssertEqual(error as? ScriptingError, .unknownImage(selector: "7", validSlots: [0, 1]))
        }
        do {
            _ = try await api.executeAsync("search", arguments: unknown)
            XCTFail("an unknown imageSlot returned rows")
        } catch {
            XCTAssertEqual(error as? ScriptingError, .unknownImage(selector: "7", validSlots: [0, 1]))
        }
    }

    func testImageSlotShapeIsValidatedAtTheAuthority() {
        for bad in [ScriptValue.bool(true), .double(1.5), .array([]), .string(String(repeating: "7", count: 65)), .int(-1)] {
            XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(
                command: "callers", arguments: .object(["address": .hex(calleeStart), "imageSlot": bad])), "\(bad)")
        }
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(
            command: "callers", arguments: .object(["address": .hex(calleeStart), "imageSlot": .int(1)])))
    }

    func testCallersCalleesAndXRefsCarryAndHonourImageSlot() async throws {
        let api = WorkspaceScriptingAPI(store: makeTwoImageStore())
        // (command, arguments without a filter, rows in the primary image, rows in the sibling)
        let cases: [(String, [String: ScriptValue], Int, Int)] = [
            ("callers", ["address": .hex(calleeStart)], 1, 2),
            ("callees", ["function": .string("caller")], 1, 2),
            ("xrefs", ["to": .hex(calleeStart)], 1, 2),
        ]
        for (command, base, primaryCount, siblingCount) in cases {
            let unfiltered = try api.execute(command, arguments: .object(base))
            XCTAssertEqual(unfiltered.arrayValue?.count, primaryCount, command)
            XCTAssertEqual(slots(unfiltered), Array(repeating: 0, count: primaryCount), command)

            var filtered = base
            filtered["imageSlot"] = .int(1)
            let inline = try api.execute(command, arguments: .object(filtered))
            XCTAssertEqual(inline.arrayValue?.count, siblingCount, command)
            XCTAssertEqual(slots(inline), Array(repeating: 1, count: siblingCount), command)

            filtered["imageSlot"] = .int(0)
            XCTAssertEqual(try api.execute(command, arguments: .object(filtered)), unfiltered, command)

            // The detached/attached row builders emit the same JSON as the inline handlers.
            for arguments in [base, base.merging(["imageSlot": ScriptValue.int(1)]) { $1 }] {
                let detached = try await api.executeAsync(command, arguments: .object(arguments))
                let expected = try api.execute(command, arguments: .object(arguments))
                XCTAssertEqual(try detached.jsonData(), try expected.jsonData(), command)
            }
        }
        let edge = try api.execute("callers", arguments: .object(["address": .hex(calleeStart), "imageSlot": .int(1)]))
        XCTAssertEqual(edge.arrayValue?.first, .object([
            "from": .hex(0x1004), "to": .hex(calleeStart), "imageSlot": .int(1),
            "toName": .string("callee"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("caller"),
        ]))
        let ref = try api.execute("xrefs", arguments: .object(["to": .hex(calleeStart)]))
        XCTAssertEqual(ref.arrayValue?.first?["kind"], .string(XRefKind.call))
    }

    // MARK: - DEF-A06: attached allowlist

    func testAttachedAllowlistAdmitsMaterialisedReadsAndExcludesFreshAnalysis() throws {
        let added: Set<String> = ["read-evidence", "reconstruction-jobs"]
        XCTAssertTrue(added.isSubset(of: MCPAttachExecutor.attachCommands))
        let infos = WorkspaceScriptingAPI.availableCommands.filter { added.contains($0.name) }
        XCTAssertEqual(Set(infos.map(\.name)), added)
        XCTAssertTrue(infos.allSatisfy { !$0.mutates }, "an admitted read must not mutate")
        let headless = Set(HeadlessAutomationAuthority.availableCommands.map(\.name))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.isSubset(of: headless))
        // Commands with a stated exclusion reason stay excluded.
        for excluded in ["neon-hitrate", "call-argument-audit", "define-types-from-c", "goto", "open-workspace",
                         "save-workspace", "make-procedure", "rebase-segment"] {
            XCTAssertFalse(MCPAttachExecutor.attachCommands.contains(excluded), excluded)
        }
        // The attached catalogue lists them.
        let catalogue = MCPAttachExecutor.attachCatalog(.array(infos.map {
            .object(["name": .string($0.name)])
        }))
        XCTAssertEqual(catalogue.arrayValue?.count, added.count)
    }

    func testAttachedExecutorServesTheAdditionsAndTheTypedSearchRefusal() async throws {
        let store = makeTwoImageStore()
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let jobs = try await executor.execute("reconstruction-jobs", .object([:]))
        XCTAssertEqual(jobs, .array([]))
        let evidence = try await executor.execute("read-evidence", .object(["operation": .string("workspace.summary")]))
        XCTAssertEqual(evidence["proposingPrincipal"], .string("mcp"))
        XCTAssertEqual(evidence["authorizingPrincipal"], .string("app"))
        let refusal = try await executor.execute("search", .object(["query": .string(String(repeating: "a", count: 300))]))
        XCTAssertEqual(refusal, .object(["error": .string("invalidPattern"), "detail": .string("tooLong")]))
        let rows = try await executor.execute("search", .object(["query": .string("mov"), "imageSlot": .int(1)]))
        XCTAssertEqual(slots(rows["results"]), [1])
        let callers = try await executor.execute("callers", .object(["address": .hex(calleeStart), "imageSlot": .int(1)]))
        XCTAssertEqual(slots(callers), [1, 1])
    }

    private func contextualRefusal(_ address: UInt64, nearest: String?, start: UInt64?,
                                   section: MCPRefusalSection?, slot: Int) -> ScriptingError {
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

    // Exact-target stub references now carry the containing source function.
    func test859UncoveredStubReturnsExactSitesOnEveryCallersPathAndImage() async throws {
        let store = make859Store()
        let api = WorkspaceScriptingAPI(store: store)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)

        for slot in [0, 1] {
            let sources: [UInt64] = slot == 0 ? [0x1004] : [0x1000, 0x1004]
            let expected = ScriptValue.array(sources.map {
                .object(["from": .hex($0), "to": .hex(0x2000), "imageSlot": .int(Int64(slot)),
                         "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main"), "toName": .null])
            })
            var fields: [String: ScriptValue] = ["address": .hex(0x2000)]
            if slot == 1 { fields["imageSlot"] = .int(1) }
            let arguments = ScriptValue.object(fields)
            XCTAssertEqual(try api.execute("callers", arguments: arguments), expected)
            let detached = try await api.executeAsync("callers", arguments: arguments)
            XCTAssertEqual(detached, expected)
            let attachedRows = try await attached.execute("callers", arguments)
            XCTAssertEqual(attachedRows, expected)

            let server = MCPServer(api: api)
            let inlineEnvelope = try XCTUnwrap(server.handle(requestValue("callers", arguments)))
            let response = await server.handleMessageAsync(try request("callers", arguments))
            let asyncEnvelope = try ScriptValue.decode(try XCTUnwrap(response))
            for envelope in [inlineEnvelope, asyncEnvelope] {
                XCTAssertNil(envelope["error"])
                XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
                let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), expected)
            }

            // The exact-target xref query remains usable and retains its own row shape.
            var exactFields: [String: ScriptValue] = ["to": .hex(0x2000)]
            if slot == 1 { exactFields["imageSlot"] = .int(1) }
            let exact = try api.execute("xrefs", arguments: .object(exactFields))
            XCTAssertEqual(exact.arrayValue?.count, slot + 1)
            XCTAssertEqual(slots(exact), Array(repeating: Int64(slot), count: slot + 1))
            XCTAssertTrue(try XCTUnwrap(exact.arrayValue).allSatisfy {
                $0["to"] == .hex(0x2000) && $0["kind"] == .string(XRefKind.call)
            })
        }
    }

    // Positive controls (pass before): start, interior, name and name precedence.
    func test859ContainingFunctionSelectorsKeepRowsOnEveryPath() async throws {
        let store = make859Store()
        let api = WorkspaceScriptingAPI(store: store)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        let selectors: [[String: ScriptValue]] = [
            ["address": .hex(0x1008)],
            ["address": .hex(0x1009)],
            ["function": .string("helper")],
            ["function": .string("helper"), "address": .hex(0x2000)],
        ]
        for slot in [0, 1] {
            let starts: [UInt64] = slot == 0 ? [0x1004] : [0x1000, 0x1004]
            let expected = ScriptValue.array(starts.map {
                .object(["from": .hex($0), "to": .hex(0x1008), "imageSlot": .int(Int64(slot)),
                         "toName": .string("helper"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main")])
            })
            for var fields in selectors {
                if slot == 1 { fields["imageSlot"] = .int(1) }
                let arguments = ScriptValue.object(fields)
                XCTAssertEqual(try api.execute("callers", arguments: arguments), expected)
                let detached = try await api.executeAsync("callers", arguments: arguments)
                XCTAssertEqual(detached, expected)
                let attachedRows = try await attached.execute("callers", arguments)
                XCTAssertEqual(attachedRows, expected)
            }
        }
    }

    // Fails before the fix for gaps/end/padding and below-first: every uncovered address
    // refuses with the contextual function-address refusal.
    func test859AddressBoundariesRefuseRatherThanFallBack() async throws {
        let api = WorkspaceScriptingAPI(store: make859Store(includeBoundaryFunctions: true))
        let text = MCPRefusalSection(name: "__TEXT,__text", start: 0x1000, end: 0x1200)
        let cases: [(UInt64, String?, UInt64?, MCPRefusalSection?)] = [
            (0x0ffc, nil, nil, nil),
            (0x100c, "helper", 0x1008, text),
            (0x1010, "helper", 0x1008, text),
            (0x3004, "later", 0x3000, nil),
            (0x4001, "zero", 0x4000, nil),
            (0x5000, "zero", 0x4000, nil),
        ]
        for (address, nearest, start, section) in cases {
            let expected = contextualRefusal(address, nearest: nearest, start: start, section: section, slot: 0)
            let arguments = ScriptValue.object(["address": .hex(address)])
            XCTAssertThrowsError(try api.execute("callers", arguments: arguments)) {
                XCTAssertEqual($0 as? ScriptingError, expected)
            }
            do {
                _ = try await api.executeAsync("callers", arguments: arguments)
                XCTFail("address outside all half-open ranges must refuse")
            } catch { XCTAssertEqual(error as? ScriptingError, expected) }
        }
        let stubArguments = ScriptValue.object(["address": .hex(0x2000)])
        let stubRows = ScriptValue.array([.object([
            "from": .hex(0x1004), "to": .hex(0x2000), "imageSlot": .int(0),
            "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main"), "toName": .null,
        ])])
        XCTAssertEqual(try api.execute("callers", arguments: stubArguments), stubRows)
        let stubAsync = try await api.executeAsync("callers", arguments: stubArguments)
        XCTAssertEqual(stubAsync, stubRows)
        // Positive control: preserve the established single-address zero-width rule.
        let arguments = ScriptValue.object(["address": .hex(0x4000)])
        let expected = ScriptValue.array([
            .object(["from": .hex(0x1000), "to": .hex(0x4000), "imageSlot": .int(0),
                     "toName": .string("zero"), "fromFunction": .hex(0x1000), "fromFunctionName": .string("_main")])
        ])
        XCTAssertEqual(try api.execute("callers", arguments: arguments), expected)
        let detached = try await api.executeAsync("callers", arguments: arguments)
        XCTAssertEqual(detached, expected)
    }

    // Fails before the fix: discovery must describe the stricter address contract.
    func test859CallersSchemaDocumentsContainmentAndExactXRefAlternative() throws {
        let info = try XCTUnwrap(HeadlessAutomationAuthority.availableCommands.first { $0.name == "callers" })
        let schema = HeadlessAutomationAuthority.inputSchema(for: info)
        let description = try XCTUnwrap(schema["properties"]?["address"]?["description"]?.stringValue)
        XCTAssertTrue(description.contains("inside a known function"))
        XCTAssertTrue(description.contains("xrefs with to"))
        XCTAssertTrue(description.contains("zero-width"))
    }

    private func make859Store(includeBoundaryFunctions: Bool = false) -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "stub-fixture", path: "/fixture",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        func analysis(_ slot: ImageSlot) -> ImageAnalysis {
            var value = ImageAnalysis()
            value.functions = [
                FunctionSummary(id: UUID(), name: "_main", startAddress: 0x1000,
                                endAddress: 0x1008, confidence: 1),
                FunctionSummary(id: UUID(), name: "helper", startAddress: 0x1008,
                                endAddress: 0x100c, confidence: 1),
            ]
            let sources: [UInt64] = slot == .primary ? [0x1004] : [0x1000, 0x1004]
            value.xrefs = sources.map {
                XRef(id: UUID(), from: $0, to: 0x1008, kind: XRefKind.call)
            } + sources.map {
                XRef(id: UUID(), from: $0, to: 0x2000, kind: XRefKind.call)
            }
            value.sections = [
                SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                               size: 0x200, fileOffset: 0, isExecutable: true),
                SectionSummary(id: UUID(), name: "__TEXT,__objc_stubs", address: 0x2000,
                               size: 0x40, fileOffset: 0x200, isExecutable: true),
            ]
            if includeBoundaryFunctions {
                value.functions += [
                    FunctionSummary(id: UUID(), name: "later", startAddress: 0x3000,
                                    endAddress: 0x3004, confidence: 1),
                    FunctionSummary(id: UUID(), name: "zero", startAddress: 0x4000,
                                    endAddress: 0x4000, confidence: 1),
                ]
                value.xrefs.append(XRef(id: UUID(), from: 0x1000, to: 0x4000, kind: XRefKind.call))
            }
            return value
        }
        let snapshot = WorkspaceSnapshot(
            binaries: [image(.primary), image(sibling)],
            analysisBySlot: [.primary: analysis(.primary), sibling: analysis(sibling)])
        return WorkspaceStore(workspaceName: "callers containment", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}
