import Foundation
import XCTest
@testable import MacScope

private struct E2NativeStub: ScriptingNativeDecompiling {
    let text: String
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        .completed(.init(text: text, language: "c", isComplete: true, isTruncated: false))
    }
}

/// E2: authored comments and call-target renames in pseudocode. Test names carry the DESIGN SPEC row.
@MainActor
final class E2UserCommentsTests: XCTestCase {
    // MARK: fixtures

    private static let straight: [InstructionRow] = [
        InstructionRow(address: 0x1000, bytes: "20 00 80 d2", mnemonic: "mov", operands: "x0, #0x1", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1004, bytes: "41 00 80 d2", mnemonic: "mov", operands: "x1, #0x2", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1008, bytes: "00 00 01 8b", mnemonic: "add", operands: "x0, x0, x1", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x100c, bytes: "02 00 80 d2", mnemonic: "mov", operands: "x2, #0x7", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1010, bytes: "e3 03 00 aa", mnemonic: "mov", operands: "x3, x0", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1014, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
    ]

    private static let branching: [InstructionRow] = [
        InstructionRow(address: 0x1000, bytes: "1f 00 00 f1", mnemonic: "cmp", operands: "x0, #0x0", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1004, bytes: "60 00 00 54", mnemonic: "b.eq", operands: "0x1010", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1008, bytes: "21 00 80 d2", mnemonic: "mov", operands: "x1, #0x1", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x100c, bytes: "42 00 80 d2", mnemonic: "mov", operands: "x2, #0x2", hasBreakpoint: false, comment: nil),
        InstructionRow(address: 0x1010, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
    ]

    private func printed(_ rows: [InstructionRow], comments: [UInt64: String] = [:]) -> PseudocodeDocument {
        let function = MacIRBuilder().buildFunction(name: "_f", instructions: rows)
        return PseudocodePrinter().print(
            function: function,
            userComments: PseudocodeUserComments(
                textByAddress: comments, bodyAddresses: Set(rows.map(\.address))))
    }

    /// First statement addresses actually emitted, ascending.
    private func emittedAddresses(_ document: PseudocodeDocument) -> [UInt64] {
        var seen: [UInt64] = []
        for line in document.lines { if let a = line.sourceAddress, !seen.contains(a) { seen.append(a) } }
        return seen.sorted()
    }

    private func flatten(_ nodes: [PseudocodeRegionNode]) -> [PseudocodeRegionNode] {
        nodes.flatMap { [$0] + flatten($0.children) }
    }

    private func makeStore(extra: [UInt64: AddressOverride] = [:], symbols: [SymbolSummary] = [],
                           instructions: [InstructionRow]? = nil, end: UInt64 = 0x1018) -> WorkspaceStore {
        let mainID = UUID()
        var snapshot = WorkspaceSnapshot(
            binaries: [BinaryImage(id: UUID(), name: "e2", path: "/tmp/e2", kind: "Mach-O executable", architecture: "arm64")],
            functions: [FunctionSummary(id: mainID, name: "_main", startAddress: 0x1000, endAddress: end, confidence: 1)],
            basicBlocks: [BasicBlockSummary(id: UUID(), functionID: mainID, startAddress: 0x1000,
                                           endAddress: end, instructionCount: 6)],
            instructions: instructions ?? Self.straight,
            xrefs: [], controlFlowEdges: [], hexBytes: Data(),
            sections: [SectionSummary(id: UUID(), name: "__TEXT,__text", address: 0x1000,
                                     size: 0x4000, fileOffset: 0x1000, isExecutable: true)])
        snapshot.symbols = symbols
        for (address, override) in extra { snapshot.addressOverrides[snapshot.key(address)] = override }
        return WorkspaceStore(workspaceName: "e2", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func decompile(_ api: WorkspaceScriptingAPI, _ extra: [String: ScriptValue] = [:]) throws -> ScriptValue {
        try api.execute("decompile", arguments: .object(["function": .string("_main")].merging(extra) { _, n in n }))
    }

    private func setComment(_ api: WorkspaceScriptingAPI, _ address: UInt64, _ text: String) throws {
        _ = try api.execute("set-comment", arguments: .object(["address": .hex(address), "comment": .string(text)]))
    }

    // MARK: U1-U4, U8 (printer level)

    func testU1CommentRendersAboveFirstStatementWithNilSourceAndRenumbers() throws {
        let base = printed(Self.straight)
        let target = try XCTUnwrap(emittedAddresses(base).dropFirst(2).first)
        let withComment = printed(Self.straight, comments: [target: "hello"])
        let index = try XCTUnwrap(withComment.lines.firstIndex { $0.sourceAddress == target })
        let inserted = withComment.lines[index - 1]
        XCTAssertNil(inserted.source)
        XCTAssertEqual(inserted.text.trimmingCharacters(in: .whitespaces), "// hello")
        XCTAssertEqual(withComment.lines.count, base.lines.count + 1)
        XCTAssertEqual(withComment.lines.map(\.lineNumber), Array(1...withComment.lines.count))
        XCTAssertEqual(withComment.placedCommentCount, 1)
        XCTAssertTrue(withComment.unplacedComments.isEmpty)
        XCTAssertEqual(withComment.lines(sourcedAt: target).count, base.lines(sourcedAt: target).count)
        for line in withComment.lines { for token in line.tokens { XCTAssertEqual(token.lineNumber, line.lineNumber) } }
    }

    func testU2NoCommentsIsByteIdenticalToTheUncommentedPrint() {
        for rows in [Self.straight, Self.branching] {
            let function = MacIRBuilder().buildFunction(name: "_f", instructions: rows)
            let plain = PseudocodePrinter().print(function: function)
            let none = PseudocodePrinter().print(function: function, userComments: .none)
            XCTAssertEqual(plain.text, none.text)
            XCTAssertEqual(plain.lines, none.lines)
            XCTAssertEqual(plain.regionTree, none.regionTree)
            XCTAssertTrue(none.unplacedComments.isEmpty)
            XCTAssertEqual(none.placedCommentCount, 0)
        }
    }

    func testU3TwoCommentsKeepAddressOrderAndEachSitsAboveItsOwnStatement() throws {
        let addresses = emittedAddresses(printed(Self.straight))
        let a = try XCTUnwrap(addresses.dropFirst(1).first), b = try XCTUnwrap(addresses.dropFirst(2).first)
        let document = printed(Self.straight, comments: [b: "second", a: "first\nsecond line"])
        let ia = try XCTUnwrap(document.lines.firstIndex { $0.sourceAddress == a })
        let ib = try XCTUnwrap(document.lines.firstIndex { $0.sourceAddress == b })
        XCTAssertEqual(document.lines[ia - 2].text.trimmingCharacters(in: .whitespaces), "// first")
        XCTAssertEqual(document.lines[ia - 1].text.trimmingCharacters(in: .whitespaces), "// second line")
        XCTAssertEqual(document.lines[ib - 1].text.trimmingCharacters(in: .whitespaces), "// second")
        XCTAssertLessThan(ia, ib)
        XCTAssertEqual(document.placedCommentCount, 2)
    }

    func testU4RegionsAndTokensAreRemappedAfterInsertion() throws {
        let base = printed(Self.branching)
        let target = try XCTUnwrap(emittedAddresses(base).first)
        let withComment = printed(Self.branching, comments: [target: "top"])
        let before = flatten(base.regionTree.map { [$0] } ?? []), after = flatten(withComment.regionTree.map { [$0] } ?? [])
        XCTAssertEqual(before.count, after.count)
        for (old, new) in zip(before, after) {
            XCTAssertEqual(old.kind, new.kind)
            XCTAssertEqual(base.lines[old.startLine - 1].text, withComment.lines[new.startLine - 1].text)
            XCTAssertEqual(base.lines[old.endLine - 1].text, withComment.lines[new.endLine - 1].text)
        }
        for line in withComment.lines { for token in line.tokens { XCTAssertEqual(token.lineNumber, line.lineNumber) } }
    }

    func testU8ControlCharactersAndSeparatorsNeverReachOutputRaw() throws {
        let target = try XCTUnwrap(emittedAddresses(printed(Self.straight)).first)
        let document = printed(Self.straight, comments: [target: "a\nb\u{2028}c\u{1}d\r\ne"])
        let text = document.text
        for bad in ["\u{2028}", "\u{2029}", "\u{85}", "\u{1}"] { XCTAssertFalse(text.contains(bad)) }
        let index = try XCTUnwrap(document.lines.firstIndex { $0.sourceAddress == target })
        XCTAssertEqual(document.lines[(index - 3)..<index].map { $0.text.trimmingCharacters(in: .whitespaces) },
                       ["// a", "// b c d", "// e"])
        XCTAssertTrue(document.lines[(index - 3)..<index].allSatisfy { $0.source == nil })
    }

    func testU5U6UnplacedReasonsAreStructuredAndTextIntact() throws {
        let document = printed(Self.straight, comments: [0x1002: "mid-instruction", 0x2000: "far"])
        XCTAssertEqual(document.placedCommentCount, 0)
        XCTAssertEqual(document.unplacedComments.map(\.address), [0x1002, 0x2000])
        XCTAssertEqual(document.unplacedComments.first?.text, "mid-instruction")
        XCTAssertEqual(document.unplacedComments.first?.reason, .noInstruction)
        let function = MacIRBuilder().buildFunction(name: "_f", instructions: Self.straight)
        let excluded = PseudocodePrinter().print(function: function, userComments: PseudocodeUserComments(
            textByAddress: [0x1002: "pool"], bodyAddresses: [0x1002], excludedAddresses: [0x1002]))
        XCTAssertEqual(excluded.unplacedComments.first?.reason, .excludedFromCode)
        let folded = PseudocodePrinter().print(function: function, userComments: PseudocodeUserComments(
            textByAddress: [0x1fff0: "folded"], bodyAddresses: [0x1fff0]))
        XCTAssertEqual(folded.unplacedComments.first?.reason, .folded)
    }

    // MARK: U7, U9, U10, U14 (scripting)

    func testU7CommentOutsideTheFunctionRangeIsNotInTheReply() throws {
        let store = makeStore(extra: [0x9000: AddressOverride(customComment: "elsewhere")])
        let reply = try decompile(WorkspaceScriptingAPI(store: store))
        XCTAssertNil(reply["unplacedComments"]); XCTAssertNil(reply["commentsTotal"])
        XCTAssertFalse(try XCTUnwrap(reply["pseudocode"]?.stringValue).contains("elsewhere"))
    }

    func testU9OverCountCapIsAtomicTypedBudgetRefusal() throws {
        var extra: [UInt64: AddressOverride] = [:]
        for i in 0..<(WorkspaceScriptingAPI.maximumUserCommentsPerDecompile + 1) {
            extra[0x1000 + UInt64(i)] = AddressOverride(customComment: "c")
        }
        let store = makeStore(extra: extra, end: 0x1000 + 0x2000)
        do {
            _ = try decompile(WorkspaceScriptingAPI(store: store)); XCTFail("expected refusal")
        } catch ScriptingError.structuredRefusal(let refusal) {
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget?.limit, Int64(WorkspaceScriptingAPI.maximumUserCommentsPerDecompile))
        }
    }

    func testU9AtTheCapIsServed() throws {
        var extra: [UInt64: AddressOverride] = [:]
        for i in 0..<WorkspaceScriptingAPI.maximumUserCommentsPerDecompile {
            extra[0x1000 + UInt64(i)] = AddressOverride(customComment: "c")
        }
        let store = makeStore(extra: extra, end: 0x1000 + 0x2000)
        XCTAssertNotNil(try decompile(WorkspaceScriptingAPI(store: store))["pseudocode"])
    }

    func testU10OverByteCapIsAtomicTypedBudgetRefusal() throws {
        let big = String(repeating: "x", count: WorkspaceScriptingAPI.maximumUserCommentBytesPerDecompile + 1)
        let store = makeStore(extra: [0x1004: AddressOverride(customComment: big)])
        do {
            _ = try decompile(WorkspaceScriptingAPI(store: store)); XCTFail("expected refusal")
        } catch ScriptingError.structuredRefusal(let refusal) {
            XCTAssertEqual(refusal.code, .budgetExceeded)
            XCTAssertEqual(refusal.budget?.limit, Int64(WorkspaceScriptingAPI.maximumUserCommentBytesPerDecompile))
        }
    }

    func testU14CommentOnAnotherSlotNeverAppearsInThePrimaryDecompile() throws {
        var store = makeStore()
        var snapshot = store.snapshot
        snapshot.addressOverrides[ImageAddress(slot: ImageSlot(rawValue: 1), address: 0x1008)] =
            AddressOverride(customComment: "sibling-only")
        store = WorkspaceStore(workspaceName: "e2", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
        let reply = try decompile(WorkspaceScriptingAPI(store: store))
        XCTAssertFalse(try XCTUnwrap(reply["pseudocode"]?.stringValue).contains("sibling-only"))
        XCTAssertNil(reply["commentsTotal"])
    }

    // MARK: U12, U13, U16, U17

    func testU1U13SetCommentThenUndoRedoDropsAndRegainsTheComment() throws {
        let store = makeStore(); let api = WorkspaceScriptingAPI(store: store)
        let g0 = store.snapshot.analysisGenerationID
        let plain = try XCTUnwrap(try decompile(api)["pseudocode"]?.stringValue)
        try setComment(api, 0x1008, "MARKER_X")
        let g1 = store.snapshot.analysisGenerationID
        XCTAssertNotEqual(g0, g1)
        let withX = try decompile(api)
        XCTAssertTrue(try XCTUnwrap(withX["pseudocode"]?.stringValue).contains("// MARKER_X"))
        XCTAssertEqual(withX["commentsTotal"], .int(1))
        store.undoManager.undo()
        let g2 = store.snapshot.analysisGenerationID
        XCTAssertNotEqual(g1, g2)
        XCTAssertEqual(try decompile(api)["pseudocode"]?.stringValue, plain)
        store.undoManager.redo()
        XCTAssertNotEqual(store.snapshot.analysisGenerationID, g2)
        XCTAssertTrue(try XCTUnwrap(try decompile(api)["pseudocode"]?.stringValue).contains("// MARKER_X"))
    }

    func testU12LineCountIncludesCommentLinesAndPagingStillWorks() throws {
        let store = makeStore(); let api = WorkspaceScriptingAPI(store: store)
        let before = try XCTUnwrap(try decompile(api, ["format": .string("lines")])["lineCount"])
        try setComment(api, 0x1008, "one\ntwo")
        let after = try XCTUnwrap(try decompile(api, ["format": .string("lines")])["lineCount"])
        guard case .int(let b) = before, case .int(let a) = after else { return XCTFail("lineCount") }
        XCTAssertEqual(a, b + 2)
    }

    func testU15U16NativeIsRefusedAndMacIRServedWithUserCommentsCause() async throws {
        let store = makeStore(); let api = WorkspaceScriptingAPI(store: store, nativeDecompiler: E2NativeStub(text: "native body"))
        try setComment(api, 0x1008, "MARKER_X")
        do {
            _ = try await api.executeAsync("decompile", arguments: .object(["function": .string("_main"), "backend": .string("native")]))
            XCTFail("expected typed refusal")
        } catch { XCTAssertNotNil(error as? ScriptingError) }
        let served = try await api.executeAsync("decompile", arguments: .object(["function": .string("_main")]))
        XCTAssertEqual(served["backend"], .string("macir"))
        XCTAssertEqual(served["fallbackCause"], .string("user-comments"))
        XCTAssertTrue(try XCTUnwrap(served["pseudocode"]?.stringValue).contains("MARKER_X"))
        let both = try await api.executeAsync("decompile", arguments: .object(["function": .string("_main"), "backend": .string("both")]))
        XCTAssertEqual(both["native"]?["pseudocode"]?.stringValue, "native body")
    }

    func testU17CommentEditChangesPseudocodeRenderInputEquality() throws {
        let store = makeStore(); let api = WorkspaceScriptingAPI(store: store)
        store.selectInstruction(0x1000)
        let before = store.focusedPseudocodeRenderInput
        try setComment(api, 0x1008, "gui")
        let after = store.focusedPseudocodeRenderInput
        XCTAssertNotEqual(before, after)
        XCTAssertEqual(before.userComments, [:])
        XCTAssertEqual(after.userComments[0x1008], "gui")
    }

    // MARK: R2-R6

    func testR2ValidIdentifierRendersVerbatim() {
        XCTAssertEqual(CallTargetRenderName.rendered("msgSend_isRichText"), "msgSend_isRichText")
    }

    func testR3InvalidNamesEscapeDeterministically() {
        XCTAssertEqual(CallTargetRenderName.rendered("a b"), "a_x20b")
        XCTAssertEqual(CallTargetRenderName.rendered("1x"), "_1x")
        XCTAssertEqual(CallTargetRenderName.rendered("\u{e9}"), "_xC3_xA9")
        let long = CallTargetRenderName.rendered(String(repeating: "a b", count: 60))
        XCTAssertLessThanOrEqual(long.utf8.count, 128)
        XCTAssertEqual(long, CallTargetRenderName.rendered(String(repeating: "a b", count: 60)))
        XCTAssertNotEqual(long, CallTargetRenderName.rendered(String(repeating: "a b", count: 61)))
    }

    private func stubStore(names: [UInt64: String], symbols: [(UInt64, String)]) -> WorkspaceStore {
        let rows = [
            InstructionRow(address: 0x1000, bytes: "00 00 00 94", mnemonic: "bl", operands: "0x2000", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1004, bytes: "00 00 00 94", mnemonic: "bl", operands: "0x2010", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1008, bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil),
        ]
        var extra: [UInt64: AddressOverride] = [:]
        for (a, n) in names { extra[a] = AddressOverride(customName: n) }
        return makeStore(extra: extra, symbols: symbols.map {
            SymbolSummary(id: UUID(), name: $0.1, address: $0.0, kind: "stub", libraryName: nil)
        }, instructions: rows, end: 0x100c)
    }

    func testR1R2RenamedStubShowsAtTheCallAndUndoRestores() throws {
        let store = stubStore(names: [:], symbols: [(0x2000, "_orig_a"), (0x2010, "_orig_b")])
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertTrue(try XCTUnwrap(try decompile(api)["pseudocode"]?.stringValue).contains("_orig_a"))
        _ = try api.execute("rename", arguments: .object(["address": .hex(0x2000), "name": .string("msgSend_isRichText")]))
        let renamed = try XCTUnwrap(try decompile(api)["pseudocode"]?.stringValue)
        XCTAssertTrue(renamed.contains("msgSend_isRichText"), renamed)
        XCTAssertFalse(renamed.contains("_orig_a"))
        store.undoManager.undo()
        XCTAssertTrue(try XCTUnwrap(try decompile(api)["pseudocode"]?.stringValue).contains("_orig_a"))
        store.undoManager.redo()
        XCTAssertTrue(try XCTUnwrap(try decompile(api)["pseudocode"]?.stringValue).contains("msgSend_isRichText"))
    }

    func testR3EscapedNameIsDisclosedWithStoredAndRendered() throws {
        let store = stubStore(names: [0x2000: "a b"], symbols: [(0x2000, "_orig_a"), (0x2010, "_orig_b")])
        let reply = try decompile(WorkspaceScriptingAPI(store: store))
        let entry = try XCTUnwrap(reply["callTargetNames"]?.arrayValue?.first)
        XCTAssertEqual(entry["stored"], .string("a b")); XCTAssertEqual(entry["rendered"], .string("a_x20b"))
        XCTAssertEqual(entry["reasons"], .array([.string("escaped")]))
        XCTAssertTrue(try XCTUnwrap(reply["pseudocode"]?.stringValue).contains("a_x20b"))
    }

    func testR4TwoStubsRenamedToTheSameNameLowestAddressKeepsIt() throws {
        let store = stubStore(names: [0x2000: "dup", 0x2010: "dup"], symbols: [(0x2000, "_a"), (0x2010, "_b")])
        let reply = try decompile(WorkspaceScriptingAPI(store: store))
        let entries = try XCTUnwrap(reply["callTargetNames"]?.arrayValue)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries.first?["address"], .hex(0x2010))
        XCTAssertEqual(entries.first?["rendered"], .string("dup_2"))
        XCTAssertEqual(entries.first?["reasons"], .array([.string("collision")]))
        let again = try decompile(WorkspaceScriptingAPI(store: store))
        XCTAssertEqual(reply["callTargetNames"], again["callTargetNames"])
    }

    func testR5RenameCollidingWithARegisterNameIsSuffixedAndDisclosed() throws {
        let store = stubStore(names: [0x2000: "x8"], symbols: [(0x2000, "_a"), (0x2010, "_b")])
        let entry = try XCTUnwrap(try decompile(WorkspaceScriptingAPI(store: store))["callTargetNames"]?.arrayValue?.first)
        XCTAssertEqual(entry["rendered"], .string("x8_2"))
        XCTAssertEqual(entry["reasons"], .array([.string("collision")]))
    }

    func testR6RenamingObjcMsgSendDisclosesTheLostSpecialCase() throws {
        let store = stubStore(names: [0x2000: "my_send"], symbols: [(0x2000, "_objc_msgSend"), (0x2010, "_b")])
        let entry = try XCTUnwrap(try decompile(WorkspaceScriptingAPI(store: store))["callTargetNames"]?.arrayValue?.first)
        XCTAssertEqual(entry["stored"], .string("my_send"))
        XCTAssertEqual(entry["reasons"], .array([.string("objcSpecialCaseLost")]))
    }

    // MARK: no-annotation golden and export identity

    func testNoCommentsNoRenamesReplyHasNoE2Fields() throws {
        let reply = try decompile(WorkspaceScriptingAPI(store: makeStore()))
        for key in ["commentsTotal", "commentsPlaced", "unplacedComments", "callTargetNames"] { XCTAssertNil(reply[key], key) }
    }
}
