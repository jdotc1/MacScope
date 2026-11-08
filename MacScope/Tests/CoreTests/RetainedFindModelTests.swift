import Foundation
import XCTest
@testable import MacScope

private actor ControlledRetainedFindWorker {
    private var pending: [String: CheckedContinuation<BinarySearchService.BoundedOutcome, Never>] = [:]
    func search(_ query: String) async -> BinarySearchService.BoundedOutcome {
        await withCheckedContinuation { pending[query] = $0 }
    }
    func contains(_ query: String) -> Bool { pending[query] != nil }
    func complete(_ query: String, address: UInt64) {
        pending.removeValue(forKey: query)?.resume(returning: .init(
            results: [.init(address: address, kind: .instruction, preview: query)],
            lowerBound: 1, isTruncated: false, isCancelled: false))
    }
}

@MainActor
final class RetainedFindModelTests: XCTestCase {
    private let workspaceID = UUID()
    private let documentID = UUID()
    func testRetainsQueryResultsAndQualifiedCursorAcrossReopenAndAllImageFocus() async throws {
        let owner = NSObject()
        let snapshot = fixture()
        let model = RetainedFindModel()
        model.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID, snapshot: snapshot, revision: 1,
                   focusedSlot: .primary, scope: .everything)
        model.query = "needle"
        model.search(selecting: ImageAddress(slot: ImageSlot(rawValue: 1), address: 0x1000))
        try await waitUntil { model.publicationID != nil }
        let publication = model.publicationID
        XCTAssertEqual(model.results.count, 2)
        XCTAssertEqual(model.cursor?.current?.imageSlot, ImageSlot(rawValue: 1))
        model.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID, snapshot: snapshot, revision: 1,
                   focusedSlot: ImageSlot(rawValue: 1), scope: .everything)
        XCTAssertEqual(model.query, "needle")
        XCTAssertEqual(model.publicationID, publication)
        XCTAssertEqual(model.results.count, 2)
        XCTAssertTrue(model.admits(model.results[1], workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID, snapshot: snapshot, revision: 1))
    }

    func testLateOldQueryAndReplacedImageCannotPublishOrNavigate() async throws {
        let owner = NSObject()
        let controlled = ControlledRetainedFindWorker()
        let model = RetainedFindModel(worker: { query, _, _, _ in await controlled.search(query) })
        let snapshot = fixture()
        model.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID, snapshot: snapshot, revision: 1,
                   focusedSlot: .primary, scope: .everything)
        model.query = "old"
        model.search(selecting: nil)
        try await waitUntilAsync { await controlled.contains("old") }
        model.query = "new"
        model.search(selecting: nil)
        try await waitUntilAsync { await controlled.contains("new") }
        await controlled.complete("new", address: 0x1004)
        try await waitUntil { model.publicationID != nil }
        await controlled.complete("old", address: 0x1000)
        await Task.yield()
        XCTAssertEqual(model.results.map(\.address), [0x1004])
        let oldHit = try XCTUnwrap(model.results.first)
        let replacement = fixture()
        XCTAssertFalse(model.admits(oldHit, workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID, snapshot: replacement, revision: 1))
        model.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID, snapshot: replacement, revision: 1,
                   focusedSlot: .primary, scope: .everything)
        XCTAssertTrue(model.results.isEmpty)
        XCTAssertNil(model.cursor)
    }

    func testSameStoreAndImagesCannotRetainOrPublishResultsAcrossLogicalDocumentReplacement() async throws {
        let owner = NSObject()
        let snapshot = fixture()
        let model = RetainedFindModel()
        model.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID,
                   snapshot: snapshot, revision: 1, focusedSlot: .primary, scope: .everything)
        model.query = "needle"
        model.search(selecting: nil)
        try await waitUntil { model.publicationID != nil }
        let hit = try XCTUnwrap(model.results.first)
        let replacementDocument = UUID()
        XCTAssertFalse(model.admits(hit, workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID,
                                    documentID: replacementDocument, snapshot: snapshot, revision: 1))
        model.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: replacementDocument,
                   snapshot: snapshot, revision: 1, focusedSlot: .primary, scope: .everything)
        XCTAssertTrue(model.query.isEmpty)
        XCTAssertTrue(model.results.isEmpty)
        XCTAssertNil(model.cursor)

        let controlled = ControlledRetainedFindWorker()
        let pending = RetainedFindModel(worker: { query, _, _, _ in await controlled.search(query) })
        pending.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: workspaceID, documentID: documentID,
                     snapshot: snapshot, revision: 1, focusedSlot: .primary, scope: .everything)
        pending.query = "old-document"
        pending.mode = .regex
        pending.search(selecting: nil)
        try await waitUntilAsync { await controlled.contains("old-document") }
        pending.bind(workspaceOwner: ObjectIdentifier(owner), workspaceID: UUID(), documentID: documentID,
                     snapshot: snapshot, revision: 1, focusedSlot: .primary, scope: .everything)
        await controlled.complete("old-document", address: 0x1000)
        await Task.yield()
        XCTAssertEqual(pending.mode, .text)
        XCTAssertTrue(pending.query.isEmpty)
        XCTAssertNil(pending.publicationID)
        XCTAssertTrue(pending.results.isEmpty)
    }

    func testFocusedFindInvalidationRetiresExactStoreCursorBeforeNextNavigation() async throws {
        let store = WorkspaceStore(workspaceName: "retained-find", snapshot: fixture(),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let model = RetainedFindModel()
        model.bind(store: store)
        var scope = BinarySearchScope.everything
        scope.images = .focused
        model.bind(workspaceOwner: ObjectIdentifier(store), workspaceID: store.workspaceID, documentID: store.documentID,
                   snapshot: store.snapshot, revision: store.mutationGeneration.rawValue,
                   focusedSlot: store.focusedImageSlot, scope: scope)
        model.query = "needle"
        model.search(selecting: nil)
        try await waitUntil { model.publicationID != nil }
        model.seedCursor(in: store)
        XCTAssertNotNil(store.searchCursor)
        store.focusImage(ImageSlot(rawValue: 1))
        // The command can arrive before either SwiftUI lifetime callback binds.
        let immediateSelection = store.selectedImageAddress
        store.findNext()
        XCTAssertNil(store.searchCursor)
        XCTAssertEqual(store.selectedImageAddress, immediateSelection)
        // Reproduce sheet-first callback ordering, not only the root convenience.
        model.bind(workspaceOwner: ObjectIdentifier(store), workspaceID: store.workspaceID, documentID: store.documentID,
                   snapshot: store.snapshot, revision: store.mutationGeneration.rawValue,
                   focusedSlot: store.focusedImageSlot, scope: scope)
        XCTAssertNil(store.searchCursor)
        XCTAssertTrue(model.results.isEmpty)
        let selection = store.selectedImageAddress
        store.findNext()
        XCTAssertEqual(store.selectedImageAddress, selection)
    }

    func testAllImageFindKeepsCursorOnFocusAndDoesNotRetireUnrelatedCursor() async throws {
        let store = WorkspaceStore(workspaceName: "retained-find", snapshot: fixture(),
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let model = RetainedFindModel()
        model.bind(store: store)
        model.query = "needle"
        model.search(selecting: nil)
        try await waitUntil { model.publicationID != nil }
        model.seedCursor(in: store)
        let cursor = store.searchCursor
        store.focusImage(ImageSlot(rawValue: 1))
        model.bind(store: store)
        XCTAssertEqual(store.searchCursor, cursor)
        XCTAssertEqual(model.results.count, 2)
        store.findNext()
        XCTAssertEqual(store.searchCursor?.retainedFindAuthority, cursor?.retainedFindAuthority)
        XCTAssertNotNil(store.searchCursor?.current)
        // Identical rows without this publication's authority are independent.
        let unrelated = model.results
        store.seedSearchCursor(unrelated)
        model.query = "new query"
        XCTAssertEqual(store.searchCursor?.results, unrelated)
        XCTAssertNil(store.searchCursor?.retainedFindAuthority)
    }

    func testBoundedSearchCapsAccumulationAndIncludesAuthoredNamesCommentsAndTags() {
        var snapshot = fixture()
        snapshot.analysisBySlot[.primary]?.instructions = (0..<2_000).map {
            InstructionRow(address: UInt64(0x1000 + $0 * 4), bytes: "00", mnemonic: "needle",
                           operands: "", hasBreakpoint: false, comment: nil)
        }
        let outcome = BinarySearchService().searchBounded(query: "needle", mode: .text, in: snapshot)
        XCTAssertEqual(outcome.results.count, 500)
        XCTAssertEqual(outcome.lowerBound, 501)
        XCTAssertTrue(outcome.isTruncated)
        var authored = AddressOverride()
        authored.customName = "authoredName"
        authored.customComment = "authoredComment"
        authored.tag = "authoredTag"
        snapshot.addressOverrides[.primary(0x1000)] = authored
        for query in ["authoredName", "authoredComment", "authoredTag"] {
            XCTAssertTrue(BinarySearchService().searchBounded(query: query, mode: .text, in: snapshot).results.contains { $0.address == 0x1000 && $0.imageSlot == .primary })
        }
        let cancelled = BinarySearchService().searchBounded(query: "needle", mode: .text,
                                                           in: snapshot, isCancelled: { true })
        XCTAssertTrue(cancelled.isCancelled)
        XCTAssertTrue(cancelled.results.isEmpty)
    }

    private func fixture() -> WorkspaceSnapshot {
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        for slot in [ImageSlot.primary, ImageSlot(rawValue: 1)] {
            let binary = BinaryImage(id: UUID(), name: "image-\(slot.rawValue)", path: "/fixture",
                                     kind: "Mach-O", architecture: "arm64", slot: slot)
            var analysis = ImageAnalysis()
            analysis.instructions = [.init(address: 0x1000, bytes: "00", mnemonic: "needle",
                                           operands: "", hasBreakpoint: false, comment: nil)]
            snapshot.insertImage(binary: binary, analysis: analysis)
        }
        return snapshot
    }

    private func waitUntil(_ predicate: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(2)
        while !predicate(), Date() < deadline { try await Task.sleep(for: .milliseconds(5)) }
        XCTAssertTrue(predicate())
    }
    private func waitUntilAsync(_ predicate: () async -> Bool) async throws {
        let deadline = Date().addingTimeInterval(2)
        while !(await predicate()), Date() < deadline { try await Task.sleep(for: .milliseconds(5)) }
        let satisfied = await predicate()
        XCTAssertTrue(satisfied)
    }

    // 857: fails before the fix. Each metadata kind must bypass 200,000 unrelated
    // instruction visits, not merely filter the already-starved result afterwards.
    func test857MetadataKindBypassesInstructionStarvation() async throws {
        let api = WorkspaceScriptingAPI(store: make857SearchStore(instructionCount: 200_000))
        for kind in ["string", "symbol", "function"] {
            let value = try await api.executeAsync("search", arguments: .object([
                "query": .string("needle"), "kind": .string(kind)
            ]))
            guard let result = value["results"], case .array(let rows) = result else {
                return XCTFail("expected search results")
            }
            XCTAssertEqual(rows.count, 1)
            XCTAssertEqual(rows.first?["kind"], .string(kind))
            XCTAssertEqual(value["total"], .int(1))
            XCTAssertEqual(value["lowerBound"], .int(1))
            XCTAssertEqual(value["isTruncated"], .bool(false))
        }
    }

    // 857: fails before the fix. No arbitrary scheduling sleep or native execution.
    func test857IncompleteEmptySearchIsAnExplicitRefusal() async throws {
        let api = WorkspaceScriptingAPI(store: make857SearchStore(instructionCount: 200_000))
        let value = try await api.executeAsync("search", arguments: .object(["query": .string("needle")]))
        XCTAssertEqual(value["results"]?.arrayValue?.count, 3)
        XCTAssertEqual(value["kindsCovered"], .array(["function", "string", "symbol"].map(ScriptValue.string)))
        XCTAssertEqual(value["incomplete"]?["kindsPending"], .array([.string("instruction")]))
        XCTAssertNotNil(value["nextCursor"]?.stringValue)
        XCTAssertEqual(value["total"], .null)
        XCTAssertEqual(value["isTruncated"], .bool(true))
    }

    // 857: fails before the fix at authority validation, not in a fixture helper.
    func test857HeadlessAuthorityAdmitsKindAndRejectsIncompatibleKinds() throws {
        for kind in ["instruction", "string", "symbol", "function"] {
            XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(
                command: "search", arguments: .object([
                    "query": .string("needle"), "kind": .string(kind)
                ])))
        }
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(
            command: "search", arguments: .object([
                "query": .string("00"), "mode": .string("hex"), "kind": .string("bytes")
            ])))
        for fields in [
            ["query": ScriptValue.string("needle"), "kind": .string("bytes")],
            ["query": .string("00"), "mode": .string("hex"), "kind": .string("symbol")],
            ["query": .string("needle"), "kind": .string("unknown")],
            ["query": .string("needle"), "kind": .null]
        ] {
            XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(
                command: "search", arguments: .object(fields)))
        }
    }

    // 857: positive controls (pass before); report-scale counts, synthetic content.
    func test857SmallImageDefaultSearchAndExactAbsenceKeepTheirShape() async throws {
        let api = WorkspaceScriptingAPI(store: make857SearchStore(
            instructionCount: 27_175, stringCount: 1_442, symbolCount: 2_248,
            functionCount: 536))
        for (query, count) in [("needle", 3), ("absent857", 0)] {
            let value = try await api.executeAsync("search", arguments: .object([
                "query": .string(query)
            ]))
            guard let result = value["results"], case .array(let rows) = result else {
                return XCTFail("expected search results")
            }
            XCTAssertEqual(rows.count, count)
            XCTAssertEqual(value["total"], .int(Int64(count)))
            XCTAssertEqual(value["lowerBound"], .int(Int64(count)))
            XCTAssertEqual(value["isTruncated"], .bool(false))
        }
    }

    // 857: fails before the fix because the synchronous API ignores kind.
    func test857SynchronousKindUsesTheSameSelector() throws {
        let api = WorkspaceScriptingAPI(store: make857SearchStore(instructionCount: 4))
        let value = try api.execute("search", arguments: .object([
            "query": .string("needle"), "kind": .string("symbol")
        ]))
        guard let result = value["results"], case .array(let rows) = result else {
            return XCTFail("expected search results")
        }
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?["kind"], .string("symbol"))
        XCTAssertEqual(value["total"], .int(1))
    }

    private func make857SearchStore(
        instructionCount: Int, stringCount: Int = 1, symbolCount: Int = 1,
        functionCount: Int = 1
    ) -> WorkspaceStore {
        let binary = BinaryImage(id: UUID(), name: "857", path: "/fixture-857",
                                 kind: "Mach-O", architecture: "arm64", slot: .primary)
        var analysis = ImageAnalysis()
        analysis.instructions = (0..<instructionCount).map {
            InstructionRow(address: 0x1000 + UInt64($0 * 4), bytes: "1f 20 03 d5",
                           mnemonic: "nop", operands: "", hasBreakpoint: false, comment: nil)
        }
        analysis.stringLiterals = (0..<stringCount).map {
            let value = $0 == 0 ? "needle" : "literal\($0)"
            return StringLiteralSummary(id: UUID(), value: value,
                address: 0x200000 + UInt64($0 * 16), sourceSection: "__cstring",
                byteLength: value.utf8.count)
        }
        analysis.symbols = (0..<symbolCount).map {
            SymbolSummary(id: UUID(), name: $0 == 0 ? "needle" : "symbol\($0)",
                          address: 0x300000 + UInt64($0 * 4), kind: "local", libraryName: nil)
        }
        analysis.functions = (0..<functionCount).map {
            FunctionSummary(id: UUID(), name: $0 == 0 ? "needle" : "function\($0)",
                startAddress: 0x400000 + UInt64($0 * 4),
                endAddress: 0x400004 + UInt64($0 * 4), confidence: 1)
        }
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: binary, analysis: analysis)
        return WorkspaceStore(workspaceName: "857 search", snapshot: snapshot,
                              engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}
