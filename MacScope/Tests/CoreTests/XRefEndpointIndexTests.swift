import Foundation
import XCTest
@testable import MacScope

@MainActor
final class XRefEndpointIndexTests: XCTestCase {
    private func ref(_ from: UInt64, _ to: UInt64, _ kind: String = XRefKind.call) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }

    private func analysis(_ refs: [XRef]) -> ImageAnalysis {
        var value = ImageAnalysis()
        value.functions = [
            FunctionSummary(id: UUID(), name: "callee", startAddress: 0x3000, endAddress: 0x3010, confidence: 1),
            FunctionSummary(id: UUID(), name: "caller", startAddress: 0x5000, endAddress: 0x5010, confidence: 1),
            FunctionSummary(id: UUID(), name: "zero", startAddress: 0x7000, endAddress: 0x7000, confidence: 1),
        ]
        value.xrefs = refs
        return value
    }

    private func makeStore(_ refs: [XRef], sibling: Bool = false) -> WorkspaceStore {
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "image\(slot.rawValue)", path: "/tmp/xref-index-\(slot.rawValue)",
                        kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        let other = ImageSlot(rawValue: 1)
        let snapshot = sibling
            ? WorkspaceSnapshot(binaries: [image(.primary), image(other)],
                analysisBySlot: [.primary: analysis([]), other: analysis(refs)])
            : WorkspaceSnapshot(binaries: [image(.primary)], analysisBySlot: [.primary: analysis(refs)])
        return WorkspaceStore(workspaceName: "Xref endpoint index", snapshot: snapshot,
                              engine: AnalysisEngine(), preparesXRefs: false, autosaveScheduler: nil)
    }

    private func sparse(nonmatches: Int) -> [XRef] {
        var refs = (0..<nonmatches).map { ref(0x10_0000 + UInt64($0), 0x9000_0000) }
        refs.append(ref(0x5004, 0x3000))
        return refs
    }

    func testGraphPagesAreAvailableOnDirectAsyncAndAttachedRoutes() async throws {
        let store = makeStore([ref(0x5004, 0x3000), ref(0x5004, 0x3000)])
        let api = WorkspaceScriptingAPI(store: store)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        let arguments: ScriptValue = .object(["address": .hex(0x3000), "page": .bool(true),
                                              "detail": .string("edges")])
        let direct = try api.execute("callers", arguments: arguments)
        let asynchronous = try await api.executeAsync("callers", arguments: arguments)
        let remote = try await attached.execute("callers", arguments)
        for result in [direct, asynchronous, remote] {
            XCTAssertEqual(result["rows"]?.arrayValue?.count, 1)
            XCTAssertEqual(result["rows"]?.arrayValue?.first?["from"], .hex(0x5004))
            XCTAssertEqual(result["projection"], .string("edges"))
            XCTAssertEqual(result["total"], .int(1))
        }
    }

    func testGraphCallerDeduplicationPersistsAcrossPages() throws {
        let store = makeStore([ref(0x5004, 0x3000), ref(0x5004, 0x3000), ref(0x5008, 0x3000)])
        let api = WorkspaceScriptingAPI(store: store)
        let first = try api.execute("callers", arguments: .object([
            "address": .hex(0x3000), "page": .bool(true), "detail": .string("edges"), "limit": .int(1),
        ]))
        XCTAssertEqual(first["rows"]?.arrayValue?.first?["from"], .hex(0x5004))
        let cursor = try XCTUnwrap(first["nextCursor"])
        let second = try api.execute("callers", arguments: .object([
            "address": .hex(0x3000), "page": .bool(true), "detail": .string("edges"),
            "limit": .int(1), "cursor": cursor,
        ]))
        XCTAssertEqual(second["rows"]?.arrayValue?.first?["from"], .hex(0x5008))
        XCTAssertEqual(second["total"], .int(2))
        XCTAssertEqual(second["nextCursor"], .null)
    }

    func testStorePreparesEachNewXRefGeneration() async throws {
        let image = BinaryImage(id: UUID(), name: "warmup", path: "/tmp/xref-warmup",
                                kind: "Mach-O executable", architecture: "arm64", slot: .primary)
        let initial = WorkspaceSnapshot(binaries: [image], analysisBySlot: [
            .primary: analysis(sparse(nonmatches: 131_072)),
        ])
        let store = WorkspaceStore(workspaceName: "Warmup", snapshot: initial,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        await store.awaitXRefPreparationForTesting()
        let first = try XCTUnwrap(store.snapshot.analysis(in: .primary))
        XCTAssertNotNil(try first.xrefEndpointIndex(checkpoint: { XCTFail("expected warm index") }))
        store.snapshot.mutateAnalysis(in: .primary) { $0.xrefs.append(ref(0x5008, 0x3000)) }
        await store.awaitXRefPreparationForTesting()
        let next = try XCTUnwrap(store.snapshot.analysis(in: .primary))
        XCTAssertFalse(first.xrefEndpointMemo === next.xrefEndpointMemo)
        let index = try XCTUnwrap(try next.xrefEndpointIndex(checkpoint: { XCTFail("expected new warm index") }))
        XCTAssertEqual(index.candidates(.to, lower: 0x3000, upperInclusive: 0x3000).map(\.from), [0x5004, 0x5008])
    }

    private func edge(_ from: UInt64, _ to: UInt64, slot: Int = 0) -> ScriptValue {
        let target: String? = to == 0x3000 ? "callee" : to == 0x5000 ? "caller" : to == 0x7000 ? "zero" : nil
        let owner: (UInt64, String)? = (0x3000..<0x3010).contains(from) ? (0x3000, "callee")
            : (0x5000..<0x5010).contains(from) ? (0x5000, "caller") : from == 0x7000 ? (0x7000, "zero") : nil
        return .object(["from": .hex(from), "to": .hex(to), "imageSlot": .int(Int64(slot)),
            "toName": target.map(ScriptValue.string) ?? .null,
            "fromFunction": owner.map { .hex($0.0) } ?? .null,
            "fromFunctionName": owner.map { .string($0.1) } ?? .null])
    }

    private func xrefRow(_ from: UInt64, _ to: UInt64, _ kind: String = XRefKind.call,
                         slot: Int = 0) -> ScriptValue {
        guard case .object(var fields) = edge(from, to, slot: slot) else { preconditionFailure("fixture row") }
        fields["kind"] = .string(kind)
        return .object(fields)
    }

    private func checkRoutes(_ store: WorkspaceStore,
                             _ cases: [(String, ScriptValue, ScriptValue)]) async throws {
        let api = WorkspaceScriptingAPI(store: store)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        for (command, args, expected) in cases {
            XCTAssertEqual(try api.execute(command, arguments: args), expected)
            let asynchronous = try await api.executeAsync(command, arguments: args)
            XCTAssertEqual(asynchronous, expected)
            let attachedResult = try await attached.execute(command, args)
            XCTAssertEqual(attachedResult, expected)
        }
    }

    // F1: fails before on async/attached work refusal; inline is a positive control.
    func testCallersOfLateEdgeAnswerOnEveryRoute() async throws {
        try await checkRoutes(makeStore(sparse(nonmatches: 100_000)), [
            ("callers", .object(["address": .hex(0x3000)]), .array([edge(0x5004, 0x3000)])),
        ])
    }

    // F2: fails before on async/attached work refusal; inline is a positive control.
    func testCalleesOfLateEdgeAnswerOnEveryRoute() async throws {
        try await checkRoutes(makeStore(sparse(nonmatches: 100_000)), [
            ("callees", .object(["function": .string("caller")]), .array([edge(0x5004, 0x3000)])),
        ])
    }

    // F3: both forms fail before on every route, including inline.
    func testXRefsToLateEdgeAnswerOnEveryRoute() async throws {
        try await checkRoutes(makeStore(sparse(nonmatches: 100_000)), [
            ("xrefs", .object(["to": .hex(0x3000)]), .array([xrefRow(0x5004, 0x3000)])),
            ("xrefs", .object(["to": .hex(0x3000), "limit": .int(1)]), .array([xrefRow(0x5004, 0x3000)])),
        ])
    }

    // F4: the same failure belongs to the selected image, not the small primary image.
    func testSiblingImageLateEdgeAnswers() async throws {
        try await checkRoutes(makeStore(sparse(nonmatches: 100_000), sibling: true), [
            ("callers", .object(["address": .hex(0x3000), "imageSlot": .int(1)]),
             .array([edge(0x5004, 0x3000, slot: 1)])),
            ("xrefs", .object(["to": .hex(0x3000), "imageSlot": .int(1)]),
             .array([xrefRow(0x5004, 0x3000, slot: 1)])),
        ])
    }

    // C1: positive control (passes before); explicit source order, duplicates and range ends.
    func testControlSmallGraphRowsMatchExplicitExpectation() async throws {
        let refs = [
            ref(0x5008, 0x300f), ref(0x5004, 0x3000), ref(0x5008, 0x300f),
            ref(0x500c, 0x3004, XRefKind.string), ref(0x3004, 0x7000),
            ref(0x5000, 0x7000), ref(0x7000, 0x3000), ref(0x6000, 0x3010),
            ref(0x7001, 0x3008),
        ]
        try await checkRoutes(makeStore(refs), [
            ("callers", .object(["address": .hex(0x3000)]),
             .array([edge(0x5008, 0x300f), edge(0x5004, 0x3000), edge(0x7000, 0x3000), edge(0x7001, 0x3008)])),
            ("callees", .object(["function": .string("caller")]),
             .array([edge(0x5008, 0x300f), edge(0x5004, 0x3000), edge(0x5000, 0x7000)])),
            ("xrefs", .object(["to": .hex(0x300f)]),
             .array([xrefRow(0x5008, 0x300f), xrefRow(0x5008, 0x300f)])),
            ("callers", .object(["function": .string("zero")]),
             .array([edge(0x3004, 0x7000), edge(0x5000, 0x7000)])),
            ("callees", .object(["function": .string("zero")]), .array([edge(0x7000, 0x3000)])),
            ("xrefs", .object(["from": .hex(0x500c)]), .array([xrefRow(0x500c, 0x3004, XRefKind.string)])),
        ])
        // A non-call-only legacy filter never constructs the overflowing range.
        let top = FunctionSummary(id: UUID(), name: "top", startAddress: UInt64.max,
                                  endAddress: UInt64.max, confidence: 1)
        let noncalls = makeStore([ref(1, 2, XRefKind.string)]).snapshot
        XCTAssertEqual(noncalls.callers(of: top), [])
        XCTAssertEqual(noncalls.callees(of: top), [])
    }

    // C2: positive control (passes before); inline has no implicit result cap.
    func testControlResultBudgetRefusesOnSameRow() async throws {
        let store = makeStore((0..<5_001).map { ref(0x10_0000 + UInt64($0), 0x3000) })
        let api = WorkspaceScriptingAPI(store: store)
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        let args = ScriptValue.object(["address": .hex(0x3000)])
        XCTAssertEqual(try api.execute("callers", arguments: args).arrayValue?.count, 5_001)
        do {
            _ = try await api.executeAsync("callers", arguments: args)
            XCTFail("expected result refusal")
        } catch {
            XCTAssertEqual(error as? ScriptingError, .structuredRefusal(MCPToolRefusal(
                code: .budgetExceeded, detail: "callers exceeds the snapshot result budget",
                budget: .init(unit: .rows, limit: 5_000), used: 5_001, narrowing: [])))
        }
        do {
            _ = try await attached.execute("callers", args)
            XCTFail("expected result refusal")
        } catch {
            XCTAssertEqual(error as? ScriptingError, .structuredRefusal(MCPToolRefusal(
                code: .budgetExceeded, detail: "callers exceeds the snapshot result budget",
                budget: .init(unit: .rows, limit: 5_000), used: 5_001, narrowing: [])))
        }
    }

    // C3: positive control (passes before); callers uses recovered edges, not the overlay.
    func testControlManualEditsDoNotChangeCallers() async throws {
        let store = makeStore([ref(0x5004, 0x3000)])
        store.snapshot.manualXRefs = [
            ManualXRef(from: 0x5004, to: 0x3000, kind: XRefKind.call, isSuppression: true),
        ]
        try await checkRoutes(store, [
            ("callers", .object(["address": .hex(0x3000)]), .array([edge(0x5004, 0x3000)])),
            ("xrefs", .object(["to": .hex(0x3000)]), .array([])),
        ])
    }

    // C4: positive control (passes before); the last raw visit is still inside the old budget.
    func testControlWorkBoundaryAnswersAtPinAndAfter() async throws {
        try await checkRoutes(makeStore(sparse(nonmatches: 99_999)), [
            ("callers", .object(["address": .hex(0x3000)]), .array([edge(0x5004, 0x3000)])),
            ("callees", .object(["function": .string("caller")]), .array([edge(0x5004, 0x3000)])),
            ("xrefs", .object(["to": .hex(0x3000)]), .array([xrefRow(0x5004, 0x3000)])),
        ])
    }

    // C5: added by Q1's answer; positive control at the pin and after.
    func testControlLargeColdInlineReadKeepsLegacyScan() throws {
        var refs = [ref(0x5004, 0x3000)]
        refs += (0..<131_072).map { ref(0x10_0000 + UInt64($0), 0x9000_0000) }
        let store = makeStore(refs)
        let api = WorkspaceScriptingAPI(store: store)
        XCTAssertTrue(Thread.isMainThread)
        XCTAssertEqual(try api.execute("callers", arguments: .object(["address": .hex(0x3000)])),
                       .array([edge(0x5004, 0x3000)]))
        XCTAssertEqual(try api.execute("callees", arguments: .object(["function": .string("caller")])),
                       .array([edge(0x5004, 0x3000)]))
        // No index build/query checkpoints may precede the legacy first-row prefix.
        var checkpoints = 0
        let selected = try store.snapshot.boundedEffectiveXRefs(.to(0x3000), limit: 1,
            maximumRows: 5_000, maximumWork: 1, checkpoint: { checkpoints += 1 })
        XCTAssertEqual(selected.map(\.from), [0x5004])
        XCTAssertEqual(checkpoints, 3)
        XCTAssertEqual(try api.execute("xrefs", arguments: .object(["to": .hex(0x3000), "limit": .int(1)])),
                       .array([xrefRow(0x5004, 0x3000)]))
    }

    // C6 (review addition): fails before on the async work refusal. Above the cold inline cap,
    // inline xrefs keeps the legacy refusal until the background route publishes the index;
    // the same xrefs value is then answered inline from the ready index.
    func testBackgroundBuildAboveColdInlineCapIsReusedInline() async throws {
        let store = makeStore(sparse(nonmatches: 131_072))
        let api = WorkspaceScriptingAPI(store: store)
        let xrefsTo = ScriptValue.object(["to": .hex(0x3000)])
        XCTAssertThrowsError(try api.execute("xrefs", arguments: xrefsTo)) { error in
            XCTAssertEqual(error as? ScriptingError, .structuredRefusal(MCPToolRefusal(
                code: .budgetExceeded, detail: "xrefs exceeds the snapshot work budget",
                budget: .init(unit: .workSteps, limit: 100_000), narrowing: ["imageSlot"])))
        }
        let asynchronous = try await api.executeAsync("callers", arguments: .object(["address": .hex(0x3000)]))
        XCTAssertEqual(asynchronous, .array([edge(0x5004, 0x3000)]))
        XCTAssertEqual(try api.execute("xrefs", arguments: xrefsTo), .array([xrefRow(0x5004, 0x3000)]))
    }
}
