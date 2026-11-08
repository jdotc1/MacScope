import Foundation
import XCTest
@testable import MacScope

@MainActor
final class XRefReadBudgetTests: XCTestCase {
    private func snapshot(_ refs: [XRef], edits: [ManualXRef] = []) -> WorkspaceSnapshot {
        var snapshot = WorkspaceSnapshot(binaries: [], functions: [], instructions: [],
                                         xrefs: refs, hexBytes: Data())
        snapshot.manualXRefs = edits
        return snapshot
    }

    private func ref(_ from: UInt64, to: UInt64 = 0x2000) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: XRefKind.call)
    }

    func testGraphPageContinuesPastSparseRowsAndRejectsStaleCursor() throws {
        let input = snapshot([ref(1, to: 8), ref(2, to: 8), ref(3)])
        let store = WorkspaceStore(workspaceName: "Graph pages", snapshot: input,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let args: ScriptValue = .object(["to": .hex(0x2000), "page": .bool(true),
                                         "detail": .string("edges"), "limit": .int(1)])
        let first = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: args,
            snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
        XCTAssertEqual(first["rows"], .array([]))
        XCTAssertEqual(first["total"], .null)
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let nextArgs: ScriptValue = .object(["to": .hex(0x2000), "page": .bool(true),
            "detail": .string("edges"), "limit": .int(1), "cursor": .string(cursor)])
        let second = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: nextArgs,
            snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
        XCTAssertEqual(second["rows"], .array([]))
        let nextCursor = try XCTUnwrap(second["nextCursor"]?.stringValue)
        let finalArgs: ScriptValue = .object(["to": .hex(0x2000), "page": .bool(true),
            "detail": .string("edges"), "limit": .int(1), "cursor": .string(nextCursor)])
        let final = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: finalArgs,
            snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
        XCTAssertEqual(final["rows"]?.arrayValue?.first?["from"], .hex(3))
        XCTAssertEqual(final["total"], .int(1))
        store.snapshot.manualXRefs.append(ManualXRef(from: 4, to: 0x2000, kind: XRefKind.call, isSuppression: false))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: nextArgs,
            snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
    }

    func testGraphPageKeepsLateSuppressionsAndAuthoredOrder() throws {
        let input = snapshot([ref(1), ref(2), ref(1)], edits: [
            ManualXRef(from: 3, to: 0x2000, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 2, to: 0x2000, kind: XRefKind.call, isSuppression: true),
        ])
        let store = WorkspaceStore(workspaceName: "Graph edits", snapshot: input,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
        ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
        XCTAssertEqual(page["rows"]?.arrayValue?.compactMap { $0["from"]?.addressValue }, [1, 1, 3])
        XCTAssertEqual(page["total"], .int(3))
    }

    func testGraphCursorCanRetryAfterCancellationAndCannotCrossStores() throws {
        let input = snapshot([ref(1, to: 8), ref(2), ref(3)])
        let firstStore = WorkspaceStore(workspaceName: "First", snapshot: input,
                                        engine: AnalysisEngine(), autosaveScheduler: nil)
        let secondStore = WorkspaceStore(workspaceName: "Second", snapshot: input,
                                         engine: AnalysisEngine(), autosaveScheduler: nil)
        let first = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
        ]), snapshot: firstStore.snapshot, context: firstStore.graphPageContext, visitLimit: 1, checkpoint: {}))
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        let next: ScriptValue = .object(["to": .hex(0x2000), "page": .bool(true),
            "detail": .string("edges"), "cursor": .string(cursor)])
        var checkpoints = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: next,
            snapshot: firstStore.snapshot, context: firstStore.graphPageContext, checkpoint: {
                checkpoints += 1
                if checkpoints == 2 { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
        let retry = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: next,
            snapshot: firstStore.snapshot, context: firstStore.graphPageContext, checkpoint: {}))
        XCTAssertEqual(retry["rows"]?.arrayValue?.compactMap { $0["from"]?.addressValue }, [2, 3])
        XCTAssertEqual(retry["total"], .int(2))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: next,
            snapshot: secondStore.snapshot, context: secondStore.graphPageContext, checkpoint: {}))
    }

    func testGraphPageDisclosesUnavailableStorageWithoutAppendingEqualTextEdges() throws {
        var input = snapshot([ref(7, to: 0x3000), ref(1), ref(8, to: 0x3000)])
        input.stringLiteralCoverage = .complete
        input.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString),
                                 0x3000: MacIRConstantString(text: "same", kind: .cfString)]
        let store = WorkspaceStore(workspaceName: "CFString graph", snapshot: input,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
        ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
        let rows = try XCTUnwrap(page["rows"]?.arrayValue)
        XCTAssertEqual(rows.compactMap { $0["from"]?.addressValue }, [1])
        XCTAssertNil(rows[0]["via"])
        XCTAssertNil(rows[0]["cString"])
        XCTAssertEqual(rows[0]["cfStringStorage"], storageNotice)
        XCTAssertEqual(page["cfStringStorage"], storageNotice)
        XCTAssertEqual(page["total"], .int(1))
        XCTAssertEqual(page["nextCursor"], .null)
    }

    func testGraphPageDoesNotInferCFStringLinkFromIncompleteInventory() throws {
        var input = snapshot([ref(7, to: 0x3000), ref(1)])
        input.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString),
                                 0x3000: MacIRConstantString(text: "same", kind: .cfString)]
        let store = WorkspaceStore(workspaceName: "Partial graph", snapshot: input,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
        ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
        XCTAssertEqual(page["rows"]?.arrayValue?.compactMap { $0["from"]?.addressValue }, [1])
        XCTAssertEqual(page["sourceComplete"], .null)
        XCTAssertEqual(page["cfStringStorage"], storageNotice)
        XCTAssertEqual(page["rows"]?.arrayValue?.first?["cfStringStorage"], storageNotice)
    }

    func testRequestedPrefixStopsBeforeRemainingRecoveredRows() throws {
        let input = snapshot([ref(1), ref(2), ref(3)])
        let rows = try WorkspaceScriptingAPI.snapshotListRead("xrefs", arguments: .object([
            "to": .hex(0x2000), "limit": .int(1),
        ]), snapshot: input, scope: .attached, selectionWorkLimit: 1)
        XCTAssertEqual(rows.arrayValue?.count, 1)
        XCTAssertEqual(rows.arrayValue?.first?["from"], .hex(1))
    }

    func testZeroLimitDoesNotScanRecoveredOrManualRows() throws {
        let input = snapshot([ref(1)], edits: [
            ManualXRef(from: 2, to: 0x2000, kind: XRefKind.call, isSuppression: false),
        ])
        let rows = try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000), "limit": .int(0),
        ]), snapshot: input, selectionWorkLimit: 0)
        XCTAssertEqual(rows, .array([]))
    }

    func testSparseRecoveredSelectionVisitsOnlyCandidates() throws {
        let input = snapshot([ref(1, to: 1), ref(2, to: 2), ref(3)])
        let rows = try WorkspaceScriptingAPI.snapshotListRead("xrefs", arguments: .object([
            "to": .hex(0x2000), "limit": .int(1),
        ]), snapshot: input, scope: .attached, selectionWorkLimit: 1)
        XCTAssertEqual(rows.arrayValue?.count, 1)
        XCTAssertEqual(rows.arrayValue?.first?["from"], .hex(3))
    }

    func testCandidateSelectionStillRefusesAtWorkBudget() throws {
        let input = snapshot([ref(1), ref(2)])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotListRead("xrefs", arguments: .object([
            "to": .hex(0x2000),
        ]), snapshot: input, scope: .attached, selectionWorkLimit: 1)) { error in
            XCTAssertEqual(error as? ScriptingError, .structuredRefusal(MCPToolRefusal(
                code: .budgetExceeded, detail: "xrefs exceeds the snapshot work budget",
                budget: .init(unit: .workSteps, limit: 1), narrowing: ["imageSlot"])))
        }
    }

    func testUnrelatedManualEditsDoNotConsumeSelectedWorkBudget() throws {
        let input = snapshot([ref(1)], edits: [
            ManualXRef(from: 7, to: 8, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 9, to: 10, kind: XRefKind.call, isSuppression: true),
        ])
        let rows = try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000), "limit": .int(1),
        ]), snapshot: input, selectionWorkLimit: 1)
        XCTAssertEqual(rows.arrayValue?.first?["from"], .hex(1))
    }

    func testResultBudgetRefusesInsteadOfReturningImplicitPartialList() throws {
        let input = snapshot([ref(1), ref(2), ref(3)])
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000),
        ]), snapshot: input, resultLimit: 2)) { error in
            XCTAssertEqual(error as? ScriptingError, .structuredRefusal(MCPToolRefusal(
                code: .budgetExceeded, detail: "xrefs exceeds the snapshot result budget; request a smaller limit",
                budget: .init(unit: .rows, limit: 2), narrowing: ["limit", "imageSlot"])))
        }
        let boundary = try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000), "limit": .int(2),
        ]), snapshot: input, resultLimit: 2)
        XCTAssertEqual(boundary.arrayValue?.count, 2)
    }

    func testOversizedRequestedLimitIsRefusedBeforeScan() throws {
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000), "limit": .int(3),
        ]), snapshot: snapshot([]), selectionWorkLimit: 0, resultLimit: 2)) { error in
            XCTAssertEqual(error as? ScriptingError, .structuredRefusal(MCPToolRefusal(
                code: .budgetExceeded, detail: "xrefs exceeds the snapshot result budget; request a smaller limit",
                budget: .init(unit: .rows, limit: 2), narrowing: ["limit", "imageSlot"])))
        }
    }

    func testInBudgetQueryPreservesRecoveredDuplicatesAndManualEditSemantics() throws {
        let first = ref(1)
        let duplicate = ref(1)
        let suppressed = ref(2)
        let input = snapshot([first, duplicate, suppressed, ref(9, to: 9)], edits: [
            ManualXRef(from: 1, to: 0x2000, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 3, to: 0x2000, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 3, to: 0x2000, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 2, to: 0x2000, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 2, to: 0x2000, kind: XRefKind.call, isSuppression: true),
            ManualXRef(from: 1, to: 0x2000, kind: XRefKind.call, isSuppression: true,
                       imageSlot: ImageSlot(rawValue: 1)),
            ManualXRef(from: 4, to: 0x2000, kind: XRefKind.call, isSuppression: false,
                       imageSlot: ImageSlot(rawValue: 1)),
        ])
        let actual = try input.boundedEffectiveXRefs(.to(0x2000), limit: nil,
            maximumRows: 4, maximumWork: 20, checkpoint: {})
        XCTAssertEqual(actual, input.effectiveXRefs(to: 0x2000))
        XCTAssertEqual(actual.map(\.from), [1, 1, 3])
        let from = try input.boundedEffectiveXRefs(.from(1), limit: nil,
            maximumRows: 3, maximumWork: 20, checkpoint: {})
        XCTAssertEqual(from, input.effectiveXRefs(from: 1))
    }

    func testLateSuppressionIsAppliedBeforeReturningRequestedPrefix() throws {
        let input = snapshot([ref(1), ref(2)], edits: [
            ManualXRef(from: 4, to: 5, kind: XRefKind.call, isSuppression: false),
            ManualXRef(from: 1, to: 0x2000, kind: XRefKind.call, isSuppression: true),
        ])
        let result = try input.boundedEffectiveXRefs(.to(0x2000), limit: 1,
            maximumRows: 1, maximumWork: 4, checkpoint: {})
        XCTAssertEqual(result.map(\.from), [2])
    }

    func testCancellationDuringSparseSelectionPublishesNoRows() throws {
        let input = snapshot((0..<300).map { ref(UInt64($0), to: 1) })
        var checkpoints = 0
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000), "limit": .int(1),
        ]), snapshot: input) {
            checkpoints += 1
            if checkpoints == 3 { throw CancellationError() }
        }) { error in
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertEqual(checkpoints, 3)
    }

    func testAttachPreservesExplicitLimitAndDoesNotInventImplicitPrefix() throws {
        let arguments = ScriptValue.object(["to": .hex(0x2000), "limit": .int(1)])
        XCTAssertEqual(MCPAttachExecutor.boundedArguments("xrefs", arguments), arguments)
        let unlimited = ScriptValue.object(["to": .hex(0x2000)])
        XCTAssertEqual(MCPAttachExecutor.boundedArguments("xrefs", unlimited), unlimited)
        XCTAssertTrue(WorkspaceScriptingAPI.snapshotListCommands.contains("xrefs"))
        let command = try XCTUnwrap(WorkspaceScriptingAPI.availableCommands.first { $0.name == "xrefs" })
        XCTAssertTrue(command.arguments.contains("limit"))
    }

    func testInlineAndAttachedReadsPreserveValidJSONAndHonorLimit() async throws {
        let input = snapshot([ref(1), ref(2), ref(3)])
        let store = WorkspaceStore(workspaceName: "Xref budget", snapshot: input,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        let executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let arguments = ScriptValue.object(["to": .hex(0x2000), "limit": .int(1)])
        let inline = try api.execute("xrefs", arguments: arguments)
        let attached = try await executor.execute("xrefs", arguments)
        XCTAssertEqual(inline.arrayValue?.count, 1)
        XCTAssertEqual(try attached.jsonData(), try inline.jsonData())
        let complete = try api.execute("xrefs", arguments: .object(["to": .hex(0x2000)]))
        // DEF-A04: every row names the image that produced it (a binary-less snapshot reads slot 0).
        let expected = ScriptValue.array(input.effectiveXRefs(to: 0x2000).map {
            .object([
                "from": .hex($0.from), "to": .hex($0.to), "kind": .string($0.kind),
                "imageSlot": .int(Int64(input.primarySlot.rawValue)),
                "toName": .null, "fromFunction": .null, "fromFunctionName": .null,
            ])
        })
        XCTAssertEqual(try complete.jsonData(), try expected.jsonData())
    }

    // Expected wire values do not use production disclosure helpers.
    private var storageNotice: ScriptValue {
        .object(["status": .string("unavailable"), "reason": .string("backingAddressNotRetained")])
    }

    private func edgeProjection(_ row: ScriptValue) -> ScriptValue {
        var fields: [String: ScriptValue] = [:]
        for key in ["from", "to", "kind", "imageSlot", "cfStringStorage", "via", "cfString"] {
            if let value = row[key] { fields[key] = value }
        }
        return .object(fields)
    }

    func testFlatAndPagedStorageParityAcrossCoverageAndRetainedFallback() throws {
        let coverages: [StringLiteralCoverage?] = [nil, .notAttempted, .complete,
            .incomplete(.stringCountLimitReached)]
        for coverage in coverages {
            for mapPresent in [false, true] {
                var input = snapshot([ref(7, to: 0x3000), ref(1), ref(1), ref(2), ref(9, to: 9)], edits: [
                    ManualXRef(from: 3, to: 0x2000, kind: XRefKind.call, isSuppression: false),
                    ManualXRef(from: 2, to: 0x2000, kind: XRefKind.call, isSuppression: true),
                    ManualXRef(from: 8, to: 9, kind: XRefKind.call, isSuppression: false),
                ])
                input.stringLiteralCoverage = coverage
                input.stringLiterals = [StringLiteralSummary(id: UUID(), value: "same", address: 0x2000,
                    sourceSection: "__TEXT,__objc_methname", byteLength: 5)]
                if mapPresent {
                    input.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString),
                        0x3000: MacIRConstantString(text: "same", kind: .cfString)]
                }
                let store = WorkspaceStore(workspaceName: "Storage parity", snapshot: input,
                    engine: AnalysisEngine(), autosaveScheduler: nil)
                let flat = try WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(0x2000)]),
                    snapshot: store.snapshot)
                let flatRows = try XCTUnwrap(flat.arrayValue)
                XCTAssertEqual(flatRows.compactMap { $0["from"]?.addressValue }, [1, 1, 3])
                var cursor: ScriptValue = .null
                var collected: [ScriptValue] = []
                var sawEmptyPartial = false, sawEmptyFinal = false, finished = false
                for _ in 0..<100 {
                    let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
                        "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
                        "limit": .int(1), "cursor": cursor,
                    ]), snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
                    let rows = try XCTUnwrap(page["rows"]?.arrayValue)
                    XCTAssertEqual(page["cfStringStorage"], storageNotice)
                    XCTAssertEqual(page["sourceComplete"], .null)
                    XCTAssertLessThanOrEqual(try WorkspaceScriptingAPI.listPageWireBytes(page),
                        WorkspaceScriptingAPI.graphPageByteLimit)
                    for row in rows {
                        XCTAssertEqual(row["cfStringStorage"], storageNotice)
                        XCTAssertNil(row["via"]); XCTAssertNil(row["cString"])
                    }
                    collected += rows
                    cursor = try XCTUnwrap(page["nextCursor"])
                    if cursor == .null {
                        XCTAssertEqual(page["total"], .int(3))
                        XCTAssertEqual(page["coverage"], .string("complete"))
                        XCTAssertEqual(page["isTruncated"], .bool(false))
                        sawEmptyFinal = rows.isEmpty; finished = true; break
                    }
                    sawEmptyPartial = sawEmptyPartial || rows.isEmpty
                    XCTAssertEqual(page["total"], .null)
                    XCTAssertEqual(page["coverage"], .string("partial"))
                    XCTAssertEqual(page["isTruncated"], .bool(true))
                    XCTAssertTrue(cursor.stringValue?.hasPrefix("x2:") == true)
                }
                XCTAssertTrue(finished); XCTAssertTrue(sawEmptyPartial); XCTAssertTrue(sawEmptyFinal)
                XCTAssertEqual(collected, flatRows.map(edgeProjection))
            }
        }
    }

    func testGraphStorageRefusalMatchesFlatOnlyAfterTerminalEmptyTraversal() throws {
        var input = snapshot([ref(7, to: 0x3000), ref(8, to: 0x3000)])
        input.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString),
            0x3000: MacIRConstantString(text: "same", kind: .cfString)]
        let store = WorkspaceStore(workspaceName: "Empty storage parity", snapshot: input,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        var flatError: ScriptingError?
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(0x2000)]),
            snapshot: store.snapshot)) { flatError = $0 as? ScriptingError }
        XCTAssertNotNil(flatError)
        let first = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
        ]), snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
        XCTAssertEqual(first["rows"], .array([]))
        XCTAssertEqual(first["cfStringStorage"], storageNotice)
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"), "cursor": .string(cursor),
        ]), snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {})) {
            XCTAssertEqual($0 as? ScriptingError, flatError)
        }
        XCTAssertEqual(try WorkspaceScriptingAPI.snapshotXRefRead(.object([
            "to": .hex(0x2000), "limit": .int(0),
        ]), snapshot: store.snapshot, selectionWorkLimit: 0), .array([]))
        // Page size zero was never admitted; do not silently change that contract.
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"), "limit": .int(0),
        ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
    }

    func testGraphRejectsOldCursorWithoutConsumingNewContinuation() throws {
        var input = snapshot([ref(9, to: 9), ref(1)])
        input.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString)]
        let store = WorkspaceStore(workspaceName: "Cursor version", snapshot: input,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        let first = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
            "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"),
        ]), snapshot: store.snapshot, context: store.graphPageContext, visitLimit: 1, checkpoint: {}))
        let cursor = try XCTUnwrap(first["nextCursor"]?.stringValue)
        XCTAssertTrue(cursor.hasPrefix("x2:"))
        func args(_ token: String) -> ScriptValue {
            .object(["to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"), "cursor": .string(token)])
        }
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs",
            arguments: args("x1:" + String(cursor.dropFirst(3))), snapshot: store.snapshot,
            context: store.graphPageContext, checkpoint: {}))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: args(cursor),
            snapshot: store.snapshot, context: store.graphPageContext, checkpoint: { throw CancellationError() })) {
            XCTAssertTrue($0 is CancellationError)
        }
        let final = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: args(cursor),
            snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
        XCTAssertEqual(final["rows"]?.arrayValue?.compactMap { $0["from"]?.addressValue }, [1])
        XCTAssertEqual(final["cfStringStorage"], storageNotice)
        XCTAssertEqual(final["total"], .int(1))
    }

    func testGraphOwnAddressAndSourceQueriesKeepDirectEdges() throws {
        var input = snapshot([ref(7, to: 0x3000), ref(1)])
        input.stringLiteralCoverage = .complete
        input.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString),
            0x3000: MacIRConstantString(text: "same", kind: .cfString)]
        let store = WorkspaceStore(workspaceName: "Direct edge controls", snapshot: input,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        for fields in [["to": ScriptValue.hex(0x3000)], ["from": ScriptValue.hex(1)]] {
            let flat = try WorkspaceScriptingAPI.snapshotXRefRead(.object(fields), snapshot: store.snapshot)
            var paged = fields
            paged["page"] = .bool(true); paged["detail"] = .string("edges")
            let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object(paged),
                snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
            XCTAssertEqual(page["rows"]?.arrayValue, flat.arrayValue?.map(edgeProjection))
            XCTAssertNil(page["cfStringStorage"])
            XCTAssertEqual(page["total"], .int(1))
        }
    }

    func testCoreReaderStorageWorldsHaveIdenticalFlatAndPagedDirectAnswers() throws {
        for (shared, utf16) in [(true, false), (false, false), (false, true)] {
            let input = ImageConstantStringProviderTests.storageAuthoritySnapshot(shared: shared, utf16: utf16)
            let store = WorkspaceStore(workspaceName: "Core storage parity", snapshot: input,
                engine: AnalysisEngine(), autosaveScheduler: nil)
            let flat = try WorkspaceScriptingAPI.snapshotXRefRead(.object(["to": .hex(0x2000)]),
                snapshot: store.snapshot)
            let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
                "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"), "limit": .int(1),
            ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
            XCTAssertEqual(page["rows"]?.arrayValue, flat.arrayValue?.map(edgeProjection))
            XCTAssertEqual(page["rows"]?.arrayValue?.compactMap { $0["from"]?.addressValue }, [0x1000])
            XCTAssertEqual(page["cfStringStorage"], storageNotice)
            XCTAssertEqual(page["rows"]?.arrayValue?.first?["cfStringStorage"], storageNotice)
            XCTAssertNil(page["rows"]?.arrayValue?.first?["via"])
            XCTAssertNil(page["rows"]?.arrayValue?.first?["cString"])
            // The final unrelated raw row may require a separate empty page.
            if let cursor = page["nextCursor"]?.stringValue {
                let last = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
                    "to": .hex(0x2000), "page": .bool(true), "detail": .string("edges"), "cursor": .string(cursor),
                ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
                XCTAssertEqual(last["rows"], .array([]))
                XCTAssertEqual(last["cfStringStorage"], storageNotice)
                XCTAssertEqual(last["total"], .int(1))
                XCTAssertEqual(last["nextCursor"], .null)
            } else { XCTAssertEqual(page["total"], .int(1)) }
        }
    }

    func testGraphStorageClassificationAndEditsStayInSelectedImage() throws {
        let sibling = ImageSlot(rawValue: 1)
        var primary = ImageAnalysis(), other = ImageAnalysis()
        primary.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cString)]
        other.constantStrings = [0x2000: MacIRConstantString(text: "same", kind: .cfString)]
        primary.xrefs = [ref(1)]
        other.xrefs = [ref(2)]
        let binaries = [ImageSlot.primary, sibling].map { slot in
            BinaryImage(id: UUID(), name: "storage-\(slot.rawValue)", path: "/fixture",
                kind: "Mach-O executable", architecture: "arm64", slot: slot)
        }
        var input = WorkspaceSnapshot(binaries: binaries, analysisBySlot: [.primary: primary, sibling: other])
        input.manualXRefs = [
            ManualXRef(from: 1, to: 0x2000, kind: XRefKind.call, isSuppression: true, imageSlot: sibling),
            ManualXRef(from: 3, to: 0x2000, kind: XRefKind.call, isSuppression: false, imageSlot: sibling),
        ]
        let store = WorkspaceStore(workspaceName: "Per-image storage", snapshot: input,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        for slot in [ImageSlot.primary, sibling] {
            let args: ScriptValue = .object(["to": .hex(0x2000), "imageSlot": .int(Int64(slot.rawValue))])
            let flat = try WorkspaceScriptingAPI.snapshotXRefRead(args, snapshot: store.snapshot)
            let page = try XCTUnwrap(WorkspaceScriptingAPI.snapshotGraphPage("xrefs", arguments: .object([
                "to": .hex(0x2000), "imageSlot": .int(Int64(slot.rawValue)),
                "page": .bool(true), "detail": .string("edges"),
            ]), snapshot: store.snapshot, context: store.graphPageContext, checkpoint: {}))
            XCTAssertEqual(page["rows"]?.arrayValue, flat.arrayValue?.map(edgeProjection))
            XCTAssertEqual(page["rows"]?.arrayValue?.compactMap { $0["from"]?.addressValue },
                slot == .primary ? [1] : [2, 3])
            if slot == .primary { XCTAssertEqual(page["cfStringStorage"], storageNotice) }
            else { XCTAssertNil(page["cfStringStorage"]) }
        }
    }
}
