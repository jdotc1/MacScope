// Item 1280: authored, unrun. Synthetic fixtures only.
import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore

@MainActor
final class CallOwnerAdjacencyTests: XCTestCase {
    private func function(_ start: UInt64, _ end: UInt64) -> FunctionSummary {
        FunctionSummary(id: UUID(), name: "f\(start)", startAddress: start,
                        endAddress: end, confidence: 1)
    }
    private func ref(_ from: UInt64, _ to: UInt64, _ kind: String = XRefKind.call) -> XRef {
        XRef(id: UUID(), from: from, to: to, kind: kind)
    }
    private func names(_ functions: [FunctionSummary]) throws -> GraphNameIndex {
        try GraphNameIndex.build(functions: functions, symbols: [], textLimit: 1 << 20, checkpoint: {})
    }
    private func fixture(_ refs: [XRef], functions: [FunctionSummary]? = nil) -> WorkspaceSnapshot {
        WorkspaceSnapshot(binaries: [], functions: functions ?? [function(0x100, 0x110),
            function(0x200, 0x210), function(0x300, 0x310), function(0x400, 0x410),
            function(0x900, 0x910)], instructions: [], xrefs: refs, hexBytes: Data())
    }
    private func large(_ edges: [XRef]) -> WorkspaceSnapshot {
        fixture(Array(repeating: ref(0x901, 0x900), count: 100_001) + edges)
    }
    private func context() -> GraphPageContext {
        GraphPageSession().capture(workspace: UUID(), document: UUID())
    }
    private func analysis(_ snapshot: WorkspaceSnapshot) throws -> ImageAnalysis {
        try XCTUnwrap(snapshot.analysis(in: snapshot.primarySlot))
    }
    private func prepare(_ snapshot: WorkspaceSnapshot) throws -> CallOwnerPrepared {
        let a = try analysis(snapshot)
        return try XCTUnwrap(a.callOwnerAdjacencyMemo.prepare(analysis: a, checkpoint: {}))
    }
    private func graph(_ snapshot: WorkspaceSnapshot, _ context: GraphPageContext,
                       cursor: ScriptValue? = nil, root: UInt64 = 0x100,
                       incoming: Bool = false, depth: Int = 2, limit: Int = 100,
                       visits: Int = 100_000, autoVisits: Int = 4_000_000) throws -> ScriptValue {
        var fields: [String: ScriptValue] = ["root": .hex(root), "depth": .int(Int64(depth)),
            "direction": .string(incoming ? "callers" : "callees"), "limit": .int(Int64(limit))]
        if let cursor { fields["cursor"] = cursor }
        return try WorkspaceScriptingAPI.boundedCallRead("call-graph", arguments: .object(fields),
            snapshot: snapshot, context: context, visitLimit: visits,
            autoContinueVisitLimit: autoVisits, checkpoint: {})
    }
    private func chain(_ snapshot: WorkspaceSnapshot, _ context: GraphPageContext,
                       first: ScriptValue? = nil, root: UInt64 = 0x100,
                       incoming: Bool = false) throws -> [ScriptValue] {
        var page = try first ?? graph(snapshot, context, root: root, incoming: incoming, limit: 1)
        var rows = try XCTUnwrap(page["edges"]?.arrayValue)
        var cursor = try XCTUnwrap(page["nextCursor"])
        var pages = 0
        while cursor != .null && pages < 32 {
            page = try graph(snapshot, context, cursor: cursor, root: root, incoming: incoming, limit: 1)
            rows += try XCTUnwrap(page["edges"]?.arrayValue)
            cursor = try XCTUnwrap(page["nextCursor"])
            pages += 1
        }
        XCTAssertEqual(cursor, .null)
        XCTAssertEqual(page["completeWithinScope"], .bool(true))
        return rows
    }
    private func state(_ backend: CallReadBackend, root: UInt64 = 0x100,
                       incoming: Bool = false) -> BoundedCallState {
        let request = BoundedCallRequest(command: "call-graph", generation: UUID(), slot: .primary,
            owner: nil, root: root, target: nil, depth: 2, incoming: incoming)
        return BoundedCallState(request: request, backend: backend, queue: [(root, 0)], seen: [root])
    }
    private func assertBudget(_ error: Error, file: StaticString = #filePath, line: UInt = #line) {
        guard let failure = error as? ScriptingError,
              case .structuredRefusal(let refusal) = failure else {
            XCTFail("Expected structured budget refusal", file: file, line: line); return
        }
        XCTAssertEqual(refusal.code, .budgetExceeded, file: file, line: line)
    }
    private func assertStale(_ error: Error, file: StaticString = #filePath, line: UInt = #line) {
        guard let failure = error as? ScriptingError,
              case .invalidArgument(let detail) = failure else {
            XCTFail("Expected invalidArgument stale cursor", file: file, line: line); return
        }
        XCTAssertTrue(detail.hasPrefix("staleCursor:"), file: file, line: line)
    }

    func testIndexMatchesLinearForEveryIntervalShapeAndDirection() throws {
        let f = [function(0x100, 0x130), function(0x110, 0x120),
            function(0x120, 0x180), function(0x200, 0x200),
            function(0x300, 0x2FF), function(0x400, 0x410),
            function(0x400, 0x430), function(UInt64.max, UInt64.max)]
        let n = try names(f)
        let endpoints: [UInt64] = [0x100, 0x110, 0x120, 0x130, 0x150, 0x17F,
            0x180, 0x200, 0x201, 0x300, 0x301, 0x400, 0x420, 0x500, UInt64.max]
        var refs = endpoints.enumerated().map { ref($0.element, endpoints[(($0.offset + 3) % endpoints.count)]) }
        refs += [refs[0], ref(0x150, 0x200, XRefKind.data)]
        let index = try XCTUnwrap(CallOwnerAdjacencyIndex.build(xrefs: refs, names: n, checkpoint: {}))
        XCTAssertEqual(index.count, refs.count)
        XCTAssertEqual(n.owner(0x110)?.start, 0x100) // Nested function loses to earlier ordinal.
        XCTAssertEqual(n.owner(0x120)?.start, 0x100) // Shadowed start.
        XCTAssertEqual(n.owner(0x150)?.start, 0x120) // Do not normalize queued 0x120 again.
        XCTAssertEqual(n.owner(0x200)?.start, 0x200)
        XCTAssertNil(n.owner(0x201))
        XCTAssertEqual(n.owner(0x300)?.start, 0x300)
        XCTAssertNil(n.owner(0x301))
        XCTAssertEqual(n.owner(0x420)?.start, 0x400)
        XCTAssertEqual(n.owner(UInt64.max)?.start, UInt64.max)
        XCTAssertNil(n.owner(0x500))
        for incoming in [false, true] {
            for key in endpoints {
                let expected = refs.indices.filter {
                    let endpoint = incoming ? refs[$0].to : refs[$0].from
                    return (n.owner(endpoint)?.start ?? endpoint) == key
                }.map(UInt32.init)
                let actual = try index.range(for: key, incoming: incoming).map {
                    try XCTUnwrap(index.ordinal(at: $0, incoming: incoming))
                }
                XCTAssertEqual(actual, expected, "key=\(key), incoming=\(incoming)")
            }
        }
        XCTAssertNil(index.ordinal(at: -1, incoming: false))
        XCTAssertNil(index.ordinal(at: refs.count, incoming: true))
    }

    func testEmptyIndexAndEligibilityBoundaries() throws {
        let index = try XCTUnwrap(CallOwnerAdjacencyIndex.build(xrefs: [], names: names([]), checkpoint: {}))
        XCTAssertEqual(index.count, 0)
        XCTAssertTrue(index.range(for: 0, incoming: false).isEmpty)
        let p = try prepare(fixture(Array(repeating: ref(0x901, 0x900), count: 100_000)))
        for count in [0, 99_999, 16_777_217] {
            XCTAssertEqual(callReadBackend(rawCount: count, prepared: p), .linear)
        }
        XCTAssertEqual(callReadBackend(rawCount: 100_000, prepared: p), .indexed(p.id))
        // An otherwise eligible count with a mismatched prepared array is cold.
        XCTAssertEqual(callReadBackend(rawCount: 16_777_216, prepared: p), .linear)
        for count in [100_000, 16_777_216] {
            XCTAssertEqual(callReadBackend(rawCount: count, prepared: nil), .linear)
        }
    }

    func testWarmSmallQuantumHasEdgeWhileColdDoesNotAndColdAutoContinues() throws {
        let cold = large([ref(0x101, 0x200)])
        let warm = large([ref(0x101, 0x200)])
        let p = try prepare(warm)
        XCTAssertEqual(try BoundedCallAdjacencyAdapter.select(analysis: analysis(warm), retainedBackend: nil).backend,
                       .indexed(p.id))
        XCTAssertEqual(try BoundedCallAdjacencyAdapter.select(analysis: analysis(cold), retainedBackend: nil).backend,
                       .linear)
        let a = try graph(cold, context(), depth: 1, visits: 2, autoVisits: 2)
        let b = try graph(warm, context(), depth: 1, visits: 2, autoVisits: 2)
        XCTAssertEqual(a["edges"], .array([]))
        XCTAssertEqual(b["edges"]?.arrayValue?.count, 1)
        XCTAssertEqual(b["nextCursor"], .null)
        let continued = try graph(cold, context(), depth: 1)
        XCTAssertEqual(continued["edges"]?.arrayValue?.count, 1)
        XCTAssertEqual(continued["nextCursor"], .null)
        XCTAssertNil(try analysis(cold).callOwnerAdjacencyMemo.peek()) // Read did not prepare.
    }

    func testColdCursorStaysLinearAfterPreparationAndWholeChainsAgree() throws {
        let edges = [ref(0x102, 0x300), ref(0x101, 0x200), ref(0x201, 0x400),
                     ref(0x301, 0x400), ref(0x101, 0x200), ref(0x103, 0x400, XRefKind.data)]
        let cold = large(edges), warm = large(edges), c = context()
        let first = try graph(cold, c, limit: 1, visits: 2, autoVisits: 2)
        XCTAssertEqual(first["edges"], .array([]))
        _ = try prepare(cold)
        XCTAssertEqual(try BoundedCallAdjacencyAdapter.select(analysis: analysis(cold), retainedBackend: .linear).backend,
                       .linear)
        let linearRows = try chain(cold, c, first: first)
        _ = try prepare(warm)
        let indexedRows = try chain(warm, context())
        XCTAssertEqual(linearRows, indexedRows)
        XCTAssertEqual(linearRows.compactMap { $0["from"] }, [.hex(0x101), .hex(0x102), .hex(0x201), .hex(0x301)])
        let incomingCold = large(edges), incomingWarm = large(edges)
        _ = try prepare(incomingWarm)
        let incoming = try chain(incomingCold, context(), root: 0x400, incoming: true)
        XCTAssertEqual(incoming, try chain(incomingWarm, context(), root: 0x400, incoming: true))
        XCTAssertEqual(incoming.compactMap { $0["from"] }, [.hex(0x201), .hex(0x301), .hex(0x101), .hex(0x102)])
    }

    #if DEBUG
    func testWarmCursorRefusesDiscardAndReplacementWithoutGenerationChange() throws {
        let s = large([ref(0x101, 0x200), ref(0x102, 0x300)])
        let a = try analysis(s), p = try prepare(s), c = context(), generation = s.analysisGenerationID
        let first = try graph(s, c, limit: 1)
        let cursor = try XCTUnwrap(first["nextCursor"])
        XCTAssertNotEqual(cursor, .null)
        a.callOwnerAdjacencyMemo.discardPreparedForTesting()
        XCTAssertEqual(s.analysisGenerationID, generation)
        for _ in 0..<2 {
            XCTAssertThrowsError(try graph(s, c, cursor: cursor, limit: 1)) { self.assertStale($0) }
        }
        let replacement = try prepare(s)
        XCTAssertNotEqual(replacement.id, p.id)
        XCTAssertEqual(s.analysisGenerationID, generation)
        XCTAssertThrowsError(try graph(s, c, cursor: cursor, limit: 1)) { self.assertStale($0) }
    }

    func testBusyPeekFallsBackWithoutWaitingOrPublishing() throws {
        let s = large([ref(0x101, 0x200)]), a = try analysis(s)
        let p = try prepare(s)
        try a.callOwnerAdjacencyMemo.withLockHeldForTesting {
            XCTAssertNil(a.callOwnerAdjacencyMemo.peek())
            XCTAssertEqual(try BoundedCallAdjacencyAdapter.select(analysis: a, retainedBackend: nil).backend, .linear)
            // Persistent contention on an indexed cursor is a retryable busy refusal, never staleCursor.
            XCTAssertThrowsError(try BoundedCallAdjacencyAdapter.select(analysis: a, retainedBackend: .indexed(p.id))) {
                guard let failure = $0 as? ScriptingError, case .invalidArgument(let detail) = failure else {
                    return XCTFail("Expected invalidArgument cursorBusy")
                }
                XCTAssertTrue(detail.hasPrefix("cursorBusy:"))
                XCTAssertFalse(detail.hasPrefix("staleCursor:"))
            }
        }
        XCTAssertEqual(a.callOwnerAdjacencyMemo.peek()?.id, p.id)
    }

    func testTransientTryLockFailureOnIndexedCursorRetriesInsteadOfStale() throws {
        let s = large([ref(0x101, 0x200), ref(0x102, 0x300)])
        let a = try analysis(s), p = try prepare(s), c = context()
        let first = try graph(s, c, limit: 1)
        let cursor = try XCTUnwrap(first["nextCursor"])
        XCTAssertNotEqual(cursor, .null)
        let held = DispatchSemaphore(value: 0)
        let memo = a.callOwnerAdjacencyMemo
        let holder = Thread {
            memo.withLockHeldForTesting {
                held.signal()
                Thread.sleep(forTimeInterval: 0.03)
            }
        }
        holder.start()
        held.wait()
        // Another thread holds the memo lock for ~30 ms; the resumed indexed read must succeed.
        let next = try graph(s, c, cursor: cursor, limit: 1)
        XCTAssertEqual(try XCTUnwrap(next["edges"]?.arrayValue).count, 1)
        XCTAssertEqual(memo.peek()?.id, p.id)
    }
    #endif

    func testEveryRawBucketRowCostsVisitAndCheckpointEvenDuplicatesAndNoncalls() throws {
        let duplicate = ref(0x101, 0x200)
        let refs = Array(repeating: duplicate, count: 600) + Array(repeating: ref(0x102, 0x200, XRefKind.data), count: 600)
        let s = large(refs), a = try analysis(s), p = try prepare(s)
        let adapter = try BoundedCallAdjacencyAdapter.select(analysis: a, retainedBackend: nil)
        var st = state(adapter.backend), visits = 0, checkpoints = 0
        XCTAssertFalse(try adapter.scan(state: &st, currentAddress: 0x100, xrefs: a.xrefs,
            names: p.names, visits: &visits, quantum: 300, checkpoint: { checkpoints += 1 }))
        XCTAssertEqual(visits, 300); XCTAssertEqual(st.scan, 300)
        XCTAssertEqual(st.pending.count, 1); XCTAssertEqual(checkpoints, 2)
        visits = 0
        XCTAssertTrue(try adapter.scan(state: &st, currentAddress: 0x100, xrefs: a.xrefs,
            names: p.names, visits: &visits, quantum: 1000, checkpoint: {}))
        XCTAssertEqual(visits, 900); XCTAssertEqual(st.scan, 1200)
        XCTAssertEqual(st.pending.count, 1)
    }

    func testScanCancellationAt256RowsPreservesChargedPrefix() throws {
        let s = large(Array(repeating: ref(0x101, 0x200), count: 600))
        let a = try analysis(s), p = try prepare(s)
        let adapter = try BoundedCallAdjacencyAdapter.select(analysis: a, retainedBackend: nil)
        var st = state(adapter.backend), visits = 0, checkpoints = 0
        XCTAssertThrowsError(try adapter.scan(state: &st, currentAddress: 0x100, xrefs: a.xrefs,
            names: p.names, visits: &visits, quantum: 600, checkpoint: {
                checkpoints += 1
                if checkpoints == 2 { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(checkpoints, 2); XCTAssertEqual(visits, 256); XCTAssertEqual(st.scan, 256)
        XCTAssertEqual(st.pending.count, 1)
    }

    func testAdjacencyCapRejectsBeforeAppendOnBothBackends() throws {
        let functions = [function(0x100, 0x3000), function(0x4000, 0x4010), function(0x9000, 0x9010)]
        let edges = (0...4096).map { ref(UInt64(0x101 + $0), 0x4000) }
        for warm in [false, true] {
            let s = fixture(edges + Array(repeating: ref(0x9001, 0x9000), count: 100_001), functions: functions)
            let a = try analysis(s)
            if warm { _ = try prepare(s) }
            let n = try names(functions)
            let adapter = try BoundedCallAdjacencyAdapter.select(analysis: a, retainedBackend: nil)
            var st = state(adapter.backend), visits = 0
            XCTAssertThrowsError(try adapter.scan(state: &st, currentAddress: 0x100, xrefs: a.xrefs,
                names: n, visits: &visits, quantum: 100_000, checkpoint: {})) { self.assertBudget($0) }
            XCTAssertEqual(visits, 4097); XCTAssertEqual(st.pending.count, 4096)
            XCTAssertEqual(st.pendingKeys.count, 4096)
            XCTAssertFalse(st.pending.contains { $0.from == 0x1101 })
        }
    }

    func testCancelledPreparationDoesNotPublishAndInputChangesResetMemo() throws {
        let s = large([ref(0x101, 0x200)])
        var a = try analysis(s)
        _ = try a.graphNames.index(functions: a.functions, symbols: a.symbols, checkpoint: {})
        var checkpoints = 0
        XCTAssertThrowsError(try a.callOwnerAdjacencyMemo.prepare(analysis: a, checkpoint: {
            checkpoints += 1
            if checkpoints == 8 { throw CancellationError() }
        })) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertEqual(checkpoints, 8); XCTAssertNil(a.callOwnerAdjacencyMemo.peek())
        let original = try XCTUnwrap(a.callOwnerAdjacencyMemo.prepare(analysis: a, checkpoint: {}))
        let saved = a
        a.functions.append(function(0x500, 0x510))
        XCTAssertNil(a.callOwnerAdjacencyMemo.peek())
        a = saved; a.symbols = []
        XCTAssertNil(a.callOwnerAdjacencyMemo.peek())
        a = saved; a.xrefs.append(ref(0x201, 0x300))
        XCTAssertNil(a.callOwnerAdjacencyMemo.peek())
        XCTAssertEqual(saved.callOwnerAdjacencyMemo.peek()?.id, original.id)
    }

    func testNodeAndTotalEdgeCapsRemainTypedOnBothBackends() throws {
        let targets = (0..<1024).map { UInt64(0x20000 + $0 * 16) }
        let nodeFunctions = [function(0x100, 0x10000), function(0x90000, 0x90010)]
            + targets.map { function($0, $0 + 16) }
        let nodeRefs = targets.enumerated().map { ref(UInt64(0x101 + $0.offset), $0.element) }
        // Two individually admitted buckets, 2049 + 2049 distinct edges, three nodes.
        let edgeFunctions = [function(0x100, 0x3000), function(0x4000, 0x7000),
            function(0x8000, 0x8010), function(0x90000, 0x90010)]
        let edgeRefs = (0..<2049).map { ref(UInt64(0x101 + $0), 0x4000) }
            + (0..<2049).map { ref(UInt64(0x4001 + $0), 0x8000) }
        for warm in [false, true] {
            for (functions, refs, detail) in [(nodeFunctions, nodeRefs, "node cap"),
                                               (edgeFunctions, edgeRefs, "total edge cap")] {
                let s = fixture(refs + Array(repeating: ref(0x90001, 0x90000), count: 100_001), functions: functions)
                if warm { _ = try prepare(s) }
                let c = context()
                var cursor: ScriptValue?, refused = false, emitted = 0
                for _ in 0..<64 {
                    do {
                        let page = try graph(s, c, cursor: cursor, limit: 100)
                        emitted += try XCTUnwrap(page["edges"]?.arrayValue).count
                        cursor = try XCTUnwrap(page["nextCursor"])
                        if cursor == .null { break }
                    } catch {
                        assertBudget(error)
                        if let failure = error as? ScriptingError,
                           case .structuredRefusal(let refusal) = failure {
                            XCTAssertTrue(refusal.detail.contains(detail))
                        }
                        refused = true; break
                    }
                }
                XCTAssertTrue(refused)
                XCTAssertLessThanOrEqual(emitted, detail == "node cap" ? 1023 : 4096)
            }
        }
    }

    func testPureBuildCancellationAndCheckpointCoverage() throws {
        let n = try names([function(0x100, 0x110), function(0x200, 0x210)])
        let refs = Array(repeating: ref(0x101, 0x200), count: 513)
        var calls = 0
        _ = try XCTUnwrap(CallOwnerAdjacencyIndex.build(xrefs: refs, names: n, checkpoint: { calls += 1 }))
        XCTAssertGreaterThanOrEqual(calls, 3)
        // Exercise every observed build checkpoint, including phase boundaries. No fixed
        // implementation-specific total is assumed; each throws before publication.
        for cancellation in 1...calls {
            var reached = 0
            XCTAssertThrowsError(try CallOwnerAdjacencyIndex.build(xrefs: refs, names: n, checkpoint: {
                reached += 1
                if reached == cancellation { throw CancellationError() }
            })) { XCTAssertTrue($0 is CancellationError) }
            XCTAssertEqual(reached, cancellation)
        }
    }

    func testWarmupReservesEightUnitsPerRowAtAdmissionBoundary() throws {
        let s = fixture(Array(repeating: ref(0x901, 0x900), count: 100_000))
        XCTAssertTrue(CallOwnerPreparation.requests(snapshot: s, maximumOrdinalCount: 799_999).isEmpty)
        let admitted = CallOwnerPreparation.requests(snapshot: s, maximumOrdinalCount: 800_000)
        XCTAssertEqual(admitted.count, 1)
        XCTAssertEqual(admitted.first?.ordinalCount, 600_000)
        XCTAssertTrue(CallOwnerPreparation.requests(snapshot: s, maximumOrdinalCount: -1).isEmpty)
        XCTAssertNil(try analysis(s).callOwnerAdjacencyMemo.peek()) // Planning itself does not build.
    }

    func testEveryRequestFieldRemainsBoundWithoutAddingBackendToEquality() throws {
        let generation = UUID(), owner = UUID(), c = context()
        func request(command: String = "call-graph", generationID: UUID? = nil,
                     slot: ImageSlot = .primary, ownerID: UUID? = nil, root: UInt64 = 0x100,
                     target: UInt64? = nil, depth: Int = 2, incoming: Bool = false) -> BoundedCallRequest {
            BoundedCallRequest(command: command, generation: generationID ?? generation,
                slot: slot, owner: ownerID ?? owner, root: root, target: target,
                depth: depth, incoming: incoming)
        }
        let original = request(), backend = CallReadBackend.indexed(UUID())
        let session = c.session.boundedCalls
        let initial = try session.begin(c, cursor: nil, request: original)
        let retained = BoundedCallState(request: original, backend: backend,
            queue: [(0x100, 0)], seen: [0x100])
        let token = try XCTUnwrap(session.commit(initial.lease, context: c, state: retained))
        let cursor = ScriptValue.string(token)
        let changes = [request(command: "call-path"), request(generationID: UUID()),
            request(slot: ImageSlot(rawValue: 1)), request(ownerID: UUID()), request(root: 0x200),
            request(target: 0x300), request(depth: 1), request(incoming: true)]
        for changed in changes {
            XCTAssertNotEqual(changed, original)
            XCTAssertThrowsError(try session.begin(c, cursor: cursor, request: changed)) { self.assertStale($0) }
        }
        let resumed = try session.begin(c, cursor: cursor, request: request())
        defer { session.abandon(resumed.lease) }
        XCTAssertEqual(resumed.state?.request, original)
        XCTAssertEqual(resumed.state?.backend, backend)
    }
}
