import XCTest
@testable import MacScope

/// Gate, cursor-fence and coordinator tests driven by an authored fake workspace. No store, parser, engine or
/// AIRS process is involved; the heavy part is replaced by authored runners.
@MainActor
final class AIRSReadCoordinatorTests: XCTestCase {
    private let unwind = AIRSMCPReads.unwindCommand
    private let swiftCommand = AIRSMCPReads.swiftErrorCommand

    private func read(_ world: AIRSFakeWorld, _ registry: AIRSReadSessionRegistry, command: String? = nil,
                      _ extra: [String: ScriptValue] = [:], runtime: AIRSReadRuntime = .live) async throws -> ScriptValue {
        let name = command ?? unwind
        var fields: [String: ScriptValue] = ["imageSlot": .int(0)]
        if name == swiftCommand { fields["function"] = .string("0x1000") }
        fields.merge(extra) { _, new in new }
        let options = try AIRSMCPReads.parse(command: name, fields: fields)
        return try await AIRSMCPLive.serve(options: options, source: world.source(), resolve: AIRSFakeWorld.resolve,
                                           registry: registry, runtime: runtime)
    }

    private func completedWorld() throws -> AIRSFakeWorld {
        let world = try AIRSFakeWorld()
        world.complete(AIRSReadFixtures.report(world.identity, AIRSReadFixtures.threeFindings(world.identity)))
        return world
    }

    private func detail(_ value: ScriptValue) -> String? { value["refusal"]?["detail"]?.stringValue }

    func testCursorGenerationCommandModelFilterFence() async throws {
        let world = try completedWorld()
        let registry = AIRSReadSessionRegistry()
        let first = try await read(world, registry, ["limit": .int(1)])
        let token = try XCTUnwrap(first["nextCursor"]?.stringValue)
        guard case .success(let good) = AIRSReadCursor.decode(token) else { return XCTFail("token") }

        func follow(_ cursor: AIRSReadCursor) async throws -> ScriptValue {
            try await read(world, registry, ["limit": .int(1), "cursor": .string(try XCTUnwrap(cursor.encoded()))])
        }
        let followed = try await follow(good)
        XCTAssertEqual(followed["returnedBefore"]?.intValue, 1)

        var variants: [(String, AIRSReadCursor)] = []
        func mutate(_ name: String, _ change: (inout AIRSReadCursor) -> Void) { var c = good; change(&c); variants.append((name, c)) }
        mutate("generation") { $0.generation = UUID() }
        mutate("command") { $0.command = AIRSMCPReads.swiftErrorCommand }
        mutate("model") { $0.modelID = "arm64-bounded-cfi-controls-v4" }
        mutate("filter") { $0.filterToken = "fn:4096" }
        mutate("slot") { $0.imageSlot = 1 }
        mutate("owner") { $0.imageOwnerID = UUID() }
        mutate("installation") { $0.installationID = UUID() }
        mutate("report") { $0.reportID = UUID() }
        mutate("entry") { $0.entryID = UUID() }
        mutate("focus") { $0.focusEpoch = UUID() }
        mutate("reportState") { $0.reportStateEpoch = UUID() }
        for (name, cursor) in variants {
            let result = try await follow(cursor)
            XCTAssertEqual(result, NavigatorMCPCommands.staleCursor, name)
        }
        XCTAssertThrowsError(try AIRSMCPReads.parse(command: unwind, fields: ["imageSlot": .int(0), "cursor": .string("AAAA")])) {
            XCTAssertEqual(($0 as? ToolArgumentError)?.refusal.field, "cursor")
        }
    }

    func testFocusAwayAndBackStillRetiresCursor() async throws {
        let world = try completedWorld()
        let registry = AIRSReadSessionRegistry()
        let first = try await read(world, registry, ["limit": .int(1)])
        let token = try XCTUnwrap(first["nextCursor"]?.stringValue)
        world.moveFocus(ImageSlot(rawValue: 1))
        world.moveFocus(.primary)
        XCTAssertEqual(world.focused, .primary)
        let stale = try await read(world, registry, ["limit": .int(1), "cursor": .string(token)])
        XCTAssertEqual(stale, NavigatorMCPCommands.staleCursor)
    }

    func testFocusChangeNeverMovesFocus() async throws {
        let world = try completedWorld()
        let registry = AIRSReadSessionRegistry()
        world.moveFocus(ImageSlot(rawValue: 1))
        let mismatch = try await read(world, registry)
        XCTAssertEqual(detail(mismatch), "focusMismatch")
        XCTAssertEqual(world.focused, ImageSlot(rawValue: 1))
        XCTAssertEqual(world.state.phase, .completed)
        world.moveFocus(.primary)

        // Focus moves while the Swift runner is suspended: the live return refuses and focus stays where it was put.
        let swiftWorld = try AIRSFakeWorld()
        swiftWorld.input = try AIRSReadFixtures.capturedInput()
        let request = AIRSReadFixtures.swiftRequest(window: [0xb4000075])
        let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        var runtime = AIRSReadRuntime.live
        runtime.swiftRun = { _, model in started.signal(); release.wait(); return AIRSReadFixtures.rawEdges(request, model: model) }
        let swiftRegistry = AIRSReadSessionRegistry()
        let finalRuntime = runtime
        let task = Task { try await self.read(swiftWorld, swiftRegistry, command: self.swiftCommand, runtime: finalRuntime) }
        while !airsTryAcquire(started) { try await Task.sleep(nanoseconds: 10_000_000) }
        swiftWorld.moveFocus(ImageSlot(rawValue: 1))
        release.signal()
        let result = try await task.value
        XCTAssertEqual(detail(result), "focusChanged")
        XCTAssertEqual(swiftWorld.focused, ImageSlot(rawValue: 1))
    }

    func testReadDoesNotStartUnwindOrReplayAnalysis() async throws {
        let world = try AIRSFakeWorld()
        let registry = AIRSReadSessionRegistry()
        let idle = try await read(world, registry)
        XCTAssertEqual(detail(idle), "auditNotReady")
        XCTAssertEqual(world.state.phase, .idle)
        world.begin()
        let running = try await read(world, registry)
        XCTAssertEqual(detail(running), "auditNotReady")
        XCTAssertEqual(world.state.phase, .running)
        let beforeCaptures = world.captureCalls

        let done = try completedWorld()
        let doneRegistry = AIRSReadSessionRegistry()
        let first = try await read(done, doneRegistry, ["limit": .int(1)])
        XCTAssertEqual(first["total"]?.intValue, 3)
        let capturesAfterFirst = done.captureCalls
        XCTAssertLessThanOrEqual(capturesAfterFirst, 1)
        let token = try XCTUnwrap(first["nextCursor"]?.stringValue)
        _ = try await read(done, doneRegistry, ["limit": .int(1), "cursor": .string(token)])
        _ = try await read(done, doneRegistry, ["limit": .int(1)])
        XCTAssertEqual(done.captureCalls, capturesAfterFirst)
        XCTAssertEqual(done.state.phase, .completed)
        XCTAssertEqual(beforeCaptures, 0)
    }

    func testLateBoundaryAbortLeaksNoRows() async throws {
        let world = try AIRSFakeWorld()
        let request = world.state.begin(world.key())
        world.state.fail("boundary invalid at second start", for: request)
        let registry = AIRSReadSessionRegistry()
        let value = try await read(world, registry)
        XCTAssertEqual(detail(value), "coordinatorFailed")
        XCTAssertEqual(value["analysis"]?["rows"]?.arrayValue?.count, 0)
        XCTAssertEqual(value["analysis"]?["total"], .null)
        XCTAssertEqual(value["analysis"]?["sourceComplete"], .bool(false))
        XCTAssertNil(value["rows"])
    }

    func testCancelledAndSupersededUnwindNeverPublish() throws {
        let world = try AIRSFakeWorld()
        let report = AIRSReadFixtures.report(world.identity, AIRSReadFixtures.threeFindings(world.identity))
        var cancelled = UnwindAuditResultState()
        let first = cancelled.begin(world.key())
        cancelled.cancel()
        XCTAssertFalse(cancelled.publish(report, for: first))
        XCTAssertNil(cancelled.report)
        XCTAssertEqual(cancelled.discardedPublicationCount, 1)

        var superseded = UnwindAuditResultState()
        let old = superseded.begin(world.key())
        let replaced = UnwindAuditResultKey(imageID: world.ownerID, slot: .primary, generation: UUID(), identity: world.identity,
                                            modelID: UnwindAuditModel.boundedLoops.rawValue, configuration: .init())
        superseded.activate(replaced)
        XCTAssertFalse(superseded.publish(report, for: old))
        XCTAssertNil(superseded.report)
        XCTAssertEqual(superseded.discardedPublicationCount, 1)
    }

    // MARK: Swift coordinator

    private func swiftKey(_ world: AIRSFakeWorld, generation: UUID? = nil) -> SwiftErrorFlowSourceKey {
        SwiftErrorFlowSourceKey(imageID: world.ownerID, slot: .primary, generation: generation ?? world.generation,
                                documentInstallationID: world.installationID, identity: world.identity)
    }

    private func settle(_ coordinator: AIRSSwiftReadCoordinator) async throws {
        for _ in 0..<200 where coordinator.isOccupied { try await Task.sleep(nanoseconds: 10_000_000) }
        try await Task.sleep(nanoseconds: 50_000_000)
    }

    func testSwiftCancelledSupersededWrongModelNeverPublish() async throws {
        let world = try AIRSFakeWorld()
        let input = try AIRSReadFixtures.capturedInput()
        let request = AIRSReadFixtures.swiftRequest(window: [0xb4000075])

        // Cancelled caller.
        do {
            let coordinator = AIRSSwiftReadCoordinator()
            let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let run: AIRSSwiftReadCoordinator.Run = { _, model in
                started.signal(); release.wait(); return AIRSReadFixtures.rawEdges(request, model: model)
            }
            let key = swiftKey(world)
            let task = Task { await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: run) }
            while !airsTryAcquire(started) { try await Task.sleep(nanoseconds: 10_000_000) }
            // A different model while the worker is occupied is refused, never queued and never cancels the first.
            let busy = await coordinator.result(key: key, model: .registerCopiesV2, input: input, deadlineMillis: 25_000, run: run)
            XCTAssertEqual(busy.failureValue, .busy)
            task.cancel()
            let cancelledOutcome = await task.value
            XCTAssertEqual(cancelledOutcome.failureValue, .cancelled)
            release.signal()
            try await settle(coordinator)
            XCTAssertEqual(coordinator.publishedCount, 0)
            XCTAssertEqual(coordinator.suppressedCount, 1)
            XCTAssertNil(coordinator.cachedResult(key: key, model: .v1))
        }
        // Superseded by an invalidation (source change) while running.
        do {
            let coordinator = AIRSSwiftReadCoordinator()
            let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let run: AIRSSwiftReadCoordinator.Run = { _, model in
                started.signal(); release.wait(); return AIRSReadFixtures.rawEdges(request, model: model)
            }
            let key = swiftKey(world)
            let task = Task { await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: run) }
            while !airsTryAcquire(started) { try await Task.sleep(nanoseconds: 10_000_000) }
            coordinator.invalidate()
            release.signal()
            let supersededOutcome = await task.value
            XCTAssertEqual(supersededOutcome.failureValue, .superseded)
            XCTAssertEqual(coordinator.publishedCount, 0)
            XCTAssertNil(coordinator.cachedResult(key: key, model: .v1))
        }
        // A runner that answers with a different model than requested is never published.
        do {
            let coordinator = AIRSSwiftReadCoordinator()
            let key = swiftKey(world)
            let wrong: AIRSSwiftReadCoordinator.Run = { _, _ in AIRSReadFixtures.rawEdges(request, model: .registerCopiesV2) }
            let outcome = await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: wrong)
            XCTAssertEqual(outcome.failureValue, .superseded)
            XCTAssertEqual(coordinator.publishedCount, 0)
            XCTAssertNil(coordinator.cachedResult(key: key, model: .v1))
            XCTAssertNil(coordinator.cachedResult(key: key, model: .registerCopiesV2))
        }
        // Control: the matching ticket, key and model does publish exactly once and is reused.
        do {
            let coordinator = AIRSSwiftReadCoordinator()
            let key = swiftKey(world)
            let good: AIRSSwiftReadCoordinator.Run = { _, model in AIRSReadFixtures.rawEdges(request, model: model) }
            let outcome = await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: good)
            XCTAssertNotNil(outcome.successValue)
            _ = await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: good)
            XCTAssertEqual(coordinator.publishedCount, 1)
            XCTAssertEqual(coordinator.runCount, 1)
        }
    }

    /// T1 + T2: a deadline leaves the flight live; a retry joins it and, once the work finishes, is served.
    func testDeadlineKeepsFlightLiveAndRetryIsServed() async throws {
        let world = try AIRSFakeWorld()
        let input = try AIRSReadFixtures.capturedInput()
        let request = AIRSReadFixtures.swiftRequest(window: [0xb4000075])
        let coordinator = AIRSSwiftReadCoordinator()
        let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let run: AIRSSwiftReadCoordinator.Run = { _, model in
            started.signal(); release.wait(); return AIRSReadFixtures.rawEdges(request, model: model)
        }
        let key = swiftKey(world)
        let first = await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 50, run: run)
        XCTAssertEqual(first.failureValue, .deadline)
        XCTAssertTrue(coordinator.isOccupied)
        // T2: a retry while the work still runs joins the flight (here it hits its own short deadline), never busy.
        let joined = await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 50, run: run)
        XCTAssertEqual(joined.failureValue, .deadline)
        // T1: release the work; the next read returns the result without a second run.
        release.signal()
        try await settle(coordinator)
        let served = await coordinator.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: run)
        XCTAssertNotNil(served.successValue)
        XCTAssertEqual(coordinator.runCount, 1)
        XCTAssertEqual(coordinator.publishedCount, 1)
        XCTAssertEqual(coordinator.suppressedCount, 0)
    }

    /// T3: replacing the installation for the same owner retires the old coordinator's flight.
    func testInstallationReplacementSuppressesOldFlight() async throws {
        let world = try AIRSFakeWorld()
        let input = try AIRSReadFixtures.capturedInput()
        let request = AIRSReadFixtures.swiftRequest(window: [0xb4000075])
        let registry = AIRSReadSessionRegistry()
        let old = try XCTUnwrap(registry.entry(owner: world, installationID: world.installationID,
                                               subscribe: world.source().subscribe))
        let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let run: AIRSSwiftReadCoordinator.Run = { _, model in
            started.signal(); release.wait(); return AIRSReadFixtures.rawEdges(request, model: model)
        }
        let key = swiftKey(world)
        let task = Task { await old.swift.result(key: key, model: .v1, input: input, deadlineMillis: 25_000, run: run) }
        while !airsTryAcquire(started) { try await Task.sleep(nanoseconds: 10_000_000) }
        let replacement = try XCTUnwrap(registry.entry(owner: world, installationID: UUID(),
                                                       subscribe: world.source().subscribe))
        XCTAssertFalse(replacement === old)
        release.signal()
        let outcome = await task.value
        XCTAssertEqual(outcome.failureValue, .superseded)
        try await settle(old.swift)
        XCTAssertEqual(old.swift.publishedCount, 0)
        XCTAssertNil(old.swift.cachedResult(key: key, model: .v1))
        XCTAssertNil(replacement.swift.cachedResult(key: key, model: .v1))
        XCTAssertEqual(replacement.swift.publishedCount, 0)
    }

    func testNativeLastStartIsNotZeroEdgeAdmission() throws {
        // Three census starts, only the first two admitted as intervals; the third is the last start.
        let request = AIRSReadFixtures.swiftRequest(window: [0xb4000075])
        var raw = AIRSReadFixtures.rawEdges(
            request, census: AIRSReadFixtures.census(starts: [0x1000, 0x1080, 0x1084]))
        raw.admittedIntervals = Array(request.functions.prefix(2))
        let built = AIRSReadBuilder.swift(raw: raw, context: AIRSReadFixtures.context(command: swiftCommand, function: 0x1084))
        guard case .aborted(let value) = built else { return XCTFail("a non-admitted last start must refuse, not return total 0") }
        XCTAssertEqual(value["refusal"]?["detail"]?.stringValue, "functionBoundaryNotAdmitted")
        XCTAssertEqual(value["analysis"]?["total"], .null)
        let admitted = AIRSReadBuilder.swift(raw: raw, context: AIRSReadFixtures.context(command: swiftCommand, function: 0x1000))
        XCTAssertNotNil(AIRSReadFixtures.builtReport(admitted))
    }

    func testStructuredPageAndP1ErrorStayDistinct() async throws {
        // Transport framing is not reachable without a server; this pins the layer below it.
        XCTAssertThrowsError(try AIRSMCPReads.parse(command: unwind, fields: ["imageSlot": .int(0), "limit": .int(0)])) {
            XCTAssertTrue($0 is ToolArgumentError)
        }
        let world = try AIRSFakeWorld()
        let refused = try await read(world, AIRSReadSessionRegistry())
        XCTAssertEqual(refused["error"]?.stringValue, "refused")
        XCTAssertEqual(refused["refusal"]?["code"]?.stringValue, "preconditionFailed")
        let page = try await read(try completedWorld(), AIRSReadSessionRegistry())
        XCTAssertNil(page["error"])
        XCTAssertEqual(page["rows"]?.arrayValue?.count, 3)
    }

    /// An equal report republished as a new publication must not be served from the old admission.
    func testRepublishedEqualReportRefusesStaleReport() async throws {
        let world = try completedWorld()
        world.input = try AIRSReadFixtures.capturedInput()
        let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        var runtime = AIRSReadRuntime.live
        runtime.census = { _ in
            started.signal(); release.wait()
            return AIRSReadFixtures.census(starts: [0x1000, 0x2000, 0x3000])
        }
        let registry = AIRSReadSessionRegistry()
        let finalRuntime = runtime
        let task = Task { try await self.read(world, registry, runtime: finalRuntime) }
        while !airsTryAcquire(started) { try await Task.sleep(nanoseconds: 10_000_000) }
        let before = world.state.publicationID
        let report = try XCTUnwrap(world.state.report)
        world.complete(report)
        XCTAssertEqual(world.state.report, report)
        XCTAssertNotEqual(world.state.publicationID, before)
        release.signal()
        let result = try await task.value
        XCTAssertEqual(detail(result), "staleReport")
    }

    private func swiftRegionWorld() throws -> AIRSFakeWorld {
        let world = try AIRSFakeWorld()
        world.input = try AIRSReadFixtures.capturedInput()
        return world
    }

    private func regionRuntime(_ request: SwiftErrorFlowRequest) -> AIRSReadRuntime {
        var runtime = AIRSReadRuntime.live
        runtime.swiftRun = { _, _ in AIRSReadFixtures.rawRegions(request) }
        return runtime
    }

    /// B1: a report-state change must retire retained Swift reports too, so a first call after the change
    /// mints a cursor that continues instead of replaying a report whose cursors are already fenced out.
    func testReportStateChangeRetiresRetainedSwiftReportAndFirstCallContinues() async throws {
        let world = try swiftRegionWorld()
        let runtime = regionRuntime(AIRSReadFixtures.singleCaller257Request())
        let registry = AIRSReadSessionRegistry()
        let args: [String: ScriptValue] = ["function": .string("0x1000"), "model": .string("regionsV1")]
        let first = try await read(world, registry, command: swiftCommand, args, runtime: runtime)
        let oldToken = try XCTUnwrap(first["nextCursor"]?.stringValue, "257 rows must page at the default limit")
        let entry = try XCTUnwrap(registry.entry(owner: world, installationID: world.installationID,
                                                 subscribe: world.source().subscribe))
        entry.noteReportStateChange()
        XCTAssertTrue(entry.reports.isEmpty, "every retained report bound to the old report-state epoch is dropped")

        let second = try await read(world, registry, command: swiftCommand, args, runtime: runtime)
        let newToken = try XCTUnwrap(second["nextCursor"]?.stringValue)
        XCTAssertNotEqual(newToken, oldToken)
        var withCursor = args
        withCursor["cursor"] = .string(newToken)
        let followed = try await read(world, registry, command: swiftCommand, withCursor, runtime: runtime)
        XCTAssertNotEqual(followed, NavigatorMCPCommands.staleCursor)
        XCTAssertEqual(followed["returnedBefore"]?.intValue, 100)
        withCursor["cursor"] = .string(oldToken)
        let stale = try await read(world, registry, command: swiftCommand, withCursor, runtime: runtime)
        XCTAssertEqual(stale, NavigatorMCPCommands.staleCursor)
    }

    /// B2 (a)+(b): single-page reads take no retained slot, so more than four distinct ones all succeed.
    func testSixDistinctSinglePageSwiftReadsAllSucceed() async throws {
        let world = try swiftRegionWorld()
        let runtime = regionRuntime(AIRSReadFixtures.region257Request())
        let registry = AIRSReadSessionRegistry()
        for index in 0..<6 {
            let start = String(format: "0x%lx", 0x1000 + index * 16)
            let page = try await read(world, registry, command: swiftCommand,
                                      ["function": .string(start), "model": .string("regionsV1")], runtime: runtime)
            XCTAssertNil(page["refusal"], start)
            XCTAssertNil(page["error"], start)
            XCTAssertEqual(page["nextCursor"], .null, start)
        }
        let entry = try XCTUnwrap(registry.entry(owner: world, installationID: world.installationID,
                                                 subscribe: world.source().subscribe))
        XCTAssertTrue(entry.reports.isEmpty)
    }

    /// B2 (c): at the cap a finished report is evicted first; with every cursor live (or abandoned) the LRU one is.
    func testRetainedCapEvictsFinishedFirstThenLeastRecentlyUsed() async throws {
        let world = try AIRSFakeWorld()
        let findings = (1...5).flatMap { n in
            ["a", "b"].map {
                AIRSReadFixtures.finding(world.identity, id: "\($0)\(n)", start: UInt64(n) * 0x1000, end: UInt64(n) * 0x1000 + 0x10)
            }
        }
        world.complete(AIRSReadFixtures.report(world.identity, findings))
        func start(_ n: Int) -> ScriptValue { .string(String(format: "0x%lx", n * 0x1000)) }
        func fill(_ registry: AIRSReadSessionRegistry) async throws -> [String] {
            var tokens: [String] = []
            for n in 1...4 {
                let page = try await read(world, registry, ["function": start(n), "limit": .int(1)])
                XCTAssertEqual(page["total"]?.intValue, 2)
                tokens.append(try XCTUnwrap(page["nextCursor"]?.stringValue))
            }
            return tokens
        }
        func follow(_ registry: AIRSReadSessionRegistry, _ n: Int, _ token: String) async throws -> ScriptValue {
            try await read(world, registry, ["function": start(n), "limit": .int(1), "cursor": .string(token)])
        }

        // Four abandoned (live) cursors: the fifth read still succeeds and the LRU report is evicted.
        let abandoned = AIRSReadSessionRegistry()
        let tokens = try await fill(abandoned)
        let fifth = try await read(world, abandoned, ["function": start(5), "limit": .int(1)])
        XCTAssertNil(fifth["refusal"])
        XCTAssertNotNil(fifth["nextCursor"]?.stringValue)
        let evictedLRU = try await follow(abandoned, 1, tokens[0])
        XCTAssertEqual(evictedLRU, NavigatorMCPCommands.staleCursor)
        for index in [1, 2, 3] {
            let still = try await follow(abandoned, index + 1, tokens[index])
            XCTAssertEqual(still["returnedBefore"]?.intValue, 1, "report \(index + 1)")
        }

        // A finished report goes first even when it is not the LRU one.
        let registry = AIRSReadSessionRegistry()
        let live = try await fill(registry)
        let done = try await follow(registry, 2, live[1])
        XCTAssertEqual(done["nextCursor"], .null)
        let next = try await read(world, registry, ["function": start(5), "limit": .int(1)])
        XCTAssertNil(next["refusal"])
        let finished = try await follow(registry, 2, live[1])
        XCTAssertEqual(finished, NavigatorMCPCommands.staleCursor)
        for index in [0, 2, 3] {
            let still = try await follow(registry, index + 1, live[index])
            XCTAssertEqual(still["returnedBefore"]?.intValue, 1, "report \(index + 1)")
        }
    }
}

private extension Result {
    var failureValue: Failure? { if case .failure(let error) = self { return error } else { return nil } }
    var successValue: Success? { if case .success(let value) = self { return value } else { return nil } }
}

/// Non-blocking semaphore poll; kept synchronous so async tests may call it.
private func airsTryAcquire(_ semaphore: DispatchSemaphore) -> Bool {
    semaphore.wait(timeout: .now()) == .success
}
