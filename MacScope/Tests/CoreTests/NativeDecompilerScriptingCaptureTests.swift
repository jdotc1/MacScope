import Foundation
import XCTest
@testable import MacScope

#if DEBUG
@MainActor
final class NativeDecompilerScriptingCaptureTests: XCTestCase {
    private let functionID = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    private let binaryID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    private let secondID = UUID(uuidString: "30000000-0000-0000-0000-000000000004")!
    private let thirdID = UUID(uuidString: "30000000-0000-0000-0000-000000000005")!

    func testT1ThreeFunctionsValidateExactlyOnce() async throws {
        let snapshot = try makeScriptingFixture()
        let work = CaptureWork()
        let dispatcher = CaptureDispatcher()
        let registry = makeRegistry(dispatcher, work: work)
        for id in [functionID, secondID, thirdID] {
            let reply = await registry.decompileForScripting(request(snapshot, id))
            XCTAssertEqual(reply, .completed(CaptureDispatcher.document))
        }
        // Red-first existing API: pin Registry:852-855 bypasses the store; value is 0, not 3.
        let successful = await registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(successful, 1)
        // Supplemental observer: catches a hidden direct validation in addition to capture.
        XCTAssertEqual(work.attempts, 1)
        XCTAssertEqual(dispatcher.requests.count, 3)
        await registry.shutdown()
    }

    func testT7ConcurrentDistinctFunctionsShareCapture() async throws {
        let snapshot = try makeScriptingFixture()
        let gate = CaptureBarrier()
        let work = CaptureWork()
        let dispatcher = CaptureDispatcher()
        let registry = makeRegistry(dispatcher, work: work, begin: { gate.blockFirst() })
        let first = Task { await registry.decompileForScripting(self.request(snapshot, self.functionID)) }
        await gate.waitForEntry()
        let submitted = CaptureSignal()
        let second = Task {
            submitted.signal()
            return await registry.decompileForScripting(self.request(snapshot, self.secondID))
        }
        await submitted.wait()
        gate.release()
        let a = await first.value
        let b = await second.value
        XCTAssertEqual(a, .completed(CaptureDispatcher.document))
        XCTAssertEqual(b, .completed(CaptureDispatcher.document))
        let successful = await registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(successful, 1) // Pin is 0: both calls bypass store.
        XCTAssertEqual(work.attempts, 1)
        XCTAssertEqual(Set(dispatcher.requests.map { $0.body.function.entryAddress.value }), [0x1000, 0x1008])
        await registry.shutdown()
    }

    func testT6PressureEvictsCaptureAndPreservesRequest() async throws {
        let snapshot = try makeScriptingFixture()
        let work = CaptureWork()
        let dispatcher = CaptureDispatcher()
        let registry = makeRegistry(dispatcher, work: work)
        let first = await registry.decompileForScripting(request(snapshot, functionID))
        await registry.memoryPressureDidOccur()
        let count = await registry.validatedImageCaptureCountForTesting()
        XCTAssertEqual(count, 0)
        let second = await registry.decompileForScripting(request(snapshot, functionID))
        XCTAssertEqual(first, second)
        XCTAssertEqual(dispatcher.requests.count, 2)
        XCTAssertEqual(try fixedPayload(dispatcher.requests[0]), try fixedPayload(dispatcher.requests[1]))
        XCTAssertEqual(work.attempts, 2) // Supplemental instrumentation assertion.
        await registry.shutdown()
    }

    func testT2T10OldCopyRenameReanalysisAndFreshRegistryIsolation() async throws {
        let a = try makeScriptingFixture()
        var b = a
        b.addressOverrides[ImageAddress(slot: .primary, address: 0x1000)] = .init(customName: "edited")
        XCTAssertNotEqual(a.analysisGenerationID, b.analysisGenerationID)
        let dispatcher = CaptureDispatcher(identitySpecific: true)
        let registry = makeRegistry(dispatcher)
        for snapshot in [a, b, a, b] {
            let result = await registry.decompileForScripting(request(snapshot, functionID))
            let direct = try NativeDecompilerSnapshotBuilder.build(from: snapshot, imageSlot: .primary,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets)
            let expected = try NativeDecompilerSubmission(snapshot: direct).projection.requestSHA256
            XCTAssertEqual(result, .completed(CaptureDispatcher.identityDocument(expected)))
            // Cached replies need not dispatch; expected identities are also checked below.
            XCTAssertTrue(dispatcher.requests.contains { $0.body.requestSHA256 == expected })
        }
        var stale = b
        stale.mutateAnalysis(in: .primary) { $0.functions[0].name = "stale" }
        XCTAssertNotEqual(stale.analysisGenerationID, b.analysisGenerationID)
        // Every projection refusal is classified unavailable (NativeDecompilerPresentationTerminalReason
        // .isUnavailable); the exact refusal stays observable in the disclosure detail.
        let refused = await registry.decompileDisclosedForScripting(request(stale, functionID))
        XCTAssertEqual(refused.outcome, .unavailable)
        XCTAssertEqual(refused.detail, "projection-analysisFingerprintMismatch")
        let other = makeRegistry(CaptureDispatcher())
        let otherResult = await other.decompileForScripting(request(a, functionID))
        XCTAssertEqual(otherResult, .completed(CaptureDispatcher.document))
        await other.shutdown()
        await registry.shutdown()
    }

    func testT5OverByteAndRowCapsKeepOrdinaryRequests() async throws {
        for snapshot in [try makeScriptingFixture(byteCount: 64 * 1_048_576 + 1),
                         try makeScriptingFixture(xrefCount: 200_001)] {
            let dispatcher = CaptureDispatcher()
            let work = CaptureWork()
            let registry = makeRegistry(dispatcher, work: work)
            let direct = try NativeDecompilerSnapshotBuilder.build(from: snapshot, imageSlot: .primary,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets)
            let expected = try NativeDecompilerSubmission(snapshot: direct).projection.requestSHA256
            for _ in 0..<2 {
                let reply = await registry.decompileForScripting(request(snapshot, functionID))
                XCTAssertEqual(reply, .completed(CaptureDispatcher.document))
            }
            XCTAssertEqual(dispatcher.requests.first?.body.requestSHA256, expected)
            let expectedEnvelope = try NativeDecompilerSubmission(snapshot: direct).projection
                .makeRequestEnvelope(requestID: UUID())
            XCTAssertEqual(try fixedPayload(XCTUnwrap(dispatcher.requests.first)), try fixedPayload(expectedEnvelope))
            let retained = await registry.validatedImageCaptureCountForTesting()
            XCTAssertEqual(retained, 0)
            XCTAssertEqual(work.attempts, 2)
            await registry.shutdown()
        }
    }

    func testT5RawDuplicateRowsExerciseScriptingRetentionBackstop() async throws {
        for rawRows in [200_000, 200_001] {
            var snapshot = try makeScriptingFixture()
            var analysis = try XCTUnwrap(snapshot.analysis(in: .primary))
            let duplicate = try XCTUnwrap(analysis.functions.first { $0.id == secondID })
            analysis.functions += Array(repeating: duplicate, count: rawRows - analysis.functions.count)
            analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
                binary: XCTUnwrap(snapshot.binary(in: .primary)), analysis: analysis)
            snapshot.analysisBySlot[.primary] = analysis
            XCTAssertEqual(analysis.functions.count, rawRows)
            XCTAssertTrue(analysis.xrefs.isEmpty)
            XCTAssertTrue(analysis.relocations.isEmpty)
            XCTAssertTrue(analysis.symbols.isEmpty)
            // Only a DIFFERENT function is duplicated. The selected function stays unambiguous.
            XCTAssertEqual(analysis.functions.filter { $0.id == functionID }.count, 1)
            let direct = try NativeDecompilerSnapshotBuilder.build(from: snapshot, imageSlot: .primary,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets)
            let directEnvelope = try NativeDecompilerRequestProjection(snapshotProjection: direct)
                .makeRequestEnvelope(requestID: UUID())
            let work = CaptureWork()
            let store = NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { work.enter() }))
            let fence = NativeDecompilerAdmissionFence()
            let token = try XCTUnwrap(fence.advance())
            let registryID = UUID()
            let owner = UUID()
            for _ in 0..<2 {
                let image = try await store.captureForScripting(registryID: registryID, owner: owner,
                    snapshot: snapshot, imageSlot: .primary, admissionToken: token)
                XCTAssertEqual(image.functionsByID.count, 3)
                // The old unique-ID charge alone would retain BOTH fixtures.
                XCTAssertLessThan(image.retainedBytes, 64 * 1_048_576)
                let captured = try NativeDecompilerSnapshotBuilder.build(from: snapshot, validatedImage: image,
                    functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets)
                XCTAssertEqual(direct, captured)
                let envelope = try NativeDecompilerRequestProjection(snapshotProjection: captured)
                    .makeRequestEnvelope(requestID: UUID())
                XCTAssertEqual(try fixedPayload(directEnvelope), try fixedPayload(envelope))
            }
            let retained = await store.captureCount()
            let validations = await store.validationCount()
            XCTAssertEqual(retained, rawRows == 200_000 ? 1 : 0)
            XCTAssertEqual(validations, rawRows == 200_000 ? 1 : 2)
            XCTAssertEqual(work.attempts, rawRows == 200_000 ? 1 : 2)
        }
    }

    func testT5RawRowBoundaryAndOverflowIncludeDuplicates() {
        typealias Key = NativeDecompilerScriptingCaptureKey
        XCTAssertEqual(Key.rawRowCount(functions: 50_000, xrefs: 50_000, relocations: 50_000, symbols: 50_000), 200_000)
        XCTAssertTrue(Key.permitsRetention(functions: 200_000, xrefs: 0, relocations: 0, symbols: 0))
        XCTAssertFalse(Key.permitsRetention(functions: 200_001, xrefs: 0, relocations: 0, symbols: 0))
        XCTAssertEqual(Key.rawRowCount(functions: Int.max, xrefs: 1, relocations: 0, symbols: 0), Int.max)
        XCTAssertFalse(Key.permitsRetention(functions: Int.max, xrefs: Int.max, relocations: Int.max, symbols: Int.max))
        // Counts are raw lengths, so 200001 duplicate IDs cannot collapse to one row.
    }

    func testT8CancelledValidationDoesNotPublishAndLiveFollowerRevalidates() async throws {
        let snapshot = try makeScriptingFixture()
        let finish = CaptureBarrier()
        let work = CaptureWork()
        let dispatcher = CaptureDispatcher()
        let registry = makeRegistry(dispatcher, work: work, finish: { finish.blockFirst() })
        let cancelled = Task { await registry.decompileForScripting(self.request(snapshot, self.functionID)) }
        await finish.waitForEntry()
        cancelled.cancel()
        // The scheduler resolves the cancelled waiter and cancels the running operation task in
        // one actor turn, so this await returns only after the worker's task is cancelled. Releasing
        // the held validation earlier races the asynchronous cancel hop and lets it publish.
        let cancelledReply = await cancelled.value
        XCTAssertEqual(cancelledReply, .failed(code: "cancelled"))
        let live = Task { await registry.decompileForScripting(self.request(snapshot, self.secondID)) }
        finish.release()
        let liveReply = await live.value
        XCTAssertEqual(liveReply, .completed(CaptureDispatcher.document))
        XCTAssertEqual(dispatcher.requests.count, 1)
        XCTAssertEqual(dispatcher.requests.first?.body.function.entryAddress.value, 0x1008)
        XCTAssertEqual(work.attempts, 2)
        let retained = await registry.validatedImageCaptureCountForTesting()
        XCTAssertEqual(retained, 1)
        await registry.shutdown()
    }

    func testT10IdenticalFunctionIDsInDistinctImagesAndSlots() async throws {
        var snapshot = try makeScriptingFixture()
        let otherSlot = ImageSlot(rawValue: 7)
        let source = try XCTUnwrap(snapshot.binary(in: .primary))
        let binary = BinaryImage(id: UUID(uuidString: "10000000-0000-0000-0000-000000000002")!,
            name: source.name, path: source.path, kind: source.kind, architecture: source.architecture,
            artifactIdentity: source.artifactIdentity, preferredSegmentLayout: source.preferredSegmentLayout,
            artifactIntegrityState: .verified, slot: otherSlot)
        var analysis = try XCTUnwrap(snapshot.analysis(in: .primary))
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
        snapshot.binaries.append(binary)
        snapshot.analysisBySlot[otherSlot] = analysis
        let dispatcher = CaptureDispatcher(identitySpecific: true)
        let registry = makeRegistry(dispatcher)
        for selected in [ImageSlot.primary, otherSlot, .primary, otherSlot] {
            let reply = await registry.decompileForScripting(.init(snapshot: snapshot, imageSlot: selected,
                functionID: functionID, startAddress: 0x1000))
            let direct = try NativeDecompilerSnapshotBuilder.build(from: snapshot, imageSlot: selected,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets)
            let digest = try NativeDecompilerSubmission(snapshot: direct).projection.requestSHA256
            XCTAssertEqual(reply, .completed(CaptureDispatcher.identityDocument(digest)))
            XCTAssertTrue(dispatcher.requests.contains { $0.body.requestSHA256 == digest })
        }
        await registry.shutdown()
    }

    func testT8DeadlineWinsBeforeHeldWorkerCleanup() async throws {
        let cleanup = CaptureSignal()
        let started = CaptureSignal()
        let expired = CaptureSignal()
        let work = Task<ScriptValue, Error> {
            started.signal()
            await cleanup.wait()
            return .string("late worker output")
        }
        await started.wait()
        do {
            _ = try await WorkspaceScriptingAPI.awaitSnapshotRead(work, deadlineNanoseconds: 0,
                onExpiry: { work.cancel(); expired.signal() })
            XCTFail("held work cannot win against deadline")
        } catch let refusal as DecompileBudgetRefusal {
            XCTAssertEqual(refusal, .deadline(milliseconds: 0))
        }
        // Deadline delivery is observed while worker cleanup remains explicitly held.
        await expired.wait()
        XCTAssertTrue(work.isCancelled)
        cleanup.signal()
        _ = try await work.value
    }

    func testT8OuterCancellationReleasesBeforeWorkerCleanup() async throws {
        let cleanup = CaptureSignal()
        let started = CaptureSignal()
        let work = Task<ScriptValue, Error> {
            started.signal()
            await cleanup.wait()
            return .string("late worker output")
        }
        await started.wait()
        let waiting = Task {
            try await WorkspaceScriptingAPI.awaitSnapshotRead(work,
                deadlineNanoseconds: UInt64.max / 4, onExpiry: {})
        }
        waiting.cancel()
        do { _ = try await waiting.value; XCTFail("cancelled read must release") }
        catch is CancellationError {}
        // This statement is reached while work is still deliberately held.
        cleanup.signal()
        _ = try await work.value
    }

    func testT11TraceOffOnPreservesDisclosuresRequestsAndReplyBytes() async throws {
        let snapshot = try makeScriptingFixture()
        let disabledRegistry = makeRegistry(CaptureDispatcher())
        let enabledRegistry = makeRegistry(CaptureDispatcher())
        let clock = PhaseTestClock()
        let sink = PhaseTestSink()
        let off = await NativeDecompilerPhaseRecord.withTrace(nil) {
            await disabledRegistry.decompileDisclosedForScripting(self.request(snapshot, self.functionID))
        }
        XCTAssertEqual(clock.readCount, 0)
        let record = NativeDecompilerPhaseRecord(clock: { clock.read() }, sink: { sink.append($0) })
        let on = await NativeDecompilerPhaseRecord.withTrace(record) {
            await enabledRegistry.decompileDisclosedForScripting(self.request(snapshot, self.functionID))
        }
        XCTAssertEqual(off, on)
        XCTAssertEqual(off.cache, "miss")
        let fixedID = UUID(uuidString: "40000000-0000-0000-0000-000000000004")!
        func encode() throws -> (NativeDecompilerPreencodedDispatchRequest, NativeDecompilerWireReplyEnvelope, Data) {
            let projection = try NativeDecompilerSnapshotBuilder.build(from: snapshot, imageSlot: .primary,
                functionID: functionID, budgets: NativeDecompilerRuntimeRegistry.productBudgets)
            // The stub reply carries only a document, which is valid solely for decompile-document.
            let submission = try NativeDecompilerSubmission(snapshot: projection, operation: .decompileDocument)
            let request = try NativeDecompilerPreencodedDispatchRequest(projection: submission.projection, requestID: fixedID)
            let reply = CaptureDispatcher.reply(for: request.envelope)
            return (request, reply, try NativeDecompilerWireCodec().encodeReply(reply, matching: request.expectedBinding))
        }
        let a = try NativeDecompilerPhaseRecord.withTrace(nil) { try encode() }
        let b = try NativeDecompilerPhaseRecord.withTrace(record) { try encode() }
        XCTAssertEqual(a.0, b.0)
        XCTAssertEqual(a.1, b.1)
        XCTAssertEqual(a.2, b.2)
        record.finish()
        XCTAssertEqual(sink.values.count, 1)
        XCTAssertEqual(WorkspaceScriptingAPI.maximumDecompileFunctionBytes, 262_144)
        XCTAssertEqual(WorkspaceScriptingAPI.maximumDecompileFunctionBlocks, 8_192)
        XCTAssertEqual(WorkspaceScriptingAPI.defaultDecompileDeadlineNanoseconds, 27_000_000_000)
        await disabledRegistry.shutdown()
        await enabledRegistry.shutdown()
    }

    func testT11FakeClockInclusiveAccountingAndDisabledClockSilence() {
        let clock = PhaseTestClock()
        let sink = PhaseTestSink()
        NativeDecompilerPhaseRecord.withTrace(nil) {
            let absent = NativeDecompilerPhaseRecord.current()
            XCTAssertNil(absent)
            absent?.end(absent?.begin(.snapshotRead))
        }
        XCTAssertEqual(clock.readCount, 0)
        let record = NativeDecompilerPhaseRecord(clock: { clock.read() }, sink: { sink.append($0) })
        let parent = record.begin(.snapshotRead) // 20
        let child = record.begin(.validation) // 30
        record.end(child) // 40
        record.end(parent) // 50
        record.add(.sliceDigestPasses, 1)
        record.finish() // 60; attempt began at 10
        record.finish()
        XCTAssertEqual(sink.values.count, 1)
        let summary = sink.values[0]
        XCTAssertEqual(summary.elapsedNanoseconds, 50)
        XCTAssertEqual(summary.durations[NativeDecompilerPhaseRecord.Phase.snapshotRead.rawValue], 30)
        XCTAssertEqual(summary.durations[NativeDecompilerPhaseRecord.Phase.validation.rawValue], 10)
        XCTAssertEqual(summary.counts[NativeDecompilerPhaseRecord.Counter.sliceDigestPasses.rawValue], 1)
        XCTAssertTrue(summary.counterObserved[NativeDecompilerPhaseRecord.Counter.sliceDigestPasses.rawValue])
        XCTAssertFalse(summary.counterObserved[NativeDecompilerPhaseRecord.Counter.contextIterations.rawValue])
        // Parent wall duration already includes child duration; these are not added.
    }

    func testT13DiagnosticCapacityOwnerLimitAndLateCallbacks() throws {
        let lookup = NativeDecompilerPhaseLookup()
        let clock = PhaseTestClock()
        let sink = PhaseTestSink()
        let record = NativeDecompilerPhaseRecord(clock: { clock.read() }, sink: { sink.append($0) })
        let owner = UUID()
        let requestID = UUID()
        let lease = try XCTUnwrap(lookup.register(requestID: requestID, owner: owner, record: record))
        XCTAssertNil(lookup.register(requestID: requestID, owner: UUID(), record: record))
        XCTAssertNil(lookup.register(requestID: UUID(), owner: owner, record: record))
        var registrations: [(UUID, UUID)] = [(requestID, lease)]
        for _ in 1..<128 {
            let id = UUID()
            registrations.append((id, try XCTUnwrap(lookup.register(requestID: id, owner: UUID(), record: record))))
        }
        XCTAssertNil(lookup.register(requestID: UUID(), owner: UUID(), record: record))
        lookup.retire(requestID: requestID, lease: UUID())
        XCTAssertTrue(lookup.lookup(requestID: requestID) === record)
        lookup.retire(requestID: requestID, lease: lease)
        XCTAssertNil(lookup.lookup(requestID: requestID))
        let replacement = try XCTUnwrap(lookup.register(requestID: requestID, owner: owner, record: record))
        lookup.retire(requestID: requestID, lease: lease) // late generation callback
        XCTAssertTrue(lookup.lookup(requestID: requestID) === record)
        lookup.retire(requestID: requestID, lease: replacement)
        for (id, token) in registrations.dropFirst() { lookup.retire(requestID: id, lease: token) }
        let spans = (0..<64).map { _ in record.begin(.dispatch) }
        XCTAssertTrue(spans.allSatisfy { $0 != nil })
        XCTAssertNil(record.begin(.dispatch))
        let finishID = UUID()
        _ = try XCTUnwrap(lookup.register(requestID: finishID, owner: UUID(), record: record))
        XCTAssertTrue(lookup.lookup(requestID: finishID) === record)
        record.finish() // terminal/cancellation seals pending spans exactly once
        XCTAssertNil(lookup.lookup(requestID: finishID), "finish retires an already registered lease")
        let reads = clock.readCount
        for span in spans { record.end(span) }
        XCTAssertNil(record.begin(.replyDecode))
        record.add(.encodedBytes, 10)
        record.finish()
        XCTAssertEqual(clock.readCount, reads)
        XCTAssertEqual(sink.values.count, 1)
        XCTAssertEqual(sink.values[0].suppressedSpans, 1)
        XCTAssertEqual(sink.values[0].unfinishedSpans, 64)
        XCTAssertNil(lookup.lookup(requestID: requestID))
        XCTAssertNil(lookup.register(requestID: UUID(), owner: UUID(), record: record),
                     "a finished record cannot be registered by a late callback")
    }

    func testT13SuppressedRegistrationPreservesNativeReply() async throws {
        let snapshot = try makeScriptingFixture()
        let baselineRegistry = makeRegistry(CaptureDispatcher())
        let tracedRegistry = makeRegistry(CaptureDispatcher())
        let baseline = await baselineRegistry.decompileDisclosedForScripting(request(snapshot, functionID))
        let sink = PhaseTestSink()
        let record = NativeDecompilerPhaseRecord(clock: { 100 }, sink: { sink.append($0) })
        let lookup = NativeDecompilerPhaseLookup.shared
        var registrations: [(UUID, UUID)] = []
        defer {
            for (id, lease) in registrations { lookup.retire(requestID: id, lease: lease) }
        }
        for _ in 0..<128 {
            let id = UUID()
            registrations.append((id, try XCTUnwrap(lookup.register(requestID: id, owner: UUID(), record: record))))
        }
        let traced = await NativeDecompilerPhaseRecord.withTrace(record) {
            await tracedRegistry.decompileDisclosedForScripting(self.request(snapshot, self.functionID))
        }
        XCTAssertEqual(traced, baseline)
        record.finish()
        XCTAssertEqual(sink.values.count, 1)
        XCTAssertEqual(sink.values[0].counts[NativeDecompilerPhaseRecord.Counter.traceRegistrationSuppressed.rawValue], 1)
        await baselineRegistry.shutdown()
        await tracedRegistry.shutdown()
    }

    func testT2ExplicitNativeCommentRefusalPrecedesNativeValidation() async throws {
        var snapshot = try makeScriptingFixture()
        snapshot.addressOverrides[ImageAddress(slot: .primary, address: 0x1000)] = .init(customComment: "authored comment")
        let native = CaptureNativeProvider()
        do {
            _ = try await WorkspaceScriptingAPI.decompileNativeFirst(
                .object(["address": .hex(0x1000), "backend": .string("native")]),
                snapshot: snapshot, native: native, checkpoint: {})
            XCTFail("explicit native with authored comment must refuse")
        } catch let ScriptingError.structuredRefusal(refusal) {
            XCTAssertTrue(refusal.detail.contains("native text cannot place authored comments"))
        }
        XCTAssertEqual(native.calls, 0)
    }

    func testT11FixedScriptSerializerOffOnEquality() async throws {
        let snapshot = try makeScriptingFixture()
        let native = CaptureNativeProvider()
        let args = ScriptValue.object(["address": .hex(0x1000), "backend": .string("native")])
        let off = try await NativeDecompilerPhaseRecord.withTrace(nil) {
            try await WorkspaceScriptingAPI.decompileNativeFirst(args, snapshot: snapshot,
                native: native, checkpoint: {})
        }
        let record = NativeDecompilerPhaseRecord(clock: { 100 }, sink: { _ in })
        let on = try await NativeDecompilerPhaseRecord.withTrace(record) {
            try await WorkspaceScriptingAPI.decompileNativeFirst(args, snapshot: snapshot,
                native: native, checkpoint: {})
        }
        record.finish()
        XCTAssertEqual(off, on)
        XCTAssertEqual(try off.jsonData(), try on.jsonData())
    }

    func testT5FifthOwnerPreservesFourOwnerBound() async throws {
        let store = NativeDecompilerValidatedImageStore()
        let snapshot = try makeScriptingFixture()
        let fence = NativeDecompilerAdmissionFence()
        let token = try XCTUnwrap(fence.advance())
        let revision = UUID()
        let owners = (1...5).map { UUID(uuidString: "00000000-0000-0000-0000-00000000000\($0)")! }
        for owner in owners {
            _ = try await store.capture(owner: owner, revision: revision, snapshot: snapshot,
                imageSlot: .primary, admissionToken: token)
        }
        let count = await store.captureCount()
        XCTAssertEqual(count, 4)
        _ = try await store.capture(owner: owners[0], revision: revision, snapshot: snapshot,
            imageSlot: .primary, admissionToken: token)
        let validations = await store.validationCount()
        XCTAssertEqual(validations, 6)
    }

    func testT5ExactlyByteCapIsRetained() async throws {
        let small = try makeScriptingFixture()
        let image = try NativeDecompilerSnapshotBuilder.validateImage(from: small, imageSlot: .primary)
        let rowCharge = image.retainedBytes - image.selectedSliceBytes.count
        let exact = try makeScriptingFixture(byteCount: 64 * 1_048_576 - rowCharge)
        let store = NativeDecompilerValidatedImageStore()
        let fence = NativeDecompilerAdmissionFence()
        let token = try XCTUnwrap(fence.advance())
        let retained = try await store.capture(owner: UUID(), revision: UUID(), snapshot: exact,
            imageSlot: .primary, admissionToken: token)
        XCTAssertEqual(retained.retainedBytes, 64 * 1_048_576)
        let count = await store.captureCount()
        XCTAssertEqual(count, 1)
    }

    // MARK: WR01 / WR04 integrated capture and runtime branch tests (test-only)

    private typealias Rec = NativeDecompilerPhaseRecord

    /// TC01: P-cold on the API route, equality oracle E against a trace-off fresh registry.
    func testWR01TC01ColdRouteCountsAndOracle() async throws {
        let snapshot = try makeScriptingFixture()
        let rig = try makeRig(snapshot)
        let before = await rig.registry.validatedImageValidationCountForTesting()
        let cold = try await call(rig, 0x1000)
        assertCleanSummary(cold.summary)
        assertPCold(cold.summary)
        let after = await rig.registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(after - before, 1)
        XCTAssertEqual(rig.work.attempts, 1)
        XCTAssertEqual(rig.dispatcher.requests.count, 1)
        XCTAssertEqual(cold.value["cache"], .string("miss"))
        let baseline = try await freshBaseline(rig.store.snapshot, address: 0x1000)
        XCTAssertEqual(cold.value, baseline.value)
        XCTAssertEqual(try rig.dispatcher.requests.last.map(fixedPayload), baseline.payload)
        await rig.registry.shutdown()
    }

    /// TC01: synthetic ordinal-clock records, interval capacity 256.
    func testWR01TC01SyntheticIntervalCapacity() {
        for (spans, dropped, complete) in [(256, UInt64(0), true), (257, UInt64(1), false)] {
            let clock = PhaseTestClock()
            let sink = PhaseTestSink()
            let record = Rec(clock: { clock.read() }, sink: { sink.append($0) })
            for _ in 0..<spans { record.end(record.begin(.validation)) }
            record.finish()
            XCTAssertEqual(sink.values.count, 1)
            let summary = sink.values[0]
            XCTAssertEqual(summary.droppedIntervals, dropped)
            XCTAssertEqual(summary.completedSpans[Rec.Phase.validation.rawValue], UInt64(spans))
            XCTAssertEqual(summary.attributionComplete, complete)
        }
    }

    /// TC02: warm repeat reuses the capture; the result branch is asserted literally (OQ5).
    func testWR01TC02WarmCallReusesCaptureAndReportsLiteralResultBranch() async throws {
        let rig = try makeRig(makeScriptingFixture())
        let cold = try await call(rig, 0x1000)
        assertPCold(cold.summary)
        let dispatchedAfterCold = rig.dispatcher.requests.count
        let attemptsAfterCold = rig.work.attempts
        let validationsAfterCold = await rig.registry.validatedImageValidationCountForTesting()
        let warm = try await call(rig, 0x1000)
        assertCleanSummary(warm.summary)
        assertPReuse(warm.summary)
        XCTAssertEqual(rig.work.attempts - attemptsAfterCold, 0)
        let validationsAfterWarm = await rig.registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validationsAfterWarm - validationsAfterCold, 0)
        let delta = rig.dispatcher.requests.count - dispatchedAfterCold
        switch resultBranch(warm.summary) {
        case "hit":
            XCTAssertNil(counter(warm.summary, .resultCacheMisses))
            XCTAssertEqual(delta, 0)
            for phase in [Rec.Phase.dispatch, .replyDecode, .replyValidation, .cacheRetention] {
                XCTAssertEqual(warm.summary.completedSpans[phase.rawValue], 0, "\(phase)")
            }
            XCTAssertEqual(warm.value["cache"], .string("hit"))
        case "miss":
            XCTAssertNil(counter(warm.summary, .resultCacheHits))
            XCTAssertEqual(counter(warm.summary, .resultCacheMisses), 1)
            XCTAssertEqual(delta, 1)
            XCTAssertEqual(warm.value["cache"], .string("miss"))
        default:
            XCTFail("neither result-cache hit nor miss observed")
        }
        print("WR01-TC02 literal result-cache branch on the warm call: \(resultBranch(warm.summary))")
        XCTAssertEqual(withoutCache(warm.value), withoutCache(cold.value))
        await rig.registry.shutdown()
    }

    /// TC04: a same-value write to `binaries` renews the native token, so the next call re-validates.
    func testWR01TC04SameValueBinaryWriteForcesRevalidation() async throws {
        let rig = try makeRig(makeScriptingFixture())
        _ = try await call(rig, 0x1000)
        let tokenBefore = rig.store.snapshot.nativeImageValidationGenerationID
        var edited = rig.store.snapshot
        let sameBinaries = edited.binaries
        edited.binaries = sameBinaries
        XCTAssertNotEqual(edited.nativeImageValidationGenerationID, tokenBefore)
        rig.store.snapshot = edited
        let attempts = rig.work.attempts
        let validations = await rig.registry.validatedImageValidationCountForTesting()
        let next = try await call(rig, 0x1000)
        assertCleanSummary(next.summary)
        XCTAssertEqual(counter(next.summary, .captureMisses), 1)
        XCTAssertNil(counter(next.summary, .captureHits))
        XCTAssertEqual(counter(next.summary, .sliceDigestPasses), 1)
        XCTAssertEqual(counter(next.summary, .canonicalPasses), 2)
        XCTAssertEqual(rig.work.attempts - attempts, 1)
        let validationsAfter = await rig.registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validationsAfter - validations, 1)
        let baseline = try await freshBaseline(rig.store.snapshot, address: 0x1000)
        XCTAssertEqual(withoutCache(next.value), withoutCache(baseline.value))
        await rig.registry.shutdown()
    }

    /// TC04: an unverified artifact is refused with the exact projection error and never dispatches.
    func testWR01TC04UnverifiedArtifactRefusal() async throws {
        var snapshot = try makeScriptingFixture()
        snapshot.binaries[0].artifactIntegrityState = .unavailable
        let dispatcher = CaptureDispatcher()
        let work = CaptureWork()
        let registry = makeRegistry(dispatcher, work: work)
        let traced = try await tracedDisclosure(registry, snapshot, functionID)
        XCTAssertEqual(traced.disclosure.detail, "projection-unverifiedArtifact")
        XCTAssertNotEqual(traced.disclosure.outcome, .completed(CaptureDispatcher.document))
        XCTAssertEqual(work.attempts, 1)
        let validations = await registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validations, 0)
        XCTAssertEqual(dispatcher.requests.count, 0)
        XCTAssertNil(counter(traced.summary, .canonicalPasses))
        await registry.shutdown()
    }

    /// TC05: a same-value analysis assignment renews the native token.
    func testWR01TC05SameValueAnalysisAssignmentForcesRevalidation() async throws {
        let rig = try makeRig(makeScriptingFixture())
        _ = try await call(rig, 0x1000)
        var edited = rig.store.snapshot
        edited.analysisBySlot[.primary] = try XCTUnwrap(edited.analysisBySlot[.primary])
        rig.store.snapshot = edited
        let validations = await rig.registry.validatedImageValidationCountForTesting()
        let next = try await call(rig, 0x1000)
        XCTAssertEqual(counter(next.summary, .captureMisses), 1)
        XCTAssertNil(counter(next.summary, .captureHits))
        let validationsAfter = await rig.registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validationsAfter - validations, 1)
        await rig.registry.shutdown()
    }

    /// TC05: a real function-name edit under a deliberately stale stored fingerprint cannot reuse or dispatch.
    func testWR01TC05StaleFingerprintRefusesWithoutDispatch() async throws {
        var snapshot = try makeScriptingFixture()
        var analysis = try XCTUnwrap(snapshot.analysisBySlot[.primary])
        analysis.functions[0].name = "entry_renamed"
        snapshot.analysisBySlot[.primary] = analysis // stored fingerprint left stale on purpose
        let dispatcher = CaptureDispatcher()
        let work = CaptureWork()
        let registry = makeRegistry(dispatcher, work: work)
        let traced = try await tracedDisclosure(registry, snapshot, functionID)
        XCTAssertEqual(traced.disclosure.detail, "projection-analysisFingerprintMismatch")
        XCTAssertEqual(work.attempts, 1)
        let validations = await registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validations, 0)
        XCTAssertEqual(dispatcher.requests.count, 0)
        XCTAssertNil(counter(traced.summary, .canonicalPasses))
        let fresh = makeRegistry(CaptureDispatcher())
        let current = await fresh.decompileDisclosedForScripting(request(snapshot, functionID))
        XCTAssertEqual(current.outcome, traced.disclosure.outcome)
        XCTAssertEqual(current.detail, traced.disclosure.detail)
        await fresh.shutdown()
        await registry.shutdown()
    }

    /// TC05: stale slice bytes under an unchanged fingerprint are refused and never reuse a capture.
    func testWR01TC05InvalidBytesCannotReuse() async throws {
        let snapshot = try makeScriptingFixture()
        let dispatcher = CaptureDispatcher()
        let registry = makeRegistry(dispatcher)
        let first = try await tracedDisclosure(registry, snapshot, functionID)
        XCTAssertEqual(first.disclosure.outcome, .completed(CaptureDispatcher.document))
        var edited = snapshot
        var analysis = try XCTUnwrap(edited.analysisBySlot[.primary])
        analysis.imageBytes[0] = 1
        edited.analysisBySlot[.primary] = analysis
        let second = try await tracedDisclosure(registry, edited, functionID)
        XCTAssertNil(counter(second.summary, .captureHits))
        XCTAssertNotEqual(second.disclosure.outcome, .completed(CaptureDispatcher.document))
        XCTAssertEqual(dispatcher.requests.count, 1)
        await registry.shutdown()
    }

    /// TC06: A/B/A with no other writes misses and re-validates every time; one latest capture is retained.
    func testWR01TC06ABAImagesNeverReuseAcrossImages() async throws {
        let imageA = try makeScriptingFixture()
        let imageB = try makeScriptingFixture(byteCount: 64)
        let dispatcher = CaptureDispatcher()
        let work = CaptureWork()
        let registry = makeRegistry(dispatcher, work: work)
        for (index, image) in [imageA, imageB, imageA].enumerated() {
            let before = await registry.validatedImageValidationCountForTesting()
            let traced = try await tracedDisclosure(registry, image, functionID)
            XCTAssertEqual(counter(traced.summary, .captureMisses), 1, "call \(index)")
            XCTAssertNil(counter(traced.summary, .captureHits), "call \(index)")
            XCTAssertEqual(counter(traced.summary, .sliceDigestPasses), 1, "call \(index)")
            let after = await registry.validatedImageValidationCountForTesting()
            XCTAssertEqual(after - before, 1, "call \(index)")
            // Each reply equals its own fresh selected-image baseline (outcome; request identity if dispatched).
            let fresh = makeRegistry(CaptureDispatcher())
            let baseline = await fresh.decompileDisclosedForScripting(request(image, functionID))
            XCTAssertEqual(traced.disclosure.outcome, baseline.outcome, "call \(index)")
            await fresh.shutdown()
        }
        let total = await registry.validatedImageValidationCountForTesting()
        let retained = await registry.validatedImageCaptureCountForTesting()
        XCTAssertEqual(total, 3)
        XCTAssertEqual(retained, 1)
        XCTAssertEqual(work.attempts, 3)
        await registry.shutdown()
    }

    /// TC07: a first-time second function reuses the capture but is a fresh result and dispatch.
    func testWR01TC07NewFunctionReusesCaptureWithFreshResult() async throws {
        let rig = try makeRig(makeScriptingFixture())
        _ = try await call(rig, 0x1000)
        let attempts = rig.work.attempts
        let dispatched = rig.dispatcher.requests.count
        let validations = await rig.registry.validatedImageValidationCountForTesting()
        let second = try await call(rig, 0x1008)
        assertCleanSummary(second.summary)
        let expected: [(Rec.Counter, UInt64?)] = [
            (.captureHits, 1), (.captureMisses, nil), (.captureOverCap, nil),
            (.resultCacheMisses, 1), (.resultCacheHits, nil), (.canonicalPasses, 2),
            (.visitedInstructions, 0), (.visitedBlocks, 0), (.visitedEdges, 0), (.visitedCalls, 0),
            (.functionsConsidered, 3), (.blocksVisited, 1), (.overridesVisited, 0),
        ]
        assertCounters(second.summary, expected)
        XCTAssertEqual(rig.work.attempts - attempts, 0)
        XCTAssertEqual(rig.dispatcher.requests.count - dispatched, 1)
        let validationsAfter = await rig.registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validationsAfter - validations, 0)
        let baseline = try await freshBaseline(rig.store.snapshot, address: 0x1008)
        XCTAssertEqual(second.value, baseline.value)
        XCTAssertEqual(try rig.dispatcher.requests.last.map(fixedPayload), baseline.payload)
        await rig.registry.shutdown()
    }

    /// TC08: raw-row bound through the traced store; counter branches at 200,000 and 200,001.
    func testWR01TC08RawRowBoundCaptureCounters() async throws {
        for rawRows in [200_000, 200_001] {
            var snapshot = try makeScriptingFixture()
            var analysis = try XCTUnwrap(snapshot.analysisBySlot[.primary])
            let duplicate = try XCTUnwrap(analysis.functions.first { $0.id == secondID })
            analysis.functions += Array(repeating: duplicate, count: rawRows - analysis.functions.count)
            analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
                binary: XCTUnwrap(snapshot.binary(in: .primary)), analysis: analysis)
            snapshot.analysisBySlot[.primary] = analysis
            let admits = rawRows == 200_000
            let work = CaptureWork()
            let store = NativeDecompilerValidatedImageStore(workObserver: .init(validationDidBegin: { work.enter() }))
            let fence = NativeDecompilerAdmissionFence()
            let token = try XCTUnwrap(fence.advance())
            let registryID = UUID(), owner = UUID()
            var summaries: [Rec.Summary] = []
            for _ in 0..<2 {
                summaries.append(try await tracedCapture(store, registryID: registryID, owner: owner,
                    snapshot: snapshot, token: token))
            }
            if admits {
                XCTAssertEqual(counter(summaries[0], .captureMisses), 1)
                XCTAssertNil(counter(summaries[0], .captureHits))
                XCTAssertEqual(counter(summaries[1], .captureHits), 1)
                XCTAssertNil(counter(summaries[1], .captureMisses))
                for summary in summaries { XCTAssertNil(counter(summary, .captureOverCap)) }
            } else {
                for summary in summaries {
                    XCTAssertEqual(counter(summary, .captureMisses), 1)
                    XCTAssertEqual(counter(summary, .captureOverCap), 1)
                    XCTAssertNil(counter(summary, .captureHits))
                }
            }
            let retained = await store.captureCount()
            let validations = await store.validationCount()
            XCTAssertEqual(retained, admits ? 1 : 0)
            XCTAssertEqual(validations, admits ? 1 : 2)
            XCTAssertEqual(work.attempts, admits ? 1 : 2)
        }
        typealias Key = NativeDecompilerScriptingCaptureKey
        XCTAssertEqual(Key.rawRowCount(functions: 50_000, xrefs: 50_000, relocations: 50_000, symbols: 50_000), 200_000)
        XCTAssertTrue(Key.permitsRetention(functions: 50_000, xrefs: 50_000, relocations: 50_000, symbols: 50_000))
        XCTAssertEqual(Key.rawRowCount(functions: 50_000, xrefs: 50_000, relocations: 50_000, symbols: 50_001), 200_001)
        XCTAssertFalse(Key.permitsRetention(functions: 50_000, xrefs: 50_000, relocations: 50_000, symbols: 50_001))
        XCTAssertEqual(Key.rawRowCount(functions: Int.max, xrefs: 1, relocations: 0, symbols: 0), Int.max)
    }

    /// TC08 charged bound: the measured row charge puts the exact total at the 64 MiB cap (retained) or one over.
    func testWR01TC08ChargedBoundCaptureCounters() async throws {
        let cap = 64 * 1_048_576
        let small = try makeScriptingFixture()
        let image = try NativeDecompilerSnapshotBuilder.validateImage(from: small, imageSlot: .primary)
        let rowCharge = image.retainedBytes - image.selectedSliceBytes.count
        for (bytes, retains) in [(cap - rowCharge, true), (cap - rowCharge + 1, false)] {
            let snapshot = try makeScriptingFixture(byteCount: bytes)
            let store = NativeDecompilerValidatedImageStore()
            let fence = NativeDecompilerAdmissionFence()
            let token = try XCTUnwrap(fence.advance())
            let summary = try await tracedCapture(store, registryID: UUID(), owner: UUID(),
                snapshot: snapshot, token: token)
            XCTAssertEqual(counter(summary, .captureMisses), 1)
            XCTAssertEqual(counter(summary, .captureOverCap), retains ? nil : 1)
            let retained = await store.captureCount()
            XCTAssertEqual(retained, retains ? 1 : 0)
        }
    }

    /// TC16: cold then unchanged warm on one registry through the API route.
    func testWR01TC16ColdThenWarmPairObservations() async throws {
        let rig = try makeRig(makeScriptingFixture())
        let generation = rig.store.snapshot.analysisGenerationID.uuidString
        let cold = try await call(rig, 0x1000)
        let warm = try await call(rig, 0x1000)
        XCTAssertEqual(rig.factory.harnesses.count, 2)
        for harness in rig.factory.harnesses { XCTAssertEqual(harness.sink.values.count, 1) }
        assertPCold(cold.summary)
        XCTAssertEqual(cold.value["cache"], .string("miss"))
        XCTAssertEqual(cold.value["generation"], .string(generation))
        assertPReuse(warm.summary)
        XCTAssertEqual(warm.summary.completedSpans[Rec.Phase.validation.rawValue], 0)
        XCTAssertNil(counter(warm.summary, .sliceDigestPasses))
        XCTAssertEqual(warm.value["generation"], .string(generation))
        // The literal result branch is asserted, never assumed: a miss is its own branch.
        let branch = resultBranch(warm.summary)
        XCTAssertEqual(warm.value["cache"], .string(branch))
        XCTAssertTrue(branch == "hit" || branch == "miss")
        print("WR01-TC16 literal result-cache branch on the warm call: \(branch)")
        await rig.registry.shutdown()
    }

    // MARK: WR04 broad-only authoring writes

    func testWR04TC03AddressOverrideKeepsNativeTokenAndHitsCapture() async throws {
        try await assertBroadOnlyWrite { snapshot in
            snapshot.addressOverrides[ImageAddress(slot: .primary, address: 0x1000)] =
                AddressOverride(customName: "renamed_entry")
        }
    }

    func testWR04TC03ImportedPrototypeKeepsNativeTokenAndHitsCapture() async throws {
        let signature = FunctionSignatureOverride(returnType: "int",
            parameterList: .authoritative([ArgOverride(name: "value", type: "int")]),
            variadicState: .fixed, noReturnState: .returns)
        try await assertBroadOnlyWrite { snapshot in
            snapshot.importedPrototypes[ImageAddress(slot: .primary, address: 0x1000)] = signature
        }
    }

    func testWR04TC03TypeDefinitionKeepsNativeTokenAndHitsCapture() async throws {
        let definition = TypeDefinition(kind: .struct, name: "NativeValidationRecord",
            fields: [FieldDef(name: "value", type: "int")])
        try await assertBroadOnlyWrite { snapshot in snapshot.typeDefinitions = [definition] }
    }

    private func assertBroadOnlyWrite(
        _ edit: (inout WorkspaceSnapshot) -> Void,
        file: StaticString = #filePath, line: UInt = #line
    ) async throws {
        let original = try makeScriptingFixture()
        let dispatcher = CaptureDispatcher()
        let work = CaptureWork()
        let registry = makeRegistry(dispatcher, work: work)
        let cold = try await tracedDisclosure(registry, original, functionID)
        XCTAssertEqual(cold.disclosure.outcome, .completed(CaptureDispatcher.document), file: file, line: line)
        var edited = original
        edit(&edited)
        XCTAssertEqual(edited.nativeImageValidationGenerationID, original.nativeImageValidationGenerationID,
                       "native token unchanged", file: file, line: line)
        XCTAssertNotEqual(edited.analysisGenerationID, original.analysisGenerationID,
                          "broad token changed", file: file, line: line)
        let validations = await registry.validatedImageValidationCountForTesting()
        let dispatched = dispatcher.requests.count
        let traced = try await tracedDisclosure(registry, edited, functionID)
        XCTAssertEqual(counter(traced.summary, .captureHits), 1, file: file, line: line)
        XCTAssertNil(counter(traced.summary, .captureMisses), file: file, line: line)
        XCTAssertEqual(work.attempts, 1, file: file, line: line)
        let validationsAfter = await registry.validatedImageValidationCountForTesting()
        XCTAssertEqual(validationsAfter - validations, 0, file: file, line: line)
        XCTAssertEqual(traced.disclosure.outcome, .completed(CaptureDispatcher.document), file: file, line: line)
        // Edited authored input equals the fresh baseline of the mutated snapshot (typed payload equality).
        let freshDispatcher = CaptureDispatcher()
        let fresh = makeRegistry(freshDispatcher)
        _ = await fresh.decompileDisclosedForScripting(request(edited, functionID))
        // Literal result branch (OQ5): a result-cache hit dispatches nothing; a miss dispatches exactly once.
        let resultHit = counter(traced.summary, .resultCacheHits) == 1
        print("WR04-TC03 literal result-cache branch after the broad-only write: \(resultHit ? "hit" : "miss")")
        XCTAssertEqual(dispatcher.requests.count - dispatched, resultHit ? 0 : 1, file: file, line: line)
        XCTAssertEqual(freshDispatcher.requests.count, 1, file: file, line: line)
        // The reused path and the fresh baseline of the mutated snapshot carry the same typed payload.
        XCTAssertEqual(try dispatcher.requests.last.map(fixedPayload), try freshDispatcher.requests.last.map(fixedPayload),
                       file: file, line: line)
        XCTAssertEqual(traced.summary.completedSpans[Rec.Phase.validation.rawValue], 0, file: file, line: line)
        if counter(traced.summary, .canonicalPasses) != nil {
            XCTAssertEqual(counter(traced.summary, .canonicalPasses), 2, file: file, line: line)
        }
        await fresh.shutdown()
        await registry.shutdown()
    }

    // MARK: WR01 helpers (private)

    private func makeRig(_ snapshot: WorkspaceSnapshot, traced: Bool = true) throws -> CaptureRig {
        let dispatcher = CaptureDispatcher()
        let work = CaptureWork()
        let registry = makeRegistry(dispatcher, work: work)
        let factory = CaptureTraceFactory()
        let store = WorkspaceStore(workspaceName: "capture rig", snapshot: snapshot, engine: AnalysisEngine(),
                                   preparesXRefs: false, autosaveScheduler: nil)
        var attempt: (@Sendable () -> Rec?)?
        if traced { attempt = { factory.make() } }
        let api = WorkspaceScriptingAPI(
            store: store, nativeDecompiler: CaptureRegistryAdapter(registry: registry),
            decompileDeadlineNanoseconds: 10_000_000_000, phaseAttempt: attempt)
        return CaptureRig(registry: registry, work: work, dispatcher: dispatcher, factory: factory,
                          store: store, api: api)
    }

    private func call(_ rig: CaptureRig, _ address: Int64) async throws -> (value: ScriptValue, summary: Rec.Summary) {
        let before = rig.factory.harnesses.count
        let value = try await rig.api.executeAsync("decompile", arguments: .object(["address": .int(address)]))
        let harnesses = rig.factory.harnesses
        XCTAssertEqual(harnesses.count, before + 1)
        let sunk = try XCTUnwrap(harnesses.last).sink.values
        XCTAssertEqual(sunk.count, 1)
        return (value, try XCTUnwrap(sunk.first))
    }

    private func freshBaseline(_ snapshot: WorkspaceSnapshot, address: Int64) async throws
        -> (value: ScriptValue, payload: Data?) {
        let rig = try makeRig(snapshot, traced: false)
        let value = try await rig.api.executeAsync("decompile", arguments: .object(["address": .int(address)]))
        let payload = try rig.dispatcher.requests.last.map(fixedPayload)
        await rig.registry.shutdown()
        return (value, payload)
    }

    private func tracedDisclosure(
        _ registry: NativeDecompilerRuntimeRegistry, _ snapshot: WorkspaceSnapshot, _ id: UUID
    ) async throws -> (disclosure: ScriptingNativeDecompileDisclosure, summary: Rec.Summary) {
        let harness = CaptureTraceHarness()
        let disclosure = await Rec.withTrace(harness.record) {
            await registry.decompileDisclosedForScripting(self.request(snapshot, id))
        }
        harness.record.finish()
        return (disclosure, try XCTUnwrap(harness.sink.values.first))
    }

    private func tracedCapture(
        _ store: NativeDecompilerValidatedImageStore, registryID: UUID, owner: UUID,
        snapshot: WorkspaceSnapshot, token: NativeDecompilerAdmissionToken
    ) async throws -> Rec.Summary {
        let harness = CaptureTraceHarness()
        _ = try await Rec.withTrace(harness.record) {
            try await store.captureForScripting(registryID: registryID, owner: owner,
                snapshot: snapshot, imageSlot: .primary, admissionToken: token,
                trace: harness.record)
        }
        harness.record.finish()
        return try XCTUnwrap(harness.sink.values.first)
    }

    private func counter(_ summary: Rec.Summary, _ counter: Rec.Counter) -> UInt64? {
        summary.counterObserved[counter.rawValue] ? summary.counts[counter.rawValue] : nil
    }

    private func resultBranch(_ summary: Rec.Summary) -> String {
        if counter(summary, .resultCacheHits) != nil { return "hit" }
        if counter(summary, .resultCacheMisses) != nil { return "miss" }
        return "unobserved"
    }

    private func withoutCache(_ value: ScriptValue) -> ScriptValue {
        guard case .object(var fields) = value else { return value }
        fields["cache"] = nil
        return .object(fields)
    }

    private func assertCleanSummary(_ summary: Rec.Summary, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(summary.droppedIntervals, 0, file: file, line: line)
        XCTAssertEqual(summary.suppressedSpans, 0, file: file, line: line)
        XCTAssertEqual(summary.unfinishedSpans, 0, file: file, line: line)
    }

    private func assertCounters(_ summary: Rec.Summary, _ expected: [(Rec.Counter, UInt64?)],
                                file: StaticString = #filePath, line: UInt = #line) {
        for (name, want) in expected {
            XCTAssertEqual(counter(summary, name), want, "\(name)", file: file, line: line)
        }
    }

    /// P-cold for fixture F (3 functions, 128 bytes, one block, two instructions).
    private func assertPCold(_ summary: Rec.Summary, file: StaticString = #filePath, line: UInt = #line) {
        assertCounters(summary, [
            (.captureMisses, 1), (.captureHits, nil), (.captureOverCap, nil),
            (.sliceDigestPasses, 1), (.sliceDigestBytes, 128),
            (.functionRows, 3), (.xrefRows, 0), (.instructionRows, 2), (.relocationRows, 0), (.sourceSymbolRows, 0),
            (.canonicalPasses, 2), (.resultCacheMisses, 1), (.resultCacheHits, nil),
            (.functionsConsidered, 3), (.blocksVisited, 1), (.overridesVisited, 0),
        ], file: file, line: line)
    }

    /// P-reuse: capture hit, no validation; the result branch is asserted separately.
    private func assertPReuse(_ summary: Rec.Summary, file: StaticString = #filePath, line: UInt = #line) {
        assertCounters(summary, [
            (.captureHits, 1), (.captureMisses, nil), (.captureOverCap, nil), (.canonicalPasses, 2),
        ], file: file, line: line)
    }

    private func fixedPayload(_ envelope: NativeDecompilerWireRequestEnvelope) throws -> Data {
        let id = UUID(uuidString: "40000000-0000-0000-0000-000000000004")!
        let rebound = NativeDecompilerRequestProjection(request: envelope.body, operation: envelope.operation)
            .makeRequestEnvelope(requestID: id)
        return try NativeDecompilerWireCodec().encodeRequest(rebound, matching: id)
    }

    private func request(_ snapshot: WorkspaceSnapshot, _ id: UUID) -> ScriptingNativeDecompileRequest {
        .init(snapshot: snapshot, imageSlot: .primary, functionID: id,
              startAddress: id == functionID ? 0x1000 : (id == secondID ? 0x1008 : 0x1010))
    }
    private func makeRegistry(_ dispatcher: CaptureDispatcher, work: CaptureWork = .init(),
                              begin: @escaping @Sendable () -> Void = {},
                              finish: @escaping @Sendable () -> Void = {}) -> NativeDecompilerRuntimeRegistry {
        .testing(policy: .enabled, dispatcher: dispatcher, authorityProvider: CaptureAuthority(),
            validationWorkObserver: .init(validationDidBegin: { work.enter(); begin() },
                                         validationDidFinish: finish))
    }
    private func makeScriptingFixture(byteCount: Int = 128, xrefCount: Int = 0) throws -> WorkspaceSnapshot {
        let bytes = Data(repeating: 0, count: byteCount)
        let artifact = try MachOSliceArtifactIdentity(
            uuid: UUID(uuidString: "30000000-0000-0000-0000-000000000003")!,
            rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0,
            selectedSliceSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes),
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let layout = try MachOPreferredSegmentLayout(
            records: [
                .init(
                    name: "__TEXT",
                    preferredVMStart: 0x1000,
                    preferredVMSize: UInt64(bytes.count),
                    sliceRelativeFileOffset: 0,
                    fileSize: UInt64(bytes.count),
                    initialProtections: 5
                ),
            ],
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let binary = BinaryImage(
            id: binaryID,
            name: "fixture",
            path: "synthetic-fixture",
            kind: "Mach-O 64-bit",
            architecture: "arm64",
            artifactIdentity: artifact,
            preferredSegmentLayout: layout,
            artifactIntegrityState: .verified,
            slot: .primary
        )
        var analysis = ImageAnalysis(
            functions: [
                FunctionSummary(
                    id: functionID,
                    name: "entry",
                    startAddress: 0x1000,
                    endAddress: 0x1008,
                    confidence: 1
                ),
            ],
            basicBlocks: [
                BasicBlockSummary(
                    id: UUID(),
                    functionID: functionID,
                    startAddress: 0x1000,
                    endAddress: 0x1008,
                    instructionCount: 2
                ),
            ],
            instructions: [
                InstructionRow(
                    address: 0x1000,
                    bytes: "1f 20 03 d5",
                    mnemonic: "nop",
                    operands: "",
                    hasBreakpoint: false,
                    comment: nil
                ),
                InstructionRow(
                    address: 0x1004,
                    bytes: "c0 03 5f d6",
                    mnemonic: "ret",
                    operands: "",
                    hasBreakpoint: false,
                    comment: nil
                ),
            ],
            sections: [
                SectionSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000005")!,
                    name: "__TEXT,__text",
                    address: 0x1000,
                    size: UInt64(bytes.count),
                    fileOffset: 0,
                    isExecutable: true
                ),
            ],
            identityEffectiveByteRanges: [try IdentityEffectiveByteRangeAttestation(
                artifactIdentity: artifact,
                segmentName: "__TEXT",
                startAddress: 0x1000,
                endAddressExclusive: 0x1000 + UInt64(bytes.count),
                sliceRelativeFileOffset: 0,
                byteCount: UInt64(bytes.count),
                initialProtections: 5,
                rawBytesSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes)
            )],
            imageBytes: bytes
        )
        analysis.functions += [
            .init(id: secondID, name: "second", startAddress: 0x1008, endAddress: 0x1010, confidence: 1),
            .init(id: thirdID, name: "third", startAddress: 0x1010, endAddress: 0x1018, confidence: 1)]
        analysis.xrefs = (0..<xrefCount).map { _ in
            .init(id: UUID(), from: 0xf0000000, to: 0xf0000004, kind: XRefKind.call)
        }
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }
}

private final class CaptureWork: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = 0
    var attempts: Int { lock.withLock { stored } }
    func enter() { lock.withLock { stored += 1 } }
}

private final class CaptureSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var signalled = false
    private var waiter: CheckedContinuation<Void, Never>?
    func signal() {
        let current = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            signalled = true
            defer { waiter = nil }
            return waiter
        }
        current?.resume()
    }
    func wait() async {
        await withCheckedContinuation { continuation in
            let immediate = lock.withLock { () -> Bool in
                if signalled { return true }
                waiter = continuation
                return false
            }
            if immediate { continuation.resume() }
        }
    }
}

/// Blocks only the first synchronous worker callback, never the test's async executor.
/// Entry/release are explicit signals, with no sleeps, elapsed assertions or polling.
private final class CaptureBarrier: @unchecked Sendable {
    private let condition = NSCondition()
    private let entered = CaptureSignal()
    private var first = true
    private var released = false
    func blockFirst() {
        condition.lock()
        guard first else { condition.unlock(); return }
        first = false
        condition.unlock()
        entered.signal()
        condition.lock()
        while !released { condition.wait() }
        condition.unlock()
    }
    func waitForEntry() async { await entered.wait() }
    func release() {
        condition.lock()
        released = true
        condition.broadcast()
        condition.unlock()
    }
}

private struct CaptureAuthority: NativeDecompilerRuntimeAuthorityProviding {
    func attestRuntimeAuthority() async throws -> NativeDecompilerRuntimeIdentity {
        CaptureDispatcher.runtimeIdentity
    }
}

private final class CaptureDispatcher: NativeDecompilerDispatching, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [NativeDecompilerWireRequestEnvelope] = []
    private let identitySpecific: Bool
    init(identitySpecific: Bool = false) { self.identitySpecific = identitySpecific }
    var requests: [NativeDecompilerWireRequestEnvelope] { lock.withLock { stored } }
    static let document = NativeDecompilerWirePseudocodeDocument(
        text: "void fixture(void) {}\n", language: "c", isComplete: true, isTruncated: false)
    func decompile(request: NativeDecompilerPreencodedDispatchRequest,
                   elapsedTimeBudget: Duration?) async throws -> NativeDecompilerWireReplyEnvelope {
        lock.withLock { stored.append(request.envelope) }
        return Self.reply(for: request.envelope, identitySpecific: identitySpecific)
    }
    static let runtimeIdentity = NativeDecompilerRuntimeIdentity(
        backendID: "native-decompiler-test",
        engineVersion: "12.1.2",
        engineRevision: String(repeating: "b", count: 40),
        wrapperVersion: "dcp03b5-v1",
        wrapperRevision: String(repeating: "c", count: 40),
        packageManifestSHA256: String(repeating: "d", count: 64),
        packageTreeSHA256: String(repeating: "e", count: 64),
        languageID: "AARCH64:LE:64:AppleSilicon",
        compilerSpecID: "default",
        targetProfileID: "apple-aarch64-pac-visible-clobber-v1",
        contextProfileSHA256: "6aa45ea9206f967c095d175b05c6c0d7980cd15a0702826d7ab38e4fd37c8ca5"
    )

    static func identityDocument(_ digest: String) -> NativeDecompilerWirePseudocodeDocument {
        .init(text: "request identity: " + digest + "\n", language: "c", isComplete: true, isTruncated: false)
    }
    static func reply(for request: NativeDecompilerWireRequestEnvelope,
                      identitySpecific: Bool = false) -> NativeDecompilerWireReplyEnvelope {
            let result = NativeDecompilerWireStructuredResult(
                requestID: request.requestID,
                requestSHA256: request.body.requestSHA256,
                image: request.body.image,
                function: request.body.function,
                addressSpaces: [],
                types: [],
                instructions: [],
                varnodes: [],
                operations: [],
                blocks: [],
                edges: [],
                ssaValues: [],
                ssaBindings: [],
                phis: [],
                memoryVersions: [],
                memoryPhis: [],
                memoryEffects: [],
                variables: [],
                calls: [],
                regions: [],
                tokens: [],
                pseudocodeDocument: identitySpecific ? identityDocument(request.body.requestSHA256) : document,
                warnings: []
            )
            let availability = NativeDecompilerWireBackendAvailability(
                available: true,
                reasonCode: "",
                runtimeIdentity: runtimeIdentity,
                capabilities: .init(
                    nativeDecompilerHeritage: true,
                    completeRegisterSSA: false,
                    memorySSA: false,
                    recoveredVariables: false,
                    recoveredTypes: false,
                    structuredControlFlow: false,
                    tokenizedPseudocode: false,
                    imageQualifiedSourceRanges: true
                )
            )
            return NativeDecompilerWireReplyEnvelope(
                requestID: request.requestID,
                success: .init(availability: availability, result: result)
            )
    }
}

// MARK: WR01/WR04 helper copies (private, test-local names; bodies copied from the API phase test class)

/// One fresh phase record with its own fake clock and sink (copy of the API test PhaseHarness).
private final class CaptureTraceHarness: @unchecked Sendable {
    let clock: PhaseTestClock
    let sink: PhaseTestSink
    let record: NativeDecompilerPhaseRecord
    init() {
        let clock = PhaseTestClock(), sink = PhaseTestSink()
        self.clock = clock
        self.sink = sink
        record = NativeDecompilerPhaseRecord(clock: { clock.read() }, sink: { sink.append($0) })
    }
}

/// Each invocation returns a distinct fresh record (copy of the API test PhaseFactory).
private final class CaptureTraceFactory: @unchecked Sendable {
    private let lock = NSLock()
    private var made: [CaptureTraceHarness] = []
    var harnesses: [CaptureTraceHarness] { lock.withLock { made } }
    func make() -> NativeDecompilerPhaseRecord? {
        let harness = CaptureTraceHarness()
        lock.withLock { made.append(harness) }
        return harness.record
    }
}

/// Forwards both seam entry points to the same registry.
private struct CaptureRegistryAdapter: ScriptingNativeDecompiling {
    let registry: NativeDecompilerRuntimeRegistry
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        await registry.decompileForScripting(request)
    }
    func decompileDisclosed(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileDisclosure {
        await registry.decompileDisclosedForScripting(request)
    }
}

/// A scripting API wired to a store holding the fixture and to one registry.
private struct CaptureRig {
    let registry: NativeDecompilerRuntimeRegistry
    let work: CaptureWork
    let dispatcher: CaptureDispatcher
    let factory: CaptureTraceFactory
    let store: WorkspaceStore
    let api: WorkspaceScriptingAPI
}
#endif

private final class PhaseTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var reads = 0
    var readCount: Int { lock.withLock { reads } }
    func read() -> UInt64 { lock.withLock { reads += 1; return UInt64(reads) * 10 } }
}
private final class PhaseTestSink: @unchecked Sendable {
    private let lock = NSLock()
    private var summaries: [NativeDecompilerPhaseRecord.Summary] = []
    var values: [NativeDecompilerPhaseRecord.Summary] { lock.withLock { summaries } }
    func append(_ value: NativeDecompilerPhaseRecord.Summary) { lock.withLock { summaries.append(value) } }
}

#if DEBUG
private final class CaptureNativeProvider: ScriptingNativeDecompiling, @unchecked Sendable {
    private let lock = NSLock()
    private var stored = 0
    var calls: Int { lock.withLock { stored } }
    func decompile(_ request: ScriptingNativeDecompileRequest) async -> ScriptingNativeDecompileOutcome {
        lock.withLock { stored += 1 }
        return .completed(CaptureDispatcher.document)
    }
}
#endif
