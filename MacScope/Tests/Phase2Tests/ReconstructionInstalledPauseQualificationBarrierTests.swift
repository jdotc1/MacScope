import CryptoKit
import Darwin
import Foundation
import XCTest

@testable import MacScope

#if DEBUG
final class ReconstructionInstalledPauseQualificationBarrierTests: XCTestCase {
    // NOT RUN: source-only decision-ordering control; not an elapsed-duration assertion.
    func testExplicitOwnedRootHoldsPauseUntilCreateOnlyRelease() async throws {
        let root = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try await assertPauseRelease(at: root, observeAbsentDecision: true)
    }

    func testNamedRunnerContainerRootHoldsPauseUntilCreateOnlyRelease() async throws {
        let parent = try XCTUnwrap(
            ReconstructionInstalledQualificationBarrierRoot.runnerTemporaryDirectory
        )
        guard FileManager.default.fileExists(atPath: parent.path) else {
            throw XCTSkip("Installed runner container has not been created on this host")
        }
        let root = parent.appendingPathComponent("MacScope-Task10-PauseBarrier-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        try await assertPauseRelease(at: root)
    }

    func testSharedRootAuthorityRejectsWrongParentsModesAndLinks() throws {
        let root = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let prefix = "MacScope-Task10-PauseBarrier-"
        let validDescriptor = try XCTUnwrap(
            ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(root.path, prefix: prefix)
        )
        Darwin.close(validDescriptor)
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(
            root.path.replacingOccurrences(of: "/private/tmp/", with: "/tmp/"), prefix: prefix
        ))
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(
            root.path + "/../" + root.lastPathComponent, prefix: prefix
        ))
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(
            root.path, prefix: "MacScope-Task10-RevealBarrier-"
        ))
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(
            "/private/tmp/" + prefix + "not-a-uuid", prefix: prefix
        ))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(root.path, prefix: prefix))
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let nested = root.appendingPathComponent(prefix + UUID().uuidString)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(nested.path, prefix: prefix))
        let link = URL(fileURLWithPath: "/private/tmp/" + prefix + UUID().uuidString)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        defer { try? FileManager.default.removeItem(at: link) }
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(link.path, prefix: prefix))
    }

    func testSharedRootAuthorityAcceptsRevealLeafOnlyInNamedRunnerContainer() throws {
        let parent = try XCTUnwrap(ReconstructionInstalledQualificationBarrierRoot.runnerTemporaryDirectory)
        guard FileManager.default.fileExists(atPath: parent.path) else {
            throw XCTSkip("Installed runner container has not been created on this host")
        }
        let prefix = "MacScope-Task10-RevealBarrier-"
        let root = parent.appendingPathComponent(prefix + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let descriptor = try XCTUnwrap(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(root.path, prefix: prefix))
        Darwin.close(descriptor)
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(
            root.path.replacingOccurrences(of: "MacScopeInstalledAppUITests.xctrunner", with: "OtherTests.xctrunner"), prefix: prefix
        ))
        XCTAssertNil(ReconstructionInstalledQualificationBarrierRoot.openOwnedRoot(
            root.path.replacingOccurrences(of: "/Data/tmp/", with: "/Data/Library/"), prefix: prefix
        ))
    }

    // NOT RUN: only opted-in callers use the decision observation; the default preserves
    // the neighboring named-runner control's existing nil-observer/80 ms path.
    private func assertPauseRelease(
        at root: URL,
        observeAbsentDecision: Bool = false
    ) async throws {
        let jobID = UUID(uuidString: "10000000-0000-0000-0000-000000000006")!
        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let candidateSHA256 = try sha256Hex(of: executableURL)
        let environment = [
            ReconstructionInstalledPauseQualificationBarrier.runEnvironmentKey: "1",
            ReconstructionInstalledPauseQualificationBarrier.rootEnvironmentKey: root.path,
            ReconstructionInstalledPauseQualificationBarrier.candidateSHA256EnvironmentKey:
                candidateSHA256,
        ]
        let completion = PauseBarrierCompletion()
        let absentDecision = observeAbsentDecision ? PauseBarrierAbsentDecision() : nil
        let observeAbsentRelease: (@Sendable () -> Void)?
        if let absentDecision {
            observeAbsentRelease = { absentDecision.observe() }
        } else {
            observeAbsentRelease = nil
        }
        let barrierTask = Task {
            let result = await ReconstructionInstalledPauseQualificationBarrier.waitIfRequested(
                reason: .pausedByUser,
                jobID: jobID,
                environment: environment,
                executableURL: executableURL,
                observeAbsentRelease: observeAbsentRelease
            )
            await completion.record(result)
            return result
        }
        do {
            if let absentDecision {
                // createArrival has completed before the observed polling decision.
                try await absentDecision.wait()
            }

            let arrival = root.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.arrivalFilename
            )
            try await waitForRegularFile(arrival)
            let receipt = try JSONSerialization.jsonObject(with: Data(contentsOf: arrival))
                as? [String: Any]
            XCTAssertEqual(receipt?["kind"] as? String, "pause")
            XCTAssertEqual(receipt?["jobID"] as? String, jobID.uuidString.lowercased())
            XCTAssertEqual(receipt?["candidateSHA256"] as? String, candidateSHA256)
            XCTAssertEqual(
                receipt?["pid"] as? Int,
                Int(ProcessInfo.processInfo.processIdentifier)
            )

            if !observeAbsentDecision {
                try await Task.sleep(nanoseconds: 80_000_000)
            }
            let prematureCompletion = await completion.value
            XCTAssertNil(prematureCompletion, "arrival must not release the pending Pause command")

            let release = root.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.releaseFilename
            )
            XCTAssertTrue(createEmptyFileExclusively(at: release))
            let barrierResult = await barrierTask.value
            XCTAssertTrue(barrierResult)
            let committedCompletion = await completion.value
            XCTAssertEqual(committedCompletion, true)
        } catch {
            if observeAbsentDecision {
                barrierTask.cancel()
                _ = await barrierTask.value
            }
            throw error
        }
    }

    func testBarrierIsNoOpWithoutBothOptInsAndRejectsSymlinkRoot() async throws {
        let root = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let jobID = UUID()
        let noOpResult = await ReconstructionInstalledPauseQualificationBarrier.waitIfRequested(
            reason: .pausedByUser,
            jobID: jobID,
            environment: [
                ReconstructionInstalledPauseQualificationBarrier.runEnvironmentKey: "1",
            ]
        )
        XCTAssertTrue(noOpResult)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(
            ReconstructionInstalledPauseQualificationBarrier.arrivalFilename
        ).path))

        let candidateMismatchResult = await
            ReconstructionInstalledPauseQualificationBarrier.waitIfRequested(
                reason: .pausedByUser,
                jobID: jobID,
                environment: [
                    ReconstructionInstalledPauseQualificationBarrier.runEnvironmentKey: "1",
                    ReconstructionInstalledPauseQualificationBarrier.rootEnvironmentKey: root.path,
                    ReconstructionInstalledPauseQualificationBarrier
                        .candidateSHA256EnvironmentKey: String(repeating: "0", count: 64),
                ],
                executableURL: URL(fileURLWithPath: CommandLine.arguments[0])
            )
        XCTAssertFalse(candidateMismatchResult)
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(
            ReconstructionInstalledPauseQualificationBarrier.arrivalFilename
        ).path))

        let link = URL(
            fileURLWithPath: "/private/tmp/MacScope-Task10-PauseBarrier-Link-\(UUID().uuidString)"
        )
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        defer { try? FileManager.default.removeItem(at: link) }
        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let candidateSHA256 = try sha256Hex(of: executableURL)
        let symlinkResult = await ReconstructionInstalledPauseQualificationBarrier.waitIfRequested(
            reason: .pausedByUser,
            jobID: jobID,
            environment: [
                ReconstructionInstalledPauseQualificationBarrier.runEnvironmentKey: "true",
                ReconstructionInstalledPauseQualificationBarrier.rootEnvironmentKey: link.path,
                ReconstructionInstalledPauseQualificationBarrier.candidateSHA256EnvironmentKey:
                    candidateSHA256,
            ],
            executableURL: executableURL
        )
        XCTAssertFalse(symlinkResult)
    }

    func testPendingControlIsInstalledBeforeBarrierAndPlannerCancellation() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "MacScope/Services/Reconstruction/ReconstructionJobCoordinator.swift"
            ),
            encoding: .utf8
        )
        let start = try XCTUnwrap(source.range(of: "    private func registerControl("))
        let suffix = source[start.lowerBound...]
        let end = try XCTUnwrap(suffix.range(of: "\n    private func run("))
        let body = String(suffix[..<end.lowerBound])
        let install = try XCTUnwrap(body.range(of: "pendingControls[jobID] = control"))
        let barrier = try XCTUnwrap(body.range(
            of: "ReconstructionInstalledPauseQualificationBarrier.waitIfRequested("
        ))
        let cancellation = try XCTUnwrap(body.range(of: "await planner.cancel(jobID: jobID)"))

        XCTAssertLessThan(install.lowerBound, barrier.lowerBound)
        XCTAssertLessThan(barrier.lowerBound, cancellation.lowerBound)
        XCTAssertTrue(body.contains("reason == .pausedByUser"))
        XCTAssertTrue(body.contains("rejectPendingControl(jobID: jobID, matching: completion)"))
    }

    // NOT RUN: default-nil production invocation still requires a real valid release.
    func testNilAbsentObserverPreservesCreateOnlyRelease() async throws {
        let root = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let invocation = try startPauseBarrier(at: root)
        do {
            try await waitForRegularFile(root.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.arrivalFilename
            ))
            let pending = await invocation.completion.value
            XCTAssertNil(pending)
            XCTAssertTrue(createEmptyFileExclusively(at: root.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.releaseFilename
            )))
            let result = await invocation.task.value
            XCTAssertTrue(result)
        } catch {
            invocation.task.cancel()
            _ = await invocation.task.value
            throw error
        }
    }

    // NOT RUN: distinct real roots, callbacks, tasks, and release files; no global signal.
    func testAbsentObserversAndReleasesAreInvocationScoped() async throws {
        let firstRoot = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: firstRoot) }
        let secondRoot = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: secondRoot) }
        let firstDecision = PauseBarrierAbsentDecision()
        let secondDecision = PauseBarrierAbsentDecision()
        let first = try startPauseBarrier(at: firstRoot) { firstDecision.observe() }
        var secondTask: Task<Bool, Never>?
        do {
            let second = try startPauseBarrier(at: secondRoot) { secondDecision.observe() }
            secondTask = second.task
            try await firstDecision.wait()
            try await secondDecision.wait()
            let firstPending = await first.completion.value
            let secondPending = await second.completion.value
            XCTAssertNil(firstPending)
            XCTAssertNil(secondPending)
            XCTAssertTrue(createEmptyFileExclusively(at: firstRoot.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.releaseFilename
            )))
            let firstResult = await first.task.value
            XCTAssertTrue(firstResult)
            let secondAfterFirstRelease = await second.completion.value
            XCTAssertNil(secondAfterFirstRelease)
            XCTAssertFalse(FileManager.default.fileExists(atPath: secondRoot.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.releaseFilename
            ).path))
            XCTAssertTrue(createEmptyFileExclusively(at: secondRoot.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.releaseFilename
            )))
            let secondResult = await second.task.value
            XCTAssertTrue(secondResult)
        } catch {
            first.task.cancel()
            secondTask?.cancel()
            _ = await first.task.value
            if let secondTask { _ = await secondTask.value }
            throw error
        }
    }

    // NOT RUN: observation is not release authority; an invalid REAL release still fails.
    func testObservedAbsentDecisionStillRejectsInvalidRelease() async throws {
        let root = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let decision = PauseBarrierAbsentDecision()
        let invocation = try startPauseBarrier(at: root) { decision.observe() }
        defer { invocation.task.cancel() }
        do {
            try await decision.wait()
            let pending = await invocation.completion.value
            XCTAssertNil(pending)
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent(
                    ReconstructionInstalledPauseQualificationBarrier.releaseFilename
                ),
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let result = await invocation.task.value
            XCTAssertFalse(result)
        } catch {
            invocation.task.cancel()
            _ = await invocation.task.value
            throw error
        }
    }

    // NOT RUN: a returned no-opt-in invocation cannot have published an absent decision.
    func testAbsentObserverIsSilentWithoutBothOptIns() async throws {
        let root = try makeOwnedRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let environments: [[String: String]] = [
            [ReconstructionInstalledPauseQualificationBarrier.runEnvironmentKey: "1"],
            [ReconstructionInstalledPauseQualificationBarrier.rootEnvironmentKey: root.path,
             ReconstructionInstalledPauseQualificationBarrier.candidateSHA256EnvironmentKey:
                String(repeating: "0", count: 64)],
        ]
        for environment in environments {
            let decision = PauseBarrierAbsentDecision()
            let result = await ReconstructionInstalledPauseQualificationBarrier.waitIfRequested(
                reason: .pausedByUser,
                jobID: UUID(),
                environment: environment,
                observeAbsentRelease: { decision.observe() }
            )
            XCTAssertTrue(result)
            let observed = await decision.finishAndWasObserved()
            XCTAssertFalse(observed)
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(
                ReconstructionInstalledPauseQualificationBarrier.arrivalFilename
            ).path))
        }
    }

    // NOT RUN: an observation before wait registration is retained; repeats are harmless.
    func testAbsentDecisionObservationBuffersBeforeWaitAndIsIsolated() async throws {
        let observed = PauseBarrierAbsentDecision()
        let untouched = PauseBarrierAbsentDecision()
        observed.observe()
        observed.observe()
        try await observed.wait()
        let crossedSignal = await untouched.finishAndWasObserved()
        XCTAssertFalse(crossedSignal)
    }

    // NOT RUN: missing observation throws rather than leaving an unbounded event waiter.
    func testMissingAbsentDecisionObservationTimesOut() async throws {
        let decision = PauseBarrierAbsentDecision()
        do {
            try await decision.wait(timeoutNanoseconds: 0)
            XCTFail("A missing absent decision must time out")
        } catch PauseBarrierObservationError.timedOut {
            // Expected; wait's defer cancels its child tasks and finishes the stream.
        }
        decision.observe() // Late callbacks return even after timeout cleanup.
    }

    // NOT RUN: narrow invocation fixture for the new observer controls only.
    private func startPauseBarrier(
        at root: URL,
        observeAbsentRelease: (@Sendable () -> Void)? = nil
    ) throws -> (task: Task<Bool, Never>, completion: PauseBarrierCompletion) {
        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let candidateSHA256 = try sha256Hex(of: executableURL)
        let environment = [
            ReconstructionInstalledPauseQualificationBarrier.runEnvironmentKey: "1",
            ReconstructionInstalledPauseQualificationBarrier.rootEnvironmentKey: root.path,
            ReconstructionInstalledPauseQualificationBarrier.candidateSHA256EnvironmentKey:
                candidateSHA256,
        ]
        let jobID = UUID()
        let completion = PauseBarrierCompletion()
        let task = Task {
            let result = await ReconstructionInstalledPauseQualificationBarrier.waitIfRequested(
                reason: .pausedByUser,
                jobID: jobID,
                environment: environment,
                executableURL: executableURL,
                observeAbsentRelease: observeAbsentRelease
            )
            await completion.record(result)
            return result
        }
        return (task, completion)
    }

    private func makeOwnedRoot() throws -> URL {
        let root = URL(
            fileURLWithPath: "/private/tmp/MacScope-Task10-PauseBarrier-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func waitForRegularFile(_ url: URL) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while clock.now < deadline {
            if (try? url.resourceValues(forKeys: [.isRegularFileKey])).map(
                { $0.isRegularFile == true }
            ) == true {
                return
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("Timed out waiting for \(url.lastPathComponent)")
    }

    private func createEmptyFileExclusively(at url: URL) -> Bool {
        let descriptor = url.path.withCString {
            Darwin.open(
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else { return false }
        return Darwin.close(descriptor) == 0
    }

    private func repositoryRoot() -> URL {
        var root = TestSourceRoot.fileURL(#filePath).deletingLastPathComponent()
        for _ in 0..<3 { root.deleteLastPathComponent() }
        return root
    }

    private func sha256Hex(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1_048_576) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

// NOT RUN: per-invocation, single-consumer, buffered one-shot observation only.
// No callback captures a root, task, continuation to production, or release operation.
private struct PauseBarrierAbsentDecision: Sendable {
    private let stream: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation

    // NOT RUN.
    init() {
        let pair = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        stream = pair.stream
        continuation = pair.continuation
    }

    // NOT RUN: synchronous publish-and-return, including repeated/late callbacks.
    func observe() {
        continuation.yield(())
        continuation.finish()
    }

    // NOT RUN: only after the observed invocation has returned, with no prior consumer.
    func finishAndWasObserved() async -> Bool {
        continuation.finish()
        var iterator = stream.makeAsyncIterator()
        return await iterator.next() != nil
    }

    // NOT RUN: this timeout bounds only test failure cleanup, never the production barrier.
    func wait(timeoutNanoseconds: UInt64 = 2_000_000_000) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer {
                group.cancelAll()
                continuation.finish()
            }
            try Task.checkCancellation()
            group.addTask { [stream] in
                var iterator = stream.makeAsyncIterator()
                guard await iterator.next() != nil else {
                    throw PauseBarrierObservationError.finishedWithoutObservation
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutNanoseconds)
                throw PauseBarrierObservationError.timedOut
            }
            _ = try await group.next()
        }
    }
}

// NOT RUN: test-only failure outcomes, not production status values.
private enum PauseBarrierObservationError: Error {
    case timedOut
    case finishedWithoutObservation
}

private actor PauseBarrierCompletion {
    private(set) var value: Bool?

    func record(_ result: Bool) {
        value = result
    }
}
#endif
