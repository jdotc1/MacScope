// Authored, unrun.
import Darwin
import Foundation
import MacScopeChildProcessC
import MacScopeFatalSignalC
import XCTest
@testable import MacScope

private struct ThreadStackSample: Sendable {
    let status: Int32
    let flags: Int32
    let size: Int
    let address: UInt
    let sawStart: Bool

    static func capture() -> Self {
        var stack = stack_t()
        let status = MacScopeReadAlternateSignalStack(&stack) // Stateless OS read only.
        return Self(status: status, flags: stack.ss_flags, size: Int(stack.ss_size),
                    address: UInt(bitPattern: stack.ss_sp),
                    sawStart: MCPFatalSignalReporter.threadStackSawStartForTesting())
    }
}

private final class ThreadStackBox: @unchecked Sendable {
    let park: Bool
    let ready = DispatchSemaphore(value: 0)
    let resume = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var before: ThreadStackSample?
    private var after: ThreadStackSample?

    init(park: Bool = false) { self.park = park }

    func record(_ sample: ThreadStackSample, baseline: Bool = false) {
        lock.lock()
        if baseline { before = sample } else { after = sample }
        lock.unlock()
    }

    func read(baseline: Bool = false) -> ThreadStackSample? {
        lock.lock()
        defer { lock.unlock() }
        return baseline ? before : after
    }
}

private let threadStackEntry: @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? = {
    pointer in
    let box = Unmanaged<ThreadStackBox>.fromOpaque(pointer).takeUnretainedValue()
    if box.park {
        box.record(ThreadStackSample.capture(), baseline: true)
        box.ready.signal()
        box.resume.wait()
    }
    box.record(ThreadStackSample.capture())
    return nil
}

@MainActor
final class MCPFatalSignalThreadStackTests: XCTestCase {
    private func assertPrepared(_ sample: ThreadStackSample, hook: Bool,
                                file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(sample.status, 0, file: file, line: line)
        XCTAssertEqual(sample.flags & SS_DISABLE, 0, file: file, line: line)
        XCTAssertGreaterThanOrEqual(sample.size, Int(SIGSTKSZ), file: file, line: line)
        XCTAssertNotEqual(sample.address, 0, file: file, line: line)
        if hook {
            XCTAssertTrue(sample.sawStart, "A START callback must successfully ensure an enabled stack before this body.",
                          file: file, line: line)
        }
    }

    // One fixture owns the process-wide hook. No Swift closure is an introspection hook.
    func testThreadStackLifecycleAndCoverage() throws {
        let begin = MCPFatalSignalReporter.beginThreadStackProbeForTesting()
        guard begin == 0 else {
            XCTFail("Could not acquire the test hook scope; preserve the existing owner.")
            return
        }
        defer {
            XCTAssertEqual(MCPFatalSignalReporter.endThreadStackProbeForTesting(), 0,
                           "Restore must observe the C predecessor, then reinstate the original hook.")
        }

        XCTAssertEqual(MCPFatalSignalReporter.installThreadStackHookForTesting(), 0)
        let first = ThreadStackSample.capture()
        assertPrepared(first, hook: false)
        XCTAssertEqual(MCPFatalSignalReporter.installThreadStackHookForTesting(), 0)
        let second = ThreadStackSample.capture()
        assertPrepared(second, hook: false)
        XCTAssertEqual(first.address, second.address, "Second install must not replace the installing stack.")

        let created = ThreadStackBox()
        let createdReference = Unmanaged.passRetained(created)
        var createdThread: pthread_t?
        MCPFatalSignalReporter.setThreadStackProbeArmedForTesting(true)
        let create = pthread_create(&createdThread, nil, threadStackEntry, createdReference.toOpaque())
        MCPFatalSignalReporter.setThreadStackProbeArmedForTesting(false)
        guard create == 0, let createdThread else {
            createdReference.release()
            XCTFail("Could not create the post-install fixture: \(create)")
            return
        }
        let joined = pthread_join(createdThread, nil)
        XCTAssertEqual(joined, 0)
        guard joined == 0 else { return } // Keep its retained storage alive on an uncertain join.
        createdReference.release()
        assertPrepared(try XCTUnwrap(created.read()), hook: true)

        for event in [PTHREAD_INTROSPECTION_THREAD_CREATE, PTHREAD_INTROSPECTION_THREAD_START,
                      PTHREAD_INTROSPECTION_THREAD_TERMINATE, PTHREAD_INTROSPECTION_THREAD_DESTROY] {
            // DESTROY may be delivered after pthread_join returns, on another thread; allow a bounded settle.
            let deadline = Date().addingTimeInterval(2)
            var count = MCPFatalSignalReporter.threadStackProbeCountForTesting(UInt32(event))
            while count == 0, Date() < deadline {
                usleep(1_000)
                count = MCPFatalSignalReporter.threadStackProbeCountForTesting(UInt32(event))
            }
            XCTAssertEqual(count, 1,
                           "Event \(event): expected one in the target fixture; excess can also mean pthread identifier reuse.")
        }
        XCTAssertEqual(MCPFatalSignalReporter.threadStackProbePreparedForTesting(), 1,
                       "Our successful START ensure must precede the predecessor's START callback.")

        let foundation = ThreadStackBox()
        let foundationDone = DispatchSemaphore(value: 0)
        let thread = Thread {
            foundation.record(ThreadStackSample.capture())
            foundationDone.signal()
        }
        thread.start()
        foundationDone.wait()
        assertPrepared(try XCTUnwrap(foundation.read()), hook: true)

        // GCD and Task.detached workers may come from a pool created before install, so ruling R1
        // leaves them uncovered; no assertion is made on them (ruling R4b).
        // These observations do not prove all workqueue workers are new or later terminate.
        // Foundation/GCD completion signals precede thread teardown; no teardown claim is made.
    }
}
